"""
Benchmarks (pytest-benchmark). Not part of the test suite: run them with
``make bench`` (``bench-save`` / ``bench-compare`` to track regressions).

This file: what scales with the rules an operator adds and what every proxied
request pays. Old and new blacklist evaluation are measured side by side so
the effect of the compiled, cached rule set (middleman/ruleset.py) is visible
in every run. Whole requests go through the Django stack with the upstream
HTTP mocked, so only the proxy's own cost is measured.
"""

import io
from unittest.mock import Mock, patch

import pytest
from django.test import Client

from _rules import CHROME, CLIENT, HOSTILE_UA, compiled, rule_values, store
from middleman import ruleset as ruleset_module
from middleman import services
from middleman.destinations import host_matches, parse_host_regex
from middleman.exceptions import InvalidRuleError
from middleman.models import BlacklistRule
from middleman.rules import (CLIENT_RULE_TYPES, RULE_TYPE_IP, RULE_TYPE_PATH,
                             USER_AGENT_RULE_TYPES, validate_ip_rule)
from middleman.ruleset import build_ruleset, current_token
from middleman.services import ProxyManager
from middleman.user_agents import (parse_user_agent_regex,
                                   parse_user_agent_rule, user_agent_matches)

RULE_COUNTS = [0, 20, 100, 400, 2000]


# --- Rule validation (dashboard/admin; once per change for stored rules) --------------

@pytest.mark.parametrize("rule_type, parser, value", [
    ("ip", validate_ip_rule, "10.0.0.0/24"),
    ("user_agent", parse_user_agent_rule, "python-requests/"),
    ("user_agent_re", parse_user_agent_regex, r"sqlmap|nikto|masscan|(bad|evil)bot/\d+"),
    ("host_re", parse_host_regex, r"([a-z0-9-]+\.)*tracker\.(com|net)"),
])
def test_validate(benchmark, rule_type, parser, value):
    benchmark.group = "validate"
    benchmark.name = "validate[{}]".format(rule_type)
    benchmark(parser, value)


# --- Matching one rule against one request ---------------------------------------------

@pytest.mark.parametrize("label, rule, user_agent", [
    ("substring/browser", parse_user_agent_rule("sqlmap"), CHROME),
    ("regex/browser", parse_user_agent_regex(r"sqlmap|nikto|masscan"), CHROME),
    ("substring/hostile-8KB", parse_user_agent_rule("sqlmap"), HOSTILE_UA),
    ("regex-backtracking/hostile-8KB", parse_user_agent_regex(r"(a+)+b"), HOSTILE_UA),
])
def test_match_user_agent(benchmark, label, rule, user_agent):
    benchmark.group = "match"
    benchmark.name = "match[{}]".format(label)
    assert benchmark(user_agent_matches, rule, user_agent) is False


def test_match_host_regex(benchmark):
    benchmark.group = "match"
    benchmark.name = "match[host_re]"
    rule = parse_host_regex(r"([a-z0-9-]+\.)*tracker\.(com|net)")
    assert benchmark(host_matches, rule, "www.example.com") is False


# --- Blacklist evaluation per request: before vs after the compiled rule set ----------

def legacy_is_blacklisted(manager, ip, path, user_agent):
    """The pre-cache implementation: load every rule and re-validate it on every request."""
    rules = BlacklistRule.objects.filter(enabled=True, rule_type__in=CLIENT_RULE_TYPES)
    for rule in rules:
        try:
            parsed = rule.parse()
        except InvalidRuleError:
            continue
        if rule.rule_type == RULE_TYPE_IP and manager._matches_ip_rule(ip, rule.value):
            return "ip", rule.value
        if rule.rule_type == RULE_TYPE_PATH and manager._matches_rule(path, rule.value):
            return "path", rule.value
        if rule.rule_type in USER_AGENT_RULE_TYPES and user_agent_matches(parsed, user_agent):
            return rule.rule_type, rule.value
    return None


@pytest.mark.django_db
@pytest.mark.parametrize("count", RULE_COUNTS)
def test_blacklist_before(benchmark, count):
    store(rule_values(count))
    manager = ProxyManager("http://target.example/home/")
    benchmark.group = "blacklist per request: before (load + re-validate every rule)"
    benchmark.name = "before[{:>4} rules]".format(count)
    assert benchmark(legacy_is_blacklisted, manager, *CLIENT, CHROME) is None


@pytest.mark.django_db
@pytest.mark.parametrize("count", RULE_COUNTS)
def test_blacklist_after(benchmark, count):
    store(rule_values(count))
    benchmark.group = "blacklist per request: after (token check + compiled rules)"
    benchmark.name = "after[{:>4} rules]".format(count)

    def one_request():
        # A new ProxyManager per request, exactly like ProxyView.
        return ProxyManager("http://target.example/home/")._is_blacklisted(*CLIENT, CHROME)

    assert benchmark(one_request) is None


@pytest.mark.parametrize("count", RULE_COUNTS)
@pytest.mark.parametrize("prefilter", [True, False], ids=["prefilter", "no-prefilter"])
def test_blacklist_match_only(benchmark, count, prefilter):
    """Matching alone (no token query): what a pure time-based cache would cost."""
    rules = compiled(rule_values(count), use_prefilter=prefilter)
    benchmark.group = "blacklist per request: compiled matching only (no database)"
    benchmark.name = "match-only[{:>4} rules, {}]".format(count, "prefilter" if prefilter else "no prefilter")
    assert benchmark(rules.match_client, *CLIENT, CHROME) is None


@pytest.mark.django_db
def test_token_query(benchmark):
    """The per-request freshness check (one primary-key lookup)."""
    store(rule_values(4))  # signals are bypassed by bulk_create: write a token
    ruleset_module.bump_version()
    benchmark.group = "blacklist per request: after (token check + compiled rules)"
    benchmark.name = "token query alone"
    assert benchmark(current_token) is not None


@pytest.mark.django_db
@pytest.mark.parametrize("count", [100, 400, 2000])
def test_compile(benchmark, count):
    """Paid once per rule change per process."""
    store(rule_values(count))
    benchmark.group = "compile rule set (once per change)"
    benchmark.name = "compile[{:>4} rules]".format(count)
    ruleset = benchmark(build_ruleset, lambda rule, error: None)
    assert len(ruleset.client_rules) == count


# --- Whole requests through the Django stack (upstream mocked) ------------------------

def _upstream(*args, **kwargs):
    response = Mock(status_code=200, reason="OK", raw=io.BytesIO(b"ok"))
    response.headers = {"content-type": "text/plain"}
    return response


@pytest.fixture
def proxy_client():
    services._REPORTED_INVALID_RULES.clear()
    with patch("middleman.upstream.head", side_effect=_upstream), \
            patch("middleman.upstream.get", side_effect=_upstream):
        yield Client()


@pytest.mark.django_db
@pytest.mark.parametrize("count", [0, 100, 400])
def test_request_allowed(benchmark, proxy_client, count):
    store(rule_values(count))
    BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
    # Every request reserves one unit of the limit: make it effectively unlimited
    # so the timed loop never hits 429 (and needs no reset inside it).
    services.AccessEntry.objects.create(
        key=ProxyManager("")._create_unique_key(CLIENT[0], "home/"),
        ip=CLIENT[0], path="home/", max_requests=2_000_000_000,
    )
    benchmark.group = "full request"
    benchmark.name = "request[allowed, {:>3} rules]".format(count)

    def request():
        return proxy_client.get("/proxy/home/", HTTP_USER_AGENT=CHROME, REMOTE_ADDR=CLIENT[0])

    assert benchmark(request).status_code == 200


@pytest.mark.django_db
def test_request_blocked_by_user_agent(benchmark, proxy_client):
    store(rule_values(100))
    BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
    benchmark.group = "full request"
    benchmark.name = "request[blocked by user_agent, 100 rules]"

    def request():
        return proxy_client.get("/proxy/home/", HTTP_USER_AGENT="sqlmap/1.7", REMOTE_ADDR=CLIENT[0])

    with patch("middleman.views.logger"):  # one warning per blocked request otherwise
        assert benchmark(request).status_code == 403


# --- Whole requests against a real upstream: keep-alive vs new connections -----------

@pytest.fixture(scope="module")
def real_upstream():
    """The zero-latency upstream stub in its own process: only connection costs remain."""
    import subprocess
    import sys
    from pathlib import Path

    stub = Path(__file__).with_name("_upstream_stub.py")
    process = subprocess.Popen([sys.executable, str(stub), "0"], stdout=subprocess.PIPE, text=True)
    try:
        yield "http://127.0.0.1:{}/".format(process.stdout.readline().strip())
    finally:
        process.kill()
        process.wait(10)


@pytest.mark.django_db
@pytest.mark.parametrize("keepalive", [True, False], ids=["keep-alive", "new-connections"])
def test_request_real_upstream(benchmark, real_upstream, keepalive, settings):
    from middleman import upstream

    settings.UPSTREAM_KEEPALIVE = keepalive
    services.AccessEntry.objects.create(
        key=ProxyManager("")._create_unique_key(CLIENT[0], "home/"),
        ip=CLIENT[0], path="home/", max_requests=2_000_000_000,
    )
    client = Client()
    benchmark.group = "full request, real upstream (HEAD + GET over TCP)"
    benchmark.name = "request[{}]".format("keep-alive pool" if keepalive else "new connections (before)")

    def request():
        response = client.get("/proxy/home/", HTTP_USER_AGENT=CHROME, REMOTE_ADDR=CLIENT[0])
        return response.status_code, b"".join(response.streaming_content)

    with patch("middleman.views.BASE_TARGET_URL", real_upstream):
        assert benchmark(request) == (200, b"ok")
    upstream.close_sessions()
