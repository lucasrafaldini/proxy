"""
Compiled blacklist rules, cached per process.

Before this module every request loaded every enabled rule from the database
and re-validated it (regex compilation lint, CIDR parsing...) before matching:
the cost grew linearly with the number of rules (about 3.7 ms per request with
100 rules). Now rules are validated and compiled once per change:

* ``RuleSet`` holds the enabled, valid database rules in matching order, each
  compiled to the cheapest matcher for its type (pre-parsed CIDR networks,
  plain string comparisons, pre-compiled RE2 patterns). The client IP is parsed
  and the User-Agent lowercased once per request, not once per rule.
* User-Agent rules are also merged into RE2 **prefilters**: for ASCII
  User-Agents (all real browsers and bots), a few linear-time passes decide
  whether *any* User-Agent rule can match, so a request that matches none
  (the normal case) skips the per-rule loop. When a prefilter matches, the
  ordered loop runs and reports exactly the same rule as before. Prefilters
  are split into chunks of at most PREFILTER_CHUNK_PROGRAM_SIZE with their own
  memory budget: one huge alternation overflows RE2's DFA cache and falls back
  to the NFA, which made a hostile 8 KB User-Agent against 400 regex rules
  take 1.5 s instead of 0.1 ms (found by bench_concurrency.py, guarded by a test).
* Freshness across processes: every change to a rule (``post_save`` /
  ``post_delete``) writes a new random token to ``RuleSetVersion``. Each
  request reads that one row (a primary-key lookup) and recompiles only if the
  token changed, so a new rule still applies to the very next request in every
  worker. The process that made the change also drops its cache immediately.
  Writes that bypass signals (``bulk_create``, ``QuerySet.update``, raw SQL,
  restores) are picked up within ``MAX_AGE_SECONDS`` at the latest.

Semantics (which requests are blocked, and which rule is reported) are
identical to evaluating the rules one by one in order; the tests compare both.
"""

import functools
import ipaddress
import logging
import threading
import time
import uuid
from typing import NamedTuple, Optional, Tuple

import re2

from middleman.exceptions import InvalidRuleError
from middleman.rules import (CLIENT_RULE_TYPES, HOST_RULE_TYPES, RULE_TYPE_IP,
                             RULE_TYPE_PATH, USER_AGENT_RULE_TYPES,
                             parse_ip_network, validate_rule)

logger = logging.getLogger(__name__)

RULESET_VERSION_NAME = "blacklist"
# Prefilter chunks: compiled program size per chunk and RE2 memory per chunk.
# At the 1 MB budget user regexes get, the DFA fell off a cliff between
# program sizes ~3000 (0.02 ms on 8 KB) and ~6200 (277 ms): stay well below.
PREFILTER_CHUNK_PROGRAM_SIZE = 2000
PREFILTER_MAX_MEM = 8 << 20
# Safety net for writes that bypass signals (bulk_create, QuerySet.update, raw SQL).
MAX_AGE_SECONDS = 60

# --- compiled rules -------------------------------------------------------------------

IP_EXACT, IP_PREFIX, IP_NETWORK = "ip_exact", "ip_prefix", "ip_network"
PATH_EXACT, PATH_PREFIX = "path_exact", "path_prefix"
UA_SUBSTRING, UA_REGEX = "ua_substring", "ua_regex"


class CompiledRule(NamedTuple):
    rule_type: str  # as stored: ip, path, user_agent, user_agent_re
    value: str  # as stored (reported on a match)
    kind: str  # one of the matcher kinds above
    target: object  # str | IPv4Network/IPv6Network | compiled RE2 pattern


class HostRuleEntry(NamedTuple):
    value: str
    parsed: object  # destinations.HostRule


def compile_client_rule(rule_type: str, value: str, parsed=None) -> CompiledRule:
    """Compile one *valid* client rule (validate it first) into its matcher."""
    if rule_type == RULE_TYPE_IP:
        network = parse_ip_network(value)
        if network is not None:
            return CompiledRule(rule_type, value, IP_NETWORK, network)
        if value.endswith("*"):
            return CompiledRule(rule_type, value, IP_PREFIX, value[:-1])
        return CompiledRule(rule_type, value, IP_EXACT, value)
    if rule_type == RULE_TYPE_PATH:
        if value.endswith("*"):
            return CompiledRule(rule_type, value, PATH_PREFIX, value[:-1])
        return CompiledRule(rule_type, value, PATH_EXACT, value)
    if rule_type in USER_AGENT_RULE_TYPES:
        if parsed is None:
            parsed = validate_rule(rule_type, value)
        kind = UA_SUBSTRING if parsed.kind == "substring" else UA_REGEX
        return CompiledRule(rule_type, value, kind, parsed.target)
    raise ValueError("not a client rule type: {!r}".format(rule_type))


@functools.lru_cache(maxsize=64)
def _compile_prefilter(pattern: str):
    options = re2.Options()
    options.case_sensitive = False
    options.log_errors = False
    options.max_mem = PREFILTER_MAX_MEM
    return re2.compile(pattern, options)


def _build_user_agent_prefilters(rules):
    """
    Case-insensitive RE2 alternations of the User-Agent rules, in chunks of at
    most PREFILTER_CHUNK_PROGRAM_SIZE, or None (no rules, or they cannot be
    compiled: the per-rule loop is then always used). They may only be used on
    ASCII User-Agents: there Python's lower() and RE2's case folding agree, so
    "no prefilter matches" proves no rule matches.
    """
    chunks, current, size = [], [], 0
    for rule in rules:
        if rule.kind == UA_SUBSTRING:
            part, cost = re2.escape(rule.target), 2 * len(rule.target) + 4
        else:
            part, cost = "(?:{})".format(rule.target.pattern), rule.target.programsize + 4
        if current and size + cost > PREFILTER_CHUNK_PROGRAM_SIZE:
            chunks.append(current)
            current, size = [], 0
        current.append(part)
        size += cost
    if current:
        chunks.append(current)
    if not chunks:
        return None
    try:
        return tuple(_compile_prefilter("|".join(parts)) for parts in chunks)
    except re2.error:
        logger.warning(
            "[RuleSet] User-Agent prefilter disabled: the %s rules could not be compiled into "
            "prefilters; rules are still applied one by one", len(rules),
        )
        return None


class RuleSet:
    """Enabled, valid rules compiled for matching; immutable once built."""

    def __init__(self, client_rules=(), host_rules=(), token=None, use_prefilter=True):
        self.client_rules = tuple(client_rules)
        self.host_rules = tuple(host_rules)
        self.token = token
        self.ip_path_rules = tuple(r for r in self.client_rules if r.rule_type in (RULE_TYPE_IP, RULE_TYPE_PATH))
        self.user_agent_rules = tuple(r for r in self.client_rules if r.rule_type in USER_AGENT_RULE_TYPES)
        self.user_agent_prefilters = (
            _build_user_agent_prefilters(self.user_agent_rules) if use_prefilter else None
        )
        self.has_network_rules = any(r.kind == IP_NETWORK for r in self.client_rules)

    def __len__(self):
        return len(self.client_rules) + len(self.host_rules)

    def match_client(self, ip: str, path: str, user_agent: str = "") -> Optional[Tuple[str, str]]:
        """(rule_type, value) of the first client rule matching, in rule order, else None."""
        if not self.client_rules:
            return None
        user_agent = user_agent or ""
        if self.user_agent_rules and self.user_agent_prefilters is not None and user_agent.isascii():
            if not any(prefilter.search(user_agent) is not None for prefilter in self.user_agent_prefilters):
                # No User-Agent rule can match: only IP/path rules are left.
                return self._first_match(self.ip_path_rules, ip, path, user_agent)
        return self._first_match(self.client_rules, ip, path, user_agent)

    def _first_match(self, rules, ip, path, user_agent):
        address = None
        address_parsed = False
        user_agent_lower = None
        for rule in rules:
            kind, target = rule.kind, rule.target
            if kind == IP_EXACT:
                matched = ip == target
            elif kind == IP_PREFIX:
                matched = ip.startswith(target)
            elif kind == IP_NETWORK:
                if not address_parsed:
                    address = _parse_client_ip(ip)
                    address_parsed = True
                # Mixed IPv4/IPv6 comparisons are simply False.
                matched = address is not None and address in target
            elif kind == PATH_EXACT:
                matched = path == target
            elif kind == PATH_PREFIX:
                matched = path.startswith(target)
            elif kind == UA_SUBSTRING:
                if user_agent_lower is None:
                    user_agent_lower = user_agent.lower()
                matched = target in user_agent_lower
            else:  # UA_REGEX
                matched = target.search(user_agent) is not None
            if matched:
                return rule.rule_type, rule.value
        return None


def _parse_client_ip(ip):
    try:
        return ipaddress.ip_address((ip or "").strip())
    except ValueError:
        logger.warning("[RuleSet] Client IP is not an IP address | ip=%r", ip)
        return None


# --- building from the database -----------------------------------------------------------

def build_ruleset(report_invalid, token=None, use_prefilter=True) -> RuleSet:
    """
    Compile the enabled database rules. ``report_invalid(rule, error)`` is
    called for every rule that is invalid in this version (it is skipped).
    """
    from middleman.models import BlacklistRule

    client, host = [], []
    rules = BlacklistRule.objects.filter(
        enabled=True, rule_type__in=CLIENT_RULE_TYPES + HOST_RULE_TYPES
    ).order_by("rule_type", "value")
    for rule in rules:
        try:
            parsed = rule.parse()
        except InvalidRuleError as error:
            report_invalid(rule, error)
            continue
        if rule.rule_type in HOST_RULE_TYPES:
            host.append(HostRuleEntry(rule.value, parsed))
        else:
            client.append(compile_client_rule(rule.rule_type, rule.value, parsed))
    return RuleSet(client, host, token=token, use_prefilter=use_prefilter)


# --- cross-process version token and the per-process cache ---------------------------------

def current_token() -> Optional[str]:
    """The rule set's version token (one primary-key lookup), None if never written."""
    from middleman.models import RuleSetVersion

    return (
        RuleSetVersion.objects.filter(name=RULESET_VERSION_NAME).values_list("token", flat=True).first()
    )


def bump_version(**kwargs) -> None:
    """
    Rules changed: publish a new random token (other processes recompile on
    their next request) and drop this process's cache. Connected to
    BlacklistRule post_save / post_delete. A random token, unlike a counter,
    can never repeat after a rollback or a database restore.
    """
    from middleman.models import RuleSetVersion

    invalidate_cache()
    token = uuid.uuid4().hex
    updated = RuleSetVersion.objects.filter(name=RULESET_VERSION_NAME).update(token=token)
    if not updated:
        RuleSetVersion.objects.update_or_create(name=RULESET_VERSION_NAME, defaults={"token": token})


_cache_lock = threading.Lock()
_cache = {"ruleset": None, "loaded_at": 0.0}


def invalidate_cache(**kwargs) -> None:
    with _cache_lock:
        _cache["ruleset"] = None


def cached_ruleset(report_invalid) -> RuleSet:
    """
    The compiled rules, recompiled when the version token changed (another
    process or this one changed a rule) or the cache is older than
    MAX_AGE_SECONDS. Database errors propagate (the caller fails closed).
    """
    token = current_token()
    now = time.monotonic()
    with _cache_lock:
        ruleset, loaded_at = _cache["ruleset"], _cache["loaded_at"]
    if ruleset is not None and ruleset.token == token and now - loaded_at < MAX_AGE_SECONDS:
        return ruleset
    started = time.perf_counter()
    ruleset = build_ruleset(report_invalid, token=token)
    logger.debug(
        "[RuleSet] Compiled blacklist rules | client_rules=%s host_rules=%s user_agent_prefilters=%s "
        "token=%s duration_ms=%.1f",
        len(ruleset.client_rules), len(ruleset.host_rules), len(ruleset.user_agent_prefilters or ()),
        token, (time.perf_counter() - started) * 1000,
    )
    with _cache_lock:
        _cache["ruleset"], _cache["loaded_at"] = ruleset, now
    return ruleset
