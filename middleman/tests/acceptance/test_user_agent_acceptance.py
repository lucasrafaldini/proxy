"""
Release acceptance tests for User-Agent blacklist rules (`make test-acceptance`).
"""

import io
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from rest_framework.test import APIClient

from middleman.models import AccessEntry, BlacklistRule
from middleman.services import ProxyManager
from middleman.tests.utils.auth import token_client
from middleman.tests.utils.blocks import assert_policy_block
from middleman.version import LEGACY_VERSION

pytestmark = pytest.mark.acceptance

SQLMAP = "sqlmap/1.7.2#stable (https://sqlmap.org)"
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
PATHS = ["home", "images", "api_v1"]


def upstream_response(*args, **kwargs):
    response = Mock(status_code=200, reason="OK", raw=io.BytesIO(b"upstream body"))
    response.headers = {"content-type": "text/plain"}
    return response


@patch("middleman.upstream.get", side_effect=upstream_response)
@patch("middleman.upstream.head", side_effect=upstream_response)
class UserAgentRuleBlocksProxyRequestsTest(TestCase):
    """A User-Agent rule created via the model or the API blocks matches with 403 and lets others through."""

    def setUp(self):
        self.client = APIClient()

    def get(self, path, user_agent):
        return self.client.get("/proxy/{}/".format(path), HTTP_USER_AGENT=user_agent, REMOTE_ADDR="198.51.100.10")

    def assert_blocked(self, path, user_agent):
        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.get(path, user_agent)
        assert_policy_block(self, response, logs.output)
        return response

    def assert_allowed(self, path, user_agent):
        response = self.get(path, user_agent)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"upstream body")

    def test_substring_rule_created_through_the_model(self, head, get):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        for path in PATHS:
            with self.subTest(path=path):
                self.assert_blocked(path, SQLMAP)
                self.assert_blocked(path, "Mozilla/5.0 (compatible; SQLMap)")
                self.assert_allowed(path, FIREFOX)

    def test_regex_rule_created_through_the_model(self, head, get):
        BlacklistRule.objects.create(rule_type="user_agent_re", value=r"nikto|^python-requests/")
        self.assert_blocked("home", "Mozilla/5.00 (Nikto/2.5.0)")
        self.assert_blocked("home", "python-requests/2.31.0")
        self.assert_allowed("home", "my-app/1.0 python-requests/2.31.0")
        self.assert_allowed("home", FIREFOX)

    def test_rule_created_through_the_api(self, head, get):
        operator, _ = token_client()
        created = operator.post("/", {"action": "create", "rule_type": "user_agent", "value": "python-requests/"})
        self.assertEqual(created.status_code, 200)
        rule = BlacklistRule.objects.get(rule_type="user_agent", value="python-requests/")
        self.assert_blocked("home", "python-requests/2.31.0")
        self.assert_allowed("home", FIREFOX)
        operator.post("/", {"action": "toggle", "rule_id": rule.pk})
        self.assert_allowed("home", "python-requests/2.31.0")

    def test_invalid_rules_are_refused_by_the_api(self, head, get):
        operator, _ = token_client()
        with self.assertLogs("middleman.views", "WARNING"):
            response = operator.post("/", {"action": "create", "rule_type": "user_agent_re", "value": ".*"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(BlacklistRule.objects.exists())

    def test_blocked_requests_never_reach_the_target_nor_count(self, head, get):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        self.assert_blocked("home", SQLMAP)
        head.assert_not_called()
        get.assert_not_called()
        self.assertFalse(AccessEntry.objects.exists())


@patch("middleman.upstream.get", side_effect=upstream_response)
@patch("middleman.upstream.head", side_effect=upstream_response)
class MissingOrEmptyUserAgentTest(TestCase):
    """No User-Agent, an empty one or blanks: never an unhandled exception or a 500, with any rules."""

    RULE_SETS = {
        "no rules": [],
        "substring rule": [("user_agent", "sqlmap")],
        "regex rule": [("user_agent_re", "nikto|masscan")],
        "empty-UA regex": [("user_agent_re", "^$")],
        "every kind": [("user_agent", "sqlmap"), ("user_agent_re", "nikto"), ("user_agent_re", "^$"),
                       ("ip", "203.0.113.0/24"), ("path", "admin/")],
    }
    USER_AGENTS = {"missing": None, "empty": "", "blank": "   "}

    def request(self, user_agent):
        headers = {} if user_agent is None else {"HTTP_USER_AGENT": user_agent}
        return APIClient().get("/proxy/home/", REMOTE_ADDR="198.51.100.11", **headers)

    def test_every_rule_set_with_every_missing_or_empty_user_agent(self, head, get):
        for label, rules in self.RULE_SETS.items():
            BlacklistRule.objects.all().delete()
            for rule_type, value in rules:
                BlacklistRule.objects.create(rule_type=rule_type, value=value)
            for ua_label, user_agent in self.USER_AGENTS.items():
                with self.subTest(rules=label, user_agent=ua_label):
                    blocked_by_empty_rule = ("user_agent_re", "^$") in rules and user_agent in (None, "")
                    with self.assertNoLogs("middleman", "ERROR"):
                        if blocked_by_empty_rule:
                            with self.assertLogs("middleman.views", "WARNING"):
                                response = self.request(user_agent)
                        else:
                            response = self.request(user_agent)
                    self.assertEqual(response.status_code, 403 if blocked_by_empty_rule else 200)

    def test_startup_setting_rules_with_missing_user_agent(self, head, get):
        with patch("middleman.services.BLACKLISTED_USER_AGENTS", ["sqlmap"]), \
                patch("middleman.services.BLACKLISTED_USER_AGENTS_RE", ["nikto"]):
            with self.assertNoLogs("middleman", "ERROR"):
                self.assertEqual(self.request(None).status_code, 200)
                self.assertEqual(self.request("").status_code, 200)

    def test_rule_matching_accepts_a_missing_value_directly(self, head, get):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        BlacklistRule.objects.create(rule_type="user_agent_re", value="^$")
        manager = ProxyManager("http://target.example/home/")
        self.assertEqual(manager._is_blacklisted("198.51.100.11", "home/", None), ("user_agent_re", "^$"))
        self.assertEqual(manager._is_blacklisted("198.51.100.11", "home/", ""), ("user_agent_re", "^$"))


class CheckBlacklistRulesUserAgentTest(TestCase):
    """check_blacklist_rules validates User-Agent rules (database and startup settings)."""

    def run_command(self, *args):
        out = io.StringIO()
        call_command("check_blacklist_rules", *args, stdout=out)
        return out.getvalue()

    def legacy(self, rule_type, value):
        rule = BlacklistRule.objects.create(rule_type=rule_type, value=value)
        BlacklistRule.objects.filter(pk=rule.pk).update(created_by_version=LEGACY_VERSION)
        return rule

    def test_valid_user_agent_rules_pass(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        BlacklistRule.objects.create(rule_type="user_agent_re", value="^$")
        BlacklistRule.objects.create(rule_type="user_agent_re", value=r"nikto|masscan")
        self.assertIn("All blacklist rules are valid.", self.run_command())

    def test_invalid_user_agent_rules_are_reported_with_their_reason(self):
        self.legacy("user_agent", "go")
        self.legacy("user_agent", "bot*")
        self.legacy("user_agent_re", ".*")
        self.legacy("user_agent_re", "(sqlmap")
        out = io.StringIO()
        with self.assertRaises(CommandError) as ctx:
            call_command("check_blacklist_rules", stdout=out)
        self.assertEqual(ctx.exception.returncode, 1)
        for reason in ("too_short", "unsupported_wildcard", "regex_matches_everything", "regex_syntax"):
            self.assertIn("reason={}".format(reason), out.getvalue())

    def test_disable_and_delete_act_only_on_invalid_user_agent_rules(self):
        bad = self.legacy("user_agent", "go")
        good = BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        self.assertIn("Disabled 1 invalid rule(s).", self.run_command("--disable-invalid"))
        bad.refresh_from_db()
        good.refresh_from_db()
        self.assertEqual((bad.enabled, good.enabled), (False, True))
        self.run_command("--delete-invalid")
        self.assertEqual(list(BlacklistRule.objects.values_list("value", flat=True)), ["sqlmap"])

    def test_startup_setting_entries_are_validated(self):
        command = "middleman.management.commands.check_blacklist_rules."
        out = io.StringIO()
        with patch(command + "BLACKLISTED_USER_AGENTS", ["sqlmap", "go"]), \
                patch(command + "BLACKLISTED_USER_AGENTS_RE", ["^$", "(x"]):
            with self.assertRaises(CommandError):
                call_command("check_blacklist_rules", stdout=out)
        self.assertIn("setting=BLACKLISTED_USER_AGENTS value='go' reason=too_short", out.getvalue())
        self.assertIn("setting=BLACKLISTED_USER_AGENTS_RE value='(x' reason=regex_syntax", out.getvalue())


class ManagePyCheckBlacklistRulesTest(TestCase):
    """CLI invocation of `python manage.py check_blacklist_rules` against a migrated database."""

    SCRIPT = textwrap.dedent("""
        import django
        django.setup()
        from django.core.management import call_command
        from middleman.models import BlacklistRule
        call_command("migrate", verbosity=0)
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        BlacklistRule.objects.create(rule_type="user_agent_re", value="^$")
    """)

    def manage(self, tmp, *args, code=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("BLACKLISTED_", "DJANGO_"))}
        env.update(DJANGO_SETTINGS_MODULE="temp_settings", PYTHONPATH=os.pathsep.join([tmp, str(settings.BASE_DIR)]),
                   PYTHONDONTWRITEBYTECODE="1")
        command = [sys.executable, "-c", code] if code else [sys.executable, "manage.py", *args]
        return subprocess.run(command, cwd=settings.BASE_DIR, env=env, capture_output=True, text=True, timeout=120)

    def test_manage_py_check_blacklist_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "temp_settings.py").write_text(
                "from proxy.test_settings import *  # noqa\n"
                "DATABASES = {{'default': {{'ENGINE': 'django.db.backends.sqlite3', 'NAME': {!r}}}}}\n".format(
                    str(Path(tmp, "db.sqlite3")))
            )
            setup = self.manage(tmp, code=self.SCRIPT)
            self.assertEqual(setup.returncode, 0, setup.stderr)

            valid = self.manage(tmp, "check_blacklist_rules")
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertIn("All blacklist rules are valid.", valid.stdout)

            self.manage(tmp, code=(
                "import django; django.setup(); from middleman.models import BlacklistRule as R;"
                "r = R.objects.create(rule_type='user_agent', value='sqlmap-x');"
                "R.objects.filter(pk=r.pk).update(value='go', created_by_version='pre-2.0.0')"
            ))
            invalid = self.manage(tmp, "check_blacklist_rules")
            self.assertEqual(invalid.returncode, 1)
            self.assertIn("type=user_agent value='go'", invalid.stdout)
            self.assertIn("reason=too_short", invalid.stdout)
            self.assertNotIn("Traceback", invalid.stderr)
