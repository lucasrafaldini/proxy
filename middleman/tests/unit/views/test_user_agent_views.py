"""
user_agent / user_agent_re rules through the real stack: dashboard, proxy,
/registry/, admin and the check_blacklist_rules command. Only HTTP to the
target is mocked.
"""

import io
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.http import HttpResponse
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from middleman.models import AccessEntry, BlacklistRule
from middleman.services import ProxyManager
from middleman.tests.utils.auth import logged_in_client
from middleman.tests.utils.blocks import assert_policy_block
from middleman.version import LEGACY_VERSION

SQLMAP = "sqlmap/1.7.2#stable (https://sqlmap.org)"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
PEER = "198.51.100.7"


def upstream(*args, **kwargs):
    response = Mock(status_code=200, reason="OK", raw=io.BytesIO(b"ok"))
    response.headers = {"content-type": "text/plain"}
    return response


def legacy_rule(rule_type, value, enabled=True):
    rule = BlacklistRule.objects.create(rule_type=rule_type, value=value, enabled=enabled)
    BlacklistRule.objects.filter(pk=rule.pk).update(created_by_version=LEGACY_VERSION)
    rule.refresh_from_db()
    return rule


class DashboardUserAgentRuleTest(TestCase):
    def setUp(self):
        self.client = logged_in_client()  # operator

    def create(self, rule_type, value):
        return self.client.post(reverse("dashboard"), {"action": "create", "rule_type": rule_type, "value": value})

    def test_can_create_both_user_agent_rule_types(self):
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            self.assertEqual(self.create("user_agent", "  sqlmap ").status_code, 200)
            self.assertEqual(self.create("user_agent_re", "^$").status_code, 200)
        self.assertEqual(
            set(BlacklistRule.objects.values_list("rule_type", "value", "enabled")),
            {("user_agent", "sqlmap", True), ("user_agent_re", "^$", True)},
        )

    def test_invalid_user_agent_rules_are_rejected_with_400_and_their_reason(self):
        cases = {
            ("user_agent", "go"): "too_short",
            ("user_agent", "sqlmap*"): "unsupported_wildcard",
            ("user_agent", "bücherbot"): "non_ascii",
            ("user_agent_re", ".*"): "regex_matches_everything",
            ("user_agent_re", "(sqlmap"): "regex_syntax",
            ("user_agent_re", "re:sqlmap"): "regex_prefix",
        }
        for (rule_type, value), reason in cases.items():
            with self.subTest(rule_type=rule_type, value=value):
                with self.assertLogs("middleman.views", "WARNING") as logs:
                    response = self.create(rule_type, value)
                self.assertEqual(response.status_code, 400)
                self.assertIn("Regra inválida", response.content.decode())
                self.assertIn("reason={}".format(reason), logs.output[0])
        self.assertFalse(BlacklistRule.objects.exists())

    def test_value_longer_than_the_column_is_rejected(self):
        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.create("user_agent", "a" * 256)
        self.assertEqual(response.status_code, 400)
        self.assertIn("reason=invalid_field", logs.output[0])
        self.assertFalse(BlacklistRule.objects.exists())

    def test_creating_a_duplicate_keeps_one_rule(self):
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            self.create("user_agent", "sqlmap")
            self.create("user_agent", "sqlmap")
        self.assertEqual(BlacklistRule.objects.count(), 1)

    def test_same_value_can_exist_as_substring_and_regex(self):
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            self.create("user_agent", "sqlmap")
            self.create("user_agent_re", "sqlmap")
        self.assertEqual(BlacklistRule.objects.count(), 2)

    def test_toggle_and_delete(self):
        rule = BlacklistRule.objects.create(rule_type="user_agent_re", value="sqlmap|nikto")
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            self.client.post(reverse("dashboard"), {"action": "toggle", "rule_id": rule.pk})
            rule.refresh_from_db()
            self.assertFalse(rule.enabled)
            self.client.post(reverse("dashboard"), {"action": "toggle", "rule_id": rule.pk})
            rule.refresh_from_db()
            self.assertTrue(rule.enabled)
            self.client.post(reverse("dashboard"), {"action": "delete", "rule_id": rule.pk})
        self.assertFalse(BlacklistRule.objects.exists())

    def test_invalid_legacy_user_agent_rule_cannot_be_re_enabled(self):
        rule = legacy_rule("user_agent", "*bot*", enabled=False)
        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.client.post(reverse("dashboard"), {"action": "toggle", "rule_id": rule.pk})
        self.assertEqual(response.status_code, 400)
        rule.refresh_from_db()
        self.assertFalse(rule.enabled)
        self.assertIn("reason=unsupported_wildcard", logs.output[0])

    def test_dashboard_offers_every_rule_type_and_lists_user_agent_rules(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        BlacklistRule.objects.create(rule_type="user_agent_re", value="^$")
        legacy_rule("user_agent_re", ".*")

        content = self.client.get(reverse("dashboard")).content.decode()

        for value, label in BlacklistRule.RuleType.choices:
            self.assertIn('<option value="{}">{}</option>'.format(value, label), content)
        self.assertIn("3 user-agent rules", content)
        self.assertIn("0 host rules", content)
        self.assertIn("1 invalid", content)
        self.assertIn("sqlmap", content)
        self.assertIn("invalid in v", content)
        self.assertIn("(regex_matches_everything)", content)

    def test_rule_values_are_escaped_on_the_dashboard(self):
        legacy_rule("user_agent", "<script>alert(1)</script>")
        content = self.client.get(reverse("dashboard")).content.decode()
        self.assertNotIn("<script>alert(1)</script>", content)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)

    def test_auditor_cannot_create_user_agent_rules(self):
        auditor = logged_in_client("auditor", role="proxy-auditor")
        with self.assertLogs("middleman.views", "WARNING"):
            response = auditor.post(reverse("dashboard"), {"action": "create", "rule_type": "user_agent", "value": "sqlmap"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(BlacklistRule.objects.exists())

    def test_anonymous_visitors_do_not_see_user_agent_rules(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="secretscanner")
        content = APIClient().get(reverse("dashboard")).content.decode()
        self.assertNotIn("secretscanner", content)


@patch("middleman.upstream.get", side_effect=upstream)
@patch("middleman.upstream.head", side_effect=upstream)
class ProxyUserAgentBlockTest(TestCase):
    def setUp(self):
        self.operator = logged_in_client()
        self.client = APIClient()
        self.url = reverse("proxy", kwargs={"path": "home"})
        self.key = ProxyManager("")._create_unique_key(PEER, "home/")

    def add_rule(self, rule_type, value):
        self.operator.post(reverse("dashboard"), {"action": "create", "rule_type": rule_type, "value": value})
        return BlacklistRule.objects.get(rule_type=rule_type, value=value)

    def get(self, **meta):
        return self.client.get(self.url, REMOTE_ADDR=PEER, **meta)

    def test_matching_user_agent_gets_a_clean_403(self, head, get):
        self.add_rule("user_agent", "sqlmap")

        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.get(HTTP_USER_AGENT=SQLMAP)

        ref = assert_policy_block(self, response, logs.output, hidden=["sqlmap", "user_agent", PEER])
        self.assertNotIn("X-RateLimit-Limit", response)
        head.assert_not_called()
        get.assert_not_called()
        self.assertIn(
            "[ProxyView] Request blocked: client matches a blacklist rule | ref={} ip=198.51.100.7 path='home/' "
            "rule_type=user_agent rule='sqlmap' user_agent={!r}".format(ref, SQLMAP),
            logs.output[0],
        )

    def test_regex_rule_403_does_not_reveal_the_blocklist(self, head, get):
        self.add_rule("user_agent_re", "nikto|masscan")
        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.get(HTTP_USER_AGENT="Mozilla/5.00 (Nikto/2.5.0)")
        assert_policy_block(self, response, logs.output, hidden=["nikto", "masscan", "Nikto", "user_agent_re"])
        self.assertIn("rule_type=user_agent_re rule='nikto|masscan'", logs.output[0])

    def test_every_block_gets_its_own_reference(self, head, get):
        self.add_rule("user_agent", "sqlmap")
        refs = set()
        for _ in range(3):
            with self.assertLogs("middleman.views", "WARNING") as logs:
                refs.add(assert_policy_block(self, self.get(HTTP_USER_AGENT=SQLMAP), logs.output))
        self.assertEqual(len(refs), 3)

    def test_other_user_agents_are_proxied(self, head, get):
        self.add_rule("user_agent", "sqlmap")
        response = self.get(HTTP_USER_AGENT=BROWSER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b"ok")
        self.assertEqual(response["X-RateLimit-Remaining"], "99")

    def test_missing_user_agent(self, head, get):
        self.add_rule("user_agent", "sqlmap")
        self.assertEqual(self.get().status_code, 200)  # substring rules never match a missing header

        self.add_rule("user_agent_re", "^$")
        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.get()
        self.assertEqual(response.status_code, 403)
        self.assertIn("user_agent=''", logs.output[0])
        with self.assertLogs("middleman.views", "WARNING"):
            self.assertEqual(self.get(HTTP_USER_AGENT="").status_code, 403)

    def test_disabling_the_rule_lets_the_client_through_again(self, head, get):
        rule = self.add_rule("user_agent", "sqlmap")
        with self.assertLogs("middleman.views", "WARNING"):
            self.assertEqual(self.get(HTTP_USER_AGENT=SQLMAP).status_code, 403)
        self.operator.post(reverse("dashboard"), {"action": "toggle", "rule_id": rule.pk})
        self.assertEqual(self.get(HTTP_USER_AGENT=SQLMAP).status_code, 200)

    def test_blocked_requests_never_reach_the_registry(self, head, get):
        self.add_rule("user_agent", "sqlmap")
        for _ in range(3):
            with self.assertLogs("middleman.views", "WARNING"):
                self.get(HTTP_USER_AGENT=SQLMAP)

        registry = self.operator.get(reverse("registry")).json()
        self.assertEqual(registry, [])
        self.assertFalse(AccessEntry.objects.exists())

    def test_registry_entry_is_per_ip_and_path_whatever_the_user_agent(self, head, get):
        self.add_rule("user_agent", "sqlmap")
        for user_agent in (BROWSER, "curl/8.4.0", "python-requests/2.31.0"):
            self.assertEqual(self.get(HTTP_USER_AGENT=user_agent).status_code, 200)
        with self.assertLogs("middleman.views", "WARNING"):
            self.get(HTTP_USER_AGENT=SQLMAP)  # blocked: not counted

        entry = self.operator.get(reverse("registry"), {"key": self.key}).json()
        self.assertEqual(
            (entry["ip"], entry["path"], entry["already_requested"]), (PEER, "home/", 3)
        )
        self.assertEqual(len(self.operator.get(reverse("registry")).json()), 1)
        self.assertNotIn("user_agent", entry)  # the UA is not stored per entry

    def test_registry_reset_does_not_lift_a_user_agent_block(self, head, get):
        self.add_rule("user_agent", "sqlmap")
        self.get(HTTP_USER_AGENT=BROWSER)
        self.operator.patch(reverse("registry"), {"key": self.key, "action": "reset_already_requested"}, format="json")
        with self.assertLogs("middleman.views", "WARNING"):
            self.assertEqual(self.get(HTTP_USER_AGENT=SQLMAP).status_code, 403)


class AdminUserAgentRuleTest(TestCase):
    def setUp(self):
        self.client = logged_in_client("admin", role=None, is_staff=True, is_superuser=True)

    def add(self, rule_type, value):
        return self.client.post(
            "/admin/middleman/blacklistrule/add/", {"rule_type": rule_type, "value": value, "enabled": "on"}
        )

    def test_admin_creates_valid_user_agent_rules(self):
        self.assertEqual(self.add("user_agent_re", "sqlmap|nikto").status_code, 302)
        self.assertTrue(BlacklistRule.objects.filter(rule_type="user_agent_re", value="sqlmap|nikto").exists())

    def test_admin_rejects_invalid_user_agent_rules(self):
        response = self.add("user_agent", "go")
        self.assertEqual(response.status_code, 200)  # form redisplayed with the error
        self.assertContains(response, "too short")
        self.assertFalse(BlacklistRule.objects.exists())

    def test_admin_list_shows_validity_and_filters_by_type(self):
        legacy_rule("user_agent_re", ".*")
        response = self.client.get("/admin/middleman/blacklistrule/", {"rule_type": "user_agent_re"})
        self.assertContains(response, "no (regex_matches_everything)")
        self.assertContains(response, "User-Agent (regex)")


class CheckBlacklistRulesUserAgentTest(TestCase):
    def run_command(self, *args):
        out = io.StringIO()
        call_command("check_blacklist_rules", *args, stdout=out)
        return out.getvalue()

    def test_valid_user_agent_rules_pass(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        BlacklistRule.objects.create(rule_type="user_agent_re", value="^$")
        self.assertIn("All blacklist rules are valid.", self.run_command())

    def test_invalid_user_agent_rules_are_reported_with_reason_and_version(self):
        legacy_rule("user_agent", "*bot*")
        legacy_rule("user_agent_re", ".*")
        out = io.StringIO()
        with self.assertRaises(CommandError) as ctx:
            call_command("check_blacklist_rules", stdout=out)
        self.assertEqual(ctx.exception.returncode, 1)
        report = out.getvalue()
        self.assertIn("type=user_agent value='*bot*' enabled=True created_by_version=pre-2.0.0 "
                      "reason=unsupported_wildcard", report)
        self.assertIn("type=user_agent_re value='.*' enabled=True created_by_version=pre-2.0.0 "
                      "reason=regex_matches_everything", report)

    def test_disable_invalid_only_touches_invalid_user_agent_rules(self):
        bad = legacy_rule("user_agent", "go")
        good = BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        self.assertIn("Disabled 1 invalid rule(s).", self.run_command("--disable-invalid"))
        bad.refresh_from_db()
        good.refresh_from_db()
        self.assertFalse(bad.enabled)
        self.assertTrue(good.enabled)

    def test_delete_invalid(self):
        legacy_rule("user_agent_re", "(sqlmap")
        BlacklistRule.objects.create(rule_type="user_agent_re", value="sqlmap")
        self.run_command("--delete-invalid")
        self.assertEqual(list(BlacklistRule.objects.values_list("value", flat=True)), ["sqlmap"])


class UserAgentSettingsVisibilityTest(TestCase):
    def test_dashboard_counts_setting_rules(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        with patch("middleman.views.BLACKLISTED_USER_AGENTS", ["nikto"]), \
                patch("middleman.views.BLACKLISTED_USER_AGENTS_RE", ["^$", "masscan"]):
            content = logged_in_client().get(reverse("dashboard")).content.decode()
        self.assertIn("4 rules", content)
        self.assertIn("4 user-agent rules", content)

    def test_check_command_reports_invalid_setting_entries(self):
        command = "middleman.management.commands.check_blacklist_rules."
        out = io.StringIO()
        with patch(command + "BLACKLISTED_USER_AGENTS", ["sqlmap", "bot*"]), \
                patch(command + "BLACKLISTED_USER_AGENTS_RE", ["(nikto"]):
            with self.assertRaises(CommandError):
                call_command("check_blacklist_rules", stdout=out)
        report = out.getvalue()
        self.assertIn("setting=BLACKLISTED_USER_AGENTS value='bot*' reason=unsupported_wildcard", report)
        self.assertIn("setting=BLACKLISTED_USER_AGENTS_RE value='(nikto' reason=regex_syntax", report)
        self.assertNotIn("'sqlmap'", report)

    def test_check_command_accepts_valid_setting_entries(self):
        command = "middleman.management.commands.check_blacklist_rules."
        out = io.StringIO()
        with patch(command + "BLACKLISTED_USER_AGENTS", ["sqlmap"]), \
                patch(command + "BLACKLISTED_USER_AGENTS_RE", ["^$"]):
            call_command("check_blacklist_rules", stdout=out)
        self.assertIn("All blacklist rules are valid.", out.getvalue())


class CheckBlacklistRulesUnknownTypeTest(TestCase):
    """Rules from a newer version (after a rollback) are reported but never destroyed by default."""

    def setUp(self):
        # Stored without validation, as a newer version would have written it.
        self.future = BlacklistRule.objects.create(rule_type="country", value="XX")
        BlacklistRule.objects.filter(pk=self.future.pk).update(created_by_version="9.0.0")
        self.bad = legacy_rule("user_agent", "go")

    def run_command(self, *args):
        out = io.StringIO()
        call_command("check_blacklist_rules", *args, stdout=out)
        return out.getvalue()

    def test_report_flags_unknown_types_and_fails(self):
        out = io.StringIO()
        with self.assertRaises(CommandError) as ctx:
            call_command("check_blacklist_rules", stdout=out)
        self.assertIn("2 invalid rule(s)", str(ctx.exception))
        self.assertIn("type=country value='XX' enabled=True created_by_version=9.0.0: rule type unknown to v",
                      out.getvalue())
        self.assertIn("(probably from a newer version); not applied, kept", out.getvalue())

    def test_delete_invalid_keeps_unknown_types(self):
        report = self.run_command("--delete-invalid")
        self.assertIn("Deleted 1 invalid rule(s).", report)
        self.assertIn("Kept 1 rule(s) of unknown types; add --include-unknown-types to delete them too.", report)
        self.assertEqual(list(BlacklistRule.objects.values_list("rule_type", flat=True)), ["country"])

    def test_disable_invalid_keeps_unknown_types_enabled(self):
        report = self.run_command("--disable-invalid")
        self.assertIn("add --include-unknown-types to disable them too.", report)
        self.future.refresh_from_db()
        self.bad.refresh_from_db()
        self.assertTrue(self.future.enabled)
        self.assertFalse(self.bad.enabled)

    def test_include_unknown_types_acts_on_them_explicitly(self):
        self.assertIn("Deleted 2 invalid rule(s).", self.run_command("--delete-invalid", "--include-unknown-types"))
        self.assertFalse(BlacklistRule.objects.exists())
