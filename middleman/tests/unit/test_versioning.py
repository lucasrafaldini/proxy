import hashlib
import io
import os
import subprocess
import sys
from unittest.mock import Mock, patch

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import RequestFactory, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from middleman import services
from middleman.models import AccessEntry, BlacklistRule
from middleman.services import ProxyManager
from middleman.tests.utils.auth import logged_in_client
from middleman.version import LEGACY_VERSION, __version__


def legacy_rule(rule_type, value, enabled=True):
    """A rule as an older version could have stored it (no validation)."""
    rule = BlacklistRule.objects.create(rule_type=rule_type, value=value, enabled=enabled)
    BlacklistRule.objects.filter(pk=rule.pk).update(created_by_version=LEGACY_VERSION)
    rule.refresh_from_db()
    return rule


class VersionStampTest(TestCase):
    def test_new_rows_are_stamped_with_the_running_version(self):
        rule = BlacklistRule.objects.create(rule_type="ip", value="10.0.0.1")
        entry = AccessEntry.objects.create(key="k", ip="10.0.0.1", path="a/")
        self.assertEqual(rule.created_by_version, __version__)
        self.assertEqual(entry.created_by_version, __version__)
        self.assertFalse(rule.is_legacy)
        self.assertFalse(entry.is_legacy)

    def test_legacy_rows_are_recognizable(self):
        self.assertTrue(legacy_rule("ip", "10.0.0.1").is_legacy)

    def test_registry_api_exposes_version_read_only(self):
        entry = AccessEntry.objects.create(key="k", ip="10.0.0.1", path="a/")
        client = logged_in_client()

        response = client.patch(
            reverse("registry"),
            {"key": "k", "action": "reset_already_requested", "created_by_version": "9.9.9"},
            format="json",
        )

        self.assertEqual(response.json()["created_by_version"], __version__)
        entry.refresh_from_db()
        self.assertEqual(entry.created_by_version, __version__)

    def test_insights_reports_version_and_legacy_entries(self):
        AccessEntry.objects.create(key="new", ip="1.1.1.1", path="a/")
        old = AccessEntry.objects.create(key="old", ip="1.1.1.2", path="a/")
        AccessEntry.objects.filter(pk=old.pk).update(created_by_version=LEGACY_VERSION)

        data = APIClient().get(reverse("insights")).json()

        self.assertEqual(data["proxy_version"], __version__)
        self.assertEqual(data["legacy_entries"], 1)

    def test_log_lines_carry_the_version(self):
        self.assertIn("[proxy v{}]".format(__version__), settings.LOGGING["formatters"]["standard"]["format"])


class InvalidLegacyRuleRuntimeTest(TestCase):
    """Invalid rules are never applied, and are reported once with their origin."""

    def setUp(self):
        services._REPORTED_INVALID_RULES.clear()
        self.proxy_manager = ProxyManager("https://target.example/index/")
        self.request = RequestFactory().get("/proxy/index/", REMOTE_ADDR="10.0.0.9")

    def _access(self):
        with patch.object(self.proxy_manager, "do_request", return_value=Mock(status_code=200)):
            return self.proxy_manager.access_filter(self.request, "index/")

    def test_invalid_legacy_rule_is_skipped_and_reported_once(self):
        rule = legacy_rule("ip", "10.0.0.0/33")

        with self.assertLogs("middleman.services", "WARNING") as logs:
            self._access()
            ProxyManager("https://target.example/index/")._is_blacklisted("10.0.0.9", "index/")

        self.assertEqual(len(logs.records), 1)
        line = logs.output[0]
        for expected in ["id={}".format(rule.pk), "value='10.0.0.0/33'", "created_by_version='pre-2.0.0'",
                         "reason=invalid_subnet", "check_blacklist_rules --disable-invalid"]:
            self.assertIn(expected, line)

    def test_valid_rules_still_apply_next_to_invalid_ones(self):
        legacy_rule("path", "/index/")  # invalid: leading slash
        BlacklistRule.objects.create(rule_type="path", value="index/")

        with self.assertLogs("middleman.services", "WARNING"):
            match = self.proxy_manager._is_blacklisted("10.0.0.9", "index/")
        self.assertEqual(match, ("path", "index/"))

    def test_invalid_setting_rule_is_skipped_and_reported(self):
        with patch("middleman.services.BLACKLISTED_IPS", ["10.0.0", "10.0.0.9"]):
            with self.assertLogs("middleman.services", "WARNING") as logs:
                match = self.proxy_manager._is_blacklisted("10.0.0.9", "index/")
        self.assertEqual(match, ("ip", "10.0.0.9"))
        self.assertIn("source=BLACKLISTED_IPS", logs.output[0])
        self.assertIn("fix the BLACKLISTED_IPS setting", logs.output[0])


class DashboardInvalidRuleTest(TestCase):
    def setUp(self):
        self.client = logged_in_client()

    def test_dashboard_flags_invalid_rules_with_their_version(self):
        legacy_rule("ip", "10.0.0.0/33")

        content = self.client.get(reverse("dashboard")).content.decode()

        self.assertIn("created by v{}".format(LEGACY_VERSION), content)
        self.assertIn("invalid in v{} (invalid_subnet)".format(__version__), content)

    def test_invalid_rule_cannot_be_re_enabled(self):
        rule = legacy_rule("ip", "10.0.0.0/33", enabled=False)

        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.client.post(reverse("dashboard"), {"action": "toggle", "rule_id": rule.pk})

        self.assertEqual(response.status_code, 400)
        rule.refresh_from_db()
        self.assertFalse(rule.enabled)
        self.assertIn("reason=invalid_subnet", logs.output[0])

    def test_invalid_rule_can_be_disabled_and_deleted(self):
        rule = legacy_rule("ip", "10.0.0.0/33")

        with self.assertLogs("middleman.views", "INFO") as logs:
            self.client.post(reverse("dashboard"), {"action": "toggle", "rule_id": rule.pk})
            self.client.post(reverse("dashboard"), {"action": "delete", "rule_id": rule.pk})

        self.assertFalse(BlacklistRule.objects.exists())
        self.assertIn("Disabled blacklist rule", logs.output[0])
        self.assertIn("Deleted blacklist rule", logs.output[1])
        self.assertIn("created_by_version='pre-2.0.0'", logs.output[1])


class CheckBlacklistRulesCommandTest(TestCase):
    def run_command(self, *args):
        out = io.StringIO()
        call_command("check_blacklist_rules", *args, stdout=out)
        return out.getvalue()

    def test_all_valid(self):
        BlacklistRule.objects.create(rule_type="host", value="example.com")
        self.assertIn("All blacklist rules are valid.", self.run_command())

    def test_reports_invalid_rules_and_fails(self):
        rule = legacy_rule("host", "https://example.com/")
        with self.assertRaises(CommandError) as ctx:
            self.run_command()
        self.assertEqual(ctx.exception.returncode, 1)
        rule.refresh_from_db()
        self.assertTrue(rule.enabled)  # reporting never changes data

    def test_report_lists_version_and_reason(self):
        legacy_rule("host", "https://example.com/")
        out = io.StringIO()
        with self.assertRaises(CommandError):
            call_command("check_blacklist_rules", stdout=out)
        self.assertIn("created_by_version=pre-2.0.0 reason=url_not_host", out.getvalue())

    def test_disable_invalid(self):
        bad = legacy_rule("ip", "10.0.0")
        good = BlacklistRule.objects.create(rule_type="ip", value="10.0.0.1")
        self.assertIn("Disabled 1 invalid rule(s).", self.run_command("--disable-invalid"))
        bad.refresh_from_db()
        good.refresh_from_db()
        self.assertFalse(bad.enabled)
        self.assertTrue(good.enabled)

    def test_delete_invalid(self):
        legacy_rule("ip", "10.0.0")
        BlacklistRule.objects.create(rule_type="ip", value="10.0.0.1")
        self.run_command("--delete-invalid")
        self.assertEqual(list(BlacklistRule.objects.values_list("value", flat=True)), ["10.0.0.1"])

    def test_invalid_setting_rules_are_reported(self):
        out = io.StringIO()
        with patch("middleman.management.commands.check_blacklist_rules.BLACKLISTED_PATHS", ["/admin"]):
            with self.assertRaises(CommandError):
                call_command("check_blacklist_rules", stdout=out)
        self.assertIn("setting=BLACKLISTED_PATHS value='/admin' reason=path_leading_slash", out.getvalue())


class DeterministicKeyTest(TestCase):
    def test_key_is_sha256_of_ip_and_path(self):
        expected = hashlib.sha256(b"1.2.3.4@admin/").hexdigest()[:20]
        self.assertEqual(ProxyManager("")._create_unique_key("1.2.3.4", "admin/"), expected)

    def test_key_is_identical_across_processes(self):
        # hash() is randomized per process; the key must not be.
        code = (
            "import os, django; os.environ['DJANGO_SETTINGS_MODULE']='proxy.test_settings'; django.setup();"
            "from middleman.services import ProxyManager;"
            "print(ProxyManager('')._create_unique_key('1.2.3.4', 'admin/'))"
        )
        keys = set()
        for seed in ("1", "2", "3"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            keys.add(subprocess.check_output([sys.executable, "-c", code], env=env, text=True).strip())
        self.assertEqual(keys, {ProxyManager("")._create_unique_key("1.2.3.4", "admin/")})
