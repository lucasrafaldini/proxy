from django.test import TestCase
from django.urls import reverse
from django.http import HttpResponse
from rest_framework.test import APIClient
import io
from unittest.mock import Mock, patch

from middleman.models import BlacklistRule
from middleman.tests.utils.auth import logged_in_client


class BlacklistViewsTest(TestCase):
    def setUp(self):
        self.client = logged_in_client()  # operator: may manage rules

    def test_can_create_blacklist_rule_from_dashboard(self):
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            response = self.client.post(
                reverse("dashboard"),
                data={"action": "create", "rule_type": "path", "value": "admin/*"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(BlacklistRule.objects.count(), 1)
        rule = BlacklistRule.objects.first()
        self.assertEqual(rule.rule_type, "path")
        self.assertEqual(rule.value, "admin/*")

    def test_can_toggle_and_delete_blacklist_rule(self):
        rule = BlacklistRule.objects.create(rule_type="ip", value="10.0.0.*")

        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            toggle_response = self.client.post(
                reverse("dashboard"),
                data={"action": "toggle", "rule_id": rule.id},
            )
        self.assertEqual(toggle_response.status_code, 200)
        rule.refresh_from_db()
        self.assertFalse(rule.enabled)

        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            delete_response = self.client.post(
                reverse("dashboard"),
                data={"action": "delete", "rule_id": rule.id},
            )
        self.assertEqual(delete_response.status_code, 200)
        self.assertEqual(BlacklistRule.objects.count(), 0)
    def test_can_create_host_rule_from_dashboard(self):
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            response = self.client.post(
                reverse("dashboard"),
                data={"action": "create", "rule_type": "host", "value": "*.example.com"},
            )

        self.assertEqual(response.status_code, 200)
        rule = BlacklistRule.objects.get()
        self.assertEqual((rule.rule_type, rule.value), ("host", "*.example.com"))

    def test_invalid_rules_are_rejected_with_400_and_not_saved(self):
        invalid = [("host", "https://example.com/page"), ("host", "re:("), ("ip", "10.0.0.0/33")]
        for rule_type, value in invalid:
            with self.subTest(rule_type=rule_type, value=value):
                with patch("middleman.views.render", return_value=HttpResponse("ok")) as render:
                    self.client.post(
                        reverse("dashboard"),
                        data={"action": "create", "rule_type": rule_type, "value": value},
                    )
                # render() is mocked, so check what the view asked it to render.
                self.assertTrue(render.call_args.args[2]["rule_error"])
                self.assertEqual(render.call_args.kwargs["status"], 400)
        self.assertFalse(BlacklistRule.objects.exists())

    def test_unknown_rule_type_is_ignored(self):
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            self.client.post(
                reverse("dashboard"),
                data={"action": "create", "rule_type": "country", "value": "BR"},
            )
        self.assertFalse(BlacklistRule.objects.exists())

    def test_dashboard_renders_rule_error_and_host_option(self):
        response = self.client.post(
            reverse("dashboard"),
            data={"action": "create", "rule_type": "host", "value": "example.com:8080"},
        )

        self.assertEqual(response.status_code, 400)
        content = response.content.decode()
        self.assertIn('<option value="host">Host (site)</option>', content)
        self.assertIn("Regra inválida", content)
        self.assertIn("ports, paths and user info are not allowed", content)

    def test_can_create_regex_host_rule(self):
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            self.client.post(
                reverse("dashboard"),
                data={"action": "create", "rule_type": "host_re", "value": r"(www\.)?example\.com"},
            )
        rule = BlacklistRule.objects.get()
        self.assertEqual((rule.rule_type, rule.value), ("host_re", r"(www\.)?example\.com"))

    def test_invalid_regex_is_rejected_with_semantic_log(self):
        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.client.post(
                reverse("dashboard"),
                data={"action": "create", "rule_type": "host_re", "value": "example.com"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("for a literal dot", response.content.decode())  # shown to the admin
        self.assertFalse(BlacklistRule.objects.exists())
        self.assertIn(
            "[Dashboard] Rejected blacklist rule | rule_type='host_re' value='example.com' "
            "reason=regex_unescaped_dot",
            logs.output[0],
        )

    def test_each_regex_mistake_is_logged_with_its_reason(self):
        cases = {
            "(example\\.com": "regex_syntax",
            ".*": "regex_matches_everything",
            "bücher\\.de": "regex_non_ascii",
            "re:example\\.com": "regex_prefix",
        }
        for value, reason in cases.items():
            with self.subTest(value=value):
                with self.assertLogs("middleman.views", "WARNING") as logs:
                    self.client.post(
                        reverse("dashboard"), data={"action": "create", "rule_type": "host_re", "value": value}
                    )
                self.assertIn("reason={}".format(reason), logs.output[0])
        self.assertFalse(BlacklistRule.objects.exists())

    def test_user_input_cannot_forge_log_lines(self):
        forged = "x\n2026-01-01 INFO middleman.views [Dashboard] Created blacklist rule"
        with self.assertLogs("middleman.views", "WARNING") as logs:
            self.client.post(reverse("dashboard"), data={"action": "create", "rule_type": "path", "value": forged})
        self.assertEqual(len(logs.records), 1)
        self.assertNotIn("\n", logs.records[0].getMessage())

    def test_rule_changes_are_audited(self):
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            with self.assertLogs("middleman.views", "INFO") as logs:
                self.client.post(reverse("dashboard"), data={"action": "create", "rule_type": "ip", "value": "10.0.0.1"})
        self.assertIn("Created blacklist rule", logs.output[0])
        self.assertIn("requester=operator@127.0.0.1", logs.output[0])  # who and from where

    def test_admin_is_routed_and_requires_login(self):
        response = APIClient().get("/admin/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/login/", response["Location"])


@patch("middleman.services.requests.get")
@patch("middleman.services.requests.head")
class CidrBlacklistForbiddenTest(TestCase):
    """A CIDR rule created on the dashboard blocks every client IP inside the subnet with 403."""

    def setUp(self):
        self.operator = logged_in_client()
        self.proxy_client = APIClient()
        self.url = reverse("proxy", kwargs={"path": "home"})
        self.operator.post(reverse("dashboard"), {"action": "create", "rule_type": "ip", "value": "10.0.0.0/24"})

    @staticmethod
    def upstream(*args, **kwargs):
        response = Mock(status_code=200, reason="OK", raw=io.BytesIO(b"ok"))
        response.headers = {"content-type": "text/plain"}
        return response

    def test_ip_inside_the_blocked_cidr_gets_403_forbidden(self, head, get):
        self.assertTrue(BlacklistRule.objects.filter(rule_type="ip", value="10.0.0.0/24", enabled=True).exists())

        with self.assertLogs("middleman.views", "WARNING"):
            response = self.proxy_client.get(self.url, REMOTE_ADDR="10.0.0.5")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.reason_phrase, "Forbidden")
        self.assertEqual(response.content, b"Access from 10.0.0.5 to home/ blocked by ip rule: 10.0.0.0/24")
        head.assert_not_called()  # the target is never contacted
        get.assert_not_called()

    def test_every_address_of_the_subnet_is_blocked_and_nothing_outside(self, head, get):
        head.side_effect = get.side_effect = self.upstream
        cases = {"10.0.0.0": 403, "10.0.0.1": 403, "10.0.0.128": 403, "10.0.0.255": 403,
                 "10.0.1.0": 200, "10.0.1.5": 200, "9.255.255.255": 200, "192.168.0.5": 200}
        for ip, expected in cases.items():
            with self.subTest(ip=ip):
                if expected == 403:
                    with self.assertLogs("middleman.views", "WARNING"):
                        response = self.proxy_client.get(self.url, REMOTE_ADDR=ip)
                else:
                    response = self.proxy_client.get(self.url, REMOTE_ADDR=ip)
                self.assertEqual(response.status_code, expected)

    def test_spoofed_forwarded_for_cannot_escape_the_cidr_block(self, head, get):
        with self.assertLogs("middleman", "WARNING"):
            response = self.proxy_client.get(self.url, REMOTE_ADDR="10.0.0.5", HTTP_X_FORWARDED_FOR="203.0.113.9")
        self.assertEqual(response.status_code, 403)

    def test_disabling_the_rule_lets_the_ip_through_again(self, head, get):
        head.side_effect = get.side_effect = self.upstream
        rule = BlacklistRule.objects.get(value="10.0.0.0/24")
        self.operator.post(reverse("dashboard"), {"action": "toggle", "rule_id": rule.pk})

        self.assertEqual(self.proxy_client.get(self.url, REMOTE_ADDR="10.0.0.5").status_code, 200)
