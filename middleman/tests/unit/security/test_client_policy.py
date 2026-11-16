"""Per-client policy: an admin hides (or shows) one client's rate limit headers."""

import io
from unittest.mock import Mock, patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from rest_framework.test import APIClient

from middleman import abuse
from middleman.models import AccessEntry, ClientPolicy
from middleman.services import ProxyManager
from middleman.tests.utils.auth import logged_in_client, make_user

PEER = "198.51.100.40"


def upstream_response(*args, **kwargs):
    response = Mock(status_code=200, reason="OK", raw=io.BytesIO(b"ok"))
    response.headers = {"content-type": "text/plain"}
    return response


class ClientPolicyModelTest(TestCase):
    def test_ip_is_stored_canonically(self):
        cases = {"::ffff:198.51.100.40": "198.51.100.40", " 198.51.100.40 ": "198.51.100.40",
                 "2001:DB8:0:0::1": "2001:db8::1"}
        for raw, canonical in cases.items():
            with self.subTest(raw=raw):
                ClientPolicy.objects.all().delete()
                self.assertEqual(ClientPolicy.objects.create(ip=raw).ip, canonical)

    def test_invalid_ip_is_rejected_by_validation(self):
        for raw in ["", "not-an-ip", "10.0.0.0/24", "10.0.0.300"]:
            with self.subTest(raw=raw):
                with self.assertRaises(ValidationError) as ctx:
                    ClientPolicy(ip=raw).full_clean()
                self.assertIn("ip", ctx.exception.message_dict)

    def test_notation_variants_cannot_create_two_policies(self):
        ClientPolicy.objects.create(ip="198.51.100.40")
        with self.assertRaises(Exception):
            ClientPolicy.objects.create(ip="::ffff:198.51.100.40")


class ClientPolicyApiTest(TestCase):
    def setUp(self):
        self.client = logged_in_client()

    def patch_policy(self, **data):
        return self.client.patch("/clients/", data, format="json")

    def test_create_then_update(self):
        with self.assertLogs("middleman.views", "INFO") as logs:
            created = self.patch_policy(ip=PEER, hide_rate_limit_headers=True, reason="ticket 1")
            updated = self.patch_policy(ip=PEER, hide_rate_limit_headers=False)
        self.assertEqual(created.status_code, 201)
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["hide_rate_limit_headers"], False)
        self.assertEqual(updated.json()["updated_by"], "operator")
        self.assertIn("Created client policy | ip={} hide_rate_limit_headers=True source=manual requester=operator@".format(PEER), logs.output[0])

    def test_admin_change_turns_an_automatic_policy_into_a_manual_one(self):
        ClientPolicy.objects.create(ip=PEER, hide_rate_limit_headers=True, source="automatic", reason="abuse")
        data = self.patch_policy(ip=PEER, hide_rate_limit_headers=False, reason="false positive").json()
        self.assertEqual((data["source"], data["reason"]), ("manual", "false positive"))
        # ...and detection no longer touches it.
        with self.assertLogs("middleman.abuse", "INFO"):
            for _ in range(20):
                abuse.report(PEER, [("auth_failure", "")])
        self.assertFalse(ClientPolicy.objects.get(ip=PEER).hide_rate_limit_headers)

    def test_ip_is_canonicalized(self):
        data = self.patch_policy(ip="::ffff:" + PEER, hide_rate_limit_headers=True).json()
        self.assertEqual(data["ip"], PEER)
        self.assertEqual(self.client.get("/clients/", {"ip": "::ffff:" + PEER}).json()["ip"], PEER)

    def test_input_is_strictly_typed(self):
        invalid = [
            ({"hide_rate_limit_headers": True}, "ip"),
            ({"ip": "nope", "hide_rate_limit_headers": True}, "ip"),
            ({"ip": ["1.2.3.4"], "hide_rate_limit_headers": True}, "ip"),
            ({"ip": PEER}, "hide_rate_limit_headers"),
            ({"ip": PEER, "hide_rate_limit_headers": "true"}, "hide_rate_limit_headers"),
            ({"ip": PEER, "hide_rate_limit_headers": 1}, "hide_rate_limit_headers"),
            ({"ip": PEER, "hide_rate_limit_headers": True, "reason": 5}, "reason"),
            ({"ip": PEER, "hide_rate_limit_headers": True, "reason": "x" * 1001}, "reason"),
        ]
        for data, field in invalid:
            with self.subTest(data=str(data)[:60]):
                response = self.patch_policy(**data)
                self.assertEqual(response.status_code, 400)
                self.assertIn(field, response.json())
        self.assertFalse(ClientPolicy.objects.exists())

    def test_get_one_and_list(self):
        self.assertEqual(self.client.get("/clients/", {"ip": PEER}).status_code, 404)
        self.assertEqual(self.client.get("/clients/", {"ip": "garbage"}).status_code, 404)
        self.patch_policy(ip=PEER, hide_rate_limit_headers=True)
        self.patch_policy(ip="198.51.100.41", hide_rate_limit_headers=False)
        self.assertEqual([p["ip"] for p in self.client.get("/clients/").json()], [PEER, "198.51.100.41"])


@patch("middleman.services.requests.get", side_effect=upstream_response)
@patch("middleman.services.requests.head", side_effect=upstream_response)
class HidingEffectTest(TestCase):
    def setUp(self):
        self.proxy_client = APIClient()
        self.admin = logged_in_client()

    def get(self, ip=PEER, path="/proxy/home/"):
        return self.proxy_client.get(path, REMOTE_ADDR=ip)

    def set_hidden(self, hidden):
        self.admin.patch("/clients/", {"ip": PEER, "hide_rate_limit_headers": hidden}, format="json")

    def test_admin_toggles_one_client(self, head, get):
        self.assertTrue(self.get().has_header("X-RateLimit-Remaining"))
        self.set_hidden(True)
        self.assertFalse(self.get().has_header("X-RateLimit-Remaining"))
        self.assertTrue(self.get(ip="198.51.100.99").has_header("X-RateLimit-Remaining"))  # others unaffected
        self.set_hidden(False)
        self.assertTrue(self.get().has_header("X-RateLimit-Remaining"))

    def test_hidden_on_429_too_but_the_limit_is_still_enforced(self, head, get):
        key = ProxyManager("")._create_unique_key(PEER, "home/")
        AccessEntry.objects.create(key=key, ip=PEER, path="home/", already_requested=5, max_requests=5)
        self.set_hidden(True)
        response = self.get()
        self.assertEqual(response.status_code, 429)
        self.assertFalse(response.has_header("X-RateLimit-Limit"))
        # The body says the limit was hit, but reveals no numbers.
        self.assertEqual(response.content, b"Address 198.51.100.40 has exceeded the allowed requests limit for path home/")

    def test_hiding_does_not_change_counting(self, head, get):
        self.set_hidden(True)
        for _ in range(3):
            self.get()
        key = ProxyManager("")._create_unique_key(PEER, "home/")
        self.assertEqual(AccessEntry.objects.get(key=key).already_requested, 3)

    def test_hidden_client_cannot_see_usage_on_the_dashboard_either(self, head, get):
        self.set_hidden(True)
        self.get()
        page = APIClient().get("/", REMOTE_ADDR=PEER).content.decode()
        self.assertNotIn(PEER, page)
        self.assertNotIn("1/100", page)

    def test_operators_still_see_everything(self, head, get):
        self.set_hidden(True)
        self.get()
        auditor = APIClient()
        auditor.force_login(make_user("auditor", role="proxy-auditor"))
        entries = auditor.get("/registry/").json()
        self.assertEqual([(e["ip"], e["already_requested"]) for e in entries], [(PEER, 1)])
