"""Runtime allowed hosts: validation, the Host header gate, and the settings endpoint."""

from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.models import Permission
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient

from middleman import hosts
from middleman.auth import create_token
from middleman.exceptions import InvalidRuleError
from middleman.models import AbuseSignal, AllowedHost
from middleman.tests.utils.auth import make_user

URL = "/settings/allowed-hosts/"


class NormalizeAllowedHostTest(SimpleTestCase):
    def test_accepted_and_normalized(self):
        cases = {
            "Example.COM.": "example.com",
            " api.example.com ": "api.example.com",
            ".example.com": ".example.com",
            ".localhost": ".localhost",
            "203.0.113.5": "203.0.113.5",
            "2001:DB8::1": "[2001:db8::1]",
            "[2001:db8:0:0::1]": "[2001:db8::1]",
            "bücher.de": "xn--bcher-kva.de",
            "exаmple.com": "xn--exmple-4nf.com",  # Cyrillic 'а': a different host, never example.com
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(hosts.normalize_allowed_host(raw), expected)

    def test_refused(self):
        cases = {
            "*": "wildcard_all", "*.example.com": "wildcard_all", "": "empty", "  ": "empty",
            ".com": "wildcard_too_broad", "example.com:8000": "has_port", "[::1]:80": "has_port",
            "http://example.com": "not_a_host", "example.com/x": "not_a_host", "user@example.com": "not_a_host",
            "a b.com": "not_a_host", "a.com,b.com": "not_a_host", "example.com\r\nX: y": "not_a_host",
            "2130706433": "non_canonical_ip", "010.0.0.1": "non_canonical_ip", ".10.0.0.1": "ip_wildcard",
            "-bad-.com": "invalid_host", "a..b": "invalid_host", "x" * 254: "too_long",
        }
        for raw, reason in cases.items():
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(InvalidRuleError) as ctx:
                    hosts.normalize_allowed_host(raw)
                self.assertEqual(ctx.exception.reason, reason)
        for raw in [None, 5, ["example.com"], {"host": "x"}]:
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidRuleError):
                    hosts.normalize_allowed_host(raw)

    def test_baseline_parsing(self):
        self.assertEqual(hosts.parse_baseline(None), ["localhost", "127.0.0.1", "[::1]"])
        self.assertEqual(hosts.parse_baseline(" a.com, .b.org ,A.com."), ["a.com", ".b.org"])
        for raw in ['["*"]', "*", "a.com,*", "a.com:80"]:
            with self.subTest(raw=raw):
                with self.assertRaises(InvalidRuleError):
                    hosts.parse_baseline(raw)

    def test_django_check_is_delegated_to_the_first_middleware(self):
        self.assertEqual(settings.ALLOWED_HOSTS[0], "*")  # tests append "testserver"
        self.assertEqual(settings.MIDDLEWARE[0], hosts.MIDDLEWARE_PATH)
        self.assertFalse(getattr(settings, "USE_X_FORWARDED_HOST", False))
        hosts.check_middleware_order(settings.MIDDLEWARE)
        for broken in ([], settings.MIDDLEWARE[1:], settings.MIDDLEWARE[1:] + [hosts.MIDDLEWARE_PATH],
                       # Not even the request-id middleware may run before the Host check.
                       [settings.MIDDLEWARE[1], hosts.MIDDLEWARE_PATH] + settings.MIDDLEWARE[2:]):
            with self.assertRaises(ImproperlyConfigured):
                hosts.check_middleware_order(broken)


class HostGateTest(TestCase):
    """AllowedHostsMiddleware on real requests."""

    def get(self, host, **extra):
        return APIClient().get("/insights/", HTTP_HOST=host, **extra)

    def test_baseline_hosts_in_their_usual_spellings(self):
        for host in ["testserver", "localhost", "localhost:8000", "LOCALHOST.", "127.0.0.1:80", "[::1]", "[::1]:8000"]:
            with self.subTest(host=host):
                self.assertEqual(self.get(host).status_code, 200)

    def test_unknown_and_malformed_hosts_are_rejected(self):
        for host in ["evil.example", "localhost.evil.example", "evil.example:80:90", "local host",
                     "localhost\r\nX-Injected: 1", "@localhost", "localhost@evil.example", "", "xn--exmple-4nf.com",
                     "exаmple.com"]:
            with self.subTest(host=host):
                with self.assertLogs("middleman.hosts", "WARNING"):
                    response = self.get(host)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.content, b"Bad request: invalid Host header.")
                hosts._WARNED_HOSTS.clear()

    def test_rejection_is_logged_once_per_host_and_reported(self):
        with self.assertLogs("middleman.hosts", "WARNING") as logs:
            for _ in range(3):
                self.get("evil.example", REMOTE_ADDR="198.51.100.9")
        self.assertEqual(len(logs.records), 1)
        self.assertIn("host='evil.example' ip=198.51.100.9", logs.output[0])
        self.assertEqual(AbuseSignal.objects.get(ip="198.51.100.9", kind="invalid_host_header").count, 3)

    def test_x_forwarded_host_cannot_smuggle_a_host(self):
        with self.assertLogs("middleman.hosts", "WARNING"):
            self.assertEqual(self.get("evil.example", HTTP_X_FORWARDED_HOST="localhost").status_code, 400)
        self.assertEqual(self.get("localhost", HTTP_X_FORWARDED_HOST="evil.example").status_code, 200)

    def test_runtime_hosts_and_wildcards(self):
        AllowedHost.objects.create(host="api.example.com")
        AllowedHost.objects.create(host=".example.org")
        for host, status in [("api.example.com", 200), ("API.EXAMPLE.COM:443", 200), ("other.example.com", 400),
                             ("example.org", 200), ("a.b.example.org", 200), ("badexample.org", 400)]:
            with self.subTest(host=host):
                hosts._WARNED_HOSTS.clear()
                if status == 400:
                    with self.assertLogs("middleman.hosts", "WARNING"):
                        self.assertEqual(self.get(host).status_code, status)
                else:
                    self.assertEqual(self.get(host).status_code, status)

    def test_changes_apply_immediately_in_this_process(self):
        with self.assertLogs("middleman.hosts", "WARNING"):
            self.assertEqual(self.get("new.example.com").status_code, 400)
        entry = AllowedHost.objects.create(host="new.example.com")
        self.assertEqual(self.get("new.example.com").status_code, 200)
        entry.delete()
        hosts._WARNED_HOSTS.clear()
        with self.assertLogs("middleman.hosts", "WARNING"):
            self.assertEqual(self.get("new.example.com").status_code, 400)

    def test_other_workers_see_changes_within_the_cache_window(self):
        clock = [1000.0]
        with patch("middleman.hosts.time.monotonic", side_effect=lambda: clock[0]):
            hosts.runtime_hosts()  # cached now
            AllowedHost.objects.bulk_create([AllowedHost(host="late.example.com")])  # no signals: another worker
            self.assertNotIn("late.example.com", hosts.runtime_hosts())
            clock[0] += hosts.CACHE_SECONDS
            self.assertIn("late.example.com", hosts.runtime_hosts())

    def test_database_failure_falls_back_to_the_baseline_only(self):
        with patch("middleman.models.AllowedHost.objects.values_list", side_effect=RuntimeError("db down")):
            with self.assertLogs("middleman.hosts", "ERROR") as logs:
                self.assertEqual(hosts.runtime_hosts(), ())
            self.assertIn("Could not load runtime hosts", logs.output[0])
            self.assertTrue(hosts.is_allowed("localhost"))

    def test_unvalidated_hosts_are_never_stored(self):
        with self.assertRaises(InvalidRuleError):
            AllowedHost.objects.create(host="*")
        self.assertEqual(AllowedHost.objects.create(host="MiXeD.Example.com.").host, "mixed.example.com")


class SettingsEndpointPermissionTest(TestCase):
    """Only active staff with the dedicated permission; operators are deliberately excluded."""

    def setUp(self):
        self.identities = {
            "no-role": make_user("nobody", role=None),
            "auditor": make_user("auditor", role="proxy-auditor", is_staff=True),
            "operator": make_user("operator", role="proxy-operator", is_staff=True),
            "settings-admin-not-staff": make_user("nsadmin", role="proxy-settings-admin"),
            "settings-admin": make_user("sadmin", role="proxy-settings-admin", is_staff=True),
            "superuser": make_user("root", role=None, is_staff=True, is_superuser=True),
        }

    def client_for(self, name, via="token"):
        client = APIClient()
        if via == "token":
            _, token = create_token(self.identities[name], "t")
            client.credentials(HTTP_AUTHORIZATION="Bearer " + token)
        else:
            client.force_login(self.identities[name])
        return client

    def test_matrix(self):
        expected = {"no-role": 403, "auditor": 403, "operator": 403, "settings-admin-not-staff": 403,
                    "settings-admin": 201, "superuser": 201}
        for name, status in expected.items():
            for via in ("token", "session"):
                with self.subTest(identity=name, via=via):
                    AllowedHost.objects.all().delete()
                    with self.assertLogs("middleman", "INFO"):
                        response = self.client_for(name, via).post(URL, {"host": "api.example.com"}, format="json")
                    self.assertEqual(response.status_code, status)
        with self.assertLogs("middleman", "WARNING"):
            self.assertEqual(APIClient().post(URL, {"host": "x.example.com"}, format="json").status_code, 401)

    def test_inactive_staff_is_rejected(self):
        user = self.identities["settings-admin"]
        client = self.client_for("settings-admin", via="session")
        user.is_active = False
        user.save()
        with self.assertLogs("middleman", "WARNING"):
            self.assertEqual(client.get(URL).status_code, 401)

    def test_permissions_are_per_method(self):
        user = make_user("viewer", role=None, is_staff=True)
        user.user_permissions.add(Permission.objects.get(codename="view_allowedhost"))
        client = APIClient()
        client.force_login(user)
        self.assertEqual(client.get(URL).status_code, 200)
        with self.assertLogs("middleman", "WARNING"):
            self.assertEqual(client.post(URL, {"host": "a.example.com"}, format="json").status_code, 403)
            self.assertEqual(client.delete(URL, {"host": "a.example.com"}, format="json").status_code, 403)

    def test_method_override_headers_do_not_escalate(self):
        AllowedHost.objects.create(host="keep.example.com")
        user = make_user("adder", role=None, is_staff=True)
        user.user_permissions.add(Permission.objects.get(codename="add_allowedhost"))
        client = APIClient()
        client.force_login(user)
        for header in ("HTTP_X_HTTP_METHOD_OVERRIDE", "HTTP_X_METHOD_OVERRIDE", "HTTP_X_HTTP_METHOD"):
            with self.subTest(header=header):
                with self.assertLogs("middleman", "INFO"):
                    client.post(URL + "?_method=DELETE", {"host": "keep.example.com", "_method": "DELETE"},
                                format="json", **{header: "DELETE"})
        self.assertTrue(AllowedHost.objects.filter(host="keep.example.com").exists())

    def test_denials_feed_abuse_detection(self):
        with self.assertLogs("middleman", "WARNING"):
            self.client_for("operator").post(URL, {"host": "api.example.com"}, format="json")
        self.assertTrue(AbuseSignal.objects.filter(kind="access_denied").exists())
        self.assertFalse(AllowedHost.objects.exists())

    def test_session_requests_need_a_csrf_token(self):
        client = APIClient(enforce_csrf_checks=True)
        client.force_login(self.identities["superuser"])
        with self.assertLogs("middleman", "WARNING"):
            response = client.post(URL, {"host": "api.example.com"}, format="json")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AllowedHost.objects.exists())


class SettingsEndpointBehaviourTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.client.force_login(make_user("sadmin", role="proxy-settings-admin", is_staff=True))

    def call(self, method, data=None, **extra):
        with self.assertLogs("middleman", "INFO"):
            return getattr(self.client, method)(URL, data or {}, format="json", **extra)

    def test_add_list_and_use(self):
        response = self.call("post", {"host": "API.Example.com.", "note": "public API"})
        self.assertEqual(response.status_code, 201)
        self.assertEqual((response.json()["host"], response.json()["created_by"]), ("api.example.com", "sadmin"))
        listing = self.client.get(URL).json()
        self.assertEqual(listing["baseline"], settings.ALLOWED_HOSTS_BASELINE)
        self.assertEqual([h["host"] for h in listing["runtime"]], ["api.example.com"])
        self.assertEqual(APIClient().get("/insights/", HTTP_HOST="api.example.com").status_code, 200)

    def test_add_is_validated_and_explained(self):
        for host, reason in [("*", "wildcard_all"), (".com", "wildcard_too_broad"), ("a.com:80", "has_port"),
                             (["a.com"], "not_a_string"), (None, "not_a_string")]:
            with self.subTest(host=host):
                response = self.call("post", {"host": host})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["reason"], reason)
        self.assertEqual(self.call("post", {"host": "a.example.com", "note": 5}).status_code, 400)
        self.assertFalse(AllowedHost.objects.exists())

    def test_duplicates_in_any_spelling_conflict(self):
        self.call("post", {"host": "api.example.com"})
        for host in ["api.example.com", "API.EXAMPLE.COM.", "localhost", "::1"]:
            with self.subTest(host=host):
                self.assertEqual(self.call("post", {"host": host}).status_code, 409)
        self.assertEqual(AllowedHost.objects.count(), 1)

    def test_rename_and_note(self):
        self.call("post", {"host": "old.example.com"})
        response = self.call("patch", {"host": "old.example.com", "new_host": "new.example.com", "note": "moved"})
        self.assertEqual((response.status_code, response.json()["host"], response.json()["note"]),
                         (200, "new.example.com", "moved"))
        self.assertEqual(list(AllowedHost.objects.values_list("host", flat=True)), ["new.example.com"])
        self.assertEqual(self.call("patch", {"host": "old.example.com"}).status_code, 404)
        self.call("post", {"host": "other.example.com"})
        self.assertEqual(self.call("patch", {"host": "new.example.com", "new_host": "other.example.com"}).status_code, 409)
        self.assertEqual(self.call("patch", {"host": "new.example.com", "new_host": "*"}).status_code, 400)
        self.assertEqual(self.call("patch", {"host": "new.example.com", "force": "yes"}).status_code, 400)

    def test_delete(self):
        self.call("post", {"host": "gone.example.com"})
        self.assertEqual(self.call("delete", {"host": "gone.example.com"}).status_code, 204)
        self.assertEqual(self.call("delete", {"host": "gone.example.com"}).status_code, 404)
        with self.assertLogs("middleman.hosts", "WARNING"):
            self.assertEqual(APIClient().get("/insights/", HTTP_HOST="gone.example.com").status_code, 400)

    def test_delete_by_query_parameter(self):
        self.call("post", {"host": "q.example.com"})
        with self.assertLogs("middleman", "INFO"):
            self.assertEqual(self.client.delete(URL + "?host=q.example.com").status_code, 204)

    def test_baseline_cannot_be_changed_here(self):
        for method, data in [("delete", {"host": "localhost"}), ("patch", {"host": "127.0.0.1", "new_host": "x.example.com"}),
                             ("delete", {"host": "testserver"})]:
            with self.subTest(method=method, data=data):
                response = self.call(method, data)
                self.assertEqual(response.status_code, 400)
                self.assertIn("ALLOWED_HOSTS environment variable", response.json()["detail"])

    def test_cannot_cut_off_the_host_in_use_without_force(self):
        self.call("post", {"host": ".example.com"})
        via = {"HTTP_HOST": "admin.example.com"}
        response = self.call("delete", {"host": ".example.com"}, **via)
        self.assertEqual(response.status_code, 409)
        self.assertIn("force", response.json()["detail"])
        self.assertEqual(self.call("patch", {"host": ".example.com", "new_host": ".example.net"}, **via).status_code, 409)
        self.assertEqual(self.call("delete", {"host": ".example.com", "force": True}, **via).status_code, 204)

    def test_changes_are_audited(self):
        with self.assertLogs("middleman.views", "WARNING") as logs:
            self.client.post(URL, {"host": "audit.example.com", "note": "ticket 7"}, format="json")
            self.client.delete(URL, {"host": "audit.example.com"}, format="json")
        self.assertIn("Added allowed host | host=audit.example.com note='ticket 7' requester=sadmin@127.0.0.1", logs.output[0])
        self.assertIn("Removed allowed host | host=audit.example.com requester=sadmin@127.0.0.1", logs.output[1])

    def test_unsupported_methods(self):
        self.assertEqual(self.client.put(URL, {"host": "a.example.com"}, format="json").status_code, 405)
        self.assertFalse(AllowedHost.objects.exists())


class AllowedHostAdminTest(TestCase):
    def test_admin_validates_and_attributes(self):
        root = make_user("root", role=None, is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_login(root)
        response = client.post("/admin/middleman/allowedhost/add/", {"host": "*", "note": ""})
        self.assertEqual(response.status_code, 200)  # form redisplayed with the error
        self.assertContains(response, "disable the protection")
        client.post("/admin/middleman/allowedhost/add/", {"host": "Admin.Example.com", "note": "via admin"})
        entry = AllowedHost.objects.get()
        self.assertEqual((entry.host, entry.created_by), ("admin.example.com", root))

    def test_operators_do_not_see_it_in_the_admin(self):
        client = APIClient()
        client.force_login(make_user("op", role="proxy-operator", is_staff=True))
        self.assertEqual(client.get("/admin/middleman/allowedhost/").status_code, 403)
