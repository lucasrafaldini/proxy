"""
What an attacker with Burp Suite (or curl) can change - request headers,
methods, paths, timing - must not change what the proxy enforces.

Only HTTP to the target is mocked; everything else is the real stack.
"""

import io
from unittest.mock import Mock, patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from middleman import abuse
from middleman.models import AccessEntry
from middleman.services import ProxyManager
from middleman.tests.utils.auth import make_user

URL = "/proxy/home/"
PEER = "198.51.100.20"


def upstream_response(status_code=200, headers=None, body=b"ok"):
    response = Mock(status_code=status_code, reason="OK", raw=io.BytesIO(body))
    response.headers = {"content-type": "text/plain"}
    response.headers.update(headers or {})
    return response


# Request headers an attacker may forge, as WSGI META entries.
FORGERIES = {
    "rate limit headers": {"HTTP_X_RATELIMIT_REMAINING": "9999", "HTTP_X_RATELIMIT_LIMIT": "9999"},
    "IETF RateLimit headers": {"HTTP_RATELIMIT_REMAINING": "9999", "HTTP_RATELIMIT": "limit=9999"},
    "X-Rate-Limit spelling": {"HTTP_X_RATE_LIMIT_REMAINING": "9999"},
    "obfuscated header name": {"HTTP_X_A8F3C1D2": "9999"},
    "X-Forwarded-For": {"HTTP_X_FORWARDED_FOR": "203.0.113.99"},
    "X-Forwarded-For chain": {"HTTP_X_FORWARDED_FOR": "10.0.0.1, 127.0.0.1, 203.0.113.99"},
    "duplicated X-Forwarded-For (joined)": {"HTTP_X_FORWARDED_FOR": "1.1.1.1,2.2.2.2"},
    "X-Real-IP": {"HTTP_X_REAL_IP": "203.0.113.99"},
    "Forwarded": {"HTTP_FORWARDED": "for=203.0.113.99;proto=https"},
    "True-Client-IP / CF": {"HTTP_TRUE_CLIENT_IP": "203.0.113.99", "HTTP_CF_CONNECTING_IP": "203.0.113.99"},
    "X-Client-IP / X-Originating-IP": {"HTTP_X_CLIENT_IP": "203.0.113.99", "HTTP_X_ORIGINATING_IP": "203.0.113.99"},
    "cookie": {"HTTP_COOKIE": "remaining=9999; sessionid=forged"},
    "forged bearer token": {"HTTP_AUTHORIZATION": "Bearer mm_00000000_" + "A" * 43},
    "basic auth": {"HTTP_AUTHORIZATION": "Basic YWRtaW46YWRtaW4="},
    "oversized value": {"HTTP_X_FORWARDED_FOR": "1.1.1.1," * 2000},
    "non-ASCII value": {"HTTP_X_FORWARDED_FOR": "1.1.1.1, ünïcödé"},
    "newline injection": {"HTTP_X_RATELIMIT_REMAINING": "1\r\nX-RateLimit-Remaining: 9999"},
    "method override": {"HTTP_X_HTTP_METHOD_OVERRIDE": "DELETE"},
}


@patch("middleman.upstream.get", side_effect=lambda *a, **k: upstream_response())
@patch("middleman.upstream.head", side_effect=lambda *a, **k: upstream_response())
class ForgedRequestHeadersTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.key = ProxyManager("")._create_unique_key(PEER, "home/")

    def entry(self, used, limit):
        return AccessEntry.objects.create(key=self.key, ip=PEER, path="home/", already_requested=used, max_requests=limit)

    def test_forgeries_do_not_lift_the_limit(self, head, get):
        entry = self.entry(5, 5)
        for label, headers in FORGERIES.items():
            with self.subTest(forgery=label):
                response = self.client.get(URL, REMOTE_ADDR=PEER, **headers)
                self.assertEqual(response.status_code, 429)
                entry.refresh_from_db()
                self.assertEqual(entry.already_requested, 5)
        get.assert_not_called()

    def test_each_request_counts_exactly_once_whatever_is_forged(self, head, get):
        entry = self.entry(0, len(FORGERIES) + 1)
        for used, (label, headers) in enumerate(FORGERIES.items(), start=1):
            with self.subTest(forgery=label):
                response = self.client.get(URL, REMOTE_ADDR=PEER, **headers)
                self.assertEqual(response.status_code, 200)
                entry.refresh_from_db()
                self.assertEqual(entry.already_requested, used)

    def test_forged_identity_never_creates_a_fresh_allowance(self, head, get):
        self.entry(5, 5)
        for value in ["203.0.113.1", "203.0.113.2", "10.0.0.1", "::1"]:
            self.client.get(URL, REMOTE_ADDR=PEER, HTTP_X_FORWARDED_FOR=value, HTTP_X_REAL_IP=value)
        self.assertEqual(AccessEntry.objects.count(), 1)

    def test_forged_values_never_reach_response_headers(self, head, get):
        self.entry(0, 100)
        forged = dict(FORGERIES["rate limit headers"], **FORGERIES["newline injection"])
        response = self.client.get(URL, REMOTE_ADDR=PEER, **forged)
        self.assertEqual(response["X-RateLimit-Remaining"], "99")
        self.assertEqual(response["X-RateLimit-Limit"], "100")
        for name, value in response.items():
            self.assertNotIn("9999", value, name)
            self.assertNotIn("\n", value, name)

    def test_ip_notation_variants_share_one_allowance(self, head, get):
        # Dual-stack sockets report IPv4 clients as ::ffff:a.b.c.d.
        self.entry(5, 5)
        response = self.client.get(URL, REMOTE_ADDR="::ffff:" + PEER)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(AccessEntry.objects.count(), 1)

    def test_query_strings_do_not_create_new_allowances(self, head, get):
        self.entry(5, 5)
        for query in ["?x=1", "?path=other", "?key=anything", "?" + "a=1&" * 50]:
            with self.subTest(query=query):
                self.assertEqual(self.client.get(URL + query, REMOTE_ADDR=PEER).status_code, 429)
        self.assertEqual(AccessEntry.objects.count(), 1)

    def test_other_methods_are_refused_and_not_counted(self, head, get):
        entry = self.entry(0, 5)
        for method in ("post", "put", "patch", "delete"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(URL, REMOTE_ADDR=PEER)
                self.assertEqual(response.status_code, 405)
        entry.refresh_from_db()
        self.assertEqual(entry.already_requested, 0)
        get.assert_not_called()

    def test_forged_host_header_is_rejected_before_anything_else(self, head, get):
        entry = self.entry(0, 5)
        with self.assertLogs("middleman", "WARNING"):
            response = self.client.get(URL, REMOTE_ADDR=PEER, HTTP_HOST="evil.example")
        self.assertEqual(response.status_code, 400)
        entry.refresh_from_db()
        self.assertEqual(entry.already_requested, 0)  # never reached the proxy
        head.assert_not_called()

    def test_zero_limit_refuses_immediately(self, head, get):
        self.entry(0, 0)
        self.assertEqual(self.client.get(URL, REMOTE_ADDR=PEER).status_code, 429)
        get.assert_not_called()


@override_settings(TRUSTED_PROXIES=["10.0.0.2"])
@patch("middleman.upstream.get", side_effect=lambda *a, **k: upstream_response())
@patch("middleman.upstream.head", side_effect=lambda *a, **k: upstream_response())
class BehindTrustedProxyTest(TestCase):
    """Behind a load balancer, the client controls only the left part of X-Forwarded-For."""

    def test_rotating_the_client_written_part_does_not_change_identity(self, head, get):
        client = APIClient()
        key = ProxyManager("")._create_unique_key("203.0.113.7", "home/")
        AccessEntry.objects.create(key=key, ip="203.0.113.7", path="home/", already_requested=5, max_requests=5)
        for spoof in ["1.1.1.1", "2.2.2.2", "1.1.1.1, 3.3.3.3"]:
            with self.subTest(spoof=spoof):
                response = client.get(URL, REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR="{}, 203.0.113.7".format(spoof))
                self.assertEqual(response.status_code, 429)
        self.assertEqual(AccessEntry.objects.count(), 1)


class RaceConditionTest(TestCase):
    """
    Parallel requests at limit - 1 (e.g. Burp Turbo Intruder) must not all pass.
    The second request is issued while the first one is still talking to the
    target - the exact interleaving of a race - without relying on threads.
    """

    def setUp(self):
        self.client = APIClient()
        self.key = ProxyManager("")._create_unique_key(PEER, "home/")

    def test_concurrent_requests_at_limit_minus_one(self):
        entry = AccessEntry.objects.create(key=self.key, ip=PEER, path="home/", already_requested=4, max_requests=5)
        inner_statuses = []
        in_flight = []

        def upstream_get(*args, **kwargs):
            if not in_flight:  # the first request is "in flight": fire more
                in_flight.append(True)
                for _ in range(3):
                    inner_statuses.append(self.client.get(URL, REMOTE_ADDR=PEER).status_code)
            return upstream_response()

        with patch("middleman.upstream.head", side_effect=lambda *a, **k: upstream_response()):
            with patch("middleman.upstream.get", side_effect=upstream_get):
                outer = self.client.get(URL, REMOTE_ADDR=PEER)

        self.assertEqual(outer.status_code, 200)
        self.assertEqual(inner_statuses, [429, 429, 429])
        entry.refresh_from_db()
        self.assertEqual(entry.already_requested, 5)

    def test_first_requests_of_a_new_client_are_each_counted(self):
        statuses = []
        in_flight = []

        def upstream_get(*args, **kwargs):
            if not in_flight:  # only the outer request fires a concurrent one
                in_flight.append(True)
                statuses.append(self.client.get(URL, REMOTE_ADDR=PEER).status_code)
            return upstream_response()

        with patch("middleman.upstream.head", side_effect=lambda *a, **k: upstream_response()):
            with patch("middleman.upstream.get", side_effect=upstream_get):
                self.client.get(URL, REMOTE_ADDR=PEER)

        self.assertEqual(statuses, [200])
        self.assertEqual(AccessEntry.objects.get().already_requested, 2)

    def test_failed_upstream_releases_the_reservation_exactly_once(self):
        import requests

        entry = AccessEntry.objects.create(key=self.key, ip=PEER, path="home/", already_requested=4, max_requests=5)
        with patch("middleman.upstream.head", side_effect=requests.ConnectionError("down")):
            with self.assertLogs("middleman.services", "ERROR"):
                self.assertEqual(self.client.get(URL, REMOTE_ADDR=PEER).status_code, 502)
        entry.refresh_from_db()
        self.assertEqual(entry.already_requested, 4)

    def test_release_never_goes_below_zero(self):
        import requests

        entry = AccessEntry.objects.create(key=self.key, ip=PEER, path="home/", already_requested=0, max_requests=5)

        def head(*args, **kwargs):
            # An operator resets the counter while the request is in flight.
            AccessEntry.objects.filter(pk=entry.pk).update(already_requested=0)
            raise requests.ConnectionError("down")

        with patch("middleman.upstream.head", side_effect=head):
            with self.assertLogs("middleman.services", "ERROR"):
                self.client.get(URL, REMOTE_ADDR=PEER)
        entry.refresh_from_db()
        self.assertEqual(entry.already_requested, 0)


class HeaderIsolationTest(TestCase):
    """Nothing the client sends goes to the target; nothing the target sends leaks back."""

    def test_client_headers_and_cookies_are_not_forwarded_to_the_target(self):
        with patch("middleman.upstream.head", return_value=upstream_response()) as head:
            with patch("middleman.upstream.get", return_value=upstream_response()) as get:
                APIClient().get(URL, REMOTE_ADDR=PEER, HTTP_COOKIE="session=abc",
                                HTTP_AUTHORIZATION="Bearer x", HTTP_X_FORWARDED_FOR="1.2.3.4")
        for call in (head.call_args, get.call_args):
            self.assertEqual(set(call.kwargs) - {"timeout", "stream", "allow_redirects"}, set())

    def test_target_headers_do_not_leak_to_the_client(self):
        hostile = upstream_response(headers={
            "X-RateLimit-Remaining": "9999", "X-RateLimit-Limit": "9999", "Set-Cookie": "admin=1",
            "Server": "secret-internal/1.0", "X-Powered-By": "internal", "Location": "https://evil.example/",
        })
        with patch("middleman.upstream.head", return_value=upstream_response()):
            with patch("middleman.upstream.get", return_value=hostile):
                response = APIClient().get(URL, REMOTE_ADDR=PEER)
        self.assertEqual(response["X-RateLimit-Remaining"], "99")
        for name in ["Set-Cookie", "Server", "X-Powered-By", "Location"]:
            self.assertFalse(response.has_header(name), name)
        self.assertFalse(response.cookies)


class ManagementApiTamperingTest(TestCase):
    """The attack found in the probe: resetting one's own counter through the registry."""

    def setUp(self):
        key = ProxyManager("")._create_unique_key(PEER, "home/")
        self.entry = AccessEntry.objects.create(key=key, ip=PEER, path="home/", already_requested=5, max_requests=5)

    def attempts(self):
        forged_token = "Bearer mm_{}_{}".format("0" * 8, "A" * 43)
        return [
            ("anonymous list", lambda c: c.get("/registry/", REMOTE_ADDR=PEER)),
            ("anonymous reset", lambda c: c.patch("/registry/", {"key": self.entry.key, "action": "reset_already_requested"}, format="json", REMOTE_ADDR=PEER)),
            ("anonymous raise limit", lambda c: c.patch("/registry/", {"key": self.entry.key, "action": "update_max_requests", "max_requests": 10 ** 6}, format="json", REMOTE_ADDR=PEER)),
            ("forged token reset", lambda c: c.patch("/registry/", {"key": self.entry.key, "action": "reset_already_requested"}, format="json", REMOTE_ADDR=PEER, HTTP_AUTHORIZATION=forged_token)),
            ("forged session cookie", lambda c: c.patch("/registry/", {"key": self.entry.key, "action": "reset_already_requested"}, format="json", REMOTE_ADDR=PEER, HTTP_COOKIE="sessionid=forged")),
            ("unhide own headers", lambda c: c.patch("/clients/", {"ip": PEER, "hide_rate_limit_headers": False}, format="json", REMOTE_ADDR=PEER)),
            ("delete blocking rule", lambda c: c.post("/", {"action": "delete", "rule_id": 1}, REMOTE_ADDR=PEER)),
        ]

    def test_every_attempt_is_refused_and_changes_nothing(self):
        client = APIClient()
        for label, attempt in self.attempts():
            with self.subTest(attempt=label):
                with self.assertLogs("middleman", "WARNING"):
                    response = attempt(client)
                self.assertEqual(response.status_code, 401)
        self.entry.refresh_from_db()
        self.assertEqual((self.entry.already_requested, self.entry.max_requests), (5, 5))

    def test_a_valid_token_of_an_unprivileged_user_cannot_reset_either(self):
        from middleman.auth import create_token

        _, token = create_token(make_user("viewer", role="proxy-auditor"), "t")
        response = APIClient().patch("/registry/", {"key": self.entry.key, "action": "reset_already_requested"},
                                     format="json", HTTP_AUTHORIZATION="Bearer " + token)
        self.assertEqual(response.status_code, 403)
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.already_requested, 5)

    def test_repeated_attempts_end_up_hiding_the_attackers_headers(self):
        client = APIClient()
        with self.assertLogs("middleman", "WARNING"):
            for _, attempt in self.attempts() * 2:
                attempt(client)
        self.assertTrue(abuse.hides_rate_limit_headers(PEER))
