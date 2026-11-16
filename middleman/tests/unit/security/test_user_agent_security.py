"""
The User-Agent is written by the client. What a client can do with it (vary
its case, pad it, rotate it, inject line breaks, send huge or binary values)
must not bypass a User-Agent rule, evade the rate limit, break the proxy or
forge log lines. Only HTTP to the target is mocked.
"""

import io
import time
from unittest.mock import Mock, patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from middleman.models import AbuseSignal, AccessEntry, BlacklistRule
from middleman.services import ProxyManager

URL = "/proxy/home/"
PEER = "203.0.113.50"


def upstream(*args, **kwargs):
    response = Mock(status_code=200, reason="OK", raw=io.BytesIO(b"ok"))
    response.headers = {"content-type": "text/plain"}
    return response


@patch("middleman.upstream.get", side_effect=upstream)
@patch("middleman.upstream.head", side_effect=upstream)
class UserAgentEvasionTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        BlacklistRule.objects.create(rule_type="user_agent_re", value=r"^python-requests/|nikto")

    def get(self, user_agent, **meta):
        return self.client.get(URL, REMOTE_ADDR=PEER, HTTP_USER_AGENT=user_agent, **meta)

    def test_case_padding_and_embedding_do_not_bypass(self, head, get):
        for user_agent in [
            "SQLMAP/1.7", "SqLmAp", "Mozilla/5.0 (compatible; sqlmap)", " " * 5000 + "sqlmap",
            "A" * 20000 + "sqlmap", "x, sqlmap/1.7",  # two User-Agent headers joined by the server
            "PYTHON-REQUESTS/2.31", "Mozilla/5.00 (Nikto/2.5.0)",
        ]:
            with self.subTest(user_agent=user_agent[-40:]):
                with self.assertLogs("middleman.views", "WARNING"):
                    self.assertEqual(self.get(user_agent).status_code, 403)
        get.assert_not_called()

    def test_anchored_regex_is_exact_about_its_anchor(self, head, get):
        # "^python-requests/" only blocks clients that start with it.
        self.assertEqual(self.get("my-app/1.0 python-requests/2.31").status_code, 200)

    def test_forwarding_headers_do_not_change_the_user_agent_check(self, head, get):
        with self.assertLogs("middleman", "WARNING"):
            response = self.get("sqlmap/1.7", HTTP_X_FORWARDED_FOR="10.9.9.9", HTTP_X_USER_AGENT="Mozilla/5.0")
        self.assertEqual(response.status_code, 403)

    def test_line_breaks_in_the_user_agent_cannot_forge_log_lines(self, head, get):
        forged = "sqlmap\n2026-01-01 INFO middleman.views [ProxyView] Proxied request | ip=1.2.3.4"
        with self.assertLogs("middleman.views", "WARNING") as logs:
            self.get(forged)
        self.assertEqual(len(logs.records), 1)
        self.assertNotIn("\n", logs.output[0])
        self.assertIn("\\n2026-01-01", logs.output[0])  # escaped by %r

    def test_huge_user_agent_is_truncated_in_logs_and_never_echoed(self, head, get):
        huge = "sqlmap" + "B" * 100_000
        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.get(huge)
        self.assertEqual(response.status_code, 403)
        self.assertLess(len(logs.output[0]), 1000)
        self.assertIn("(+99806 chars)", logs.output[0])
        self.assertNotIn(b"BBBB", response.content)

    def test_binary_and_non_ascii_user_agents_are_handled(self, head, get):
        with self.assertLogs("middleman.views", "WARNING"):
            self.assertEqual(self.get("\xff\xfe\x00sqlmap\xe9").status_code, 403)
        self.assertEqual(self.get("Caf\xe9Browser/1.0 \xff").status_code, 200)

    def test_regex_rule_is_linear_on_hostile_user_agents(self, head, get):
        BlacklistRule.objects.create(rule_type="user_agent_re", value=r"(a+)+b")
        started = time.perf_counter()
        self.assertEqual(self.get("a" * 50_000 + "!").status_code, 200)
        self.assertLess(time.perf_counter() - started, 2)


@patch("middleman.upstream.get", side_effect=upstream)
@patch("middleman.upstream.head", side_effect=upstream)
class UserAgentRateLimitTest(TestCase):
    """The User-Agent is not part of the rate-limit key: rotating it gains nothing."""

    def setUp(self):
        self.client = APIClient()
        key = ProxyManager("")._create_unique_key(PEER, "home/")
        self.entry = AccessEntry.objects.create(key=key, ip=PEER, path="home/", already_requested=0, max_requests=3)

    def test_rotating_the_user_agent_does_not_reset_the_limit(self, head, get):
        statuses = [
            self.client.get(URL, REMOTE_ADDR=PEER, HTTP_USER_AGENT="client-{}".format(n)).status_code
            for n in range(6)
        ]
        self.assertEqual(statuses, [200, 200, 200, 429, 429, 429])
        self.assertEqual(AccessEntry.objects.count(), 1)
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.already_requested, 3)

    def test_blocked_user_agents_do_not_consume_the_limit(self, head, get):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        for _ in range(5):
            with self.assertLogs("middleman.views", "WARNING"):
                self.client.get(URL, REMOTE_ADDR=PEER, HTTP_USER_AGENT="sqlmap")
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.already_requested, 0)
        self.assertEqual(self.client.get(URL, REMOTE_ADDR=PEER, HTTP_USER_AGENT="Mozilla/5.0").status_code, 200)


@patch("middleman.upstream.get", side_effect=upstream)
@patch("middleman.upstream.head", side_effect=upstream)
class UserAgentAbuseSignalTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")

    def test_user_agent_blocks_count_as_blacklist_hits(self, head, get):
        for _ in range(3):
            with self.assertLogs("middleman.views", "WARNING"):
                self.client.get(URL, REMOTE_ADDR=PEER, HTTP_USER_AGENT="sqlmap")
        signal = AbuseSignal.objects.get(ip=PEER)
        self.assertEqual((signal.kind, signal.count), ("blacklist_hit", 3))

    def test_allowed_user_agents_record_nothing(self, head, get):
        self.client.get(URL, REMOTE_ADDR=PEER, HTTP_USER_AGENT="Mozilla/5.0")
        self.assertFalse(AbuseSignal.objects.exists())

    @override_settings(ABUSE_DETECTION={"THRESHOLD": 3})
    def test_repeated_user_agent_blocks_hide_the_rate_limit_headers(self, head, get):
        for _ in range(3):
            with self.assertLogs("middleman", "WARNING"):
                self.client.get(URL, REMOTE_ADDR=PEER, HTTP_USER_AGENT="sqlmap")
        response = self.client.get(URL, REMOTE_ADDR=PEER, HTTP_USER_AGENT="Mozilla/5.0")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("X-RateLimit-Limit", response)
