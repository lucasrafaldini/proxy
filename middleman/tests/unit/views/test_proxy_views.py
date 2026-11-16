import io
import os
from unittest.mock import Mock, patch

import requests
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from middleman.exceptions import BlacklistedAccessException, ExceededRequestsLimitException
from middleman.models import AccessEntry, BlacklistRule
from middleman.services import ProxyManager
from middleman.tests.utils.blocks import assert_policy_block


class FakeUpstreamResponse:
    status_code = 200
    reason = "OK"

    def __init__(self):
        self.headers = {"content-type": "application/json"}
        self.raw = io.BytesIO(b'{"ok": true}')
        self.closed = False

    def close(self):  # like requests.Response.close
        self.closed = True


def access_filter_with_rate_limit(limit, remaining):
    """Build an access_filter side effect that records rate limit state."""

    def side_effect(manager, request, path):
        manager.rate_limit = {"limit": limit, "remaining": remaining}
        return FakeUpstreamResponse()

    return side_effect

class ProxyViewTest(TestCase):
    """Unit tests for the proxy view."""

    def setUp(self):
        """Set up the tests."""

        self.client = APIClient()
        # Just a placeholder url for testing purposes
        self.base_url = os.environ.get("BASE_TARGET_URL", "https://httpstatuses.com/")
        self.paths = ["100", "200", "300", "400", "500"]

    @patch("middleman.views.ProxyManager.access_filter")
    def test_proxy_view(self, mock_access_filter):
        """Test proxy view"""

        class FakeResponse:
            status_code = 200
            reason = "OK"
            headers = {"content-type": "application/json"}
            raw = io.BytesIO(b'{"ok": true}')

        mock_access_filter.return_value = FakeResponse()

        url = "{}".format(reverse("proxy", kwargs={"path": self.paths[0]}))
        proxy_response = self.client.get(url)

        self.assertEqual(proxy_response.status_code, 200)
        self.assertTrue(proxy_response.streaming)
        mock_access_filter.assert_called()


class ProxyViewRateLimitHeadersTest(TestCase):
    """X-RateLimit-* headers on proxy responses."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("proxy", kwargs={"path": "200"})

    @patch("middleman.views.ProxyManager.access_filter", autospec=True)
    def test_forwards_rate_limit_headers(self, mock_access_filter):
        mock_access_filter.side_effect = access_filter_with_rate_limit(100, 47)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.streaming)
        self.assertEqual(response["X-RateLimit-Limit"], "100")
        self.assertEqual(response["X-RateLimit-Remaining"], "47")
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(b"".join(response.streaming_content), b'{"ok": true}')

    @patch("middleman.views.ProxyManager.access_filter", autospec=True)
    def test_forwards_zero_remaining_on_last_allowed_request(self, mock_access_filter):
        mock_access_filter.side_effect = access_filter_with_rate_limit(10, 0)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["X-RateLimit-Limit"], "10")
        self.assertEqual(response["X-RateLimit-Remaining"], "0")

    @patch("middleman.views.ProxyManager.access_filter")
    def test_omits_headers_when_rate_limit_unknown(self, mock_access_filter):
        mock_access_filter.return_value = FakeUpstreamResponse()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.has_header("X-RateLimit-Limit"))
        self.assertFalse(response.has_header("X-RateLimit-Remaining"))

    @patch("middleman.views.ProxyManager.access_filter", autospec=True)
    def test_exceeded_limit_returns_429_with_headers(self, mock_access_filter):
        def side_effect(manager, request, path):
            manager.rate_limit = {"limit": 100, "remaining": 0}
            raise ExceededRequestsLimitException("127.0.0.1", path)

        mock_access_filter.side_effect = side_effect

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.reason_phrase, "Too Many Requests")
        self.assertTrue(response["Content-Type"].startswith("text/plain"))
        self.assertIn(b"exceeded the allowed requests limit", response.content)
        self.assertEqual(response["X-RateLimit-Limit"], "100")
        self.assertEqual(response["X-RateLimit-Remaining"], "0")
        # Limits never reset on their own, so there is no honest Retry-After.
        self.assertFalse(response.has_header("Retry-After"))

    @patch("middleman.views.ProxyManager.access_filter", autospec=True)
    def test_exceeded_limit_returns_429_even_without_rate_limit_state(self, mock_access_filter):
        mock_access_filter.side_effect = ExceededRequestsLimitException("127.0.0.1", "200/")

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 429)
        self.assertFalse(response.has_header("X-RateLimit-Limit"))

    @patch("middleman.views.ProxyManager.access_filter")
    def test_blacklisted_response_has_no_rate_limit_headers(self, mock_access_filter):
        mock_access_filter.side_effect = BlacklistedAccessException(
            "10.0.0.1", "200/", "ip", "10.0.0.0/24"
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
        self.assertFalse(response.has_header("X-RateLimit-Limit"))
        self.assertFalse(response.has_header("X-RateLimit-Remaining"))

    @patch("middleman.views.ProxyManager.access_filter", side_effect=Exception("boom"))
    def test_generic_failure_has_no_rate_limit_headers(self, _mock_access_filter):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 500)
        self.assertFalse(response.has_header("X-RateLimit-Limit"))


class ProxyViewRateLimitIntegrationTest(TestCase):
    """Headers reflect the stored access entry (only the upstream call is mocked)."""

    ip = "127.0.0.1"  # APIClient's default REMOTE_ADDR

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("proxy", kwargs={"path": "200"})
        self.key = ProxyManager("")._create_unique_key(self.ip, "200/")

    @patch("middleman.services.ProxyManager.do_request")
    def test_headers_count_down_across_requests(self, mock_do_request):
        AccessEntry.objects.create(
            key=self.key, ip=self.ip, path="200/", already_requested=0, max_requests=2
        )
        mock_do_request.side_effect = lambda: FakeUpstreamResponse()

        first = self.client.get(self.url)
        second = self.client.get(self.url)
        third = self.client.get(self.url)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first["X-RateLimit-Limit"], "2")
        self.assertEqual(first["X-RateLimit-Remaining"], "1")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second["X-RateLimit-Remaining"], "0")
        self.assertEqual(third.status_code, 429)
        self.assertEqual(third["X-RateLimit-Limit"], "2")
        self.assertEqual(third["X-RateLimit-Remaining"], "0")
        self.assertEqual(mock_do_request.call_count, 2)

    @patch("middleman.services.ProxyManager.do_request")
    def test_first_request_creates_entry_and_sends_headers(self, mock_do_request):
        mock_do_request.return_value = FakeUpstreamResponse()

        response = self.client.get(self.url)

        entry = AccessEntry.objects.get(key=self.key)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["X-RateLimit-Limit"], str(entry.max_requests))
        self.assertEqual(
            response["X-RateLimit-Remaining"],
            str(entry.max_requests - entry.already_requested),
        )

    @patch("middleman.services.ProxyManager.do_request")
    def test_cidr_rule_blocks_client_with_403(self, mock_do_request):
        BlacklistRule.objects.create(rule_type="ip", value="10.0.0.0/24")

        with self.assertLogs("middleman.views", "WARNING") as logs:
            blocked = self.client.get(self.url, REMOTE_ADDR="10.0.0.42")

        assert_policy_block(self, blocked, logs.output, hidden=["10.0.0.0/24", "10.0.0.42"])
        self.assertIn("rule='10.0.0.0/24'", logs.output[0])
        self.assertFalse(blocked.has_header("X-RateLimit-Limit"))
        mock_do_request.assert_not_called()

        mock_do_request.return_value = FakeUpstreamResponse()
        allowed = self.client.get(self.url, REMOTE_ADDR="10.0.1.42")
        self.assertEqual(allowed.status_code, 200)


@patch("middleman.upstream.get")
@patch("middleman.upstream.head")
class ProxyViewHostRuleTest(TestCase):
    """Host (site) rules through the full view, with only HTTP mocked."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("proxy", kwargs={"path": "200"})

    def _redirect(self, location):
        response = FakeUpstreamResponse()
        response.status_code = 302
        response.headers = {"location": location}
        response.close = lambda: None
        return response

    def test_blocked_target_site_returns_403(self, head, get):
        with patch("middleman.views.BASE_TARGET_URL", "https://target.example/"):
            BlacklistRule.objects.create(rule_type="host", value="target.example")

            with self.assertLogs("middleman.views", "WARNING") as logs:
                response = self.client.get(self.url)

        assert_policy_block(self, response, logs.output, hidden=["target.example", "host rule"])
        self.assertIn("host='target.example' rule='target.example'", logs.output[0])
        self.assertFalse(response.has_header("X-RateLimit-Limit"))
        head.assert_not_called()

    def test_redirect_to_blocked_site_returns_403_and_is_not_counted(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="*.blocked.example")
        head.return_value = FakeUpstreamResponse()
        get.return_value = self._redirect("https://www.blocked.example/landing")

        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.client.get(self.url)

        # The redirect target may be internal: it is only in the log.
        assert_policy_block(self, response, logs.output, hidden=["blocked.example"])
        self.assertIn("host='www.blocked.example'", logs.output[0])
        self.assertEqual(get.call_count, 1)
        # The reserved request was released: nothing counted.
        self.assertEqual(AccessEntry.objects.get().already_requested, 0)

    def test_redirect_to_allowed_site_is_streamed(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="blocked.example")
        head.return_value = FakeUpstreamResponse()
        get.side_effect = [self._redirect("https://mirror.example/200/"), FakeUpstreamResponse()]

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b'{"ok": true}')
        self.assertEqual(response["X-RateLimit-Remaining"], "99")  # this request counted


@patch("middleman.upstream.get")
@patch("middleman.upstream.head")
class ProxyViewStatusCodeTest(TestCase):
    """Each failure maps to one status code; only HTTP is mocked."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("proxy", kwargs={"path": "200"})

    def test_target_unreachable_is_502_and_logged_with_url(self, head, get):
        head.side_effect = requests.ConnectionError("connection refused")

        with self.assertLogs("middleman.services", "ERROR") as logs:
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.content, b"Bad gateway: the target server is not available.")
        self.assertNotIn(b"http", response.content)  # target URL is not leaked
        self.assertIn("Target is not reachable", logs.output[0])
        self.assertIn("error=ConnectionError: connection refused", logs.output[0])
        self.assertIn("url='", logs.output[0])

    def test_target_timeout_is_504(self, head, get):
        head.side_effect = requests.ReadTimeout("read timed out")

        with self.assertLogs("middleman.services", "ERROR") as logs:
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, 504)
        self.assertIn("Target timed out", logs.output[0])
        self.assertIn("timeout=10s", logs.output[0])

    def test_target_failing_availability_check_is_502(self, head, get):
        head.return_value = Mock(status_code=503)

        with self.assertLogs("middleman.services", "ERROR") as logs:
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("method=HEAD status=503", logs.output[0])
        get.assert_not_called()

    def test_too_many_redirects_is_502(self, head, get):
        head.return_value = Mock(status_code=200)
        redirect = FakeUpstreamResponse()
        redirect.status_code = 302
        redirect.headers = {"location": "/loop/"}
        redirect.close = lambda: None
        get.return_value = redirect

        with self.assertLogs("middleman.services", "ERROR") as logs:
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, 502)
        self.assertIn("TooManyRedirects", logs.output[-1])

    def test_upstream_failure_does_not_consume_rate_limit(self, head, get):
        key = ProxyManager("")._create_unique_key("127.0.0.1", "200/")
        AccessEntry.objects.create(key=key, ip="127.0.0.1", path="200/", already_requested=4, max_requests=5)
        head.side_effect = requests.ConnectionError("down")

        with self.assertLogs("middleman.services", "ERROR"):
            self.client.get(self.url)

        self.assertEqual(AccessEntry.objects.get(key=key).already_requested, 4)

    def test_unresolvable_destination_with_ip_host_rule_fails_closed_with_502(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="10.0.0.0/8")

        with patch("middleman.services.system_resolver", return_value=[]):
            with self.assertLogs("middleman.views", "ERROR") as logs:
                response = self.client.get(self.url)

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.content, b"Bad gateway: the destination could not be verified.")
        self.assertIn("rule='10.0.0.0/8'", logs.output[0])
        head.assert_not_called()

    def test_regex_host_rule_blocks_with_403(self, head, get):
        BlacklistRule.objects.create(rule_type="host_re", value=r"(www\.)?blocked\.example")
        head.return_value = FakeUpstreamResponse()
        redirect = FakeUpstreamResponse()
        redirect.status_code = 301
        redirect.headers = {"location": "https://WWW.Blocked.Example/"}
        redirect.close = lambda: None
        get.return_value = redirect

        with self.assertLogs("middleman.views", "WARNING") as logs:
            response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
        self.assertIn("host='www.blocked.example'", logs.output[0])

    def test_storage_failure_is_500_without_internals(self, head, get):
        head.return_value = FakeUpstreamResponse()
        get.return_value = FakeUpstreamResponse()

        with patch("middleman.services.RegistryInterface.get_or_create_access_entry", side_effect=RuntimeError("db down")):
            with self.assertLogs("middleman.services", "ERROR") as logs:
                response = self.client.get(self.url)

        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"db down", response.content)
        self.assertIn("Could not store access entry", logs.output[0])
        self.assertIn("RuntimeError: db down", logs.output[0])  # traceback included

    def test_unexpected_error_is_500_and_logged_with_traceback(self, head, get):
        with patch("middleman.views.ProxyManager.access_filter", side_effect=KeyError("bug")):
            with self.assertLogs("middleman.views", "ERROR") as logs:
                response = self.client.get(self.url)

        self.assertEqual(response.status_code, 500)
        self.assertIn("Traceback", logs.output[0])

    def test_missing_client_address_is_400(self, head, get):
        with self.assertLogs("middleman.client_ip", "ERROR"):
            response = self.client.get(self.url, REMOTE_ADDR="")

        self.assertEqual(response.status_code, 400)

    def test_blocked_and_limited_requests_are_logged_with_context(self, head, get):
        BlacklistRule.objects.create(rule_type="ip", value="10.0.0.0/24")
        key = ProxyManager("")._create_unique_key("127.0.0.1", "200/")
        AccessEntry.objects.create(key=key, ip="127.0.0.1", path="200/", already_requested=5, max_requests=5)

        with self.assertLogs("middleman.views", "WARNING") as logs:
            self.client.get(self.url, REMOTE_ADDR="10.0.0.7")
            self.client.get(self.url)

        self.assertRegex(
            logs.output[0],
            r"client matches a blacklist rule \| ref=[0-9a-f]{12} ip=10\.0\.0\.7 path='200/' rule_type=ip rule='10\.0\.0\.0/24'",
        )
        self.assertIn("rate limit exceeded | ip=127.0.0.1 path='200/' limit=5", logs.output[1])

    def test_successful_request_is_logged_once_with_client_and_limits(self, head, get):
        head.return_value = FakeUpstreamResponse()
        get.return_value = FakeUpstreamResponse()

        with self.assertLogs("middleman", "INFO") as logs:
            response = self.client.get(self.url)

        # One ProxyView line, plus the separate access log line (middleman.access).
        by_logger = {}
        for record in logs.records:
            by_logger.setdefault(record.name, []).append(record.getMessage())
        self.assertEqual(sorted(by_logger), ["middleman.access", "middleman.views"])
        self.assertEqual(len(by_logger["middleman.views"]), 1)
        self.assertIn("[ProxyView] Proxied request | ip=127.0.0.1 path='200/' status=200 limit=100 remaining=99",
                      by_logger["middleman.views"][0])
        self.assertRegex(by_logger["middleman.access"][0], r"^\[Access\] GET '/proxy/200/' 200 \| duration_ms=")
        self.assertRegex(response["X-Request-ID"], r"^[0-9a-f]{12}$")
