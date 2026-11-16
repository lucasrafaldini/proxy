import ipaddress
import unittest
from unittest.mock import Mock, patch

import pytest
import requests
from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.client import RequestFactory

from middleman.exceptions import (AccessNotRegisteredException,
                                  BlacklistedAccessException,
                                  BlockedDestinationException,
                                  ExceededRequestsLimitException,
                                  ServerNotRespondingException)
from middleman.models import AccessEntry, BlacklistRule
from middleman.rules import parse_ip_network
from middleman.services import ProxyManager
from middleman.tests.utils.factories.access_entry import \
    AccessEntryModelFactory
from middleman.tests.utils.mocked_requests import mock_api_requests
from proxy.settings import BASE_TARGET_URL


class test_proxy_manager(unittest.TestCase):
    def setUp(self):
        self.base_url = BASE_TARGET_URL
        self.path = "index/"
        self.target_url = "{}{}".format(self.base_url, self.path)
        self.proxy_manager = ProxyManager(self.target_url)
        self.request = RequestFactory()

    @pytest.mark.django_db
    def test_create_unique_key(self):
        access_entry = AccessEntryModelFactory.create()
        key = self.proxy_manager._create_unique_key(access_entry.ip, access_entry.path)
        repeated_key = self.proxy_manager._create_unique_key(access_entry.ip, access_entry.path)
        self.assertTrue(len(key) <= 20)
        self.assertEqual(key, repeated_key)

    # def test_do_request(self):

    @patch("requests.get", side_effect=mock_api_requests(200))
    @patch("requests.head", side_effect=mock_api_requests(200))
    @pytest.mark.django_db
    def test_access_filter_pass(self, mock_get, mock_head):
        access_entry = AccessEntryModelFactory.create()

        with patch(
            "middleman.services.ProxyManager._create_unique_key",
            return_value=access_entry.key,
        ) as _create_unique_key:
            with patch(
                "middleman.services.ProxyManager._get_user_ip",
                return_value=access_entry.ip,
            ) as _get_user_ip:
                with patch("middleman.services.ProxyManager.do_request") as do_request:
                    self.proxy_manager.access_filter(
                        self.request.get("{}".format(self.target_url)),
                        access_entry.path,
                    )
                    _create_unique_key.assert_called()
                    _get_user_ip.assert_called()
                    do_request.assert_called()

    @pytest.mark.django_db
    def test_access_filter_block(self):
        access_entry = AccessEntryModelFactory.create(already_requested=100)

        with patch(
            "middleman.services.ProxyManager._create_unique_key",
            return_value=access_entry.key,
        ) as _create_unique_key:
            with patch(
                "middleman.services.ProxyManager._get_user_ip",
                return_value=access_entry.ip,
            ) as _get_user_ip:
                with patch("middleman.services.ProxyManager.do_request") as do_request:
                    with self.assertRaises(ExceededRequestsLimitException):
                        self.proxy_manager.access_filter(
                            self.request.get("{}".format(self.target_url)),
                            access_entry.path,
                        )
                        _create_unique_key.assert_called()
                        _get_user_ip.assert_called()
                        do_request.assert_not_called()

    @patch("requests.get", side_effect=mock_api_requests(200))
    @patch("requests.head", side_effect=mock_api_requests(200))
    @pytest.mark.django_db
    def test_access_filter_blocks_blacklisted_path(self, mock_get, mock_head):
        access_entry = AccessEntryModelFactory.create()

        with patch("middleman.services.BLACKLISTED_PATHS", ["index/*"]):
            with patch(
                "middleman.services.ProxyManager._create_unique_key",
                return_value=access_entry.key,
            ) as _create_unique_key:
                with patch(
                    "middleman.services.ProxyManager._get_user_ip",
                    return_value=access_entry.ip,
                ) as _get_user_ip:
                    with patch("middleman.services.ProxyManager.do_request") as do_request:
                        with self.assertRaises(BlacklistedAccessException):
                            self.proxy_manager.access_filter(
                                self.request.get("{}".format(self.target_url)),
                                "index/",
                            )
                        _create_unique_key.assert_not_called()
                        _get_user_ip.assert_called()
                        do_request.assert_not_called()

    @patch("requests.get", side_effect=mock_api_requests(200))
    @patch("requests.head", side_effect=mock_api_requests(200))
    @pytest.mark.django_db
    def test_access_filter_blocks_blacklisted_ip(self, mock_get, mock_head):
        access_entry = AccessEntryModelFactory.create()

        with patch("middleman.services.BLACKLISTED_IPS", [access_entry.ip]):
            with patch(
                "middleman.services.ProxyManager._get_user_ip",
                return_value=access_entry.ip,
            ) as _get_user_ip:
                with patch("middleman.services.ProxyManager.do_request") as do_request:
                    with self.assertRaises(BlacklistedAccessException):
                        self.proxy_manager.access_filter(
                            self.request.get("{}".format(self.target_url)),
                            access_entry.path,
                        )
                    _get_user_ip.assert_called()
                    do_request.assert_not_called()


class CidrBlacklistMatchingTest(SimpleTestCase):
    """Unit tests for IP rule matching, including CIDR subnets."""

    def setUp(self):
        self.proxy_manager = ProxyManager("https://example.com/index/")

    def test_ipv4_cidr_matches_addresses_inside_subnet(self):
        for ip in ["10.0.0.0", "10.0.0.1", "10.0.0.128", "10.0.0.255"]:
            with self.subTest(ip=ip):
                self.assertTrue(self.proxy_manager._matches_ip_rule(ip, "10.0.0.0/24"))

    def test_ipv4_cidr_does_not_match_addresses_outside_subnet(self):
        for ip in ["10.0.1.0", "9.255.255.255", "10.0.10.1", "192.168.1.1"]:
            with self.subTest(ip=ip):
                self.assertFalse(self.proxy_manager._matches_ip_rule(ip, "10.0.0.0/24"))

    def test_cidr_prefix_lengths(self):
        self.assertTrue(self.proxy_manager._matches_ip_rule("172.31.255.254", "172.16.0.0/12"))
        self.assertFalse(self.proxy_manager._matches_ip_rule("172.32.0.1", "172.16.0.0/12"))
        self.assertTrue(self.proxy_manager._matches_ip_rule("192.168.1.7", "192.168.1.7/32"))
        self.assertFalse(self.proxy_manager._matches_ip_rule("192.168.1.8", "192.168.1.7/32"))
        self.assertTrue(self.proxy_manager._matches_ip_rule("8.8.8.8", "0.0.0.0/0"))

    def test_cidr_with_host_bits_set_is_accepted(self):
        # "192.168.1.77/24" is interpreted as the 192.168.1.0/24 network.
        self.assertTrue(self.proxy_manager._matches_ip_rule("192.168.1.3", "192.168.1.77/24"))
        self.assertFalse(self.proxy_manager._matches_ip_rule("192.168.2.3", "192.168.1.77/24"))

    def test_ipv6_cidr(self):
        self.assertTrue(self.proxy_manager._matches_ip_rule("2001:db8::1", "2001:db8::/32"))
        self.assertFalse(self.proxy_manager._matches_ip_rule("2001:db9::1", "2001:db8::/32"))

    def test_ip_version_mismatch_does_not_match(self):
        self.assertFalse(self.proxy_manager._matches_ip_rule("10.0.0.1", "2001:db8::/32"))
        self.assertFalse(self.proxy_manager._matches_ip_rule("2001:db8::1", "10.0.0.0/8"))

    def test_surrounding_whitespace_is_ignored(self):
        # X-Forwarded-For values are often formatted as "ip, ip".
        self.assertTrue(self.proxy_manager._matches_ip_rule(" 10.0.0.5 ", " 10.0.0.0/24 "))

    def test_invalid_cidr_rule_never_matches_and_does_not_raise(self):
        for rule in ["10.0.0.0/33", "10.0.0/24/1", "not-an-ip/24", "10.0.0.*/24"]:
            with self.subTest(rule=rule):
                self.assertFalse(self.proxy_manager._matches_ip_rule("10.0.0.1", rule))

    def test_invalid_client_ip_never_matches_cidr_and_does_not_raise(self):
        for ip in ["", None, "unknown", "10.0.0.300"]:
            with self.subTest(ip=ip):
                self.assertFalse(self.proxy_manager._matches_ip_rule(ip, "10.0.0.0/24"))

    def test_exact_and_wildcard_ip_rules_still_work(self):
        self.assertTrue(self.proxy_manager._matches_ip_rule("10.0.0.7", "10.0.0.7"))
        self.assertFalse(self.proxy_manager._matches_ip_rule("10.0.0.70", "10.0.0.7"))
        self.assertTrue(self.proxy_manager._matches_ip_rule("10.0.0.70", "10.0.0.*"))
        self.assertFalse(self.proxy_manager._matches_ip_rule("10.0.1.70", "10.0.0.*"))

    def test_settings_blacklisted_ips_support_cidr(self):
        with patch("middleman.services.BLACKLISTED_IPS", ["192.168.1.0/24"]):
            with patch("middleman.services.BlacklistRule.objects") as objects:
                objects.filter.return_value = []
                self.assertEqual(
                    self.proxy_manager._is_blacklisted("192.168.1.42", "index/"),
                    ("ip", "192.168.1.0/24"),
                )
                self.assertIsNone(
                    self.proxy_manager._is_blacklisted("192.168.2.42", "index/")
                )


class CidrBlacklistRuleTest(TestCase):
    """CIDR rules stored in the database block whole subnets."""

    def setUp(self):
        self.proxy_manager = ProxyManager("https://example.com/index/")
        self.request = RequestFactory().get("/proxy/index")
        patcher = patch.object(
            self.proxy_manager, "do_request", return_value=Mock(status_code=200)
        )
        self.do_request = patcher.start()
        self.addCleanup(patcher.stop)

    def _access(self, ip, path="index/"):
        with patch.object(self.proxy_manager, "_get_user_ip", return_value=ip):
            return self.proxy_manager.access_filter(self.request, path)

    def test_blocks_ip_inside_cidr_rule(self):
        BlacklistRule.objects.create(rule_type="ip", value="10.0.0.0/24")

        with self.assertRaises(BlacklistedAccessException) as ctx:
            self._access("10.0.0.99")

        self.assertEqual(ctx.exception.rule_type, "ip")
        self.assertEqual(ctx.exception.rule_value, "10.0.0.0/24")
        self.do_request.assert_not_called()
        self.assertFalse(AccessEntry.objects.filter(ip="10.0.0.99").exists())

    def test_allows_ip_outside_cidr_rule(self):
        BlacklistRule.objects.create(rule_type="ip", value="10.0.0.0/24")

        response = self._access("10.0.1.1")

        self.assertEqual(response.status_code, 200)
        self.do_request.assert_called_once()

    @override_settings(TRUSTED_PROXIES=["127.0.0.1"])
    def test_blocks_client_from_forwarded_for_header_sent_by_trusted_proxy(self):
        BlacklistRule.objects.create(rule_type="ip", value="192.168.1.0/24")
        # The client sent "203.0.113.9"; our proxy (127.0.0.1) appended the
        # address it really saw, 192.168.1.20.
        request = RequestFactory().get(
            "/proxy/index", HTTP_X_FORWARDED_FOR="203.0.113.9, 192.168.1.20"
        )

        with self.assertRaises(BlacklistedAccessException) as ctx:
            self.proxy_manager.access_filter(request, "index/")
        self.assertEqual(ctx.exception.ip, "192.168.1.20")
        self.do_request.assert_not_called()

    @override_settings(TRUSTED_PROXIES=["127.0.0.1"])
    def test_blocked_client_cannot_escape_by_prepending_a_fake_address(self):
        BlacklistRule.objects.create(rule_type="ip", value="192.168.1.0/24")
        # Blocked client 192.168.1.20 prepends an innocent-looking address.
        request = RequestFactory().get(
            "/proxy/index", HTTP_X_FORWARDED_FOR="8.8.8.8, 192.168.1.20"
        )

        with self.assertRaises(BlacklistedAccessException):
            self.proxy_manager.access_filter(request, "index/")

    def test_blocked_client_cannot_escape_by_spoofing_the_header_directly(self):
        BlacklistRule.objects.create(rule_type="ip", value="127.0.0.0/8")
        # No trusted proxies: the header is ignored and the TCP peer is used.
        request = RequestFactory().get("/proxy/index", HTTP_X_FORWARDED_FOR="8.8.8.8")

        with self.assertRaises(BlacklistedAccessException) as ctx:
            self.proxy_manager.access_filter(request, "index/")
        self.assertEqual(ctx.exception.ip, "127.0.0.1")

    def test_disabled_cidr_rule_does_not_block(self):
        BlacklistRule.objects.create(rule_type="ip", value="10.0.0.0/24", enabled=False)

        response = self._access("10.0.0.99")

        self.assertEqual(response.status_code, 200)

    def test_invalid_cidr_rule_does_not_break_other_rules(self):
        BlacklistRule.objects.create(rule_type="ip", value="10.0.0.0/99")
        BlacklistRule.objects.create(rule_type="ip", value="10.0.0.0/16")

        with self.assertRaises(BlacklistedAccessException) as ctx:
            self._access("10.0.200.1")
        self.assertEqual(ctx.exception.rule_value, "10.0.0.0/16")

    def test_path_rules_are_not_interpreted_as_cidr(self):
        # A path rule that happens to look like a subnet must not block IPs.
        BlacklistRule.objects.create(rule_type="path", value="10.0.0.0/24")

        response = self._access("10.0.0.5", path="index/")

        self.assertEqual(response.status_code, 200)


class BlacklistRuleValidationTest(SimpleTestCase):
    """Model-level validation of CIDR values."""

    def test_parse_ip_network(self):
        self.assertIsNone(parse_ip_network("10.0.0.1"))
        self.assertIsNone(parse_ip_network("10.0.0.*"))
        self.assertEqual(str(parse_ip_network("10.0.0.0/24")), "10.0.0.0/24")
        self.assertEqual(str(parse_ip_network("10.0.0.9/24")), "10.0.0.0/24")
        with self.assertRaises(ValueError):
            parse_ip_network("10.0.0.0/33")

    def test_is_cidr(self):
        self.assertTrue(BlacklistRule(rule_type="ip", value="10.0.0.0/24").is_cidr)
        self.assertFalse(BlacklistRule(rule_type="ip", value="10.0.0.1").is_cidr)
        self.assertFalse(BlacklistRule(rule_type="path", value="admin/*").is_cidr)

    def test_clean_accepts_valid_ip_rules(self):
        for value in ["10.0.0.0/24", "192.168.1.0/24", "2001:db8::/32", "10.0.0.1", "10.0.*"]:
            with self.subTest(value=value):
                BlacklistRule(rule_type="ip", value=value).clean()

    def test_clean_rejects_malformed_cidr(self):
        for value in ["10.0.0.0/33", "300.0.0.0/24", "abc/24"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError) as ctx:
                    BlacklistRule(rule_type="ip", value=value).clean()
                self.assertIn("value", ctx.exception.message_dict)

    def test_clean_ignores_path_rules_with_slashes(self):
        BlacklistRule(rule_type="path", value="api/v1/*").clean()


class RateLimitStateTest(TestCase):
    """access_filter() records rate limit state for the rate limit headers."""

    def setUp(self):
        self.proxy_manager = ProxyManager("https://example.com/index/")
        self.request = RequestFactory().get("/proxy/index")

    def _access(self, ip, key):
        with patch.object(self.proxy_manager, "_get_user_ip", return_value=ip):
            with patch.object(self.proxy_manager, "_create_unique_key", return_value=key):
                with patch.object(
                    self.proxy_manager, "do_request", return_value=Mock(status_code=200)
                ):
                    return self.proxy_manager.access_filter(self.request, "index/")

    def test_no_rate_limit_headers_before_access(self):
        self.assertIsNone(self.proxy_manager.rate_limit)
        self.assertEqual(self.proxy_manager.rate_limit_headers(), {})

    def test_existing_entry_reports_remaining_after_this_request(self):
        entry = AccessEntryModelFactory.create(already_requested=52, max_requests=100)

        self._access(entry.ip, entry.key)

        entry.refresh_from_db()
        self.assertEqual(entry.already_requested, 53)
        self.assertEqual(self.proxy_manager.rate_limit, {"limit": 100, "remaining": 47})
        self.assertEqual(
            self.proxy_manager.rate_limit_headers(),
            {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "47"},
        )

    def test_last_allowed_request_reports_zero_remaining(self):
        entry = AccessEntryModelFactory.create(already_requested=9, max_requests=10)

        self._access(entry.ip, entry.key)

        self.assertEqual(self.proxy_manager.rate_limit, {"limit": 10, "remaining": 0})

    def test_new_entry_reports_stored_limit(self):
        self._access("203.0.113.5", "new_key_0001")

        entry = AccessEntry.objects.get(key="new_key_0001")
        self.assertEqual(
            self.proxy_manager.rate_limit,
            {
                "limit": entry.max_requests,
                "remaining": entry.max_requests - entry.already_requested,
            },
        )

    def test_exceeded_limit_reports_zero_remaining(self):
        entry = AccessEntryModelFactory.create(already_requested=100, max_requests=100)

        with self.assertRaises(ExceededRequestsLimitException):
            self._access(entry.ip, entry.key)

        self.assertEqual(self.proxy_manager.rate_limit, {"limit": 100, "remaining": 0})

    def test_remaining_never_negative_when_limit_lowered(self):
        # e.g. max_requests reduced via PATCH /registry below already_requested
        entry = AccessEntryModelFactory.create(already_requested=80, max_requests=50)

        with self.assertRaises(ExceededRequestsLimitException):
            self._access(entry.ip, entry.key)

        self.assertEqual(self.proxy_manager.rate_limit, {"limit": 50, "remaining": 0})

    def test_blacklisted_request_has_no_rate_limit_state(self):
        BlacklistRule.objects.create(rule_type="ip", value="198.51.100.0/24")

        with self.assertRaises(BlacklistedAccessException):
            self._access("198.51.100.7", "blocked_key_01")

        self.assertEqual(self.proxy_manager.rate_limit_headers(), {})


def upstream(status_code=200, location=None):
    """A fake requests.Response, optionally a redirect."""
    response = Mock(status_code=status_code)
    response.headers = {"location": location} if location else {}
    return response


class HostRuleValidationTest(SimpleTestCase):
    def test_clean_accepts_valid_host_rules(self):
        for value in ["example.com", "*.example.com", "93.184.215.14", "10.0.0.0/8"]:
            with self.subTest(value=value):
                BlacklistRule(rule_type="host", value=value).clean()

    def test_clean_rejects_invalid_host_rules(self):
        for value in ["https://example.com/", "example.com:8080", "ex*.com", "re:(", "10.0.0.0/33"]:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError) as ctx:
                    BlacklistRule(rule_type="host", value=value).clean()
                self.assertIn("value", ctx.exception.message_dict)


@patch("middleman.services.requests.get")
@patch("middleman.services.requests.head")
class DestinationBlockingTest(TestCase):
    """Host rules block a destination site, including via redirects."""

    ip = "203.0.113.10"

    def setUp(self):
        self.proxy_manager = ProxyManager("https://target.example/index/")
        self.request = RequestFactory().get("/proxy/index/", REMOTE_ADDR=self.ip)

    def test_allowed_target_is_fetched_without_following_redirects_implicitly(self, head, get):
        head.return_value = upstream(200)
        get.return_value = upstream(200)

        response = self.proxy_manager.access_filter(self.request, "index/")

        self.assertIs(response, get.return_value)
        get.assert_called_once_with(
            "https://target.example/index/", stream=True, timeout=10, allow_redirects=False
        )

    def test_blocked_target_is_rejected_before_any_upstream_request(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="target.example")

        with self.assertRaises(BlockedDestinationException) as ctx:
            self.proxy_manager.access_filter(self.request, "index/")

        self.assertEqual(ctx.exception.host, "target.example")
        self.assertEqual(ctx.exception.rule_type, "host")
        self.assertEqual(ctx.exception.ip, self.ip)
        head.assert_not_called()
        get.assert_not_called()
        self.assertFalse(AccessEntry.objects.exists())

    def test_other_sites_are_not_affected(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="www.target.example")
        BlacklistRule.objects.create(rule_type="host", value="*.other.example")
        head.return_value = upstream(200)
        get.return_value = upstream(200)

        response = self.proxy_manager.access_filter(self.request, "index/")

        self.assertEqual(response.status_code, 200)

    def test_disabled_and_invalid_host_rules_are_ignored(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="target.example", enabled=False)
        BlacklistRule.objects.create(rule_type="host", value="re:(")
        head.return_value = upstream(200)
        get.return_value = upstream(200)

        self.assertEqual(self.proxy_manager.access_filter(self.request, "index/").status_code, 200)

    def test_redirect_to_blocked_site_is_stopped_before_connecting(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="*.blocked.example")
        head.return_value = upstream(200)
        first_hop = upstream(302, location="https://cdn.blocked.example/file")
        get.return_value = first_hop

        with self.assertRaises(BlockedDestinationException) as ctx:
            self.proxy_manager.access_filter(self.request, "index/")

        self.assertEqual(ctx.exception.host, "cdn.blocked.example")
        self.assertEqual(get.call_count, 1)  # never requested the blocked hop
        first_hop.close.assert_called_once()

    def test_redirect_using_url_tricks_is_still_blocked(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="127.0.0.0/8")
        head.return_value = upstream(200)
        for location in ["http://2130706433/admin", "http://allowed.example@127.0.0.1/", "http://127.0.0.1\\@allowed.example/"]:
            with self.subTest(location=location):
                get.reset_mock()
                get.return_value = upstream(301, location=location)
                with self.assertRaises(BlockedDestinationException):
                    ProxyManager("https://target.example/index/").do_request()
                self.assertEqual(get.call_count, 1)

    def test_redirects_to_allowed_sites_are_followed(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="blocked.example")
        head.return_value = upstream(200)
        final = upstream(200)
        get.side_effect = [upstream(301, location="/moved/"), upstream(307, location="https://mirror.example/x"), final]

        response = self.proxy_manager.do_request()

        self.assertIs(response, final)
        self.assertEqual(
            [c.args[0] for c in get.call_args_list],
            ["https://target.example/index/", "https://target.example/moved/", "https://mirror.example/x"],
        )

    def test_redirect_without_location_is_returned_as_is(self, head, get):
        head.return_value = upstream(200)
        get.return_value = upstream(304)

        self.assertEqual(self.proxy_manager.do_request().status_code, 304)

    def test_redirect_loop_is_bounded(self, head, get):
        head.return_value = upstream(200)
        get.side_effect = lambda *a, **k: upstream(302, location="/again/")

        with self.assertRaises(ServerNotRespondingException):
            self.proxy_manager.do_request()
        self.assertEqual(get.call_count, 11)  # first request + MAX_REDIRECTS

    def test_blocked_redirect_does_not_consume_rate_limit(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="blocked.example")
        entry = AccessEntryModelFactory.create(ip=self.ip, already_requested=5, max_requests=10)
        head.return_value = upstream(200)
        get.return_value = upstream(302, location="https://blocked.example/")

        with patch.object(self.proxy_manager, "_create_unique_key", return_value=entry.key):
            with self.assertRaises(BlockedDestinationException):
                self.proxy_manager.access_filter(self.request, "index/")

        entry.refresh_from_db()
        self.assertEqual(entry.already_requested, 5)

    def test_blocked_redirect_for_new_client_is_not_reported_as_registration_error(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="blocked.example")
        head.return_value = upstream(200)
        get.return_value = upstream(302, location="https://blocked.example/")

        with self.assertRaises(BlockedDestinationException):
            self.proxy_manager.access_filter(self.request, "index/")
        self.assertEqual(AccessEntry.objects.get().already_requested, 0)  # released

    def test_ip_host_rule_resolves_target_once(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="198.51.100.0/24")
        BlacklistRule.objects.create(rule_type="host", value="198.51.100.7")

        with patch("middleman.services.system_resolver", return_value=[ipaddress.ip_address("198.51.100.7")]) as resolver:
            with self.assertRaises(BlockedDestinationException) as ctx:
                self.proxy_manager.access_filter(self.request, "index/")

        self.assertEqual(ctx.exception.rule_value, "198.51.100.0/24")
        resolver.assert_called_once_with("target.example")
        head.assert_not_called()

    def test_existing_entry_upstream_failure_keeps_original_error(self, head, get):
        # Used to be masked by `logger.exception(e.msg)` raising AttributeError.
        entry = AccessEntryModelFactory.create(ip=self.ip, already_requested=3)
        head.side_effect = requests.ConnectionError("down")

        with patch.object(self.proxy_manager, "_create_unique_key", return_value=entry.key):
            with self.assertRaises(ServerNotRespondingException):
                self.proxy_manager.access_filter(self.request, "index/")
        entry.refresh_from_db()
        self.assertEqual(entry.already_requested, 3)  # failures are not counted

    def test_new_client_upstream_failure_is_reported_as_upstream_failure(self, head, get):
        # Used to be disguised as AccessNotRegisteredException (a 400 at the time).
        head.side_effect = requests.ConnectionError("down")

        with self.assertRaises(ServerNotRespondingException):
            self.proxy_manager.access_filter(self.request, "index/")
        self.assertEqual(AccessEntry.objects.get().already_requested, 0)  # released

    def test_new_client_storage_failure_is_access_not_registered(self, head, get):
        head.return_value = upstream(200)
        get.return_value = upstream(200)

        with patch("middleman.services.RegistryInterface.get_or_create_access_entry", side_effect=RuntimeError("db down")):
            with self.assertRaises(AccessNotRegisteredException):
                self.proxy_manager.access_filter(self.request, "index/")
