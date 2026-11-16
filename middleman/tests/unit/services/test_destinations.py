import ipaddress
import socket
from unittest.mock import patch

from django.test import SimpleTestCase

from middleman.destinations import (host_from_url, host_matches,
                                    normalize_host, parse_host_regex,
                                    parse_host_rule, parse_ip_literal,
                                    system_resolver)


def resolver_for(mapping):
    """Fake DNS: {"host": ["1.2.3.4", ...]}; unknown hosts resolve to nothing."""

    def resolve(host):
        return [ipaddress.ip_address(a) for a in mapping.get(host, [])]

    return resolve


def no_dns(host):
    raise AssertionError("DNS must not be used for {}".format(host))


class NormalizeHostTest(SimpleTestCase):
    def test_case_and_trailing_dot(self):
        self.assertEqual(normalize_host("WWW.Example.COM."), "www.example.com")

    def test_idn_is_punycoded(self):
        self.assertEqual(normalize_host("Bücher.de"), "xn--bcher-kva.de")
        self.assertEqual(normalize_host("xn--bcher-kva.de"), "xn--bcher-kva.de")

    def test_ipv4_alternative_notations_are_canonicalized(self):
        # All of these reach 127.0.0.1 through the system resolver.
        for spelling in ["127.0.0.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1", "0x7f000001"]:
            with self.subTest(spelling=spelling):
                self.assertEqual(normalize_host(spelling), "127.0.0.1")

    def test_ipv6_is_canonicalized(self):
        self.assertEqual(normalize_host("[2001:DB8:0:0::1]"), "2001:db8::1")

    def test_hostnames_that_look_numeric_are_not_ips(self):
        for host in ["123.com", "deadbeef", "1e100", "0x.com"]:
            with self.subTest(host=host):
                self.assertIsNone(parse_ip_literal(host))
                self.assertEqual(normalize_host(host), host)

    def test_empty(self):
        self.assertEqual(normalize_host(""), "")
        self.assertEqual(normalize_host(None), "")


class HostFromUrlTest(SimpleTestCase):
    def test_strips_userinfo_port_and_case(self):
        self.assertEqual(host_from_url("https://user:pw@Example.COM.:8443/a?b#c"), "example.com")

    def test_userinfo_trick_resolves_to_real_host(self):
        self.assertEqual(host_from_url("http://example.com@blocked.com/"), "blocked.com")
        self.assertEqual(host_from_url("http://example.com:80@blocked.com/"), "blocked.com")

    def test_backslash_trick_matches_what_requests_connects_to(self):
        # urllib.parse says "allowed.com"; urllib3/requests connect to "blocked.com".
        self.assertEqual(host_from_url("http://blocked.com\\@allowed.com/"), "blocked.com")

    def test_numeric_ip_url(self):
        self.assertEqual(host_from_url("http://2130706433/admin"), "127.0.0.1")
        self.assertEqual(
            host_from_url("http://[::ffff:7f00:1]/"),
            str(ipaddress.ip_address("::ffff:7f00:1")),
        )

    def test_unparseable_urls_have_no_host(self):
        self.assertEqual(host_from_url("http://[bad/"), "")
        self.assertEqual(host_from_url("http:///nohost"), "")


class ParseHostRuleTest(SimpleTestCase):
    def test_rule_kinds(self):
        self.assertEqual(parse_host_rule(" Example.COM. "), ("exact", "example.com"))
        self.assertEqual(parse_host_rule("*.Example.com"), ("subdomains", "example.com"))
        self.assertEqual(parse_host_rule("bücher.de"), ("exact", "xn--bcher-kva.de"))
        self.assertEqual(parse_host_rule("10.0.0.0/8").kind, "network")
        self.assertEqual(
            parse_host_rule("93.184.215.14").target, ipaddress.ip_network("93.184.215.14/32")
        )
        self.assertEqual(
            parse_host_rule("2130706433").target, ipaddress.ip_network("127.0.0.1/32")
        )

    def test_invalid_rules(self):
        invalid = [
            "", "   ", "re:", "re:(", "https://example.com", "example.com/path",
            "example.com:8080", "user@example.com", "ex*.com", "*example.com",
            "*.1.2.3", "a..b", "-bad-.com", "10.0.0.0/33",
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_host_rule(value)


class HostMatchesTest(SimpleTestCase):
    def test_exact_blocks_one_and_only_one_site(self):
        rule = parse_host_rule("example.com")
        for host in ["example.com", "EXAMPLE.com.", "Example.Com"]:
            with self.subTest(host=host):
                self.assertTrue(host_matches(rule, host, resolver=no_dns))
        for host in ["www.example.com", "notexample.com", "example.com.evil.net", "example.co"]:
            with self.subTest(host=host):
                self.assertFalse(host_matches(rule, host, resolver=no_dns))

    def test_exact_rule_does_not_block_the_sites_ip(self):
        # Shared IPs (CDNs) would cause collateral blocking; IP rules are opt-in.
        self.assertFalse(host_matches(parse_host_rule("example.com"), "93.184.215.14", resolver=no_dns))

    def test_subdomains_respect_label_boundaries(self):
        rule = parse_host_rule("*.example.com")
        for host in ["www.example.com", "a.b.example.com", "WWW.EXAMPLE.COM."]:
            with self.subTest(host=host):
                self.assertTrue(host_matches(rule, host, resolver=no_dns))
        for host in ["example.com", "badexample.com", "example.com.evil.net"]:
            with self.subTest(host=host):
                self.assertFalse(host_matches(rule, host, resolver=no_dns))

    def test_idn_rule_matches_both_spellings(self):
        rule = parse_host_rule("bücher.de")
        self.assertTrue(host_matches(rule, "xn--bcher-kva.de", resolver=no_dns))
        self.assertTrue(host_matches(rule, "BÜCHER.de", resolver=no_dns))

    def test_regex_is_full_match_on_canonical_host(self):
        rule = parse_host_regex("(www\\.)?example\\.(com|net)")
        self.assertTrue(host_matches(rule, "www.example.net", resolver=no_dns))
        self.assertTrue(host_matches(rule, "EXAMPLE.COM.", resolver=no_dns))
        self.assertFalse(host_matches(rule, "api.example.com", resolver=no_dns))
        self.assertFalse(host_matches(rule, "example.com.evil.net", resolver=no_dns))

    def test_ip_rule_matches_ip_literals_in_any_notation_without_dns(self):
        rule = parse_host_rule("127.0.0.0/8")
        for host in ["127.0.0.1", "2130706433", "0x7f.1", "::ffff:127.0.0.1"]:
            with self.subTest(host=host):
                self.assertTrue(host_matches(rule, host, resolver=no_dns))
        self.assertFalse(host_matches(rule, "10.0.0.1", resolver=no_dns))

    def test_ip_rule_matches_hostnames_that_resolve_into_it(self):
        dns = resolver_for({"example.com": ["93.184.215.14", "2606:2800:21f:cb07::1"], "other.com": ["1.1.1.1"]})
        self.assertTrue(host_matches(parse_host_rule("93.184.215.0/24"), "example.com", resolver=dns))
        self.assertTrue(host_matches(parse_host_rule("2606:2800::/32"), "example.com", resolver=dns))
        self.assertFalse(host_matches(parse_host_rule("93.184.215.0/24"), "other.com", resolver=dns))

    def test_ip_rule_does_not_match_when_dns_fails(self):
        self.assertFalse(host_matches(parse_host_rule("10.0.0.0/8"), "nxdomain.invalid", resolver=resolver_for({})))

    def test_empty_host_never_matches(self):
        self.assertFalse(host_matches(parse_host_rule("example.com"), "", resolver=no_dns))


class SystemResolverTest(SimpleTestCase):
    @patch("middleman.destinations.socket.getaddrinfo")
    def test_collects_addresses(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
        ]
        self.assertEqual(
            system_resolver("example.com"),
            [ipaddress.ip_address("1.2.3.4"), ipaddress.ip_address("::1")],
        )

    @patch("middleman.destinations.socket.getaddrinfo", side_effect=socket.gaierror("nope"))
    def test_failure_returns_empty(self, _getaddrinfo):
        self.assertEqual(system_resolver("nxdomain.invalid"), [])
