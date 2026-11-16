from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

from middleman import client_ip
from middleman.client_ip import get_client_ip, parse_address, parse_trusted_proxies


def meta(remote_addr="198.51.100.1", forwarded_for=None):
    data = {"REMOTE_ADDR": remote_addr}
    if forwarded_for is not None:
        data["HTTP_X_FORWARDED_FOR"] = forwarded_for
    return data


class ParseAddressTest(SimpleTestCase):
    def test_formats_written_by_proxies(self):
        cases = {
            "10.0.0.1": "10.0.0.1",
            " 10.0.0.1 ": "10.0.0.1",
            "10.0.0.1:5678": "10.0.0.1",
            "2001:db8::1": "2001:db8::1",
            "[2001:db8::1]:443": "2001:db8::1",
            "[2001:db8::1]": "2001:db8::1",
            "::ffff:10.0.0.1": "10.0.0.1",  # dual-stack sockets
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(str(parse_address(raw)), expected)

    def test_garbage_is_rejected(self):
        for raw in ["", None, "unknown", "_hidden", "10.0.0.300", "example.com", "1.2.3.4:80:90"]:
            with self.subTest(raw=raw):
                self.assertIsNone(parse_address(raw))


class TrustedProxiesSettingTest(SimpleTestCase):
    def test_typos_fail_loudly(self):
        with self.assertRaises(ImproperlyConfigured) as ctx:
            parse_trusted_proxies(("10.0.0.0/8", "10.0.0.0/33"))
        self.assertIn("10.0.0.0/33", str(ctx.exception))

    def test_ips_and_subnets(self):
        networks = parse_trusted_proxies(("10.0.0.1", "172.16.0.0/12", "2001:db8::/32"))
        self.assertEqual([str(n) for n in networks], ["10.0.0.1/32", "172.16.0.0/12", "2001:db8::/32"])


class GetClientIpTest(SimpleTestCase):
    def setUp(self):
        client_ip._WARNED_UNTRUSTED_PEERS.clear()

    # --- default: nobody is trusted ------------------------------------------

    def test_without_header_the_peer_is_the_client(self):
        self.assertEqual(get_client_ip(meta("198.51.100.1")), "198.51.100.1")

    def test_header_from_untrusted_peer_is_ignored(self):
        self.assertEqual(get_client_ip(meta("198.51.100.1", "1.2.3.4")), "198.51.100.1")

    def test_untrusted_peer_sending_header_is_reported_once(self):
        with self.assertLogs("middleman.client_ip", "WARNING") as logs:
            get_client_ip(meta("198.51.100.1", "1.2.3.4"))
            get_client_ip(meta("198.51.100.1", "5.6.7.8"))
            get_client_ip(meta("198.51.100.2", "1.2.3.4"))
        self.assertEqual(len(logs.records), 2)  # once per peer, not per request
        self.assertIn("peer=198.51.100.1", logs.output[0])
        self.assertIn("TRUSTED_PROXIES", logs.output[0])

    # --- behind trusted proxies -------------------------------------------------

    @override_settings(TRUSTED_PROXIES=["10.0.0.2"])
    def test_one_trusted_proxy(self):
        self.assertEqual(get_client_ip(meta("10.0.0.2", "203.0.113.7")), "203.0.113.7")

    @override_settings(TRUSTED_PROXIES=["10.0.0.2"])
    def test_client_supplied_entries_are_never_used(self):
        # The client sent "1.1.1.1"; the proxy appended the real address.
        self.assertEqual(get_client_ip(meta("10.0.0.2", "1.1.1.1, 203.0.113.7")), "203.0.113.7")

    @override_settings(TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_chain_of_trusted_proxies_is_skipped(self):
        header = "1.1.1.1, 203.0.113.7, 10.1.1.1, 10.2.2.2"
        self.assertEqual(get_client_ip(meta("10.0.0.2", header)), "203.0.113.7")

    @override_settings(TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_all_hops_trusted_returns_origin(self):
        self.assertEqual(get_client_ip(meta("10.0.0.2", "10.9.9.9, 10.1.1.1")), "10.9.9.9")

    @override_settings(TRUSTED_PROXIES=["10.0.0.2"])
    def test_trusted_proxy_without_header_is_the_client(self):
        self.assertEqual(get_client_ip(meta("10.0.0.2")), "10.0.0.2")

    @override_settings(TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_malformed_entry_stops_at_nearest_verified_hop(self):
        with self.assertLogs("middleman.client_ip", "WARNING") as logs:
            ip = get_client_ip(meta("10.0.0.2", "203.0.113.7, garbage, 10.1.1.1"))
        self.assertEqual(ip, "10.1.1.1")
        self.assertIn("entry='garbage'", logs.output[0])

    @override_settings(TRUSTED_PROXIES=["10.0.0.2"])
    def test_ports_and_ipv6_in_header(self):
        self.assertEqual(get_client_ip(meta("10.0.0.2", "[2001:db8::7]:1234")), "2001:db8::7")
        self.assertEqual(get_client_ip(meta("10.0.0.2", "203.0.113.7:5555")), "203.0.113.7")

    @override_settings(TRUSTED_PROXIES=["10.0.0.2"])
    def test_ipv4_mapped_peer_is_recognized_as_trusted(self):
        self.assertEqual(get_client_ip(meta("::ffff:10.0.0.2", "203.0.113.7")), "203.0.113.7")

    def test_unusable_remote_addr(self):
        with self.assertLogs("middleman.client_ip", "ERROR"):
            self.assertIsNone(get_client_ip({"REMOTE_ADDR": ""}))
