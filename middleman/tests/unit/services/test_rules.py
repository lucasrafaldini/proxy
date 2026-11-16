import time

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from middleman.destinations import (MAX_REGEX_LENGTH, host_matches,
                                    parse_host_regex, parse_host_rule)
from middleman.exceptions import InvalidRuleError
from middleman.models import BlacklistRule
from middleman.rules import validate_ip_rule, validate_path_rule, validate_rule


class InvalidRuleErrorTest(SimpleTestCase):
    def test_is_a_value_error_with_reason_and_message(self):
        error = InvalidRuleError("regex_syntax", "Invalid regex.", "host_re", "(")
        self.assertIsInstance(error, ValueError)
        self.assertEqual((error.reason, str(error), error.rule_type, error.value),
                         ("regex_syntax", "Invalid regex.", "host_re", "("))


class HostRegexTest(SimpleTestCase):
    """Only valid, unambiguous, bounded regex rules are accepted."""

    def assertRejected(self, pattern, reason):
        with self.assertRaises(InvalidRuleError) as ctx:
            parse_host_regex(pattern)
        self.assertEqual(ctx.exception.reason, reason, str(ctx.exception))
        self.assertEqual(ctx.exception.rule_type, "host_re")
        return ctx.exception

    def test_accepts_valid_patterns(self):
        for pattern in [
            r"(www\.)?example\.com",
            r"(www\.)?example\.(com|net|org)",
            r".*\.example\.com",
            r"[^.]+\.example\.com",
            r"[.]example\.com",
            r"[].]x\.com",
            r"ads?[0-9]*\.[a-z]+\.com",
            r"([a-z0-9-]{1,63}\.)*tracker\.(com|io)",
            r"^example\.com$",
            r"xn--bcher-kva\.de",
        ]:
            with self.subTest(pattern=pattern):
                self.assertEqual(parse_host_regex(pattern).kind, "regex")

    def test_matching_is_full_and_case_insensitive(self):
        rule = parse_host_regex(r"(www\.)?example\.com")
        self.assertTrue(host_matches(rule, "WWW.Example.com"))
        self.assertFalse(host_matches(rule, "www.example.com.evil.net"))
        self.assertFalse(host_matches(rule, "evil-example.com"))

    def test_empty(self):
        self.assertRejected("   ", "empty")

    def test_prefix_from_the_old_syntax(self):
        self.assertRejected(r"re:example\.com", "regex_prefix")

    def test_too_long(self):
        error = self.assertRejected("a" * (MAX_REGEX_LENGTH + 1) + r"\.com", "regex_too_long")
        self.assertIn(str(MAX_REGEX_LENGTH), error.message)

    def test_non_ascii(self):
        self.assertRejected(r"bücher\.de", "regex_non_ascii")

    def test_url_parts_and_whitespace(self):
        for pattern in [r"https://example\.com", r"example\.com/admin", r"user@example\.com", r"example\.com x"]:
            with self.subTest(pattern=pattern):
                self.assertRejected(pattern, "regex_not_host")

    def test_unescaped_literal_dot(self):
        error = self.assertRejected("example.com", "regex_unescaped_dot")
        self.assertIn("position 7", error.message)
        self.assertRejected(r"(www.)?example\.com", "regex_unescaped_dot")

    def test_syntax_errors_and_unsupported_constructs(self):
        for pattern in [r"(example\.com", r"[a-z\.com", r"(a)\1\.com", r"(?=x)x\.com", r"(?<!x)x\.com", r"a{1001}\.com"]:
            with self.subTest(pattern=pattern):
                error = self.assertRejected(pattern, "regex_syntax")
                self.assertIn("RE2", error.message)
                self.assertNotIn("b'", error.message)  # decoded, readable message

    def test_too_complex(self):
        self.assertRejected(r"([a-z0-9-]{1,63}\.){1,10}example\.com", "regex_too_complex")

    def test_matches_everything(self):
        for pattern in [".*", ".+", "(.*)", r"[a-z0-9.:-]*|.*"]:
            with self.subTest(pattern=pattern):
                self.assertRejected(pattern, "regex_matches_everything")

    def test_catastrophic_backtracking_pattern_runs_in_linear_time(self):
        # With Python's re, (a+)+$ needs ~2s for 25 characters and doubles per
        # character. RE2 is linear, so it stays instant even on long hosts.
        rule = parse_host_regex(r"(a+)+\.example\.com")
        hostile_host = "a" * 5000 + "!"
        started = time.perf_counter()
        self.assertFalse(host_matches(rule, hostile_host))
        self.assertLess(time.perf_counter() - started, 0.5)

    def test_host_rule_points_regexes_to_their_own_type(self):
        with self.assertRaises(InvalidRuleError) as ctx:
            parse_host_rule(r"re:example\.com")
        self.assertEqual(ctx.exception.reason, "regex_in_host_rule")
        self.assertIn("Host (regex)", ctx.exception.message)


class IpAndPathRuleTest(SimpleTestCase):
    def test_valid_ip_rules(self):
        for value in ["10.0.0.7", "2001:db8::1", "10.0.0.0/24", "10.0.0.5/24", "10.0.*", "2001:db8:*"]:
            with self.subTest(value=value):
                validate_ip_rule(value)

    def test_invalid_ip_rules(self):
        cases = {
            "": "empty",
            "10.0.0.0/33": "invalid_subnet",
            "*": "invalid_ip_wildcard",
            "host*": "invalid_ip_wildcard",
            "10.0.0": "invalid_ip",
            "example.com": "invalid_ip",
        }
        for value, reason in cases.items():
            with self.subTest(value=value):
                with self.assertRaises(InvalidRuleError) as ctx:
                    validate_ip_rule(value)
                self.assertEqual(ctx.exception.reason, reason)

    def test_valid_path_rules(self):
        for value in ["admin/", "admin/*", "admin*", "*"]:
            with self.subTest(value=value):
                validate_path_rule(value)

    def test_invalid_path_rules(self):
        cases = {
            "": "empty",
            "/admin/": "path_leading_slash",
            "admin": "path_missing_trailing_slash",  # could never match
            "ad*min/": "unsupported_wildcard",
            "admin panel/": "invalid_path",
            "https://x.com/": "invalid_path",
        }
        for value, reason in cases.items():
            with self.subTest(value=value):
                with self.assertRaises(InvalidRuleError) as ctx:
                    validate_path_rule(value)
                self.assertEqual(ctx.exception.reason, reason)

    def test_unknown_rule_type(self):
        with self.assertRaises(InvalidRuleError) as ctx:
            validate_rule("country", "BR")
        self.assertEqual(ctx.exception.reason, "unknown_rule_type")


class BlacklistRuleModelValidationTest(SimpleTestCase):
    def test_clean_reports_reason_as_error_code(self):
        rule = BlacklistRule(rule_type="host_re", value="example.com")
        with self.assertRaises(ValidationError) as ctx:
            rule.clean()
        self.assertEqual(ctx.exception.error_dict["value"][0].code, "regex_unescaped_dot")

    def test_validation_error_property(self):
        self.assertIsNone(BlacklistRule(rule_type="host_re", value=r"example\.com").validation_error)
        self.assertEqual(BlacklistRule(rule_type="ip", value="10.0.0").validation_error.reason, "invalid_ip")
