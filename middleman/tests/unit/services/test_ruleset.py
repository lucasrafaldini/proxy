"""
The compiled, cached rule set (middleman/ruleset.py): same answers as the
rule-by-rule evaluation, fast in the worst case, fresh across processes.
"""

import random
import time
from unittest.mock import patch

from django.db import OperationalError, connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext

from middleman import ruleset as ruleset_module
from middleman import services
from middleman.exceptions import InvalidRuleError
from middleman.models import BlacklistRule, RuleSetVersion
from middleman.rules import RULE_TYPE_IP, RULE_TYPE_PATH, validate_rule
from middleman.ruleset import (PREFILTER_CHUNK_PROGRAM_SIZE, RuleSet,
                               build_ruleset, cached_ruleset,
                               compile_client_rule)
from middleman.services import ProxyManager
from middleman.user_agents import user_agent_matches
from middleman.version import LEGACY_VERSION


def reference_match(rules, ip, path, user_agent):
    """Rule-by-rule evaluation, exactly as before the compiled rule set."""
    manager = ProxyManager("")
    for rule_type, value in rules:
        try:
            parsed = validate_rule(rule_type, value)
        except InvalidRuleError:
            continue
        if rule_type == RULE_TYPE_IP and manager._matches_ip_rule(ip, value):
            return rule_type, value
        if rule_type == RULE_TYPE_PATH and manager._matches_rule(path, value):
            return rule_type, value
        if rule_type.startswith("user_agent") and user_agent_matches(parsed, user_agent):
            return rule_type, value
    return None


def compiled(rules, use_prefilter=True):
    return RuleSet([compile_client_rule(t, v) for t, v in rules], use_prefilter=use_prefilter)


RULE_POOL = [
    ("ip", "10.0.0.7"), ("ip", "10.0.0.0/24"), ("ip", "10.1.*"), ("ip", "2001:db8::/32"), ("ip", "192.168.1.1"),
    ("ip", "0.0.0.0/0"), ("path", "admin/"), ("path", "admin*"), ("path", "api/v1/*"), ("path", "*"),
    ("user_agent", "sqlmap"), ("user_agent", "python-requests/"), ("user_agent", "BadBot, v1"),
    ("user_agent", "kit"), ("user_agent", "sTr"), ("user_agent", "mobi"), ("user_agent_re", "^$"), ("user_agent_re", "nikto|masscan"),
    ("user_agent_re", r"^curl/[0-7]\."), ("user_agent_re", r"bot/\d+$"), ("user_agent_re", r"(a+)+b"),
]
IPS = ["10.0.0.7", "10.0.0.200", "10.1.2.3", "192.168.1.1", "2001:db8::5", "::1", "8.8.8.8", "", "not-an-ip"]
PATHS = ["admin/", "administrator/", "api/v1/users/", "api/v2/", "home/", ""]
USER_AGENTS = [
    "", "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0", "sqlmap/1.7", "SQLMAP", "python-requests/2.31",
    "x python-requests/2.31", "Nikto/2.5", "curl/7.88.1", "curl/8.4.0", "GoodBot/12", "badbot, V1",
    "a" * 3000 + "b", "a" * 3000 + "!",
    # Non-ASCII: Python's lower() and RE2's case folding differ here, so the
    # prefilter must be bypassed (Kelvin sign K lowers to ASCII "k";
    # dotted I lowers to "i" + combining dot; long s folds to "s" in RE2).
    "\u212aIT browser", "\u0130stanbul", "\u017ftr", "Caf\xe9 SQLmap \xff", "\u212a",
    # "MOB\u0130LE".lower() contains "mobi" (dotted I lowers to "i" + U+0307) but
    # RE2's simple case folding does not map U+0130 to "i": without the ASCII
    # guard the prefilter would wrongly skip the "mobi" rule.
    "MOB\u0130LE Safari",
]


class RuleSetEquivalenceTest(SimpleTestCase):
    def test_same_answer_as_rule_by_rule_evaluation(self):
        rng = random.Random(20261116)
        checked = 0
        for _ in range(150):
            rules = sorted(rng.sample(RULE_POOL, rng.randint(0, len(RULE_POOL))))
            fast, loop = compiled(rules), compiled(rules, use_prefilter=False)
            for _ in range(20):
                request = (rng.choice(IPS), rng.choice(PATHS), rng.choice(USER_AGENTS))
                expected = reference_match(rules, *request)
                with self.subTest(rules=rules, request=request):
                    self.assertEqual(fast.match_client(*request), expected)
                    self.assertEqual(loop.match_client(*request), expected)
                checked += 1
        self.assertEqual(checked, 3000)

    def test_every_pool_user_agent_against_every_single_rule(self):
        for rule in RULE_POOL:
            fast = compiled([rule])
            for user_agent in USER_AGENTS:
                with self.subTest(rule=rule, user_agent=user_agent[:30]):
                    self.assertEqual(fast.match_client("203.0.113.1", "x/", user_agent),
                                     reference_match([rule], "203.0.113.1", "x/", user_agent))

    def test_reports_the_first_rule_in_order(self):
        rules = [("ip", "10.0.0.0/24"), ("ip", "10.0.0.7"), ("user_agent", "sqlmap")]
        self.assertEqual(compiled(rules).match_client("10.0.0.7", "x/", "sqlmap"), ("ip", "10.0.0.0/24"))

    def test_empty_rule_set(self):
        self.assertIsNone(RuleSet().match_client("10.0.0.7", "admin/", "sqlmap"))
        self.assertEqual(len(RuleSet()), 0)

    def test_invalid_client_ip_is_logged_and_never_matches_networks(self):
        with self.assertLogs("middleman.ruleset", "WARNING") as logs:
            self.assertIsNone(compiled([("ip", "10.0.0.0/8")]).match_client("garbage", "x/", ""))
        self.assertIn("Client IP is not an IP address | ip='garbage'", logs.output[0])

    def test_compile_rejects_non_client_types(self):
        with self.assertRaises(ValueError):
            compile_client_rule("host", "example.com")


class PrefilterTest(SimpleTestCase):
    HOSTILE = "a" * 8192 + "!"

    def regex_rules(self, count):
        return [("user_agent_re", r"(a+)+scanner{}|evil{}bot/\d+".format(i, i)) for i in range(count)]

    def test_many_regex_rules_stay_fast_on_a_hostile_user_agent(self):
        # One 400-rule alternation overflowed RE2's DFA budget: 1.5 s per request.
        rules = compiled(self.regex_rules(400))
        started = time.perf_counter()
        for _ in range(5):
            self.assertIsNone(rules.match_client("203.0.113.1", "x/", self.HOSTILE))
        self.assertLess((time.perf_counter() - started) / 5, 0.25)

    def test_prefilters_are_split_by_program_size(self):
        rules = compiled(self.regex_rules(400))
        self.assertGreater(len(rules.user_agent_prefilters), 1)
        for prefilter in rules.user_agent_prefilters:
            self.assertLessEqual(prefilter.programsize, 2 * PREFILTER_CHUNK_PROGRAM_SIZE)

    def test_matches_in_any_chunk_are_found(self):
        rules = compiled(self.regex_rules(400))
        self.assertEqual(rules.match_client("1.1.1.1", "x/", "evil399bot/7"),
                         ("user_agent_re", r"(a+)+scanner399|evil399bot/\d+"))

    def test_no_user_agent_rules_no_prefilter(self):
        self.assertIsNone(compiled([("ip", "10.0.0.1")]).user_agent_prefilters)

    def test_prefilter_that_cannot_compile_falls_back_to_the_loop(self):
        with patch("middleman.ruleset._compile_prefilter", side_effect=ruleset_module.re2.error("too big")):
            with self.assertLogs("middleman.ruleset", "WARNING") as logs:
                rules = compiled([("user_agent", "sqlmap")])
        self.assertIsNone(rules.user_agent_prefilters)
        self.assertEqual(rules.match_client("1.1.1.1", "x/", "SQLMAP"), ("user_agent", "sqlmap"))
        self.assertIn("prefilter disabled", logs.output[0])


class RuleSetCacheTest(TestCase):
    def setUp(self):
        self.reported = []

    def ruleset(self):
        return cached_ruleset(lambda rule, error: self.reported.append((rule.value, error.reason)))

    def test_compiled_once_until_a_rule_changes(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        with patch("middleman.ruleset.build_ruleset", wraps=build_ruleset) as build:
            first = self.ruleset()
            self.assertIs(self.ruleset(), first)
            self.assertEqual(build.call_count, 1)
            rule = BlacklistRule.objects.create(rule_type="path", value="admin/")  # save: new token
            self.assertEqual(self.ruleset().match_client("1.1.1.1", "admin/", ""), ("path", "admin/"))
            rule.enabled = False
            rule.save(update_fields=["enabled"])
            self.assertIsNone(self.ruleset().match_client("1.1.1.1", "admin/", ""))
            rule.delete()
            self.ruleset()
            self.assertEqual(build.call_count, 4)

    def test_change_made_by_another_process_is_seen_on_the_next_request(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        self.assertIsNotNone(self.ruleset().match_client("1.1.1.1", "x/", "sqlmap"))
        # Another worker disabled it: its signal updated the token in the database;
        # this process's cache was not touched.
        BlacklistRule.objects.filter(value="sqlmap").update(enabled=False)
        RuleSetVersion.objects.filter(name="blacklist").update(token="written-by-another-process")
        self.assertIsNone(self.ruleset().match_client("1.1.1.1", "x/", "sqlmap"))

    def test_writes_that_bypass_signals_are_picked_up_after_max_age(self):
        self.ruleset()
        BlacklistRule.objects.bulk_create([BlacklistRule(rule_type="user_agent", value="sqlmap")])  # no signal
        self.assertIsNone(self.ruleset().match_client("1.1.1.1", "x/", "sqlmap"))  # still cached
        later = time.monotonic() + ruleset_module.MAX_AGE_SECONDS + 1
        with patch("middleman.ruleset.time.monotonic", return_value=later):
            self.assertIsNotNone(self.ruleset().match_client("1.1.1.1", "x/", "sqlmap"))

    def test_bump_creates_the_version_row_when_missing(self):
        RuleSetVersion.objects.all().delete()
        ruleset_module.bump_version()
        token = RuleSetVersion.objects.get(name="blacklist").token
        ruleset_module.bump_version()
        self.assertNotEqual(RuleSetVersion.objects.get(name="blacklist").token, token)

    def test_invalid_rules_are_reported_at_compile_time_and_skipped(self):
        rule = BlacklistRule.objects.create(rule_type="user_agent_re", value=".*")
        BlacklistRule.objects.filter(pk=rule.pk).update(created_by_version=LEGACY_VERSION)
        BlacklistRule.objects.create(rule_type="host", value="example.com")
        rules = self.ruleset()
        self.assertEqual(self.reported, [(".*", "regex_matches_everything")])
        self.assertEqual(len(rules.client_rules), 0)
        self.assertEqual([entry.value for entry in rules.host_rules], ["example.com"])

    def test_database_errors_propagate(self):
        with patch("middleman.ruleset.current_token", side_effect=OperationalError("Connection refused")):
            with self.assertRaises(OperationalError):
                self.ruleset()

    def test_one_token_query_per_request_even_with_redirect_checks(self):
        BlacklistRule.objects.create(rule_type="host", value="blocked.example")
        manager = ProxyManager("http://target.example/home/")
        with CaptureQueriesContext(connection) as queries:
            manager._is_blacklisted("1.1.1.1", "home/", "Mozilla")
            manager._blocked_destination("http://target.example/home/")
            manager._blocked_destination("http://hop.example/next/")
        token_queries = [q for q in queries.captured_queries if "middleman_ruleset_version" in q["sql"]]
        self.assertEqual(len(token_queries), 1)


class SettingRulesTest(SimpleTestCase):
    def test_setting_rules_are_compiled_once_per_value(self):
        services._compiled_setting_rules.cache_clear()
        first = services._compiled_setting_rules(("10.0.0.1",), (), (), ())
        self.assertIs(services._compiled_setting_rules(("10.0.0.1",), (), (), ()), first)
        self.assertIsNot(services._compiled_setting_rules(("10.0.0.2",), (), (), ()), first)
        self.assertEqual(first.match_client("10.0.0.1", "x/", ""), ("ip", "10.0.0.1"))
