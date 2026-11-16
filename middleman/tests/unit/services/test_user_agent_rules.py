"""
user_agent / user_agent_re blacklist rules: validation, matching, the model,
its migration and enforcement in ProxyManager.
"""

import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock, patch

from django.conf import settings
from django.core.exceptions import ValidationError
from django.test import RequestFactory, SimpleTestCase, TestCase

from middleman import services
from middleman.destinations import MAX_REGEX_LENGTH, parse_host_regex
from middleman.exceptions import (BlacklistedAccessException,
                                  ExceededRequestsLimitException,
                                  InvalidRuleError)
from middleman.models import AccessEntry, BlacklistRule
from middleman.rules import (CLIENT_RULE_TYPES, HOST_RULE_TYPES,
                             USER_AGENT_RULE_TYPES, validate_rule)
from middleman.services import ProxyManager
from middleman.user_agents import (LOGGED_USER_AGENT_LENGTH,
                                   MIN_USER_AGENT_LENGTH, UserAgentRule,
                                   loggable_user_agent,
                                   parse_user_agent_regex,
                                   parse_user_agent_rule, user_agent_from_meta,
                                   user_agent_matches)
from middleman.version import LEGACY_VERSION

CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
SQLMAP = "sqlmap/1.7.2#stable (https://sqlmap.org)"


class UserAgentSubstringRuleTest(SimpleTestCase):
    def assertRejected(self, value, reason):
        with self.assertRaises(InvalidRuleError) as ctx:
            parse_user_agent_rule(value)
        self.assertEqual(ctx.exception.reason, reason, str(ctx.exception))
        self.assertEqual(ctx.exception.rule_type, "user_agent")
        self.assertEqual(ctx.exception.value, value)
        return ctx.exception

    def test_accepts_distinctive_tokens(self):
        for value in ["sqlmap", "python-requests/", "Nikto", "curl/7.", "Go-http-client",
                      "Mozilla/5.0 (compatible; BadBot/1.0)", "abc"]:
            with self.subTest(value=value):
                self.assertEqual(parse_user_agent_rule(value).kind, "substring")

    def test_value_is_stripped_and_lowercased_for_matching(self):
        self.assertEqual(parse_user_agent_rule("  SQLMap  "), UserAgentRule("substring", "sqlmap"))

    def test_empty(self):
        for value in ["", "   ", None]:
            with self.subTest(value=value):
                self.assertRejected(value, "empty")

    def test_too_short_tokens_would_match_unrelated_clients(self):
        error = self.assertRejected("go", "too_short")
        self.assertIn(str(MIN_USER_AGENT_LENGTH), error.message)
        self.assertRejected("/", "too_short")

    def test_star_is_not_a_wildcard_here(self):
        error = self.assertRejected("sqlmap*", "unsupported_wildcard")
        self.assertIn("User-Agent (regex)", error.message)
        self.assertRejected("*bot*", "unsupported_wildcard")

    def test_non_ascii_could_never_match(self):
        self.assertRejected("bücherbot", "non_ascii")

    def test_control_characters(self):
        for value in ["bad\tbot", "bad\nbot", "bad\x00bot", "bad\x7fbot"]:
            with self.subTest(value=value):
                self.assertRejected(value, "invalid_characters")


class UserAgentRegexRuleTest(SimpleTestCase):
    def assertRejected(self, pattern, reason):
        with self.assertRaises(InvalidRuleError) as ctx:
            parse_user_agent_regex(pattern)
        self.assertEqual(ctx.exception.reason, reason, str(ctx.exception))
        self.assertEqual(ctx.exception.rule_type, "user_agent_re")
        return ctx.exception

    def test_accepts_valid_patterns(self):
        for pattern in [
            r"sqlmap|nikto|masscan",
            r"^python-requests/",
            r"^$",  # missing / empty User-Agent
            r"curl/[0-7]\.",
            r"(bad|evil)bot/\d+",
            r"^Mozilla/4\.0 \(compatible; MSIE 6\.0",  # spaces, '/' and '(' are normal here
            r"scan.*tool",  # unescaped dots are fine for User-Agents
        ]:
            with self.subTest(pattern=pattern):
                self.assertEqual(parse_user_agent_regex(pattern).kind, "regex")

    def test_empty(self):
        self.assertRejected("  ", "empty")

    def test_re_prefix(self):
        self.assertRejected("re:sqlmap", "regex_prefix")

    def test_too_long(self):
        self.assertRejected("a" * (MAX_REGEX_LENGTH + 1), "regex_too_long")

    def test_non_ascii(self):
        self.assertRejected("bücher", "regex_non_ascii")

    def test_syntax_errors_and_unsupported_constructs(self):
        for pattern in ["(sqlmap", "[a-z", r"(a)\1", "(?=x)x", "(?<!x)bot"]:
            with self.subTest(pattern=pattern):
                error = self.assertRejected(pattern, "regex_syntax")
                self.assertIn("RE2", error.message)

    def test_too_complex(self):
        self.assertRejected(r"([a-z0-9-]{1,63}/){1,10}bot", "regex_too_complex")

    def test_patterns_matching_every_client_are_rejected(self):
        # "." and "[a-z]" do not match a missing User-Agent, but block every real client.
        for pattern in [".*", ".", "|sqlmap", "x*", "^", "(?s).*", r"\w|^$", "[a-z]", r"\S"]:
            with self.subTest(pattern=pattern):
                self.assertRejected(pattern, "regex_matches_everything")

    def test_host_regex_validation_is_unchanged_by_the_shared_compiler(self):
        self.assertEqual(parse_host_regex(r"(www\.)?example\.com").kind, "regex")
        for pattern, reason in [("(example\\.com", "regex_syntax"),
                                (r"([a-z0-9-]{1,63}\.){1,10}example\.com", "regex_too_complex")]:
            with self.assertRaises(InvalidRuleError) as ctx:
                parse_host_regex(pattern)
            self.assertEqual((ctx.exception.reason, ctx.exception.rule_type), (reason, "host_re"))


class UserAgentMatchingTest(SimpleTestCase):
    def test_substring_is_case_insensitive_and_matches_anywhere(self):
        rule = parse_user_agent_rule("sqlmap")
        for user_agent in [SQLMAP, "SQLMAP", "Mozilla/5.0 (compatible; SqLmAp)", "xsqlmapx"]:
            with self.subTest(user_agent=user_agent):
                self.assertTrue(user_agent_matches(rule, user_agent))
        for user_agent in [CHROME, "sql map", "sqlma", ""]:
            with self.subTest(user_agent=user_agent):
                self.assertFalse(user_agent_matches(rule, user_agent))

    def test_substring_never_matches_a_missing_user_agent(self):
        self.assertFalse(user_agent_matches(parse_user_agent_rule("abc"), None))

    def test_regex_is_searched_case_insensitively(self):
        rule = parse_user_agent_regex("sqlmap|nikto")
        self.assertTrue(user_agent_matches(rule, "Mozilla/5.0 (Nikto/2.5.0)"))
        self.assertTrue(user_agent_matches(rule, SQLMAP.upper()))
        self.assertFalse(user_agent_matches(rule, CHROME))

    def test_regex_anchors(self):
        rule = parse_user_agent_regex("^python-requests/")
        self.assertTrue(user_agent_matches(rule, "python-requests/2.31.0"))
        self.assertFalse(user_agent_matches(rule, "my-app (python-requests/2.31.0)"))

    def test_empty_regex_blocks_missing_and_empty_user_agents_only(self):
        rule = parse_user_agent_regex("^$")
        self.assertTrue(user_agent_matches(rule, ""))
        self.assertTrue(user_agent_matches(rule, None))
        self.assertFalse(user_agent_matches(rule, " "))
        self.assertFalse(user_agent_matches(rule, CHROME))

    def test_latin1_bytes_in_the_header_do_not_break_matching(self):
        # WSGI decodes header bytes as latin-1.
        user_agent = "Caf\xe9Bot \xff\xfe sqlmap"
        self.assertTrue(user_agent_matches(parse_user_agent_rule("sqlmap"), user_agent))
        self.assertTrue(user_agent_matches(parse_user_agent_regex("sqlmap$"), user_agent))

    def test_regex_matching_is_linear_on_hostile_input(self):
        rule = parse_user_agent_regex(r"(a+)+b")
        started = time.perf_counter()
        self.assertFalse(user_agent_matches(rule, "a" * 100_000 + "!"))
        self.assertLess(time.perf_counter() - started, 0.5)

    def test_unknown_kind_never_matches(self):
        self.assertFalse(user_agent_matches(UserAgentRule("other", "x"), "x"))

    def test_user_agent_from_meta(self):
        self.assertEqual(user_agent_from_meta({"HTTP_USER_AGENT": "curl/8"}), "curl/8")
        self.assertEqual(user_agent_from_meta({}), "")
        self.assertEqual(user_agent_from_meta({"HTTP_USER_AGENT": None}), "")

    def test_loggable_user_agent_is_truncated(self):
        self.assertEqual(loggable_user_agent("curl/8"), "curl/8")
        self.assertEqual(loggable_user_agent(None), "")
        long_value = "A" * (LOGGED_USER_AGENT_LENGTH + 50)
        logged = loggable_user_agent(long_value)
        self.assertTrue(logged.startswith("A" * LOGGED_USER_AGENT_LENGTH))
        self.assertTrue(logged.endswith("(+50 chars)"))


class RuleTypeRegistryTest(SimpleTestCase):
    def test_validate_rule_dispatches_user_agent_types(self):
        self.assertEqual(validate_rule("user_agent", "sqlmap").kind, "substring")
        self.assertEqual(validate_rule("user_agent_re", "sqlmap|nikto").kind, "regex")
        with self.assertRaises(InvalidRuleError) as ctx:
            validate_rule("user_agent", "go")
        self.assertEqual(ctx.exception.reason, "too_short")

    def test_rule_type_groups(self):
        self.assertEqual(set(USER_AGENT_RULE_TYPES), {"user_agent", "user_agent_re"})
        self.assertTrue(set(USER_AGENT_RULE_TYPES) <= set(CLIENT_RULE_TYPES))
        self.assertFalse(set(CLIENT_RULE_TYPES) & set(HOST_RULE_TYPES))
        # Every model choice is enforced somewhere.
        self.assertEqual(set(BlacklistRule.RuleType.values), set(CLIENT_RULE_TYPES) | set(HOST_RULE_TYPES))


class BlacklistRuleModelUserAgentTest(SimpleTestCase):
    def test_rule_type_column_fits_every_choice(self):
        # SQLite (tests) ignores varchar lengths; Postgres (production) rejects
        # longer values. "user_agent_re" did not fit the old max_length=8.
        field = BlacklistRule._meta.get_field("rule_type")
        for value in BlacklistRule.RuleType.values:
            with self.subTest(rule_type=value):
                self.assertLessEqual(len(value), field.max_length)

    def test_full_clean_accepts_user_agent_rules(self):
        for rule_type, value in [("user_agent", "sqlmap"), ("user_agent_re", "^$")]:
            with self.subTest(rule_type=rule_type):
                BlacklistRule(rule_type=rule_type, value=value).full_clean(
                    exclude=["created_by_version"], validate_unique=False, validate_constraints=False
                )

    def test_clean_reports_reason_as_error_code(self):
        with self.assertRaises(ValidationError) as ctx:
            BlacklistRule(rule_type="user_agent", value="bot*").clean()
        self.assertEqual(ctx.exception.error_dict["value"][0].code, "unsupported_wildcard")

    def test_validation_error_property(self):
        self.assertIsNone(BlacklistRule(rule_type="user_agent_re", value="sqlmap").validation_error)
        self.assertEqual(
            BlacklistRule(rule_type="user_agent_re", value=".*").validation_error.reason,
            "regex_matches_everything",
        )

    def test_not_a_cidr_rule(self):
        self.assertFalse(BlacklistRule(rule_type="user_agent", value="a/b").is_cidr)


class MigrationStateTest(SimpleTestCase):
    """The suite runs with --nomigrations, so check the migration files out of process."""

    def test_models_and_migrations_are_in_sync(self):
        project_root = Path(settings.BASE_DIR)
        env = dict(os.environ, DJANGO_SETTINGS_MODULE="proxy.test_settings")
        result = subprocess.run(
            [sys.executable, "manage.py", "makemigrations", "middleman", "--check", "--dry-run"],
            cwd=project_root, env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_user_agent_migration_widens_rule_type(self):
        from importlib import import_module

        from django.db import migrations

        migration = import_module("middleman.migrations.0007_blacklistrule_user_agent_types").Migration
        alter, park = migration.operations
        self.assertIsInstance(alter, migrations.AlterField)
        self.assertEqual((alter.model_name, alter.name), ("blacklistrule", "rule_type"))
        self.assertGreaterEqual(alter.field.max_length, len("user_agent_re"))
        self.assertIn("user_agent_re", dict(alter.field.choices))
        # Reversible: rollback parks User-Agent rules (see test_migrations.py).
        self.assertIsInstance(park, migrations.RunPython)
        self.assertTrue(park.reversible)


class ProxyManagerUserAgentTest(TestCase):
    def setUp(self):
        self.manager = ProxyManager("https://target.example/index/")

    def request(self, **meta):
        return RequestFactory().get("/proxy/index/", REMOTE_ADDR="10.0.0.9", **meta)

    def access(self, **meta):
        with patch.object(self.manager, "do_request", return_value=Mock(status_code=200)) as do_request:
            try:
                return self.manager.access_filter(self.request(**meta), "index/")
            finally:
                self.do_request = do_request

    def test_is_blacklisted_matches_user_agent_rules(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        BlacklistRule.objects.create(rule_type="user_agent_re", value="^$")
        self.assertEqual(self.manager._is_blacklisted("10.0.0.9", "index/", SQLMAP), ("user_agent", "sqlmap"))
        self.assertEqual(self.manager._is_blacklisted("10.0.0.9", "index/", ""), ("user_agent_re", "^$"))
        self.assertIsNone(self.manager._is_blacklisted("10.0.0.9", "index/", CHROME))

    def test_is_blacklisted_keeps_its_old_signature(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        BlacklistRule.objects.create(rule_type="path", value="index/")
        self.assertEqual(self.manager._is_blacklisted("10.0.0.9", "index/"), ("path", "index/"))

    def test_disabled_user_agent_rules_do_not_apply(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap", enabled=False)
        self.assertIsNone(self.manager._is_blacklisted("10.0.0.9", "index/", SQLMAP))

    def test_access_filter_blocks_before_rate_limiting_and_fetching(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        with self.assertRaises(BlacklistedAccessException) as ctx:
            self.access(HTTP_USER_AGENT=SQLMAP)
        exc = ctx.exception
        self.assertEqual((exc.ip, exc.path, exc.rule_type, exc.rule_value), ("10.0.0.9", "index/", "user_agent", "sqlmap"))
        self.assertEqual(exc.user_agent, SQLMAP)
        self.assertNotIn(SQLMAP, str(exc))  # the body never echoes the client's header
        self.do_request.assert_not_called()
        self.assertFalse(AccessEntry.objects.exists())

    def test_allowed_user_agent_goes_through_and_is_recorded_on_the_manager(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        self.access(HTTP_USER_AGENT=CHROME)
        self.do_request.assert_called_once()
        self.assertEqual(self.manager.user_agent, CHROME)
        self.assertEqual(AccessEntry.objects.get().already_requested, 1)

    def test_missing_user_agent_is_blocked_only_by_an_empty_regex(self):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        self.access()  # no User-Agent header: substring rules never match
        self.assertEqual(self.manager.user_agent, "")
        BlacklistRule.objects.create(rule_type="user_agent_re", value="^$")
        with self.assertRaises(BlacklistedAccessException) as ctx:
            self.access()
        self.assertEqual(ctx.exception.rule_type, "user_agent_re")
        self.assertEqual(ctx.exception.user_agent, "")

    def test_ip_and_path_blocks_do_not_carry_the_user_agent(self):
        BlacklistRule.objects.create(rule_type="ip", value="10.0.0.9")
        with self.assertRaises(BlacklistedAccessException) as ctx:
            self.access(HTTP_USER_AGENT=SQLMAP)
        self.assertEqual(ctx.exception.rule_type, "ip")
        self.assertIsNone(ctx.exception.user_agent)

    def test_rate_limit_still_applies_to_allowed_user_agents(self):
        key = self.manager._create_unique_key("10.0.0.9", "index/")
        AccessEntry.objects.create(key=key, ip="10.0.0.9", path="index/", already_requested=1, max_requests=1)
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        with self.assertRaises(ExceededRequestsLimitException):
            self.access(HTTP_USER_AGENT=CHROME)

    def test_invalid_legacy_user_agent_rule_is_skipped_and_reported_once(self):
        services._REPORTED_INVALID_RULES.clear()
        rule = BlacklistRule.objects.create(rule_type="user_agent_re", value=".*")
        BlacklistRule.objects.filter(pk=rule.pk).update(created_by_version=LEGACY_VERSION)

        with self.assertLogs("middleman.services", "WARNING") as logs:
            self.access(HTTP_USER_AGENT=SQLMAP)
            self.manager._is_blacklisted("10.0.0.9", "index/", SQLMAP)

        self.do_request.assert_called_once()  # never applied
        self.assertEqual(len(logs.records), 1)
        self.assertIn("rule_type='user_agent_re'", logs.output[0])
        self.assertIn("reason=regex_matches_everything", logs.output[0])


def start_django(**env):
    """Import settings in a fresh interpreter and print the parsed User-Agent settings."""
    code = (
        "import django, json; django.setup(); from django.conf import settings;"
        "print(json.dumps([settings.BLACKLISTED_USER_AGENTS, settings.BLACKLISTED_USER_AGENTS_RE]))"
    )
    clean = {k: v for k, v in os.environ.items() if not k.startswith("BLACKLISTED_")}
    clean.update(DJANGO_SETTINGS_MODULE="proxy.test_settings", **env)
    return subprocess.run([sys.executable, "-c", code], cwd=settings.BASE_DIR, env=clean,
                          capture_output=True, text=True)


class UserAgentSettingsStartupTest(SimpleTestCase):
    def test_unset_means_no_rules(self):
        result = start_django()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "[[], []]")

    def test_json_arrays_keep_commas_and_regex_syntax(self):
        result = start_django(
            BLACKLISTED_USER_AGENTS='["sqlmap", " Mozilla/5.0 (compatible; BadBot, v1) ", ""]',
            BLACKLISTED_USER_AGENTS_RE='["^$", "nikto|masscan", "bot/\\\\d+"]',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip().splitlines()[-1],
            '[["sqlmap", "Mozilla/5.0 (compatible; BadBot, v1)"], ["^$", "nikto|masscan", "bot/\\\\d+"]]',
        )

    def test_malformed_values_stop_startup(self):
        for value in ["sqlmap,nikto", '{"ua": "sqlmap"}', '["sqlmap", 3]', '"sqlmap"', "[unclosed"]:
            with self.subTest(value=value):
                result = start_django(BLACKLISTED_USER_AGENTS=value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("BLACKLISTED_USER_AGENTS must be a JSON array of strings", result.stderr)
        result = start_django(BLACKLISTED_USER_AGENTS_RE="^$")
        self.assertIn("BLACKLISTED_USER_AGENTS_RE must be a JSON array of strings", result.stderr)


class UserAgentSettingRulesTest(TestCase):
    def setUp(self):
        services._REPORTED_INVALID_RULES.clear()
        self.manager = ProxyManager("https://target.example/index/")

    def test_setting_rules_block(self):
        with patch("middleman.services.BLACKLISTED_USER_AGENTS", ["BadBot, v1"]), \
                patch("middleman.services.BLACKLISTED_USER_AGENTS_RE", ["^$"]):
            self.assertEqual(
                self.manager._is_blacklisted("10.0.0.9", "index/", "Mozilla/5.0 (compatible; badbot, V1)"),
                ("user_agent", "BadBot, v1"),
            )
            self.assertEqual(self.manager._is_blacklisted("10.0.0.9", "index/", ""), ("user_agent_re", "^$"))
            self.assertIsNone(self.manager._is_blacklisted("10.0.0.9", "index/", CHROME))

    def test_setting_rules_apply_through_the_proxy(self):
        request = RequestFactory().get("/proxy/index/", REMOTE_ADDR="10.0.0.9", HTTP_USER_AGENT=SQLMAP)
        with patch("middleman.services.BLACKLISTED_USER_AGENTS_RE", ["^sqlmap/"]):
            with self.assertRaises(BlacklistedAccessException) as ctx:
                self.manager.access_filter(request, "index/")
        self.assertEqual((ctx.exception.rule_type, ctx.exception.user_agent), ("user_agent_re", SQLMAP))
        self.assertFalse(AccessEntry.objects.exists())

    def test_invalid_setting_entries_are_skipped_and_reported_once(self):
        with patch("middleman.services.BLACKLISTED_USER_AGENTS", ["go", "sqlmap"]), \
                patch("middleman.services.BLACKLISTED_USER_AGENTS_RE", [".*"]):
            with self.assertLogs("middleman.services", "WARNING") as logs:
                self.assertEqual(self.manager._is_blacklisted("10.0.0.9", "index/", SQLMAP), ("user_agent", "sqlmap"))
                self.assertIsNone(self.manager._is_blacklisted("10.0.0.9", "index/", CHROME))
        self.assertEqual(len(logs.records), 2)  # once per invalid entry, not per request
        self.assertIn("source=BLACKLISTED_USER_AGENTS id=None rule_type='user_agent' value='go' "
                      "created_by_version=None reason=too_short", logs.output[0])
        self.assertIn("fix the BLACKLISTED_USER_AGENTS setting", logs.output[0])
        self.assertIn("source=BLACKLISTED_USER_AGENTS_RE", logs.output[1])
        self.assertIn("reason=regex_matches_everything", logs.output[1])

    def test_ip_and_path_settings_are_checked_first(self):
        with patch("middleman.services.BLACKLISTED_PATHS", ["index/"]), \
                patch("middleman.services.BLACKLISTED_USER_AGENTS", ["sqlmap"]):
            self.assertEqual(self.manager._is_blacklisted("10.0.0.9", "index/", SQLMAP), ("path", "index/"))
