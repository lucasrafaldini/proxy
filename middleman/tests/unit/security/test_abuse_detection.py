"""Abuse detection: signals, scoring, thresholds, windows, automatic hiding and false positives."""

import io
from datetime import timedelta
from unittest.mock import Mock, patch

from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from middleman import abuse
from middleman import client_ip
from middleman.client_ip import resolve_client
from middleman.models import AbuseSignal, AccessEntry, BlacklistRule, ClientPolicy
from middleman.services import ProxyManager

URL = "/proxy/home/"
PEER = "198.51.100.30"
OTHER = "198.51.100.31"


def upstream_response(*args, **kwargs):
    response = Mock(status_code=200, reason="OK", raw=io.BytesIO(b"ok"))
    response.headers = {"content-type": "text/plain"}
    return response


class RequestSignalsTest(SimpleTestCase):
    def setUp(self):
        client_ip._WARNED_UNTRUSTED_PEERS.clear()  # warn-once state is per process

    def signals(self, meta):
        meta = dict({"REMOTE_ADDR": PEER}, **meta)
        return abuse.request_signals(meta, resolve_client(meta))

    def test_forged_rate_limit_headers_in_any_spelling(self):
        for key in ["HTTP_X_RATELIMIT_REMAINING", "HTTP_X_RATELIMIT_LIMIT", "HTTP_RATELIMIT",
                    "HTTP_RATELIMIT_POLICY", "HTTP_X_RATE_LIMIT_RESET", "HTTP_RATE_LIMIT"]:
            with self.subTest(key=key):
                self.assertEqual(self.signals({key: "1"}), [("forged_rate_limit_header", "")])

    def test_similar_but_legitimate_headers_are_not_signals(self):
        for key in ["HTTP_X_RATELIMITER_VERSION", "HTTP_X_RATING", "HTTP_ACCEPT", "HTTP_X_LIMIT", "HTTP_USER_AGENT"]:
            with self.subTest(key=key):
                self.assertEqual(self.signals({key: "1"}), [])

    def test_one_signal_per_request_however_many_forged_headers(self):
        signals = self.signals({"HTTP_X_RATELIMIT_REMAINING": "1", "HTTP_X_RATELIMIT_LIMIT": "1", "HTTP_RATELIMIT": "1"})
        self.assertEqual(signals, [("forged_rate_limit_header", "")])

    def test_forwarding_data_is_fingerprinted_not_stored(self):
        with self.assertLogs("middleman.client_ip", "WARNING"):
            (kind, fp), = self.signals({"HTTP_X_FORWARDED_FOR": "203.0.113.5"})
        self.assertEqual(kind, "forwarding_rotation")
        self.assertRegex(fp, r"^[0-9a-f]{32}$")
        self.assertNotIn("203.0.113.5", fp)

    def test_no_forwarding_data_no_signal(self):
        self.assertEqual(self.signals({}), [])

    @override_settings(TRUSTED_PROXIES=["10.0.0.2"])
    def test_behind_trusted_proxy_only_the_client_written_part_counts(self):
        meta = {"REMOTE_ADDR": "10.0.0.2", "HTTP_X_FORWARDED_FOR": "203.0.113.7"}
        self.assertEqual(abuse.request_signals(meta, resolve_client(meta)), [])
        meta = {"REMOTE_ADDR": "10.0.0.2", "HTTP_X_FORWARDED_FOR": "1.1.1.1, 203.0.113.7"}
        (kind, _), = abuse.request_signals(meta, resolve_client(meta))
        self.assertEqual(kind, "forwarding_rotation")


class ScoringTest(TestCase):
    def record(self, kind, fp="", times=1, now=None):
        now = now or timezone.now()
        for _ in range(times):
            abuse._record(PEER, kind, fp, now)

    def test_weights(self):
        self.record("rate_limited_retry", times=3)
        self.record("auth_failure", times=2)
        self.record("forged_rate_limit_header")
        self.assertEqual(abuse.score(PEER), (3 * 1 + 2 * 3 + 5, {"rate_limited_retry": 3, "auth_failure": 6, "forged_rate_limit_header": 5}))

    def test_forwarding_scores_only_additional_distinct_values(self):
        self.record("forwarding_rotation", "a", times=50)  # constant value: corporate proxy
        self.assertEqual(abuse.score(PEER)[0], 0)
        self.record("forwarding_rotation", "b")
        self.record("forwarding_rotation", "c")
        self.assertEqual(abuse.score(PEER)[0], 2 * 3)

    def test_events_in_the_same_minute_share_one_row(self):
        self.record("blacklist_hit", times=50)
        self.assertEqual(AbuseSignal.objects.count(), 1)
        self.assertEqual(AbuseSignal.objects.get().count, 50)

    def test_window_boundaries(self):
        now = timezone.now().replace(second=30)
        window = abuse.get_config()["WINDOW_MINUTES"]
        self.record("rate_limited_retry", now=now - timedelta(minutes=window - 1))  # oldest bucket inside
        self.record("auth_failure", now=now - timedelta(minutes=window))  # just outside
        self.assertEqual(abuse.score(PEER, now=now), (1, {"rate_limited_retry": 1}))

    def test_scores_are_per_client(self):
        self.record("auth_failure", times=5)
        self.assertEqual(abuse.score(OTHER)[0], 0)

    def test_concurrent_bucket_creation_still_counts(self):
        from django.db.models.query import QuerySet

        now = timezone.now()
        # A competing request already inserted the bucket, but our first
        # UPDATE ran just before that insert and matched nothing.
        abuse._record(PEER, "blacklist_hit", "", now)
        real_update, calls = QuerySet.update, []

        def update(queryset, **kwargs):
            calls.append(kwargs)
            return 0 if len(calls) == 1 else real_update(queryset, **kwargs)

        with patch.object(QuerySet, "update", update):
            abuse._record(PEER, "blacklist_hit", "", now)  # INSERT hits the real unique constraint
        self.assertEqual(len(calls), 2)  # missed UPDATE, then the fallback UPDATE
        self.assertEqual(AbuseSignal.objects.get().count, 2)


class ThresholdAndPolicyTest(TestCase):
    def report(self, kind, times=1):
        for _ in range(times):
            abuse.report(PEER, [(kind, "")])

    def test_below_threshold_nothing_happens(self):
        with self.assertLogs("middleman.abuse", "INFO"):
            self.report("rate_limited_retry", times=9)
        self.assertFalse(ClientPolicy.objects.exists())

    def test_reaching_the_threshold_hides_headers_automatically(self):
        with self.assertLogs("middleman.abuse", "INFO") as logs:
            self.report("rate_limited_retry", times=10)
        policy = ClientPolicy.objects.get(ip=PEER)
        self.assertTrue(policy.hide_rate_limit_headers)
        self.assertEqual(policy.source, "automatic")
        self.assertIn("Abuse score 10 >= 10 in 10 min: rate_limited_retry=10", policy.reason)
        warnings = [line for line in logs.output if line.startswith("WARNING")]
        self.assertEqual(len(warnings), 1)
        self.assertIn("Hiding rate limit headers for client | ip={} score=10".format(PEER), warnings[0])

    def test_further_signals_do_not_log_the_decision_again(self):
        with self.assertLogs("middleman.abuse", "INFO"):
            self.report("rate_limited_retry", times=10)
        with self.assertLogs("middleman.abuse", "INFO") as logs:
            self.report("rate_limited_retry", times=5)
        self.assertFalse([line for line in logs.output if line.startswith("WARNING")])

    def test_admin_decision_to_show_headers_is_final(self):
        ClientPolicy.objects.create(ip=PEER, hide_rate_limit_headers=False, source="manual", reason="trusted partner")
        with self.assertLogs("middleman.abuse", "INFO"):
            self.report("auth_failure", times=20)
        policy = ClientPolicy.objects.get(ip=PEER)
        self.assertEqual((policy.hide_rate_limit_headers, policy.source, policy.reason), (False, "manual", "trusted partner"))

    def test_admin_decision_to_hide_is_kept_as_manual(self):
        ClientPolicy.objects.create(ip=PEER, hide_rate_limit_headers=True, source="manual", reason="ticket 42")
        with self.assertLogs("middleman.abuse", "INFO"):
            self.report("auth_failure", times=20)
        policy = ClientPolicy.objects.get(ip=PEER)
        self.assertEqual((policy.source, policy.reason), ("manual", "ticket 42"))

    def test_concurrent_flagging_creates_one_policy(self):
        from django.db.models.query import QuerySet

        # Another request flagged the client between our lookup and our insert.
        ClientPolicy.objects.create(ip=PEER, hide_rate_limit_headers=True, source="automatic", reason="first")
        real_first = QuerySet.first

        def first(queryset):
            return None if queryset.model is ClientPolicy else real_first(queryset)

        with patch.object(QuerySet, "first", first):
            with self.assertLogs("middleman.abuse", "INFO"):
                self.report("auth_failure", times=4)
        self.assertEqual(ClientPolicy.objects.filter(ip=PEER).count(), 1)
        self.assertEqual(ClientPolicy.objects.get(ip=PEER).reason, "first")

    def test_automatic_policy_with_headers_shown_is_re_flagged(self):
        # Not produced by the app (admin edits become manual), e.g. a direct DB edit.
        ClientPolicy.objects.create(ip=PEER, hide_rate_limit_headers=False, source="automatic")
        with self.assertLogs("middleman.abuse", "INFO"):
            self.report("auth_failure", times=4)
        policy = ClientPolicy.objects.get(ip=PEER)
        self.assertTrue(policy.hide_rate_limit_headers)
        self.assertIn("auth_failure=12", policy.reason)

    @override_settings(ABUSE_DETECTION={"ENABLED": False})
    def test_disabled_detection_records_nothing(self):
        self.report("auth_failure", times=20)
        self.assertFalse(AbuseSignal.objects.exists())
        self.assertFalse(ClientPolicy.objects.exists())

    @override_settings(ABUSE_DETECTION={"THRESHOLD": 3, "WEIGHTS": {"rate_limited_retry": 0}})
    def test_configurable_threshold_and_weights(self):
        with self.assertLogs("middleman.abuse", "INFO"):
            self.report("rate_limited_retry", times=50)  # weight 0: ignored
        self.assertFalse(ClientPolicy.objects.exists())
        with self.assertLogs("middleman.abuse", "INFO"):
            self.report("auth_failure")
        self.assertTrue(ClientPolicy.objects.get(ip=PEER).hide_rate_limit_headers)

    def test_detection_failure_is_logged_and_swallowed(self):
        with patch("middleman.abuse._record", side_effect=RuntimeError("db down")):
            with self.assertLogs("middleman.abuse", "ERROR") as logs:
                abuse.report(PEER, [("auth_failure", "")])
        self.assertIn("Failed to record abuse signals | ip={}".format(PEER), logs.output[0])
        self.assertIn("RuntimeError: db down", logs.output[0])

    def test_nothing_to_report(self):
        abuse.report(PEER, [])
        abuse.report(None, [("auth_failure", "")])
        self.assertFalse(AbuseSignal.objects.exists())


class ConfigValidationTest(SimpleTestCase):
    def test_defaults(self):
        self.assertEqual(abuse.get_config()["THRESHOLD"], 10)

    def test_invalid_configurations(self):
        invalid = [
            {"UNKNOWN": 1},
            {"THRESHOLD": 0},
            {"THRESHOLD": True},
            {"THRESHOLD": "10"},
            {"WINDOW_MINUTES": -1},
            {"ENABLED": "yes"},
            {"WEIGHTS": {"made_up_kind": 1}},
            {"WEIGHTS": {"auth_failure": -1}},
            {"WEIGHTS": {"auth_failure": 1.5}},
        ]
        for config in invalid:
            with self.subTest(config=config):
                with override_settings(ABUSE_DETECTION=config):
                    with self.assertRaises(ImproperlyConfigured):
                        abuse.get_config()


@patch("middleman.upstream.get", side_effect=upstream_response)
@patch("middleman.upstream.head", side_effect=upstream_response)
class EndToEndDetectionTest(TestCase):
    """Real requests through the proxy until the client gets flagged."""

    def setUp(self):
        self.client = APIClient()

    def get(self, ip=PEER, **headers):
        return self.client.get(URL, REMOTE_ADDR=ip, **headers)

    def assertShowsHeaders(self, response, shown=True):
        self.assertEqual(response.has_header("X-RateLimit-Limit"), shown)
        self.assertEqual(response.has_header("X-RateLimit-Remaining"), shown)

    def test_forged_rate_limit_headers(self, head, get):
        with self.assertLogs("middleman", "INFO"):
            first = self.get(HTTP_X_RATELIMIT_REMAINING="9999")
            second = self.get(HTTP_X_RATELIMIT_REMAINING="9999")  # score 10: flagged after this one
            third = self.get()
        self.assertShowsHeaders(first)
        self.assertShowsHeaders(second)
        self.assertEqual(third.status_code, 200)  # still served...
        self.assertShowsHeaders(third, shown=False)  # ...but blind to its limits

    def test_rotating_spoofed_forwarding_headers(self, head, get):
        with self.assertLogs("middleman", "INFO"):
            for i in range(5):  # 4 additional distinct values x 3 = 12
                self.get(HTTP_X_FORWARDED_FOR="203.0.113.{}".format(i))
        self.assertShowsHeaders(self.get(), shown=False)

    def test_constant_forwarding_header_is_not_abuse(self, head, get):
        # Corporate forward proxies add a constant X-Forwarded-For.
        with self.assertLogs("middleman", "WARNING"):
            for _ in range(30):
                self.get(HTTP_X_FORWARDED_FOR="10.20.30.40")
        self.assertShowsHeaders(self.get(HTTP_X_FORWARDED_FOR="10.20.30.40"))
        self.assertFalse(ClientPolicy.objects.exists())

    def test_hammering_after_429(self, head, get):
        key = ProxyManager("")._create_unique_key(PEER, "home/")
        AccessEntry.objects.create(key=key, ip=PEER, path="home/", already_requested=5, max_requests=5)
        with self.assertLogs("middleman", "INFO"):
            responses = [self.get() for _ in range(11)]
        self.assertTrue(all(r.status_code == 429 for r in responses))
        self.assertShowsHeaders(responses[0])
        self.assertShowsHeaders(responses[-1], shown=False)  # 429s stop revealing the limit too

    def test_probing_blacklisted_paths(self, head, get):
        BlacklistRule.objects.create(rule_type="path", value="home/")
        with self.assertLogs("middleman", "INFO"):
            for _ in range(10):
                self.assertEqual(self.get().status_code, 403)
        self.assertTrue(abuse.hides_rate_limit_headers(PEER))

    def test_destination_blocks_are_not_the_clients_fault(self, head, get):
        BlacklistRule.objects.create(rule_type="host", value="localhost")
        with self.assertLogs("middleman", "WARNING"):
            for _ in range(15):
                self.assertEqual(self.get().status_code, 403)
        self.assertFalse(AbuseSignal.objects.exists())

    def test_bad_tokens_against_the_management_api(self, head, get):
        with self.assertLogs("middleman", "INFO"):
            for _ in range(4):
                self.client.get("/registry/", REMOTE_ADDR=PEER, HTTP_AUTHORIZATION="Bearer mm_00000000_" + "A" * 43)
        self.assertShowsHeaders(self.get(), shown=False)

    def test_anonymous_management_attempts(self, head, get):
        with self.assertLogs("middleman", "INFO"):
            for _ in range(10):
                self.client.patch("/registry/", {"key": "x", "action": "reset_already_requested"}, format="json", REMOTE_ADDR=PEER)
        self.assertTrue(abuse.hides_rate_limit_headers(PEER))

    def test_other_clients_are_unaffected(self, head, get):
        with self.assertLogs("middleman", "INFO"):
            for _ in range(3):
                self.get(HTTP_X_RATELIMIT_REMAINING="1")
        self.assertShowsHeaders(self.get(ip=OTHER))

    def test_flag_applies_to_every_path_of_the_client(self, head, get):
        ClientPolicy.objects.create(ip=PEER, hide_rate_limit_headers=True, source="automatic")
        for path in ["/proxy/home/", "/proxy/other/", "/proxy/x/"]:
            with self.subTest(path=path):
                self.assertShowsHeaders(self.client.get(path, REMOTE_ADDR=PEER), shown=False)

    @override_settings(TRUSTED_PROXIES=["10.0.0.2"])
    def test_behind_a_load_balancer_only_the_abuser_is_flagged(self, head, get):
        with self.assertLogs("middleman", "INFO"):
            for _ in range(3):
                self.client.get(URL, REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR="203.0.113.66",
                                HTTP_X_RATELIMIT_REMAINING="1")
        self.assertTrue(abuse.hides_rate_limit_headers("203.0.113.66"))
        self.assertFalse(abuse.hides_rate_limit_headers("10.0.0.2"))
        honest = self.client.get(URL, REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR="203.0.113.67")
        self.assertShowsHeaders(honest)

    def test_detector_crash_does_not_break_proxying(self, head, get):
        with patch("middleman.abuse._record", side_effect=RuntimeError("db down")):
            with self.assertLogs("middleman.abuse", "ERROR"):
                response = self.get(HTTP_X_RATELIMIT_REMAINING="1")
        self.assertEqual(response.status_code, 200)


class PruneCommandTest(TestCase):
    def test_prunes_only_old_buckets(self):
        now = timezone.now()
        abuse._record(PEER, "auth_failure", "", now - timedelta(days=40))
        abuse._record(PEER, "auth_failure", "", now - timedelta(days=1))
        out = io.StringIO()
        call_command("prune_abuse_signals", "--older-than-days", "30", stdout=out)
        self.assertEqual(AbuseSignal.objects.count(), 1)
        self.assertIn("Deleted 1 abuse signal bucket(s)", out.getvalue())

    def test_never_touches_policies(self):
        ClientPolicy.objects.create(ip=PEER, hide_rate_limit_headers=True, source="automatic")
        call_command("prune_abuse_signals", "--older-than-days", "1", stdout=io.StringIO())
        self.assertTrue(ClientPolicy.objects.exists())

    def test_refuses_invalid_ages(self):
        with self.assertRaises(CommandError):
            call_command("prune_abuse_signals", "--older-than-days", "0")
