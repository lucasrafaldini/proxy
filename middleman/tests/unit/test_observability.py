"""
Application-wide logging (middleman/observability.py): request ids on every
line, the access log, JSON output, and database errors turned into 503s with
a semantic log line.
"""

import io
import json
import logging
import os
import subprocess
import sys
from unittest.mock import Mock, patch

from django.conf import settings
from django.db import OperationalError, ProgrammingError
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from middleman.models import BlacklistRule
from middleman.observability import (JsonFormatter, RequestContextFilter,
                                     current_request_id, parse_message)
from middleman.tests.utils.blocks import assert_policy_block
from middleman.version import __version__

REFUSED = ('connection to server at "localhost" (127.0.0.1), port 5432 failed: Connection refused\n'
           '\tIs the server running on that host and accepting TCP/IP connections?')


def upstream(*args, **kwargs):
    response = Mock(status_code=200, reason="OK", raw=io.BytesIO(b"ok"))
    response.headers = {"content-type": "text/plain"}
    return response


class CapturingHandler(logging.Handler):
    """Like the console handler: records pass through RequestContextFilter."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []
        self.addFilter(RequestContextFilter())

    def emit(self, record):
        self.records.append(record)


class captured_logs:
    """Capture every record of the given loggers, as the real handler would see them."""

    def __init__(self, *names, level=logging.INFO):
        self.names, self.level = names or ("middleman", "django"), level

    def __enter__(self):
        self.handler = CapturingHandler()
        self.previous = []
        for name in self.names:
            log = logging.getLogger(name)
            self.previous.append((log, log.level))
            log.addHandler(self.handler)
            log.setLevel(self.level)
        return self.handler.records

    def __exit__(self, *exc):
        for log, level in self.previous:
            log.removeHandler(self.handler)
            log.setLevel(level)


@patch("middleman.upstream.get", side_effect=upstream)
@patch("middleman.upstream.head", side_effect=upstream)
class RequestIdTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_every_response_has_a_unique_request_id(self, head, get):
        ids = {self.client.get("/insights/")["X-Request-ID"] for _ in range(5)}
        self.assertEqual(len(ids), 5)
        for request_id in ids:
            self.assertRegex(request_id, r"^[0-9a-f]{12}$")

    def test_every_line_of_a_request_carries_its_id_including_djangos(self, head, get):
        BlacklistRule.objects.create(rule_type="user_agent", value="sqlmap")
        with captured_logs() as records:
            response = self.client.get("/proxy/home/", HTTP_USER_AGENT="sqlmap")
        request_id = response["X-Request-ID"]
        ref = assert_policy_block(self, response)
        self.assertEqual(ref, request_id)  # the 403 ref is the request id
        by_logger = {record.name: record.request_id for record in records}
        # The block, the access line and Django's own "Forbidden" line.
        self.assertEqual(by_logger.get("middleman.views"), request_id)
        self.assertEqual(by_logger.get("middleman.access"), request_id)
        self.assertEqual(by_logger.get("django.request"), request_id)

    def test_rejected_host_headers_are_logged_with_the_request_id(self, head, get):
        # AllowedHostsMiddleware runs first: the id must already exist (request_started).
        with captured_logs("middleman.hosts", "middleman.access") as records:
            response = self.client.get("/insights/", HTTP_HOST="evil.example")
        self.assertEqual(response.status_code, 400)
        self.assertRegex(response["X-Request-ID"], r"^[0-9a-f]{12}$")
        self.assertEqual({record.name for record in records}, {"middleman.hosts", "middleman.access"})
        for record in records:
            self.assertEqual(record.request_id, response["X-Request-ID"])
        access = [r.getMessage() for r in records if r.name == "middleman.access"][0]
        self.assertRegex(access, r"^\[Access\] GET '/insights/' 400 \| duration_ms=")

    def test_the_id_ends_with_the_request(self, head, get):
        self.client.get("/insights/")
        self.assertEqual(current_request_id(), "-")
        with captured_logs("middleman") as records:
            logging.getLogger("middleman.test").warning("outside any request")
        self.assertEqual(records[0].request_id, "-")
        self.assertEqual(records[0].proxy_version, __version__)


@patch("middleman.upstream.get", side_effect=upstream)
@patch("middleman.upstream.head", side_effect=upstream)
class AccessLogTest(TestCase):
    def access_records(self, **request):
        client = APIClient(raise_request_exception=False)
        with captured_logs("middleman.access", level=logging.DEBUG) as records:
            response = client.get(request.pop("path", "/proxy/home/"), **request)
        return response, [r for r in records if r.name == "middleman.access"]

    def test_one_info_line_per_request(self, head, get):
        response, records = self.access_records(REMOTE_ADDR="198.51.100.3")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].levelno, logging.INFO)
        self.assertRegex(records[0].getMessage(),
                         r"^\[Access\] GET '/proxy/home/' 200 \| duration_ms=\d+\.\d ip=198\.51\.100\.3 slow=False$")

    def test_slow_requests_are_warnings(self, head, get):
        with patch("middleman.observability._clock", side_effect=[100.0, 105.0]):
            response, records = self.access_records()
        self.assertEqual(records[0].levelno, logging.WARNING)
        self.assertIn("duration_ms=5000.0", records[0].getMessage())
        self.assertIn("slow=True", records[0].getMessage())

    @override_settings(LOG_SLOW_REQUEST_MS=100_000)
    def test_the_slow_threshold_is_configurable(self, head, get):
        with patch("middleman.observability._clock", side_effect=[100.0, 105.0]):
            response, records = self.access_records()
        self.assertEqual(records[0].levelno, logging.INFO)

    def test_server_errors_are_errors(self, head, get):
        with patch("middleman.views.InsightsView.get", side_effect=RuntimeError("boom")):
            response, records = self.access_records(path="/insights/")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(records[0].levelno, logging.ERROR)

    def test_hostile_paths_cannot_forge_lines(self, head, get):
        response, records = self.access_records(path="/proxy/home/%0a2026-01-01%20INFO%20forged/")
        self.assertNotIn("\n", records[0].getMessage())


class JsonFormatTest(SimpleTestCase):
    def format(self, message, *args, exc_info=None, **extra):
        record = logging.LogRecord("middleman.views", logging.WARNING, __file__, 1, message, args, exc_info)
        for key, value in extra.items():
            setattr(record, key, value)
        RequestContextFilter().filter(record)
        line = JsonFormatter().format(record)
        self.assertNotIn("\n", line)
        return json.loads(line)

    def test_structured_fields(self):
        payload = self.format(
            "[ProxyView] Request blocked: client matches a blacklist rule | ref=%s ip=%s path=%r rule_type=%s rule=%r",
            "abc123", "10.0.0.5", "home/", "user_agent", "sqlmap",
        )
        self.assertEqual(payload["component"], "ProxyView")
        self.assertEqual(payload["event"], "Request blocked: client matches a blacklist rule")
        self.assertEqual(payload["fields"], {"ref": "abc123", "ip": "10.0.0.5", "path": "'home/'",
                                             "rule_type": "user_agent", "rule": "'sqlmap'"})
        self.assertEqual(payload["level"], "WARNING")
        self.assertEqual(payload["logger"], "middleman.views")
        self.assertEqual(payload["request_id"], "-")
        self.assertIn("version", payload)

    def test_hostile_values_stay_one_valid_line(self):
        hostile = 'sqlmap"}\n{"level": "INFO", "forged": true}\u2028'
        payload = self.format("[ProxyView] Blocked | user_agent=%r", hostile)
        self.assertEqual(payload["fields"]["user_agent"], repr(hostile))
        self.assertNotIn("forged", payload)

    def test_exceptions_and_extra_attributes(self):
        try:
            raise ValueError("boom")
        except ValueError:
            payload = self.format("plain message", exc_info=sys.exc_info(), tenant="acme")
        self.assertIn("ValueError: boom", payload["exception"])
        self.assertEqual(payload["extra"], {"tenant": "acme"})
        self.assertNotIn("component", payload)

    def test_parse_message(self):
        self.assertEqual(parse_message("no convention here"), (None, "no convention here", {}))
        self.assertEqual(parse_message("[X] Event"), ("X", "Event", {}))
        self.assertEqual(
            parse_message("[X] Event | a=1 b='two words' c=[1, 2] d=\"q\""),
            ("X", "Event", {"a": "1", "b": "'two words'", "c": "[1, 2]", "d": '"q"'}),
        )


class DatabaseErrorResponseTest(TestCase):
    def test_database_outage_in_a_view_is_a_503_with_a_reason(self):
        client = APIClient(raise_request_exception=False)
        with patch("middleman.views.InsightsView.get", side_effect=OperationalError(REFUSED)):
            with self.assertLogs("middleman.observability", "ERROR") as logs:
                response = client.get("/insights/")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.content.decode(), "Service unavailable: the proxy's database is not reachable "
                         "(ref {}).".format(response["X-Request-ID"]))
        self.assertIn("[Request] Database error: Nothing is accepting connections at", logs.output[0])
        self.assertIn("reason=connection_refused", logs.output[0])
        self.assertNotIn("Traceback", logs.output[0])

    def test_other_database_errors_are_a_500_without_details(self):
        client = APIClient(raise_request_exception=False)
        with patch("middleman.views.InsightsView.get", side_effect=ProgrammingError("syntax error at or near")):
            with self.assertLogs("middleman.observability", "ERROR"):
                response = client.get("/insights/")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.content.decode(), "Internal error (ref {}).".format(response["X-Request-ID"]))

    def test_non_database_errors_are_left_to_django(self):
        client = APIClient(raise_request_exception=False)
        with patch("middleman.views.InsightsView.get", side_effect=RuntimeError("boom")):
            response = client.get("/insights/")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"database", response.content)

    def test_proxy_fails_closed_with_503_when_rules_cannot_be_read(self):
        client = APIClient()
        with patch("middleman.services.cached_ruleset", side_effect=OperationalError(REFUSED)), \
                patch("middleman.upstream.head") as head:
            with self.assertLogs("middleman.views", "ERROR") as logs:
                response = client.get("/proxy/home/")
        self.assertEqual(response.status_code, 503)
        self.assertIn("[ProxyView] Database error:", logs.output[0])
        self.assertIn("path='home/'", logs.output[0])
        head.assert_not_called()  # never proxied unchecked

    def test_proxy_answers_503_when_the_access_entry_cannot_be_stored(self):
        client = APIClient()
        with patch("middleman.interfaces.RegistryInterface.get_or_create_access_entry",
                   side_effect=OperationalError("server closed the connection unexpectedly")), \
                patch("middleman.upstream.head"):
            with self.assertLogs("middleman", "ERROR") as logs:
                response = client.get("/proxy/home/")
        self.assertEqual(response.status_code, 503)
        self.assertIn("reason=connection_lost", "\n".join(logs.output))
        self.assertFalse(any("Traceback" in line for line in logs.output))

    def test_proxy_database_error_that_is_not_an_outage_is_a_500(self):
        client = APIClient()
        with patch("middleman.services.cached_ruleset", side_effect=ProgrammingError("permission denied for table x")):
            with self.assertLogs("middleman.views", "ERROR"):
                response = client.get("/proxy/home/")
        self.assertEqual(response.status_code, 500)
        self.assertRegex(response.content.decode(), r"^Internal proxy error \(ref [0-9a-f]{12}\)\.$")

    def test_allowed_hosts_and_abuse_detection_fallbacks_explain_database_errors(self):
        from middleman import abuse, hosts

        hosts.invalidate_cache()
        with patch("middleman.models.AllowedHost.objects.values_list", side_effect=OperationalError(REFUSED)):
            with self.assertLogs("middleman.hosts", "ERROR") as logs:
                self.assertEqual(hosts.runtime_hosts(), ())
        self.assertIn("reason=connection_refused", logs.output[0])
        self.assertIn("fallback='only the baseline hosts are accepted'", logs.output[0])
        with patch("middleman.abuse._record", side_effect=OperationalError(REFUSED)):
            with self.assertLogs("middleman.abuse", "ERROR") as logs:
                abuse.report("10.0.0.1", [("blacklist_hit", "")])
        self.assertIn("[AbuseDetector] Database error", logs.output[0])


def start_django(code="", **env):
    clean = {k: v for k, v in os.environ.items() if not k.startswith(("LOG_", "POSTGRES_"))}
    clean["DJANGO_SETTINGS_MODULE"] = "proxy.test_settings"
    clean.update(env)
    script = "import django; django.setup();" + code
    return subprocess.run([sys.executable, "-c", script], cwd=settings.BASE_DIR, env=clean,
                          capture_output=True, text=True)


class LoggingSettingsTest(SimpleTestCase):
    def test_invalid_values_stop_startup(self):
        cases = {
            "LOG_FORMAT": ("xml", "LOG_FORMAT='xml' is not valid; use text or json."),
            "LOG_SLOW_REQUEST_MS": ("fast", "LOG_SLOW_REQUEST_MS='fast' must be a positive integer."),
            "POSTGRES_PORT": ("0", "POSTGRES_PORT='0' must be a positive integer."),
            "POSTGRES_CONNECT_TIMEOUT": ("-1", "POSTGRES_CONNECT_TIMEOUT='-1' must be a positive integer."),
        }
        for name, (value, message) in cases.items():
            with self.subTest(name=name):
                result = start_django(**{name: value})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_json_format_writes_one_object_per_line(self):
        result = start_django(
            "import logging; logging.getLogger('middleman.views').warning('[ProxyView] Hello | a=%s', 1)",
            LOG_FORMAT="json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stderr.strip().splitlines()[-1])
        self.assertEqual((payload["component"], payload["event"], payload["fields"]), ("ProxyView", "Hello", {"a": "1"}))

    def test_text_format_shows_version_and_request(self):
        result = start_django("import logging; logging.getLogger('middleman.views').warning('hello')")
        self.assertRegex(result.stderr, r"WARNING  middleman\.views \[proxy v[^\]]+\] \[req -\] hello")

    def test_database_port_and_timeout_are_configurable(self):
        result = start_django(
            "from django.conf import settings as s; d = s.DATABASES['default'];"
            "print(d['PORT'], d['OPTIONS'])",
            DJANGO_SETTINGS_MODULE="proxy.settings", POSTGRES_PORT="6543", POSTGRES_CONNECT_TIMEOUT="3",
        )
        self.assertEqual(result.stdout.strip(), "6543 {'connect_timeout': 3}")
