"""
Semantic explanations of failures (middleman/diagnostics.py), `manage.py`
without stack traces, and `python manage.py doctor`.

The messages below are the exact ones PostgreSQL 16 / psycopg2 produced for
each situation (captured against a real server).
"""

import io
import os
import socket
import subprocess
import sys
from unittest.mock import patch

import psycopg2
import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import OperationalError, ProgrammingError
from django.test import SimpleTestCase, TestCase

from middleman.diagnostics import (describe_database, explain_database_error,
                                   format_command_failure,
                                   handle_command_failure)
from middleman.management.commands.doctor import explain_target_error
from middleman.models import BlacklistRule
from middleman.version import LEGACY_VERSION

DB = {"ENGINE": "django.db.backends.postgresql", "HOST": "127.0.0.1", "PORT": 54329, "NAME": "mm", "USER": "alice"}
ALL_SET = {name: "x" for name in ("POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")}

REAL_MESSAGES = {
    "connection_refused": 'connection to server at "127.0.0.1", port 54399 failed: Connection refused\n'
                          '\tIs the server running on that host and accepting TCP/IP connections?',
    "host_not_found": 'could not translate host name "db.invalid" to address: Name or service not known',
    "timeout": 'connection to server at "127.0.0.1", port 54400 failed: timeout expired',
    "password_missing": 'connection to server at "127.0.0.1", port 54329 failed: fe_sendauth: no password supplied',
    "auth_failed": 'connection to server at "127.0.0.1", port 54329 failed: FATAL:  password authentication '
                   'failed for user "alice"',
    "role_missing": 'connection to server at "127.0.0.1", port 54329 failed: FATAL:  role "nobody" does not exist',
    "database_missing": 'connection to server at "127.0.0.1", port 54329 failed: FATAL:  database "nope" does '
                        'not exist',
    "not_postgres": 'connection to server at "10.255.255.1", port 54329 failed: received invalid response to SSL '
                    'negotiation: H',
    "schema_missing": 'relation "middleman_blacklist_rule" does not exist\nLINE 1: ...ddleman_blacklist_rule"',
    "permission_denied": "permission denied for table middleman_blacklist_rule",
    "connection_lost": "server closed the connection unexpectedly\n\tThis probably means the server terminated "
                       "abnormally",
    "too_many_connections": "FATAL:  sorry, too many clients already / remaining connection slots are reserved",
    "sqlite_unavailable": "unable to open database file",
    "sqlite_locked": "database is locked",
    "driver_missing": "Error loading psycopg2 module: No module named 'psycopg2'",
}


class ExplainDatabaseErrorTest(SimpleTestCase):
    def explain(self, message, environ=ALL_SET, wrap=True):
        if wrap:  # Django wraps the driver's error, like in real life
            try:
                try:
                    raise psycopg2.OperationalError(message)
                except psycopg2.OperationalError as driver_error:
                    raise OperationalError(message) from driver_error
            except OperationalError as exc:
                return explain_database_error(exc, DB, environ)
        return explain_database_error(OperationalError(message), DB, environ)

    def test_every_real_message_gets_its_reason(self):
        for reason, message in REAL_MESSAGES.items():
            with self.subTest(reason=reason):
                diagnosis = self.explain(message)
                self.assertEqual(diagnosis.reason, reason)
                self.assertTrue(diagnosis.summary and diagnosis.hints)
                self.assertNotIn("\n", diagnosis.detail)

    def test_summaries_name_the_failing_settings(self):
        self.assertIn("127.0.0.1:54329", self.explain(REAL_MESSAGES["connection_refused"]).summary)
        self.assertIn("'alice'", self.explain(REAL_MESSAGES["auth_failed"]).summary)
        self.assertIn("'mm'", self.explain(REAL_MESSAGES["database_missing"]).summary)
        self.assertIn("createdb -O alice mm", self.explain(REAL_MESSAGES["database_missing"]).hints[0])
        self.assertIn("make migrate", self.explain(REAL_MESSAGES["schema_missing"]).hints[0])

    def test_outages_are_503_material_other_errors_are_not(self):
        self.assertTrue(self.explain(REAL_MESSAGES["connection_refused"]).unavailable)
        self.assertTrue(self.explain(REAL_MESSAGES["schema_missing"]).unavailable)
        self.assertFalse(self.explain(REAL_MESSAGES["permission_denied"]).unavailable)

    def test_driver_error_alone_and_deep_chains_are_understood(self):
        self.assertEqual(explain_database_error(psycopg2.OperationalError(REAL_MESSAGES["timeout"]), DB, ALL_SET).reason,
                         "timeout")
        try:
            try:
                raise psycopg2.OperationalError(REAL_MESSAGES["auth_failed"])
            except psycopg2.OperationalError:
                raise RuntimeError("wrapped twice")
        except RuntimeError as exc:
            self.assertEqual(explain_database_error(exc, DB, ALL_SET).reason, "auth_failed")

    def test_unknown_errors(self):
        diagnosis = self.explain("something nobody has seen before", wrap=False)
        self.assertEqual(diagnosis.reason, "database_error")
        self.assertIn("doctor", diagnosis.hints[0])

    def test_unset_variables_are_pointed_out(self):
        diagnosis = self.explain(REAL_MESSAGES["connection_refused"], environ={})
        self.assertIn("Not set, so defaults are used: POSTGRES_HOST, POSTGRES_PORT", diagnosis.hints[-1])
        loaded = self.explain(REAL_MESSAGES["connection_refused"], environ={"MIDDLEMAN_ENV_FILE": ".env"})
        self.assertIn(".env was loaded but does not set them", loaded.hints[-1])
        with patch("middleman.diagnostics.os.path.exists", return_value=True):
            self.assertIn("source .env", self.explain(REAL_MESSAGES["connection_refused"], environ={}).hints[-1])
        with patch("middleman.diagnostics.os.path.exists", return_value=False):
            self.assertIn("cp .env.example .env", self.explain(REAL_MESSAGES["connection_refused"], environ={}).hints[-1])
        # Not a settings problem: no environment hint.
        self.assertNotIn("Not set", " ".join(self.explain(REAL_MESSAGES["schema_missing"], environ={}).hints))

    def test_describe_database(self):
        self.assertEqual(describe_database(DB), "PostgreSQL database 'mm' on 127.0.0.1:54329 as user 'alice'")
        self.assertEqual(describe_database({"ENGINE": "django.db.backends.sqlite3", "NAME": "/tmp/x.db"}),
                         "SQLite database /tmp/x.db")
        self.assertEqual(describe_database({"ENGINE": "custom", "NAME": "n"}), "custom database 'n'")


class CommandFailureTest(SimpleTestCase):
    def test_database_failures_are_explained_without_a_trace(self):
        stream = io.StringIO()
        with self.assertLogs("middleman.diagnostics", "ERROR"):
            handled = handle_command_failure(OperationalError(REAL_MESSAGES["connection_refused"]),
                                             ["manage.py", "migrate"], stream)
        self.assertTrue(handled)
        output = stream.getvalue()
        self.assertIn("ERROR: `migrate` failed: Nothing is accepting connections at", output)
        self.assertIn("Reason:   connection_refused", output)
        self.assertIn("What to do:\n    1. Start PostgreSQL", output)
        self.assertIn("make doctor", output)

    def test_traceback_flag_lets_the_exception_propagate(self):
        with self.assertLogs("middleman.diagnostics", "ERROR"):
            self.assertFalse(handle_command_failure(OperationalError("x"), ["manage.py", "migrate", "--traceback"],
                                                    io.StringIO()))

    def test_configuration_errors_are_one_paragraph(self):
        stream = io.StringIO()
        self.assertTrue(handle_command_failure(ImproperlyConfigured("LOG_FORMAT='xml' is not valid"),
                                               ["manage.py", "runserver"], stream))
        self.assertIn("`runserver` failed: the configuration is invalid.\n  LOG_FORMAT='xml' is not valid",
                      stream.getvalue())

    def test_other_errors_are_not_swallowed(self):
        self.assertFalse(handle_command_failure(RuntimeError("bug"), ["manage.py", "migrate"], io.StringIO()))

    def test_format(self):
        text = format_command_failure("migrate", explain_database_error(OperationalError("database is locked"), DB, {}),
                                      "SQLite database x")
        self.assertIn("Database: SQLite database x", text)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ManagePyTest(SimpleTestCase):
    """The real `python manage.py migrate` (what `make migrate` runs) against a closed port."""

    def run_manage(self, *args, **env):
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("POSTGRES_", "DJANGO_", "LOG"))}
        clean.update(POSTGRES_HOST="127.0.0.1", POSTGRES_PORT=str(free_port()), POSTGRES_CONNECT_TIMEOUT="3", **env)
        return subprocess.run([sys.executable, "manage.py", *args], cwd=settings.BASE_DIR, env=clean,
                              capture_output=True, text=True, timeout=60)

    def test_migrate_without_a_database_explains_itself(self):
        result = self.run_manage("migrate")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ERROR: `migrate` failed: Nothing is accepting connections at 127.0.0.1:", result.stderr)
        self.assertIn("Reason:   connection_refused", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_traceback_flag_still_shows_the_trace(self):
        result = self.run_manage("migrate", "--traceback")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Reason:   connection_refused", result.stderr)
        self.assertIn("Traceback", result.stderr)

    def test_invalid_configuration_is_one_paragraph(self):
        result = self.run_manage("migrate", LOG_FORMAT="xml")
        self.assertEqual(result.returncode, 1)
        self.assertIn("the configuration is invalid.\n  LOG_FORMAT='xml' is not valid", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


class DoctorTest(TestCase):
    def doctor(self, *args):
        out = io.StringIO()
        try:
            call_command("doctor", *args, stdout=out)
        except CommandError as exc:
            return out.getvalue(), exc
        return out.getvalue(), None

    def test_healthy_installation(self):
        with patch("middleman.management.commands.doctor.requests.head") as head:
            head.return_value.status_code = 200
            output, error = self.doctor()
        self.assertIsNone(error, output)
        for line in ["[ OK ] Database: " + describe_database(), "[ OK ] Migrations: all applied",
                     "[ OK ] Blacklist rules: 0 rule(s), 0 enabled, all valid",
                     "answered HEAD with 200", "Ready. 0 problem(s)"]:
            self.assertIn(line, output)

    def test_database_failure_skips_what_depends_on_it(self):
        with patch("middleman.management.commands.doctor.connection.ensure_connection",
                   side_effect=OperationalError(REAL_MESSAGES["auth_failed"])):
            output, error = self.doctor("--skip-network")
        self.assertEqual(error.returncode, 1)
        self.assertIn("[FAIL] Database:", output)
        self.assertIn("(auth_failed)", output)
        self.assertIn("-> Check POSTGRES_USER / POSTGRES_PASSWORD.", output)
        self.assertIn("[SKIP] Migrations: skipped (database unavailable)", output)
        self.assertIn("[SKIP] Blacklist rules: skipped (database unavailable)", output)
        self.assertIn("[SKIP] Target server: skipped (--skip-network)", output)

    def test_pending_migrations_fail(self):
        pending = [(type("M", (), {"app_label": "middleman", "name": "0008_ruleset_version"})(), False)]
        with patch("middleman.management.commands.doctor.MigrationExecutor.migration_plan", return_value=pending):
            output, error = self.doctor("--skip-network")
        self.assertIn("[FAIL] Migrations: 1 not applied: middleman.0008_ruleset_version", output)
        self.assertIn("-> Run: make migrate", output)
        self.assertIn("[SKIP] Blacklist rules: skipped (migrations not applied)", output)
        self.assertIsNotNone(error)

    def test_invalid_rules_and_insecure_settings_are_warnings(self):
        rule = BlacklistRule.objects.create(rule_type="ip", value="10.0.0.1")
        BlacklistRule.objects.filter(pk=rule.pk).update(value="10.0.0", created_by_version=LEGACY_VERSION)
        output, error = self.doctor("--skip-network")
        self.assertIsNone(error, output)
        self.assertIn("[WARN] Blacklist rules: 1 of 1 invalid", output)
        self.assertIn("[WARN] SECRET_KEY: a development key (django-insecure-...) is in use", output)
        with self.settings(SECRET_KEY="a-real-long-random-production-secret-value-0123456789"):
            output, _ = self.doctor("--skip-network")
        self.assertNotIn("SECRET_KEY", output)

    def test_unreachable_target_fails_with_the_reason(self):
        with patch("middleman.management.commands.doctor.requests.head",
                   side_effect=requests.ConnectionError("[Errno 111] Connection refused")):
            output, error = self.doctor()
        self.assertIn("[FAIL] Target server: http://localhost:8000/ - connection refused", output)
        self.assertEqual(error.returncode, 1)

    def test_target_answering_head_with_an_error_is_a_warning(self):
        with patch("middleman.management.commands.doctor.requests.head") as head:
            head.return_value.status_code = 405
            output, _ = self.doctor()
        self.assertIn("[WARN] Target server: http://localhost:8000/ answered HEAD with 405", output)

    def test_explain_target_error(self):
        cases = {
            requests.Timeout(): "no answer within the timeout",
            requests.exceptions.SSLError("bad cert"): "TLS/SSL handshake failed",
            requests.ConnectionError("Failed to resolve 'x.invalid'"): "does not resolve (DNS)",
            requests.ConnectionError("Connection refused"): "connection refused",
            requests.ConnectionError("weird"): "not reachable: weird",
        }
        for exc, expected in cases.items():
            with self.subTest(exc=exc):
                self.assertIn(expected, explain_target_error(exc))

    def test_environment_report(self):
        with patch.dict(os.environ, {"MIDDLEMAN_ENV_FILE": ".env"}):
            output, _ = self.doctor("--skip-network")
        self.assertIn("[ OK ] Environment: loaded from .env", output)
        variables = ("POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")
        with patch.dict(os.environ, {}, clear=False):
            for name in variables:
                os.environ.pop(name, None)
            os.environ.pop("MIDDLEMAN_ENV_FILE", None)
            output, _ = self.doctor("--skip-network")
        self.assertIn("[WARN] Environment: no POSTGRES_* variable is set", output)
        with patch.dict(os.environ, {"POSTGRES_HOST": "db"}):
            os.environ.pop("MIDDLEMAN_ENV_FILE", None)
            output, _ = self.doctor("--skip-network")
        self.assertIn("[ OK ] Environment: variables from the shell", output)

    def test_debug_is_a_warning(self):
        with self.settings(DEBUG=True):
            output, _ = self.doctor("--skip-network")
        self.assertIn("[WARN] DEBUG: on", output)

    def test_migration_check_database_error(self):
        with patch("middleman.management.commands.doctor.MigrationExecutor",
                   side_effect=ProgrammingError(REAL_MESSAGES["permission_denied"])):
            output, error = self.doctor("--skip-network")
        self.assertIn("[FAIL] Migrations: User", output)
