"""
Check that this installation can run, and explain every problem found.

    python manage.py doctor                 # exit 1 if anything is broken
    python manage.py doctor --skip-network  # do not contact BASE_TARGET_URL

Checks, in order (later checks are skipped when what they need is broken):
configuration, database connection, migrations, blacklist rules, the target
server, and logging. Every failure comes with the reason and what to do.
"""

import os

import requests
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError, connection
from django.db.migrations.executor import MigrationExecutor

from middleman.diagnostics import (describe_database, explain_database_error,
                                   unset_database_variables)
from middleman.version import __version__

OK, WARN, FAIL, SKIP = "OK", "WARN", "FAIL", "SKIP"
# Django's marker for generated/development keys (also flagged by check --deploy, W009).
INSECURE_KEY_PREFIX = "django-insecure-"


def explain_target_error(exc) -> str:
    text = str(exc)
    if isinstance(exc, requests.Timeout):
        return "no answer within the timeout (host down, firewall, or very slow)"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS/SSL handshake failed (certificate or protocol problem)"
    if "Name or service not known" in text or "Failed to resolve" in text or "nodename nor servname" in text:
        return "the host name does not resolve (DNS): check BASE_TARGET_URL"
    if "Connection refused" in text:
        return "connection refused: nothing listens on that host/port"
    return "not reachable: {}".format(" ".join(text.split())[:200])


class Command(BaseCommand):
    help = "Check settings, database, migrations, rules and the target server; explain every problem."

    def add_arguments(self, parser):
        parser.add_argument("--skip-network", action="store_true", help="Do not contact BASE_TARGET_URL.")

    def report(self, status, title, detail="", hints=()):
        style = {OK: self.style.SUCCESS, WARN: self.style.WARNING, FAIL: self.style.ERROR}.get(status, str)
        self.stdout.write("{} {}{}".format(style("[{:^4}]".format(status)), title, ": " + detail if detail else ""))
        for hint in hints:
            self.stdout.write("         -> {}".format(hint))
        self.results.append(status)

    def handle(self, *args, **options):
        self.results = []
        self.stdout.write("MiddleMan v{} doctor (settings: {})".format(__version__, os.environ.get("DJANGO_SETTINGS_MODULE")))
        self.check_configuration()
        database_ok = self.check_database()
        migrated = self.check_migrations() if database_ok else self.skip("Migrations", "database unavailable")
        if migrated:
            self.check_rules()
        elif database_ok:
            self.skip("Blacklist rules", "migrations not applied")
        else:
            self.skip("Blacklist rules", "database unavailable")
        if options["skip_network"]:
            self.skip("Target server", "--skip-network")
        else:
            self.check_target()
        self.check_logging()

        failures, warnings = self.results.count(FAIL), self.results.count(WARN)
        summary = "{} problem(s), {} warning(s).".format(failures, warnings)
        if failures:
            raise CommandError(summary + " Fix the [FAIL] items above.", returncode=1)
        self.stdout.write(self.style.SUCCESS("Ready. " + summary))

    def skip(self, title, why):
        self.report(SKIP, title, "skipped ({})".format(why))
        return False

    # --- checks ---------------------------------------------------------------------

    def check_configuration(self):
        env_file = os.environ.get("MIDDLEMAN_ENV_FILE")
        unset = unset_database_variables()
        if env_file:
            self.report(OK, "Environment", "loaded from {}".format(env_file))
        elif unset and len(unset) == 5:
            hint = ("source .env (or use make targets, which load it)" if os.path.exists(".env")
                    else "cp .env.example .env, edit it, then source .env")
            self.report(WARN, "Environment", "no POSTGRES_* variable is set: built-in defaults are used", [hint])
        else:
            self.report(OK, "Environment", "variables from the shell")
        if settings.SECRET_KEY.startswith(INSECURE_KEY_PREFIX):
            self.report(WARN, "SECRET_KEY", "a development key ({}...) is in use".format(INSECURE_KEY_PREFIX),
                        ["Set SECRET_KEY to a long random value before production."])
        if settings.DEBUG:
            self.report(WARN, "DEBUG", "on: error pages expose settings and stack traces", ["Never in production."])
        self.report(OK, "Target", settings.BASE_TARGET_URL)

    def check_database(self):
        description = describe_database()
        try:
            connection.ensure_connection()
            version = connection.cursor().connection.server_version if connection.vendor == "postgresql" else None
        except DatabaseError as exc:
            diagnosis = explain_database_error(exc)
            self.report(FAIL, "Database", "{} ({}) - {}".format(description, diagnosis.reason, diagnosis.summary),
                        diagnosis.hints)
            return False
        server = " (server {}.{})".format(version // 10000, version % 10000) if version else ""
        self.report(OK, "Database", description + server)
        return True

    def check_migrations(self):
        try:
            executor = MigrationExecutor(connection)
            plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
        except DatabaseError as exc:
            diagnosis = explain_database_error(exc)
            self.report(FAIL, "Migrations", diagnosis.summary, diagnosis.hints)
            return False
        if plan:
            names = ["{}.{}".format(migration.app_label, migration.name) for migration, _ in plan]
            self.report(FAIL, "Migrations", "{} not applied: {}{}".format(
                len(names), ", ".join(names[:5]), ", ..." if len(names) > 5 else ""), ["Run: make migrate"])
            return False
        self.report(OK, "Migrations", "all applied")
        return True

    def check_rules(self):
        from middleman.models import BlacklistRule

        rules = list(BlacklistRule.objects.all())
        invalid = [rule for rule in rules if rule.validation_error is not None]
        enabled = sum(1 for rule in rules if rule.enabled)
        if invalid:
            self.report(WARN, "Blacklist rules", "{} of {} invalid in v{} (never applied)".format(
                len(invalid), len(rules), __version__), ["Review them: make check-rules"])
        else:
            self.report(OK, "Blacklist rules", "{} rule(s), {} enabled, all valid".format(len(rules), enabled))

    def check_target(self):
        url = settings.BASE_TARGET_URL
        try:
            response = requests.head(url, timeout=5, allow_redirects=False)
        except requests.RequestException as exc:
            self.report(FAIL, "Target server", "{} - {}".format(url, explain_target_error(exc)),
                        ["Check BASE_TARGET_URL and that the target is up; proxied requests answer 502/504 meanwhile."])
            return
        if response.status_code != 200:
            self.report(WARN, "Target server", "{} answered HEAD with {}".format(url, response.status_code),
                        ["The proxy requires HEAD to answer 200; other statuses make proxied requests answer 502."])
        else:
            self.report(OK, "Target server", "{} answered HEAD with 200".format(url))

    def check_logging(self):
        self.report(OK, "Logging", "level {} ({}), format {}, slow requests >= {} ms".format(
            settings.LOGLEVEL, "set LOGLEVEL=INFO for access logs" if settings.LOGLEVEL not in ("DEBUG", "INFO")
            else "access log on", settings.LOG_FORMAT, settings.LOG_SLOW_REQUEST_MS))
