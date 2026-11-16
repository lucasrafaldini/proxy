"""
Rolling back and re-applying migration 0007 (User-Agent rule types).

The suite runs with --nomigrations, so the real migrations run in a fresh
interpreter against a temporary SQLite database.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

SCRIPT = textwrap.dedent('''
    import json, django
    django.setup()
    from datetime import datetime, timezone
    from django.core.management import call_command
    from django.db import connection

    PARKED = "middleman_blacklist_rule_parked"
    OLD = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    def rules():
        with connection.cursor() as cursor:
            cursor.execute("SELECT rule_type, value, enabled, created_by_version, created_at "
                           "FROM middleman_blacklist_rule ORDER BY rule_type, value")
            return [[r[0], r[1], bool(r[2]), r[3], str(r[4])[:19]] for r in cursor.fetchall()]

    def parked():
        if PARKED not in connection.introspection.table_names():
            return None
        with connection.cursor() as cursor:
            cursor.execute("SELECT rule_type, value FROM " + PARKED + " ORDER BY id")
            return [list(r) for r in cursor.fetchall()]

    def insert(rule_type, value, enabled=True, version="2.1.0"):
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO middleman_blacklist_rule (rule_type, value, enabled, created_at, created_by_version) "
                "VALUES (%s, %s, %s, %s, %s)", [rule_type, value, enabled, OLD, version])

    result = {}
    call_command("migrate", verbosity=0)
    insert("ip", "10.0.0.1")
    insert("user_agent", "sqlmap")
    insert("user_agent_re", "^$", enabled=False, version="pre-2.0.0")
    insert("user_agent_re", "nikto")

    call_command("migrate", "middleman", "0006", verbosity=0)   # rollback
    result["rolled_back"] = {"rules": rules(), "parked": parked()}

    insert("user_agent_re", "nikto", version="2.0.0")  # re-created while rolled back
    call_command("migrate", verbosity=0)                       # upgrade again
    result["upgraded"] = {"rules": rules(), "parked": parked()}

    call_command("migrate", "middleman", "0006", verbosity=0)  # nothing lost on a second round trip
    call_command("migrate", verbosity=0)
    result["second_round_trip"] = {"rules": rules(), "parked": parked()}
    print("RESULT=" + json.dumps(result))
''')


class UserAgentMigrationRollbackTest(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "rollback_settings.py").write_text(
                "from proxy.test_settings import *  # noqa\n"
                "DATABASES = {{'default': {{'ENGINE': 'django.db.backends.sqlite3', 'NAME': {!r}}}}}\n".format(
                    str(Path(tmp, "db.sqlite3"))
                )
            )
            env = {k: v for k, v in os.environ.items() if not k.startswith("BLACKLISTED_")}
            env.update(
                DJANGO_SETTINGS_MODULE="rollback_settings",
                PYTHONPATH=os.pathsep.join([tmp, str(settings.BASE_DIR)]),
            )
            cls.process = subprocess.run(
                [sys.executable, "-c", SCRIPT], cwd=settings.BASE_DIR, env=env, capture_output=True, text=True
            )
        lines = [line for line in cls.process.stdout.splitlines() if line.startswith("RESULT=")]
        cls.result = json.loads(lines[-1][len("RESULT="):]) if lines else None

    def setUp(self):
        self.assertEqual(self.process.returncode, 0, self.process.stderr)
        self.assertIsNotNone(self.result, self.process.stdout)

    def test_rollback_parks_user_agent_rules_out_of_reach_of_older_versions(self):
        rolled_back = self.result["rolled_back"]
        self.assertEqual([rule[:2] for rule in rolled_back["rules"]], [["ip", "10.0.0.1"]])
        self.assertEqual(
            rolled_back["parked"], [["user_agent", "sqlmap"], ["user_agent_re", "^$"], ["user_agent_re", "nikto"]]
        )
        self.assertIn("Parked 3 User-Agent blacklist rule(s)", self.process.stderr)

    def test_upgrade_restores_them_with_their_original_fields(self):
        upgraded = self.result["upgraded"]
        self.assertIsNone(upgraded["parked"])  # table dropped
        self.assertEqual(upgraded["rules"], [
            ["ip", "10.0.0.1", True, "2.1.0", "2026-01-02 03:04:05"],
            ["user_agent", "sqlmap", True, "2.1.0", "2026-01-02 03:04:05"],
            ["user_agent_re", "^$", False, "pre-2.0.0", "2026-01-02 03:04:05"],
            # Re-created while rolled back: the current row wins over the parked one.
            ["user_agent_re", "nikto", True, "2.0.0", "2026-01-02 03:04:05"],
        ])
        self.assertIn("Restored 2 parked User-Agent blacklist rule(s) (1 already existed)", self.process.stderr)

    def test_round_trips_are_lossless(self):
        self.assertEqual(self.result["second_round_trip"], self.result["upgraded"])
