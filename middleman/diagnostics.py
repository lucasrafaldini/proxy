"""
Semantic explanations for failures that otherwise surface as stack traces.

``explain_database_error`` turns a database exception (Django's wrapper or the
driver's own, anywhere in the ``__cause__``/``__context__`` chain) into a
``Diagnosis``: a stable ``reason`` code, a one-sentence ``summary`` of what is
wrong, ``hints`` on what to do, and the original ``detail``. It knows which
settings produced the failing connection (POSTGRES_* variables) and which ones
were left at their defaults, the most common cause of "it crashes".

Used by manage.py (``make migrate`` & co. print the explanation instead of a
60-line traceback), by the request middleware and the proxy view (503 +
diagnosis log line), by the allowed-hosts and abuse-detection fallbacks, and
by ``python manage.py doctor``.
"""

import logging
import os
import re
import sys
from typing import List, NamedTuple, Optional

DB_ENV_VARS = ("POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")


class Diagnosis(NamedTuple):
    reason: str  # stable code, e.g. connection_refused
    summary: str  # what is wrong, in one sentence
    hints: List[str]  # what to do, most likely first
    detail: str  # the original error, one line
    unavailable: bool  # True: the database cannot be used at all (HTTP 503)


def _chain(exc):
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def _one_line(exc) -> str:
    text = " ".join(str(exc).split())
    return text or type(exc).__name__


def database_settings(alias="default") -> dict:
    try:
        from django.conf import settings

        return dict(settings.DATABASES.get(alias, {}))
    except Exception:  # settings not importable: nothing to describe
        return {}


def describe_database(db: Optional[dict] = None) -> str:
    db = database_settings() if db is None else db
    engine = db.get("ENGINE", "")
    if engine.endswith("sqlite3"):
        return "SQLite database {}".format(db.get("NAME"))
    if engine.endswith("postgresql"):
        return "PostgreSQL database {!r} on {}:{} as user {!r}".format(
            db.get("NAME"), db.get("HOST") or "localhost", db.get("PORT") or 5432, db.get("USER"),
        )
    return "{} database {!r}".format(engine or "unknown", db.get("NAME"))


def unset_database_variables(environ=None) -> List[str]:
    environ = os.environ if environ is None else environ
    return [name for name in DB_ENV_VARS if not environ.get(name)]


def _environment_hint(environ=None) -> Optional[str]:
    environ = os.environ if environ is None else environ
    unset = unset_database_variables(environ)
    if not unset:
        return None
    hint = "Not set, so defaults are used: {}.".format(", ".join(unset))
    if environ.get("MIDDLEMAN_ENV_FILE"):
        hint += " ({} was loaded but does not set them.)".format(environ["MIDDLEMAN_ENV_FILE"])
    elif os.path.exists(".env"):
        hint += " Load your settings first: source .env (make targets do it automatically)."
    else:
        hint += " Create your settings: cp .env.example .env, edit it, then source .env."
    return hint


# (reason, pattern on the error text, unavailable, summary template, hints)
_RULES = [
    ("driver_missing", r"Error loading psycopg2|No module named 'psycopg2'", True,
     "The PostgreSQL driver (psycopg2) is not installed in this Python environment.",
     ["Use the project virtualenv: make venv, then run commands through make (or .venv/bin/python).",
      "Or install it: pip install -r requirements.txt"]),
    ("connection_refused", r"Connection refused|could not connect to server: No such file", True,
     "Nothing is accepting connections at {where}: PostgreSQL is not running there, or it listens on another host/port.",
     ["Start PostgreSQL (e.g. sudo service postgresql start, or: docker run -d -p 5432:5432 "
      "-e POSTGRES_PASSWORD=... postgres:16).",
      "Or point the proxy at your server: POSTGRES_HOST / POSTGRES_PORT (see .env.example)."]),
    ("host_not_found", r"could not translate host name|Name or service not known|nodename nor servname|"
     r"Temporary failure in name resolution", True,
     "The database host name {host!r} cannot be resolved (DNS).",
     ["Check POSTGRES_HOST for typos; inside Docker use the service name, outside use localhost or an IP."]),
    ("timeout", r"timeout expired|timed out", True,
     "Connecting to {where} timed out: the host is unreachable or a firewall drops the traffic.",
     ["Check that POSTGRES_HOST / POSTGRES_PORT are right and that the port is open from this machine."]),
    ("password_missing", r"no password supplied|fe_sendauth", True,
     "The server requires a password for user {user!r}, but none is configured.",
     ["Set POSTGRES_PASSWORD."]),
    ("auth_failed", r"password authentication failed|authentication failed", True,
     "The server rejected user {user!r}: wrong password (or the user may not log in from this host).",
     ["Check POSTGRES_USER / POSTGRES_PASSWORD.",
      "Reset it as a superuser: ALTER USER \"{user}\" WITH PASSWORD '...';"]),
    ("role_missing", r'role "[^"]*" does not exist', True,
     "The database user {user!r} does not exist on the server.",
     ["Create it: createuser --pwprompt {user}  (or set POSTGRES_USER to an existing user)."]),
    ("database_missing", r'database "[^"]*" does not exist', True,
     "The database {name!r} does not exist on the server.",
     ["Create it: createdb -O {user} {name}  (or set POSTGRES_DB to an existing database), then make migrate."]),
    ("too_many_connections", r"too many connections|remaining connection slots", True,
     "The database server has no free connection slots.",
     ["Lower the number of workers/processes, or raise max_connections on the server."]),
    ("connection_lost", r"server closed the connection unexpectedly|terminating connection|"
     r"connection already closed|SSL SYSCALL error", True,
     "The connection to the database was lost (server restarted, crashed or a network/proxy dropped it).",
     ["Retry; if it keeps happening check the database server logs."]),
    ("not_postgres", r"invalid response to SSL negotiation|received invalid response|"
     r"server sent an unexpected|expected authentication request", True,
     "Something answered at {where}, but it is not PostgreSQL (an HTTP server or another service?).",
     ["Check POSTGRES_HOST / POSTGRES_PORT: they point at the wrong service."]),
    ("ssl", r"SSL", True,
     "The SSL/TLS negotiation with the database failed.",
     ["Check the server's SSL settings (sslmode) and certificates."]),
    ("schema_missing", r"relation \"[^\"]*\" does not exist|no such table", True,
     "The database is reachable but the proxy's tables do not exist: migrations have not been applied.",
     ["Run: make migrate  (python manage.py migrate)."]),
    ("permission_denied", r"permission denied", False,
     "User {user!r} is connected but lacks privileges on the proxy's tables.",
     ["Grant them, e.g.: GRANT ALL ON ALL TABLES IN SCHEMA public TO \"{user}\"; (or run migrations as the owner)."]),
    ("sqlite_unavailable", r"unable to open database file", True,
     "The SQLite database file {name!r} cannot be opened (missing directory or no permission).",
     ["Check the path and the directory permissions."]),
    ("sqlite_locked", r"database is locked", False,
     "The SQLite database is locked by another writer.",
     ["SQLite is for tests/local use; use PostgreSQL for concurrent traffic."]),
]


def explain_database_error(exc, db: Optional[dict] = None, environ=None) -> Diagnosis:
    """Diagnosis for a database exception (never raises)."""
    db = database_settings() if db is None else db
    host = db.get("HOST") or "localhost"
    port = db.get("PORT") or 5432
    values = {
        "where": "{}:{}".format(host, port), "host": host, "port": port,
        "user": db.get("USER") or "?", "name": db.get("NAME") or "?",
    }
    texts = [_one_line(item) for item in _chain(exc)]
    detail = next((text for text in texts if text), _one_line(exc))
    for reason, pattern, unavailable, summary, hints in _RULES:
        if any(re.search(pattern, text, re.IGNORECASE) for text in texts):
            hints = [hint.format(**values) for hint in hints]
            if reason not in ("schema_missing", "permission_denied", "driver_missing", "sqlite_locked"):
                env_hint = _environment_hint(environ)
                if env_hint:
                    hints.append(env_hint)
            return Diagnosis(reason, summary.format(**values), hints, detail, unavailable)
    return Diagnosis(
        "database_error",
        "The database returned an error the proxy does not recognise.",
        ["Run python manage.py doctor, and rerun with --traceback for the full stack trace."],
        detail, False,
    )


def log_database_error(log, component, exc, diagnosis=None, **context):
    """One semantic log line for a database error (traceback only at DEBUG)."""
    diagnosis = diagnosis or explain_database_error(exc)
    fields = " ".join("{}={!r}".format(key, value) for key, value in context.items())
    log.error(
        "[%s] Database error: %s | reason=%s database=%r %shint=%r detail=%r",
        component, diagnosis.summary, diagnosis.reason, describe_database(),
        fields + " " if fields else "", diagnosis.hints[0] if diagnosis.hints else "", diagnosis.detail,
        exc_info=log.isEnabledFor(logging.DEBUG),
    )
    return diagnosis


# --- management commands (manage.py) ----------------------------------------------------

def _command_name(argv):
    args = [arg for arg in argv[1:] if not arg.startswith("-")]
    return args[0] if args else "manage.py"


def format_command_failure(command, diagnosis, description) -> str:
    lines = [
        "",
        "ERROR: `{}` failed: {}".format(command, diagnosis.summary),
        "  Database: {}".format(description),
        "  Reason:   {}".format(diagnosis.reason),
        "  What to do:",
    ]
    lines += ["    {}. {}".format(number, hint) for number, hint in enumerate(diagnosis.hints, start=1)]
    lines += [
        "  Details:  {}".format(diagnosis.detail),
        "  Checks everything at once: make doctor. Full stack trace: add --traceback.",
        "",
    ]
    return "\n".join(lines)


def handle_command_failure(exc, argv, stream=None) -> bool:
    """
    Explain a failed management command on ``stream`` (stderr). Returns True if
    the failure was explained (the caller exits with status 1), False to let
    the exception propagate unchanged. With --traceback it always propagates.
    """
    from django.core.exceptions import ImproperlyConfigured

    stream = stream or sys.stderr
    command = _command_name(argv)
    database_error = _is_database_error(exc)
    if database_error:
        diagnosis = explain_database_error(exc)
        stream.write(format_command_failure(command, diagnosis, describe_database()))
        logging.getLogger("middleman.diagnostics").error(
            "[Diagnostics] Command failed | command=%s reason=%s detail=%r", command, diagnosis.reason,
            diagnosis.detail,
        )
    elif isinstance(exc, ImproperlyConfigured):
        stream.write(
            "\nERROR: `{}` failed: the configuration is invalid.\n  {}\n"
            "  Fix the setting/environment variable named above (see .env.example), then retry.\n"
            "  Full stack trace: add --traceback.\n\n".format(command, _one_line(exc))
        )
    else:
        return False
    return "--traceback" not in argv


def _is_database_error(exc) -> bool:
    try:
        from django.db import Error as DjangoDatabaseError
    except Exception:
        return False
    for item in _chain(exc):
        if isinstance(item, DjangoDatabaseError):
            return True
        if "psycopg2" in _one_line(item) and "Error loading" in _one_line(item):
            return True
    return False
