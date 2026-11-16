"""
Application-wide logging: request context, formats and the access log.

Every log line carries the proxy version and the id of the request it belongs
to (``-`` outside requests), whatever logger wrote it (``middleman.*``,
``django.*``, ``axes``...), so one grep/query finds everything a request did:

    2026-01-01 12:00:00,000 WARNING  middleman.views [proxy v2.1.0] [req 3f9a1c2b7d4e] [ProxyView] ...

* The id is assigned by ``begin_request``, connected to Django's
  ``request_started`` signal, which fires before any middleware: so
  ``AllowedHostsMiddleware`` can stay the very first middleware (the Host
  header is validated before anything else runs) and its own log lines still
  carry the id. ``clear_request_id`` (``request_finished``) ends it.
* ``RequestContextMiddleware`` (right after AllowedHostsMiddleware) returns
  the id as ``X-Request-ID`` and writes one access line per request
  (``middleman.access``: INFO, WARNING when slower than
  ``LOG_SLOW_REQUEST_MS``, ERROR for 5xx). Requests rejected for their Host
  header get the same header and access line from AllowedHostsMiddleware.
* The id is also the ``ref`` of policy ``403`` bodies, so a user reporting a
  block gives operators the key to every line of that request.
* Database errors that escape a view become a ``503`` (or ``500``) with a
  one-line diagnosis (middleman.diagnostics) instead of a bare stack trace.
* ``LOG_FORMAT=json`` writes one JSON object per line (for log pipelines):
  time, level, logger, version, request_id, message, the ``[Component]`` and
  the ``key=value`` fields of the message, and the exception if any.

Client-supplied values are always logged with ``%r`` (escaped, no line
breaks), so they cannot forge log lines in either format.
"""

import contextvars
import json
import logging
import re
import secrets
import time
from datetime import datetime, timezone

from middleman.version import __version__

access_logger = logging.getLogger("middleman.access")
logger = logging.getLogger(__name__)

NO_REQUEST = "-"
_clock = time.perf_counter  # module alias: tests patch this, not the global time module
_request_id = contextvars.ContextVar("middleman_request_id", default=NO_REQUEST)
_request_started_at = contextvars.ContextVar("middleman_request_started_at", default=None)
MAX_LOGGED_PATH = 200


def new_request_id() -> str:
    """Random, unguessable, 12 hex characters."""
    return secrets.token_hex(6)


def current_request_id() -> str:
    """Id of the request being handled by this thread/task, or '-'."""
    return _request_id.get()


def begin_request(**kwargs) -> str:
    """A request starts (connected to request_started, before any middleware): give it an id."""
    request_id = new_request_id()
    _request_id.set(request_id)
    _request_started_at.set(_clock())
    return request_id


def clear_request_id(**kwargs) -> None:
    """The request is over (connected to request_finished): later lines are not part of it."""
    _request_id.set(NO_REQUEST)
    _request_started_at.set(None)


def ensure_request_id(request) -> str:
    """The current request's id (assigned by begin_request; created here if the signal did not run)."""
    request_id = _request_id.get()
    if request_id == NO_REQUEST:
        request_id = begin_request()
    request.request_id = request_id
    return request_id


def elapsed_ms() -> float:
    started = _request_started_at.get()
    return (_clock() - started) * 1000 if started is not None else 0.0


def log_access(request, status) -> None:
    """One access line for ``request`` (INFO; WARNING when slow; ERROR for 5xx)."""
    from django.conf import settings

    from middleman.client_ip import get_client_ip

    duration_ms = elapsed_ms()
    slow = duration_ms >= getattr(settings, "LOG_SLOW_REQUEST_MS", 2000)
    level = logging.ERROR if status >= 500 else logging.WARNING if slow else logging.INFO
    if access_logger.isEnabledFor(level):
        access_logger.log(
            level, "[Access] %s %r %s | duration_ms=%.1f ip=%s slow=%s",
            request.method, _loggable_path(request.path), status, duration_ms,
            get_client_ip(request.META), slow,
        )


class RequestContextFilter(logging.Filter):
    """Adds ``request_id`` and ``proxy_version`` to every record (attach it to handlers)."""

    def filter(self, record):
        if not hasattr(record, "request_id"):
            record.request_id = _request_id.get()
        record.proxy_version = __version__
        return True


_COMPONENT = re.compile(r"^\[([^\]]+)\]\s*")
_FIELD = re.compile(r"""(\w+)=('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\[[^\]]*\]|\{[^}]*\}|\S+)""")


def parse_message(message: str):
    """
    Split a '[Component] text | key=value key2=value2' message into
    (component, text, fields). Values are kept as logged (repr'd strings keep
    their quotes). Messages that do not follow the convention give (None, message, {}).
    """
    component = None
    match = _COMPONENT.match(message)
    if match:
        component = match.group(1)
        message = message[match.end():]
    text, _, rest = message.partition(" | ")
    fields = dict(_FIELD.findall(rest)) if rest else {}
    return component, text, fields


_STANDARD_ATTRS = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {
    "message", "asctime", "request_id", "proxy_version",
}


class JsonFormatter(logging.Formatter):
    """One JSON object per line."""

    def format(self, record):
        message = record.getMessage()
        component, text, fields = parse_message(message)
        payload = {
            "time": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "version": getattr(record, "proxy_version", __version__),
            "request_id": getattr(record, "request_id", NO_REQUEST),
            "message": message,
        }
        if component:
            payload["component"] = component
            payload["event"] = text
        if fields:
            payload["fields"] = fields
        extra = {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS and not k.startswith("_")}
        if extra:
            payload["extra"] = extra
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def _loggable_path(path):
    path = path or ""
    return path if len(path) <= MAX_LOGGED_PATH else path[:MAX_LOGGED_PATH] + "…"


class RequestContextMiddleware:
    """
    X-Request-ID + access log + semantic handling of database errors. Goes
    right after AllowedHostsMiddleware (which must stay first); the id itself
    is assigned earlier, by begin_request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Assigned by begin_request (request_started); cleared by clear_request_id
        # (request_finished), not here: Django logs django.request / django.server
        # lines after the middleware returns, and they must carry the id too.
        request_id = ensure_request_id(request)
        status = 500
        try:
            response = self.get_response(request)
            status = response.status_code
            response["X-Request-ID"] = request_id
            return response
        finally:
            log_access(request, status)

    def process_exception(self, request, exception):
        """Database errors that escape a view: explain them and answer 503/500 in plain text."""
        from django.db import DatabaseError
        from django.http import HttpResponse

        from middleman.diagnostics import explain_database_error, log_database_error

        if not isinstance(exception, DatabaseError):
            return None
        diagnosis = explain_database_error(exception)
        log_database_error(logger, "Request", exception, diagnosis, method=request.method,
                           path=_loggable_path(request.path))
        status = 503 if diagnosis.unavailable else 500
        message = (
            "Service unavailable: the proxy's database is not reachable (ref {}).".format(current_request_id())
            if diagnosis.unavailable else
            "Internal error (ref {}).".format(current_request_id())
        )
        return HttpResponse(message, status=status, content_type="text/plain; charset=utf-8")
