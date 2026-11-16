"""
HTTP to the target server, with reused (keep-alive) connections.

Before this module every proxied request opened two new TCP (and TLS)
connections, one for the HEAD availability check and one for the GET, and
closed them: on the benchmark VM that cost ~10 ms per request, more than every
other step together. Now:

* each process has one ``requests.Session``, shared by its threads, whose
  connection pool keeps idle connections open (``POOL_HOSTS`` hosts x
  ``POOL_PER_HOST`` connections; more are opened under bursts and dropped
  after use), so the HEAD, the GET and the next requests reuse them. Shared,
  not per thread: servers that run each request in a new thread (Django's
  runserver, thread-per-connection WSGI servers) would otherwise get a new
  pool per request - no reuse, and idle connections left open until garbage
  collection (the throughput benchmark stalled). Sharing is safe here: the
  session is never modified after creation, cookies are not stored (and the
  cookie jar is locked), redirects are not followed, and urllib3's pools are
  thread-safe. A forked process (gunicorn --preload) gets its own session;
* the streamed body goes back to the pool only once it has been read to the
  end (``stream_body``); a body the client stopped reading is closed, never
  reused with unread data in it. Small redirect bodies are drained so their
  connection can be reused too (``discard``);
* **cookies are never stored**: a shared session would otherwise send a cookie
  the target set for one client along with every other client's requests
  (``requests.get``, used before, never kept cookies either);
* one retry, and only for a pooled connection the server dropped before
  answering (``RetryDroppedConnection``): servers close idle keep-alive
  connections, and a request sent just as the close arrives would otherwise
  fail. GET/HEAD only (idempotent). Every other error (timeouts, refused
  connections, DNS...) is handled exactly like requests' default (no retry),
  so timeouts are not doubled and 502/504 mapping is unchanged.

``UPSTREAM_KEEPALIVE=false`` restores one connection per call (the previous
behaviour), e.g. for a target that mishandles keep-alive.

Everything else is unchanged: same timeouts, same headers (requests' defaults),
same environment handling (proxy variables, CA bundle), no redirects followed
here (ProxyManager checks every hop against the host rules first).
"""

import logging
import os
import threading
from http.cookiejar import DefaultCookiePolicy

import requests
from django.conf import settings
from requests.adapters import HTTPAdapter
from urllib3.exceptions import ProtocolError
from urllib3.response import BaseHTTPResponse
from urllib3.util.retry import Retry

POOL_HOSTS = 8  # distinct hosts (target + redirect hops) with a pool, per process
POOL_PER_HOST = 32  # idle connections kept per host and process (bursts open extra ones)
CHUNK_SIZE = 64 * 1024
MAX_DRAINED_BODY = 64 * 1024  # redirect bodies up to this size are drained for reuse

logger = logging.getLogger(__name__)
_lock = threading.Lock()
_shared = {"session": None, "pid": None}

# requests' own default: no retry at all, read errors re-raised as they are.
_NO_RETRY = Retry(0, read=False)

# Bursts beyond POOL_PER_HOST open extra connections that are closed after use;
# urllib3 logs each one as a WARNING ("Connection pool is full"): expected here.
logging.getLogger("urllib3.connectionpool").addFilter(
    lambda record: "Connection pool is full" not in record.getMessage()
)


class RetryDroppedConnection(Retry):
    """
    Retry once when the connection failed before a response started (the
    server closed a pooled keep-alive connection: ProtocolError such as
    RemoteDisconnected / ConnectionResetError). Anything else is delegated to
    requests' default no-retry policy, unchanged.
    """

    def increment(self, method=None, url=None, response=None, error=None, _pool=None, _stacktrace=None):
        if isinstance(error, ProtocolError) and self.read and method in ("GET", "HEAD"):
            return super().increment(method, url, response, error, _pool, _stacktrace)
        return _NO_RETRY.increment(method, url, response, error, _pool, _stacktrace)


def _retry_policy() -> Retry:
    return RetryDroppedConnection(total=1, connect=0, read=1, status=0, other=0, redirect=0,
                                  raise_on_status=False, respect_retry_after_header=False)


def keepalive_enabled() -> bool:
    return getattr(settings, "UPSTREAM_KEEPALIVE", True)


def _new_session() -> requests.Session:
    session = requests.Session()
    # Never store cookies: they would leak from one client's request to the next.
    session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
    adapter = HTTPAdapter(pool_connections=POOL_HOSTS, pool_maxsize=POOL_PER_HOST, pool_block=False,
                          max_retries=_retry_policy())
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def session() -> requests.Session:
    """This process's keep-alive session (created on first use, again after a fork)."""
    pid = os.getpid()
    current = _shared["session"]
    if current is not None and _shared["pid"] == pid:
        return current
    with _lock:
        if _shared["session"] is None or _shared["pid"] != pid:
            # After a fork the parent's sockets must not be shared: start over
            # (the inherited session object is simply dropped, not closed).
            _shared["session"], _shared["pid"] = _new_session(), pid
        return _shared["session"]


def close_sessions() -> None:
    """Close the pooled connections (tests, shutdown)."""
    with _lock:
        current, _shared["session"], _shared["pid"] = _shared["session"], None, None
    if current is not None:
        current.close()


def head(url, *, timeout, **kwargs):
    """HEAD ``url``. ``timeout`` is required: an upstream call must never wait forever."""
    if not keepalive_enabled():
        return requests.head(url, timeout=timeout, **kwargs)
    return session().head(url, timeout=timeout, **kwargs)


def get(url, *, timeout, **kwargs):
    """GET ``url``. ``timeout`` is required: an upstream call must never wait forever."""
    if not keepalive_enabled():
        return requests.get(url, timeout=timeout, **kwargs)
    return session().get(url, timeout=timeout, **kwargs)


def stream_body(response, chunk_size=CHUNK_SIZE):
    """
    Yield the (decoded) body of a ``stream=True`` response. Read to the end,
    the connection goes back to the pool; abandoned (client gone, error), it is
    closed.
    """
    raw = response.raw
    completed = False
    try:
        if isinstance(raw, BaseHTTPResponse):
            # Same bytes as iterating `raw` (decoded), without splitting on newlines.
            yield from raw.stream(chunk_size, decode_content=True)
        else:  # file-like stand-ins (tests)
            while True:
                chunk = raw.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        completed = True
    finally:
        if completed and isinstance(raw, BaseHTTPResponse):
            raw.release_conn()
        else:
            response.close()


def discard(response) -> None:
    """Done with a response whose body is not needed (redirects): reuse its connection if cheap."""
    raw = getattr(response, "raw", None)
    length = response.headers.get("content-length") if hasattr(response, "headers") else None
    if isinstance(raw, BaseHTTPResponse) and length is not None and length.isdigit() and int(length) <= MAX_DRAINED_BODY:
        try:
            raw.drain_conn()
            raw.release_conn()
            return
        except Exception as exc:  # noqa: BLE001 - reuse is an optimisation: close it instead
            logger.debug("[Upstream] Could not drain a redirect body; closing its connection | error=%r", exc)
    response.close()
