"""
Allowed hosts (Host header validation), managed at runtime.

Django's ``ALLOWED_HOSTS`` is fixed at startup. Here the allowed hosts are:

* a **baseline** from the ``ALLOWED_HOSTS`` environment variable (default:
  localhost, 127.0.0.1, [::1]). It cannot be changed through the API, so an
  admin can never lock everyone out; changing it needs a redeploy;
* **runtime hosts** stored in the database (``AllowedHost``), managed only
  through ``/settings/allowed-hosts/`` or the admin by users with the
  dedicated permissions.

``AllowedHostsMiddleware`` must be the first middleware: it rejects requests
whose Host header is not allowed before anything else reads it. Django's own
check is therefore delegated (``settings.ALLOWED_HOSTS = ["*"]``), and the app
refuses to start if the middleware is missing or not first.

Matching uses Django's own ``split_domain_port``/``validate_host``, so
semantics are exactly Django's: ``example.com`` matches only that host,
``.example.com`` matches it and its subdomains, ports are ignored.
"""

import ipaddress
import logging
import threading
import time

from django.http import HttpResponseBadRequest
from django.http.request import split_domain_port, validate_host

from middleman.destinations import _is_valid_hostname, normalize_host, parse_ip_literal
from middleman.exceptions import InvalidRuleError

logger = logging.getLogger(__name__)

MIDDLEWARE_PATH = "middleman.hosts.AllowedHostsMiddleware"
DEFAULT_BASELINE = ("localhost", "127.0.0.1", "[::1]")
# Other processes/workers see runtime changes within this many seconds.
CACHE_SECONDS = 5
MAX_LENGTH = 253


def _invalid(reason, message, value):
    return InvalidRuleError(reason, message, rule_type="allowed_host", value=value)


def normalize_allowed_host(value) -> str:
    """
    Validate and normalize one allowed-host entry; raises InvalidRuleError.

    Accepted: ``example.com``, ``.example.com`` (domain and subdomains; at least
    two labels, so ``.com`` is refused), IPv4 ``203.0.113.5`` and IPv6
    ``2001:db8::1`` / ``[2001:db8::1]`` (stored bracketed, as Django compares).
    Refused: ``*`` (would accept any Host), ports, schemes, paths, user info,
    whitespace and non-canonical IP spellings.
    """
    if not isinstance(value, str):
        raise _invalid("not_a_string", "Host must be a string.", value)
    raw = value.strip()
    if not raw:
        raise _invalid("empty", "Host cannot be empty.", value)
    if len(raw) > MAX_LENGTH:
        raise _invalid("too_long", "Host is longer than {} characters.".format(MAX_LENGTH), value)
    if raw == "*" or "*" in raw:
        raise _invalid(
            "wildcard_all",
            "'*' would accept any Host header and disable the protection; "
            "use '.example.com' to allow a domain and its subdomains.",
            value,
        )
    if any(c.isspace() for c in raw) or any(c in raw for c in "/@?#\\,"):
        raise _invalid(
            "not_a_host",
            "Enter only a host name or IP (no scheme, path, user info, spaces or commas).",
            value,
        )

    # IPv6, with or without brackets.
    bare = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    if ":" in bare:
        try:
            address = ipaddress.IPv6Address(bare)
        except ValueError:
            raise _invalid("has_port", "Ports are not part of an allowed host; remove ':{}'.".format(
                raw.rsplit(":", 1)[-1]), value)
        return "[{}]".format(address.compressed)

    wildcard = raw.startswith(".")
    name = raw[1:] if wildcard else raw
    address = parse_ip_literal(name)
    if address is not None:
        if wildcard:
            raise _invalid("ip_wildcard", "A leading '.' only applies to domain names.", value)
        if str(address) != name.strip().lower():
            raise _invalid(
                "non_canonical_ip",
                "'{}' is not a plain dotted IP; leading zeros, hex and shortened forms are "
                "ambiguous (write e.g. 10.0.0.1).".format(raw),
                value,
            )
        return str(address)

    host = normalize_host(name)
    if not _is_valid_hostname(host):
        raise _invalid("invalid_host", "'{}' is not a valid host name.".format(raw), value)
    if wildcard and "." not in host and host != "localhost":
        raise _invalid(
            "wildcard_too_broad",
            "'{}' would allow every host under a top-level domain.".format(raw),
            value,
        )
    return "." + host if wildcard else host


def parse_baseline(raw):
    """Parse the ALLOWED_HOSTS environment value (comma-separated); raises InvalidRuleError."""
    if raw is None or not raw.strip():
        return list(DEFAULT_BASELINE)
    if raw.strip().startswith("["):
        raise _invalid(
            "not_comma_separated",
            "ALLOWED_HOSTS must be comma-separated (e.g. 'example.com,.example.org'), not a list literal.",
            raw,
        )
    hosts = []
    for item in raw.split(","):
        host = normalize_allowed_host(item)
        if host not in hosts:
            hosts.append(host)
    return hosts


# --- runtime hosts (database), cached per process -----------------------------

_cache_lock = threading.Lock()
_cache = {"hosts": None, "loaded_at": 0.0}


def invalidate_cache(**kwargs) -> None:
    """Drop the cached runtime hosts (connected to AllowedHost save/delete)."""
    with _cache_lock:
        _cache["hosts"] = None


def runtime_hosts():
    """Hosts added at runtime. If the database fails, none (fail closed)."""
    now = time.monotonic()
    with _cache_lock:
        if _cache["hosts"] is not None and now - _cache["loaded_at"] < CACHE_SECONDS:
            return _cache["hosts"]
    try:
        from middleman.models import AllowedHost

        hosts = tuple(AllowedHost.objects.values_list("host", flat=True))
    except Exception:
        logger.exception("[AllowedHosts] Could not load runtime hosts; only the baseline is accepted")
        return ()
    with _cache_lock:
        _cache["hosts"], _cache["loaded_at"] = hosts, now
    return hosts


def baseline_hosts():
    from django.conf import settings

    return list(getattr(settings, "ALLOWED_HOSTS_BASELINE", DEFAULT_BASELINE))


def is_allowed(domain: str) -> bool:
    if not domain:
        return False
    return validate_host(domain, baseline_hosts()) or validate_host(domain, runtime_hosts())


def check_middleware_order(middleware) -> None:
    """Raise ImproperlyConfigured unless AllowedHostsMiddleware is the first middleware."""
    from django.core.exceptions import ImproperlyConfigured

    if not middleware or middleware[0] != MIDDLEWARE_PATH:
        raise ImproperlyConfigured(
            "{} must be the first entry of MIDDLEWARE: it is the only Host header check "
            "(ALLOWED_HOSTS is delegated to it).".format(MIDDLEWARE_PATH)
        )


_WARNED_HOSTS = set()
_MAX_WARNED_HOSTS = 1024


class AllowedHostsMiddleware:
    """Reject requests whose Host header is not allowed (400), before anything reads it."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw_host = request._get_raw_host()
        domain, _ = split_domain_port(raw_host)
        if is_allowed(domain):
            return self.get_response(request)

        from middleman import abuse
        from middleman.client_ip import get_client_ip

        client = get_client_ip(request.META)
        if raw_host not in _WARNED_HOSTS and len(_WARNED_HOSTS) < _MAX_WARNED_HOSTS:
            _WARNED_HOSTS.add(raw_host)
            logger.warning(
                "[AllowedHosts] Rejected request with a Host that is not allowed | host=%r ip=%s path=%r",
                raw_host, client, request.path,
            )
        abuse.report(client, [("invalid_host_header", "")])
        return HttpResponseBadRequest(
            "Bad request: invalid Host header.", content_type="text/plain; charset=utf-8"
        )
