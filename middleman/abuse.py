"""
Abuse and tampering detection.

Signals are recorded per client IP and aggregated per minute. Each kind has a
weight; when a client's score over the last ``window_minutes`` reaches
``threshold``, the client's rate limit headers are hidden automatically
(ClientPolicy, source=automatic). Admin decisions (source=manual) are never
changed by automation. The consequence is deliberately mild - the client can
still use the proxy, it just stops seeing its limits - which keeps false
positives cheap.

Signals and why they indicate tampering:

* forged_rate_limit_header: the client *sends* X-RateLimit-* / RateLimit-*
  headers. They are response headers; no legitimate client sends them.
* forwarding_rotation: the client-supplied forwarding data (X-Forwarded-For
  from an untrusted peer, X-Real-IP, Forwarded, ...) keeps changing. A
  constant value (corporate forward proxy) scores nothing; every additional
  distinct value in the window does (limit-evasion attempts rotate it).
* rate_limited_retry: each request answered 429.
* blacklist_hit: each request blocked by a client (ip/path) rule. Destination
  (host) blocks are caused by the target's redirects, not the client.
* auth_failure: invalid, expired or revoked API token.
* access_denied: management API without credentials or permission.
* login_failure: failed password login at /admin/login/ (django-axes locks
  the IP after AXES_FAILURE_LIMIT failures; this feeds the same score).
* invalid_host_header: Host header that is not allowed (Host header
  injection / cache or password-reset poisoning attempts).
"""

import hashlib
import logging
import re
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import IntegrityError, transaction
from django.db.models import Count, F, Sum
from django.utils import timezone

logger = logging.getLogger(__name__)

DEFAULTS = {
    "ENABLED": True,
    "WINDOW_MINUTES": 10,
    "THRESHOLD": 10,
    "WEIGHTS": {
        "forged_rate_limit_header": 5,
        "forwarding_rotation": 3,
        "rate_limited_retry": 1,
        "blacklist_hit": 1,
        "auth_failure": 3,
        "access_denied": 1,
        "login_failure": 3,
        "invalid_host_header": 1,
    },
}

# Request headers (as WSGI META keys) that only a tampering client would send.
_RATE_LIMIT_HEADER = re.compile(r"HTTP_(X_)?RATE_?LIMIT(_|$)")


def get_config() -> dict:
    """ABUSE_DETECTION settings merged over DEFAULTS; raises ImproperlyConfigured."""
    user = getattr(settings, "ABUSE_DETECTION", {}) or {}
    unknown = set(user) - set(DEFAULTS)
    if unknown:
        raise ImproperlyConfigured("ABUSE_DETECTION has unknown keys: {}".format(sorted(unknown)))
    config = dict(DEFAULTS, **{k: v for k, v in user.items() if k != "WEIGHTS"})
    weights = dict(DEFAULTS["WEIGHTS"], **user.get("WEIGHTS", {}))
    unknown = set(weights) - set(DEFAULTS["WEIGHTS"])
    if unknown:
        raise ImproperlyConfigured("ABUSE_DETECTION['WEIGHTS'] has unknown kinds: {}".format(sorted(unknown)))
    for kind, weight in weights.items():
        if not isinstance(weight, int) or isinstance(weight, bool) or weight < 0:
            raise ImproperlyConfigured("ABUSE_DETECTION weight for {} must be an int >= 0.".format(kind))
    for key in ("WINDOW_MINUTES", "THRESHOLD"):
        value = config[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ImproperlyConfigured("ABUSE_DETECTION['{}'] must be an int >= 1.".format(key))
    if not isinstance(config["ENABLED"], bool):
        raise ImproperlyConfigured("ABUSE_DETECTION['ENABLED'] must be True or False.")
    config["WEIGHTS"] = weights
    return config


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:32]


def request_signals(meta, resolution):
    """Header-based signals for one proxied request: list of (kind, fingerprint)."""
    signals = []
    if any(_RATE_LIMIT_HEADER.match(key) for key in meta):
        signals.append(("forged_rate_limit_header", ""))
    if resolution.client_supplied_forwarding:
        signals.append(("forwarding_rotation", fingerprint("\n".join(resolution.client_supplied_forwarding))))
    return signals


def _bucket(now):
    return now.replace(second=0, microsecond=0)


def _record(ip: str, kind: str, fp: str, now) -> None:
    from middleman.models import AbuseSignal

    lookup = {"ip": ip, "kind": kind, "bucket": _bucket(now), "fingerprint": fp}
    updated = AbuseSignal.objects.filter(**lookup).update(count=F("count") + 1)
    if updated:
        return
    try:
        with transaction.atomic():
            AbuseSignal.objects.create(count=1, **lookup)
    except IntegrityError:
        # A concurrent request created the bucket first.
        AbuseSignal.objects.filter(**lookup).update(count=F("count") + 1)


def score(ip: str, config=None, now=None) -> tuple:
    """(score, {kind: points}) over the configured window."""
    from middleman.models import AbuseSignal

    config = config or get_config()
    now = now or timezone.now()
    since = _bucket(now) - timedelta(minutes=config["WINDOW_MINUTES"] - 1)
    rows = (
        AbuseSignal.objects.filter(ip=ip, bucket__gte=since)
        .values("kind")
        .annotate(total=Sum("count"), distinct=Count("fingerprint", distinct=True))
    )
    points = {}
    for row in rows:
        weight = config["WEIGHTS"].get(row["kind"], 0)
        if row["kind"] == "forwarding_rotation":
            value = weight * max(row["distinct"] - 1, 0)
        else:
            value = weight * row["total"]
        if value:
            points[row["kind"]] = value
    return sum(points.values()), points


def _apply_automatic_policy(ip: str, total: int, points: dict, config) -> None:
    from middleman.models import ClientPolicy

    policy = ClientPolicy.objects.filter(ip=ip).first()
    if policy is not None and (
        policy.source == ClientPolicy.Source.MANUAL or policy.hide_rate_limit_headers
    ):
        return  # admin decisions are final; already hidden needs nothing
    reason = "Abuse score {} >= {} in {} min: {}".format(
        total, config["THRESHOLD"], config["WINDOW_MINUTES"],
        ", ".join("{}={}".format(kind, value) for kind, value in sorted(points.items())),
    )
    if policy is None:
        try:
            with transaction.atomic():
                ClientPolicy.objects.create(
                    ip=ip, hide_rate_limit_headers=True,
                    source=ClientPolicy.Source.AUTOMATIC, reason=reason,
                )
        except IntegrityError:
            return  # created concurrently; the next signal re-evaluates it
    else:
        ClientPolicy.objects.filter(pk=policy.pk, source=ClientPolicy.Source.AUTOMATIC).update(
            hide_rate_limit_headers=True, reason=reason, updated_at=timezone.now()
        )
    logger.warning(
        "[AbuseDetector] Hiding rate limit headers for client | ip=%s score=%s threshold=%s points=%s",
        ip, total, config["THRESHOLD"], points,
    )


def report(ip, signals, now=None) -> None:
    """
    Record ``signals`` (list of (kind, fingerprint)) for ``ip`` and apply the
    automatic policy if the score reaches the threshold. Never raises: a
    detection failure must not break the request; it is logged instead.
    """
    if not ip or not signals:
        return
    try:
        config = get_config()
        if not config["ENABLED"]:
            return
        now = now or timezone.now()
        for kind, fp in signals:
            _record(ip, kind, fp, now)
        total, points = score(ip, config, now)
        logger.info(
            "[AbuseDetector] Suspicious activity | ip=%s signals=%s score=%s threshold=%s",
            ip, [kind for kind, _ in signals], total, config["THRESHOLD"],
        )
        if total >= config["THRESHOLD"]:
            _apply_automatic_policy(ip, total, points, config)
    except Exception:
        logger.exception("[AbuseDetector] Failed to record abuse signals | ip=%s signals=%s", ip, signals)


def hides_rate_limit_headers(ip) -> bool:
    from middleman.models import ClientPolicy

    return bool(ip) and ClientPolicy.objects.filter(ip=ip, hide_rate_limit_headers=True).exists()
