import ipaddress

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from middleman.exceptions import InvalidRuleError
from middleman.rules import validate_rule
from middleman.version import LEGACY_VERSION, current_version


def canonical_ip(value):
    """Canonical text form of an IP (IPv4-mapped IPv6 unwrapped), or None."""
    try:
        address = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped if mapped is not None else address)


class AccessEntry(models.Model):
    """
    A single access entry.
    """

    class Meta:
        app_label = "middleman"
        db_table = "middleman_access_entry"
        ordering = ["ip"]

    key = models.CharField(max_length=20, unique=True)
    ip = models.CharField(max_length=45)
    path = models.CharField(max_length=255)
    already_requested = models.IntegerField(default=0)
    max_requests = models.IntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)
    # Proxy version that created the row; LEGACY_VERSION for rows that predate
    # version tracking (their IP may come from an unverified X-Forwarded-For).
    created_by_version = models.CharField(
        max_length=32, default=current_version, editable=False
    )

    def __str__(self):
        return self.key

    def __repr__(self):
        return "Access from {} to {} at {}".format(self.ip, self.path, self.created_at)

    @property
    def is_legacy(self) -> bool:
        return self.created_by_version == LEGACY_VERSION


class BlacklistRule(models.Model):
    """A persistent rule that blocks requests before proxying."""

    class RuleType(models.TextChoices):
        # Who is asking:
        IP = "ip", "IP"
        PATH = "path", "Path"
        # Where the proxy would connect (see middleman/destinations.py):
        HOST = "host", "Host (site)"
        HOST_RE = "host_re", "Host (regex)"
        # What the client says it is (User-Agent header, see middleman/user_agents.py):
        USER_AGENT = "user_agent", "User-Agent"
        USER_AGENT_RE = "user_agent_re", "User-Agent (regex)"

    class Meta:
        app_label = "middleman"
        db_table = "middleman_blacklist_rule"
        ordering = ["rule_type", "value"]
        constraints = [
            models.UniqueConstraint(
                fields=["rule_type", "value"], name="unique_blacklist_rule"
            )
        ]

    # Must fit the longest RuleType value ("user_agent_re"). SQLite ignores
    # the length, Postgres does not: a too-short column only fails in production.
    rule_type = models.CharField(max_length=16, choices=RuleType.choices)
    value = models.CharField(max_length=255)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # Proxy version that created the rule; LEGACY_VERSION for rules created
    # before validation existed, which may therefore be invalid.
    created_by_version = models.CharField(
        max_length=32, default=current_version, editable=False
    )

    def __str__(self):
        return "{}: {}".format(self.rule_type, self.value)

    @property
    def is_cidr(self) -> bool:
        """True when this is an IP rule expressed as a CIDR subnet."""
        return self.rule_type == self.RuleType.IP and "/" in (self.value or "")

    @property
    def is_legacy(self) -> bool:
        return self.created_by_version == LEGACY_VERSION

    def parse(self):
        """Validate the rule; returns the parsed host/User-Agent rule (or None). Raises InvalidRuleError."""
        return validate_rule(self.rule_type, self.value)

    @property
    def validation_error(self):
        """None if the rule is valid for the current version, else the InvalidRuleError."""
        try:
            self.parse()
        except InvalidRuleError as exc:
            return exc
        return None

    def clean(self):
        super().clean()
        error = self.validation_error
        if error is not None:
            raise ValidationError({"value": ValidationError(error.message, code=error.reason)})


class ApiToken(models.Model):
    """
    API token for the management API. Only a SHA-256 hash of the token is
    stored; the token itself is shown once, when it is created
    (``python manage.py create_api_token``). Requests act as ``user``, so the
    user's permissions decide what the token may do.
    """

    class Meta:
        app_label = "middleman"
        db_table = "middleman_api_token"
        ordering = ["-created_at"]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_tokens"
    )
    name = models.CharField(max_length=100, help_text="What the token is for, e.g. 'ci' or 'ops-script'.")
    prefix = models.CharField(max_length=16, unique=True, editable=False)
    key_hash = models.CharField(max_length=64, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True, editable=False)
    created_by_version = models.CharField(max_length=32, default=current_version, editable=False)

    def __str__(self):
        return "{} ({}, mm_{}_…)".format(self.name, self.user, self.prefix)


class ClientPolicy(models.Model):
    """
    Per-client settings, keyed by the resolved client IP. Currently: whether
    the client may see its own rate limit headers. Set manually by an admin
    (``source=manual``, never changed by automation) or by abuse detection
    (``source=automatic``).
    """

    class Source(models.TextChoices):
        MANUAL = "manual", "Set by an admin"
        AUTOMATIC = "automatic", "Set by abuse detection"

    class Meta:
        app_label = "middleman"
        db_table = "middleman_client_policy"
        ordering = ["ip"]
        verbose_name_plural = "client policies"

    ip = models.CharField(max_length=45, unique=True)
    hide_rate_limit_headers = models.BooleanField(default=False)
    source = models.CharField(max_length=10, choices=Source.choices, default=Source.MANUAL)
    reason = models.TextField(blank=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by_version = models.CharField(max_length=32, default=current_version, editable=False)

    def __str__(self):
        return "{} (hide headers: {}, {})".format(self.ip, self.hide_rate_limit_headers, self.source)

    def clean(self):
        super().clean()
        canonical = canonical_ip(self.ip)
        if canonical is None:
            raise ValidationError({"ip": ValidationError("'{}' is not a valid IP address.".format(self.ip), code="invalid_ip")})
        self.ip = canonical

    def save(self, *args, **kwargs):
        # Always store the canonical form, so lookups by resolved client IP match.
        self.ip = canonical_ip(self.ip) or self.ip
        super().save(*args, **kwargs)


class AbuseSignal(models.Model):
    """
    Suspicious behaviour of one client, aggregated per minute ``bucket`` (and
    ``fingerprint`` for signals that count distinct values), so an attacker
    cannot create one row per request.
    """

    class Kind(models.TextChoices):
        FORGED_RATE_LIMIT_HEADER = "forged_rate_limit_header", "Sent rate limit headers to the proxy"
        FORWARDING_ROTATION = "forwarding_rotation", "Rotated client-supplied forwarding headers"
        RATE_LIMITED_RETRY = "rate_limited_retry", "Kept requesting after being rate limited"
        BLACKLIST_HIT = "blacklist_hit", "Request blocked by a client blacklist rule"
        AUTH_FAILURE = "auth_failure", "Invalid, expired or revoked API token"
        ACCESS_DENIED = "access_denied", "Management API without credentials or permission"
        LOGIN_FAILURE = "login_failure", "Failed admin login (password)"
        INVALID_HOST_HEADER = "invalid_host_header", "Request with a Host header that is not allowed"

    class Meta:
        app_label = "middleman"
        db_table = "middleman_abuse_signal"
        ordering = ["-bucket"]
        constraints = [
            models.UniqueConstraint(
                fields=["ip", "kind", "bucket", "fingerprint"], name="unique_abuse_signal_bucket"
            )
        ]
        indexes = [models.Index(fields=["ip", "bucket"], name="abuse_signal_ip_bucket")]

    ip = models.CharField(max_length=45)
    kind = models.CharField(max_length=32, choices=Kind.choices)
    bucket = models.DateTimeField(help_text="Start of the minute the events happened in.")
    fingerprint = models.CharField(max_length=32, blank=True, default="")
    count = models.PositiveIntegerField(default=0)
    created_by_version = models.CharField(max_length=32, default=current_version, editable=False)

    def __str__(self):
        return "{} {} ×{} @ {}".format(self.ip, self.kind, self.count, self.bucket)


class AllowedHost(models.Model):
    """
    A Host header value accepted in addition to the ALLOWED_HOSTS baseline.
    Managed at runtime through /settings/allowed-hosts/ or the admin; values
    are validated and normalized by middleman.hosts.normalize_allowed_host.
    """

    class Meta:
        app_label = "middleman"
        db_table = "middleman_allowed_host"
        ordering = ["host"]

    host = models.CharField(max_length=255, unique=True)
    note = models.CharField(max_length=255, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by_version = models.CharField(max_length=32, default=current_version, editable=False)

    def __str__(self):
        return self.host

    def clean(self):
        from middleman.hosts import normalize_allowed_host

        super().clean()
        try:
            self.host = normalize_allowed_host(self.host)
        except InvalidRuleError as error:
            raise ValidationError({"host": ValidationError(error.message, code=error.reason)})

    def save(self, *args, **kwargs):
        # Never store an unvalidated host, whatever the code path.
        from middleman.hosts import normalize_allowed_host

        self.host = normalize_allowed_host(self.host)
        super().save(*args, **kwargs)


class RuleSetVersion(models.Model):
    """
    Version token of a rule set (one row per set; currently only "blacklist").
    Every change to a BlacklistRule writes a new random token, so every process
    knows with one primary-key lookup whether its compiled rules are stale
    (see middleman/ruleset.py). Not meant to be edited by hand.
    """

    class Meta:
        app_label = "middleman"
        db_table = "middleman_ruleset_version"

    name = models.CharField(max_length=32, primary_key=True)
    token = models.CharField(max_length=32)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "{}@{}".format(self.name, self.token)
