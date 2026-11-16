"""
Authentication (API tokens) and authorisation (Django permissions) for the
management endpoints.

Token format: ``mm_<prefix>_<secret>``. ``prefix`` (8 hex chars) is stored in
clear to find the row; only SHA-256(token) is stored, so a database leak does
not reveal usable tokens. Tokens carry 256 bits of randomness, so a fast hash
is appropriate (unlike passwords). Send them as ``Authorization: Bearer <token>``.

Every failure answers the same 401 message so responses cannot be used to
learn whether a prefix exists or a token was revoked; the specific reason is
logged server-side. The token itself is never logged.
"""

import hashlib
import hmac
import logging
import re
import secrets
from datetime import timedelta
from typing import Optional, Tuple

from django.utils import timezone
from rest_framework import exceptions, permissions
from rest_framework.authentication import BaseAuthentication, get_authorization_header

logger = logging.getLogger(__name__)

# Public format marker every token starts with; not a secret.
TOKEN_PREFIX = "mm"  # nosec B105
KEYWORD = "bearer"
GENERIC_FAILURE = "Invalid or expired API token."
# last_used_at is refreshed at most this often, to avoid a write per request.
LAST_USED_RESOLUTION = timedelta(seconds=60)
_TOKEN_FORMAT = re.compile(r"mm_([0-9a-f]{8})_([A-Za-z0-9_-]{43})")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> Tuple[str, str, str]:
    """Return (token, prefix, key_hash) for a new token."""
    prefix = secrets.token_hex(4)
    token = "{}_{}_{}".format(TOKEN_PREFIX, prefix, secrets.token_urlsafe(32))
    return token, prefix, hash_token(token)


def create_token(user, name: str, expires_in: Optional[timedelta] = None):
    """Create and store a token for ``user``; returns (ApiToken, token). Show the token once."""
    from middleman.models import ApiToken

    while True:
        token, prefix, key_hash = generate_token()
        if not ApiToken.objects.filter(prefix=prefix).exists():
            break
    expires_at = timezone.now() + expires_in if expires_in else None
    api_token = ApiToken.objects.create(
        user=user, name=name, prefix=prefix, key_hash=key_hash, expires_at=expires_at
    )
    logger.info(
        "[Auth] Created API token | user=%r name=%r prefix=%s expires_at=%s",
        user.get_username(), name, prefix, expires_at,
    )
    return api_token, token


def parse_token(token: str) -> Optional[str]:
    """Return the prefix of a well-formed token, else None."""
    match = _TOKEN_FORMAT.fullmatch(token)
    return match.group(1) if match else None


class ApiTokenAuthentication(BaseAuthentication):
    """``Authorization: Bearer mm_<prefix>_<secret>``."""

    def authenticate_header(self, request):
        # Makes DRF answer 401 (not 403) and tell clients how to authenticate.
        return 'Bearer realm="middleman"'

    def _fail(self, request, reason: str, prefix: Optional[str] = None):
        logger.warning(
            "[Auth] Rejected API token | reason=%s prefix=%s path=%r remote_addr=%s",
            reason, prefix, request.path, request.META.get("REMOTE_ADDR"),
        )
        raise exceptions.AuthenticationFailed(GENERIC_FAILURE)

    def authenticate(self, request):
        from middleman.models import ApiToken

        try:
            header = get_authorization_header(request).decode("ascii")
        except UnicodeDecodeError:
            self._fail(request, "non_ascii_header")
        parts = header.split()
        if not parts or parts[0].lower() != KEYWORD:
            return None  # not ours (no header, or another scheme such as Basic)
        if len(parts) != 2:
            self._fail(request, "malformed_header")

        token = parts[1]
        prefix = parse_token(token)
        if prefix is None:
            self._fail(request, "malformed_token")

        api_token = ApiToken.objects.select_related("user").filter(prefix=prefix).first()
        # Compare even when the prefix is unknown, so timing does not reveal it.
        expected = api_token.key_hash if api_token is not None else "0" * 64
        if not hmac.compare_digest(hash_token(token), expected) or api_token is None:
            self._fail(request, "unknown_token", prefix)
        if api_token.revoked_at is not None:
            self._fail(request, "revoked", prefix)
        now = timezone.now()
        if api_token.expires_at is not None and api_token.expires_at <= now:
            self._fail(request, "expired", prefix)
        if not api_token.user.is_active:
            self._fail(request, "inactive_user", prefix)

        if api_token.last_used_at is None or now - api_token.last_used_at >= LAST_USED_RESOLUTION:
            ApiToken.objects.filter(pk=api_token.pk).update(last_used_at=now)
        return api_token.user, api_token


class MethodPermissions(permissions.BasePermission):
    """
    Require Django model permissions per HTTP method. Subclasses set
    ``required = {"GET": ["app.perm"], ...}``; methods not listed are denied.
    """

    required = {}

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated):
            return False
        perms = self.required.get(request.method)
        if perms is None:
            # Methods the view does not implement must answer 405, not 403;
            # implemented but unlisted methods are denied.
            return not hasattr(view, request.method.lower())
        return user.has_perms(perms)


class RegistryPermissions(MethodPermissions):
    required = {
        "GET": ["middleman.view_accessentry"],
        "HEAD": ["middleman.view_accessentry"],
        "PATCH": ["middleman.change_accessentry"],
    }


class ClientPolicyPermissions(MethodPermissions):
    required = {
        "GET": ["middleman.view_clientpolicy"],
        "HEAD": ["middleman.view_clientpolicy"],
        "PATCH": ["middleman.change_clientpolicy", "middleman.add_clientpolicy"],
    }


class SettingsPermissions(MethodPermissions):
    """
    Runtime settings (allowed hosts): the dedicated permission per method AND
    an active staff account. Token or session; sessions are CSRF-protected.
    """

    required = {
        "GET": ["middleman.view_allowedhost"],
        "HEAD": ["middleman.view_allowedhost"],
        "POST": ["middleman.add_allowedhost"],
        "PATCH": ["middleman.change_allowedhost"],
        "DELETE": ["middleman.delete_allowedhost"],
    }

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated and user.is_active and user.is_staff):
            return False
        return super().has_permission(request, view)


class DashboardPermissions(permissions.BasePermission):
    """The page is public (aggregates only); each rule action needs its permission."""

    action_perms = {
        "create": "middleman.add_blacklistrule",
        "toggle": "middleman.change_blacklistrule",
        "delete": "middleman.delete_blacklistrule",
    }

    def has_permission(self, request, view):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        user = request.user
        if not (user and user.is_authenticated):
            return False
        perm = self.action_perms.get(request.data.get("action"))
        return perm is not None and user.has_perm(perm)


# Default roles, created after migrations (see apps.py).
ROLE_PERMISSIONS = {
    "proxy-auditor": [
        "view_accessentry", "view_blacklistrule", "view_clientpolicy", "view_abusesignal",
    ],
    "proxy-operator": [
        "view_accessentry", "change_accessentry",
        "view_blacklistrule", "add_blacklistrule", "change_blacklistrule", "delete_blacklistrule",
        "view_clientpolicy", "add_clientpolicy", "change_clientpolicy",
        "view_abusesignal",
    ],
    # Allowed hosts are security-critical: a separate role, not part of
    # proxy-operator. Its members must also be staff (see SettingsPermissions).
    "proxy-settings-admin": [
        "view_allowedhost", "add_allowedhost", "change_allowedhost", "delete_allowedhost",
    ],
}
