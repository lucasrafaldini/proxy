import logging

from django.apps import AppConfig
from django.db.models.signals import post_delete, post_migrate, post_save

logger = logging.getLogger(__name__)


def ensure_default_roles(sender, using="default", **kwargs):
    """
    Create the default groups with their permissions (see auth.ROLE_PERMISSIONS).
    Runs after migrations, when permissions exist. Idempotent; permissions
    added by hand to the groups are kept.
    """
    from django.contrib.auth.models import Group, Permission

    from middleman.auth import ROLE_PERMISSIONS

    for role, codenames in ROLE_PERMISSIONS.items():
        group, _ = Group.objects.using(using).get_or_create(name=role)
        perms = Permission.objects.using(using).filter(
            content_type__app_label="middleman", codename__in=codenames
        )
        missing = set(codenames) - set(perms.values_list("codename", flat=True))
        if missing:
            logger.error("[Roles] Permissions not found for role | role=%s missing=%s", role, sorted(missing))
        group.permissions.add(*perms)


def _loggable_username(username):
    """
    The username if it is an existing account, else a placeholder: people
    sometimes type their password into the username field, and a failed
    attempt must never write it to the logs.
    """
    from django.contrib.auth import get_user_model

    if username and get_user_model().objects.filter(username=username).exists():
        return username
    return "<not an account>"


def axes_username(request, credentials):
    """AXES_USERNAME_CALLABLE: axes stores usernames too; same protection as the logs."""
    from django.conf import settings

    field = getattr(settings, "AXES_USERNAME_FORM_FIELD", "username")
    raw = (credentials or {}).get(field) or request.POST.get(field)
    return _loggable_username(raw)


def report_login_failure(sender, credentials=None, request=None, **kwargs):
    """Failed password logins feed abuse detection (axes does the lockout)."""
    if request is None:
        return
    from middleman import abuse
    from middleman.client_ip import get_client_ip

    ip = get_client_ip(request.META)
    logger.warning(
        "[AdminLogin] Failed login | ip=%s username=%r path=%r",
        ip, _loggable_username((credentials or {}).get("username")), request.path,
    )
    abuse.report(ip, [("login_failure", "")])


def report_lockout(sender, request=None, username=None, ip_address=None, **kwargs):
    logger.warning(
        "[AdminLogin] Client locked out after too many failed logins | ip=%s username=%r",
        ip_address, _loggable_username(username),
    )


class MiddlemanConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "middleman"

    def ready(self):
        from axes.signals import user_locked_out
        from django.conf import settings
        from django.contrib.auth.signals import user_login_failed

        from middleman.abuse import get_config
        from middleman.client_ip import trusted_networks
        from middleman.hosts import check_middleware_order, invalidate_cache

        # Fail at startup, not on the first request, on security misconfiguration.
        trusted_networks()
        get_config()
        check_middleware_order(settings.MIDDLEWARE)
        if settings.DEBUG:
            logger.warning(
                "[Settings] DEBUG mode is ON (explicitly enabled): error pages show settings "
                "and stack traces. Never run with DEBUG in production."
            )

        post_migrate.connect(ensure_default_roles, sender=self)
        user_login_failed.connect(report_login_failure, dispatch_uid="middleman_login_failure")
        user_locked_out.connect(report_lockout, dispatch_uid="middleman_lockout")
        post_save.connect(invalidate_cache, sender="middleman.AllowedHost", dispatch_uid="allowed_host_saved")
        post_delete.connect(invalidate_cache, sender="middleman.AllowedHost", dispatch_uid="allowed_host_deleted")
