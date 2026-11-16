from django.contrib import admin, messages
from django.utils import timezone

from middleman.models import (AbuseSignal, AccessEntry, AllowedHost, ApiToken,
                              BlacklistRule, ClientPolicy)


@admin.register(AccessEntry)
class AccessEntryAdmin(admin.ModelAdmin):
    list_display = ("ip", "path", "already_requested", "max_requests", "created_at", "created_by_version")
    search_fields = ("ip", "path", "key")
    list_filter = ("created_at", "created_by_version")
    readonly_fields = ("created_by_version",)


@admin.register(BlacklistRule)
class BlacklistRuleAdmin(admin.ModelAdmin):
    list_display = ("rule_type", "value", "enabled", "validity", "created_at", "created_by_version")
    list_filter = ("rule_type", "enabled", "created_by_version", "created_at")
    search_fields = ("value",)
    readonly_fields = ("created_by_version",)

    @admin.display(description="Valid in this version")
    def validity(self, obj):
        error = obj.validation_error
        return "yes" if error is None else "no ({}): {}".format(error.reason, error.message)


@admin.register(ClientPolicy)
class ClientPolicyAdmin(admin.ModelAdmin):
    list_display = ("ip", "hide_rate_limit_headers", "source", "updated_by", "updated_at", "reason")
    list_filter = ("hide_rate_limit_headers", "source")
    search_fields = ("ip", "reason")
    readonly_fields = ("source", "updated_by", "created_at", "updated_at", "created_by_version")

    def save_model(self, request, obj, form, change):
        # An admin decision is final: abuse detection never overrides it.
        obj.source = ClientPolicy.Source.MANUAL
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(AbuseSignal)
class AbuseSignalAdmin(admin.ModelAdmin):
    """Read-only audit trail of what abuse detection saw."""

    list_display = ("ip", "kind", "count", "bucket", "fingerprint")
    list_filter = ("kind",)
    search_fields = ("ip",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ApiToken)
class ApiTokenAdmin(admin.ModelAdmin):
    """
    Tokens are created with `python manage.py create_api_token` (the secret is
    shown once and never stored), so they cannot be added here.
    """

    list_display = ("name", "user", "prefix", "created_at", "expires_at", "last_used_at", "revoked_at")
    list_filter = ("revoked_at",)
    search_fields = ("name", "prefix", "user__username")
    readonly_fields = ("user", "prefix", "created_at", "last_used_at", "created_by_version")
    fields = ("name", "user", "prefix", "expires_at", "revoked_at", "created_at", "last_used_at", "created_by_version")
    actions = ["revoke"]

    def has_add_permission(self, request):
        return False

    @admin.action(description="Revoke selected tokens", permissions=["change"])
    def revoke(self, request, queryset):
        updated = queryset.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())
        self.message_user(request, "Revoked {} token(s).".format(updated), messages.SUCCESS)


@admin.register(AllowedHost)
class AllowedHostAdmin(admin.ModelAdmin):
    """Runtime allowed hosts; values are validated (model.clean). The baseline is not listed here."""

    list_display = ("host", "note", "created_by", "created_at", "created_by_version")
    search_fields = ("host", "note")
    readonly_fields = ("created_by", "created_at", "updated_at", "created_by_version")

    def has_module_permission(self, request):
        return request.user.is_active and request.user.is_staff and super().has_module_permission(request)

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
