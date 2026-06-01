from django.contrib import admin

from middleman.models import AccessEntry, BlacklistRule


@admin.register(AccessEntry)
class AccessEntryAdmin(admin.ModelAdmin):
	list_display = ("ip", "path", "already_requested", "max_requests", "created_at")
	search_fields = ("ip", "path", "key")
	list_filter = ("created_at",)


@admin.register(BlacklistRule)
class BlacklistRuleAdmin(admin.ModelAdmin):
	list_display = ("rule_type", "value", "enabled", "created_at")
	list_filter = ("rule_type", "enabled", "created_at")
	search_fields = ("value",)
