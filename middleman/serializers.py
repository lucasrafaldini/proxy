from rest_framework import serializers

from middleman.models import AccessEntry


class AccessEntrySerializer(serializers.ModelSerializer):
    """A serializer class for the AccessEntry model"""

    class Meta:
        model = AccessEntry
        fields = (
            "key",
            "ip",
            "path",
            "already_requested",
            "max_requests",
            "created_at",
            "created_by_version",
        )
        read_only_fields = ("created_by_version",)
