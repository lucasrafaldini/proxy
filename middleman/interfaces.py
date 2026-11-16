from django.db.models.query import QuerySet

from middleman.serializers import AccessEntrySerializer

from .models import AccessEntry


class RegistryInterface:
    """
    Data access for access entries. Lookups of unknown keys raise
    ``AccessEntry.DoesNotExist``; callers decide how to answer and log it.
    """

    def __init__(self):
        self.model = AccessEntry

    def create_access_entry(
        self,
        key: str,
        ip: str,
        path: str,
        already_requested: int = 0,
        max_requests: int = 100,
    ) -> AccessEntry:
        """Create a new access entry"""
        return self.model.objects.create(
            key=key,
            ip=ip,
            path=path,
            already_requested=already_requested,
            max_requests=max_requests,
        )

    def get_or_create_access_entry(self, key: str, ip: str, path: str) -> AccessEntry:
        """Entry for ``key``, created with defaults if missing (safe under concurrency)."""
        entry, _ = self.model.objects.get_or_create(key=key, defaults={"ip": ip, "path": path})
        return entry

    def get_access_entry(self, key: str) -> AccessEntry:
        """Get an access entry; raises AccessEntry.DoesNotExist."""
        return self.model.objects.get(key=key)

    def get_all_access_entries(self) -> QuerySet:
        """Get all access entries"""
        return self.model.objects.all().order_by("created_at")

    def _update(self, key: str, data: dict) -> AccessEntrySerializer:
        target_obj = self.model.objects.get(key=key)
        serializer = AccessEntrySerializer(target_obj, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
        return serializer

    def update_max_requests(self, key: str, max_requests: int) -> AccessEntrySerializer:
        """
        Update max_requests. Returns the serializer (check ``.errors``);
        raises AccessEntry.DoesNotExist.
        """
        return self._update(key, {"max_requests": max_requests})

    def reset_already_requested(self, key: str) -> AccessEntrySerializer:
        """
        Reset already_requested to 0. Returns the serializer (check
        ``.errors``); raises AccessEntry.DoesNotExist.
        """
        return self._update(key, {"already_requested": 0})
