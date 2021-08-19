import logging

from django.db.models.query import QuerySet

from middleman.serializers import AccessEntrySerializer

from .models import AccessEntry

logger = logging.getLogger(__name__)


class RegistryInterface:
    """Interface to create new access registers"""

    def __init__(self):
        """Initialize the interface"""
        self.model = AccessEntry

    def create_access_entry(
        self,
        key: str,
        ip: str,
        path: str,
        already_requested: int = 0,
        max_requests: int = 100,
    ) -> None:
        """Create a new access entry"""
        self.model.objects.create(
            key=key,
            ip=ip,
            path=path,
            already_requested=already_requested,
            max_requests=max_requests,
        )

    def get_access_entry(self, key) -> AccessEntry:
        """Get an access entry"""
        try:
            return self.model.objects.get(key=key)
        except AccessEntry.DoesNotExist:
            logger.exception("Access entry does not exist")
            raise AccessEntry.DoesNotExist

    def get_all_access_entries(self) -> QuerySet:
        """Get all access entries"""
        return self.model.objects.all().order_by("created_at")

    def update_max_requests(
        self, key: str, max_requests: int
    ) -> AccessEntry or AccessEntry.DoesNotExist:
        """Update the max requests of an access entry"""
        try:
            target_obj = self.model.objects.get(key=key)
            serializer_class = AccessEntrySerializer(
                target_obj, data={"max_requests": max_requests}, partial=True
            )
            if serializer_class.is_valid():
                serializer_class.save()
            return serializer_class
        except AccessEntry.DoesNotExist:
            logger.exception("Access entry does not exist")
            raise AccessEntry.DoesNotExist

    def reset_already_requested(
        self, key: str
    ) -> AccessEntry or AccessEntry.DoesNotExist:
        """Reset the already requested flag of an access entry"""
        try:
            target_obj = self.model.objects.get(key=key)
            serializer_class = AccessEntrySerializer(
                target_obj, data={"already_requested": 0}, partial=True
            )
            if serializer_class.is_valid():
                serializer_class.save()
            return serializer_class
        except AccessEntry.DoesNotExist:
            logger.exception("Access entry does not exist")
            raise AccessEntry.DoesNotExist
