from utils.factories import AccessEntryModelFactory
from interfaces import RegistryInterface
from models import AccessEntry
from unittest import assertEqual
import pytest


class test_interfaces(unittest.TestCase):
    def setUp(self):
        self._interface = RegistryInterface()

    @pytest.mark.django_db
    def test_create_access_entry(self):
        self._interface.create_access_entry(
            AccessEntryModelFactory.key,
            AccessEntryModelFactory.ip,
            AccessEntryModelFactory.path,
            AccessEntryModelFactory.request,
            AccessEntryModelFactory.already_requested,
            AccessEntryModelFactory.max_requests,
            AccessEntryModelFactory.created_at,
        )

        assertEqual(1, AccessEntry.objects.count())

    @pytest.mark.django_db
    def test_get_access_entry(self):
        access_entry = AccessEntryModelFactory.create()
        self.assertEqual(
            self._interface.get_access_entry(access_entry.key), access_entry
        )

    @pytest.mark.django_db
    def test_get_all_access_entries(self):
        access_entry = AccessEntryModelFactory.create()
        self.assertEqual(self._interface.get_all_access_entries(), [access_entry])
        self.assertEqual(self._interface.get_all_access_entries().count(), 1)
