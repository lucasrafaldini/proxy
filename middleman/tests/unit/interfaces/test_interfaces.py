from middleman.tests.utils.factories.access_entry import AccessEntryModelFactory
from middleman.interfaces import RegistryInterface
from middleman.models import AccessEntry
import unittest
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
            AccessEntryModelFactory.already_requested,
            AccessEntryModelFactory.max_requests,
        )

        self.assertEqual(1, AccessEntry.objects.count())

        created_object = AccessEntry.objects.get(key=AccessEntryModelFactory.key)
        self.assertTrue(created_object)
        self.assertTrue(
            [
                created_object.ip,
                created_object.path,
                created_object.already_requested,
                created_object.max_requests,
            ]
            == [
                AccessEntryModelFactory.ip,
                AccessEntryModelFactory.path,
                AccessEntryModelFactory.already_requested,
                AccessEntryModelFactory.max_requests,
            ]
        )

    @pytest.mark.django_db
    def test_get_access_entry(self):
        access_entry = AccessEntryModelFactory.create()
        self.assertEqual(
            self._interface.get_access_entry(access_entry.key), access_entry
        )

    @pytest.mark.django_db
    def test_get_all_access_entries(self):
        access_entry = AccessEntryModelFactory.create()
        self.assertEqual(
            self._interface.get_all_access_entries()[0].key, access_entry.key
        )
        self.assertEqual(self._interface.get_all_access_entries().count(), 1)

    @pytest.mark.django_db
    def test_update_max_requests(self):
        access_entry = AccessEntryModelFactory.create()
        self._interface.update_max_requests(
            access_entry.key, access_entry.max_requests + 1
        )
        self.assertEqual(
            self._interface.get_access_entry(access_entry.key).max_requests,
            access_entry.max_requests + 1,
        )

    @pytest.mark.django_db
    def test_reset_max_requests(self):
        access_entry = AccessEntryModelFactory.create()
        self._interface.reset_already_requested(access_entry.key)
        self.assertEqual(
            self._interface.get_access_entry(access_entry.key).already_requested, 0
        )
