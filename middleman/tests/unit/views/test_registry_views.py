from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from middleman.models import AccessEntry
from middleman.tests.utils.factories.access_entry import \
    AccessEntryModelFactory
from middleman.views import RegistryView

# class ProxyViewTest(TestCase):
#     """Unit tests for the proxy view."""

#     def setUp(self):
#         """Set up the tests."""
#         self.client = APIClient()

#     def test_proxy_view(self):
#         """Test the proxy view."""

#         response = self.client.get("index/")
#         self.assertEqual(response.status_code, 200)


class RegistryViewTest(TestCase):
    """Unit tests for the registry view."""

    def setUp(self):
        """Set up the tests."""
        self.client = APIClient()

    def test_registry_view_get_all_entries(self):
        """Test the registry view to get all entries"""

        (
            first_entry,
            second_entry,
        ) = AccessEntryModelFactory.create(), AccessEntryModelFactory.create(
            key="example_key"
        )
        url = reverse("registry")
        response = self.client.get(url)
        data = response.json()
        self.assertEqual(first_entry.key, data[0]["key"])
        self.assertEqual(second_entry.key, data[1]["key"])
        self.assertEqual(response.status_code, 200)

    def test_registry_view_get_one_entry(self):
        """Test the registry view to get one entry"""

        single_entry = AccessEntryModelFactory.create(key="totally_foced_key")
        url = reverse("registry")
        response = self.client.get(url, data={"key": single_entry.key})
        data = response.json()
        self.assertEqual(single_entry.key, data[0]["key"])
        self.assertEqual(response.status_code, 200)

    def test_registry_view_update_max_requests(self):
        """Test patch registry view to update max requests"""

        single_entry = AccessEntryModelFactory.create(max_requests=3)
        url = reverse("registry")
        response = self.client.patch(
            url,
            data={
                "key": single_entry.key,
                "action": "update_max_requests",
                "max_requests": 100,
            },
        )
        data = response.json()

        updated_object = AccessEntry.objects.get(key=single_entry.key)

        self.assertEqual(updated_object.max_requests, 100)
        self.assertEqual(single_entry.key, data["key"])
        self.assertTrue(single_entry.max_requests != data["max_requests"])
        self.assertEqual(response.status_code, 200)

    def test_registry_view_reset_already_requested(self):
        """Test patch registry view to update already requested"""

        single_entry = AccessEntryModelFactory.create(already_requested=99)
        url = reverse("registry")
        response = self.client.patch(
            url,
            data={
                "key": single_entry.key,
                "action": "reset_already_requested",
            },
        )
        data = response.json()

        updated_object = AccessEntry.objects.get(key=single_entry.key)

        self.assertEqual(updated_object.already_requested, 0)
        self.assertEqual(single_entry.key, data["key"])
        self.assertTrue(single_entry.already_requested != data["already_requested"])
        self.assertEqual(response.status_code, 200)
