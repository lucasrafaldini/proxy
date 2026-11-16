from django.test import TestCase
from django.urls import reverse

from middleman.models import AccessEntry
from middleman.tests.utils.auth import logged_in_client
from middleman.tests.utils.factories.access_entry import \
    AccessEntryModelFactory


class RegistryViewTest(TestCase):
    """Unit tests for the registry view."""

    def setUp(self):
        """Set up the tests."""
        self.client = logged_in_client()  # operator: may view/change entries

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
        AccessEntryModelFactory.create()  # must not be returned
        response = self.client.get(url, data={"key": single_entry.key})
        data = response.json()
        # Used to pass by accident: ?key= was ignored and the whole list came back.
        self.assertEqual(single_entry.key, data["key"])
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


class RegistryViewErrorTest(TestCase):
    """Unknown keys are 404, bad input is 400, and the log says what happened."""

    def setUp(self):
        self.client = logged_in_client()  # operator: may view/change entries
        self.url = reverse("registry")
        self.entry = AccessEntryModelFactory.create(key="known", max_requests=10)

    def test_get_unknown_key_is_404(self):
        with self.assertLogs("middleman.views", "INFO") as logs:
            response = self.client.get(self.url, {"key": "nope"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "Access entry 'nope' not found."})
        self.assertEqual(logs.output, ["INFO:middleman.views:[RegistryView] Access entry not found | key='nope'"])

    def test_get_with_key_in_body_still_works(self):
        response = self.client.generic("GET", self.url, '{"key": "known"}', content_type="application/json")
        self.assertEqual(response.json()["key"], "known")

    def test_get_with_body_but_no_key_is_400(self):
        response = self.client.generic("GET", self.url, '{"other": 1}', content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_patch_missing_fields_is_400_naming_them(self):
        with self.assertLogs("middleman.views", "INFO") as logs:
            response = self.client.patch(self.url, {}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"detail": "Missing required field(s): key, action."})
        self.assertIn("missing=['key', 'action']", logs.output[0])

    def test_patch_unknown_key_is_404(self):
        for action in ["reset_already_requested", "update_max_requests"]:
            with self.subTest(action=action):
                response = self.client.patch(
                    self.url, {"key": "nope", "action": action, "max_requests": 5}, format="json"
                )
                self.assertEqual(response.status_code, 404)

    def test_patch_invalid_max_requests_is_400_and_not_saved(self):
        # Used to answer 200, echo "abc" back and log "successful".
        with self.assertLogs("middleman.views", "INFO") as logs:
            response = self.client.patch(
                self.url, {"key": "known", "action": "update_max_requests", "max_requests": "abc"}, format="json"
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("max_requests", response.json())
        self.entry.refresh_from_db()
        self.assertEqual(self.entry.max_requests, 10)
        self.assertIn("Rejected PATCH: invalid value", logs.output[0])
        self.assertNotIn("successful", logs.output[0])

    def test_patch_unknown_action_is_400(self):
        response = self.client.patch(self.url, {"key": "known", "action": "explode"}, format="json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("explode", response.json()["detail"])

    def test_successful_patch_is_logged_with_resulting_values(self):
        with self.assertLogs("middleman.views", "INFO") as logs:
            self.client.patch(
                self.url, {"key": "known", "action": "update_max_requests", "max_requests": 42}, format="json"
            )
        self.assertIn("Applied update_max_requests | key='known'", logs.output[0])
        self.assertIn("max_requests=42", logs.output[0])

    def test_validation_errors_are_logged_readably(self):
        with self.assertLogs("middleman.views", "INFO") as logs:
            self.client.patch(
                self.url, {"key": "known", "action": "update_max_requests", "max_requests": "abc"}, format="json"
            )
        self.assertIn("errors={'max_requests': ['A valid integer is required.']}", logs.output[0])
        self.assertNotIn("ErrorDetail", logs.output[0])
