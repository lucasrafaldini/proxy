from django.test import TestCase
from django.urls import reverse
from django.http import HttpResponse
from rest_framework.test import APIClient
from unittest.mock import patch

from middleman.models import BlacklistRule


class BlacklistViewsTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_can_create_blacklist_rule_from_dashboard(self):
        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            response = self.client.post(
                reverse("dashboard"),
                data={"action": "create", "rule_type": "path", "value": "admin/*"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(BlacklistRule.objects.count(), 1)
        rule = BlacklistRule.objects.first()
        self.assertEqual(rule.rule_type, "path")
        self.assertEqual(rule.value, "admin/*")

    def test_can_toggle_and_delete_blacklist_rule(self):
        rule = BlacklistRule.objects.create(rule_type="ip", value="10.0.0.*")

        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            toggle_response = self.client.post(
                reverse("dashboard"),
                data={"action": "toggle", "rule_id": rule.id},
            )
        self.assertEqual(toggle_response.status_code, 200)
        rule.refresh_from_db()
        self.assertFalse(rule.enabled)

        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            delete_response = self.client.post(
                reverse("dashboard"),
                data={"action": "delete", "rule_id": rule.id},
            )
        self.assertEqual(delete_response.status_code, 200)
        self.assertEqual(BlacklistRule.objects.count(), 0)