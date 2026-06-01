import pytest
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from unittest.mock import patch
from django.http import HttpResponse

from middleman.tests.utils.factories.access_entry import AccessEntryModelFactory


class DashboardViewsTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    @pytest.mark.django_db
    def test_dashboard_view_renders(self):
        AccessEntryModelFactory.create()

        with patch("middleman.views.render", return_value=HttpResponse("ok")):
            response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)

    @pytest.mark.django_db
    def test_insights_view_returns_summary(self):
        AccessEntryModelFactory.create()
        AccessEntryModelFactory.create(path="admin/")

        response = self.client.get(reverse("insights"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["total_entries"], 2)
        self.assertEqual(response.data["unique_paths"], 2)
        self.assertEqual(response.data["blocked_entries"], 0)