import os
import random

import pytest
import requests
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from middleman.models import AccessEntry
from middleman.tests.utils.factories.access_entry import \
    AccessEntryModelFactory


class ProxyViewTest(TestCase):
    """Unit tests for the proxy view."""

    def setUp(self):
        """Set up the tests."""

        self.client = APIClient()
        # Just a placeholder url for testing purposes
        self.base_url = os.environ["BASE_TARGET_URL"]
        self.paths = ["100", "200", "300", "400", "500"]

    def test_proxy_view(self):
        """Test proxy view"""

        url = "{}".format(reverse("proxy", kwargs={"path": self.paths[0]}))
        proxy_response = self.client.get(url)

        original_response = requests.get("{}{}".format(self.base_url, self.paths[0]))

        self.assertEqual(proxy_response.status_code, 200)
        self.assertEqual(proxy_response.status_code, original_response.status_code)
        self.assertEqual(proxy_response.reason_phrase, original_response.reason)
        self.assertTrue(proxy_response.streaming)
