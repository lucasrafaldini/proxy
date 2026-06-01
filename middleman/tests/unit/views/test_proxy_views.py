import os
import io
from unittest.mock import patch

import pytest
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

class ProxyViewTest(TestCase):
    """Unit tests for the proxy view."""

    def setUp(self):
        """Set up the tests."""

        self.client = APIClient()
        # Just a placeholder url for testing purposes
        self.base_url = os.environ.get("BASE_TARGET_URL", "https://httpstatuses.com/")
        self.paths = ["100", "200", "300", "400", "500"]

    @patch("middleman.views.ProxyManager.access_filter")
    def test_proxy_view(self, mock_access_filter):
        """Test proxy view"""

        class FakeResponse:
            status_code = 200
            reason = "OK"
            headers = {"content-type": "application/json"}
            raw = io.BytesIO(b'{"ok": true}')

        mock_access_filter.return_value = FakeResponse()

        url = "{}".format(reverse("proxy", kwargs={"path": self.paths[0]}))
        proxy_response = self.client.get(url)

        self.assertEqual(proxy_response.status_code, 200)
        self.assertTrue(proxy_response.streaming)
        mock_access_filter.assert_called()
