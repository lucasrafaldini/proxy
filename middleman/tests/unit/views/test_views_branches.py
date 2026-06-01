from unittest.mock import patch

from django.urls import reverse
from rest_framework.test import APIClient

from middleman.exceptions import BlacklistedAccessException


class TestViewsBranches:
    def setup_method(self):
        self.client = APIClient()

    @patch("middleman.views.ProxyManager.access_filter", side_effect=BlacklistedAccessException("1.1.1.1", "admin/", "path", "admin/*"))
    def test_proxy_view_returns_403_for_blacklisted(self, _mock_access_filter):
        response = self.client.get(reverse("proxy", kwargs={"path": "admin"}))
        assert response.status_code == 403

    @patch("middleman.views.ProxyManager.access_filter", side_effect=Exception("boom"))
    def test_proxy_view_returns_400_on_unexpected_error(self, _mock_access_filter):
        response = self.client.get(reverse("proxy", kwargs={"path": "admin"}))
        assert response.status_code == 400

    def test_registry_patch_missing_max_requests_returns_400(self):
        response = self.client.patch(
            reverse("registry"),
            data={"key": "abc", "action": "update_max_requests"},
            format="json",
        )
        assert response.status_code == 400

    def test_registry_patch_invalid_action_returns_400(self):
        response = self.client.patch(
            reverse("registry"),
            data={"key": "abc", "action": "invalid_action"},
            format="json",
        )
        assert response.status_code == 400
