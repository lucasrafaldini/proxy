from unittest.mock import Mock, patch

import pytest
from django.test.client import RequestFactory

from middleman.exceptions import AccessNotRegisteredException, ServerNotRespondingException
from middleman.services import ProxyManager
from middleman.tests.utils.factories.access_entry import AccessEntryModelFactory


class TestProxyManagerBranches:
    def setup_method(self):
        self.proxy_manager = ProxyManager("https://example.com/index/")
        self.request_factory = RequestFactory()

    def test_get_user_ip_prefers_forwarded_for(self):
        request = self.request_factory.get("/", HTTP_X_FORWARDED_FOR="10.10.10.1, 127.0.0.1")
        assert self.proxy_manager._get_user_ip(request) == "10.10.10.1"

    def test_get_user_ip_fallbacks_remote_addr(self):
        request = self.request_factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.10"
        assert self.proxy_manager._get_user_ip(request) == "127.0.0.10"

    def test_matches_rule_exact_and_wildcard(self):
        assert self.proxy_manager._matches_rule("admin/index", "admin/*") is True
        assert self.proxy_manager._matches_rule("admin/index", "admin/index") is True
        assert self.proxy_manager._matches_rule("admin/index", "ops/*") is False

    @patch("middleman.services.requests.get")
    @patch("middleman.services.requests.head")
    def test_do_request_success(self, mock_head, mock_get):
        mock_head.return_value = Mock(status_code=200)
        mock_get.return_value = Mock(status_code=200)

        response = self.proxy_manager.do_request()

        assert response.status_code == 200
        mock_head.assert_called_once()
        mock_get.assert_called_once()

    @patch("middleman.services.requests.head")
    def test_do_request_non_200_returns_none(self, mock_head):
        mock_head.return_value = Mock(status_code=503)
        assert self.proxy_manager.do_request() is None

    @patch("middleman.services.requests.head", side_effect=Exception("boom"))
    def test_do_request_raises_not_responding(self, _mock_head):
        with pytest.raises(ServerNotRespondingException):
            self.proxy_manager.do_request()

    @pytest.mark.django_db
    @patch("middleman.services.RegistryInterface.create_access_entry")
    def test_access_filter_creates_new_entry(self, mock_create_access_entry):
        request = self.request_factory.get("/")

        with patch.object(self.proxy_manager, "_get_user_ip", return_value="1.1.1.1"):
            with patch.object(self.proxy_manager, "_create_unique_key", return_value="12345678901234567890"):
                with patch.object(self.proxy_manager, "do_request", return_value=Mock(status_code=200)):
                    response = self.proxy_manager.access_filter(request, "index/")

        assert response.status_code == 200
        mock_create_access_entry.assert_called_once()

    @pytest.mark.django_db
    def test_access_filter_raises_access_not_registered(self):
        request = self.request_factory.get("/")

        with patch.object(self.proxy_manager, "_get_user_ip", return_value="2.2.2.2"):
            with patch.object(self.proxy_manager, "_create_unique_key", return_value="22345678901234567890"):
                with patch.object(self.proxy_manager, "do_request", side_effect=Exception("boom")):
                    with pytest.raises(AccessNotRegisteredException):
                        self.proxy_manager.access_filter(request, "index/")
