from unittest.mock import Mock, patch

import pytest
import requests
from django.test import override_settings
from django.test.client import RequestFactory

from middleman.exceptions import (AccessNotRegisteredException,
                                  ServerNotRespondingException,
                                  UpstreamStatusException)
from middleman.models import AccessEntry
from middleman.services import ProxyManager


class TestProxyManagerBranches:
    def setup_method(self):
        self.proxy_manager = ProxyManager("https://example.com/index/")
        self.request_factory = RequestFactory()

    @override_settings(TRUSTED_PROXIES=["127.0.0.1"])
    def test_get_user_ip_uses_forwarded_for_from_trusted_proxy(self):
        request = self.request_factory.get("/", HTTP_X_FORWARDED_FOR="10.10.10.1, 127.0.0.1")
        assert self.proxy_manager._get_user_ip(request) == "10.10.10.1"

    def test_get_user_ip_ignores_forwarded_for_from_untrusted_peer(self):
        # Anyone can send this header; without TRUSTED_PROXIES it is spoofable.
        request = self.request_factory.get("/", HTTP_X_FORWARDED_FOR="10.10.10.1")
        assert self.proxy_manager._get_user_ip(request) == "127.0.0.1"

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
    def test_do_request_non_200_raises_upstream_status(self, mock_head):
        # Used to return None, which crashed the view with an AttributeError.
        mock_head.return_value = Mock(status_code=503)
        with pytest.raises(UpstreamStatusException) as exc_info:
            self.proxy_manager.do_request()
        assert exc_info.value.status_code == 503

    @patch("middleman.services.requests.head", side_effect=requests.ConnectionError("refused"))
    def test_do_request_raises_not_responding(self, _mock_head):
        with pytest.raises(ServerNotRespondingException):
            self.proxy_manager.do_request()

    @patch("middleman.services.requests.head", side_effect=KeyError("bug"))
    def test_do_request_does_not_disguise_programming_errors(self, _mock_head):
        # Only network errors mean "target not responding"; bugs must surface (500).
        with pytest.raises(KeyError):
            self.proxy_manager.do_request()

    @pytest.mark.django_db
    def test_access_filter_creates_new_entry(self):
        request = self.request_factory.get("/")

        with patch.object(self.proxy_manager, "_get_user_ip", return_value="1.1.1.1"):
            with patch.object(self.proxy_manager, "_create_unique_key", return_value="sample_key_12345"):
                with patch.object(self.proxy_manager, "do_request", return_value=Mock(status_code=200)):
                    response = self.proxy_manager.access_filter(request, "index/")

        assert response.status_code == 200
        entry = AccessEntry.objects.get(key="sample_key_12345")
        assert (entry.ip, entry.path, entry.already_requested) == ("1.1.1.1", "index/", 1)

    @pytest.mark.django_db
    @patch("middleman.services.RegistryInterface.get_or_create_access_entry", side_effect=RuntimeError("db down"))
    def test_access_filter_raises_access_not_registered(self, _mock_create):
        request = self.request_factory.get("/")

        with patch.object(self.proxy_manager, "_get_user_ip", return_value="2.2.2.2"):
            with patch.object(self.proxy_manager, "_create_unique_key", return_value="sample_key_67890"):
                with patch.object(self.proxy_manager, "do_request", return_value=Mock(status_code=200)):
                    with pytest.raises(AccessNotRegisteredException):
                        self.proxy_manager.access_filter(request, "index/")
