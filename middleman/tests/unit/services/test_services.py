from unittest.mock import patch

from middleman.services import ProxyManager
from proxy.settings import BASE_TARGET_URL
from middleman.tests.utils.factories.access_entry import AccessEntryModelFactory
from middleman.tests.utils.mocked_requests import mock_api_requests
from middleman.exceptions import ExceededRequestsLimitException
from django.test.client import RequestFactory
import unittest
import pytest


class test_proxy_manager(unittest.TestCase):
    def setUp(self):
        self.base_url = BASE_TARGET_URL
        self.path = "index/"
        self.target_url = "{}{}".format(self.base_url, self.path)
        self.proxy_manager = ProxyManager(self.target_url)
        self.request = RequestFactory()

    @pytest.mark.django_db
    def test_create_unique_key(self):
        access_entry = AccessEntryModelFactory.create()
        key = self.proxy_manager._create_unique_key(access_entry.ip, access_entry.path)
        self.assertTrue(len(key) <= 20)
        self.assertEqual(key, access_entry.key)

    # def test_do_request(self):

    @patch("requests.get", side_effect=mock_api_requests(200))
    @patch("requests.head", side_effect=mock_api_requests(200))
    @pytest.mark.django_db
    def test_access_filter_pass(self, mock_get, mock_head):
        access_entry = AccessEntryModelFactory.create()

        with patch(
            "middleman.services.ProxyManager._create_unique_key",
            return_value=access_entry.key,
        ) as _create_unique_key:
            with patch(
                "middleman.services.ProxyManager._get_user_ip",
                return_value=access_entry.ip,
            ) as _get_user_ip:
                with patch("middleman.services.ProxyManager.do_request") as do_request:
                    self.proxy_manager.access_filter(
                        self.request.get("{}".format(self.target_url)),
                        access_entry.path,
                    )
                    _create_unique_key.assert_called()
                    _get_user_ip.assert_called()
                    do_request.assert_called()

    @pytest.mark.django_db
    def test_access_filter_block(self):
        access_entry = AccessEntryModelFactory.create(already_requested=100)

        with patch(
            "middleman.services.ProxyManager._create_unique_key",
            return_value=access_entry.key,
        ) as _create_unique_key:
            with patch(
                "middleman.services.ProxyManager._get_user_ip",
                return_value=access_entry.ip,
            ) as _get_user_ip:
                with patch("middleman.services.ProxyManager.do_request") as do_request:
                    with self.failUnlessRaises(ExceededRequestsLimitException):
                        self.proxy_manager.access_filter(
                            self.request.get("{}".format(self.target_url)),
                            access_entry.path,
                        )
                        _create_unique_key.assert_called()
                        _get_user_ip.assert_called()
                        do_request.assert_not_called()
