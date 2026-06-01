import logging

import requests
from django.db import transaction
from requests.models import Request, Response

from middleman.models import AccessEntry, BlacklistRule
from proxy.settings import BLACKLISTED_IPS, BLACKLISTED_PATHS

from .exceptions import (AccessNotRegisteredException,
                         BlacklistedAccessException,
                         ExceededRequestsLimitException,
                         ServerNotRespondingException)
from .interfaces import RegistryInterface

logger = logging.getLogger(__name__)
REQUEST_TIMEOUT = 10


class ProxyManager:
    def __init__(self, url: str):
        self.url = url
        self.model = AccessEntry

    def _create_unique_key(self, ip: str, path: str) -> str:
        """Create a unique key for the access entry"""
        return "{}".format(hash("{}@{}".format(ip, path)) % 10 ** 20)

    def _get_user_ip(self, request: Request):
        """Get the user IP from the request"""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")

    def _matches_rule(self, value: str, rule: str) -> bool:
        """Match exact rules and simple wildcard suffix rules."""
        if rule.endswith("*"):
            return value.startswith(rule[:-1])
        return value == rule

    def _is_blacklisted(self, ip: str, path: str):
        for rule in BLACKLISTED_IPS:
            if self._matches_rule(ip, rule):
                return "ip", rule
        for rule in BLACKLISTED_PATHS:
            if self._matches_rule(path, rule):
                return "path", rule
        for rule in BlacklistRule.objects.filter(enabled=True):
            if rule.rule_type == "ip" and self._matches_rule(ip, rule.value):
                return "ip", rule.value
            if rule.rule_type == "path" and self._matches_rule(path, rule.value):
                return "path", rule.value
        return None

    def do_request(self) -> Response or None:
        """Make request to server"""

        try:
            # Just checking if the server is up
            response = requests.head(self.url, timeout=REQUEST_TIMEOUT)
            logger.info("[ProxyManager] Server is up")
            if response.status_code == 200:
                logger.info(
                    "[ProxyManager] Successfully connected to {}".format(self.url)
                )
                return requests.get(self.url, stream=True, timeout=REQUEST_TIMEOUT)
            else:
                logger.error(
                    "[ProxyManager] Server returned {}".format(response.status_code)
                )
                return None
        except Exception:
            msg = "Server not responding"
            logger.exception(msg)
            raise ServerNotRespondingException(self.url)

    def access_filter(self, request: Request, path: str):
        """Filter access to endpoints by IP and path"""

        ip = self._get_user_ip(request)
        blacklist_match = self._is_blacklisted(ip, path)
        if blacklist_match is not None:
            rule_type, rule_value = blacklist_match
            raise BlacklistedAccessException(ip, path, rule_type, rule_value)

        key = self._create_unique_key(ip, path)
        if self.model.objects.filter(key=key).exists():
            register = self.model.objects.get(key=key)
            if register.already_requested >= register.max_requests:
                raise ExceededRequestsLimitException(ip, path)
            try:
                response = self.do_request()
                with transaction.atomic():
                    register.already_requested += 1
                    register.save()
                return response
            except Exception as e:
                logger.exception(e.msg)
                raise e
        else:
            try:
                response = self.do_request()
                key = self._create_unique_key(ip, path)
                interface = RegistryInterface()
                interface.create_access_entry(key, ip, path)
                return response
            except Exception:
                msg = "Access not registered"
                logger.exception("[ProxyManager] {}".format(msg))
                raise AccessNotRegisteredException(key, ip, path)
