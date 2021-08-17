import requests
from requests.models import Response
import logging
from django.db import transaction
from .interfaces import RegistryInterface
from .exceptions import (
    ServerNotRespondingException,
    ExceededRequestsLimitException,
    AccessNotRegisteredException,
)


logger = logging.getLogger(__name__)


class ProxyManager:

    def __init__(self, url: str):
        self.url = url

    def _create_unique_key(self, ip, path) -> str:
        """Create a unique key for the access entry"""
        return f'{hash("{}@{}".format(ip, path) % 10**8)}'

    def do_request(self) -> Response or None:
        """Make request to the server"""

        try:
            # Just checking if the server is up
            response = requests.head(self.url)
            if response.status_code == 200:
                logger.info(
                    "[ProxyManager] Successfully connected to {}".format(self.url)
                )
                return requests.get(self.url, stream=True)
            else:
                logger.error(
                    "[ProxyManager] Server returned {}".format(response.status_code)
                )
                return None
        except Exception:
            msg = "Server not responding"
            logger.exception(msg)
            raise ServerNotRespondingException(self.url)

    def access_filter(self, ip: str, path: str, request: dict) -> bool:
        """Filter access to endpoints by IP and path"""

        key = self._create_unique_key(ip, path)
        if self.objects.filter(key=key).exists():
            register = self.objects.get(key=key)
            if register.already_requested >= register.max_requests:
                raise ExceededRequestsLimitException
            try:
                response = self.do_request()
                with transaction.atomic():
                    register.already_requested += 1
                    register.save()
                return response
            except Exception:
                raise ExceededRequestsLimitException
        else:
            try:
                response = self.do_request()
                key = self._create_unique_key(ip, path)
                RegistryInterface.create_access_entry(key, ip, path, request)
                return response
            except Exception:
                msg = "Access not registered"
                logger.exception("[ProxyManager] {}".format(msg))
                raise AccessNotRegisteredException(key, ip, path)
