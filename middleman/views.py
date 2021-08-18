from django.http.response import HttpResponseBadRequest
from proxy.settings import BASE_TARGET_URL
from requests.models import Request
from rest_framework.views import APIView
from .services import ProxyManager
from django.http import StreamingHttpResponse
from .interfaces import RegistryInterface

import logging


logger = logging.getLogger(__name__)


class ProxyView(APIView):
    """
    Proxy view
    """

    def get(self, request: Request, path: str):
        base_url = BASE_TARGET_URL
        if path is None:
            logging.error('Missing path')
            return HttpResponseBadRequest('Path is required')

        if request.method == "GET":
            try:
                path = "{}/".format(path)
                target_url = "{}{}".format(base_url, path)
                proxy = ProxyManager(target_url)
                response = proxy.access_filter(
                    request,
                    path,
                )
                return StreamingHttpResponse(
                    response.raw,
                    content_type=response.headers.get('content-type'),
                    status=response.status_code,
                    reason=response.reason)
            except Exception:
                msg = 'Request failed'
                logger.exception(msg)
                return HttpResponseBadRequest(content=msg)

class RegistryView(APIView):
    """
    Registry view
    """
    paginate_by = 10

    def get_queryset(self):
        return RegistryInterface.get_all_access_entries()
