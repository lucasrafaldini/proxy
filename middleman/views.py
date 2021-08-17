from django.http.response import HttpResponseBadRequest
from proxy.settings import BASE_TARGET_URL
from requests.models import Request
from rest_framework.views import APIView, ListAPIView
from .services import ProxyManager
from django.http import StreamingHttpResponse
from .interfaces import RegistryInterface

import logging


logger = logging.getLogger(__name__)


class ProxyView(APIView):
    """
    Proxy view
    """

    def get(self, request: Request) -> StreamingHttpResponse:
        base_url = BASE_TARGET_URL
        url = request.GET['url']
        if request.method == 'GET' and url in base_url:
            try:
                proxy = ProxyManager(url)
                response = proxy.access_filter(
                    request.raw._connection.sock.getsockname(),
                    url.replace(base_url, ''),
                    request
                )
                return StreamingHttpResponse(
                    response.raw,
                    content_type=response.headers.get('content-type'),
                    status=response.status_code,
                    reason=response.reason)
            except Exception as e:
                msg = 'Request failed'
                logger.exception(msg)
                return HttpResponseBadRequest(content=msg)

class RegistryView(ListAPIView):
    """
    Registry view
    """
    paginate_by = 10

    def get_queryset(self):
        return RegistryInterface.get_all_access_entries()
