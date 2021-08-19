import json
import logging

from django.http import StreamingHttpResponse
from django.http.response import HttpResponseBadRequest
from requests.models import Request
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView

from middleman.serializers import AccessEntrySerializer
from proxy.settings import BASE_TARGET_URL

from .interfaces import RegistryInterface
from .services import ProxyManager

logger = logging.getLogger(__name__)


class ProxyView(APIView):
    """
    Proxy view
    """

    def get(self, request: Request, path: str):
        base_url = BASE_TARGET_URL
        if path is None:
            logging.error("Missing path")
            return HttpResponseBadRequest("Path is required")
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
                content_type=response.headers.get("content-type"),
                status=response.status_code,
                reason=response.reason,
            )
        except Exception:
            msg = "Request failed"
            logger.exception(msg)
            return HttpResponseBadRequest(content=msg)


class RegistryView(APIView):
    """
    View to get all and individual registers,
    update max request limits and reset already used requests
    """

    def __init__(self):
        self.interface = RegistryInterface()
        self.bad_request_message = "Request body is misssing or incomplete"

    def get(self, request):
        """Get all registers paginated"""
        if request.data.get("key") is not None:
            logger.info(
                "[Registry View] Patch request failed because request body is missing or incomplete"
            )
            key = request.data.get("key")
            access_entry = self.interface.get_access_entry(key)
            seralizer_class = AccessEntrySerializer(access_entry)
            logger.info(
                "[Registry View] Successfully returned key:{} register".format(key)
            )
            return Response(seralizer_class.data, status=status.HTTP_200_OK)

        if not request.data:
            queryset = self.interface.get_all_access_entries()
            paginator = PageNumberPagination()
            result_page = paginator.paginate_queryset(queryset, request)
            serializer = AccessEntrySerializer(
                result_page, many=True, context={"request": request}
            )
            logger.info(
                "[Registry View] Successfully returned {} registers".format(
                    len(serializer.data)
                )
            )
            return Response(serializer.data, status=status.HTTP_200_OK)
        return HttpResponseBadRequest("Request body is misssing or incomplete")

    def patch(self, request):
        """Update register maximum requests limit"""

        if all(
            value is None
            for value in [
                request.data,
                request.data.get("key"),
                request.data.get("action"),
            ]
        ):
            logger.info(
                "[Registry View] Patch request failed because request body is missing or incomplete"
            )
            return HttpResponseBadRequest(self.bad_request_message)

        if request.data.get("action") == "update_max_requests":
            if request.data.get("max_requests") is None:
                logger.info(
                    "[Registry View] Patch request failed because max_requests is missing"
                )
                return HttpResponseBadRequest(self.bad_request_message)
            key, max_requests = request.data.get("key"), request.data.get(
                "max_requests"
            )
            serialized_data = self.interface.update_max_requests(key, max_requests)
            logger.info("[Registry View] Update request limit try successful")
            if serialized_data.data:
                return Response(serialized_data.data, status=status.HTTP_200_OK)
            return Response(serialized_data.errors, status=status.HTTP_400_BAD_REQUEST)
        elif request.data.get("action") == "reset_already_requested":
            key = request.data.get("key")
            serialized_data = self.interface.reset_already_requested(key)
            logger.info("[Registry View] Reset request limit try successful")
            if serialized_data.data:
                return Response(serialized_data.data, status=status.HTTP_200_OK)
            return Response(serialized_data.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            logger.info(
                "[Registry View] Patch request failed because action is missing or invalid"
            )
            return HttpResponseBadRequest(self.bad_request_message)
