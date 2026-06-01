import logging

from django.db.models import Count, F, Q
from django.http import StreamingHttpResponse
from django.http.response import HttpResponseBadRequest
from django.http.response import HttpResponseForbidden
from django.shortcuts import render
from requests.models import Request
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView

from middleman.models import AccessEntry, BlacklistRule
from middleman.serializers import AccessEntrySerializer
from proxy.settings import BASE_TARGET_URL, BLACKLISTED_IPS, BLACKLISTED_PATHS

from .exceptions import BlacklistedAccessException
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
        except BlacklistedAccessException as exc:
            logger.warning("[ProxyView] %s", exc)
            return HttpResponseForbidden(str(exc))
        except Exception:
            msg = "Request failed"
            logger.exception(msg)
            return HttpResponseBadRequest(content=msg)


class DashboardView(APIView):
    """Public landing page for the proxy control room."""

    def get(self, request):
        entries = AccessEntry.objects.all().order_by("-created_at")
        rules = BlacklistRule.objects.all().order_by("rule_type", "value")
        policy_rule_count = len(BLACKLISTED_IPS) + len(BLACKLISTED_PATHS) + rules.count()
        blocked_entries = entries.filter(Q(already_requested__gte=F("max_requests"))).count()
        top_paths = list(
            entries.values("path")
            .annotate(hits=Count("id"))
            .order_by("-hits", "path")[:5]
        )
        recent_table = list(entries[:8])
        recent_entries = []
        incident_feed = []
        for entry in recent_table:
            if entry.already_requested >= entry.max_requests:
                state = "danger"
                badge = "locked"
                note = "blocked by policy"
            elif entry.already_requested >= max(entry.max_requests - 5, 0):
                state = "warn"
                badge = "almost full"
                note = "approaching limit"
            else:
                state = "ok"
                badge = "open"
                note = "still flowing"
            recent_entries.append({"entry": entry, "state": state, "badge": badge})
            incident_feed.append(
                {
                    "path": entry.path,
                    "ip": entry.ip,
                    "state": state,
                    "note": note,
                    "ratio": "{}/{}".format(entry.already_requested, entry.max_requests),
                }
            )

        threat_paths = []
        for entry in recent_table:
            if entry.already_requested >= max(entry.max_requests - 5, 0):
                threat_paths.append(entry)
        threat_paths = threat_paths[:3]

        summary = {
            "total_entries": entries.count(),
            "unique_ips": entries.values("ip").distinct().count(),
            "unique_paths": entries.values("path").distinct().count(),
            "blocked_entries": blocked_entries,
            "base_target_url": BASE_TARGET_URL,
        }
        incident_summary = [
            {
                "title": "Containment status",
                "value": "active" if blocked_entries else "standby",
                "hint": "{} blocked routes detected".format(blocked_entries),
            },
            {
                "title": "Target profile",
                "value": "{}".format(BASE_TARGET_URL),
                "hint": "proxy destination locked",
            },
            {
                "title": "Threat density",
                "value": "{} hot paths".format(len(threat_paths)),
                "hint": "paths near their request ceiling",
            },
            {
                "title": "Policy rules",
                "value": "{} rules".format(policy_rule_count),
                "hint": "{} IP rules · {} path rules".format(
                    len(BLACKLISTED_IPS) + rules.filter(rule_type="ip").count(),
                    len(BLACKLISTED_PATHS) + rules.filter(rule_type="path").count(),
                ),
            },
        ]
        return render(
            request,
            "middleman/dashboard.html",
            {
                "summary": summary,
                "top_paths": top_paths,
                "recent_entries": recent_entries,
                "blocked_entries": blocked_entries,
                "incident_feed": incident_feed,
                "incident_summary": incident_summary,
                "threat_paths": threat_paths,
                "rules": rules,
            },
        )

    def post(self, request):
        action = request.data.get("action")
        rule_type = request.data.get("rule_type")
        value = (request.data.get("value") or "").strip()

        if action == "create" and rule_type in {"ip", "path"} and value:
            BlacklistRule.objects.get_or_create(rule_type=rule_type, value=value)
        elif action == "toggle":
            rule_id = request.data.get("rule_id")
            if rule_id:
                rule = BlacklistRule.objects.filter(id=rule_id).first()
                if rule is not None:
                    rule.enabled = not rule.enabled
                    rule.save(update_fields=["enabled"])
        elif action == "delete":
            rule_id = request.data.get("rule_id")
            if rule_id:
                BlacklistRule.objects.filter(id=rule_id).delete()

        return self.get(request)


class InsightsView(APIView):
    """JSON summary for the control room dashboard."""

    def get(self, request):
        entries = AccessEntry.objects.all().order_by("-created_at")
        payload = {
            "base_target_url": BASE_TARGET_URL,
            "total_entries": entries.count(),
            "unique_ips": entries.values("ip").distinct().count(),
            "unique_paths": entries.values("path").distinct().count(),
            "blocked_entries": entries.filter(Q(already_requested__gte=F("max_requests"))).count(),
            "top_paths": list(
                entries.values("path")
                .annotate(hits=Count("id"))
                .order_by("-hits", "path")[:5]
            ),
        }
        return Response(payload, status=status.HTTP_200_OK)


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
