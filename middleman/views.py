import logging

from django.core.exceptions import ValidationError
from django.db.models import Count, F, Q
from django.http import HttpRequest, HttpResponse, StreamingHttpResponse
from django.shortcuts import render
from rest_framework import exceptions, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from middleman.models import (AccessEntry, AllowedHost, BlacklistRule,
                              ClientPolicy, canonical_ip)
from middleman.serializers import AccessEntrySerializer
from middleman.version import LEGACY_VERSION, __version__
from proxy.settings import BASE_TARGET_URL, BLACKLISTED_IPS, BLACKLISTED_PATHS

from . import abuse
from . import hosts
from .auth import (ClientPolicyPermissions, DashboardPermissions,
                   RegistryPermissions, SettingsPermissions)
from .client_ip import get_client_ip
from .exceptions import InvalidRuleError
from .exceptions import (AccessNotRegisteredException,
                         BlacklistedAccessException,
                         BlockedDestinationException,
                         ClientAddressUnavailableException,
                         DestinationUnverifiableException,
                         ExceededRequestsLimitException,
                         ServerNotRespondingException,
                         UpstreamStatusException, UpstreamTimeoutException)
from .interfaces import RegistryInterface
from .services import ProxyManager

logger = logging.getLogger(__name__)


def _text_response(message: str, status_code: int) -> HttpResponse:
    return HttpResponse(message, status=status_code, content_type="text/plain; charset=utf-8")


def _requester(request) -> str:
    """'<username>@<client ip>' for audit logs ('anonymous@…' if not logged in)."""
    user = getattr(request, "user", None)
    name = user.get_username() if user is not None and user.is_authenticated else "anonymous"
    return "{}@{}".format(name, get_client_ip(request.META))


class ManagementAPIView(APIView):
    """
    Base for endpoints that need authentication. Rejected requests are
    reported to the abuse detector: bad tokens as auth_failure, missing
    credentials or permissions as access_denied.
    """

    def handle_exception(self, exc):
        if isinstance(exc, exceptions.AuthenticationFailed):
            kind = "auth_failure"
        elif isinstance(exc, (exceptions.NotAuthenticated, exceptions.PermissionDenied)):
            kind = "access_denied"
        else:
            kind = None
        if kind is not None:
            logger.warning(
                "[%s] Rejected %s request | reason=%s requester=%s",
                type(self).__name__, self.request.method, kind, _requester(self.request),
            )
            abuse.report(get_client_ip(self.request.META), [(kind, "")])
        return super().handle_exception(exc)


class ProxyView(APIView):
    """
    Proxy view.

    Status codes: upstream status on success; 403 blacklisted client, path or
    destination; 429 rate limit exceeded; 502 target unreachable, failing its
    availability check or unverifiable; 504 target timeout; 400 client address
    unavailable; 500 internal error. 502/504 bodies never include the target
    URL (it may be internal); the logs do.
    """

    # Public and anonymous: an Authorization header sent by a proxy client
    # must not turn its request into a 401.
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request: HttpRequest, path: str):
        path = "{}/".format(path)
        proxy = ProxyManager("{}{}".format(BASE_TARGET_URL, path))
        try:
            response = proxy.access_filter(request, path)
        except BlockedDestinationException as exc:
            logger.warning(
                "[ProxyView] Request blocked: destination matches a host rule "
                "| ip=%s path=%r host=%r rule=%r",
                exc.ip, exc.path, exc.host, exc.rule_value,
            )
            return _text_response(str(exc), status.HTTP_403_FORBIDDEN)
        except BlacklistedAccessException as exc:
            logger.warning(
                "[ProxyView] Request blocked: client matches a blacklist rule "
                "| ip=%s path=%r rule_type=%s rule=%r",
                exc.ip, exc.path, exc.rule_type, exc.rule_value,
            )
            return _text_response(str(exc), status.HTTP_403_FORBIDDEN)
        except ExceededRequestsLimitException as exc:
            logger.warning(
                "[ProxyView] Request rejected: rate limit exceeded | ip=%s path=%r limit=%s",
                exc.ip, exc.path, (proxy.rate_limit or {}).get("limit"),
            )
            # No Retry-After: limits have no time window, they only reset when
            # an operator resets the entry via PATCH /registry/.
            return self._with_rate_limit_headers(
                _text_response(str(exc), status.HTTP_429_TOO_MANY_REQUESTS), proxy
            )
        except UpstreamTimeoutException:
            # Logged with the URL and error by ProxyManager.do_request.
            return _text_response(
                "Gateway timeout: the target server did not answer in time.",
                status.HTTP_504_GATEWAY_TIMEOUT,
            )
        except (ServerNotRespondingException, UpstreamStatusException):
            # Logged with the URL and error by ProxyManager.do_request.
            return _text_response(
                "Bad gateway: the target server is not available.", status.HTTP_502_BAD_GATEWAY
            )
        except DestinationUnverifiableException as exc:
            logger.error(
                "[ProxyView] Request refused: destination cannot be checked against an IP host rule "
                "| ip=%s path=%r host=%r rule=%r",
                proxy.client_ip, path, exc.host, exc.rule_value,
            )
            return _text_response(
                "Bad gateway: the destination could not be verified.", status.HTTP_502_BAD_GATEWAY
            )
        except ClientAddressUnavailableException:
            # Logged by client_ip.get_client_ip.
            return _text_response(
                "Bad request: the client address could not be determined.",
                status.HTTP_400_BAD_REQUEST,
            )
        except AccessNotRegisteredException:
            # Logged with traceback by ProxyManager.access_filter.
            return _text_response(
                "Internal proxy error: the request could not be registered.",
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except Exception:
            logger.exception("[ProxyView] Unexpected error while proxying | path=%r", path)
            return _text_response("Internal proxy error.", status.HTTP_500_INTERNAL_SERVER_ERROR)

        rate_limit = proxy.rate_limit or {}
        logger.info(
            "[ProxyView] Proxied request | ip=%s path=%r status=%s limit=%s remaining=%s",
            proxy.client_ip, path, response.status_code,
            rate_limit.get("limit"), rate_limit.get("remaining"),
        )
        streaming_response = StreamingHttpResponse(
            response.raw,
            content_type=response.headers.get("content-type"),
            status=response.status_code,
            reason=response.reason,
        )
        return self._with_rate_limit_headers(streaming_response, proxy)

    @staticmethod
    def _with_rate_limit_headers(response, proxy: ProxyManager):
        """Attach X-RateLimit-* headers for the client's access entry, if known."""
        for header, value in proxy.rate_limit_headers().items():
            response[header] = value
        return response


class DashboardView(ManagementAPIView):
    """
    Control room. Aggregates are public; per-client activity (IPs, usage) and
    blacklist rules are only shown to users with the matching permissions, and
    each rule action needs its own permission (see auth.DashboardPermissions).
    """

    permission_classes = [DashboardPermissions]

    def get(self, request):
        return self._render(request)

    @staticmethod
    def _ui_permissions(user) -> dict:
        def has(perm):
            return bool(user and user.is_authenticated and user.has_perm("middleman." + perm))

        return {
            "view_clients": has("view_accessentry"),
            "view_rules": has("view_blacklistrule"),
            "add_rules": has("add_blacklistrule"),
            "change_rules": has("change_blacklistrule"),
            "delete_rules": has("delete_blacklistrule"),
        }

    def _render(self, request, rule_error=None, status_code=200):
        perms_ui = self._ui_permissions(request.user)
        entries = AccessEntry.objects.all().order_by("-created_at")
        rules = BlacklistRule.objects.all().order_by("rule_type", "value")
        policy_rule_count = len(BLACKLISTED_IPS) + len(BLACKLISTED_PATHS) + rules.count()
        blocked_entries = entries.filter(Q(already_requested__gte=F("max_requests"))).count()
        top_paths = list(
            entries.values("path")
            .annotate(hits=Count("id"))
            .order_by("-hits", "path")[:5]
        )
        rule_rows = list(rules)
        for rule in rule_rows:
            rule.invalid = rule.validation_error  # shown as "invalid in v…" on the page
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
        if not perms_ui["view_clients"]:
            # Never hand per-client data (IPs, usage) to the template for
            # users who may not see it, even if the template changes later.
            recent_entries, incident_feed, threat_paths = [], [], []
        if not perms_ui["view_rules"]:
            rule_rows = []

        summary = {
            "total_entries": entries.count(),
            "unique_ips": entries.values("ip").distinct().count(),
            "unique_paths": entries.values("path").distinct().count(),
            "blocked_entries": blocked_entries,
            "base_target_url": BASE_TARGET_URL,
            "proxy_version": __version__,
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
                "hint": "{} IP rules · {} path rules · {} host rules · {} invalid".format(
                    len(BLACKLISTED_IPS) + rules.filter(rule_type="ip").count(),
                    len(BLACKLISTED_PATHS) + rules.filter(rule_type="path").count(),
                    rules.filter(rule_type__in=["host", "host_re"]).count(),
                    sum(1 for rule in rule_rows if rule.invalid),
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
                "rules": rule_rows,
                "rule_error": rule_error,
                "perms_ui": perms_ui,
                "proxy_version": __version__,
            },
            status=status_code,
        )

    def post(self, request):
        action = request.data.get("action")
        requester = _requester(request)

        if action == "create":
            return self._create_rule(request, requester)
        if action in ("toggle", "delete"):
            rule = BlacklistRule.objects.filter(id=request.data.get("rule_id") or None).first()
            if rule is None:
                logger.info(
                    "[Dashboard] Ignored %s: rule not found | rule_id=%r requester=%s",
                    action, request.data.get("rule_id"), requester,
                )
                return self._render(request)
            if action == "delete":
                rule.delete()
                logger.info(
                    "[Dashboard] Deleted blacklist rule | rule_type=%s value=%r "
                    "created_by_version=%r requester=%s",
                    rule.rule_type, rule.value, rule.created_by_version, requester,
                )
                return self._render(request)
            return self._toggle_rule(request, rule, requester)

        logger.info("[Dashboard] Ignored unknown action | action=%r requester=%s", action, requester)
        return self._render(request)

    def _create_rule(self, request, requester):
        rule_type = request.data.get("rule_type")
        value = (request.data.get("value") or "").strip()
        rule = BlacklistRule(rule_type=rule_type, value=value)
        try:
            # Reject unknown types and malformed values instead of storing
            # rules that can never match. Uniqueness is handled below.
            rule.clean_fields(exclude=["created_by_version"])
            rule.clean()
        except ValidationError as exc:
            error_dict = exc.message_dict
            errors = error_dict.get("value") or error_dict.get("rule_type") or exc.messages
            reason = getattr(rule.validation_error, "reason", None) or "invalid_field"
            logger.warning(
                "[Dashboard] Rejected blacklist rule | rule_type=%r value=%r reason=%s detail=%r requester=%s",
                rule_type, value, reason, " ".join(errors), requester,
            )
            return self._render(
                request, rule_error=" ".join(errors), status_code=status.HTTP_400_BAD_REQUEST
            )
        rule, created = BlacklistRule.objects.get_or_create(rule_type=rule_type, value=value)
        logger.info(
            "[Dashboard] %s blacklist rule | id=%s rule_type=%s value=%r requester=%s",
            "Created" if created else "Kept existing", rule.pk, rule.rule_type, rule.value, requester,
        )
        return self._render(request)

    def _toggle_rule(self, request, rule, requester):
        error = rule.validation_error
        if not rule.enabled and error is not None:
            logger.warning(
                "[Dashboard] Refused to enable a rule that is invalid in this version "
                "| id=%s rule_type=%s value=%r created_by_version=%r reason=%s requester=%s",
                rule.pk, rule.rule_type, rule.value, rule.created_by_version, error.reason, requester,
            )
            return self._render(
                request,
                rule_error="Rule {!r} cannot be enabled: {}".format(rule.value, error.message),
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        rule.enabled = not rule.enabled
        rule.save(update_fields=["enabled"])
        logger.info(
            "[Dashboard] %s blacklist rule | id=%s rule_type=%s value=%r requester=%s",
            "Enabled" if rule.enabled else "Disabled", rule.pk, rule.rule_type, rule.value, requester,
        )
        return self._render(request)


class InsightsView(APIView):
    """Public JSON summary for the control room dashboard (aggregates only, no IPs)."""

    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        entries = AccessEntry.objects.all().order_by("-created_at")
        payload = {
            "proxy_version": __version__,
            "base_target_url": BASE_TARGET_URL,
            "total_entries": entries.count(),
            # Rows created before version tracking (see CHANGELOG.md).
            "legacy_entries": entries.filter(created_by_version=LEGACY_VERSION).count(),
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


class RegistryView(ManagementAPIView):
    """
    List access entries, fetch one by key, update max_requests and reset
    already_requested. Unknown keys answer 404; invalid input answers 400.
    Requires view_accessentry (GET) / change_accessentry (PATCH).
    """

    permission_classes = [RegistryPermissions]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.interface = RegistryInterface()

    @staticmethod
    def _error(message: str, status_code: int) -> Response:
        return Response({"detail": message}, status=status_code)

    def get(self, request):
        """One entry (?key=... or {"key": ...} body) or all entries, paginated."""
        key = request.query_params.get("key") or request.data.get("key")
        if key is not None:
            try:
                access_entry = self.interface.get_access_entry(key)
            except AccessEntry.DoesNotExist:
                logger.info("[RegistryView] Access entry not found | key=%r", key)
                return self._error("Access entry {!r} not found.".format(key), status.HTTP_404_NOT_FOUND)
            logger.info("[RegistryView] Returned access entry | key=%r", key)
            return Response(AccessEntrySerializer(access_entry).data, status=status.HTTP_200_OK)

        if request.data:
            logger.info(
                "[RegistryView] Rejected GET: body has no 'key' | fields=%s", sorted(request.data.keys())
            )
            return self._error(
                "Send {\"key\": ...} (or ?key=...) to fetch one entry, or no body to list all.",
                status.HTTP_400_BAD_REQUEST,
            )

        queryset = self.interface.get_all_access_entries()
        paginator = PageNumberPagination()
        result_page = paginator.paginate_queryset(queryset, request)
        serializer = AccessEntrySerializer(result_page, many=True, context={"request": request})
        logger.info("[RegistryView] Listed access entries | count=%s", len(serializer.data))
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        """Update max_requests or reset already_requested for one entry."""
        requester = _requester(request)
        key, action = request.data.get("key"), request.data.get("action")
        missing = [name for name, value in (("key", key), ("action", action)) if not value]
        if missing:
            logger.info(
                "[RegistryView] Rejected PATCH: missing fields | missing=%s requester=%s",
                missing, requester,
            )
            return self._error(
                "Missing required field(s): {}.".format(", ".join(missing)), status.HTTP_400_BAD_REQUEST
            )

        if action == "update_max_requests":
            max_requests = request.data.get("max_requests")
            if max_requests in (None, ""):
                logger.info(
                    "[RegistryView] Rejected PATCH: missing max_requests | key=%r requester=%s",
                    key, requester,
                )
                return self._error("Missing required field: max_requests.", status.HTTP_400_BAD_REQUEST)
            operation = lambda: self.interface.update_max_requests(key, max_requests)  # noqa: E731
        elif action == "reset_already_requested":
            operation = lambda: self.interface.reset_already_requested(key)  # noqa: E731
        else:
            logger.info(
                "[RegistryView] Rejected PATCH: unknown action | action=%r key=%r requester=%s",
                action, key, requester,
            )
            return self._error(
                "Unknown action {!r}; use update_max_requests or reset_already_requested.".format(action),
                status.HTTP_400_BAD_REQUEST,
            )

        try:
            serializer = operation()
        except AccessEntry.DoesNotExist:
            logger.info(
                "[RegistryView] Rejected PATCH: access entry not found | action=%s key=%r requester=%s",
                action, key, requester,
            )
            return self._error("Access entry {!r} not found.".format(key), status.HTTP_404_NOT_FOUND)
        if serializer.errors:
            logger.info(
                "[RegistryView] Rejected PATCH: invalid value | action=%s key=%r errors=%r requester=%s",
                action, key,
                {field: [str(message) for message in messages] for field, messages in serializer.errors.items()},
                requester,
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        logger.info(
            "[RegistryView] Applied %s | key=%r already_requested=%s max_requests=%s requester=%s",
            action, key, serializer.data["already_requested"], serializer.data["max_requests"], requester,
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


class ClientPolicyView(ManagementAPIView):
    """
    Per-client policies (currently: hide rate limit headers).

    GET  /clients/            list, paginated
    GET  /clients/?ip=1.2.3.4 one policy (404 if none)
    PATCH /clients/ {"ip": "1.2.3.4", "hide_rate_limit_headers": true, "reason": "..."}
          creates or updates the policy; admin changes are source=manual and
          are never overridden by abuse detection.
    """

    permission_classes = [ClientPolicyPermissions]

    @staticmethod
    def _serialize(policy: ClientPolicy) -> dict:
        return {
            "ip": policy.ip,
            "hide_rate_limit_headers": policy.hide_rate_limit_headers,
            "source": policy.source,
            "reason": policy.reason,
            "updated_by": policy.updated_by.get_username() if policy.updated_by else None,
            "updated_at": policy.updated_at,
            "created_by_version": policy.created_by_version,
        }

    def get(self, request):
        raw_ip = request.query_params.get("ip")
        if raw_ip is not None:
            ip = canonical_ip(raw_ip)
            policy = ClientPolicy.objects.filter(ip=ip).first() if ip else None
            if policy is None:
                logger.info("[ClientPolicyView] Policy not found | ip=%r", raw_ip)
                return Response({"detail": "No policy for {!r}.".format(raw_ip)}, status=status.HTTP_404_NOT_FOUND)
            return Response(self._serialize(policy))
        paginator = PageNumberPagination()
        page = paginator.paginate_queryset(ClientPolicy.objects.select_related("updated_by"), request)
        return Response([self._serialize(policy) for policy in page])

    def patch(self, request):
        requester = _requester(request)
        raw_ip = request.data.get("ip")
        hide = request.data.get("hide_rate_limit_headers")
        reason = request.data.get("reason", "")
        errors = {}
        ip = canonical_ip(raw_ip) if isinstance(raw_ip, str) else None
        if ip is None:
            errors["ip"] = "A valid IP address is required."
        if not isinstance(hide, bool):
            errors["hide_rate_limit_headers"] = "Must be true or false (JSON boolean)."
        if not isinstance(reason, str) or len(reason) > 1000:
            errors["reason"] = "Must be a string of at most 1000 characters."
        if errors:
            logger.info(
                "[ClientPolicyView] Rejected PATCH: invalid input | fields=%s requester=%s",
                sorted(errors), requester,
            )
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        policy, created = ClientPolicy.objects.update_or_create(
            ip=ip,
            defaults={
                "hide_rate_limit_headers": hide,
                "source": ClientPolicy.Source.MANUAL,
                "reason": reason,
                "updated_by": request.user,
            },
        )
        logger.info(
            "[ClientPolicyView] %s client policy | ip=%s hide_rate_limit_headers=%s source=manual requester=%s",
            "Created" if created else "Updated", ip, hide, requester,
        )
        return Response(self._serialize(policy), status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class AllowedHostsView(ManagementAPIView):
    """
    Runtime allowed hosts (Host header values accepted besides the baseline).

    GET    /settings/allowed-hosts/                      baseline + runtime hosts
    POST   {"host": "api.example.com", "note": "..."}    add (201; 409 if already allowed)
    PATCH  {"host": "...", "new_host": "...", "note": "...", "force": false}   rename / edit note
    DELETE {"host": "...", "force": false}               remove (204)

    Requires an active staff account with the matching *_allowedhost
    permission (role proxy-settings-admin). Baseline hosts (ALLOWED_HOSTS
    environment variable) cannot be changed here. Removing or renaming the
    host the request itself came through needs "force": true, so an admin does
    not cut off their own access by accident. Changes apply immediately in
    this process and within hosts.CACHE_SECONDS in the others.
    """

    permission_classes = [SettingsPermissions]

    @staticmethod
    def _error(detail, code, **extra):
        return Response(dict({"detail": detail}, **extra), status=code)

    @staticmethod
    def _serialize(entry):
        return {
            "host": entry.host,
            "note": entry.note,
            "created_by": entry.created_by.get_username() if entry.created_by else None,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
            "created_by_version": entry.created_by_version,
        }

    def _normalized(self, request, field, value, requester):
        try:
            return hosts.normalize_allowed_host(value), None
        except InvalidRuleError as error:
            logger.warning(
                "[AllowedHostsView] Rejected %s: invalid host | field=%s value=%r reason=%s requester=%s",
                request.method, field, value, error.reason, requester,
            )
            return None, self._error(error.message, status.HTTP_400_BAD_REQUEST, field=field, reason=error.reason)

    @staticmethod
    def _note(request):
        note = request.data.get("note", "")
        if not isinstance(note, str) or len(note) > 255:
            return None
        return note

    @staticmethod
    def _force(request):
        force = request.data.get("force", False)
        return force if isinstance(force, bool) else None

    @staticmethod
    def _current_host(request):
        domain, _ = hosts.split_domain_port(request._get_raw_host())
        return domain

    def _baseline_refusal(self, request, host, requester):
        if host in hosts.baseline_hosts():
            logger.warning(
                "[AllowedHostsView] Rejected %s of a baseline host | host=%s requester=%s",
                request.method, host, requester,
            )
            return self._error(
                "{} comes from the ALLOWED_HOSTS environment variable; change it there.".format(host),
                status.HTTP_400_BAD_REQUEST,
            )
        return None

    def _self_cutoff_refusal(self, request, host, force, requester):
        if force:
            return None
        current = self._current_host(request)
        if hosts.validate_host(current, [host]) and not hosts.validate_host(current, hosts.baseline_hosts()):
            logger.warning(
                "[AllowedHostsView] Refused %s of the host this request uses without force | host=%s requester=%s",
                request.method, host, requester,
            )
            return self._error(
                "This request came through {}; removing it would cut off access through it. "
                "Send \"force\": true to confirm.".format(current),
                status.HTTP_409_CONFLICT,
            )
        return None

    def _runtime_entry(self, request, host, requester):
        entry = AllowedHost.objects.filter(host=host).first()
        if entry is None:
            logger.info(
                "[AllowedHostsView] Rejected %s: not a runtime allowed host | host=%s requester=%s",
                request.method, host, requester,
            )
            return self._error("{} is not a runtime allowed host.".format(host), status.HTTP_404_NOT_FOUND)
        return entry

    def get(self, request):
        return Response({
            "baseline": hosts.baseline_hosts(),
            "runtime": [self._serialize(entry) for entry in AllowedHost.objects.select_related("created_by")],
            "cache_seconds": hosts.CACHE_SECONDS,
        })

    def post(self, request):
        requester = _requester(request)
        host, error = self._normalized(request, "host", request.data.get("host"), requester)
        if error:
            return error
        note = self._note(request)
        if note is None:
            logger.warning("[AllowedHostsView] Rejected POST: invalid note | host=%s requester=%s", host, requester)
            return self._error("note must be a string of at most 255 characters.", status.HTTP_400_BAD_REQUEST)
        if host in hosts.baseline_hosts() or AllowedHost.objects.filter(host=host).exists():
            logger.info("[AllowedHostsView] Host already allowed | host=%s requester=%s", host, requester)
            return self._error("{} is already allowed.".format(host), status.HTTP_409_CONFLICT)
        entry = AllowedHost.objects.create(host=host, note=note, created_by=request.user)
        logger.warning(
            "[AllowedHostsView] Added allowed host | host=%s note=%r requester=%s", host, note, requester
        )
        return Response(self._serialize(entry), status=status.HTTP_201_CREATED)

    def patch(self, request):
        requester = _requester(request)
        host, error = self._normalized(request, "host", request.data.get("host"), requester)
        if error:
            return error
        refusal = self._baseline_refusal(request, host, requester)
        if refusal:
            return refusal
        entry = self._runtime_entry(request, host, requester)
        if isinstance(entry, Response):
            return entry
        force = self._force(request)
        note = self._note(request) if "note" in request.data else entry.note
        if force is None or note is None:
            logger.warning(
                "[AllowedHostsView] Rejected PATCH: invalid force/note | host=%s requester=%s", host, requester
            )
            return self._error("force must be true/false; note a string of at most 255 characters.",
                               status.HTTP_400_BAD_REQUEST)
        new_host = host
        if "new_host" in request.data:
            new_host, error = self._normalized(request, "new_host", request.data.get("new_host"), requester)
            if error:
                return error
        if new_host != host:
            if new_host in hosts.baseline_hosts() or AllowedHost.objects.filter(host=new_host).exists():
                logger.info(
                    "[AllowedHostsView] Rejected PATCH: new_host already allowed | host=%s new_host=%s requester=%s",
                    host, new_host, requester,
                )
                return self._error("{} is already allowed.".format(new_host), status.HTTP_409_CONFLICT)
            refusal = self._self_cutoff_refusal(request, host, force, requester)
            if refusal:
                return refusal
        entry.host, entry.note = new_host, note
        entry.save()
        logger.warning(
            "[AllowedHostsView] Updated allowed host | host=%s new_host=%s note=%r requester=%s",
            host, new_host, note, requester,
        )
        return Response(self._serialize(entry))

    def delete(self, request):
        requester = _requester(request)
        raw = request.data.get("host", request.query_params.get("host"))
        host, error = self._normalized(request, "host", raw, requester)
        if error:
            return error
        refusal = self._baseline_refusal(request, host, requester)
        if refusal:
            return refusal
        entry = self._runtime_entry(request, host, requester)
        if isinstance(entry, Response):
            return entry
        force = self._force(request)
        if force is None:
            logger.warning("[AllowedHostsView] Rejected DELETE: invalid force | host=%s requester=%s", host, requester)
            return self._error("force must be true or false.", status.HTTP_400_BAD_REQUEST)
        refusal = self._self_cutoff_refusal(request, host, force, requester)
        if refusal:
            return refusal
        entry.delete()
        logger.warning("[AllowedHostsView] Removed allowed host | host=%s requester=%s", host, requester)
        return Response(status=status.HTTP_204_NO_CONTENT)
