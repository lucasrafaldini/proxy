import hashlib
import ipaddress
import logging
from typing import Optional, Tuple
from urllib.parse import urljoin

import requests
from django.db.models import F
from django.http import HttpRequest
from requests.models import Response

from middleman.models import AccessEntry, BlacklistRule
from middleman.rules import (RULE_TYPE_IP, RULE_TYPE_PATH, parse_ip_network,
                             validate_ip_rule, validate_path_rule)
from proxy.settings import BLACKLISTED_IPS, BLACKLISTED_PATHS

from . import abuse
from .client_ip import ClientResolution, resolve_client
from .destinations import (host_from_url, host_matches, parse_ip_literal,
                           system_resolver)
from .exceptions import (AccessNotRegisteredException,
                         BlacklistedAccessException,
                         BlockedDestinationException,
                         ClientAddressUnavailableException,
                         DestinationUnverifiableException,
                         ExceededRequestsLimitException, InvalidRuleError,
                         ServerNotRespondingException,
                         UpstreamStatusException, UpstreamTimeoutException)
from .interfaces import RegistryInterface

logger = logging.getLogger(__name__)
REQUEST_TIMEOUT = 10
MAX_REDIRECTS = 10
REDIRECT_STATUSES = {301, 302, 303, 307, 308}

HOST_RULE_TYPES = (BlacklistRule.RuleType.HOST, BlacklistRule.RuleType.HOST_RE)
INVALID_RULE_ACTION = (
    "fix or delete it on the dashboard, or run: "
    "python manage.py check_blacklist_rules --disable-invalid"
)

# Invalid rules already reported by this process: reported once, not per request.
_REPORTED_INVALID_RULES = set()
_MAX_REPORTED_INVALID_RULES = 4096


def _report_invalid_rule(source: str, rule_type: str, value: str, error: InvalidRuleError,
                         rule_id=None, created_by_version=None) -> None:
    marker = (source, rule_id, rule_type, value)
    if marker in _REPORTED_INVALID_RULES:
        return
    if len(_REPORTED_INVALID_RULES) < _MAX_REPORTED_INVALID_RULES:
        _REPORTED_INVALID_RULES.add(marker)
    logger.warning(
        "[ProxyManager] Skipping blacklist rule that is invalid in this version "
        "| source=%s id=%s rule_type=%r value=%r created_by_version=%r reason=%s detail=%r action=%r",
        source, rule_id, rule_type, value, created_by_version, error.reason, error.message,
        INVALID_RULE_ACTION if source == "database" else "fix the {} setting".format(source),
    )


class ProxyManager:
    def __init__(self, url: str):
        self.url = url
        self.model = AccessEntry
        # Populated by access_filter() once the client's access entry is known:
        # {"limit": <max_requests>, "remaining": <requests left>}
        self.rate_limit = None
        self.client_ip = None  # set by access_filter, for logging
        # Set from the client's ClientPolicy: the client may not see its limits.
        self.hide_rate_limit_headers = False
        self.client_resolution = None  # set by _get_user_ip
        self._dns_cache = {}

    def _create_unique_key(self, ip: str, path: str) -> str:
        """
        Deterministic key for an IP + path. (It used Python's hash(), which is
        randomized per process: every restart or worker produced new keys and
        silently reset/multiplied the rate limits.)
        """
        digest = hashlib.sha256("{}@{}".format(ip, path).encode("utf-8")).hexdigest()
        return digest[:20]

    def _get_user_ip(self, request: HttpRequest) -> str:
        """
        Client IP; X-Forwarded-For is only used from TRUSTED_PROXIES. The full
        resolution is kept in ``self.client_resolution`` for abuse detection.
        """
        resolution = resolve_client(request.META)
        if resolution.ip is None:
            raise ClientAddressUnavailableException(request.META.get("REMOTE_ADDR"))
        self.client_resolution = resolution
        return resolution.ip

    def _matches_rule(self, value: str, rule: str) -> bool:
        """Match exact rules and simple wildcard suffix rules."""
        if rule.endswith("*"):
            return value.startswith(rule[:-1])
        return value == rule

    def _matches_ip_rule(self, ip: str, rule: str) -> bool:
        """Match an IP against a CIDR subnet, an exact IP or a wildcard rule."""
        try:
            network = parse_ip_network(rule)
        except ValueError:
            # Callers validate rules first; this only protects direct calls.
            return False
        if network is None:
            return self._matches_rule(ip, rule)
        try:
            address = ipaddress.ip_address((ip or "").strip())
        except ValueError:
            logger.warning("[ProxyManager] Client IP is not an IP address | ip=%r", ip)
            return False
        # Mixed IPv4/IPv6 comparisons are simply False.
        return address in network

    def _set_rate_limit(self, entry: AccessEntry) -> None:
        """Record rate limit state for the given access entry."""
        self.rate_limit = {
            "limit": entry.max_requests,
            "remaining": max(entry.max_requests - entry.already_requested, 0),
        }

    def rate_limit_headers(self) -> dict:
        """Standard rate limit headers; empty if unknown or hidden for this client."""
        if self.rate_limit is None or self.hide_rate_limit_headers:
            return {}
        return {
            "X-RateLimit-Limit": str(self.rate_limit["limit"]),
            "X-RateLimit-Remaining": str(self.rate_limit["remaining"]),
        }

    @staticmethod
    def _valid_setting_rules(setting_name: str, rule_type: str, values, validator):
        for value in values:
            try:
                validator(value)
            except InvalidRuleError as error:
                _report_invalid_rule(setting_name, rule_type, value, error)
                continue
            yield value

    @staticmethod
    def _valid_database_rules(queryset):
        """Enabled rules that are valid in this version, with their parsed form."""
        for rule in queryset:
            try:
                parsed = rule.parse()
            except InvalidRuleError as error:
                _report_invalid_rule(
                    "database", rule.rule_type, rule.value, error,
                    rule_id=rule.pk, created_by_version=rule.created_by_version,
                )
                continue
            yield rule, parsed

    def _is_blacklisted(self, ip: str, path: str) -> Optional[Tuple[str, str]]:
        for rule in self._valid_setting_rules("BLACKLISTED_IPS", RULE_TYPE_IP, BLACKLISTED_IPS, validate_ip_rule):
            if self._matches_ip_rule(ip, rule):
                return "ip", rule
        for rule in self._valid_setting_rules("BLACKLISTED_PATHS", RULE_TYPE_PATH, BLACKLISTED_PATHS, validate_path_rule):
            if self._matches_rule(path, rule):
                return "path", rule
        client_rules = BlacklistRule.objects.filter(
            enabled=True, rule_type__in=(RULE_TYPE_IP, RULE_TYPE_PATH)
        )
        for rule, _ in self._valid_database_rules(client_rules):
            if rule.rule_type == RULE_TYPE_IP and self._matches_ip_rule(ip, rule.value):
                return "ip", rule.value
            if rule.rule_type == RULE_TYPE_PATH and self._matches_rule(path, rule.value):
                return "path", rule.value
        return None

    def _resolve(self, host: str):
        """Resolve a host once per ProxyManager (only needed for IP host rules)."""
        if host not in self._dns_cache:
            self._dns_cache[host] = system_resolver(host)
        return self._dns_cache[host]

    def _blocked_destination(self, url: str) -> Optional[str]:
        """
        Value of the first host/host_re rule matching ``url``, else None.
        Raises DestinationUnverifiableException when an IP rule applies but the
        host name cannot be resolved (fail closed).
        """
        host = host_from_url(url)
        if not host:
            return None
        rules = BlacklistRule.objects.filter(enabled=True, rule_type__in=HOST_RULE_TYPES)
        for rule, parsed in self._valid_database_rules(rules):
            if parsed.kind == "network" and parse_ip_literal(host) is None and not self._resolve(host):
                raise DestinationUnverifiableException(host, rule.value)
            if host_matches(parsed, host, resolver=self._resolve):
                return rule.value
        return None

    def _check_destination(self, url: str, ip: str = None, path: str = None) -> None:
        """Raise BlockedDestinationException if ``url`` points at a blocked site."""
        rule_value = self._blocked_destination(url)
        if rule_value is not None:
            raise BlockedDestinationException(host_from_url(url), rule_value, ip, path)

    def _get_following_redirects(self) -> Response:
        """
        GET the target, following redirects manually so every hop is checked
        against the host rules *before* the proxy connects to it. Letting
        requests follow redirects itself would let a target bounce the proxy
        to a blocked site.
        """
        url = self.url
        for _ in range(MAX_REDIRECTS + 1):
            response = requests.get(
                url, stream=True, timeout=REQUEST_TIMEOUT, allow_redirects=False
            )
            location = None
            if response.status_code in REDIRECT_STATUSES:
                location = response.headers.get("location")
            if not location:
                return response
            next_url = urljoin(url, location)
            response.close()
            self._check_destination(next_url)
            logger.info(
                "[ProxyManager] Following upstream redirect | status=%s from=%r to=%r",
                response.status_code, url, next_url,
            )
            url = next_url
        raise requests.TooManyRedirects(
            "more than {} redirects starting at {}".format(MAX_REDIRECTS, self.url)
        )

    def do_request(self) -> Response:
        """
        Check that the target is up (HEAD must answer 200), then GET it.
        Raises UpstreamTimeoutException, ServerNotRespondingException or
        UpstreamStatusException; blocked redirect hops raise
        BlockedDestinationException / DestinationUnverifiableException.
        """
        try:
            head = requests.head(self.url, timeout=REQUEST_TIMEOUT)
            if head.status_code != 200:
                logger.error(
                    "[ProxyManager] Target failed the availability check "
                    "| url=%r method=HEAD status=%s",
                    self.url, head.status_code,
                )
                raise UpstreamStatusException(self.url, head.status_code)
            response = self._get_following_redirects()
        except requests.Timeout as exc:
            logger.error(
                "[ProxyManager] Target timed out | url=%r timeout=%ss error=%s: %s",
                self.url, REQUEST_TIMEOUT, type(exc).__name__, exc,
            )
            raise UpstreamTimeoutException(self.url) from exc
        except requests.RequestException as exc:
            logger.error(
                "[ProxyManager] Target is not reachable | url=%r error=%s: %s",
                self.url, type(exc).__name__, exc,
            )
            raise ServerNotRespondingException(self.url) from exc
        # DEBUG: ProxyView logs the outcome of every request at INFO already.
        logger.debug(
            "[ProxyManager] Fetched target | url=%r status=%s", self.url, response.status_code
        )
        return response

    def access_filter(self, request: HttpRequest, path: str) -> Response:
        """
        Apply blacklist rules and the rate limit, then proxy the request.
        Tampering/abuse signals seen along the way are reported to the abuse
        detector, whatever the outcome.
        """
        ip = self.client_ip = self._get_user_ip(request)
        resolution = self.client_resolution or ClientResolution(ip, ip, False, ())
        signals = abuse.request_signals(request.META, resolution)
        try:
            self.hide_rate_limit_headers = abuse.hides_rate_limit_headers(ip)
            return self._filter_and_fetch(ip, path, signals)
        finally:
            abuse.report(ip, signals)

    def _filter_and_fetch(self, ip: str, path: str, signals: list) -> Response:
        blacklist_match = self._is_blacklisted(ip, path)
        if blacklist_match is not None:
            rule_type, rule_value = blacklist_match
            signals.append(("blacklist_hit", ""))
            raise BlacklistedAccessException(ip, path, rule_type, rule_value)
        # Blocked sites are rejected before rate limiting, so they never count.
        self._check_destination(self.url, ip, path)

        key = self._create_unique_key(ip, path)
        try:
            entry = RegistryInterface().get_or_create_access_entry(key, ip, path)
        except Exception as exc:
            logger.exception(
                "[ProxyManager] Could not store access entry | key=%s ip=%s path=%r", key, ip, path
            )
            raise AccessNotRegisteredException(key, ip, path) from exc

        # Reserve one request atomically. A separate "check, then increment
        # later" let parallel requests all pass the check at limit - 1.
        reserved = self.model.objects.filter(
            pk=entry.pk, already_requested__lt=F("max_requests")
        ).update(already_requested=F("already_requested") + 1)
        if not reserved:
            entry.refresh_from_db()
            self._set_rate_limit(entry)
            signals.append(("rate_limited_retry", ""))
            raise ExceededRequestsLimitException(ip, path)

        try:
            response = self.do_request()
        except Exception:
            # Requests the proxy could not complete do not count.
            self.model.objects.filter(pk=entry.pk, already_requested__gt=0).update(
                already_requested=F("already_requested") - 1
            )
            raise
        entry.refresh_from_db()
        self._set_rate_limit(entry)
        return response
