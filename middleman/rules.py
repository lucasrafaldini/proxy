"""
Validation of blacklist rule values, shared by the model (admin/dashboard),
the proxy at request time and the ``check_blacklist_rules`` command.

Every rule type has exactly one validator; all of them raise
``InvalidRuleError`` (a ``ValueError``) with a stable ``reason`` code.
"""

import ipaddress
import re

from middleman.destinations import parse_host_regex, parse_host_rule
from middleman.exceptions import InvalidRuleError

RULE_TYPE_IP = "ip"
RULE_TYPE_PATH = "path"
RULE_TYPE_HOST = "host"
RULE_TYPE_HOST_RE = "host_re"

# A wildcard IP rule is a non-empty prefix of an IPv4/IPv6 address + "*".
_IP_PREFIX_WILDCARD = re.compile(r"[0-9a-fA-F:.]+\*")


def parse_ip_network(value: str):
    """
    Parse an IP rule written in CIDR notation (e.g. ``10.0.0.0/24``).

    Returns an ``IPv4Network``/``IPv6Network`` when ``value`` is CIDR notation,
    ``None`` when it is not (exact IPs and ``*`` wildcard rules), and raises
    ``ValueError`` when it looks like CIDR but is malformed (e.g. ``/33``).
    Host bits are tolerated (``10.0.0.5/24`` is read as ``10.0.0.0/24``).
    """
    value = (value or "").strip()
    if "/" not in value:
        return None
    return ipaddress.ip_network(value, strict=False)


def validate_ip_rule(value: str) -> None:
    """Client IP rule: exact IP, CIDR subnet or address prefix + ``*``."""
    raw = (value or "").strip()
    if not raw:
        raise InvalidRuleError("empty", "IP rule cannot be empty.", RULE_TYPE_IP, value)
    if "/" in raw:
        try:
            parse_ip_network(raw)
        except ValueError:
            raise InvalidRuleError(
                "invalid_subnet", "'{}' is not a valid CIDR subnet.".format(raw), RULE_TYPE_IP, value
            )
        return
    if raw.endswith("*"):
        if not _IP_PREFIX_WILDCARD.fullmatch(raw):
            raise InvalidRuleError(
                "invalid_ip_wildcard",
                "'{}' is not a valid IP wildcard; use an address prefix such as 10.0.0.* "
                "(or a CIDR subnet such as 10.0.0.0/24).".format(raw),
                RULE_TYPE_IP, value,
            )
        return
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        raise InvalidRuleError(
            "invalid_ip",
            "'{}' is not a valid IP address, CIDR subnet or IP wildcard.".format(raw),
            RULE_TYPE_IP, value,
        )


def validate_path_rule(value: str) -> None:
    """Requested path rule: exact path or prefix + ``*`` (paths look like ``admin/``)."""
    raw = (value or "").strip()
    if not raw:
        raise InvalidRuleError("empty", "Path rule cannot be empty.", RULE_TYPE_PATH, value)
    if raw.startswith("/"):
        raise InvalidRuleError(
            "path_leading_slash",
            "Paths are matched without a leading '/'; write '{}'.".format(raw.lstrip("/")),
            RULE_TYPE_PATH, value,
        )
    if "://" in raw or any(c.isspace() for c in raw):
        raise InvalidRuleError(
            "invalid_path",
            "'{}' is not a path; enter something like admin/ or admin/*.".format(raw),
            RULE_TYPE_PATH, value,
        )
    if "*" in raw[:-1]:
        raise InvalidRuleError(
            "unsupported_wildcard",
            "'*' is only supported at the end of a path rule (e.g. admin/*).",
            RULE_TYPE_PATH, value,
        )
    if not raw.endswith(("/", "*")):
        # ProxyView always appends '/', so an exact rule without it never matches.
        raise InvalidRuleError(
            "path_missing_trailing_slash",
            "Proxied paths always end with '/'; write '{0}/' (exact) or '{0}*' (prefix).".format(raw),
            RULE_TYPE_PATH, value,
        )


def validate_rule(rule_type: str, value: str):
    """
    Validate ``value`` for ``rule_type``. Returns the parsed HostRule for
    host/host_re rules and None otherwise; raises InvalidRuleError.
    """
    if rule_type == RULE_TYPE_IP:
        return validate_ip_rule(value)
    if rule_type == RULE_TYPE_PATH:
        return validate_path_rule(value)
    if rule_type == RULE_TYPE_HOST:
        return parse_host_rule(value)
    if rule_type == RULE_TYPE_HOST_RE:
        return parse_host_regex(value)
    raise InvalidRuleError(
        "unknown_rule_type", "Unknown rule type {!r}.".format(rule_type), rule_type, value
    )
