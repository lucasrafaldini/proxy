"""
Destination ("site") matching for ``host`` blacklist rules.

The same site can be written in many ways (``EXAMPLE.com.``, ``user@example.com:8443``,
``bücher.de`` vs ``xn--bcher-kva.de``, ``2130706433`` for ``127.0.0.1``...). Every
spelling is a potential bypass, so hosts are reduced to one canonical form before
they are compared.

Host rule syntax, from narrowest to broadest:

``example.com``
    Exactly this host. Does NOT match ``www.example.com`` or the site's IP
    address, so an admin can block one site without collateral damage.
``*.example.com``
    Any subdomain of ``example.com`` at any depth (``a.example.com``,
    ``a.b.example.com``). Does NOT match ``example.com`` itself; add both rules
    to block a whole domain. Matching is done on label boundaries, so
    ``badexample.com`` is never matched.
``93.184.215.14`` / ``93.184.215.0/24`` / ``2606:2800::/32``
    Destination IP address or subnet. Matches URLs that use an IP literal (in
    any notation the resolver accepts) *and* host names that resolve into it.
    Deliberately opt-in: many unrelated sites can share one IP (CDNs, shared
    hosting), so an IP rule can block more than one site.

Regular expressions are a separate rule type (``host_re``) rather than a
prefix inside a host rule, so the admin has to choose them explicitly. See
``parse_host_regex`` for the format they must follow.
"""

import functools
import ipaddress
import re
import socket
from typing import Callable, Iterable, List, NamedTuple, Optional, Union

import re2

from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url

from middleman.exceptions import InvalidRuleError

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
Resolver = Callable[[str], Iterable[IPAddress]]

SUBDOMAIN_PREFIX = "*."

# Regex (host_re) limits. RE2 guarantees matching time linear in the input,
# so there is no catastrophic backtracking; these limits bound the per-request
# cost and catch patterns that are almost certainly mistakes.
MAX_REGEX_LENGTH = 200
# Compiled RE2 program size. Typical host patterns are < 100; the realistic
# upper end, "([a-z0-9-]{1,63}\\.)*tracker\\.(com|net)", is ~600. Nested
# bounded repetitions such as "(x{1,100}){1,10}" are > 2000.
MAX_REGEX_PROGRAM_SIZE = 1000
REGEX_MAX_MEM = 1 << 20  # bytes RE2 may use to compile one pattern
# Hosts used to detect patterns that would match (block) every destination.
_MATCH_ALL_PROBES = (
    "example.com", "a", "localhost", "xn--bcher-kva.de", "127.0.0.1", "::1",
    "some-random.host.test", "0",
)

# Legacy IPv4 spellings understood by inet_aton()/getaddrinfo(): "127.1",
# "2130706433", "0x7f.0.0.1", "0177.0.0.1"...
_NUMERIC_IPV4 = re.compile(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}")
_HOST_LABEL = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?")


class HostRule(NamedTuple):
    kind: str  # "exact" | "subdomains" | "network" | "regex"
    target: object  # str | IPNetwork | compiled RE2 pattern


def _invalid(reason: str, message: str, value: str, rule_type: str = "host"):
    return InvalidRuleError(reason, message, rule_type=rule_type, value=value)


def parse_ip_literal(host: str) -> Optional[IPAddress]:
    """Return the IP address ``host`` denotes if it is an IP literal, else None."""
    if not host:
        return None
    candidate = host.strip().lower()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    if _NUMERIC_IPV4.fullmatch(candidate):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(candidate))
        except OSError:
            return None
    return None


def normalize_host(host: str) -> str:
    """Canonical form of a host: lowercase, no trailing dot, IDNA, canonical IPs."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    address = parse_ip_literal(host)
    if address is not None:
        return str(address)
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def host_from_url(url: str) -> str:
    """
    Canonical host of ``url`` (userinfo, port and brackets removed).

    Uses urllib3's parser on purpose: it is what ``requests`` uses to decide
    where to connect. ``urllib.parse`` disagrees on inputs such as
    ``http://blocked.com\\@allowed.com/`` (it reports ``allowed.com`` while
    urllib3 connects to ``blocked.com``), which would be a bypass.
    """
    try:
        return normalize_host(parse_url(url).host or "")
    except (LocationParseError, ValueError):
        return ""


def _is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    return all(_HOST_LABEL.fullmatch(label) for label in host.split("."))


def parse_host_rule(value: str) -> HostRule:
    """Parse a ``host`` rule value. Raises ``InvalidRuleError`` (a ValueError)."""
    raw = (value or "").strip()
    if not raw:
        raise _invalid("empty", "Host rule cannot be empty.", value)

    if raw[:3].lower() == "re:":
        raise _invalid(
            "regex_in_host_rule",
            "Regular expressions are not allowed in a Host rule; "
            "choose the 'Host (regex)' rule type and enter the pattern without 're:'.",
            value,
        )

    if "://" in raw:
        raise _invalid("url_not_host", "Enter only the host (example.com), not a URL.", value)

    if "/" in raw:
        try:
            return HostRule("network", ipaddress.ip_network(raw, strict=False))
        except ValueError:
            raise _invalid("invalid_subnet", "'{}' is not a valid IP subnet.".format(raw), value)

    address = parse_ip_literal(raw)
    if address is not None:
        return HostRule("network", ipaddress.ip_network(address))

    if raw.startswith(SUBDOMAIN_PREFIX):
        base = normalize_host(raw[len(SUBDOMAIN_PREFIX):])
        if parse_ip_literal(base) is not None or not _is_valid_hostname(base):
            raise _invalid(
                "invalid_subdomain_rule",
                "'{}' is not a valid '*.domain' rule.".format(raw),
                value,
            )
        return HostRule("subdomains", base)

    if "*" in raw:
        raise _invalid(
            "unsupported_wildcard",
            "Wildcards are only supported as a leading '*.' (e.g. *.example.com); "
            "use a 'Host (regex)' rule for anything else.",
            value,
        )
    host = normalize_host(raw)
    if not _is_valid_hostname(host):
        raise _invalid(
            "invalid_host",
            "'{}' is not a valid host name (ports, paths and user info are not allowed).".format(raw),
            value,
        )
    return HostRule("exact", host)


def _unescaped_dot_position(pattern: str) -> Optional[int]:
    """
    Position of the first '.' that is outside a character class, not escaped
    and not followed by a quantifier - i.e. a dot that was almost certainly
    meant as a literal label separator (``example.com`` instead of
    ``example\\.com``). Returns None if there is none.
    """
    i, in_class, length = 0, False, len(pattern)
    while i < length:
        char = pattern[i]
        if char == "\\":
            i += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
            # A ']' right after '[' or '[^' is a literal, not the end.
            if pattern[i + 1:i + 2] == "^":
                i += 1
            if pattern[i + 1:i + 2] == "]":
                i += 1
        elif char == "." and pattern[i + 1:i + 2] not in ("*", "+", "?", "{"):
            return i
        i += 1
    return None


def _re2_options():
    options = re2.Options()
    options.case_sensitive = False
    options.log_errors = False  # errors are raised and logged by us, not printed by C++
    options.max_mem = REGEX_MAX_MEM
    return options


@functools.lru_cache(maxsize=1024)
def _compile_regex(pattern: str):
    return re2.compile(pattern, _re2_options())


def compile_rule_regex(pattern: str, value: str, rule_type: str):
    """
    Compile a rule regex with RE2 (case-insensitive), shared by every regex
    rule type. Raises ``InvalidRuleError`` with reason ``regex_syntax`` or
    ``regex_too_complex``; type-specific lints are left to the caller.
    """
    try:
        compiled = _compile_regex(pattern)
    except re2.error as exc:
        detail = exc.args[0] if exc.args else exc
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", "replace")
        raise _invalid(
            "regex_syntax",
            "Invalid regex: {}. Rules use RE2 syntax (no backreferences or lookarounds).".format(detail),
            value, rule_type,
        )
    if compiled.programsize > MAX_REGEX_PROGRAM_SIZE:
        raise _invalid(
            "regex_too_complex",
            "Regex is too complex (compiled size {} > {}); simplify large or nested "
            "repetitions such as {{1,100}}.".format(compiled.programsize, MAX_REGEX_PROGRAM_SIZE),
            value, rule_type,
        )
    return compiled


def parse_host_regex(value: str) -> HostRule:
    """
    Parse and lint a ``host_re`` rule. Raises ``InvalidRuleError`` (a ValueError)
    whose ``reason`` says what is wrong.

    The pattern is full-matched, case-insensitively, against the canonical
    host (lowercase ASCII/punycode, no port). It must:

    * be RE2 syntax: linear-time matching, so no backreferences or lookarounds;
    * be at most MAX_REGEX_LENGTH characters and MAX_REGEX_PROGRAM_SIZE compiled;
    * contain only ASCII (hosts are matched in punycode: xn--bcher-kva\\.de);
    * not contain whitespace, '/' or '@' (it matches a host, not a URL);
    * escape literal dots (``example\\.com``); '.' is only accepted as a
      wildcard when quantified (``.*``, ``.+``, ``.?``, ``.{n}``);
    * not match every host (use a path rule ``*`` to block everything).
    """
    pattern = (value or "").strip()
    rule_type = "host_re"
    if not pattern:
        raise _invalid("empty", "Regex rule cannot be empty.", value, rule_type)
    if pattern[:3].lower() == "re:":
        raise _invalid(
            "regex_prefix",
            "Enter the pattern without the 're:' prefix; the rule type already says it is a regex.",
            value, rule_type,
        )
    if len(pattern) > MAX_REGEX_LENGTH:
        raise _invalid(
            "regex_too_long",
            "Regex is {} characters long; the maximum is {}.".format(len(pattern), MAX_REGEX_LENGTH),
            value, rule_type,
        )
    if not pattern.isascii():
        raise _invalid(
            "regex_non_ascii",
            "Regex must be ASCII: hosts are matched in punycode form "
            "(write xn--bcher-kva\\.de, not bücher\\.de).",
            value, rule_type,
        )
    forbidden = sorted({c for c in pattern if c.isspace() or c in "/@"})
    if forbidden:
        raise _invalid(
            "regex_not_host",
            "Regex is matched against the host name only (no scheme, path, user info "
            "or spaces); remove {}.".format(", ".join(repr(c) for c in forbidden)),
            value, rule_type,
        )
    dot = _unescaped_dot_position(pattern)
    if dot is not None:
        raise _invalid(
            "regex_unescaped_dot",
            "Unescaped '.' at position {} matches any character; write '\\.' for a "
            "literal dot, or '.*' / '.+' for a wildcard.".format(dot),
            value, rule_type,
        )
    compiled = compile_rule_regex(pattern, value, rule_type)
    if all(compiled.fullmatch(probe) for probe in _MATCH_ALL_PROBES):
        raise _invalid(
            "regex_matches_everything",
            "Regex matches every host, which would block all destinations; "
            "make it specific (e.g. (www\\.)?example\\.com).",
            value, rule_type,
        )
    return HostRule("regex", compiled)


def system_resolver(host: str) -> List[IPAddress]:
    """Resolve ``host`` with the system resolver; returns [] if it cannot."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return []
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return addresses


def _with_ipv4_mapped(addresses: Iterable[IPAddress]) -> List[IPAddress]:
    """Also consider the IPv4 address inside IPv4-mapped IPv6 (::ffff:1.2.3.4)."""
    result = []
    for address in addresses:
        result.append(address)
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None:
            result.append(mapped)
    return result


def host_matches(rule: HostRule, host: str, resolver: Optional[Resolver] = None) -> bool:
    """True if the (already canonical or raw) ``host`` is matched by ``rule``."""
    host = normalize_host(host)
    if not host:
        return False
    if rule.kind == "exact":
        return host == rule.target
    if rule.kind == "subdomains":
        return host.endswith("." + rule.target)
    if rule.kind == "regex":
        return rule.target.fullmatch(host) is not None
    if rule.kind == "network":
        literal = parse_ip_literal(host)
        if literal is not None:
            addresses = [literal]
        else:
            addresses = list((resolver or system_resolver)(host))
        return any(address in rule.target for address in _with_ipv4_mapped(addresses))
    return False
