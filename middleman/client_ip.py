"""
Trustworthy client IP resolution.

``X-Forwarded-For`` is written by whoever sends the request, so a client can
put any address in it. The only address a client cannot forge is the TCP peer
(``REMOTE_ADDR``). The header is therefore only believed when the peer is one
of *our* proxies, listed in ``settings.TRUSTED_PROXIES`` (IPs or CIDRs):

* peer not trusted (the default: nothing is trusted) -> the peer is the client
  and the header is ignored;
* peer trusted -> walk the header from right to left (each proxy appends the
  address it saw), skipping trusted proxies; the first untrusted address is
  the client. Entries to the left of it were supplied by the client and are
  never used.

Encrypting or hashing the IP would not help: whoever produces the token must
already know the real address, which is exactly the trust problem above.
"""

import ipaddress
import logging
from functools import lru_cache
from typing import Iterable, NamedTuple, Optional, Tuple

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)

# Peers already warned about, so a misconfiguration is reported without
# flooding the logs with one line per request.
_WARNED_UNTRUSTED_PEERS = set()
_MAX_WARNED_PEERS = 1024


def _canonical(address):
    """Unwrap IPv4-mapped IPv6 (::ffff:10.0.0.1 from dual-stack sockets)."""
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped if mapped is not None else address


def parse_address(value: str):
    """
    Parse one address as written by proxies: ``1.2.3.4``, ``1.2.3.4:5678``,
    ``2001:db8::1`` or ``[2001:db8::1]:443``. Returns None if malformed.
    """
    candidate = (value or "").strip()
    if candidate.startswith("["):
        candidate = candidate[1:].split("]", 1)[0]
    elif candidate.count(":") == 1:  # IPv4 with a port
        candidate = candidate.split(":", 1)[0]
    try:
        return _canonical(ipaddress.ip_address(candidate))
    except ValueError:
        return None


@lru_cache(maxsize=8)
def parse_trusted_proxies(values: Tuple[str, ...]):
    """Parse TRUSTED_PROXIES entries; raises ImproperlyConfigured on typos."""
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError:
            raise ImproperlyConfigured(
                "TRUSTED_PROXIES contains {!r}, which is not an IP address or CIDR subnet.".format(value)
            )
    return tuple(networks)


def trusted_networks():
    return parse_trusted_proxies(tuple(getattr(settings, "TRUSTED_PROXIES", ()) or ()))


def _is_trusted(address, networks: Iterable) -> bool:
    return any(address.version == net.version and address in net for net in networks)


def _warn_untrusted_peer_once(peer) -> None:
    if peer in _WARNED_UNTRUSTED_PEERS or len(_WARNED_UNTRUSTED_PEERS) >= _MAX_WARNED_PEERS:
        return
    _WARNED_UNTRUSTED_PEERS.add(peer)
    logger.warning(
        "[ClientIP] Ignoring X-Forwarded-For from a peer that is not in TRUSTED_PROXIES "
        "| peer=%s hint=%r",
        peer,
        "if this peer is your load balancer or reverse proxy, add it to TRUSTED_PROXIES",
    )


# Headers some clients/proxies use to claim an origin address. The proxy
# never trusts them; they are only inspected to detect spoofing attempts.
OTHER_FORWARDING_HEADERS = (
    "HTTP_X_REAL_IP", "HTTP_FORWARDED", "HTTP_X_CLIENT_IP", "HTTP_TRUE_CLIENT_IP",
    "HTTP_CF_CONNECTING_IP", "HTTP_X_ORIGINATING_IP", "HTTP_X_FORWARDED_HOST",
)


class ClientResolution(NamedTuple):
    ip: Optional[str]
    peer: Optional[str]
    peer_trusted: bool
    # Forwarding data written by the client (not by our trusted proxies),
    # e.g. the whole X-Forwarded-For of an untrusted peer. Never used to
    # identify the client; abuse detection looks for rotating values here.
    client_supplied_forwarding: Tuple[str, ...]


def resolve_client(meta) -> ClientResolution:
    """Resolve the client IP and describe how it was obtained."""
    peer = parse_address(meta.get("REMOTE_ADDR"))
    if peer is None:
        logger.error(
            "[ClientIP] Request has no usable REMOTE_ADDR | remote_addr=%r",
            meta.get("REMOTE_ADDR"),
        )
        return ClientResolution(None, None, False, ())

    other = tuple(
        "{}={}".format(name[5:], meta[name]) for name in OTHER_FORWARDING_HEADERS if meta.get(name)
    )
    forwarded_for = meta.get("HTTP_X_FORWARDED_FOR")
    networks = trusted_networks()
    if not _is_trusted(peer, networks):
        if forwarded_for:
            _warn_untrusted_peer_once(peer)
        supplied = (("X_FORWARDED_FOR=" + forwarded_for,) if forwarded_for else ()) + other
        return ClientResolution(str(peer), str(peer), False, supplied)

    if not forwarded_for:
        logger.debug("[ClientIP] Trusted proxy sent no X-Forwarded-For | peer=%s", peer)
        return ClientResolution(str(peer), str(peer), True, other)

    entries = forwarded_for.split(",")
    client = peer
    for index in range(len(entries) - 1, -1, -1):
        entry = entries[index]
        address = parse_address(entry)
        if address is None:
            # Stop at garbage rather than guess; the nearest verified hop is used.
            logger.warning(
                "[ClientIP] Malformed X-Forwarded-For entry; using the nearest verified hop "
                "| entry=%r header=%r used=%s",
                entry.strip(), forwarded_for, client,
            )
            return ClientResolution(str(client), str(peer), True, ("X_FORWARDED_FOR=" + forwarded_for,) + other)
        client = address
        if not _is_trusted(address, networks):
            # Everything left of the client was written by the client itself.
            left = ",".join(e.strip() for e in entries[:index])
            supplied = (("X_FORWARDED_FOR=" + left,) if left else ()) + other
            return ClientResolution(str(address), str(peer), True, supplied)
    # Every hop is one of our proxies: the left-most one is the origin.
    return ClientResolution(str(client), str(peer), True, other)


def get_client_ip(meta) -> Optional[str]:
    """Resolve the client IP from a request's META; None if REMOTE_ADDR is unusable."""
    return resolve_client(meta).ip


def axes_client_ip(request) -> Optional[str]:
    """AXES_CLIENT_IP_CALLABLE: login lockouts use the same trusted client IP."""
    if not request.META.get("REMOTE_ADDR"):
        # Programmatic logins (e.g. Client.force_login) have no network peer;
        # real HTTP requests always do.
        return None
    return get_client_ip(request.META)
