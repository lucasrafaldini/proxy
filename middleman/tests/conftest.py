import ipaddress
import socket

import pytest


@pytest.fixture(autouse=True)
def reset_process_state():
    """
    Per-process caches and warn-once sets survive between tests, but test
    transactions are rolled back without firing post_delete. Reset them so
    no test sees another test's state.
    """
    from middleman import client_ip, hosts, ruleset, services

    hosts.invalidate_cache()
    hosts._WARNED_HOSTS.clear()
    client_ip._WARNED_UNTRUSTED_PEERS.clear()
    services._REPORTED_INVALID_RULES.clear()
    services._compiled_setting_rules.cache_clear()
    ruleset.invalidate_cache()
    yield
    hosts.invalidate_cache()
    ruleset.invalidate_cache()


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    """
    Unit and functional tests never reach the outside world: a connection to
    anything but loopback fails the test (a mock that stopped intercepting
    must not silently turn into real network I/O). Loopback stays open for
    the functional tests' live servers.
    """
    real_connect = socket.socket.connect

    def guarded_connect(sock, address):
        host = address[0] if isinstance(address, tuple) else None
        if host is not None:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = host == "localhost"
            if not loopback:
                raise AssertionError("test tried to connect to {!r}: mock the upstream call".format(address))
        return real_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    yield
    from middleman import upstream

    upstream.close_sessions()
