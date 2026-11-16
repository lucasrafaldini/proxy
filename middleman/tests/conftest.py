import pytest


@pytest.fixture(autouse=True)
def reset_process_state():
    """
    Per-process caches and warn-once sets survive between tests, but test
    transactions are rolled back without firing post_delete. Reset them so
    no test sees another test's state.
    """
    from middleman import client_ip, hosts, services

    hosts.invalidate_cache()
    hosts._WARNED_HOSTS.clear()
    client_ip._WARNED_UNTRUSTED_PEERS.clear()
    services._REPORTED_INVALID_RULES.clear()
    yield
    hosts.invalidate_cache()
