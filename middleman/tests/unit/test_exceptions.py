from middleman.exceptions import (
    AccessNotRegisteredException,
    BlacklistedAccessException,
    ExceededRequestsLimitException,
    ServerNotRespondingException,
)


def test_server_not_responding_str():
    assert "not responding" in str(ServerNotRespondingException("https://example.com"))


def test_exceeded_requests_limit_str():
    msg = str(ExceededRequestsLimitException("10.0.0.1", "index/"))
    assert "10.0.0.1" in msg
    assert "index/" in msg


def test_access_not_registered_str():
    msg = str(AccessNotRegisteredException("k1", "10.0.0.1", "index/"))
    assert "k1" in msg
    assert "10.0.0.1" in msg


def test_blacklisted_access_str():
    msg = str(BlacklistedAccessException("10.0.0.1", "admin/", "path", "admin/*"))
    assert "blocked" in msg
    assert "admin/*" in msg
