"""
End-to-end: real HTTP from a client to a live proxy server, and from the
proxy to a real upstream server. Covers the main flows operators rely on.
"""

import re

import pytest
from urllib3.util import SKIP_HEADER

from middleman.models import AccessEntry, BlacklistRule
from middleman.services import ProxyManager


pytestmark = pytest.mark.functional

POLICY_403 = re.compile(r"Forbidden: the request was blocked by the proxy's access policy \(ref [0-9a-f]{12}\)\.")
SQLMAP = "sqlmap/1.7.2#stable (https://sqlmap.org)"
BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"


def key_for(path):
    return ProxyManager("")._create_unique_key("127.0.0.1", path)


def test_request_is_proxied_streamed_and_counted(anonymous, operator, upstream):
    response = anonymous.get("/proxy/home/", headers={"User-Agent": BROWSER})

    assert response.status_code == 200
    assert response.text == "upstream saw /home/"
    assert (response.headers["X-RateLimit-Limit"], response.headers["X-RateLimit-Remaining"]) == ("100", "99")
    assert upstream.hits == [("HEAD", "/home/"), ("GET", "/home/")]

    entry = operator.get("/registry/", params={"key": key_for("home/")}).json()
    assert (entry["ip"], entry["path"], entry["already_requested"]) == ("127.0.0.1", "home/", 1)


def test_user_agent_rule_lifecycle(anonymous, operator, upstream):
    created = operator.post("/", data={"action": "create", "rule_type": "user_agent", "value": "sqlmap"})
    assert created.status_code == 200
    rule = BlacklistRule.objects.get(rule_type="user_agent", value="sqlmap")

    blocked = anonymous.get("/proxy/home/", headers={"User-Agent": SQLMAP})
    assert blocked.status_code == 403
    assert POLICY_403.fullmatch(blocked.text)
    assert "sqlmap" not in blocked.text and "X-RateLimit-Limit" not in blocked.headers
    assert upstream.hits == []  # the target was never contacted
    assert not AccessEntry.objects.exists()  # and nothing was counted

    assert anonymous.get("/proxy/home/", headers={"User-Agent": BROWSER}).status_code == 200

    operator.post("/", data={"action": "toggle", "rule_id": rule.pk})
    assert anonymous.get("/proxy/home/", headers={"User-Agent": SQLMAP}).status_code == 200


def test_missing_user_agent_can_be_blocked_with_an_empty_regex(anonymous, operator, upstream):
    operator.post("/", data={"action": "create", "rule_type": "user_agent_re", "value": "^$"})
    # requests/urllib3 add a default User-Agent; SKIP_HEADER really sends none.
    assert anonymous.get("/proxy/home/", headers={"User-Agent": SKIP_HEADER}).status_code == 403
    assert anonymous.get("/proxy/home/", headers={"User-Agent": BROWSER}).status_code == 200


def test_invalid_rule_is_rejected_with_400(operator):
    response = operator.post("/", data={"action": "create", "rule_type": "user_agent_re", "value": ".*"})
    assert response.status_code == 400
    assert "matches every User-Agent" in response.text
    assert not BlacklistRule.objects.exists()


def test_rate_limit_429_and_operator_reset(anonymous, operator, upstream):
    assert anonymous.get("/proxy/home/").status_code == 200
    patched = operator.patch(
        "/registry/", json={"key": key_for("home/"), "action": "update_max_requests", "max_requests": 2}
    )
    assert patched.status_code == 200

    assert anonymous.get("/proxy/home/").status_code == 200
    limited = anonymous.get("/proxy/home/")
    assert limited.status_code == 429
    assert limited.headers["X-RateLimit-Remaining"] == "0"

    operator.patch("/registry/", json={"key": key_for("home/"), "action": "reset_already_requested"})
    assert anonymous.get("/proxy/home/").status_code == 200


def test_redirect_to_a_blocked_host_is_refused_and_not_counted(anonymous, operator, upstream):
    operator.post("/", data={"action": "create", "rule_type": "host", "value": upstream.blocked_redirect_host})

    response = anonymous.get("/proxy/hop/")

    assert response.status_code == 403
    assert POLICY_403.fullmatch(response.text)
    assert upstream.blocked_redirect_host not in response.text
    assert upstream.hits == [("HEAD", "/hop/"), ("GET", "/hop/")]  # never followed
    assert AccessEntry.objects.get().already_requested == 0


def test_target_redirecting_the_availability_check_is_a_502(anonymous, upstream):
    # HEAD must answer 200; a redirect there is treated as "target not available".
    response = anonymous.get("/proxy/moved/")
    assert response.status_code == 502
    assert response.text == "Bad gateway: the target server is not available."
    assert upstream.hits == [("HEAD", "/moved/")]
    assert AccessEntry.objects.get().already_requested == 0


def test_ip_rule_blocks_the_client(anonymous, operator, upstream):
    operator.post("/", data={"action": "create", "rule_type": "ip", "value": "127.0.0.0/8"})
    assert anonymous.get("/proxy/home/").status_code == 403
    assert upstream.hits == []


def test_public_pages_and_insights(anonymous, upstream):
    anonymous.get("/proxy/home/")

    dashboard = anonymous.get("/")
    assert dashboard.status_code == 200
    # No per-client data for anonymous visitors (the client and the target share
    # 127.0.0.1 here, so ignore the target URL, which the dashboard does show).
    target_url = "http://127.0.0.1:{}/".format(upstream.server_address[1])
    assert "127.0.0.1" not in dashboard.text.replace(target_url, "")
    assert "visible to operators only" in dashboard.text

    insights = anonymous.get("/insights/").json()
    assert (insights["total_entries"], insights["unique_paths"]) == (1, 1)


def test_management_api_requires_credentials(anonymous):
    response = anonymous.get("/registry/")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_unknown_host_header_is_rejected(anonymous):
    assert anonymous.get("/insights/", headers={"Host": "evil.example"}).status_code == 400


def test_request_id_ties_the_response_to_its_log_lines(anonymous, operator, upstream, caplog):
    operator.post("/", data={"action": "create", "rule_type": "user_agent", "value": "sqlmap"})
    with caplog.at_level("INFO", logger="middleman"):
        blocked = anonymous.get("/proxy/home/", headers={"User-Agent": SQLMAP})
    request_id = blocked.headers["X-Request-ID"]
    assert blocked.text.endswith("(ref {}).".format(request_id))
    lines = [record.getMessage() for record in caplog.records
             if record.name == "middleman.views" and "ref={}".format(request_id) in record.getMessage()]
    assert len(lines) == 1 and "rule_type=user_agent rule='sqlmap'" in lines[0]
    assert any(record.name == "middleman.access" and "403" in record.getMessage() for record in caplog.records)
