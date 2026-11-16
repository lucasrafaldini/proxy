"""
Fixtures for end-to-end tests: a live Django server (pytest-django's
live_server) proxying to a real upstream HTTP server on a local socket.
Nothing in the request path is mocked.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from middleman.auth import create_token
from middleman.tests.utils.auth import make_user

BLOCKED_REDIRECT_HOST = "blocked.invalid"


class _UpstreamHandler(BaseHTTPRequestHandler):
    """
    200 with a body naming the path. GET /hop/ redirects to a host tests can
    block (HEAD answers 200: the proxy's availability check needs a 200).
    /moved/ redirects both HEAD and GET.
    """

    def do_HEAD(self):
        self._respond(send_body=False)

    def do_GET(self):
        self._respond(send_body=True)

    def _respond(self, send_body):
        self.server.hits.append((self.command, self.path))
        if (self.path.startswith("/hop/") and self.command == "GET") or self.path.startswith("/moved/"):
            self.send_response(302)
            self.send_header("Location", "http://{}/landing/".format(BLOCKED_REDIRECT_HOST))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = "upstream saw {}".format(self.path).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def log_message(self, *args):  # keep test output clean
        pass


@pytest.fixture
def upstream(monkeypatch):
    """A real HTTP target; the proxy's BASE_TARGET_URL points at it."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    server.hits = []
    server.blocked_redirect_host = BLOCKED_REDIRECT_HOST
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = "http://127.0.0.1:{}/".format(server.server_address[1])
    monkeypatch.setattr("middleman.views.BASE_TARGET_URL", url)
    yield server
    server.shutdown()
    server.server_close()


class Api:
    """Tiny HTTP client for the live server (optionally with an API token)."""

    def __init__(self, base_url, token=None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        if token:
            self.session.headers["Authorization"] = "Bearer " + token

    def close(self):
        self.session.close()

    def request(self, method, path, **kwargs):
        kwargs.setdefault("timeout", 15)
        kwargs.setdefault("allow_redirects", False)
        return self.session.request(method, self.base_url + path, **kwargs)

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)

    def patch(self, path, **kwargs):
        return self.request("PATCH", path, **kwargs)


@pytest.fixture
def anonymous(live_server):
    # Closed at teardown: a keep-alive connection left open would make the live
    # server's worker thread finish only during shutdown, racing the database
    # teardown (DatabaseError in a thread, reported as a pytest warning).
    api = Api(live_server.url)
    yield api
    api.close()


@pytest.fixture
def operator(live_server):
    _, token = create_token(make_user("operator", role="proxy-operator"), "functional-tests")
    api = Api(live_server.url, token)
    yield api
    api.close()
