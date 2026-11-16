"""
Keep-alive connections to the target (middleman/upstream.py), against a real
local HTTP server that records every TCP connection and request it receives.
"""

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from middleman import upstream

BODY = b"hello from upstream " * 10
BIG_BODY = b"x" * (1024 * 1024)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.server.connections.append(self.client_address)

    def do_HEAD(self):
        self._respond(send_body=False)

    def do_GET(self):
        self._respond(send_body=True)

    def _respond(self, send_body):
        server = self.server
        server.requests.append((self.command, self.path, self.headers.get("Cookie")))
        body = BIG_BODY if self.path.startswith("/big/") else BODY
        if self.path.startswith("/redirect/") and self.command == "GET":
            self.send_response(302)
            self.send_header("Location", "/home/")
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"moved")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        # A target that sets a cookie for the client of *this* request.
        self.send_header("Set-Cookie", "session=for-{}; Path=/".format(self.path.strip("/")))
        self.end_headers()
        if send_body:
            self.wfile.write(body)
        if server.close_after_response:
            # Keep-alive advertised, then the server silently drops the idle connection.
            self.close_connection = True

    def log_message(self, *args):
        pass


class _UpstreamTestServer(ThreadingHTTPServer):
    request_queue_size = 64


class UpstreamServerMixin:
    def setUp(self):
        super().setUp()
        upstream.close_sessions()
        self.server = _UpstreamTestServer(("127.0.0.1", 0), _Handler)
        self.server.connections, self.server.requests = [], []
        self.server.close_after_response = False
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:{}/".format(self.server.server_address[1])

    def tearDown(self):
        upstream.close_sessions()
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def proxy(self, path="home"):
        with patch("middleman.views.BASE_TARGET_URL", self.base):
            response = APIClient().get("/proxy/{}/".format(path))
        body = b"".join(response.streaming_content) if response.streaming else response.content
        return response, body


class KeepAliveTest(UpstreamServerMixin, TestCase):
    def test_proxied_requests_reuse_one_connection(self):
        for _ in range(3):
            response, body = self.proxy()
            self.assertEqual((response.status_code, body), (200, BODY))
        self.assertEqual([method for method, _, _ in self.server.requests], ["HEAD", "GET"] * 3)
        self.assertEqual(len(self.server.connections), 1)

    @override_settings(UPSTREAM_KEEPALIVE=False)
    def test_keepalive_can_be_turned_off(self):
        for _ in range(3):
            self.assertEqual(self.proxy()[1], BODY)
        self.assertEqual(len(self.server.connections), 6)  # one per HEAD and GET, as before 2.1.0

    def test_cookies_set_by_the_target_never_reach_other_requests(self):
        self.proxy("alice")
        self.proxy("bob")
        self.assertEqual(len(self.server.connections), 1)  # same pooled session...
        self.assertEqual([cookie for _, _, cookie in self.server.requests], [None] * 4)  # ...no cookie sent
        self.assertEqual(len(upstream.session().cookies), 0)

    def test_large_bodies_stream_intact_and_the_connection_is_reused(self):
        self.assertEqual(self.proxy("big")[1], BIG_BODY)
        self.assertEqual(self.proxy("home")[1], BODY)
        self.assertEqual(len(self.server.connections), 1)

    def test_abandoned_body_closes_its_connection_instead_of_reusing_it(self):
        response = upstream.get(self.base + "big/", stream=True, timeout=10)
        chunks = upstream.stream_body(response, chunk_size=1024)
        next(chunks)  # the client read 1 KB of 1 MB, then went away
        chunks.close()
        self.assertTrue(response.raw.closed)
        # The next request cannot get the half-read connection: it opens a new one.
        self.assertEqual(upstream.get(self.base + "home/", timeout=10).content, BODY)
        self.assertEqual(len(self.server.connections), 2)

    def test_connections_closed_by_the_server_are_replaced_transparently(self):
        self.server.close_after_response = True
        for _ in range(3):
            self.assertEqual(self.proxy()[1], BODY)
            time.sleep(0.05)  # let the server's FIN arrive, as between real requests
        self.assertEqual(len(self.server.connections), 6)

    def test_small_redirect_bodies_are_drained_for_reuse(self):
        with patch("middleman.views.BASE_TARGET_URL", self.base):
            response = APIClient().get("/proxy/redirect/")
        self.assertEqual(b"".join(response.streaming_content), BODY)
        self.assertEqual([(m, p) for m, p, _ in self.server.requests],
                         [("HEAD", "/redirect/"), ("GET", "/redirect/"), ("GET", "/home/")])
        self.assertEqual(len(self.server.connections), 1)

    def test_short_lived_threads_share_the_pool(self):
        # Thread-per-request servers (runserver): every request in a new thread
        # must still reuse the pooled connection, not open (and leak) its own.
        for _ in range(5):
            thread = threading.Thread(target=lambda: upstream.get(self.base + "home/", timeout=10).content)
            thread.start()
            thread.join()
        self.assertEqual(len(self.server.connections), 1)

    def test_concurrent_threads_are_served_without_cross_talk(self):
        results, errors = [], []

        def fetch(name):
            try:
                response = upstream.get(self.base + "{}/".format(name), timeout=10)
                results.append(response.content)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=fetch, args=("client{}".format(i),)) for i in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(results, [BODY] * 16)
        self.assertLessEqual(len(self.server.connections), 16)
        self.assertEqual({cookie for _, _, cookie in self.server.requests}, {None})

    def test_a_forked_process_gets_its_own_session(self):
        parent = upstream.session()
        self.assertIs(upstream.session(), parent)
        with patch("middleman.upstream.os.getpid", return_value=-1):
            child = upstream.session()
        self.assertIsNot(child, parent)

    def test_timeouts_and_no_redirects_are_unchanged(self):
        with patch.object(upstream.session(), "get", wraps=upstream.session().get) as get:
            self.proxy()
        kwargs = get.call_args.kwargs
        self.assertEqual((kwargs["timeout"], kwargs["allow_redirects"], kwargs["stream"]), (10, False, True))


class DiscardTest(TestCase):
    def test_unknown_or_large_bodies_are_closed(self):
        class Response:
            headers = {"content-length": str(10 * 1024 * 1024)}
            raw = None
            closed = False

            def close(self):
                self.closed = True

        response = Response()
        upstream.discard(response)
        self.assertTrue(response.closed)


class _SlowHandler(_Handler):
    def _respond(self, send_body):
        self.server.requests.append((self.command, self.path, None))
        time.sleep(0.5)  # longer than the client's timeout
        super()._respond(send_body)


class _AlwaysDropHandler(_Handler):
    def _respond(self, send_body):
        self.server.requests.append((self.command, self.path, None))
        self.close_connection = True  # closes without any response


class FailureModesTest(UpstreamServerMixin, TestCase):
    """Errors look exactly like before (requests' defaults); only dropped pooled connections are retried."""

    def start(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.connections, server.requests, server.close_after_response = [], [], False
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, "http://127.0.0.1:{}/home/".format(server.server_address[1])

    def exception_of(self, call, *args, **kwargs):
        try:
            call(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - the type is what we compare
            return type(exc)
        return None

    def test_same_exception_types_as_plain_requests(self):
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            refused = "http://127.0.0.1:{}/".format(sock.getsockname()[1])  # bound, not listening
            cases = {"connection refused": refused, "unknown host": "http://no-such-host.invalid/"}
            for label, url in cases.items():
                with self.subTest(label):
                    expected = self.exception_of(__import__("requests").get, url, timeout=2)
                    self.assertIsNotNone(expected)
                    self.assertIs(self.exception_of(upstream.get, url, timeout=2), expected)
                    self.assertIs(self.exception_of(upstream.head, url, timeout=2),
                                  self.exception_of(__import__("requests").head, url, timeout=2))

    def test_read_timeouts_are_not_retried(self):
        import requests as plain

        server, url = self.start(_SlowHandler)
        started = time.perf_counter()
        self.assertIs(self.exception_of(upstream.get, url, timeout=0.2), plain.ReadTimeout)
        self.assertLess(time.perf_counter() - started, 0.45)  # one timeout, not two
        self.assertEqual(len(server.requests), 1)

    def test_a_server_that_always_drops_gets_exactly_one_retry(self):
        import requests as plain

        server, url = self.start(_AlwaysDropHandler)
        self.assertIs(self.exception_of(upstream.get, url, timeout=2), plain.ConnectionError)
        self.assertEqual(len(server.requests), 2)

    def test_proxy_maps_real_failures_like_before(self):
        server, url = self.start(_SlowHandler)
        with patch("middleman.views.BASE_TARGET_URL", url.replace("home/", "")), \
                patch("middleman.services.REQUEST_TIMEOUT", 0.2), self.assertLogs("middleman", "ERROR"):
            self.assertEqual(APIClient().get("/proxy/home/").status_code, 504)
        import socket

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            closed_port = sock.getsockname()[1]
        with patch("middleman.views.BASE_TARGET_URL", "http://127.0.0.1:{}/".format(closed_port)), \
                self.assertLogs("middleman", "ERROR"):
            self.assertEqual(APIClient().get("/proxy/home/").status_code, 502)


class KeepAliveSettingTest(TestCase):
    def start(self, **env):
        import os
        import subprocess
        import sys

        from django.conf import settings

        clean = {k: v for k, v in os.environ.items() if k != "UPSTREAM_KEEPALIVE"}
        clean.update(DJANGO_SETTINGS_MODULE="proxy.test_settings", **env)
        code = "import django; django.setup(); from django.conf import settings; print(settings.UPSTREAM_KEEPALIVE)"
        return subprocess.run([sys.executable, "-c", code], cwd=settings.BASE_DIR, env=clean,
                              capture_output=True, text=True)

    def test_default_on_strict_values(self):
        self.assertEqual(self.start().stdout.strip(), "True")
        self.assertEqual(self.start(UPSTREAM_KEEPALIVE="false").stdout.strip(), "False")
        result = self.start(UPSTREAM_KEEPALIVE="sometimes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UPSTREAM_KEEPALIVE='sometimes' is not a boolean", result.stderr)


class TimeoutRequiredTest(TestCase):
    def test_upstream_calls_without_a_timeout_are_refused(self):
        for call in (upstream.get, upstream.head):
            with self.subTest(call=call.__name__):
                with self.assertRaises(TypeError):
                    call("http://127.0.0.1:9/")

    def test_failed_drain_closes_the_connection_and_leaves_a_debug_trace(self):
        from urllib3.response import HTTPResponse

        raw = HTTPResponse(body=b"", preload_content=False)

        class Response:
            headers = {"content-length": "5"}
            closed = False

            def close(self):
                self.closed = True

        response = Response()
        response.raw = raw
        with patch.object(HTTPResponse, "drain_conn", side_effect=OSError("reset")), \
                self.assertLogs("middleman.upstream", "DEBUG") as logs:
            upstream.discard(response)
        self.assertTrue(response.closed)
        self.assertIn("Could not drain a redirect body", logs.output[0])
