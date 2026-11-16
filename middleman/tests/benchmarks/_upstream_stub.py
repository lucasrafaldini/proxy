"""
Slow upstream for bench_throughput.py, run as its own process so it never
competes with the benchmark's client threads for the GIL (in-process, the
GIL convoy effect made the stub itself the bottleneck).

    python _upstream_stub.py <latency_seconds>   # prints the port, serves until killed
"""

import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SlowUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Headers and body are separate writes: without this, Nagle + the client's
    # delayed ACK add up to 40 ms per response.
    disable_nagle_algorithm = True
    latency = 0.05

    def _reply(self):
        time.sleep(self.latency / 2)  # HEAD and GET each take half
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()

    def do_HEAD(self):
        self._reply()

    def do_GET(self):
        self._reply()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class UpstreamServer(ThreadingHTTPServer):
    daemon_threads = True
    # socketserver's default backlog (5) drops connections under many
    # concurrent clients (SYN retries of ~1 s).
    request_queue_size = 128


if __name__ == "__main__":
    SlowUpstream.latency = float(sys.argv[1])
    server = UpstreamServer(("127.0.0.1", 0), SlowUpstream)
    print(server.server_address[1], flush=True)
    server.serve_forever()
