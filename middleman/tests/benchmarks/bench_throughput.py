"""
Concurrency *across* requests: throughput of a real server.

A proxied request mostly waits: for the database and, above all, for the
target (HEAD, then GET). This benchmark starts the real app (``manage.py
runserver``, migrated SQLite file) in front of an upstream that takes
UPSTREAM_LATENCY seconds per request, and measures requests/second with 1, 4
and 16 concurrent clients: single-threaded (``--nothreading``), threaded (one
process), and threaded x 4 processes (like 4 gunicorn workers; clients are
spread round-robin over them). Each client has its own access entry (high limit), like
distinct users.

"direct (no proxy)" sends the same HEAD + GET straight to the upstream with
the same client code: it is the ceiling of this harness (client threads share
one GIL), so read the proxy's numbers relative to it. The table printed at
the end (requests/s) is the number to read; the pytest-benchmark rows are the
time per batch of REQUESTS requests.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import requests
from django.conf import settings

UPSTREAM_LATENCY = 0.050  # seconds per proxied request (HEAD + GET)
REQUESTS = 48
CONCURRENCY = [1, 4, 16]
# Generous: a single-threaded dev server has a listen backlog of 10, so 16
# clients trigger SYN retries (1, 2, 4, 8, 16 s...), which can exceed 30 s.
CLIENT_TIMEOUT = 120
RESULTS = {}
STUB = Path(__file__).with_name("_upstream_stub.py")


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_until_up(url, process, log_path, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("server exited: " + Path(log_path).read_text(errors="replace")[-2000:])
        try:
            requests.get(url, timeout=1)
            return
        except requests.RequestException:
            time.sleep(0.2)
    raise RuntimeError("server did not start in {}s".format(timeout))


@pytest.fixture(scope="module")
def environment():
    # The upstream runs in its own process: sharing the GIL with the client
    # threads made it the bottleneck (see _upstream_stub.py).
    upstream = subprocess.Popen([sys.executable, str(STUB), str(UPSTREAM_LATENCY)], stdout=subprocess.PIPE, text=True)
    try:
        upstream_url = "http://127.0.0.1:{}/".format(upstream.stdout.readline().strip())
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "throughput_settings.py").write_text(
                "from proxy.settings import *  # noqa\n"
                "DATABASES = {{'default': {{'ENGINE': 'django.db.backends.sqlite3', 'NAME': {!r},"
                " 'OPTIONS': {{'timeout': 20}}}}}}\n".format(str(Path(tmp, "db.sqlite3")))
            )
            env = {k: v for k, v in os.environ.items() if not k.startswith(("BLACKLISTED_", "DJANGO_", "UPSTREAM_"))}
            env.update(
                DJANGO_SETTINGS_MODULE="throughput_settings",
                PYTHONPATH=os.pathsep.join([tmp, str(settings.BASE_DIR)]),
                BASE_TARGET_URL=upstream_url,
                LOGLEVEL="ERROR",
            )
            manage = [sys.executable, str(Path(settings.BASE_DIR, "manage.py"))]
            subprocess.run(manage + ["migrate", "-v0"], env=env, check=True, cwd=settings.BASE_DIR)
            # One access entry per client, with a limit the benchmark never reaches.
            subprocess.run(manage + ["shell", "-c", (
                "from middleman.models import AccessEntry; from middleman.services import ProxyManager as P\n"
                "for i in range(max({c})):\n"
                "    p = 'client%d/' % i\n"
                "    AccessEntry.objects.create(key=P('')._create_unique_key('127.0.0.1', p), ip='127.0.0.1',"
                " path=p, max_requests=2_000_000_000)\n"
            ).format(c=CONCURRENCY)], env=env, check=True, cwd=settings.BASE_DIR)
            yield manage, env, upstream_url, tmp
    finally:
        # Even when setup fails before the yield: never leave the stub running.
        upstream.kill()
        upstream.wait(10)


MODES = {
    # mode: (server processes, threaded, upstream keep-alive)
    "direct (no proxy)": (0, None, None),
    "single-threaded": (1, False, True),
    "threaded": (1, True, True),
    "threaded x4 procs": (4, True, True),
    # Same as above with UPSTREAM_KEEPALIVE=false: new connections per call (before 2.1.0).
    "x4 procs, no keepalive": (4, True, False),
}


@pytest.fixture(scope="module", params=list(MODES))
def server(request, environment):
    """(mode, [base URLs]); clients are spread round-robin over the processes."""
    manage, env, upstream_url, tmp = environment
    processes, threaded, keepalive = MODES[request.param]
    if not processes:
        # Same clients straight to the upstream: the ceiling of this harness.
        yield request.param, [upstream_url.rstrip("/")]
        return
    started = []
    try:
        for _ in range(processes):
            port = _free_port()
            args = manage + ["runserver", "127.0.0.1:{}".format(port), "--noreload"]
            if not threaded:
                args.append("--nothreading")
            server_env = dict(env, UPSTREAM_KEEPALIVE="true" if keepalive else "false")
            # A log file, never an unread PIPE: runserver writes a line per
            # request, and a full 64 KB pipe blocks the server (it hung at
            # ~500 requests). The file lives in the temporary directory.
            log_path = Path(tmp, "server-{}.log".format(port))
            with open(log_path, "wb") as log:
                process = subprocess.Popen(args, env=server_env, cwd=settings.BASE_DIR,
                                           stdout=subprocess.DEVNULL, stderr=log)
            started.append((process, "http://127.0.0.1:{}".format(port), log_path))
        for process, base, log_path in started:
            _wait_until_up(base + "/insights/", process, log_path)
        yield request.param, [base for _, base, _ in started]
    finally:
        for process, _, _ in started:
            process.terminate()
            process.wait(10)


@pytest.mark.parametrize("clients", CONCURRENCY)
def test_throughput(benchmark, server, clients):
    mode, bases = server
    sessions = [requests.Session() for _ in range(clients)]

    def client_run(index, count):
        statuses = []
        base = bases[index % len(bases)]
        for _ in range(count):
            if mode == "direct (no proxy)":
                # What the proxy does per request: HEAD, then GET.
                requests.head("{}/client{}/".format(base, index), timeout=CLIENT_TIMEOUT)
                statuses.append(requests.get("{}/client{}/".format(base, index), timeout=CLIENT_TIMEOUT).status_code)
            else:
                url = "{}/proxy/client{}/".format(base, index)
                statuses.append(sessions[index].get(url, timeout=CLIENT_TIMEOUT).status_code)
        return statuses

    def batch():
        per_client = [REQUESTS // clients] * clients
        with ThreadPoolExecutor(clients) as pool:
            results = list(pool.map(client_run, range(clients), per_client))
        return [status for statuses in results for status in statuses]

    benchmark.group = "throughput: {} requests, upstream {:.0f} ms".format(REQUESTS, UPSTREAM_LATENCY * 1000)
    benchmark.name = "throughput[{}, {:>2} clients]".format(mode, clients)
    statuses = benchmark.pedantic(batch, rounds=3, warmup_rounds=1, iterations=1)
    assert statuses == [200] * REQUESTS
    RESULTS[(mode, clients)] = REQUESTS / benchmark.stats.stats.median


def summary_lines():
    """requests/s table, printed by conftest.pytest_terminal_summary."""
    if not RESULTS:
        return []
    modes = [mode for mode in MODES if any(key[0] == mode for key in RESULTS)]
    lines = ["Throughput in requests/s (median of 3 batches of {}; upstream latency {:.0f} ms):".format(
        REQUESTS, UPSTREAM_LATENCY * 1000)]
    lines.append("  {:<8}".format("clients") + "".join("{:>24}".format(mode) for mode in modes))
    for clients in CONCURRENCY:
        lines.append("  {:<8}".format(clients) + "".join(
            "{:>24}".format("{:.1f}".format(RESULTS[(mode, clients)]) if (mode, clients) in RESULTS else "-")
            for mode in modes))
    return lines
