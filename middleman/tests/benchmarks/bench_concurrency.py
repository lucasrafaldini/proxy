"""
Should one request evaluate its blacklist (or its other steps) in parallel?

Every parallel strategy below computes exactly the sequential answer (first
matching rule in order): the rules are split into ordered chunks, the chunks
are matched concurrently, and the first non-empty chunk result wins.

* sequential        - RuleSet.match_client (what the proxy does)
* threads-4         - ThreadPoolExecutor, 4 chunks
* processes-4       - ProcessPoolExecutor, 4 chunks; workers compile their
                      rules once (RE2 patterns cannot be pickled), each request
                      ships (ip, path, user agent) and gets the answer back
* asyncio-gather    - coroutines on an event loop (no I/O to overlap)
* asyncio-to_thread - asyncio.to_thread, i.e. threads driven by a loop

Scenarios: "typical" (mixed rules, browser User-Agent, prefilter on) and a
deliberate worst case that gives parallelism its best chance: only regex
rules, prefilter off, an 8 KB hostile User-Agent (every rule scans 8 KB).

The second half measures the other steps of a request one by one, and the
fixed cost of handing work to a thread: any intra-request concurrency has to
save more than that.
"""

import asyncio
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

import pytest
from django.db.models import F

from _rules import (CHROME, CLIENT, HOSTILE_UA, compiled,
                    regex_heavy_values, rule_values, store)
from middleman import abuse, ruleset as ruleset_module
from middleman.client_ip import resolve_client
from middleman.interfaces import RegistryInterface
from middleman.models import AccessEntry, BlacklistRule
from middleman.services import ProxyManager

WORKERS = 4
SCENARIOS = {
    "typical-400": (lambda: rule_values(400), CHROME, True),
    "typical-2000": (lambda: rule_values(2000), CHROME, True),
    "worst-400-regex-8KB": (lambda: regex_heavy_values(400), HOSTILE_UA, False),
    # Same worst case with the prefilter on (the default): one RE2 pass instead of 400.
    "worst-400-regex-8KB-prefilter": (lambda: regex_heavy_values(400), HOSTILE_UA, True),
}


def _first(results):
    for result in results:
        if result is not None:
            return result
    return None


# --- process workers: module-level functions so they can be pickled -------------------

_WORKER_PARTS = None


def _init_worker(value_chunks, use_prefilter):
    global _WORKER_PARTS
    _WORKER_PARTS = [compiled(chunk, use_prefilter) for chunk in value_chunks]


def _match_chunk(index, ip, path, user_agent):
    return _WORKER_PARTS[index].match_client(ip, path, user_agent)


def _split_values(values, parts):
    ordered = sorted(values)
    size = -(-len(ordered) // parts)
    return [ordered[i:i + size] for i in range(0, len(ordered), size)]


@pytest.fixture(scope="module")
def thread_pool():
    with ThreadPoolExecutor(WORKERS) as pool:
        yield pool


@pytest.fixture(scope="module")
def event_loop_for_bench():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.mark.parametrize("scenario", list(SCENARIOS))
@pytest.mark.parametrize("strategy", ["sequential", "threads-4", "processes-4", "asyncio-gather", "asyncio-to_thread"])
def test_parallel_blacklist(benchmark, scenario, strategy, thread_pool, event_loop_for_bench):
    make_values, user_agent, prefilter = SCENARIOS[scenario]
    values = make_values()
    whole = compiled(values, use_prefilter=prefilter)
    expected = whole.match_client(*CLIENT, user_agent)
    parts = [compiled(chunk, prefilter) for chunk in _split_values(values, WORKERS)]
    benchmark.group = "parallel blacklist evaluation: {}".format(scenario)
    benchmark.name = "{}[{}]".format(strategy, scenario)

    if strategy == "sequential":
        run = lambda: whole.match_client(*CLIENT, user_agent)  # noqa: E731
        assert benchmark(run) == expected
    elif strategy == "threads-4":
        def run():
            futures = [thread_pool.submit(part.match_client, *CLIENT, user_agent) for part in parts]
            return _first(future.result() for future in futures)
        assert benchmark(run) == expected
    elif strategy == "processes-4":
        context = multiprocessing.get_context("fork")
        with ProcessPoolExecutor(WORKERS, mp_context=context, initializer=_init_worker,
                                 initargs=(_split_values(values, WORKERS), prefilter)) as pool:
            list(pool.map(_match_chunk, range(len(parts)), *zip(*[(*CLIENT, user_agent)] * len(parts))))  # warm up

            def run():
                futures = [pool.submit(_match_chunk, i, *CLIENT, user_agent) for i in range(len(parts))]
                return _first(future.result() for future in futures)
            assert benchmark(run) == expected
    elif strategy == "asyncio-gather":
        async def gather():
            async def one(part):
                return part.match_client(*CLIENT, user_agent)
            return _first(await asyncio.gather(*(one(part) for part in parts)))
        assert benchmark(lambda: event_loop_for_bench.run_until_complete(gather())) == expected
    else:  # asyncio-to_thread
        async def gather():
            return _first(await asyncio.gather(
                *(asyncio.to_thread(part.match_client, *CLIENT, user_agent) for part in parts)
            ))
        assert benchmark(lambda: event_loop_for_bench.run_until_complete(gather())) == expected


# --- the other steps of a request, one by one -------------------------------------------

META = {"REMOTE_ADDR": CLIENT[0], "HTTP_USER_AGENT": CHROME}


@pytest.fixture
def request_state(db):
    store(rule_values(100))
    BlacklistRule.objects.create(rule_type="host", value="blocked.example")  # signals: writes a token
    manager = ProxyManager("http://target.example/home/")
    key = manager._create_unique_key(*CLIENT)
    entry = AccessEntry.objects.create(key=key, ip=CLIENT[0], path=CLIENT[1], max_requests=2_000_000_000)
    return manager, key, entry


STEPS = {
    "client ip (X-Forwarded-For logic)": lambda m, k, e: resolve_client(META),
    "tampering signals": lambda m, k, e: abuse.request_signals(META, resolve_client(META)),
    "client policy lookup (db)": lambda m, k, e: abuse.hides_rate_limit_headers(CLIENT[0]),
    "rule set token check (db)": lambda m, k, e: ruleset_module.current_token(),
    "blacklist match (100 rules, compiled)": lambda m, k, e: m._is_blacklisted(*CLIENT, CHROME),
    "destination check (host rules)": lambda m, k, e: m._blocked_destination("http://target.example/home/"),
    "access entry get_or_create (db)": lambda m, k, e: RegistryInterface().get_or_create_access_entry(k, *CLIENT),
    # The exact statement ProxyManager uses to reserve one request atomically.
    "reserve one request (db UPDATE)": lambda m, k, e: AccessEntry.objects.filter(
        pk=e.pk, already_requested__lt=F("max_requests")).update(already_requested=F("already_requested") + 1),
    "refresh entry (db)": lambda m, k, e: e.refresh_from_db(),
    "abuse report, no signals": lambda m, k, e: abuse.report(CLIENT[0], []),
}


@pytest.mark.parametrize("step", list(STEPS))
def test_request_step(benchmark, request_state, step):
    manager, key, entry = request_state
    manager._ruleset()  # compiled once, like any request after the first
    benchmark.group = "request steps (what could run concurrently?)"
    benchmark.name = "step[{}]".format(step)
    benchmark(STEPS[step], manager, key, entry)


def test_thread_handoff(benchmark, thread_pool):
    """Floor cost of running anything in another thread and waiting for it."""
    benchmark.group = "request steps (what could run concurrently?)"
    benchmark.name = "step[thread handoff: submit + wait, no work]"
    benchmark(lambda: thread_pool.submit(int).result())


# --- talking to the upstream: new connections vs a pooled keep-alive session -----------

@pytest.fixture(scope="module")
def instant_upstream():
    """The upstream stub with zero latency, in its own process: only connection cost remains."""
    import subprocess
    import sys
    from pathlib import Path

    stub = Path(__file__).with_name("_upstream_stub.py")
    process = subprocess.Popen([sys.executable, str(stub), "0"], stdout=subprocess.PIPE, text=True)
    yield "http://127.0.0.1:{}/home/".format(process.stdout.readline().strip())
    process.kill()
    process.wait(10)


def test_upstream_new_connections(benchmark, instant_upstream):
    """What ProxyManager.do_request does today: requests.head + requests.get, new connection each."""
    import requests

    def fetch():
        requests.head(instant_upstream, timeout=10)
        response = requests.get(instant_upstream, stream=True, timeout=10, allow_redirects=False)
        response.content
        response.close()

    benchmark.group = "request steps (what could run concurrently?)"
    benchmark.name = "step[upstream HEAD+GET, new connections]"
    benchmark(fetch)


def test_upstream_pooled_session(benchmark, instant_upstream):
    """Alternative: one keep-alive session (connection pool) per thread."""
    import requests

    session = requests.Session()

    def fetch():
        session.head(instant_upstream, timeout=10)
        response = session.get(instant_upstream, stream=True, timeout=10, allow_redirects=False)
        response.content
        response.close()

    benchmark.group = "request steps (what could run concurrently?)"
    benchmark.name = "step[upstream HEAD+GET, pooled keep-alive session]"
    benchmark(fetch)
    session.close()
