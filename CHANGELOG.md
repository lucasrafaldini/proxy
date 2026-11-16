# Changelog

Every access entry and blacklist rule stores the version that created it
(`created_by_version`), and every log line shows the running version
(`[proxy vX.Y.Z]`). Use this file to understand what a version means before
acting on data it produced.

## 2.1.0 - 2026-11-16

User-Agent rules, compiled blacklist rules, keep-alive connections to the
target, application-wide logging with request ids, semantic error messages,
`make doctor`, benchmarks and storage-clean tooling. Rows created from now on
are stamped `2.1.0`.

**Read the breaking changes below before upgrading**: this release changes
HTTP bodies and status codes clients and monitors may rely on, although it is
numbered as a minor version.

### Breaking changes

- **403 bodies are generic.** Every `403` caused by a blacklist rule (client or
  destination) now answers `Forbidden: the request was blocked by the proxy's
  access policy (ref <12 hex>).` It used to name the rule type and value (and,
  for host rules, the destination host), which handed scanners the blocklist
  and could reveal internal host names. The random `ref` is also on the log
  line, which keeps every detail. Clients that parsed the old text must stop.
- **Database outages answer `503 Service Unavailable`** (was `500 Internal
  proxy error`), for proxied requests and every other endpoint: the proxy
  cannot check its rules, so it refuses to forward (fail closed), and `503` is
  the status for a temporary inability to serve. Other database errors answer
  `500`. Both bodies carry the request id, and the log line explains the cause
  (see Added: diagnostics). Monitoring or load-balancer rules keyed on `500`
  for this case must include `503`.
- **`make security` fails when the dependency audit cannot run** (pip-audit
  now uses `--strict`): it previously skipped unauditable dependencies and
  reported success, i.e. an audit of nothing. When the vulnerability data is
  unreachable (a different endpoint from pip's package index), the failure
  explains it; `make security AUDIT=off` skips the audit explicitly.
- **`make test` no longer writes `coverage.xml`**; `make ci` does (for CI
  tools). No other run leaves coverage files in the project tree.

### Changed
- **Blacklist rules are compiled once per change** instead of being loaded and
  re-validated on every request (`middleman/ruleset.py`, migration `0008`
  adds the `RuleSetVersion` token table). Results are identical (a randomized
  test compares both implementations on thousands of requests); rule changes
  still apply to the next request in every process. Per-request cost of the
  blacklist check with 100 / 400 / 2000 stored rules dropped from 3.9 / 13.9 /
  58 ms to 0.56 / 0.64 / 1.15 ms (medians on a shared VM, about 0.4 ms of it the
  version-token lookup; see README, Benchmarks).
- **Connections to the target are reused** (`middleman/upstream.py`): one
  keep-alive pool per process instead of a new TCP/TLS connection for every
  `HEAD` and `GET`. Three proxied requests now use one connection instead of
  six; a whole proxied request against a real upstream takes about half the
  time at best (7-10 ms vs 15-21 ms minimum on the benchmark VM), with no
  throughput regression under 16 concurrent clients (interleaved A/B).
  Cookies set by the target are never stored (they would leak between
  clients); a pooled connection the server closed is retried once (GET/HEAD
  only, before any response); every other error, timeouts included, behaves
  exactly as before. `UPSTREAM_KEEPALIVE=false` restores one connection per
  call.

### Added

- **Logging across the application** (`middleman/observability.py`): a request
  id on every log line (any logger, including Django's) and in the
  `X-Request-ID` response header; it is also the `ref` of policy `403`s; an
  access log (`middleman.access`, slow requests at `WARNING` with
  `LOG_SLOW_REQUEST_MS`); `LOG_FORMAT=json` for one JSON object per line with
  the message's `[Component]` and `key=value` fields split out.
- **Semantic error explanations** (`middleman/diagnostics.py`): database
  failures are classified (connection refused, unknown host, timeout, not
  PostgreSQL, wrong/missing password, unknown role/database, migrations not
  applied, permission denied, connection lost, ...) with the settings in use,
  which `POSTGRES_*` variables were left at their defaults, and what to do.
  `manage.py` prints this instead of a stack trace (exit code 1; `--traceback`
  still shows it), as it does for invalid settings; requests log it with the
  `503`; allowed-hosts and abuse-detection fallbacks log it too.
- **Storage hygiene for every make target**: nothing is written to the
  project tree except requested outputs (`htmlcov/`, `.benchmarks/` pruned to
  `BENCH_KEEP`, `coverage.xml` from `make ci`); no bytecode, pytest cache,
  coverage data or test database there; no pip/black/pip-audit caches in
  `~/.cache`; `.venv` is rebuilt when the requirements change and cleaned of
  packages nobody asked for. `make check-hygiene` verifies it (files, temp
  files, processes, cache and virtualenv growth) over repeated runs.
- `python manage.py doctor` / `make doctor`: checks environment, database,
  migrations, rules, the target server and logging, explaining each problem.
- `POSTGRES_PORT` (was fixed at 5432) and `POSTGRES_CONNECT_TIMEOUT` (default
  10 s; connecting to an unreachable host no longer hangs for minutes).
- `make migrate`, `make run`, `make doctor`, `make check-rules` load `.env`
  automatically (`ENV_FILE=...` to use another file).
- **Acceptance tests for the definition of done** (`middleman/tests/acceptance/`,
  `make test-acceptance`): one test class per criterion - User-Agent rules
  created via the model or the API block matches with `403` and let others
  through; missing, empty or blank User-Agents never raise or answer `500`;
  `python manage.py check_blacklist_rules` validates User-Agent rules (run
  literally against a migrated database).
- Direct `pytest` runs keep pytest's cache, coverage data and benchmark
  storage in `.venv` too (`pytest.ini`, `.coveragerc`).
- Every benchmark run ends with a **decisions table**: each design decision
  (compiled rule cache, User-Agent prefilter, in-request parallelism with
  threads / processes / asyncio, upstream keep-alive, server concurrency)
  with the adopted flow, its alternative and the measured gain/loss from that
  same run.
- Benchmarks for parallel and concurrent processing (`bench_concurrency.py`:
  threads, processes and asyncio against sequential blacklist evaluation, the
  cost of every request step, thread handoff, pooled vs new upstream
  connections) and server throughput (`bench_throughput.py`, `make
  bench-throughput`: single-threaded vs threaded vs 4 processes under 1/4/16
  clients). Findings in the README.
- User-Agent blacklist rules: `user_agent` (case-insensitive substring) and
  `user_agent_re` (RE2 regex searched anywhere in the header; `^$` matches a
  missing User-Agent). Checked with `ip`/`path` rules before the rate limit:
  matching requests answer `403`, never reach the target and never create or
  count an access entry. Blocks count as `blacklist_hit` abuse signals. Values
  are validated (too short, `*`, non-ASCII, regex syntax/size, regexes that
  match every User-Agent) on the dashboard, in the admin and by
  `check_blacklist_rules`. The User-Agent is not part of the rate-limit key.
- `BLACKLISTED_USER_AGENTS` / `BLACKLISTED_USER_AGENTS_RE` startup settings, as
  JSON arrays (User-Agents contain commas). Malformed values stop startup;
  invalid entries are skipped, logged once and reported by
  `check_blacklist_rules`. `.env.example` (referenced by the README but
  missing) now exists and documents every variable.
- `check_blacklist_rules` keeps rules of unknown types (from a newer version,
  e.g. after a rollback) when run with `--disable-invalid` / `--delete-invalid`;
  `--include-unknown-types` acts on them explicitly.
- The dashboard's rule type list is built from the model, so it always offers
  every type; the policy summary counts User-Agent rules.
- Makefile: `make help` (default), scoped test targets (`test-services`,
  `test-views`, `test-security`, `test-interfaces`, `test-core`,
  `test-functional`, `test-user-agent`, `test-k`, `test-failed`, ...),
  `coverage-html`, `migrations-check`, `ci`, `clean`, `distclean`, and
  benchmarks (`bench`, `bench-save`, `bench-compare`, pytest-benchmark).
- Functional tests (`middleman/tests/functional/`): a live server proxying to a
  real upstream over real HTTP, nothing mocked; part of `make test`.

### Fixed

- Accumulating and stale files from make targets: saved benchmark runs were
  never pruned, `.venv` kept packages installed by hand or dropped from the
  requirements (they were installed on top), `manage.py` runs left
  `__pycache__` and `test_db.sqlite3`, every pytest run created `.pytest_cache`,
  `.coverage` and (through pytest-benchmark) an empty `.benchmarks/`, pip
  filled `~/.cache/pip`, and the throughput benchmark could leave its upstream
  server running when its setup failed.
- `make bench-all` (and any benchmark target) failed when a `-k` filter
  matched nothing in one of its files; that is now a reported skip.
- The functional tests left their keep-alive client sessions open, making the
  live server's worker threads race its database teardown (unhandled
  `DatabaseError` thread warnings); the fixtures now close them.
- The throughput benchmark read nothing from the servers' stderr pipe: after
  ~500 requests the 64 KB pipe filled and the server hung (seen as client
  timeouts). Server output now goes to a log file in the temporary directory.
- The User-Agent prefilter of the compiled rule set was a single RE2
  alternation at first; with hundreds of regex rules it overflowed RE2's DFA
  budget and a hostile 8 KB User-Agent took 1.5 s per request. It is now split
  into chunks with their own budget (0.2 ms for 400 rules); a test guards it.
  Found by the new concurrency benchmarks before release.
- `make migrate` (and every management command) crashed with a bare stack
  trace when the database was not reachable; it now explains why.
- `make test` failed with `Permission denied` (the scripts had lost their
  executable bit); the Makefile now calls them through `bash`, and the bits are
  restored. Every Make target runs inside `.venv`, created on first use:
  `make migrate` / `run` / `security` / `format` used the system Python and
  tools, which do not have the dependencies.

### Upgrading and rolling back

1. `make doctor` (or `python manage.py doctor`) to check the installation.
2. `make migrate`: `0007` widens `BlacklistRule.rule_type` from 8 to 16
   characters (`user_agent_re` did not fit; Postgres enforces the length),
   `0008` adds the `RuleSetVersion` table.
3. Review clients and monitors for the breaking changes above (403 body text,
   503 on database outages).
4. Run several worker processes in production (see README, Benchmarks).

To roll back to 2.0.0, run `python manage.py migrate middleman 0006` before
deploying the old code (it reverses `0008` and `0007`). User-Agent rules are
parked in `middleman_blacklist_rule_parked` (so the column can shrink and
2.0.0's `check_blacklist_rules --delete-invalid` cannot delete them as
`unknown_rule_type`) and restored, with their original state and dates, by
`migrate` when upgrading again. Rules re-created while rolled back win over
parked copies.

## 2.0.0

First versioned release. Rows that existed before it are stamped `pre-2.0.0`.

### Breaking changes

- **Status codes.** Rate limit exceeded: `429` (was `400`). Target unreachable
  or failing its availability check: `502`; target timeout: `504`; internal
  errors: `500` (all were `400`). Error bodies are plain text and no longer
  include the target URL.
- **Client IP.** `X-Forwarded-For` is only used when the request comes from an
  address in `TRUSTED_PROXIES` (default: none). Deployments behind a reverse
  proxy must set it, or every client is seen as the proxy.
- **Access entry keys** are now a SHA-256 of `ip@path`. They used Python's
  `hash()`, which changes on every process start, so each restart or worker
  created new entries and silently reset/multiplied limits. Entries created by
  `pre-2.0.0` stop matching; reset or delete them as needed.
- **Authentication.** `/registry/`, the new `/clients/` and the dashboard's rule
  actions require an API token or a staff session plus the matching
  permission (roles `proxy-operator` / `proxy-auditor`). They were open to
  anyone, which let any client reset its own rate limit. The public dashboard
  no longer shows per-client IPs and usage to anonymous visitors.
- **DEBUG** is off unless explicitly enabled with `DEBUG=true` (strict:
  unrecognised values stop startup) or `python manage.py <command> --debug`.
  It was always on (`DEBUG = " "`), and `LOGLEVEL=DEBUG` no longer enables it.
- **ALLOWED_HOSTS** is a comma-separated baseline (it crashed Django when set);
  more hosts are managed at runtime via `/settings/allowed-hosts/`. Requests
  with other `Host` headers answer `400`.
- **Admin login** is locked for 15 minutes per client IP after 5 failures
  (`429`).
- **Counting.** A client's first request now counts (`max_requests=100` allowed
  101 requests), and requests are reserved atomically, so parallel requests at
  the limit can no longer all get through.
- **Registry**: unknown keys answer `404` (was `500`); invalid `max_requests`
  answers `400` (was `200`, echoing the invalid value). Error bodies are JSON
  `{"detail": ...}`.
- **Rule validation.** `ip` and `path` rules are validated (e.g. an exact path
  without a trailing `/`, which could never match, is rejected).

### Added

- `X-RateLimit-Limit` / `X-RateLimit-Remaining` headers.
- CIDR subnets in `ip` rules.
- Destination rules: `host` (exact host, `*.subdomains`, destination IP/CIDR)
  and `host_re` (RE2 regex, linted), checked on the target and every redirect
  hop.
- `created_by_version` on access entries and rules; `proxy_version` and
  `legacy_entries` in `/insights/`; version shown on the dashboard.
- `python manage.py check_blacklist_rules [--disable-invalid | --delete-invalid]`.
- `/admin/` is routed (it was registered but unreachable).
- API tokens (`create_api_token`; hashed at rest; revocable; optional expiry)
  and default roles `proxy-operator` / `proxy-auditor`.
- Client policies (`/clients/`, admin): hide rate limit headers for one client.
- Brute-force protection for `/admin/login/` (django-axes), using the trusted
  client IP; failed logins also feed abuse detection.
- Runtime allowed hosts (`AllowedHost`, `/settings/allowed-hosts/`, admin),
  role `proxy-settings-admin` (staff only), host header gate middleware.
- `make run-debug`.
- Abuse detection that hides the headers automatically for clients that tamper
  with headers, rotate forwarding headers, hammer after `429`, probe the
  blacklist or the management API; `prune_abuse_signals` command.
- Logging configuration driven by `LOGLEVEL`, with a consistent
  `[Component] message | key=value` format and audit lines for rule and
  registry changes.
- `scripts/run_tests.sh` (`make test`).

### Fixed

- Invalid rules are never applied and are reported (once per process) with
  their id, value, reason and `created_by_version`, instead of being silently
  skipped on every request.
- IP host rules fail closed when the destination cannot be resolved.
- Upstream failures for new clients were reported as "access not registered".
- Several misleading log messages (e.g. a successful registry lookup logged as
  a failed PATCH).

### Removed

- Docker Makefile targets, `.dockerignore` and `scripts/wait-for-it.sh` (the
  Docker files they referred to are not part of the project).
- The `env` block in `pytest.ini` (it needed an uninstalled plugin and broke
  Django settings), the unused `dj-database-url` dependency and
  `DATABASE_URI` variable, and the deprecated `USE_L10N` setting.

## pre-2.0.0

Data created before version tracking. Rules were not validated (CIDR, host
and regex rules did not exist or were not checked); access entry IPs may have
been taken from a client-supplied `X-Forwarded-For` header.
