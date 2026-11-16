# Changelog

Every access entry and blacklist rule stores the version that created it
(`created_by_version`), and every log line shows the running version
(`[proxy vX.Y.Z]`). Use this file to understand what a version means before
acting on data it produced.

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
