# **MiddleMan**
![DjangoREST](https://img.shields.io/badge/Django-REST-ff1709?style=flat-square&logo=django&logoColor=white)
![Django](https://img.shields.io/badge/Django-4.2-092E20?style=flat-square&logo=django&logoColor=white)
![Postgres](https://img.shields.io/badge/PostgreSQL-ready-316192?style=flat-square&logo=postgresql&logoColor=white)
![Coverage Gate](https://img.shields.io/badge/Coverage%20gate-80%25%2B-brightgreen?style=flat-square)

MiddleMan is a rate-limiting, policy-enforcing HTTP proxy built with Django, Django REST Framework and PostgreSQL. It forwards `GET /proxy/<path>/` to a configured target, counts every client per path, blocks traffic that matches blacklist rules (client IP, path, User-Agent, destination site), and exposes a control-room dashboard, a management API and the Django admin to operate it.

**Current version: 2.1.0** — User-Agent filtering, compiled blacklist rules, keep-alive connections to the target, request ids and explained errors across the application. See [Release 2.1.0](#2-release-210) and [CHANGELOG.md](./CHANGELOG.md). **This release contains breaking changes.**

## **Index**

1. [Overview](#1-overview)
   - [What the proxy does](#what-the-proxy-does)
   - [Request lifecycle](#request-lifecycle)
   - [Project layout](#project-layout)
2. [Release 2.1.0](#2-release-210)
   - [Highlights](#highlights)
   - [Breaking changes](#breaking-changes)
   - [Upgrading from 2.0.0](#upgrading-from-200)
   - [Release verification](#release-verification)
3. [Quick start](#3-quick-start)
4. [Configuration reference](#4-configuration-reference)
5. [Endpoints](#5-endpoints)
   - [Proxy responses](#proxy-responses)
   - [Rate limit headers](#rate-limit-headers)
   - [Connections to the target](#connections-to-the-target)
6. [Blacklist rules](#6-blacklist-rules)
   - [Rule types](#rule-types)
   - [Client rules: `ip` and `path`](#client-rules-ip-and-path)
   - [User-Agent rules: `user_agent` and `user_agent_re`](#user-agent-rules-user_agent-and-user_agent_re)
   - [Destination rules: `host` and `host_re`](#destination-rules-host-and-host_re)
   - [Startup rules (environment)](#startup-rules-environment)
   - [How rules are evaluated](#how-rules-are-evaluated)
   - [Invalid rules and `check_blacklist_rules`](#invalid-rules-and-check_blacklist_rules)
7. [Security](#7-security)
   - [Authentication and roles](#authentication-and-roles)
   - [Admin login protection](#admin-login-protection)
   - [Allowed hosts](#allowed-hosts)
   - [Client IP and trusted proxies](#client-ip-and-trusted-proxies)
   - [Client policies and abuse detection](#client-policies-and-abuse-detection)
8. [Logging and troubleshooting](#8-logging-and-troubleshooting)
   - [Log lines and request ids](#log-lines-and-request-ids)
   - [Errors are explained](#errors-are-explained)
   - [`make doctor`](#make-doctor)
9. [Versions, upgrades and rollback](#9-versions-upgrades-and-rollback)
10. [Development](#10-development)
    - [Make command reference](#make-command-reference)
    - [Testing](#testing)
    - [Storage hygiene](#storage-hygiene)
    - [Benchmarks](#benchmarks)
    - [Security checks](#security-checks)
    - [Formatting](#formatting)
11. [Contributing](#11-contributing)
12. [License](#12-license)

---

## **1. Overview**

### What the proxy does

You configure a target with `BASE_TARGET_URL` (with a trailing `/`) and request its paths through the proxy. With `BASE_TARGET_URL=http://www.example.com/` and the proxy at `https://awesome-proxy.com/`, a `GET https://awesome-proxy.com/proxy/images/` returns `http://www.example.com/images/`, **streamed** from the target. Paths are a single segment of letters, digits and `_` (the route is `proxy/<path>/`).

For every request the proxy:

- identifies the client by a spoofing-resistant IP ([Client IP and trusted proxies](#client-ip-and-trusted-proxies));
- applies blacklist rules on the client (IP, path, User-Agent) and on the destination, including every redirect hop ([Blacklist rules](#6-blacklist-rules));
- enforces a per-client, per-path request limit stored in the database (`AccessEntry`: `max_requests`, `already_requested`), created with defaults on first use;
- streams the target's answer back, reusing connections to the target ([Connections to the target](#connections-to-the-target)).

Operators work with the **control-room dashboard** (`/`: live activity, top paths, threat board, containment status, rule management), the **management API** (`/registry/`, `/clients/`, `/settings/allowed-hosts/`, with API tokens and roles), the **Django admin** (`/admin/`) and a public JSON summary (`/insights/`).

### Request lifecycle

What happens to `GET /proxy/<path>/`, in order (each step can end the request):

| # | Step | Where | Ends with |
| - | ---- | ----- | --------- |
| 1 | A request id is assigned (before any middleware) | `observability.begin_request` (`request_started` signal) | — |
| 2 | The `Host` header is validated (first middleware) | `hosts.AllowedHostsMiddleware` | `400` |
| 3 | `X-Request-ID` and the access log line are prepared; database errors become `503` | `observability.RequestContextMiddleware` | `503` / `500` |
| 4 | The client IP is resolved (`X-Forwarded-For` only from `TRUSTED_PROXIES`) | `client_ip.resolve_client` | `400` |
| 5 | Tampering signals are collected (forged rate-limit headers, rotating forwarding headers) | `abuse.request_signals` | — |
| 6 | The client's policy is read (hide rate-limit headers?) | `abuse.hides_rate_limit_headers` | — |
| 7 | Client rules: startup rules, then database rules (IP, path, User-Agent) | `ProxyManager._is_blacklisted` → `ruleset` | `403` |
| 8 | Destination rules on the target URL | `ProxyManager._check_destination` | `403` / `502` |
| 9 | The access entry is fetched or created, and one request is reserved atomically | `interfaces.RegistryInterface`, `services` | `429` / `503` |
| 10 | `HEAD` availability check (must answer `200`), then `GET`, following redirects manually and checking every hop against destination rules | `ProxyManager.do_request`, `upstream` | `502` / `504` / `403` |
| 11 | The body is streamed; its keep-alive connection returns to the pool when fully sent | `upstream.stream_body` | upstream status |
| 12 | Rate-limit headers, `X-Request-ID`, one access log line; abuse signals are recorded | views, `observability`, `abuse.report` | — |

Blocked (`403`), limited (`429`) and failed (`5xx`) requests never count against the limit; requests that reach the target count whatever its answer.

### Project layout

| Path | Responsibility |
| ---- | -------------- |
| `middleman/views.py` | HTTP endpoints: proxy, dashboard, insights, registry, client policies, allowed hosts. |
| `middleman/services.py` | `ProxyManager`: the request pipeline (steps 4-10 above). |
| `middleman/upstream.py` | Connections to the target: keep-alive pool, streaming and release, retry of dropped connections. |
| `middleman/rules.py` | Rule types and validation of `ip` / `path` rules; dispatch of every rule type's validator. |
| `middleman/user_agents.py` | `user_agent` / `user_agent_re` parsing, validation and matching. |
| `middleman/destinations.py` | `host` / `host_re` parsing and host canonicalisation; shared RE2 compilation. |
| `middleman/ruleset.py` | Compiled, cached rule set with cross-process version token and User-Agent prefilters. |
| `middleman/models.py` | `AccessEntry`, `BlacklistRule`, `ApiToken`, `ClientPolicy`, `AbuseSignal`, `AllowedHost`, `RuleSetVersion`. |
| `middleman/auth.py` | API tokens, roles and permission classes. |
| `middleman/client_ip.py` | Client IP resolution and trusted proxies. |
| `middleman/hosts.py` | Allowed hosts (baseline + runtime) and the Host-header middleware. |
| `middleman/abuse.py` | Abuse signals, scoring and automatic client policies. |
| `middleman/observability.py` | Request ids, access log, text/JSON log formats, database-error responses. |
| `middleman/diagnostics.py` | Semantic explanations of database/configuration errors (used by `manage.py`, views, `doctor`). |
| `middleman/interfaces.py`, `serializers.py` | Access-entry data access and serialisation. |
| `middleman/management/commands/` | `check_blacklist_rules`, `doctor`, `create_api_token`, `prune_abuse_signals`. |
| `middleman/migrations/` | `0001`-`0008` (`0007` User-Agent rule types, `0008` rule-set version). |
| `middleman/templates/middleman/dashboard.html` | Control-room dashboard. |
| `middleman/version.py` | The version (single source of truth). |
| `proxy/settings.py`, `test_settings.py` | Settings (environment-driven, validated at startup); test settings (SQLite in memory). |
| `manage.py` | Django commands; failures are explained instead of dumped. |
| `scripts/run_tests.sh` | Single entry point for the test suite (prepares `.venv`, runs pytest isolated). |
| `scripts/check_hygiene.sh`, `scripts/housekeeping.py` | Storage-hygiene verification; pruning of saved benchmarks. |
| `middleman/tests/unit/` | Unit tests: `services/`, `views/`, `security/`, `interfaces/` and core tests (settings, versioning, migrations, logging, diagnostics). |
| `middleman/tests/acceptance/` | Release acceptance tests for User-Agent rules. |
| `middleman/tests/functional/` | End to end over real HTTP (live server + real upstream, nothing mocked). |
| `middleman/tests/benchmarks/` | `bench_*.py` (pytest-benchmark; not part of the test suite). |

---

## **2. Release 2.1.0**

The full list is in [CHANGELOG.md](./CHANGELOG.md#210---2026-11-16); this is the summary.

### Highlights

- **User-Agent filtering** (the release's goal): two new rule types, `user_agent` (case-insensitive substring) and `user_agent_re` (RE2 regex), from the dashboard, the API, the admin or the environment; matching requests get `403` before rate limiting ([details](#user-agent-rules-user_agent-and-user_agent_re)).
- **Compiled blacklist rules**: validated and compiled once per change instead of on every request, still applied on the very next request in every process (7x-58x faster with 100-2000 rules).
- **Keep-alive connections to the target**: one connection instead of a new one per `HEAD` and `GET`.
- **Observability**: a request id on every log line and response, an access log, JSON logs, and database/configuration errors explained in plain language (`make migrate` included), `make doctor`.
- **Tooling**: `make` targets for every task (all verified), benchmarks with a decisions table, storage hygiene (`make check-hygiene`), release acceptance tests.

### Breaking changes

| Change | Before | Now | What to do |
| ------ | ------ | --- | ---------- |
| Body of policy `403`s | Named the rule type and value (and the destination host) | Generic: `Forbidden: the request was blocked by the proxy's access policy (ref <id>).` | Stop parsing the body; use the `ref` / `X-Request-ID` to find the log line. |
| Database outage during a request | `500` | `503 Service Unavailable` (fail closed) | Alerting / load-balancer rules keyed on `500` must include `503`. |
| `coverage.xml` | Written by every test run | Written by `make ci` only | CI jobs that upload it: run `make ci`. |
| `make security` | Passed when the dependency audit could not run | Fails (`--strict`), with an explanation | Run it where PyPI is reachable, or `AUDIT=off` deliberately. |

### Upgrading from 2.0.0

1. Install the requirements (or let `make venv` do it).
2. `make doctor` — checks settings, database, migrations, rules and target.
3. `make migrate` — `0007` widens `BlacklistRule.rule_type` from 8 to 16 characters, `0008` adds `RuleSetVersion`.
4. `make check-rules` — reports rules that are invalid in 2.1.0.
5. Review clients and monitors for the breaking changes above.
6. In production run several worker processes (see [Benchmarks](#benchmarks)).

Rolling back is covered in [Versions, upgrades and rollback](#9-versions-upgrades-and-rollback).

### Release verification

Run `./scripts/run_tests.sh` (or `make test`) from the `proxy` directory to execute the 611-test unit, security, acceptance and functional suite with the 80% coverage gate (`make test-acceptance` runs `middleman/tests/acceptance/test_user_agent_acceptance.py` in isolation).

---

## **3. Quick start**

```bash
cp .env.example .env     # edit it: every variable is documented there
make doctor              # checks settings, database, migrations, rules and target
make migrate
make run                 # http://127.0.0.1:8000/
```

- The `make` targets create `.venv` and install the dependencies on first use, and load `.env` automatically (for direct `python manage.py …` commands, `source .env` first).
- Create people and credentials: `python manage.py createsuperuser`, add others to the `proxy-operator` / `proxy-auditor` groups in the admin, and create API tokens with `python manage.py create_api_token <username> --name <purpose>`.
- Before production: `python manage.py check --deploy` (secret key, HTTPS cookies, HSTS, …) and run several worker processes (e.g. gunicorn `--workers` ≈ CPU cores).
- If something fails, the error says why and what to do ([Errors are explained](#errors-are-explained)).

## **4. Configuration reference**

Settings are read from environment variables only (`.env.example` documents them all). Invalid values stop the app at startup with a message naming the variable.

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `BASE_TARGET_URL` | `http://localhost:8000/` | Target to proxy (with the trailing `/`). |
| `UPSTREAM_KEEPALIVE` | `true` | Reuse connections to the target; `false` = a new connection per call. Strict boolean. |
| `SECRET_KEY` | a public development key (`django-insecure-…`) | Django secret key; `make doctor` warns while it is a `django-insecure-` key. |
| `DEBUG` | `false` | Strict boolean (`true/false`, `1/0`, `yes/no`, `on/off`); never in production. `make run-debug` enables it for one run. |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` | Baseline of accepted `Host` headers, comma-separated ([Allowed hosts](#allowed-hosts)). |
| `TRUSTED_PROXIES` | empty | Reverse proxies allowed to set `X-Forwarded-For` (IPs/CIDRs, comma-separated). |
| `BLACKLISTED_IPS` | empty | Startup `ip` rules, comma-separated. |
| `BLACKLISTED_PATHS` | empty | Startup `path` rules, comma-separated. |
| `BLACKLISTED_USER_AGENTS` | `[]` | Startup `user_agent` rules, **JSON array** (User-Agents contain commas). |
| `BLACKLISTED_USER_AGENTS_RE` | `[]` | Startup `user_agent_re` rules, **JSON array** (escape backslashes: `"bot/\\d+"`). |
| `POSTGRES_HOST` | `localhost` | Database host. |
| `POSTGRES_PORT` | `5432` | Database port (positive integer). |
| `POSTGRES_DB` | `db-test` | Database name. |
| `POSTGRES_USER` | `proxy-test` | Database user. |
| `POSTGRES_PASSWORD` | empty | Database password. |
| `POSTGRES_CONNECT_TIMEOUT` | `10` | Seconds before giving up on an unreachable database (instead of hanging). |
| `LOGLEVEL` | `WARNING` | `DEBUG`, `INFO` (adds the access log), `WARNING`, `ERROR`, `CRITICAL`. |
| `LOG_FORMAT` | `text` | `text` or `json` (one object per line). |
| `LOG_SLOW_REQUEST_MS` | `2000` | Requests slower than this are logged at `WARNING`. |

In `proxy/settings.py` (not environment): `ABUSE_DETECTION` ([abuse detection](#client-policies-and-abuse-detection)), `AXES_FAILURE_LIMIT` / `AXES_COOLOFF_TIME` ([admin login](#admin-login-protection)).

## **5. Endpoints**

| Method | Endpoint url | Body / query | Access | Description |
| ------ | ------------ | ------------ | ------ | ----------- |
| `GET`  | `/proxy/{path}/` | | public | Returns the target's `{path}/` as a stream, registering your IP address and the path. |
| `GET`  | `/` | | public | Control room dashboard. Aggregates for everyone; per-client activity and rules only for users allowed to see them. |
| `POST` | `/` | `action=create&rule_type=…&value=…`, `action=toggle&rule_id=…`, `action=delete&rule_id=…` | `add_` / `change_` / `delete_blacklistrule` | Manage blacklist rules (invalid rules answer `400`). With an API token this is the rule API. |
| `GET`  | `/insights/` | | public | JSON aggregates (includes `proxy_version` and `legacy_entries`; no IPs). |
| `GET`  | `/registry/` | | `view_accessentry` | List all access entries, paginated. |
| `GET`  | `/registry/` | `?key=access_entry_key` (or body `{"key": "access_entry_key"}`) | `view_accessentry` | One access entry; `404` if the key does not exist. |
| `PATCH` | `/registry/` | `{"key": "access_entry_key", "action": "update_max_requests", "max_requests": 999}` | `change_accessentry` | Update max requests for the entry; `400` for invalid values, `404` for unknown keys. |
| `PATCH` | `/registry/` | `{"key": "access_entry_key", "action": "reset_already_requested"}` | `change_accessentry` | Reset `already_requested`; `404` for unknown keys. |
| `GET`  | `/clients/` | optional `?ip=1.2.3.4` | `view_clientpolicy` | Client policies (all, paginated, or one; `404` if none). |
| `PATCH` | `/clients/` | `{"ip": "1.2.3.4", "hide_rate_limit_headers": true, "reason": "…"}` | `add_` + `change_clientpolicy` | Create/update a client's policy (`201` created, `200` updated). |
| `GET` `POST` `PATCH` `DELETE` | `/settings/allowed-hosts/` | see [Allowed hosts](#allowed-hosts) | staff + `*_allowedhost` | Runtime allowed hosts. |
| | `/admin/` | | staff | Django admin (create a superuser with `python manage.py createsuperuser`). |

Protected endpoints answer `401` without valid credentials (with `WWW-Authenticate: Bearer`), `403` without the permission, and `405` for unsupported methods. Every response carries an `X-Request-ID` header.

### Proxy responses

| Status | When |
| ------ | ---- |
| upstream status | Request allowed; the body is streamed from the target. |
| `400 Bad Request` | The client address cannot be determined, or the `Host` header is not allowed. |
| `403 Forbidden` | The client IP, path or User-Agent, or the destination site, matches a blacklist rule. |
| `429 Too Many Requests` | The client's `already_requested` reached `max_requests` for that path. |
| `500 Internal Server Error` | A failure inside the proxy (other than the database being unreachable). |
| `502 Bad Gateway` | The target is unreachable, fails its availability check (`HEAD` must answer `200`), redirects too many times, or the destination cannot be verified against an IP host rule. |
| `503 Service Unavailable` | The proxy's database is not reachable: rules cannot be checked, so nothing is proxied (fail closed). |
| `504 Gateway Timeout` | The target did not answer within 10 seconds. |

- Error bodies are short plain-text messages. They never include the target URL or host (it may be internal); the logs do.
- Every `403` caused by a blacklist rule has the same body: `Forbidden: the request was blocked by the proxy's access policy (ref 3f9a1c2b7d4e).` It never says which rule or rule type matched, nor echoes the client's data, so a scanner cannot map the blocklist. The `ref` is the request id (also in `X-Request-ID` and on every log line of the request).
- Requests the proxy refuses or cannot complete (`403`, `429`, `500`, `502`, `503`, `504`) do not count against the client's limit.

### Rate limit headers

Allowed and `429` responses carry the client's limit, unless hidden for that client ([client policies](#client-policies-and-abuse-detection)):

- `X-RateLimit-Limit`: `max_requests` for this IP + path.
- `X-RateLimit-Remaining`: requests left (never negative).

There is no `Retry-After`: limits have no time window; they are only reset by an operator via `PATCH /registry/`.

### Connections to the target

The proxy keeps connections to the target open and reuses them (`middleman/upstream.py`): one keep-alive pool per process, shared by its threads, instead of a new TCP (and TLS) connection for every `HEAD` and `GET`.

- A streamed body returns its connection to the pool only once it has been read to the end; if the client goes away mid-body, the connection is closed, never reused with unread data in it.
- Cookies set by the target are never stored, so nothing leaks from one client's request to another's.
- If the target closed an idle pooled connection, the request is retried once on a new connection (`GET`/`HEAD` only, only when no response had started). Every other error, timeouts included, is handled exactly as before: no retry, `502`/`504` as above.
- Every call to the target requires a timeout (10 seconds).
- A process forked after startup (e.g. gunicorn `--preload`) gets its own pool.
- `UPSTREAM_KEEPALIVE=false` opens a new connection per call, as before 2.1.0.

---

## **6. Blacklist rules**

Rules live in the `BlacklistRule` table and are managed on the dashboard, through the API (`POST /` with a token) or in the admin. A new, changed or deleted rule applies to the **next request** in every process, without a restart. `ip`, `path` and User-Agent rules can also be set at startup through the environment.

Every value is validated when it is created; invalid values are rejected (`400` on the dashboard/API, a form error in the admin) with a message and a stable reason code.

### Rule types

| Type | Matches | Examples |
| ---- | ------- | -------- |
| `ip` | Client IP: exact, CIDR subnet (IPv4/IPv6) or address prefix + `*`. | `10.0.0.7`, `192.168.1.0/24`, `10.0.0.*` |
| `path` | Requested path (always ends with `/`): exact or prefix + `*`. | `admin/`, `admin/*`, `admin*` |
| `user_agent` | Client `User-Agent` header: case-insensitive substring. | `sqlmap`, `python-requests/` |
| `user_agent_re` | Client `User-Agent` header: RE2 regex, searched anywhere. | `sqlmap\|nikto`, `^python-requests/`, `^$` |
| `host` | A destination **site**, checked for the target URL *and every redirect hop* before the proxy connects. | `example.com`, `*.example.com`, `93.184.215.0/24` |
| `host_re` | A destination site matched by a regular expression. | `(www\.)?example\.(com\|net)` |

Client rules (`ip`, `path`, `user_agent`, `user_agent_re`) are checked before the rate limit: blocked requests never reach the target, never create or count an access entry, and answer `403`.

### Client rules: `ip` and `path`

- `ip`: an exact address, a CIDR subnet (`10.0.0.0/24`, `2001:db8::/32`; host bits are tolerated) or an address prefix followed by `*` (`10.0.0.*`). Invalid addresses, subnets (`/33`) and wildcards are refused.
- `path`: proxied paths always end with `/` and have no leading `/`. `admin/` is exact; `admin/*` and `admin*` are prefixes; `*` alone blocks everything. `*` is only allowed at the end.

### User-Agent rules: `user_agent` and `user_agent_re`

User-Agent rules filter on what the client **says** it is. The header is written by the client, so they stop scanners, scripts and bots that announce themselves, not a determined attacker, who can send any value: use them next to `ip` rules and the rate limit, not instead of them. For the same reason the User-Agent is not part of the rate-limit key (rotating it does not give a client a fresh limit).

**`user_agent`** — case-insensitive substring:

- `sqlmap` blocks `sqlmap/1.7.2#stable` and `Mozilla/5.0 (compatible; SQLMap)`.
- At least 3 characters (shorter tokens hit unrelated clients), ASCII only, no control characters, no `*` (it is not a wildcard here: use a regex).
- Never matches a request without a User-Agent.

**`user_agent_re`** — [RE2](https://github.com/google/re2) regex, case-insensitive, **searched** anywhere in the User-Agent (anchor with `^` / `$`; unlike `host_re`, which is full-matched):

- RE2 syntax (no backreferences or lookarounds), at most 200 characters and a compiled-size budget, ASCII only, no `re:` prefix.
- Must not match every User-Agent (`.*`, `.`, `[a-z]` are refused: they would block all clients).
- `^$` blocks requests with a **missing or empty** User-Agent.
- Matching is linear-time whatever the input (no catastrophic backtracking), including 8 KB hostile headers.

**Missing, empty and unusual headers** are handled safely: a missing header and an empty one are the same value (`""`); blanks, non-ASCII bytes and repeated `User-Agent` headers (joined by the server) are matched as they are, never raising an error. Blocked requests are logged with the client's User-Agent, escaped and truncated to 200 characters; the `403` body stays generic.

Validation reason codes: `empty`, `too_short`, `non_ascii`, `invalid_characters`, `unsupported_wildcard` (`user_agent`); `empty`, `regex_prefix`, `regex_too_long`, `regex_non_ascii`, `regex_syntax`, `regex_too_complex`, `regex_matches_everything` (`user_agent_re`).

Blocks by User-Agent rules count as `blacklist_hit` [abuse signals](#client-policies-and-abuse-detection), like `ip`/`path` blocks.

### Destination rules: `host` and `host_re`

`host` rules, from narrowest to broadest:

- `example.com`: only that host, not `www.example.com` and not its IP address.
- `*.example.com`: any subdomain (any depth) but not `example.com` itself; add both to block the whole domain. Never matches look-alikes such as `badexample.com`.
- `93.184.215.14` or `93.184.215.0/24`: the destination's IP/subnet, matching IP URLs in any notation (`http://2130706433/` is `127.0.0.1`) and host names that resolve into it. Many sites can share one IP (CDNs, shared hosting), so this can block more than one site. If the name cannot be resolved, the request is refused with `502` (fail closed).

Hosts are canonicalised before matching (case, trailing dot, user info, port, IDN/punycode, numeric IPs), using the same URL parser `requests` uses to connect.

`host_re` rules are full-matched, case-insensitively, against the canonical host, on RE2, and must: use RE2 syntax and stay under 200 characters and a compiled-size budget; escape literal dots (`example\.com`; `.` is only accepted when quantified, `.*`/`.+`); be ASCII (`xn--bcher-kva\.de`), without spaces, `/` or `@`; not match every host.

Destination blocks are caused by the target (or its redirects), not by the client, so they do not count as abuse signals.

### Startup rules (environment)

```bash
export BLACKLISTED_IPS='10.0.0.0/24,192.168.1.7'
export BLACKLISTED_PATHS='admin/*'
export BLACKLISTED_USER_AGENTS='["sqlmap", "python-requests/", "Mozilla/5.0 (compatible; BadBot, v1)"]'
export BLACKLISTED_USER_AGENTS_RE='["^$", "nikto|masscan", "bot/\\d+"]'   # JSON: escape backslashes
```

User-Agent settings are JSON arrays because User-Agents contain commas. A value that is not a JSON array of strings stops the app at startup; an invalid entry (e.g. `"go"`, too short) is skipped, logged once and reported by `check_blacklist_rules`, like invalid `BLACKLISTED_IPS` entries. Startup rules cannot change without a restart; destination rules exist only in the database.

### How rules are evaluated

- Order: startup rules (`ip`, `path`, `user_agent`, `user_agent_re`), then database rules ordered by type and value. The first match is the one logged.
- Database rules are validated and compiled **once per change** (`middleman/ruleset.py`): pre-parsed networks, plain string comparisons, pre-compiled RE2 patterns; the client IP is parsed and the User-Agent lowercased once per request.
- User-Agent rules are also merged into RE2 **prefilters** (chunks of bounded size): for ASCII User-Agents a few linear passes decide whether any User-Agent rule can match, and the per-rule loop only runs when one can. Results are identical to evaluating rules one by one (a randomized test compares both on thousands of requests).
- Freshness: every rule change (`post_save` / `post_delete`) writes a new random token to `RuleSetVersion`; each request reads it (one primary-key lookup) and recompiles when it changed, so a change in any worker applies to the next request everywhere. Writes that bypass Django signals (`bulk_create`, `QuerySet.update`, raw SQL, restores) are picked up within 60 seconds.
- If the rules cannot be read (database down), the request is refused with `503` (fail closed).

### Invalid rules and `check_blacklist_rules`

Rules that are invalid in the running version (e.g. created by an older version, before validation existed) are **never applied**. The dashboard and the admin flag them, the log reports each one once, and they cannot be re-enabled.

```bash
python manage.py check_blacklist_rules                    # report; exit 1 if any rule is invalid
python manage.py check_blacklist_rules --disable-invalid  # or --delete-invalid
```

- Validates every database rule (all six types, User-Agent rules included) and the startup settings, printing id, type, value, `created_by_version`, reason code and message.
- Rules whose **type** this version does not know (they come from a newer version, e.g. after a rollback) are reported but never disabled or deleted, unless `--include-unknown-types` is given.
- `make check-rules` runs it with `.env` loaded.

---

## **7. Security**

### Authentication and roles

- **Scripts and services** use API tokens: `Authorization: Bearer mm_<prefix>_<secret>`. Create one with `python manage.py create_api_token <username> --name <purpose> [--expires-in-days N]`; it is printed once and only its SHA-256 hash is stored. Revoke tokens in the admin (*API tokens → Revoke selected tokens*); tokens cannot be created there.
- **People** log in at `/admin/login/` (staff users); the dashboard then shows what their permissions allow, and its forms are CSRF-protected.
- A token acts with its **user's permissions**. Groups created automatically by `migrate`:
  - `proxy-auditor`: view access entries, rules, client policies and abuse signals;
  - `proxy-operator`: the above, plus change access entries, add/change/delete rules and set client policies;
  - `proxy-settings-admin`: manage allowed hosts (members must also be staff). Deliberately separate from `proxy-operator`.

  No role can manage API tokens; that is left to superusers.
- Every token failure (malformed, unknown, wrong secret, revoked, expired, inactive user) answers the same `401 Invalid or expired API token.`; the specific reason is logged with the token prefix, never the token.

### Admin login protection

Password logins (`/admin/login/`) are protected by [django-axes](https://github.com/jazzband/django-axes):

- After **5 failed attempts** a client IP is **locked out for 15 minutes** (`429`), even with the right password. The IP is the same spoofing-resistant client IP as everywhere else, so rotating `X-Forwarded-For` or usernames does not help.
- Lockouts are per IP, not per username, so nobody can lock an admin out of their account from elsewhere.
- A successful login does not clear the IP's failures (otherwise an attacker with any account could reset the counter between guesses).
- Failed logins also count toward [abuse detection](#client-policies-and-abuse-detection).
- Passwords are never stored or logged, and neither are usernames that are not real accounts.
- Unlock with `python manage.py axes_reset_ip <ip>` (or `axes_reset` for everyone); attempts are listed in the admin under *Axes*.

Settings: `AXES_FAILURE_LIMIT`, `AXES_COOLOFF_TIME` in `proxy/settings.py`.

### Allowed hosts

Requests whose `Host` header is not allowed are rejected with `400` before anything else runs (Host header injection, cache and password-reset poisoning). `AllowedHostsMiddleware` must be the first middleware; the app refuses to start otherwise (the request id is assigned earlier, by a signal, so even rejected requests have one).

- **Baseline:** `ALLOWED_HOSTS`, comma-separated (default `localhost,127.0.0.1,[::1]`). It cannot be changed at runtime, so admins can never lock everyone out. Invalid values (`*`, ports, a list literal such as `["*"]`, …) stop the app at startup.
- **Runtime hosts:** managed through `/settings/allowed-hosts/` (or the admin) by **staff** users with the `*_allowedhost` permissions (role `proxy-settings-admin`, or superusers). Changes apply immediately in the process that made them and within 5 seconds in the others.

  | Request | Effect |
  | ------- | ------ |
  | `GET` | `{"baseline": [...], "runtime": [...], "cache_seconds": 5}` |
  | `POST {"host": "api.example.com", "note": "..."}` | Add (`201`; `409` if already allowed in any spelling) |
  | `PATCH {"host": "...", "new_host": "...", "note": "..."}` | Rename or edit the note |
  | `DELETE {"host": "..."}` (or `?host=`) | Remove (`204`) |

  Values: `example.com`, `.example.com` (domain and subdomains), IPv4, IPv6 (stored as `[2001:db8::1]`); `*`, `.com`-style wildcards, ports, schemes and non-standard IP spellings are refused with a reason. Baseline hosts answer `400` here. Removing or renaming the host your own request came through answers `409` unless you send `"force": true`.

Django's own `ALLOWED_HOSTS` setting is `["*"]` because the check is done by `middleman.hosts.AllowedHostsMiddleware`.

### Client IP and trusted proxies

Clients can write any `X-Forwarded-For` header, so it is only believed when the TCP peer is one of your reverse proxies / load balancers, listed in `TRUSTED_PROXIES` (comma-separated IPs or CIDRs). The header is then read right to left, skipping trusted proxies; the first other address is the client, and anything further left (written by the client) is ignored.

- **Clients connect directly** (default, `TRUSTED_PROXIES` empty): the header is ignored.
- **Behind a proxy**: set `TRUSTED_PROXIES` to its address(es). Otherwise every client is seen as the proxy's IP, and the log says so once per peer.

A typo in `TRUSTED_PROXIES` stops the app at startup.

### Client policies and abuse detection

Rate limit headers can be hidden for one client (by IP). The client is still served and still limited; it just can no longer see its limit or usage.

- **Manually:** `PATCH /clients/` or the admin (*Client policies*). An admin decision is final: detection never changes it.
- **Automatically:** the proxy scores suspicious behaviour per client over a 10-minute window and hides the headers once the score reaches 10:

  | Signal | Points | Why it indicates tampering |
  | ------ | ------ | -------------------------- |
  | Sending `X-RateLimit-*` / `RateLimit-*` request headers | 5 per request | They are response headers; no legitimate client sends them. |
  | Rotating forwarding headers (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`, …) | 3 per extra distinct value | Rotating them is the classic limit-evasion trick. A constant value (corporate proxy) scores nothing. |
  | Invalid, expired or revoked API token | 3 each | Token guessing or replay. |
  | Requests answered `429` | 1 each | Hammering after being limited. |
  | Requests blocked by an `ip`/`path`/`user_agent`/`user_agent_re` rule | 1 each | Probing the blacklist. Destination (`host`) blocks do not count. |
  | Management API without credentials or permission | 1 each | Probing the admin API. |
  | Failed admin login | 3 each | Password guessing (axes also locks the IP). |
  | `Host` header that is not allowed | 1 each | Host header injection attempts. |

  Tune it with `ABUSE_DETECTION` in settings (`ENABLED`, `WINDOW_MINUTES`, `THRESHOLD`, `WEIGHTS`); invalid values stop the app at startup. Signals are stored per minute (an attacker cannot create one row per request) and can be reviewed in the admin (*Abuse signals*); delete old ones with `python manage.py prune_abuse_signals --older-than-days 30`.

Hiding headers is not what stops abuse: the limit is enforced on the server, and forged request headers have no effect (see `middleman/tests/unit/security/`). It only removes the feedback an abuser would use to tune an attack.

---

## **8. Logging and troubleshooting**

### Log lines and request ids

Every log line, whatever wrote it (the proxy, Django, django-axes), carries the running version and the request it belongs to (`-` outside requests):

```
2026-01-01 12:00:00,000 WARNING  middleman.views [proxy v2.1.0] [req 3f9a1c2b7d4e] [ProxyView] Request blocked: client matches a blacklist rule | ref=3f9a1c2b7d4e ip=10.0.0.7 path='admin/' rule_type=user_agent rule='sqlmap' user_agent='sqlmap/1.7.2#stable'
2026-01-01 12:00:00,001 INFO     middleman.access [proxy v2.1.0] [req 3f9a1c2b7d4e] [Access] GET '/proxy/admin/' 403 | duration_ms=4.2 ip=10.0.0.7 slow=False
```

- **Request ids**: random, 12 hex characters, assigned before any middleware runs, returned as `X-Request-ID` on every response and used as the `ref` of policy `403`s and `503`s. Given a `ref` from a user, `grep 3f9a1c2b7d4e` finds everything that request did.
- **Access log** (`middleman.access`): one line per request with method, path, status, duration and client IP, at `INFO` (visible with `LOGLEVEL=INFO`), `WARNING` when slower than `LOG_SLOW_REQUEST_MS`, `ERROR` for `5xx`. Requests rejected for their `Host` header have one too.
- **Format**: `LOG_FORMAT=text` (default) or `json`: one JSON object per line with `time`, `level`, `logger`, `version`, `request_id`, `message`, and the message split into `component`, `event` and `fields` (the `key=value` pairs), plus `exception` when there is one.
- Client-supplied values (User-Agent, paths, hosts) are always escaped (`%r`), so they cannot forge lines in either format.

### Errors are explained

Failures that used to surface as a 60-line stack trace say what is wrong, with which settings, and what to do:

```
$ make migrate
ERROR: `migrate` failed: Nothing is accepting connections at localhost:5432: PostgreSQL is not running there, or it listens on another host/port.
  Database: PostgreSQL database 'db-test' on localhost:5432 as user 'proxy-test'
  Reason:   connection_refused
  What to do:
    1. Start PostgreSQL (e.g. sudo service postgresql start, or: docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=... postgres:16).
    2. Or point the proxy at your server: POSTGRES_HOST / POSTGRES_PORT (see .env.example).
    3. Not set, so defaults are used: POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD. Create your settings: cp .env.example .env, edit it, then source .env.
  Details:  connection to server at "localhost" (127.0.0.1), port 5432 failed: Connection refused ...
  Checks everything at once: make doctor. Full stack trace: add --traceback.
```

Recognised database problems (verified against a real PostgreSQL 16): `connection_refused`, `host_not_found`, `timeout`, `not_postgres` (the host/port is another service), `password_missing`, `auth_failed`, `role_missing`, `database_missing`, `schema_missing` (migrations not applied), `permission_denied`, `connection_lost`, `too_many_connections`, `ssl`, `driver_missing`, and SQLite's `sqlite_unavailable` / `sqlite_locked`. The same diagnosis is used everywhere:

- **Management commands** (`make migrate`, `make check-rules`, any `python manage.py …`): the explanation above, exit code 1; add `--traceback` for the full trace. Invalid settings get a one-paragraph message too.
- **Requests**: a database outage answers `503` (`500` for other database errors) in plain text with the request id, and logs one `ERROR` line with the reason and a hint (the stack trace only at `LOGLEVEL=DEBUG`). The proxy never forwards a request whose rules it could not read.
- **Fallbacks** that keep serving (runtime allowed hosts, abuse detection) log the same diagnosis.

### `make doctor`

`make doctor` (`python manage.py doctor [--skip-network]`) checks everything at once and explains each problem; it exits with 1 if anything is broken:

```
[ OK ] Environment: loaded from .env
[ OK ] Target: http://127.0.0.1:8080/
[ OK ] Database: PostgreSQL database 'proxy' on 127.0.0.1:5432 as user 'proxy' (server 16.15)
[FAIL] Migrations: 2 not applied: middleman.0007_blacklistrule_user_agent_types, middleman.0008_ruleset_version
         -> Run: make migrate
[SKIP] Blacklist rules: skipped (migrations not applied)
[ OK ] Target server: http://127.0.0.1:8080/ answered HEAD with 200
[ OK ] Logging: level WARNING (set LOGLEVEL=INFO for access logs), format text, slow requests >= 2000 ms
```

Checks: environment (and whether `.env` was loaded), `SECRET_KEY` and `DEBUG`, database connection, pending migrations, invalid rules, the target's `HEAD` answer, logging.

---

## **9. Versions, upgrades and rollback**

- The version lives in `middleman/version.py` (single source of truth). Every access entry and blacklist rule stores `created_by_version`; rows that existed before 2.0.0 are marked `pre-2.0.0`. Every log line and `/insights/` (`proxy_version`) show the running version.
- Upgrading from 2.0.0: see [Upgrading from 2.0.0](#upgrading-from-200).
- **Rolling back** to 2.0.0: unapply the migrations *before* deploying the old code, `python manage.py migrate middleman 0006` (it reverses `0008` and `0007`). User-Agent rules are moved to the table `middleman_blacklist_rule_parked`, out of reach of 2.0.0 (whose `check_blacklist_rules --delete-invalid` would otherwise delete them as an unknown type), and `migrate` restores them, with their original state and dates, when you upgrade again. Taking a backup first never hurts: `python manage.py dumpdata middleman.blacklistrule > rules.json`.

---

## **10. Development**

Everything runs inside the project virtualenv `.venv`, created and kept in sync with the requirements automatically: nothing to install globally and nothing to activate. `make` (or `make help`) lists every command.

### Make command reference

Variables: `ARGS` (extra pytest arguments), `K` (for `test-k`), `PYTHON` (interpreter for `.venv`), `VENV`, `ENV_FILE` (default `.env`), `AUDIT=off`, `BENCH_KEEP` (default 5), `BENCH_FAIL` (default `min:75%`), `HYGIENE_TARGETS`.

| Group | Command | What it does |
| ----- | ------- | ------------ |
| Help | `make help` | List every command (default target). |
| Setup | `make venv` | Create/repair `.venv`; install requirements only when they changed; remove packages nobody asked for. |
| | `make venv-recreate` | Rebuild `.venv` from scratch (e.g. `PYTHON=python3.11`). |
| Run the app | `make doctor` | Check settings, database, migrations, rules and target; explain every problem. |
| | `make migrate` | Apply database migrations. |
| | `make run` | Development server on `http://127.0.0.1:8000/`. |
| | `make run-debug` | Same with `DEBUG` on (local development only). |
| | `make check-rules` | `check_blacklist_rules`: report rules invalid in this version. |
| | `make migrations-check` | Fail if models changed without a migration. |
| Tests | `make test` | Full suite (unit, views, security, acceptance, functional) with the 80% coverage gate. |
| | `make test-quick` | Full suite, quiet, no coverage, stop at the first failure. |
| | `make test-unit` | All unit tests. |
| | `make test-services` / `test-views` / `test-security` / `test-interfaces` / `test-core` | One scope of unit tests (see [Testing](#testing)). |
| | `make test-acceptance` | Definition-of-done criteria of the release. |
| | `make test-functional` | End to end over real HTTP. |
| | `make test-user-agent` | Everything about User-Agent rules, across scopes. |
| | `make test-k K=cidr` | Tests matching a `-k` expression. |
| | `make test-failed` | Only the tests that failed last time. |
| | `make coverage-html` | Full suite + HTML coverage report in `htmlcov/` (replaced each run). |
| | `make pytest ARGS="…"` | Raw pytest in the test environment. |
| Benchmarks | `make bench` | Rules, matching, requests, parallel strategies, request steps (~2.5 min). |
| | `make bench-throughput` | Real servers under 1/4/16 clients (~3 min). |
| | `make bench-all` | Both, with the complete decisions table. |
| | `make bench-save` | Run `make bench` and save the baseline in `.benchmarks/` (newest `BENCH_KEEP` kept). |
| | `make bench-compare` | Compare with the baseline; fail on a regression beyond `BENCH_FAIL`. |
| Quality | `make security` | `bandit` + `pip-audit --strict` (`AUDIT=off` to skip the audit explicitly). |
| | `make format` | `black` + `isort` over the code (rewrites files). |
| | `make ci` | Full suite + `coverage.xml` + security checks. |
| Housekeeping | `make clean` | Remove every generated file and cache (keeps `.venv`'s packages and `.benchmarks`). |
| | `make check-hygiene` | Run targets twice and verify they leave no files, caches, temp files or processes behind. |
| | `make distclean` | Also remove `.venv` and saved benchmarks. |

Every target above was executed and verified for this release (including `run`/`run-debug` proxying a real request, `doctor` against a real PostgreSQL, `format` on a copy, and `distclean` followed by a rebuild).

### Testing

```bash
make test                        # or ./scripts/run_tests.sh (same thing)
```

`scripts/run_tests.sh` checks that the machine can run the tests and prepares it:

- finds a supported Python (3.8-3.12, Django 4.2) or uses `PYTHON=/path/to/python3`;
- creates or repairs `.venv` (override with `VENV_DIR=...`), rebuilds it when the requirement files change, removes packages that are not in the requirements;
- runs pytest with `proxy.test_settings` (SQLite in memory), ignoring shell variables that would change results (`BLACKLISTED_*`, `TRUSTED_PROXIES`, `ALLOWED_HOSTS`, `LOG*`, `POSTGRES_*`, `UPSTREAM_KEEPALIVE`, `DJANGO_SETTINGS_MODULE`, …).

Extra arguments go to pytest (`./scripts/run_tests.sh -k cidr --no-cov`; use `--no-cov` for subsets because of the coverage gate). Other options: `--setup-only` (`make venv`), `--recreate` (`make venv-recreate`), `--help`.

**Direct pytest.** pytest lives in `.venv`, not in the system Python (`python -m pytest` there answers `No module named pytest`):

```bash
source .venv/bin/activate && pytest --ds=proxy.test_settings
# or: .venv/bin/python -m pytest
```

Unlike `make test`, a direct run sees your shell variables (an exported `DJANGO_SETTINGS_MODULE` takes precedence over `pytest.ini`) and lets Python write `__pycache__` (`PYTHONDONTWRITEBYTECODE=1` avoids it; `make clean` removes it). pytest's cache, coverage data and benchmark storage stay in `.venv` either way.

**Suites** (`middleman/tests/`):

| Suite | Scope | Command |
| ----- | ----- | ------- |
| `unit/services/` | Rules and matching (IP, path, User-Agent, host), compiled rule set, destinations, client IP, `ProxyManager`, keep-alive connections | `make test-services` |
| `unit/views/` | Proxy, dashboard, registry, blacklist and User-Agent views | `make test-views` |
| `unit/security/` | Tokens, authorization, admin login, allowed hosts, tampering, abuse detection, User-Agent evasion | `make test-security` |
| `unit/interfaces/` | Registry data access | `make test-interfaces` |
| `unit/test_*.py` | Settings/startup, versioning, migrations (incl. rollback), exceptions, logging, diagnostics, `doctor`, housekeeping | `make test-core` |
| `acceptance/` | Release acceptance tests for User-Agent rules | `make test-acceptance` |
| `functional/` | End to end over real HTTP: a live server proxying to a real upstream, nothing mocked | `make test-functional` |

Safety nets: tests can only open connections to loopback (a mock that stops intercepting fails the test instead of reaching the network); per-process caches are reset between tests. Coverage gate: `--cov-fail-under=80` for `middleman` and `proxy` (currently 97%).

### Storage hygiene

Running `make` targets over and over never accumulates files:

- **Nothing in the project tree** except the outputs you ask for: `htmlcov/` (`make coverage-html`, replaced on every run), `.benchmarks/` (`make bench-save`, pruned to the newest `BENCH_KEEP`) and `coverage.xml` (`make ci`). No `__pycache__`, `.pytest_cache`, `.coverage` or database files: bytecode is off for every target, caches live in `.venv`, the test settings use an in-memory database.
- **Nothing outside it**: pip runs with `--no-cache-dir`; black's and pip-audit's caches live in `.venv/.cache`; temporary directories of tests and benchmarks are removed; the servers they start are stopped even when setup fails.
- **A virtualenv that matches the requirements**: rebuilt from scratch when the requirement files change; every run compares it with a snapshot of the clean install and removes packages nobody asked for (a `pip install` by hand) or reinstalls changed ones.
- `make clean` removes every generated file; `make distclean` also `.venv` and `.benchmarks`.

`make check-hygiene` proves it: it runs a representative set of targets twice (tests, coverage report, benchmarks with real servers, `doctor`, …) and fails if any run leaves files in the project tree, files in its private temporary directory, processes running, grows `~/.cache`, or keeps growing `.venv` (`make check-hygiene HYGIENE_TARGETS="test-quick bench"` for a subset). Its last full run: 13 targets × 2 rounds, clean.

### Benchmarks

Benchmarks ([pytest-benchmark](https://pytest-benchmark.readthedocs.io/)) live in `middleman/tests/benchmarks/bench_*.py` and are not part of the test suite (timings are not pass/fail material for `make test`).

| File | Question it answers |
| ---- | ------------------- |
| `bench_proxy.py` | What do validation, matching and a whole request cost? The blacklist check **before** (load and re-validate every rule on every request) and **after** (compiled rule set), with 0 to 2000 rules; matching with and without the User-Agent prefilter; compiling; whole requests against a real upstream with and without keep-alive. |
| `bench_concurrency.py` | Should one request evaluate its blacklist in **parallel**? Sequential vs threads vs processes vs asyncio (same answer, checked), for typical rule sets and a deliberate worst case (400 regex rules, 8 KB hostile User-Agent). The cost of every other request step, and of handing work to a thread. |
| `bench_throughput.py` | Does **concurrency across requests** help? The real app (`runserver`) in front of an upstream that takes 50 ms: single-threaded vs threaded vs 4 processes (with and without keep-alive), under 1, 4 and 16 clients. |

Every run ends with a **decisions table**: one row per design decision, the adopted flow next to its alternative, with the medians of that same run and the gain or loss. Rows appear only when the run included both sides (`make bench-all` prints them all). One full run:

```
Compiled rule-set cache (blacklist check, 100 rules)       compiled + token = 451 us   vs load + re-validate = 1.86 ms -> 4.14x faster
Compiled rule-set cache (blacklist check, 400 rules)       compiled + token = 496 us   vs load + re-validate = 6.01 ms -> 12.12x faster
Compiled rule-set cache (blacklist check, 2000 rules)      compiled + token = 652 us   vs load + re-validate = 37.9 ms -> 58.14x faster
User-Agent prefilter (matching only, 400 rules)            prefilter = 114 us          vs rule-by-rule = 489 us        -> 4.29x faster
User-Agent prefilter (matching only, 2000 rules)           prefilter = 549 us          vs rule-by-rule = 3.12 ms       -> 5.69x faster
User-Agent prefilter (worst case: 8 KB UA, 400 regexes)    prefilter = 177 us          vs rule-by-rule = 9.87 ms       -> 55.66x faster
In-request parallelism (blacklist, 2000 rules): threads    sequential = 521 us         vs 4 threads = 846 us           -> 1.62x faster
In-request parallelism (blacklist, 2000 rules): processes  sequential = 521 us         vs 4 processes = 1.1 ms         -> 2.10x faster
In-request parallelism (blacklist, 2000 rules): asyncio    sequential = 521 us         vs asyncio gather = 550 us      -> 1.06x faster
In-request parallelism (worst case UA): threads            sequential = 9.87 ms        vs 4 threads = 20.9 ms          -> 2.11x faster
In-request parallelism (worst case UA): processes          sequential = 9.87 ms        vs 4 processes = 5.58 ms        -> 1.77x slower
Upstream keep-alive pool (whole request, real upstream)    keep-alive pool = 8.46 ms   vs new connections = 10.3 ms    -> 1.22x faster
```

Throughput (requests/s, upstream 50 ms; before keep-alive, which leaves throughput at saturation unchanged):

| Clients | Single-threaded | Threaded, 1 process | Threaded, 4 processes |
| ------: | --------------: | ------------------: | --------------------: |
| 1 | 9.8 | 12.6 | 12.9 |
| 4 | 11.5 | 30.0 | **53.3** |
| 16 | 10.9 | 23.9 | **68.1** |

**Decisions they support:**

- **Do not parallelise the blacklist check inside a request.** It is CPU-bound Python plus RE2, which holds the GIL: threads are slower than sequential, asyncio has nothing to overlap, a process pool pays milliseconds of inter-process round trip. The one case where processes win (worst case without prefilter) is beaten 55x by the prefilter.
- **Do not run a request's steps concurrently.** The independent steps are database queries of ~0.4 ms; a thread handoff costs ~0.2 ms, and Django database connections are per thread. The dependent steps (access entry → reserve → refresh) cannot overlap.
- **Scale across requests with processes.** One threaded process stops scaling at a few clients (the GIL); 4 processes keep scaling (6x single-threaded at 16 clients). Run several worker processes in production.
- **Reuse upstream connections** (done): 1 connection instead of 6 for 3 proxied requests, about half the time at best per request against a real upstream, faster in 8/8 interleaved single-client pairs, neutral at saturation (6/12 pairs).

**Caveats.** The benchmark VM wakes a sleeping thread in ~0.7 ms (ordinary hardware: 5-20 µs) and identical code drifted up to ±50% between runs, so absolute numbers are pessimistic; compare numbers from the same machine only. Database steps were measured on SQLite in memory. `BENCH_FAIL` defaults to a deliberately coarse `min:75%` for that reason (an injected 0.1 ms delay in User-Agent matching still failed it by 1000%+); tighten it on a quiet machine (`make bench-compare BENCH_FAIL=min:15%`), or `BENCH_FAIL=` to only report.

The benchmarks already paid for themselves: the first User-Agent prefilter (one big RE2 alternation) took **1.5 s** per request on a hostile 8 KB User-Agent with 400 regex rules; it is now chunked (0.2 ms) and guarded by a test.

### Security checks

```bash
make security
```

- `bandit` on application code and scripts;
- `pip-audit --strict` on installed dependencies: the run **fails if any dependency could not be audited** (an audit that cannot run is a failure, not a pass).

pip-audit needs `https://pypi.org/pypi/<name>/json` (or OSV), a different endpoint from the package index pip installs from, so pip can work where the audit cannot (mirrors, restricted networks). `make security` then fails with an explanation; run it where PyPI is reachable, or skip the audit explicitly and visibly with `make security AUDIT=off` (also `make ci AUDIT=off`).

### Formatting

```bash
make format     # black + isort, installed in .venv; rewrites files
```

---

## **11. Contributing**

Feel free to contribute, but before you get to work, take a look at the issues to make sure nobody is already doing the same thing, and open one if you find a bug or want a feature.

1. Fork the repo, or clone it: `git clone https://github.com/lucasrafaldini/proxy.git`.
2. Code. Before opening a pull request run `make test`, `make migrations-check`, `make security` (or `AUDIT=off` if your network cannot reach PyPI) and, for performance-sensitive changes, `make bench-compare`.
3. Open a pull request: <a href="https://github.com/lucasrafaldini/proxy/compare/" target="_blank">`https://github.com/lucasrafaldini/proxy/compare/`</a>.

## **12. License**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](./LICENSE)
