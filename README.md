# **MiddleMan**
![DjangoREST](https://img.shields.io/badge/Django-REST-ff1709?style=flat-square&logo=django&logoColor=white)
![Django](https://img.shields.io/badge/Django-4.2-092E20?style=flat-square&logo=django&logoColor=white)
![Postgres](https://img.shields.io/badge/PostgreSQL-ready-316192?style=flat-square&logo=postgresql&logoColor=white)
![Coverage Gate](https://img.shields.io/badge/Coverage%20gate-80%25%2B-brightgreen?style=flat-square)

Proxy service built with Django, DRF and PostgreSQL, now shaped like a control room for traffic policy and observability. Current version: **2.0.0** (see [CHANGELOG.md](./CHANGELOG.md)).

- [**MiddleMan**](#middleman)
  - [**Explanation**](#explanation)
  - [**What's New (Finish-Up)**](#whats-new-finish-up)
  - [**Endpoints**](#endpoints)
  - [**Blacklist rules**](#blacklist-rules)
  - [**Authentication and roles**](#authentication-and-roles)
  - [**Admin login protection**](#admin-login-protection)
  - [**Allowed hosts**](#allowed-hosts)
  - [**Client policies and abuse detection**](#client-policies-and-abuse-detection)
  - [**Client IP and trusted proxies**](#client-ip-and-trusted-proxies)
  - [**Versions, logs and legacy data**](#versions-logs-and-legacy-data)
  - [**Quick Run**](#quick-run)
  - [**Testing**](#testing)
  - [**Security checks**](#security-checks)
  - [**Formatting**](#formatting)
  - [Contributing](#contributing)
    - [Step 1](#step-1)
    - [Step 2](#step-2)
    - [Step 3](#step-3)
    - [TO-DO's](#to-dos)
  - [License](#license)


## **Explanation**
You define a base url (your target) and request paths of that target through the proxy.

Example:

Let's say your target is `http://www.example.com/`. You set `BASE_TARGET_URL=http://www.example.com/` (with the trailing slash) and send requests to the proxy, indicating the path you want.

If the proxy is hosted at `https://awesome-proxy.com/`, a `GET` to `https://awesome-proxy.com/proxy/images/` returns `http://www.example.com/images/` __streamed from the server__. Paths are a single segment of letters, digits and `_` (the route is `proxy/<path>/`).

The service registers your `IP Address` and the path you want to access, then filters access based on the `max_requests` and `already_requested` saved in the database for your registered key. If you do not have a key registered yet, the service creates one with default values.

The current hackathon-friendly angle is the control room homepage: it turns the proxy into a visible product, with stats, recent activity and a JSON insights endpoint you can show in a demo.

You can also put the proxy into containment mode with blacklist rules, which block matching traffic before it reaches the target server.

## **What's New (Finish-Up)**

- Control Room dashboard: a polished war-room-style homepage that shows live registry activity, top paths, threat board and containment status.
- `/insights/` endpoint: a machine-readable JSON summary that powers the dashboard and supports automation.
- Persistent, editable blacklist: `BlacklistRule` model with a small CRUD UI on the dashboard and the Django admin (`/admin/`) so you can block IPs, paths and destination sites at runtime without touching the environment or restarting.
- Tests & migrations for everything above.

Version 2.0.0 adds rate limit headers, proper HTTP status codes, CIDR and destination (host/regex) rules, spoofing-resistant client IPs and version stamps on stored data. See [CHANGELOG.md](./CHANGELOG.md) before upgrading: some changes are breaking.


## **Endpoints**

| Method | Endpoint url | Body / query | Access | Description |
| ------ | ------------ | ------------ | ------ | ----------- |
| `GET`  | `/proxy/{path}/` | | public | Returns the target's `{path}/` as a stream, registering your IP address and the path. |
| `GET`  | `/` | | public | Control room dashboard. Aggregates for everyone; per-client activity and rules only for users allowed to see them. |
| `POST` | `/` | `action=create&rule_type=…&value=…`, `action=toggle&rule_id=…`, `action=delete&rule_id=…` | `add_` / `change_` / `delete_blacklistrule` | Manage blacklist rules (invalid rules answer `400`). |
| `GET`  | `/insights/` | | public | JSON aggregates (includes `proxy_version` and `legacy_entries`; no IPs). |
| `GET`  | `/registry/` | | `view_accessentry` | List all access entries, paginated. |
| `GET`  | `/registry/` | `?key=access_entry_key` (or body `{"key": "access_entry_key"}`) | `view_accessentry` | One access entry; `404` if the key does not exist. |
| `PATCH` | `/registry/` | `{"key": "access_entry_key", "action": "update_max_requests", "max_requests": 999}` | `change_accessentry` | Update max requests for the entry; `400` for invalid values, `404` for unknown keys. |
| `PATCH` | `/registry/` | `{"key": "access_entry_key", "action": "reset_already_requested"}` | `change_accessentry` | Reset `already_requested`; `404` for unknown keys. |
| `GET`  | `/clients/` | optional `?ip=1.2.3.4` | `view_clientpolicy` | Client policies (all, paginated, or one; `404` if none). |
| `PATCH` | `/clients/` | `{"ip": "1.2.3.4", "hide_rate_limit_headers": true, "reason": "…"}` | `add_` + `change_clientpolicy` | Create/update a client's policy (`201` created, `200` updated). |
| `GET` `POST` `PATCH` `DELETE` | `/settings/allowed-hosts/` | see [Allowed hosts](#allowed-hosts) | staff + `*_allowedhost` | Runtime allowed hosts. |
| | `/admin/` | | staff | Django admin (create a superuser with `python manage.py createsuperuser`). |

Protected endpoints answer `401` without valid credentials (with `WWW-Authenticate: Bearer`), `403` without the permission, and `405` for unsupported methods.

#### Proxy responses

| Status | When |
| ------ | ---- |
| upstream status | Request allowed; the body is streamed from the target. |
| `400 Bad Request` | The client address cannot be determined. |
| `403 Forbidden` | The client IP/path or the destination site matches a blacklist rule. |
| `429 Too Many Requests` | The client's `already_requested` reached `max_requests` for that path. |
| `500 Internal Server Error` | A failure inside the proxy (e.g. the access entry could not be stored). |
| `502 Bad Gateway` | The target is unreachable, fails its availability check (`HEAD` must answer `200`), redirects too many times, or the destination cannot be verified against an IP host rule. |
| `504 Gateway Timeout` | The target did not answer within 10 seconds. |

Error bodies are short plain-text messages; they never include the target URL (it may be internal). The logs do.
Requests the proxy refuses or cannot complete (`403`, `429`, `500`, `502`, `504`) do not count against the client's limit; responses proxied from the target count, whatever their status.

Allowed and `429` responses carry rate limit headers for the client's access entry, unless they are hidden for that client (see [client policies](#client-policies-and-abuse-detection)):

- `X-RateLimit-Limit`: `max_requests` for this IP + path.
- `X-RateLimit-Remaining`: requests left (never negative).

There is no `Retry-After`: limits have no time window; they are only reset by an operator via `PATCH /registry/`.

## **Blacklist rules**

Rules live in the `BlacklistRule` table and are managed on the dashboard or in the admin. They are read on every request, so a new rule applies to the next request without restarting the server. That is why destination rules exist only in the database: the proxy is meant to filter traffic continuously while operators adjust rules. (`BLACKLISTED_IPS` / `BLACKLISTED_PATHS` remain available as startup settings.)

Every value is validated when it is created; invalid values are rejected with a message explaining the problem.

| Type | Matches | Examples |
| ---- | ------- | -------- |
| `ip` | Client IP: exact, CIDR subnet (IPv4/IPv6) or address prefix + `*`. | `10.0.0.7`, `192.168.1.0/24`, `10.0.0.*` |
| `path` | Requested path (always ends with `/`): exact or prefix + `*`. | `admin/`, `admin/*`, `admin*` |
| `host` | A destination **site**, checked for the target URL *and every redirect hop* before the proxy connects. | see below |
| `host_re` | A destination site matched by a regular expression. | `(www\.)?example\.(com\|net)` |

`host` rules, from narrowest to broadest:

- `example.com`: only that host, not `www.example.com` and not its IP address. Use this to block one and only one site.
- `*.example.com`: any subdomain (any depth) but not `example.com` itself; add both to block the whole domain. Never matches look-alikes such as `badexample.com`.
- `93.184.215.14` or `93.184.215.0/24`: the destination's IP/subnet, matching IP URLs in any notation (`http://2130706433/` is `127.0.0.1`) and host names that resolve into it. Many sites can share one IP (CDNs, shared hosting), so this can block more than one site. If the name cannot be resolved, the request is refused with `502` (fail closed).

Hosts are canonicalized before matching (case, trailing dot, user info, port, IDN/punycode, numeric IPs), using the same URL parser `requests` uses to connect.

`host_re` rules are full-matched, case-insensitively, against the canonical host. They run on [RE2](https://github.com/google/re2) (linear time: no catastrophic backtracking) and must:

- use RE2 syntax (no backreferences or lookarounds) and stay under 200 characters and a compiled-size budget;
- escape literal dots (`example\.com`); `.` is only accepted as a wildcard when quantified (`.*`, `.+`);
- be ASCII (hosts are matched in punycode: `xn--bcher-kva\.de`), without spaces, `/` or `@` (a host, not a URL);
- not match every host (use a `path` rule `*` to block everything).

## **Authentication and roles**

- **Scripts and services** use API tokens: `Authorization: Bearer mm_<prefix>_<secret>`. Create one with
  `python manage.py create_api_token <username> --name <purpose> [--expires-in-days N]`; it is printed once and only its SHA-256 hash is stored. Revoke tokens in the admin (*API tokens → Revoke selected tokens*); tokens cannot be created there.
- **People** log in at `/admin/login/` (staff users); the dashboard then shows what their permissions allow, and its forms are CSRF-protected.
- A token acts with its **user's permissions**. Two groups are created automatically by `migrate`:
  - `proxy-auditor`: view access entries, rules, client policies and abuse signals;
  - `proxy-operator`: the above, plus change access entries, add/change/delete rules and set client policies;
  - `proxy-settings-admin`: manage allowed hosts (members must also be staff). Deliberately separate from `proxy-operator`.

  No role can manage API tokens; that is left to superusers.
- Every token failure (malformed, unknown, wrong secret, revoked, expired, inactive user) answers the same `401 Invalid or expired API token.`; the specific reason is logged with the token prefix, never the token.

## **Admin login protection**

Password logins (`/admin/login/`) are protected by [django-axes](https://github.com/jazzband/django-axes):

- After **5 failed attempts** a client IP is **locked out for 15 minutes** (`429`), even with the right password. The IP is the same spoofing-resistant client IP as everywhere else (`TRUSTED_PROXIES`), so rotating `X-Forwarded-For` does not help, and neither does rotating usernames.
- Lockouts are per IP, not per username, so nobody can lock an admin out of their account from elsewhere.
- A successful login does not clear the IP's failures (otherwise an attacker with any account could reset the counter between guesses).
- Failed logins also count toward [abuse detection](#client-policies-and-abuse-detection).
- Passwords are never stored or logged, and neither are usernames that are not real accounts (people sometimes type their password into the username field).
- Unlock with `python manage.py axes_reset_ip <ip>` (or `axes_reset` for everyone); attempts are listed in the admin under *Axes*.

Settings: `AXES_FAILURE_LIMIT`, `AXES_COOLOFF_TIME` in `proxy/settings.py`.

## **Allowed hosts**

Requests whose `Host` header is not allowed are rejected with `400` before anything else runs (Host header injection, cache and password-reset poisoning).

- **Baseline:** the `ALLOWED_HOSTS` environment variable, comma-separated (default `localhost,127.0.0.1,[::1]`). It cannot be changed at runtime, so admins can never lock everyone out. Invalid values (`*`, ports, a list literal such as `["*"]`, …) stop the app at startup.
- **Runtime hosts:** managed through `/settings/allowed-hosts/` (or the admin) by **staff** users with the `*_allowedhost` permissions (role `proxy-settings-admin`, or superusers). Changes apply immediately in the process that made them and within 5 seconds in the others.

  | Request | Effect |
  | ------- | ------ |
  | `GET` | `{"baseline": [...], "runtime": [...], "cache_seconds": 5}` |
  | `POST {"host": "api.example.com", "note": "..."}` | Add (`201`; `409` if already allowed in any spelling) |
  | `PATCH {"host": "...", "new_host": "...", "note": "..."}` | Rename or edit the note |
  | `DELETE {"host": "..."}` (or `?host=`) | Remove (`204`) |

  Values: `example.com`, `.example.com` (domain and subdomains), IPv4, IPv6 (stored as `[2001:db8::1]`); `*`, `.com`-style wildcards, ports, schemes and non-standard IP spellings are refused with a reason. Baseline hosts answer `400` here. Removing or renaming the host your own request came through answers `409` unless you send `"force": true`.

Django's own `ALLOWED_HOSTS` setting is `["*"]` because the check is done by `middleman.hosts.AllowedHostsMiddleware`; the app refuses to start if that middleware is not the first one.

## **Client policies and abuse detection**

Rate limit headers can be hidden for one client (by IP). The client is still served and still limited; it just can no longer see its limit or usage (the public dashboard never shows per-client data either).

- **Manually:** `PATCH /clients/` or the admin (*Client policies*). An admin decision is final: detection never changes it.
- **Automatically:** the proxy scores suspicious behaviour per client over a 10-minute window and hides the headers once the score reaches 10:

  | Signal | Points | Why it indicates tampering |
  | ------ | ------ | -------------------------- |
  | Sending `X-RateLimit-*` / `RateLimit-*` request headers | 5 per request | They are response headers; no legitimate client sends them. |
  | Rotating forwarding headers (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`, …) | 3 per extra distinct value | Rotating them is the classic limit-evasion trick. A constant value (corporate proxy) scores nothing. |
  | Invalid, expired or revoked API token | 3 each | Token guessing or replay. |
  | Requests answered `429` | 1 each | Hammering after being limited. |
  | Requests blocked by an `ip`/`path` rule | 1 each | Probing the blacklist. Destination (`host`) blocks are caused by the target, so they do not count. |
  | Management API without credentials or permission | 1 each | Probing the admin API. |
  | Failed admin login | 3 each | Password guessing (axes also locks the IP). |
  | `Host` header that is not allowed | 1 each | Host header injection attempts. |

  Tune it with `ABUSE_DETECTION` in settings (`ENABLED`, `WINDOW_MINUTES`, `THRESHOLD`, `WEIGHTS`); invalid values stop the app at startup. Signals are stored per minute (an attacker cannot create one row per request) and can be reviewed in the admin (*Abuse signals*); delete old ones with `python manage.py prune_abuse_signals --older-than-days 30`.

Hiding headers is not what stops abuse: the limit is enforced on the server, and forged request headers have no effect (see the tests in `middleman/tests/unit/security/`). It only removes the feedback an abuser would use to tune an attack.

## **Client IP and trusted proxies**

Clients can write any `X-Forwarded-For` header, so it is only believed when the TCP peer is one of your reverse proxies / load balancers, listed in `TRUSTED_PROXIES` (comma-separated IPs or CIDRs). The header is then read right to left, skipping trusted proxies; the first other address is the client, and anything further left (written by the client) is ignored.

- **Clients connect directly** (default, `TRUSTED_PROXIES` empty): the header is ignored.
- **Behind a proxy**: set `TRUSTED_PROXIES` to its address(es). Otherwise every client is seen as the proxy's IP, and the log says so once per peer.

A typo in `TRUSTED_PROXIES` stops the app at startup.

## **Versions, logs and legacy data**

- Every access entry and blacklist rule stores `created_by_version`. Rows that existed before 2.0.0 are marked `pre-2.0.0`: their rules were never validated, and their IPs may come from a spoofed header.
- Rules that are invalid in the running version are **never applied**. The dashboard and admin flag them, the log reports each one once, and `python manage.py check_blacklist_rules` lists them (exit code 1) with `--disable-invalid` / `--delete-invalid` to act on them. Invalid rules cannot be re-enabled.
- Log lines look like `2026-01-01 12:00:00 WARNING  middleman.views [proxy v2.0.0] [ProxyView] Request blocked: client matches a blacklist rule | ip=10.0.0.7 path='admin/' rule_type=ip rule='10.0.0.0/24'`. Set the level with `LOGLEVEL` (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`; default `WARNING`).

### **Quick Run**

Create your local environment file and load it into your shell (settings are read from environment variables only):

```bash
cp .env.example .env   # then edit it
source .env
```

`BASE_TARGET_URL` should be the target url you want to proxy (with a trailing `/`);

`SECRET_KEY` is the Django secret key;

`LOGLEVEL` is the log level you want to use;

`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` and `POSTGRES_HOST` configure the Postgres database;

`TRUSTED_PROXIES` lists the reverse proxies allowed to set `X-Forwarded-For` (see above);

`BLACKLISTED_IPS` / `BLACKLISTED_PATHS` are optional comma-separated `ip` / `path` rules read at startup;

`ALLOWED_HOSTS` is the baseline of accepted `Host` header values (see [Allowed hosts](#allowed-hosts));

`DEBUG` is off unless set to `true` (never in production); for local development use `make run-debug` (`python manage.py runserver --debug`).

Then, with the dependencies installed (`pip install -r requirements.txt`):

```bash
make migrate
make run
```

Before going to production run `python manage.py check --deploy` (secret key, HTTPS cookies, HSTS, …). Check stored rules after upgrading with `make check-rules`, then create users (`python manage.py createsuperuser`, add others to the `proxy-operator` / `proxy-auditor` groups in the admin) and tokens (`python manage.py create_api_token …`).


### **Testing**
Run the whole suite with a single command:

```bash
make test   # same as ./scripts/run_tests.sh
```

The script checks that this machine can run the tests and prepares it when needed:

- Finds a supported Python (3.8 to 3.12, Django 4.2) or uses `PYTHON=/path/to/python3`.
- Creates or repairs a virtualenv in `.venv/` (override with `VENV_DIR=...`).
- Installs `test_requirements.txt` the first time, and again whenever the requirement files change or a package is missing.
- Runs pytest with `proxy.test_settings` (SQLite), ignoring shell variables that would change results (`BLACKLISTED_IPS`, `TRUSTED_PROXIES`, `ALLOWED_HOSTS`, `LOGLEVEL`, `DJANGO_SETTINGS_MODULE`, ...).

Extra arguments go to pytest, e.g. `./scripts/run_tests.sh -k cidr --no-cov` (use `--no-cov` when running a subset, because of the coverage gate).
Other options: `--setup-only` (prepare the environment without running tests), `--recreate` (rebuild `.venv` from scratch) and `--help`.

Coverage gate is enforced in `pytest.ini` with `--cov-fail-under=80` (for `middleman` and `proxy`).

### **Security checks**

Run static security checks and dependency audit (inside the test virtualenv):

```bash
make security
```

This runs:
- `bandit` on application code;
- `pip-audit` on installed dependencies.

### **Formatting**

To run black and isort (both in `test_requirements.txt`), you can also use Makefile:

```bash
make format
```

----------------------------------------------------------------

---

## Contributing

> Feel free to contribute, but before you get to work, take a look at our issues to make sure you are not going to do something someone else is already doing. Feel free to add some issues if you find any bug or if you think I should add some funcionality.

> To start coding this project follow these steps:

### Step 1

- **Option 1**

  - 🍴 Fork this repo!

- **Option 2**
  - 👯 Clone this repo to your local machine using `https://github.com/lucasrafaldini/proxy.git`

### Step 2

- **CODE LIKE THERE'S NO TOMORROW!** 🔨🔨🔨

### Step 3

- 🔃 Create a new pull request using <a href="https://github.com/lucasrafaldini/proxy/compare/" target="_blank">`https://github.com/lucasrafaldini/proxy/compare/`</a>.

---

### TO-DO's

- [ ] Implement a cache system;
- [ ] Also get UserAgent info and make it a filtering criterium;
- [ ] Add a Postman/Insomnia collection to be avaiable for testing;
- [ ] Implement a  stress test with around 50k requests per second in each endpoint (maybe use [Locust](https://locust.io/));
- [ ] Add AsyncIO + cache to make 50k requests/s charge possible;
- [ ] Implement multithreads and multiprocessing to make 50k requests/s charge possible;

---

## License


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](./LICENSE)
