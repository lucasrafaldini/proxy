# **MiddleMan**
![DjangoREST](https://img.shields.io/badge/Django-REST-ff1709?style=flat-square&logo=django&logoColor=white)
![Django](https://img.shields.io/badge/Django-4.2-092E20?style=flat-square&logo=django&logoColor=white)
![Postgres](https://img.shields.io/badge/PostgreSQL-ready-316192?style=flat-square&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-enabled-0db7ed?style=flat-square&logo=docker&logoColor=white)
[![Quality](https://img.shields.io/github/actions/workflow/status/lucasrafaldini/proxy/quality.yml?style=flat-square&label=quality)](https://github.com/lucasrafaldini/proxy/actions)
![Coverage Gate](https://img.shields.io/badge/Coverage%20gate-80%25%2B-brightgreen?style=flat-square)

Proxy service built with Django, DRF and PostgreSQL, now shaped like a control room for traffic policy and observability.

- [**MiddleMan**](#middleman)
  - [**Explanation**](#explanation)
  - [**Endpoints**](#endpoints)
    - [**Quick Run**](#quick-run)
    - [**Testing**](#testing)
    - [**Formatting**](#formatting)
  - [Contributing](#contributing)
    - [Step 1](#step-1)
    - [Step 2](#step-2)
    - [Step 3](#step-3)
    - [TO-DO's](#to-dos)
  - [License](#license)


## **Explanation**
You define a base url (your target) and request from the proxy address all paths you want from your target.

Example:

Let's say you have a target url: `http://www.example.com/` and you want to proxy all paths from this url. So, you define `http://www.example.com/` as your `.env` variable `BASE_TARGET_URL`. Now, you just redirect all requests to the URL your proxy is using, indicating the path you want to proxy.

So, if the proxy is hosted at `https://awesome-proxy.com/` and you want to access `http://example.com/assets/images` you just send a `GET` request to `https://awesome-proxy.com/assets/images` and you will get the response from `http://example.com/assets/images` __streamed from the server__.

The service registers your `IP Address` and the path you want to access, then filters access based on the `max_requests` and `already_requested` saved in the database for your registered key. If you do not have a key registered yet, the service creates one with default values.

The current hackathon-friendly angle is the new control room homepage: it turns the proxy into a visible product, with stats, recent activity and a JSON insights endpoint you can show in a demo.

You can also put the proxy into containment mode with `BLACKLISTED_IPS` and `BLACKLISTED_PATHS`, which block matching traffic before it reaches the target server.

## **What's New (Finish-Up)**

- Control Room dashboard: a polished war-room-style homepage that shows live registry activity, top paths, threat board and containment status.
- `/insights/` endpoint: a machine-readable JSON summary that powers the dashboard and supports automation.
- Persistent, editable blacklist: `BlacklistRule` model with a small CRUD UI on the dashboard and admin integration so you can block IPs and paths at runtime without touching `.env` or restarting.
- Tests & migrations: added a migration for the new model and unit tests for the blacklist flow so contributors can verify behavior locally.

These changes turn the repo into a demoable piece: easy to present in a short hackathon pitch and simple to reproduce.

For runtime operations, the dashboard now lets you create, toggle and delete persistent blacklist rules in the database without touching `.env`.


## **Endpoints**

You find the endpoints' method, url, body and description in the table bellow.

| Method | Endpoint url | Body | Description |
| ------ | ---------------- |---------- |-------------------------------------------------------------------------------- |
| `GET`  | `/proxy/{path}`  |                  | Returns desired path content as a stream, registering your IP address and the path you tried to access. | 
| `GET`  | `/`  |                  | Shows the control room dashboard with live registry stats. |
| `GET`  | `/insights/`  |                  | Returns JSON summary data for the dashboard or external tools. |
| `GET`  | `/registry`  |                  | List all access entry register paginated                                  |
| `GET`  | `/registry`  |    `{"key": "access_entry_key"}`              | List one access entry register  |
| `PATCH`  | `/registry`  |  `{"key": "access_entry_key", "action": "update_max_requests", "max_requests": "999"}`    | Update max requests allowed for the desired access entry indexed by its key |
| `PATCH`  | `/registry`  | `{"key": "access_entry_key", "action": "reset_already_requested"}` | Reset already_requested field for the desired access entry indexed by its key |
### **Quick Run**

Setup you local .env file:

```bash
$ cp .env.example .env
```

Edit .env file with your settings:

`BASE_TARGET_URL` should be the target url you want to proxy;

`SECRET_KEY` is the Django secret key;

`LOGLEVEL` is the log level you want to use;

`DATABASE_URI` is the database URI

`POSTGRES_USER` is the Postgres user;

`POSTGRES_PASSWORD` is the Postgres password;

`POSTGRES_DB` is the Postgres database;

`POSTGRES_HOST` is the Postgres host;

`BLACKLISTED_IPS` is a comma-separated list of IPs or wildcard prefixes to block;

`BLACKLISTED_PATHS` is a comma-separated list of paths or wildcard prefixes to block;

Use the dashboard to manage persistent `ip` and `path` blacklist rules during the demo.

Use the Makefile to build, run and even test the project:

For building please use:
```bash
$ make build-and-run
```

If you just want to run the project:
```bash
$ make run
```


### **Testing**
To run the tests locally (recommended):

1. Create a virtualenv and install dev/test dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r test_requirements.txt
```

2. Run the test suite with `pytest`:

```bash
pytest -q
```

Coverage gate is enforced in `pytest.ini` with `--cov-fail-under=80` (for `middleman` and `proxy`).

Alternatively you can use the Makefile (which uses Docker in CI-like flows):

```bash
make test
```

### **Security checks**

Run static security checks and dependency audit:

```bash
make security
```

This runs:
- `bandit` on application code;
- `pip-audit` on installed dependencies.

### **Formatting**

To run black and isort, you can also use Makefile:

```bash
$ make format
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

- [ ] Make key a url parameter in individual acces entry endpoint;
- [ ] Implement a cache system;
- [ ] Also get UserAgent info and make it a filtering criterium;
- [ ] Add a Postman/Insomnia collection to be avaiable for testing;
- [ ] Implement a way to make a blacklist of paths and IPs to avoid;
- [ ] Implement a  stress test with around 50k requests per second in each endpoint (maybe use [Locust](https://locust.io/));
- [ ] Add AsyncIO + cache to make 50k requests/s charge possible;
- [ ] Implement multithreads and multiprocessing to make 50k requests/s charge possible;

---

## License


[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE)
