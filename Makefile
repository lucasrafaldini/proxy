# MiddleMan - developer commands. Run `make` (or `make help`) for the list.
#
# Everything runs inside the project virtualenv (.venv), which is created or
# repaired automatically (scripts/run_tests.sh --setup-only), so no global
# Python packages and no activated virtualenv are needed.
#
# Variables (override on the command line, e.g. `make test ARGS="-k cidr"`):
#   ARGS          extra pytest arguments for the test targets
#   K             pytest -k expression for `make test-k`
#   PYTHON        interpreter used to create .venv (default: newest supported python3)
#   VENV          virtualenv directory (default: .venv)
#   ENV_FILE      settings file loaded by the app targets (default: .env)
#   BENCH_KEEP    saved benchmark runs kept by `make bench-save` (default: 5)
#   HYGIENE_TARGETS  targets checked by `make check-hygiene` (default: a representative set)
#   BENCH_FAIL    regression gate for `make bench-compare`: <stat>:<0-99>% or <stat>:<seconds>
#                 (default: min:75%, coarse on purpose: identical
#                 code drifted up to ±50% between runs on a shared VM; empty = report only)

VENV ?= .venv
, := ,
PY := $(VENV)/bin/python
# Storage hygiene: no target leaves bytecode, caches or stray files in the
# project tree or in ~/.cache. Tool caches live in the virtualenv (bounded,
# removed with it); `make check-hygiene` verifies all of it.
export PYTHONDONTWRITEBYTECODE := 1
export PIP_NO_CACHE_DIR := 1
TOOL_CACHE := $(abspath $(VENV))/.cache
export BLACK_CACHE_DIR := $(TOOL_CACHE)/black
# Called through bash so it works even if the executable bit was lost (e.g. zip).
RUN_TESTS := bash scripts/run_tests.sh
export VENV_DIR := $(abspath $(VENV))

# App targets load .env (if present) like `source .env` would; the test
# targets never do (they run isolated, see scripts/run_tests.sh).
ENV_FILE ?= .env
LOAD_ENV = if [ -f "$(abspath $(ENV_FILE))" ]; then set -a; . "$(abspath $(ENV_FILE))"; set +a; export MIDDLEMAN_ENV_FILE="$(ENV_FILE)"; fi;
MANAGE = @$(LOAD_ENV) $(PY) manage.py

NO_COV := --no-cov
UNIT := middleman/tests/unit
BENCH_DIR := middleman/tests/benchmarks
# Micro/meso benchmarks (fast enough to compare on every change); the server
# throughput benchmark starts real servers and runs separately.
BENCH_FILES ?= $(BENCH_DIR)/bench_proxy.py $(BENCH_DIR)/bench_concurrency.py
# Warmup is capped: uncapped, pytest-benchmark warms up for up to 100000
# iterations, i.e. minutes for the 10 ms worst-case benchmarks.
BENCH_OPTS := -o python_files=bench_*.py $(NO_COV) --benchmark-only --benchmark-storage=file://$(abspath .benchmarks) \
	--benchmark-warmup=on --benchmark-warmup-iterations=20 --benchmark-min-rounds=15 \
	--benchmark-sort=name --benchmark-columns=min,median,mean,ops,rounds
BENCH_FAIL ?= min:75%
BENCH_KEEP ?= 5
# pytest exits 5 when a -k/-m filter deselects every test: for a scoped
# benchmark run that is a skip ("nothing here matches"), not a failure.
define RUN_BENCH
	$(RUN_TESTS) $(1); status=$$?; \
	if [ $$status -eq 5 ]; then echo "No benchmarks matched the filter here; skipped."; exit 0; fi; \
	exit $$status
endef

.DEFAULT_GOAL := help

##@ Help

help: ## Show this help
	@awk 'BEGIN { FS = ":.*## " } \
		/^##@/ { printf "\n%s\n", substr($$0, 5) } \
		/^[a-zA-Z0-9_-]+:.*## / { printf "  make %-18s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo "Examples: make test ARGS=\"-x\" | make test-k K=cidr | make pytest ARGS=\"middleman/tests/unit/views -vv\""
	@echo "Virtualenv: $(VENV) (use it directly with: source $(VENV)/bin/activate, then python -m pytest)"

##@ Setup

venv: ## Create/repair .venv and install requirements (only when they changed)
	@$(RUN_TESTS) --setup-only

venv-recreate: ## Rebuild .venv from scratch (e.g. make venv-recreate PYTHON=python3.11)
	@$(RUN_TESTS) --recreate --setup-only

##@ Run the app (settings: cp .env.example .env; these targets load .env automatically)

doctor: venv ## Check settings, database, migrations, rules and target; explain every problem
	$(MANAGE) doctor

migrate: venv ## Apply database migrations
	$(MANAGE) migrate

run: venv ## Run the development server
	$(MANAGE) runserver

run-debug: venv ## Run the development server with DEBUG on (local development only)
	$(MANAGE) runserver --debug

check-rules: venv ## Report blacklist rules that are invalid in this version
	$(MANAGE) check_blacklist_rules

migrations-check: venv ## Fail if models changed without a migration
	DJANGO_SETTINGS_MODULE=proxy.test_settings $(PY) manage.py makemigrations --check --dry-run

##@ Tests (the full suite enforces the 80% coverage gate; scoped runs skip it)

test: ## Full suite: unit, views, security, acceptance, functional + coverage gate
	$(RUN_TESTS) $(ARGS)

test-quick: ## Full suite, quiet, no coverage, stop at the first failure
	$(RUN_TESTS) -q -x $(NO_COV) $(ARGS)

test-unit: ## All unit tests (services, views, security, interfaces, core)
	$(RUN_TESTS) $(UNIT) $(NO_COV) $(ARGS)

test-services: ## Rules, matching, destinations, client IP, ProxyManager
	$(RUN_TESTS) $(UNIT)/services $(NO_COV) $(ARGS)

test-views: ## Proxy, dashboard, registry and blacklist views
	$(RUN_TESTS) $(UNIT)/views $(NO_COV) $(ARGS)

test-security: ## Auth, tokens, tampering, abuse detection, allowed hosts, User-Agent evasion
	$(RUN_TESTS) $(UNIT)/security $(NO_COV) $(ARGS)

test-interfaces: ## Registry data-access layer
	$(RUN_TESTS) $(UNIT)/interfaces $(NO_COV) $(ARGS)

test-core: ## Settings/startup, versioning, migrations, exceptions, logging, diagnostics, doctor
	$(RUN_TESTS) $(wildcard $(UNIT)/test_*.py) $(NO_COV) $(ARGS)

test-acceptance: ## Release acceptance tests (User-Agent filtering)
	$(RUN_TESTS) middleman/tests/acceptance $(NO_COV) -v $(ARGS)

test-functional: ## End-to-end over real HTTP: live server + real upstream
	$(RUN_TESTS) middleman/tests/functional $(NO_COV) -v $(ARGS)

test-user-agent: ## Everything about User-Agent rules (all scopes)
	$(RUN_TESTS) $(NO_COV) -k "user_agent or UserAgent" $(ARGS)

test-k: ## Tests matching a -k expression: make test-k K=cidr
	@test -n "$(K)" || { echo "Usage: make test-k K=<pytest -k expression>"; exit 2; }
	$(RUN_TESTS) $(NO_COV) -k "$(K)" $(ARGS)

test-failed: ## Re-run only the tests that failed last time
	$(RUN_TESTS) --lf $(NO_COV) $(ARGS)

coverage-html: ## Full suite with an HTML coverage report in htmlcov/ (replaces the previous one)
	rm -rf htmlcov
	$(RUN_TESTS) --cov-report=html $(ARGS)
	@echo "Open htmlcov/index.html"

pytest: ## Raw pytest in the test environment: make pytest ARGS="..."
	$(RUN_TESTS) $(ARGS)

##@ Benchmarks (pytest-benchmark; not part of the test suite)

bench: ## Rules, matching, requests, parallel strategies, request steps (~2.5 min)
	@$(call RUN_BENCH,$(BENCH_FILES) $(BENCH_OPTS) $(ARGS))

bench-throughput: ## Real servers under 1/4/16 clients: single/threaded/4 processes (~3 min)
	@$(call RUN_BENCH,$(BENCH_DIR)/bench_throughput.py $(BENCH_OPTS) --benchmark-columns=median$(,)rounds $(ARGS))

bench-all: bench bench-throughput ## Every benchmark

bench-save: ## Run `make bench`, save it as the baseline in .benchmarks/ (keeps the newest BENCH_KEEP)
	@$(call RUN_BENCH,$(BENCH_FILES) $(BENCH_OPTS) --benchmark-autosave $(ARGS))
	@$(PY) scripts/housekeeping.py prune-benchmarks --keep $(BENCH_KEEP)

bench-compare: ## Compare with the last saved baseline; fail if slower than BENCH_FAIL (empty: report only)
	@ls .benchmarks/*/*.json >/dev/null 2>&1 || { echo "No baseline yet: run 'make bench-save' first."; exit 2; }
	@$(call RUN_BENCH,$(BENCH_FILES) $(BENCH_OPTS) --benchmark-compare $(if $(BENCH_FAIL),--benchmark-compare-fail=$(BENCH_FAIL)) $(ARGS))

##@ Quality

security: venv ## Static security checks (bandit) and dependency audit (pip-audit; AUDIT=off to skip)
	$(PY) -m bandit -q -r middleman proxy manage.py scripts -x middleman/tests -s B101
	@if [ "$(AUDIT)" = "off" ]; then \
		echo "Dependency audit SKIPPED (AUDIT=off): dependencies were not checked for known vulnerabilities."; \
	else \
		output="$$($(PY) -m pip_audit --strict --progress-spinner off --cache-dir "$(TOOL_CACHE)/pip-audit" 2>&1)"; \
		status=$$?; \
		echo "$$output"; \
		if [ $$status -ne 0 ] && echo "$$output" | grep -qiE "not found on PyPI|connection|resolve|timed out"; then \
			echo ""; \
			echo "The dependency audit FAILED because the vulnerability data is not reachable from here:"; \
			echo "  pip-audit needs https://pypi.org/pypi/<name>/json (or OSV via -s osv), which is a"; \
			echo "  different endpoint from the package index pip installs from - so pip may work while"; \
			echo "  the audit cannot. An audit that cannot run is a failure, not a pass."; \
			echo "  Run make security on a machine with PyPI access, or skip it explicitly: make security AUDIT=off"; \
		fi; \
		exit $$status; \
	fi

format: venv ## Format the code (black + isort)
	$(PY) -m black . && $(PY) -m isort --profile black .

ci: ## What CI should run: full suite (+ coverage.xml for CI tools) and security checks
	$(RUN_TESTS) --cov-report=xml $(ARGS)
	$(MAKE) --no-print-directory security

##@ Housekeeping

clean: ## Remove every generated file and cache (keeps .venv's packages and .benchmarks)
	rm -rf htmlcov coverage.xml $(VENV)/.pytest_cache $(VENV)/.coverage $(TOOL_CACHE)
	@# Locations used before 2.1.0 (and by tools run outside make):
	rm -rf .pytest_cache .coverage test_db.sqlite3
	find . -path ./$(VENV) -prune -o -path ./.git -prune -o -name __pycache__ -type d -exec rm -rf {} +

check-hygiene: ## Run make targets and verify they leave no files, caches, temp dirs or processes behind
	bash scripts/check_hygiene.sh $(HYGIENE_TARGETS)

distclean: clean ## Also remove .venv and saved benchmarks
	rm -rf $(VENV) .benchmarks

.PHONY: help venv venv-recreate doctor migrate run run-debug check-rules migrations-check \
	test test-quick test-unit test-services test-views test-security test-interfaces test-core \
	test-acceptance test-functional test-user-agent test-k test-failed coverage-html pytest \
	bench bench-throughput bench-all bench-save bench-compare security format ci clean check-hygiene distclean
