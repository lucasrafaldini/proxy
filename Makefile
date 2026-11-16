PYTHON ?= python3

# Run the app locally (configure the environment first: source .env).
migrate:
	$(PYTHON) manage.py migrate
run:
	$(PYTHON) manage.py runserver
# Local development only: DEBUG on (detailed error pages, static files served).
run-debug:
	$(PYTHON) manage.py runserver --debug
# Report blacklist rules that are invalid in the running version.
check-rules:
	$(PYTHON) manage.py check_blacklist_rules
# Prepares .venv if needed, then runs the whole suite (see scripts/run_tests.sh).
test:
	./scripts/run_tests.sh
security:
	bandit -q -r middleman proxy manage.py -x middleman/tests -s B101
	pip-audit
format:
	black . && isort --profile black .

.PHONY: migrate run run-debug check-rules test security format
