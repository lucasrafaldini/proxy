
build-and-run:
	docker-compose up --build --remove-orphans
run:
	docker-compose up --remove-orphans
test:
	docker-compose -f docker-compose-test.yml up --build --exit-code-from proxy-api-test
test-local:
	pytest -q
security:
	bandit -q -r middleman proxy manage.py -x middleman/tests -s B101
	pip-audit
format:
	black . && isort --recursive .
