
build:
	docker build -t proxy .
run:
	docker-compose up --remove-orphans
test:
	docker-compose -f docker-compose-test.yml up --build --exit-code-from test
