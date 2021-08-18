
build-and-run:
	docker-compose up --build --remove-orphans
run:
	docker-compose up --remove-orphans
test:
	docker-compose -f docker-compose-test.yml up --build --exit-code-from proxy-api-test
