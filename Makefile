.PHONY: up stop status logs test credentials
# up: gera chaves/configuração (bootstrap) e sobe Keycloak, API e portal.
up:
	docker compose build bootstrap
	docker compose run --rm --no-deps bootstrap
	docker compose up -d --no-build --wait --wait-timeout 120
status:
	docker compose ps -a
logs:
	docker compose logs -f keycloak resource-server client-app
test:
	docker build --target test -t telemedicina-tests:local .
	docker run --rm telemedicina-tests:local
credentials:
	docker compose run --rm --no-deps bootstrap python -m scripts.credentials
stop:
	docker compose stop
