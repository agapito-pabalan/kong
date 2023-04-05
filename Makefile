.PHONY: $(MAKECMDGOALS)

clean:
	docker-compose down --volumes --remove-orphans

shell:
	docker-compose -f docker-compose.yml run --rm ash

up:
	docker-compose -f docker-compose.yml up -d

down:
	docker-compose -f docker-compose.yml down --remove-orphans

attach:
	docker attach kong

logs:
	docker-compose -f docker-compose.yml logs -f

local:
	docker compose -f docker-compose.yml -f docker-compose.local.yml up

local-rebuild:
	docker compose -f docker-compose.yml -f docker-compose.local.yml up --build