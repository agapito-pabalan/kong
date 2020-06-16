.PHONY: $(MAKECMDGOALS)

build:
	docker-compose build

clean:
	docker-compose down --volumes --remove-orphans

shell:
	docker-compose run --rm ash

up:
	docker-compose up -d

down:
	docker-compose down --remove-orphans

attach:
	docker attach kong

logs:
	docker-compose logs -f
