.PHONY: $(MAKECMDGOALS)

build:
	docker-compose build

clean:
	docker-compose down --volumes --remove-orphans

shell:
	docker-compose run --rm ash

up:
	docker-compose up

down:
	docker-compose down --remove-orphans

attach-backend:
	docker attach orion_backend_1

logs:
	docker-compose logs -f
