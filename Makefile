.PHONY: $(MAKECMDGOALS)

clean:
	docker-compose down --volumes --remove-orphans

shell:
	docker-compose -f docker-compose.local.yml run --rm ash

up:
	docker-compose -f docker-compose.local.yml up -d

down:
	docker-compose -f docker-compose.local.yml down --remove-orphans

attach:
	docker attach kong

logs:
	docker-compose -f docker-compose.local.yml logs -f
