.PHONY: start stop rebuild logs ps clean

# Start containers in detached mode (without rebuilding)
start:
	docker-compose up -d

# Stop and remove containers, networks
stop:
	docker-compose down

# Rebuild images and start containers
rebuild:
	docker-compose up -d --build

# Tail logs for all services
logs:
	docker-compose logs -f

# Tail logs for only the backend services
ps:
	docker-compose ps

# Stop containers and delete the database/redis volumes
clean:
	docker-compose down -v