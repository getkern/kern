export COMPOSE_PROJECT_NAME=kern-r2-bound
timeout 45 $COMPOSE -f docker-compose.yml up --abort-on-container-exit --exit-code-from io
echo EXIT_IO:$?
$COMPOSE -f docker-compose.yml logs io | tail -n 20
$COMPOSE -f docker-compose.yml down -v
