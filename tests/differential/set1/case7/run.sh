export COMPOSE_PROJECT_NAME=kern-case7-net
timeout 120 $COMPOSE -f docker-compose.yml up --abort-on-container-exit --exit-code-from probe
echo EXIT_NET:$?
$COMPOSE -f docker-compose.yml logs probe
$COMPOSE -f docker-compose.yml ps
$COMPOSE -f docker-compose.yml down -v
