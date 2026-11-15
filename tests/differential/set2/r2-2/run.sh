export COMPOSE_PROJECT_NAME=kern-r2-vol
$COMPOSE -f docker-compose.yml up -d seed
sleep 2
$COMPOSE -f docker-compose.yml logs seed | grep -q SECRET_OK
$COMPOSE -f docker-compose.yml logs seed | grep -q BIND_OK

$COMPOSE -f docker-compose.yml run --rm inspector
echo EXIT_INSPECT_1:$?

$COMPOSE -f docker-compose.yml down
$COMPOSE -f docker-compose.yml run --rm inspector
echo EXIT_SURVIVED:$?

$COMPOSE -f docker-compose.yml down -v
$COMPOSE -f docker-compose.yml run --rm inspector
echo EXIT_AFTER_V:$?
