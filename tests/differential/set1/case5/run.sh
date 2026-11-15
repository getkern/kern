export COMPOSE_PROJECT_NAME=kern-case5-ci
timeout 180 $COMPOSE -f docker-compose.yml up --abort-on-container-exit --exit-code-from test
echo EXIT_CI:$?
$COMPOSE -f docker-compose.yml logs test
$COMPOSE -f docker-compose.yml down -v
echo PS_AFTER_DOWN:$($COMPOSE -f docker-compose.yml ps -q 2>/dev/null | wc -l)
