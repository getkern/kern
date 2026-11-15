export COMPOSE_PROJECT_NAME=kern-case9-signals
mkdir -p data
rm -f data/*

$COMPOSE -f docker-compose.yml up -d graceful stubborn
sleep 2
test -f data/graceful_started && test -f data/stubborn_started && echo BOTH_STARTED

$COMPOSE -f docker-compose.yml stop graceful
test -f data/graceful_bye && echo GRACEFUL_BYE_OK

S=$(date +%s)
$COMPOSE -f docker-compose.yml stop stubborn
echo EXIT_STOP_STUBBORN:$? SECONDS:$(( $(date +%s) - S ))

$COMPOSE -f docker-compose.yml up -d slow-start
sleep 1
$COMPOSE -f docker-compose.yml down
echo EXIT_DOWN_DURING_START:$?
echo PS_AFTER_DOWN:$($COMPOSE -f docker-compose.yml ps -q 2>/dev/null | wc -l)

$COMPOSE -f docker-compose.yml down -v 2>/dev/null || true
