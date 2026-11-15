export COMPOSE_PROJECT_NAME=kern-case10-day2
$COMPOSE -f docker-compose.yml up -d dbdata
sleep 3
$COMPOSE -f docker-compose.yml up --abort-on-container-exit --exit-code-from writer writer
echo EXIT_WRITER:$?
$COMPOSE -f docker-compose.yml logs dbdata

$COMPOSE -f docker-compose.yml restart dbdata
sleep 2
$COMPOSE -f docker-compose.yml run --rm --no-deps -v pgdata:/data alpine:3.20 cat /data/marker
echo EXIT_VOL:$?

$COMPOSE -f docker-compose.yml logs --no-color dbdata | head -n 50

$COMPOSE -f docker-compose.yml down
$COMPOSE -f docker-compose.yml run --rm -v pgdata:/data alpine:3.20 cat /data/marker
echo SURVIVED:$?
$COMPOSE -f docker-compose.yml down -v
