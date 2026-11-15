timeout 90 $COMPOSE -p r2a -f docker-compose.yml up -d --wait --wait-timeout 60 &
timeout 90 $COMPOSE -p r2b -f docker-compose.yml up -d --wait --wait-timeout 60 &
wait
PA=$($COMPOSE -p r2a -f docker-compose.yml port web 80 | sed 's/.*://')
PB=$($COMPOSE -p r2b -f docker-compose.yml port web 80 | sed 's/.*://')
echo PORTS:$PA:$PB
test -n "$PA" -a -n "$PB" -a "$PA" != "$PB" && echo PARALLEL_OK

# up -d twice in a row (idempotent)
$COMPOSE -p r2a -f docker-compose.yml up -d
echo EXIT_UP2:$?
ID1=$($COMPOSE -p r2a -f docker-compose.yml ps -q web)
$COMPOSE -p r2a -f docker-compose.yml up -d
ID2=$($COMPOSE -p r2a -f docker-compose.yml ps -q web)
test "$ID1" = "$ID2" && echo IDEMPOTENT_OK || echo RECREATED_ON_SECOND_UP

# restart during requests
(
  for i in $(seq 1 30); do curl -sS -m 1 http://127.0.0.1:$PA/ >/dev/null || true; sleep 0.05; done
) &
$COMPOSE -p r2a -f docker-compose.yml restart web
wait
curl -sS -m 3 http://127.0.0.1:$PA/ | grep -q OK && echo AFTER_RESTART_OK

$COMPOSE -p r2a -f docker-compose.yml down -v &
$COMPOSE -p r2b -f docker-compose.yml down -v &
wait
