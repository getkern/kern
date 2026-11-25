export COMPOSE_PROJECT_NAME=kern-case9-signals
mkdir -p data
rm -f data/*

$COMPOSE -f docker-compose.yml up -d graceful stubborn
sleep 2
test -f data/graceful_started && test -f data/stubborn_started && echo BOTH_STARTED

$COMPOSE -f docker-compose.yml stop graceful
test -f data/graceful_bye && echo GRACEFUL_BYE_OK

# THE STOP IS JUDGED BY WHAT IT MEANS, not by a count of whole seconds: `stop_grace_period: 2s`
# makes either engine kill the service after about 2.x s, and `date +%s` read that one interval as
# 2 or 3 depending on where the second boundary fell (seen as a "difference" between engines that
# was neither's). Killed after the grace, and not left running or ignored, is the fact compared.
S=$(date +%s%N)
$COMPOSE -f docker-compose.yml stop stubborn
RC=$?
MS=$(( ($(date +%s%N) - S) / 1000000 ))
echo EXIT_STOP_STUBBORN:$RC
[ "$MS" -ge 1900 ] && [ "$MS" -lt 6000 ] && echo STOP_AFTER_GRACE_OK
echo "S1: stop took ${MS} ms"

$COMPOSE -f docker-compose.yml up -d slow-start
sleep 1
$COMPOSE -f docker-compose.yml down
echo EXIT_DOWN_DURING_START:$?
echo PS_AFTER_DOWN:$($COMPOSE -f docker-compose.yml ps -q 2>/dev/null | wc -l)

$COMPOSE -f docker-compose.yml down -v 2>/dev/null || true
