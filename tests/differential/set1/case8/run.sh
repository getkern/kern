export COMPOSE_PROJECT_NAME=kern-case8-fail

timeout 45 $COMPOSE -f docker-compose.wait.yml up -d --wait --wait-timeout 15
echo EXIT_WAIT:$?
$COMPOSE -f docker-compose.wait.yml ps -a
$COMPOSE -f docker-compose.wait.yml down -v

timeout 60 $COMPOSE -f docker-compose.missing.yml up -d
echo EXIT_MISSING:$?
$COMPOSE -f docker-compose.missing.yml ps -a || true
$COMPOSE -f docker-compose.missing.yml down -v 2>/dev/null || true

timeout 30 $COMPOSE -f docker-compose.badcmd.yml up --abort-on-container-exit --exit-code-from bad
echo EXIT_BADCMD:$?
$COMPOSE -f docker-compose.badcmd.yml down -v 2>/dev/null || true

timeout 30 $COMPOSE -f docker-compose.flash.yml up --abort-on-container-exit --exit-code-from flash
echo EXIT_FLASH:$?
$COMPOSE -f docker-compose.flash.yml logs
$COMPOSE -f docker-compose.flash.yml down -v
