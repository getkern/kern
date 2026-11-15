cd proj
export COMPOSE_PROJECT_NAME=kern-r2-files
timeout 30 $COMPOSE -f docker-compose.yml up --abort-on-container-exit --exit-code-from app.v1
echo EXIT_FILES:$?
$COMPOSE -f docker-compose.yml logs app.v1
$COMPOSE -f docker-compose.yml down -v
cd ..
