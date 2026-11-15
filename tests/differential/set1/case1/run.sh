export COMPOSE_PROJECT_NAME=kern-case1-gpu
timeout 180 $COMPOSE -f docker-compose.yml up --abort-on-container-exit --exit-code-from torch
echo EXIT_UP:$?
$COMPOSE -f docker-compose.yml down -v
