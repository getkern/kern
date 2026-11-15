export COMPOSE_FILE="docker-compose.base.yml:docker-compose.override.yml"
$COMPOSE --profile frontend up -d
$COMPOSE ps | grep web && echo PROFILE_OK
$COMPOSE down -v
unset COMPOSE_FILE
