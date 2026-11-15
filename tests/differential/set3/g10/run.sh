export COMPOSE_PROJECT_NAME="verylongprojectnamethatextendsovermanycharactersforboundarytesting123456"
$COMPOSE up -d
$COMPOSE ps
$COMPOSE down -v
unset COMPOSE_PROJECT_NAME
echo "SCALE_OK"
