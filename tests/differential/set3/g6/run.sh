$COMPOSE up -d
sleep 2
$COMPOSE stop
EXIT_STOP=$?
echo "EXIT_STOP:$EXIT_STOP"
$COMPOSE down -v
