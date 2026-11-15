$COMPOSE up --abort-on-container-exit
echo EXIT_UP:$?
$COMPOSE logs consumer | grep -q "READING: data-sync" && echo SHM_SHARED_OK
$COMPOSE down -v
