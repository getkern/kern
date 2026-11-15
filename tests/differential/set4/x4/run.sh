$COMPOSE up --abort-on-container-exit
echo EXIT_UP:$?
$COMPOSE up --abort-on-container-exit --exit-code-from memory-hog
echo EXIT_FROM:$?
$COMPOSE down -v
