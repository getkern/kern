$COMPOSE up --abort-on-container-exit --exit-code-from tuner
$COMPOSE logs tuner | grep -q "1024" && echo SYSCTL_OK
$COMPOSE logs tuner | grep -q "2048" && echo ULIMIT_OK
$COMPOSE down -v
