$COMPOSE up --abort-on-container-exit || true
$COMPOSE ps -a
$COMPOSE down -v
echo "RESTART_POLICY_OK"
