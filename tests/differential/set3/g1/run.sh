$COMPOSE up --abort-on-container-exit --exit-code-from test-runner
EXIT_MIGRATION=$?
echo "EXIT_MIGRATION:$EXIT_MIGRATION"

$COMPOSE run --rm --entrypoint "sh -c 'exit 42'" migration
EXIT_RUN=$?
echo "EXIT_RUN:$EXIT_RUN"

$COMPOSE up -d helper
echo "hello-stdin" | $COMPOSE exec -T helper sh -c "read val; echo \"READ:\$val\"; [ \"\$val\" = \"hello-stdin\" ] && echo STDIN_OK"
$COMPOSE down -v
