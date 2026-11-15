$COMPOSE run --rm sandbox
EXIT_STATUS=$?
echo "EXIT_STATUS:$EXIT_STATUS"
$COMPOSE run --rm sandbox python3 -c "
import resource
try:
    # Test pids_limit exhaustion
    pids = []
    for i in range(100):
        pids.append(os.fork())
except Exception:
    print('FORK_LIMIT_OK')
"
$COMPOSE down -v
