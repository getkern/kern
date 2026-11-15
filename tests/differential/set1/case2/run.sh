export COMPOSE_PROJECT_NAME=kern-case2-sandbox

timeout 30 $COMPOSE -f docker-compose.yml run --rm -v "$PWD/good.py:/tmp/good.py:ro" sandbox python /tmp/good.py
echo EXIT_GOOD:$?

timeout 30 $COMPOSE -f docker-compose.yml run --rm -v "$PWD/net_probe.py:/tmp/net_probe.py:ro" sandbox python /tmp/net_probe.py
echo EXIT_NET:$?

timeout 60 $COMPOSE -f docker-compose.yml run --rm -v "$PWD/oom.py:/tmp/oom.py:ro" sandbox python /tmp/oom.py
echo EXIT_OOM:$?

timeout 30 $COMPOSE -f docker-compose.yml run --rm -v "$PWD/forkbomb.py:/tmp/forkbomb.py:ro" sandbox python /tmp/forkbomb.py
echo EXIT_FORK:$?

timeout 30 $COMPOSE -f docker-compose.yml run --rm -v "$PWD/write_probe.py:/tmp/write_probe.py:ro" sandbox python /tmp/write_probe.py
echo EXIT_WRITE:$?

timeout 5 $COMPOSE -f docker-compose.yml run --rm -v "$PWD/good.py:/tmp/good.py:ro" sandbox python -c "import time; time.sleep(60)"
echo EXIT_TIMEOUT:$?

$COMPOSE -f docker-compose.yml down -v 2>/dev/null || true
