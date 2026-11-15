export COMPOSE_PROJECT_NAME=kern-r2-loopbind
$COMPOSE -f docker-compose.yml up -d
sleep 2

# Dal host: la porta pubblicata NON deve servire LOOP_OK
curl -sS -m 2 -o /tmp/r2_loop.txt -w "%{http_code}" http://127.0.0.1:18099/ || true
echo
echo EXIT_HOST_CURL:$?
# se il file esiste e contiene LOOP_OK → FAIL
grep -q LOOP_OK /tmp/r2_loop.txt 2>/dev/null && echo LEAKED || echo NOT_REACHABLE_OK

# Dal container: localhost deve funzionare
$COMPOSE -f docker-compose.yml exec -T loop python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8099/').read().decode())"
echo EXIT_IN:$?

$COMPOSE -f docker-compose.yml down -v
