export COMPOSE_PROJECT_NAME=kern-r2-v6
# Serve IPv6 abilitato sul host (loopback ::1 basta per 18087).
$COMPOSE -f docker-compose.yml up -d --wait --wait-timeout 60

curl -6 -sS -o /dev/null -w "%{http_code}" "http://[::1]:18087/"
echo EXIT_V6_LOOP:$?

curl -6 -sS -o /dev/null -w "%{http_code}" "http://[::1]:18086/" || true
echo EXIT_V6_ANY:$?

$COMPOSE -f docker-compose.yml down -v
