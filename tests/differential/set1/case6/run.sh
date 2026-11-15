timeout 90 $COMPOSE -p kern-pr-a -f docker-compose.yml up -d --wait --wait-timeout 60
timeout 90 $COMPOSE -p kern-pr-b -f docker-compose.yml up -d --wait --wait-timeout 60
timeout 90 $COMPOSE -p kern-pr-c -f docker-compose.yml up -d --wait --wait-timeout 60

PA=$($COMPOSE -p kern-pr-a -f docker-compose.yml port web 80 | sed 's/.*://')
PB=$($COMPOSE -p kern-pr-b -f docker-compose.yml port web 80 | sed 's/.*://')
PC=$($COMPOSE -p kern-pr-c -f docker-compose.yml port web 80 | sed 's/.*://')
echo PORTS:$PA:$PB:$PC

curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:$PA/
echo
curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:$PB/
echo
curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:$PC/
echo

$COMPOSE -p kern-pr-a -f docker-compose.yml down -v &
$COMPOSE -p kern-pr-b -f docker-compose.yml down -v &
$COMPOSE -p kern-pr-c -f docker-compose.yml down -v &
wait
for p in kern-pr-a kern-pr-b kern-pr-c; do echo LEFT_$p:$($COMPOSE -p $p -f docker-compose.yml ps -q 2>/dev/null | wc -l); done
