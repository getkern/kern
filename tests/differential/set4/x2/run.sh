$COMPOSE up -d --scale web=15
echo EXIT_UP:$?
# Controlla che 15 istanze siano su senza conflitti di porta
$COMPOSE ps
echo RUNNING:$($COMPOSE ps -q | wc -l)
ok=0; for p in $(seq 8080 8095); do c=$(curl -s -m 2 -o /dev/null -w "%{http_code}" http://127.0.0.1:$p/); [ "$c" = 200 ] && ok=$((ok+1)); done; echo PORTS_ANSWERING:$ok
$COMPOSE down -v
echo LEFT:$($COMPOSE ps -q | wc -l)
