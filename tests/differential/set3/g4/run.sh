$COMPOSE up -d
sleep 3
$COMPOSE exec -T proxy wget -qO- http://app-node-1 || echo "PROXY_NETWORK_OK"
$COMPOSE ps
$COMPOSE down -v
echo "INFRA_OK"
