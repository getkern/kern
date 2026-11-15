export COMPOSE_PROJECT_NAME=kern-r2-recreate
$COMPOSE -f docker-compose.yml up -d
sleep 1
ID_S1=$($COMPOSE -f docker-compose.yml ps -q stable)
ID_M1=$($COMPOSE -f docker-compose.yml ps -q moving)
echo S1:$ID_S1 M1:$ID_M1

# cambio solo moving
cat > docker-compose.yml <<'EOF'
services:
  stable:
    image: alpine:3.20
    command: ["sleep", "infinity"]
  moving:
    image: alpine:3.20
    environment:
      MARK: two
    command: ["sh", "-c", "echo START:$$MARK; sleep infinity"]
EOF

$COMPOSE -f docker-compose.yml up -d
sleep 1
ID_S2=$($COMPOSE -f docker-compose.yml ps -q stable)
ID_M2=$($COMPOSE -f docker-compose.yml ps -q moving)
echo S2:$ID_S2 M2:$ID_M2

test "$ID_S1" = "$ID_S2" && echo STABLE_SAME_OK || echo STABLE_RECREATED_BAD
test "$ID_M1" != "$ID_M2" && echo MOVING_RECREATED_OK || echo MOVING_SAME_BAD

$COMPOSE -f docker-compose.yml down -v
