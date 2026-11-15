# Host con 2 GPU. kern: --allow-device-grants oppure allow_gpu_grants=true (stesso per entrambi i progetti).
# Docker: NVIDIA Container Toolkit già configurato.

timeout 120 $COMPOSE -p gpu0 -f docker-compose.gpu0.yml up --abort-on-container-exit --exit-code-from torch &
PA=$!
timeout 120 $COMPOSE -p gpu1 -f docker-compose.gpu1.yml up --abort-on-container-exit --exit-code-from torch &
PB=$!
wait $PA; echo EXIT_GPU0:$?
wait $PB; echo EXIT_GPU1:$?
$COMPOSE -p gpu0 -f docker-compose.gpu0.yml logs torch
$COMPOSE -p gpu1 -f docker-compose.gpu1.yml logs torch
$COMPOSE -p gpu0 -f docker-compose.gpu0.yml down -v
$COMPOSE -p gpu1 -f docker-compose.gpu1.yml down -v
