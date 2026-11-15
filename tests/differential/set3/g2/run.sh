$COMPOSE up --abort-on-container-exit --exit-code-from ml-trainer
$COMPOSE logs ml-trainer | grep -q "CUDA_AVAILABLE: True" && echo CUDA_OK
$COMPOSE down -v
