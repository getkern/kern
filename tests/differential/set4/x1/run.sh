$COMPOSE up --abort-on-container-exit
echo EXIT_UP:$?
$COMPOSE logs reader | grep -q "hello from user 1000" && echo READER_OK
$COMPOSE logs writer | grep -qi "denied" && echo WRITER_DENIED
ls -ln shared_data 2>&1 | tail -n +2 | awk '{print "HOST_FILE:", $3":"$4, $9}'
$COMPOSE down -v
