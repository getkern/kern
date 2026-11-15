$COMPOSE up -d ops
sleep 2
$COMPOSE cp ops:/tmp/test.txt ./downloaded.txt
cat ./downloaded.txt | grep -q "initial" && echo CP_OK
$COMPOSE top ops
$COMPOSE down -v
rm -f downloaded.txt
