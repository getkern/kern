export COMPOSE_PROJECT_NAME=kern-r2-https
sh gen_certs.sh
$COMPOSE -f docker-compose.yml up -d --wait --wait-timeout 90

curl -sS -o /tmp/r2_https.txt --cacert certs/cert.pem https://127.0.0.1:18443/
echo EXIT_HTTPS:$?
cat /tmp/r2_https.txt

curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18080/
echo EXIT_HTTP:$?

echo | openssl s_client -connect 127.0.0.1:18443 -servername localhost 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName | grep -q "IP Address:127.0.0.1" && echo CERT_SAN_OK

$COMPOSE -f docker-compose.yml down -v
