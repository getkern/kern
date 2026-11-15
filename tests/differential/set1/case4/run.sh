export COMPOSE_PROJECT_NAME=kern-case4-https
$COMPOSE -f docker-compose.yml up -d --wait --wait-timeout 90

curl -sS -o /tmp/k4_https.txt --cacert certs/cert.pem https://127.0.0.1:18443/
echo EXIT_HTTPS:$?
cat /tmp/k4_https.txt; echo

curl -sS -o /tmp/k4_http.txt -w "%{http_code}:%{redirect_url}\n" http://127.0.0.1:18080/
echo EXIT_HTTP:$?

echo | openssl s_client -connect 127.0.0.1:18443 -servername localhost 2>/dev/null \
  | openssl x509 -noout -subject | grep -q "CN *= *localhost" && echo CERT_OK

$COMPOSE -f docker-compose.yml down -v
