export COMPOSE_PROJECT_NAME=kern-case3-ssh
$COMPOSE -f docker-compose.yml build
$COMPOSE -f docker-compose.yml up -d --wait --wait-timeout 60

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/kern_case3_known \
  -i keys/id_ed25519 -p 2222 app@127.0.0.1 'echo SSH_OK; hostname'
echo EXIT_SSH:$?

echo payload > /tmp/kern_case3_up.txt
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/kern_case3_known \
  -i keys/id_ed25519 -P 2222 /tmp/kern_case3_up.txt app@127.0.0.1:/tmp/up.txt
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/kern_case3_known \
  -i keys/id_ed25519 -p 2222 app@127.0.0.1 'cat /tmp/up.txt'

printf 'put /tmp/kern_case3_up.txt /tmp/sftp.txt\nget /tmp/sftp.txt /tmp/kern_case3_down.txt\nbye\n' | \
  sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/kern_case3_known \
  -i keys/id_ed25519 -P 2222 app@127.0.0.1
cmp /tmp/kern_case3_up.txt /tmp/kern_case3_down.txt && echo SFTP_OK

ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/kern_case3_known \
  -i keys/wrong -p 2222 app@127.0.0.1 'echo SHOULD_NOT' ; echo EXIT_WRONG:$?

$COMPOSE -f docker-compose.yml restart ssh
$COMPOSE -f docker-compose.yml up -d --wait --wait-timeout 60
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/tmp/kern_case3_known \
  -i keys/id_ed25519 -p 2222 app@127.0.0.1 'echo SSH_AFTER_RESTART'

$COMPOSE -f docker-compose.yml down -v
