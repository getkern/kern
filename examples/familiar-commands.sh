#!/bin/sh
# Already use the big container and cloud tools? kern speaks the same shapes -
# on your own hardware, with no daemon, no account, and one small binary.
#
# Same CLI muscle memory as Docker:
#   docker run --rm alpine echo hi   ->  kern box demo --image alpine -- echo hi
#   docker ps                        ->  kern ps
#   docker exec -it web sh           ->  kern exec web -it -- sh
#   docker stop web                  ->  kern stop web
#   docker compose up                ->  kern compose stack.toml up
#
# The building blocks the managed clouds are made of - run them locally or at
# the edge, no cloud account:
#   AWS Lambda / GCP Cloud Functions  ->  a fresh box per request  (serverless-per-request.sh)
#   AWS Fargate / GCP Cloud Run       ->  a detached box with a port  (web-service.sh)
#   an ECS / GKE task                 ->  kern compose stack.toml up
#
# A quick live check of two of the commands above:
set -eu
kern="${KERN:-kern}"

echo '==> kern box demo --image alpine -- echo "hello from kern"'
"$kern" box demo --image alpine -- echo "hello from kern"

echo
echo '==> kern ps   (the box already exited - nothing left running, no daemon)'
"$kern" ps
