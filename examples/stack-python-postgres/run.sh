#!/bin/sh
# A real two-service stack on kern: a Python API and an official Postgres, in one pod.
#
# It proves the multi-service path end to end: the API box and the Postgres box share
# one pod network (a single loopback, like a Kubernetes pod), the API talks to the DB
# at localhost:5432, and a note written over HTTP is read back from the database.
#
# The pod is created with --uid-range because the official postgres image drops
# privilege to the "postgres" user in its entrypoint (gosu); a member that drops
# privilege needs the subordinate uid range the pod holder maps.
#
# Done criterion: the two curls at the end return the notes we wrote.
set -eu

KERN=${KERN:-kern}
POD=stack-demo
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cleanup() { $KERN killall >/dev/null 2>&1 || true; $KERN pod rm "$POD" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "1/4  building the API image (python + pg8000)"
$KERN build -t stack-notes:1 -f "$here/Dockerfile" "$here" >/dev/null

echo "2/4  creating the pod (--uid-range: postgres drops privilege in its entrypoint)"
$KERN pod create "$POD" --uid-range >/dev/null

echo "3/4  starting postgres and the API in the pod"
$KERN box db --pod "$POD" --image postgres:16 --memory 512M \
  -e POSTGRES_PASSWORD=secret -d >/dev/null
$KERN box api --pod "$POD" --image stack-notes:1 --memory 512M \
  -e PGPASSWORD=secret -p 8080:8080 -d >/dev/null

echo "4/4  waiting for the stack, then writing and reading a note"
i=0
while [ "$i" -lt 60 ]; do
  i=$((i + 1)); sleep 1
  [ "$(curl -fsS -X POST 127.0.0.1:8080/notes -d 'hello' 2>/dev/null)" = "ok" ] && break
done
curl -fsS -X POST 127.0.0.1:8080/notes -d 'world' >/dev/null
notes=$(curl -fsS 127.0.0.1:8080/notes)

echo
echo "GET /notes -> $notes"
case "$notes" in
  *hello*world*) echo "OK: wrote two notes over HTTP and read them back from Postgres, across two boxes in a pod." ;;
  *) echo "FAIL: unexpected response: $notes"; exit 1 ;;
esac
