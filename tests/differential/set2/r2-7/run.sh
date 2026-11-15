export COMPOSE_PROJECT_NAME=kern-r2-json
$COMPOSE -f docker-compose.yml up -d --wait --wait-timeout 60

$COMPOSE -f docker-compose.yml ps --format json > /tmp/r2_ps.json
python3 - <<'PY'
import json,sys
raw=open("/tmp/r2_ps.json").read().strip()
# Docker Compose may emit NDJSON (one object per line) or a single array
objs=[]
if raw.startswith("["):
    objs=json.loads(raw)
else:
    for line in raw.splitlines():
        line=line.strip()
        if line: objs.append(json.loads(line))
assert objs, "empty ps json"
# find service web.api (name field varies: Service / Name)
joined=json.dumps(objs)
assert "web.api" in joined or "web_api" in joined, joined[:500]
print("PS_JSON_OK", len(objs))
PY
echo EXIT_PS:$?

PORT_LINE=$($COMPOSE -f docker-compose.yml port web.api 80)
echo PORT_LINE:$PORT_LINE
echo "$PORT_LINE" | grep -Eq ':[0-9]+$' && echo PORT_OK

curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18088/
echo
$COMPOSE -f docker-compose.yml down -v
