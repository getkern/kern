#!/bin/sh
# One GPU per service, from a `docker-compose.yml`: a web front and two APIs, each API on its own card.
#
#   nginx (publishes 18931) -> /card0 -> api0  (deploy.resources.reservations.devices: device_ids ["0"])
#                           -> /card1 -> api1  (device_ids ["1"])
#
# Each API holds a CUDA context on the one card its service was given and, on every request, writes a
# pattern into a buffer on that card and reads it back. The host's own `nvidia-smi` is then asked which
# card each process is on, so what the box says and what the driver sees are compared.
#
# WHAT A GRANT GIVES: the card's device nodes, the driver's libraries bound read-only, the loader cache
# rebuilt so `libcuda.so.1` resolves, `NVIDIA_VISIBLE_DEVICES` as docker writes it. A service that asks
# for no card (here, nginx) gets none of it.
#
# WHAT IT DOES NOT GIVE:
#   - a VRAM limit. `mem_limit` and `--memory` cap host RAM, not the card's memory: a service can fill
#     the card it was given. Separate cards are the separation.
#   - a boundary against the code on the card. The box opens the NVIDIA driver's device nodes, so the
#     kernel driver is part of what that code can reach. Grant a card to code you would trust with it.
#
# A file cannot grant itself hardware: `--allow-device-grants` is the operator's half, on the command
# line. Runs on one card too (both APIs share it, and it says so); with no NVIDIA card it says that and
# exits 0. Images: nginx:alpine and python:3.12-slim. Rootless; everything is removed at the end.
set -eu
kern="${KERN:-kern}"
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2

if ! command -v nvidia-smi >/dev/null 2>&1 || ! nvidia-smi -L >/dev/null 2>&1; then
    echo "no NVIDIA card on this host (nvidia-smi is absent or lists none): nothing to grant"
    exit 0
fi
cards=$(nvidia-smi --query-gpu=uuid --format=csv,noheader | wc -l)
second=1
if [ "$cards" -lt 2 ]; then
    second=0
    echo "one card on this host: both APIs get card 0, and the per-card split below is one card"
fi

work="$(mktemp -d)"
trap 'cd /; "$kern" compose "$work/docker-compose.yml" -p gpu-demo down >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
cd "$work"
mkdir -p app nginx

# The API: the CUDA driver through ctypes, so the image needs nothing but Python.
cat > app/api.py <<'PY'
import ctypes, json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
MB = 64
c = ctypes.CDLL("libcuda.so.1")
assert c.cuInit(0) == 0
n = ctypes.c_int(); c.cuDeviceGetCount(ctypes.byref(n))
d = ctypes.c_int(); c.cuDeviceGet(ctypes.byref(d), 0)
u = (ctypes.c_ubyte * 16)(); c.cuDeviceGetUuid(u, d); h = bytes(u).hex()
UUID = "GPU-%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])
ctx = ctypes.c_void_p(); assert c.cuCtxCreate_v2(ctypes.byref(ctx), 0, d) == 0
buf = ctypes.c_uint64(); assert c.cuMemAlloc_v2(ctypes.byref(buf), ctypes.c_size_t(MB << 20)) == 0
served = 0
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        global served
        if self.path != "/health":
            c.cuCtxSetCurrent(ctx); served += 1; v = served % 251
            c.cuMemsetD8_v2(buf, ctypes.c_ubyte(v), ctypes.c_size_t(MB << 20))
            back = (ctypes.c_ubyte * 4096)()
            c.cuMemcpyDtoH_v2(back, buf, ctypes.c_size_t(4096))
            body = {"card": UUID, "cards_in_box": n.value, "pattern_ok": all(b == v for b in back)}
        else:
            body = {"ok": True}
        out = json.dumps(body).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers()
        self.wfile.write(out)
class S(ThreadingHTTPServer):
    request_queue_size = 128
S(("0.0.0.0", 8000), H).serve_forever()
PY

cat > nginx/default.conf <<'NG'
server {
  listen 80;
  location = /health { return 200 "ok\n"; }
  location /card0 { proxy_pass http://api0:8000/; }
  location /card1 { proxy_pass http://api1:8000/; }
}
NG

cat > docker-compose.yml <<YML
services:
  web:
    image: nginx:alpine
    ports: ["18931:80"]
    volumes: ["./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro"]
    depends_on:
      api0: {condition: service_healthy}
      api1: {condition: service_healthy}
  api0:
    image: python:3.12-slim
    command: ["python3", "/app/api.py"]
    volumes: ["./app:/app:ro"]
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"]
      interval: 2s
      retries: 30
    deploy:
      resources:
        reservations:
          devices: [{driver: nvidia, device_ids: ["0"], capabilities: [gpu]}]
  api1:
    image: python:3.12-slim
    command: ["python3", "/app/api.py"]
    volumes: ["./app:/app:ro"]
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"]
      interval: 2s
      retries: 30
    deploy:
      resources:
        reservations:
          devices: [{driver: nvidia, device_ids: ["$second"], capabilities: [gpu]}]
YML

echo "==> 1. without --allow-device-grants the file is refused: it cannot grant itself the cards"
"$kern" compose docker-compose.yml -p gpu-demo up -d 2>&1 | grep -m1 "ask for a GPU" || true

echo
echo "==> 2. with the operator's grant, up -d --wait (returns once both APIs answer their health check)"
"$kern" compose docker-compose.yml -p gpu-demo up -d --wait --allow-device-grants

echo
echo "==> 3. each route answers from its own card, through nginx on the host's port"
for route in card0 card1; do
    printf '  /%s  ' "$route"
    curl -sS -m 10 "http://127.0.0.1:18931/$route" || echo "(no answer)"
    echo
done

echo
echo "==> 4. the driver's own view from the host: which card each process is on"
echo "  host cards:"
nvidia-smi --query-gpu=index,uuid --format=csv,noheader | sed 's/^/    /'
echo "  processes on them:"
nvidia-smi --query-compute-apps=gpu_uuid,pid,used_memory --format=csv,noheader | sed 's/^/    /'

echo
echo "==> 5. the service that asked for no card has none (/dev/dxg is the card's node on WSL2)"
"$kern" compose docker-compose.yml -p gpu-demo exec -T web -- /bin/sh -c \
    'ls /dev/nvidia* /dev/dxg 2>/dev/null || echo "  web: no GPU node"'

echo
echo "==> 6. down"
"$kern" compose docker-compose.yml -p gpu-demo down

echo
if [ "$cards" -lt 2 ]; then
    echo "done - one card, shared by the two services, granted by the operator; nothing is left running."
else
    echo "done - two cards, one per service, granted by the operator; nothing is left running."
fi
