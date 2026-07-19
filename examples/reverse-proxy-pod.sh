#!/bin/sh
# A reverse-proxy POD: an app box behind an nginx box, sharing ONE network namespace.
# Only nginx's port is published to the host; the app is reachable ONLY inside the pod.
#
# Pod semantics (see pods.sh) that this recipe leans on:
#   - members share ONE loopback, so services must use DISTINCT ports (nginx :80, app :8080);
#   - members resolve each other BY NAME via the pod's shared /etc/hosts (nginx proxies to
#     http://app:8080, which resolves to 127.0.0.1 on the shared loopback);
#   - `-p` on a member publishes THAT service to the host (here: only nginx's :80).
#
# The nginx box uses the official image with a small self-contained config we bind over
# /etc/nginx. It runs workers as root (mapped uid 0) on purpose: `kern pod create` maps a
# single uid into the pod, so the stock config's drop to the `nginx` user (uid 101) has no uid
# to land on. `user root;` keeps everything on the one mapped uid - no privilege drop needed.
# (For images that MUST drop to a service uid inside a shared netns, use `kern compose`, which
# maps a uid range into the pod automatically - see compose-webstack.sh.)
set -eu
kern="${KERN:-kern}"

pod=rp-pod
port="${PORT:-8088}"
conf="$(mktemp -d)"

cleanup() {
  "$kern" stop app proxy >/dev/null 2>&1 || true
  "$kern" pod rm "$pod" >/dev/null 2>&1 || true
  rm -rf "$conf"
  "$kern" gc >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# A minimal, self-contained nginx.conf: workers as root, one server that proxies to the app peer
# BY NAME over the shared loopback. No mime.types/include needed for a plain proxy.
cat > "$conf/nginx.conf" <<'NGINX'
user root;
worker_processes 1;
pid /tmp/nginx.pid;
events { worker_connections 128; }
http {
    access_log /dev/stdout;
    server {
        listen 80;
        location / {
            proxy_pass http://app:8080;
        }
    }
}
NGINX

echo "==> 1. create the pod (loopback-only; the app never touches the host network):"
"$kern" pod create "$pod" --no-outbound

echo
echo "==> 2. the APP: a detached box in the pod, serving HTTP on :8080 (NOT published):"
"$kern" box app --pod "$pod" --image alpine -d -- \
  sh -c 'while true; do printf "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello from the APP behind nginx\n" | nc -lp 8080; done'
sleep 1

echo
echo "==> 3. NGINX in front: same pod, published to the host on 127.0.0.1:$port -> nginx :80:"
"$kern" box proxy --pod "$pod" --image nginx -d \
  -p "$port:80" -v "$conf:/etc/nginx:ro"

echo "==> waiting for the proxy to answer..."
fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsS --max-time 2 "$1" 2>/dev/null
  else wget -qO- -T 2 "$1" 2>/dev/null; fi
}
i=0
while [ "$i" -lt 25 ]; do
  if body="$(fetch "http://127.0.0.1:$port/")"; then break; fi
  i=$((i + 1)); sleep 1
done
[ "$i" -lt 25 ] || { echo "   proxy did not come up"; exit 1; }

echo
echo "==> kern pod ls (both members share the pod's one netns):"
"$kern" pod ls | sed 's/^/   /'

echo
echo "==> a request to the HOST-published nginx port reaches the app THROUGH the proxy:"
printf '   host -> nginx:%s -> app:8080 responded: %s\n' "$port" "$body"

echo
echo "==> cleanup (via trap): stop app+proxy, remove the pod, drop the temp config, kern gc."
