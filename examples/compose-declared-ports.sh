#!/bin/sh
# A stack is ONE pod: every service shares a single network namespace, the way a Kubernetes pod
# does. That buys you name resolution for free (peers reach each other as http://admin:3100) and
# costs you one thing: two services cannot listen on the same internal port. One binds, the other
# dies with EADDRINUSE buried in its own log, while `up` still reports success.
#
# kern refuses that stack instead, before anything starts. This example walks every case.
#
# Three spellings, one space:
#   ports:  ["8080:80"]   published to the host, and the container side counts
#   port:   3100          declared only, and passed to the service as PORT=3100
#   expose: ["9000"]      declared only, Docker's spelling, no variable set
set -eu
kern="${KERN:-kern}"
w=$(mktemp -d); trap '"$kern" compose "$w/ok.toml" down >/dev/null 2>&1 || true; rm -rf "$w"' EXIT

say() { printf '\n==> %s\n' "$1"; }

# --- 1. a healthy stack, one of each spelling ------------------------------------------------
cat > "$w/ok.toml" <<'EOF'
[box.web]
image = "alpine:3.19"
ports = ["8080:80"]
command = ["sleep", "60"]

[box.admin]
image = "alpine:3.19"
port = 3100
command = ["sleep", "60"]

[box.worker]
image = "alpine:3.19"
expose = ["9000", "53/udp"]
command = ["sleep", "60"]
EOF
say "kern compose ok.toml config   (what kern understood, reservations included)"
"$kern" compose "$w/ok.toml" config

# --- 2. the collision, refused before anything starts ----------------------------------------
cat > "$w/clash.toml" <<'EOF'
[box.a]
image = "alpine:3.19"
port = 3100
command = ["true"]

[box.b]
image = "alpine:3.19"
expose = ["3100"]
command = ["true"]
EOF
say "two services on 3100, one via port: and one via expose: - the same space, so refused"
# `config` is the dry run and refuses EXACTLY what `up` refuses. Run bare and read the status:
# piping it would hide the exit code, which is the thing being demonstrated.
if "$kern" compose "$w/clash.toml" config; then
  echo "!! expected a refusal and did not get one"; exit 1
fi
echo "   (exit 1, and no box was started)"

# --- 3. --no-pod lifts the constraint, because the premise is gone ----------------------------
say "the same file with --no-pod: each service gets its own namespace, so 3100 twice is fine"
"$kern" compose "$w/clash.toml" config --no-pod

# --- 4. a PORT= that contradicts port: --------------------------------------------------------
cat > "$w/contradiction.toml" <<'EOF'
[box.a]
image = "alpine:3.19"
port = 3100
env = ["PORT=9999"]
command = ["true"]
EOF
say "port: 3100 with PORT=9999 - kern would reserve 3100 while the service listens on 9999"
if "$kern" compose "$w/contradiction.toml" config; then
  echo "!! expected a refusal and did not get one"; exit 1
fi

# --- 5. ranges: expanded on ports:, refused on expose: ----------------------------------------
cat > "$w/range.toml" <<'EOF'
[box.a]
image = "alpine:3.19"
ports = ["8000-8002:8000-8002"]
command = ["true"]

[box.b]
image = "alpine:3.19"
port = 8001
command = ["true"]
EOF
say "a range in ports: is expanded, so the clash INSIDE it (8001) is still found"
if "$kern" compose "$w/range.toml" config; then
  echo "!! expected a refusal and did not get one"; exit 1
fi

cat > "$w/erange.toml" <<'EOF'
[box.a]
image = "alpine:3.19"
expose = ["3000-3005"]
command = ["true"]
EOF
say "a range in expose: in YOUR kern profile is refused, with the line number"
if "$kern" compose "$w/erange.toml" config; then
  echo "!! expected a refusal and did not get one"; exit 1
fi

# The same entry in someone else's docker-compose.yml is warned about and skipped instead. Failing a
# whole stack over one line of pure documentation is the wrong trade for a file kern did not write.
# Same parser in both, so "53/udp" means the same thing either way; only the disposition differs.
cat > "$w/erange.yml" <<'EOF'
services:
  a:
    image: alpine:3.19
    expose: ["3000-3005"]
    command: ["true"]
EOF
say "the same range in a docker-compose.yml: warned and skipped, the stack still runs"
"$kern" compose "$w/erange.yml" config

# --- 6. it is not only a dry run: `up` reaches the same verdict --------------------------------
say "the same rejection from up, not just from config"
if "$kern" compose "$w/clash.toml" up; then
  echo "!! up accepted a stack that config refused - they must agree"; exit 1
fi

printf '\nEvery case above is decided by kern, not left to whoever binds first.\n'
