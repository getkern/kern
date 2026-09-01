#!/bin/sh
# Point `docker` at kern and keep typing what you already type.
#
# kern reads its own argv[0]: invoked as `docker` it translates the command line and runs it as a
# rootless, daemonless box. There is nothing to configure, no socket, and no daemon to start.
#
#   ln -s "$(command -v kern)" ~/.local/bin/docker
#
# The translation is honest about its limits, which is the part worth reading. Every flag lands in
# exactly one of three buckets, and the third one is why you can trust the first two:
#
#   PASS  kern has the same flag        -> forwarded verbatim
#   DROP  pure metadata, no runtime effect -> dropped, with a note on stderr
#   FAIL  changes behaviour, kern has no equivalent -> REFUSED, loudly
#
# Unknown flags FAIL too. A best-effort shim that silently ignores what it does not understand
# gives you a container that is not the one you asked for, and you find out much later.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2

w=$(mktemp -d); trap 'rm -rf "$w"' EXIT
mkdir -p "$w/bin"
ln -sf "$(command -v "$kern" || echo "$kern")" "$w/bin/docker"
export PATH="$w/bin:$PATH"

say() { printf '\n==> %s\n' "$1"; }

say 'docker run --rm alpine:3.19 echo "hello"'
docker run --rm alpine:3.19 echo "hello from a rootless box, no daemon"

say 'docker ps'
docker ps

# --- FAIL: refused rather than quietly misinterpreted ------------------------------------------
say 'docker run --device /dev/kvm ...   (FAIL bucket: refused, not ignored)'
if docker run --rm --device /dev/kvm alpine:3.19 true; then
  echo "!! expected a refusal"; exit 1
fi

say 'docker run --pid=host ...   (namespace sharing would break the boundary kern exists for)'
if docker run --rm --pid=host alpine:3.19 true; then
  echo "!! expected a refusal"; exit 1
fi

# --- compose, including the flag everyone types -------------------------------------------------
cat > "$w/stack.yml" <<'EOF'
services:
  web:
    image: alpine:3.19
    command: ["sleep", "60"]
  cache:
    image: alpine:3.19
    command: ["sleep", "60"]
EOF
say 'docker compose -f stack.yml up -d'
# `-d` is the most-typed flag in the ecosystem. compose is already detached in kern, so it lands in
# the DROP bucket: forwarding it verbatim used to kill the command on kern's usage text.
( cd "$w" && docker compose -f stack.yml up -d )
say 'docker compose -f stack.yml ps'
( cd "$w" && docker compose -f stack.yml ps )
say 'docker compose -f stack.yml down'
( cd "$w" && docker compose -f stack.yml down )

cat <<'TEXT'

--------------------------------------------------------------------------------
Two things the shim does NOT pretend about:

  --privileged is forwarded, but kern's is not Docker's. kern stays rootless: it
      relaxes a handful of syscalls for nesting, it does not hand you the host. If
      you need Docker's meaning, you need Docker.

  There is no /var/run/docker.sock. Anything that talks to the Engine API instead
      of running the CLI (some IDE integrations, testcontainers) does not work, and
      cannot: kern has no daemon to talk to. That is the trade, stated once.
--------------------------------------------------------------------------------
TEXT
