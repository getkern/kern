#!/bin/sh
# kern is daemonless, which is the point: nothing of kern is resident when nothing is running.
# The cost is that after a reboot PID 1 comes up, not kern. So a stack that must survive a reboot
# needs an init unit, and `kern compose <file> systemd` writes one for you.
#
# It PRINTS the unit on stdout and installs nothing. Where a unit belongs, whether it is a user
# unit or a system one, and whether it should linger, are decisions about your machine.
#
# Read the generated comments: the unit says out loud what it does NOT do.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2

w=$(mktemp -d); trap 'rm -rf "$w"' EXIT

cat > "$w/shop.toml" <<'EOF'
[box.db]
image = "alpine:3.19"
port = 5432
command = ["sleep", "300"]

[box.api]
image = "alpine:3.19"
port = 3000
depends_on = ["db"]
command = ["sleep", "300"]
EOF

echo '==> kern compose shop.toml systemd'
"$kern" compose "$w/shop.toml" systemd

cat <<'TEXT'

--------------------------------------------------------------------------------
What to notice in what was just printed:

  Type=oneshot + RemainAfterExit=yes
      `up` starts detached boxes and returns. Under Type=simple systemd would read
      that return as "the stack died" and tear it straight back down.

  TimeoutStartSec=600
      the first boot after a fresh install pulls images, which outlasts the 90s default.

  It does NOT supervise.
      The unit starts the stack and stops it. A service that dies an hour later stays
      dead: kern has no per-stack supervisor. The unit says so in its own comments
      rather than letting you assume a restart that will not come.

Installing it (nothing above did):

  kern compose shop.toml systemd > ~/.config/systemd/user/kern-shop.service
  systemctl --user daemon-reload
  systemctl --user enable --now kern-shop.service
  loginctl enable-linger $USER      # or the stack stops when you log out

--------------------------------------------------------------------------------
TEXT

# The unit is generated from a file that has been VALIDATED first: the same graph, condition and
# port checks `config` runs. A unit built from a stack that cannot come up would fail at boot, on a
# machine nobody is watching, which is the worst possible moment to find out.
cat > "$w/broken.toml" <<'EOF'
[box.a]
image = "alpine:3.19"
port = 3100
command = ["true"]

[box.b]
image = "alpine:3.19"
port = 3100
command = ["true"]
EOF
echo '==> a stack that cannot come up produces no unit at all, rather than one that fails at boot'
if "$kern" compose "$w/broken.toml" systemd > "$w/out.service" 2>&1; then
  echo "!! expected a refusal and did not get one"; exit 1
fi
echo "   refused, and nothing usable was written:"
sed 's/^/     /' "$w/out.service"
