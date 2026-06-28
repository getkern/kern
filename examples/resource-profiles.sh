#!/bin/sh
# Reusable resource PROFILES: define CPU / disk / GPIO slices once in a kern.toml, attach them to
# a box by name.
#
# Instead of repeating --memory/--cpus/--cpuset-cpus on every command, you declare named virtual
# profiles in a kern.toml and reference them with a prefix token before the `--`:
#
#   kern box app --config kern-profiles.toml  vcpu:slim vdisk:scratch  -- ./app
#
# A box loads a config from (highest precedence first):  --config <path>  >  $KERN_CONFIG  >
# ~/.config/kern/kern.toml.  Profile tokens are  vcpu:<name>  vgpio:<name>  vdisk:<name>.
#
# This walk-through uses the sibling kern-profiles.toml. Fully rootless and non-invasive: the vdisk
# is a size-capped tmpfs (RAM-backed, ephemeral); everything is discarded on box exit.
set -eu
kern="${KERN:-kern}"
img="${IMG:-alpine}"

# Find the TOML next to this script (works regardless of the CWD you run from).
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cfg="$here/kern-profiles.toml"
[ -f "$cfg" ] || { echo "missing $cfg (run from a checkout with the examples/ dir)"; exit 1; }

echo "==> the profiles this config defines:"
sed -n 's/^\(name = .*\)/    \1/p' "$cfg"
echo

echo "── 1. it's valid kern.toml:"
"$kern" validate "$cfg" | sed 's/^/   /'

echo
echo "── 2. attach vcpu:slim and see it RESOLVE into concrete caps (--show-config is a dry run):"
echo "     (memory in bytes, cpus = quota, cpuset = pinning, nice from priority)"
"$kern" box rp-slim --image "$img" --config "$cfg" vcpu:slim vdisk:scratch --show-config \
  | grep -E '^(name|memory|cpus|cpuset|nice):' | sed 's/^/   /'

echo
echo "── 3. 'burst' extends 'slim' and overrides it — same dry run shows the merged result:"
"$kern" box rp-burst --image "$img" --config "$cfg" vcpu:burst --show-config \
  | grep -E '^(memory|cpus|cpuset):' | sed 's/^/   /'
echo "   (cpus 0.5->2, memory 256M->512M; cpuset 0 inherited from slim)"

echo
echo "── 4. the vdisk:scratch profile is a real mount at /vdisk/scratch inside the box:"
"$kern" box rp-disk --image "$img" --config "$cfg" vdisk:scratch -- sh -c '
  echo "     mount:"; df -h /vdisk/scratch 2>/dev/null | sed "s/^/       /"
  echo "hello from a profile-mounted disk" > /vdisk/scratch/note.txt
  echo "     wrote + read back: $(cat /vdisk/scratch/note.txt)"
'
echo "   (the 32m cap is a tmpfs here — rootless; kern upgrades it to ext4-on-loop when privileged)"

echo
echo "NOTE on enforcement: --show-config prints the resolved INTENT. Hard CPU/memory caps need a"
echo "cgroup v2 delegation (e.g. a systemd user slice) to be kernel-enforced — see governed-run.sh"
echo "and SECURITY.md. The vgpio:leds profile is device-dependent; see device-isolation.sh."
echo
echo "done — profiles defined once, reused by name; the boxes and their tmpfs are gone."
