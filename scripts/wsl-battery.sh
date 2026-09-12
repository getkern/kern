#!/bin/sh
# Run the fault-taxonomy battery INSIDE a WSL2 distro, from the Linux side of the bridge.
#
# WHY A SCRIPT AND NOT A COMMAND LINE. Every trap here has been paid for at least once:
#
#   * `wsl -d kern -- sh -c '<script>'` loses the script: PowerShell eats `$i` and nested quoting before
#     WSL ever sees it. The rule is a FILE with LF endings, copied in, and run by path.
#   * `2>&1 | Out-String` in PowerShell turns kern's progress lines on stderr into red
#     `NativeCommandError` entries. Measured: `$Error.Count` was 0 without the capture and 14 with it.
#     Nothing here pipes kern through PowerShell.
#   * The distro is ALPINE, so the binary must be the **musl** build. A glibc binary fails with a
#     loader error that reads like a kern bug.
#   * Alpine has no python3 by default and the battery is Python, so it is installed here rather than
#     discovered missing halfway through a run.
#
# Run it INSIDE the distro (`wsl -d kern`), not from Windows:
#
#     sh scripts/wsl-battery.sh /path/to/kern-musl /path/to/bindings/python
#
# Both paths may be under /mnt/c. The battery needs to import the binding, so the binding's directory
# is what is passed, not a file.
set -eu

KERNBIN=${1:-}
SDKDIR=${2:-}
if [ -z "$KERNBIN" ] || [ -z "$SDKDIR" ]; then
    echo "usage: wsl-battery.sh <kern-musl-binary> <bindings/python dir>" >&2
    exit 2
fi
if [ ! -x "$KERNBIN" ]; then
    echo "not executable: $KERNBIN" >&2
    exit 2
fi
if [ ! -f "$SDKDIR/kern_sandbox/__init__.py" ]; then
    echo "not a bindings/python directory: $SDKDIR" >&2
    exit 2
fi

# IDENTITY FIRST, and the musl check is the one that matters here: a glibc binary on Alpine dies with a
# loader error, and the message a reader gets does not say "wrong build".
echo "== identity"
"$KERNBIN" --version
if command -v sha256sum >/dev/null 2>&1; then sha256sum "$KERNBIN"; fi
# NO `ldd` CHECK HERE, and it was here and it lied. On Alpine, musl's `ldd` answers a STATIC binary
# with something that matches neither "not a dynamic executable" nor "statically", so the check printed
# "this binary is dynamically linked" about a correct musl build. The step above already settles it: a
# glibc binary on Alpine cannot run at all, so if `--version` printed a version, the binary is right.
# A check that can fire on a correct input, next to a step that already proves the point, is noise.

echo "== python3"
if ! command -v python3 >/dev/null 2>&1; then
    echo "  installing (Alpine ships none)"
    apk add --no-cache python3 >/dev/null 2>&1 || {
        echo "  could not install python3; run 'apk add python3' as root and retry" >&2
        exit 2
    }
fi
python3 --version

# THE CAP QUESTION, ASKED BEFORE THE BATTERY, because it is the one thing a WSL2 distro answers
# differently from a CI runner and from a desktop: measured on this distro on 2026-09-05, a
# `--memory 128M` box read `memory.max` = 134217728 exactly, so the OOM cases here should RUN and not
# skip. If they skip, the distro has changed and that is the finding.
echo "== does a memory cap bite in this distro"
"$KERNBIN" box wslcapprobe-$$ --image alpine --memory 64m -- \
    /bin/sh -c 'cat /sys/fs/cgroup$(awk -F: "/^0::/{print \$3}" /proc/self/cgroup)/memory.max 2>/dev/null' \
    || echo "  (the probe box did not run)"

echo "== battery"
HERE=$(cd "$(dirname "$0")" && pwd)
KERN_BIN="$KERNBIN" PYTHONPATH="$SDKDIR" python3 "$HERE/fault-taxonomy-battery.py" "$KERNBIN"
