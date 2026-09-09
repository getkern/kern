#!/bin/sh
# The one measurement the review cycle asked for and nobody had: is the cold-start residue kern
# pays the SAME residue under two different definitions of "cold"?
#
# Two conditions, same binary, same rootfs, same `/bin/true`, same core:
#
#   AT REST      30 s of quiet, then ONE process. The condition under which the original
#                15-31 ms first-box defect appeared.
#   ALTERNATING  back-to-back batches, the condition under which the +1.76 ms (kern) and
#                +1.36 ms (bwrap) residues were measured, and from which "0.4 ms is kern's"
#                was concluded.
#
# The claim under test is NOT kern's absolute number, it is whether the DIFFERENCE between kern
# and bwrap survives the change of condition. Both tools pay the harness overhead of a Python
# `subprocess.run`, so it cancels in the difference; it does not cancel in the absolute, which is
# why no absolute from this script belongs in any document.
#
# DECLARED LIMITATION, because it decides how much this measurement is worth: a desktop with a
# browser and an editor running is not an idle machine, and the RCU grace period that made the
# original defect expensive gets short when any core keeps waking. Pinning to a high core number
# and waiting 30 s approximates rest; it does not create it. A result here that shows no
# difference between the two conditions is therefore WEAK evidence - it is consistent with "there
# is no difference" and equally consistent with "this machine cannot produce the at-rest
# condition". A result that DOES show a difference is strong, because the confound pushes the
# other way.
set -eu

REPS=${REPS:-7}
QUIET=${QUIET:-30}
CORE=${CORE:-27}
KERN=${KERN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/kern}

[ -x "$KERN" ] || { echo "no kern binary at $KERN (set KERN=)" >&2; exit 2; }
command -v bwrap >/dev/null || { echo "bubblewrap is not installed here" >&2; exit 2; }
command -v taskset >/dev/null || { echo "taskset (util-linux) needed to pin" >&2; exit 2; }
[ "$CORE" -lt "$(nproc)" ] || { echo "core $CORE does not exist ($(nproc) online)" >&2; exit 2; }

D=$(mktemp -d /var/tmp/kern-bench-rest.XXXXXX)
trap 'rm -rf "$D"' EXIT INT TERM

RF=$D/rootfs
mkdir -p "$RF/bin" "$RF/proc" "$RF/dev"
BB=$(command -v busybox) || { echo "busybox needed for the test rootfs" >&2; exit 2; }
cp "$BB" "$RF/bin/busybox"
for l in $(ldd "$BB" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
    [ -e "$l" ] && { mkdir -p "$RF$(dirname "$l")"; cp "$l" "$RF$l" 2>/dev/null; }
done
ln -sf busybox "$RF/bin/true"

cat > "$D/run.py" <<'PY'
import os, statistics, subprocess, sys, time

RF, REPS, QUIET, KERN = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), os.path.abspath(sys.argv[4])
DN = subprocess.DEVNULL
V = {
    "kern":  lambda n: [KERN, "box", n, "--rootfs", RF, "--", "/bin/true"],
    "bwrap": lambda n: ["bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                        "--unshare-net", "--bind", RF, "/", "--proc", "/proc", "--dev", "/dev", "/bin/true"],
}

# Positive control FIRST: a tool that does not start would otherwise report a very fast failure as
# a very fast success, which is the shape this project keeps getting caught by.
for name, mk in V.items():
    r = subprocess.run(mk("ctl0"), capture_output=True)
    if r.returncode != 0:
        print(f"  positive control FAILED for {name}: rc={r.returncode} {r.stderr[:200]!r}")
        raise SystemExit(3)
print("  positive control: both tools start")

def one(mk, n):
    """One process, wall clock around it. Both tools pay the same harness cost."""
    t0 = time.perf_counter()
    subprocess.run(mk(n), stdout=DN, stderr=DN)
    return (time.perf_counter() - t0) * 1000

def batch(mk, n, tag):
    t0 = time.perf_counter()
    for i in range(n):
        subprocess.run(mk(f"{tag}{i}"), stdout=DN, stderr=DN)
    return (time.perf_counter() - t0) / n * 1000

# ---- condition ALTERNATING: back-to-back, no quiet. Measured FIRST so the at-rest rounds that
# follow are not warmed by it (the reverse order would hand the at-rest condition a warm cache).
alt = {k: [] for k in V}
for k, mk in V.items():
    batch(mk, 30, f"w{k[0]}")          # warm-up, never counted
for r in range(6):
    order = list(V.items()) if r % 2 else list(V.items())[::-1]
    for k, mk in order:
        alt[k].append(batch(mk, 200, f"alt{r}{k[0]}"))

# ---- condition AT REST: QUIET seconds of nothing, then ONE process.
rest = {k: [] for k in V}
for r in range(REPS):
    order = list(V.items()) if r % 2 else list(V.items())[::-1]
    for k, mk in order:
        time.sleep(QUIET)
        rest[k].append(one(mk, f"rest{r}{k[0]}"))

mk_a, mb_a = statistics.median(alt["kern"]), statistics.median(alt["bwrap"])
mk_r, mb_r = statistics.median(rest["kern"]), statistics.median(rest["bwrap"])
print(f"  ALTERNATING  kern {mk_a:6.3f}  bwrap {mb_a:6.3f}  kern-bwrap {mk_a-mb_a:+6.3f} ms   (n=6 batches of 200)")
print(f"  AT REST      kern {mk_r:6.3f}  bwrap {mb_r:6.3f}  kern-bwrap {mk_r-mb_r:+6.3f} ms   (n={REPS} single shots, {QUIET:.0f}s quiet each)")
print(f"  residue      kern {mk_r-mk_a:+6.3f}  bwrap {mb_r-mb_a:+6.3f}  -> the part that is kern's: {(mk_r-mk_a)-(mb_r-mb_a):+.3f} ms")
print(f"  raw kern  at rest: {' '.join(f'{v:.2f}' for v in rest['kern'])}")
print(f"  raw bwrap at rest: {' '.join(f'{v:.2f}' for v in rest['bwrap'])}")
PY

echo "bench-rest: core $CORE, $REPS rounds, ${QUIET}s quiet per sample"
echo "  kern: $KERN"
taskset -c "$CORE" python3 "$D/run.py" "$RF" "$REPS" "$QUIET" "$KERN"
