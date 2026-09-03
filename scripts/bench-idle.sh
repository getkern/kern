#!/bin/sh
# kern against bubblewrap on an IDLE machine, which is the one condition eleven replicas have not had.
#
# WHAT ELEVEN REPLICAS ALREADY SETTLED, so this does not re-ask it: kern is faster, every time. The
# direction never moved across 44,000 starts, 158 of 160 batches, and not one of eleven bootstrap
# intervals touched zero. What is NOT settled is the size, because it moves with the scheduler:
# roughly +9% under a free scheduler and +6.5% with the core pinned, where BOTH runtimes drop about
# 0.7 ms because the cache stays warm. Part of the margin was scheduling rather than code.
#
# So this measures the same thing on a quiet machine, both ways, and prints them side by side.
#
# THE THREE VARIABLES ARE FIXED HERE, because each one moved the answer by more than the answer:
#   * the BINARY: the shipped static-pie musl build, not `cargo build --release`, which is glibc on a
#     normal distro and 9% slower because it pays ld.so twice.
#   * the FLAGS: kern's default behaviour, cgroup cap and all. `KERN_NO_SCOPE=1` was added once to
#     "level the field" and makes kern 0.22 ms SLOWER, so it levels nothing.
#   * the ORDER: batches alternate, and the starting runtime flips between replicas. Measured in
#     sequence instead, bubblewrap alone read 3.0 one day and 2.7 the next: three times the margin.
#
# Usage:  sh scripts/bench-idle.sh [replicas]      (default 4: two free, two pinned)
set -eu

REPS=${1:-4}
KERN="target/$(uname -m)-unknown-linux-musl/release/kern"
[ -x "$KERN" ] || { echo "build it first:  cargo build --release --target $(uname -m)-unknown-linux-musl" >&2; exit 2; }
command -v bwrap >/dev/null || { echo "bubblewrap is not installed here" >&2; exit 2; }

# IDLE IS THE POINT OF THIS SCRIPT, so it refuses rather than producing a number that says something
# about the browser instead of about the runtimes.
#
# MEASURED FROM /proc/stat OVER TWO SECONDS, not from the load average, and the first version used the
# load average and was wrong: that number carries a minute of history, so running this script twice in
# a row refuses the second time because it remembers the FIRST RUN. It reported 0.84 on a machine that
# was already idle. What matters here is whether the CPU is busy NOW.
# LC_ALL=C ON EVERY awk HERE, and without it this gate quietly under-reports. In an Italian locale
# `printf "%.1f"` emits a COMMA, and awk then reads "12,5" as 12: a machine at 12.5% busy passed a
# `> 12` check. It always fails toward accepting, which is the wrong direction for a gate whose whole
# job is to refuse. Found in this script's own output, printing "1,1%".
busy_now() {
    set -- $(LC_ALL=C awk '/^cpu /{print $2+$3+$4+$6+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat)
    b1=$1; t1=$2
    sleep 2
    set -- $(LC_ALL=C awk '/^cpu /{print $2+$3+$4+$6+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat)
    LC_ALL=C awk -v b1="$b1" -v t1="$t1" -v b2="$1" -v t2="$2" 'BEGIN{d=t2-t1; printf "%.1f", (d>0)?100*(b2-b1)/d:0}'
}
busy=$(busy_now)
if [ "$(LC_ALL=C awk -v b="$busy" 'BEGIN{print (b > 12)}')" = "1" ]; then
    echo "the CPU is $busy% busy right now: close what is running, this measures the machine otherwise." >&2
    echo "(override with FORCE=1 if you know why)" >&2
    [ "${FORCE:-0}" = "1" ] || exit 1
fi
echo "  CPU busy at start: $busy%   (load average, which lags by a minute: $(awk '{print $1}' /proc/loadavg))"

D=$(mktemp -d) || exit 2
RF=$D/rootfs
mkdir -p "$RF/bin" "$RF/proc" "$RF/dev"
BB=$(command -v busybox) || { echo "busybox needed for the test rootfs" >&2; exit 2; }
cp "$BB" "$RF/bin/busybox"
for l in $(ldd "$BB" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
    [ -e "$l" ] && { mkdir -p "$RF$(dirname "$l")"; cp "$l" "$RF$l" 2>/dev/null; }
done
ln -sf busybox "$RF/bin/true"

cat > "$D/run.py" <<'PY'
import os, random, statistics, subprocess, sys, time
RF, REP, KERN = sys.argv[1], int(sys.argv[2]), os.path.abspath(sys.argv[3])
DN = subprocess.DEVNULL
V = {
    "kern": lambda n: [KERN, "box", n, "--rootfs", RF, "--", "/bin/true"],
    "bwrap": lambda n: ["bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
                        "--unshare-net", "--bind", RF, "/", "--proc", "/proc", "--dev", "/dev", "/bin/true"],
}
for name, mk in V.items():
    if subprocess.run(mk(f"probe{REP}"), capture_output=True).returncode != 0:
        print(f"    positive control failed for {name}"); raise SystemExit(3)

def batch(mk, n, tag):
    t0 = time.perf_counter()
    for i in range(n):
        subprocess.run(mk(f"{tag}{i}"), stdout=DN, stderr=DN)
    return (time.perf_counter() - t0) / n * 1000

for mk in V.values():          # warm-up, never counted
    batch(mk, 30, f"w{REP}")
order = list(V.items())
if REP % 2:                    # odd replicas start from bwrap: if order matters, it shows
    order = order[::-1]
res = {k: [] for k in V}
for r in range(10):
    for k, mk in order:
        res[k].append(batch(mk, 200, f"a{REP}{r}{k[0]}"))
    for k, mk in reversed(order):
        res[k].append(batch(mk, 200, f"b{REP}{r}{k[0]}"))
ks, bs = res["kern"], res["bwrap"]
mk_, mb = statistics.median(ks), statistics.median(bs)
random.seed(1000 + REP)
d = sorted(statistics.median(random.choices(bs, k=len(bs))) - statistics.median(random.choices(ks, k=len(ks)))
           for _ in range(20000))
lo, hi = d[500], d[19499]
print(f"    kern {mk_:.3f}  bwrap {mb:.3f}  diff {mb-mk_:+.3f} ms ({(mb-mk_)/mb*100:+.1f}%)  "
      f"IC95 [{lo:+.3f}, {hi:+.3f}]  kern faster in {sum(1 for a, b in zip(ks, bs) if a < b)}/20")
PY

i=1
while [ "$i" -le "$REPS" ]; do
    if [ $((i % 2)) -eq 1 ]; then
        echo "  replica $i (free scheduler, starts from $([ $((i % 2)) -eq 1 ] && echo bwrap || echo kern)):"
        python3 "$D/run.py" "$RF" "$i" "$KERN"
    else
        core=$(( (i * 3) % $(nproc) ))
        echo "  replica $i (pinned to core $core):"
        taskset -c "$core" python3 "$D/run.py" "$RF" "$i" "$KERN"
    fi
    i=$((i + 1))
done
echo "  CPU busy at end: $(busy_now)%"
rm -rf "$D"
