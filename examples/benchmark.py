#!/usr/bin/env python3
"""Reproduce the README "Performance" table on your own machine.

Same workload as the docs: isolate one `/bin/true` and measure *startup overhead*, against
whatever runtimes are installed (kern, bubblewrap, crun, runc, podman, docker). Latency is
reported as **total time / N** over N sequential runs — at sub-millisecond scale a per-call
timer (its own fork+exec) would dominate, so we never time a single run on its own.

    python3 examples/benchmark.py                 # auto-detect everything, 200 runs + 200 parallel
    python3 examples/benchmark.py --runs 500
    python3 examples/benchmark.py --conc 50       # lighter concurrency (e.g. on an edge board)
    KERN=./target/release/kern python3 examples/benchmark.py

It prints the same three tables as BENCHMARKS.md — cold-start (median/min/max), throughput
(runs/s, same data), and concurrency (N parallel, wall-clock) — for whatever runtimes are
installed, so anyone can reproduce the published numbers on their own machine. Stdlib only,
no dependencies. Honest caveat: the top tier sits within a couple ms of each
other and of run-to-run noise — nobody "wins" single-shot latency outright. The real gap is to
the engines (podman/docker), which fork conmon / round-trip a daemon every run.
"""

import argparse
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

DEVNULL = subprocess.DEVNULL


def sh(argv, env=None):
    """Run argv silently; never raise. Returns True on exit 0."""
    return subprocess.run(argv, stdout=DEVNULL, stderr=DEVNULL, env=env).returncode == 0


def have(name):
    return shutil.which(name) is not None


def get_rootfs(kern, workdir):
    """An Alpine rootfs for kern/bwrap/crun/runc. Pull it once with kern if needed."""
    dest = os.path.join(workdir, "alpine-rootfs")
    print("==> pulling alpine rootfs (once)...", file=sys.stderr)
    if not sh([kern, "pull", "alpine", "--dest", dest]):
        sys.exit("could not pull alpine with kern — pass a ready rootfs via --rootfs")
    return dest


def make_oci_bundle(spec_tool, rootfs, workdir):
    """A minimal rootless OCI bundle (config.json + rootfs copy) for crun/runc."""
    bundle = os.path.join(workdir, "bundle")
    os.makedirs(os.path.join(bundle, "rootfs"), exist_ok=True)
    subprocess.run(["cp", "-a", rootfs + "/.", os.path.join(bundle, "rootfs")], check=True)
    subprocess.run([spec_tool, "spec", "--rootless"], cwd=bundle, check=True,
                   stdout=DEVNULL, stderr=DEVNULL)
    cfg = os.path.join(bundle, "config.json")
    with open(cfg) as f:
        c = json.load(f)
    c["process"]["args"] = ["/bin/busybox", "true"]
    c["process"]["terminal"] = False
    with open(cfg, "w") as f:
        json.dump(c, f)
    return bundle


def bench(label, cmd_for, n, repeat, uid, env=None):
    """Warm once, then time `repeat` batches of `n` runs each. Returns the per-batch ms/run
    samples (sorted) so the caller can report min / median / max — runtimes vary run-to-run
    (runc especially), and a single batch would hide that. `uid` yields a globally-unique id per
    run so OCI container names never collide across batches."""
    sh(cmd_for(next(uid)), env=env)  # warm (caches, cgroup tree, image store)
    samples = []
    for _ in range(repeat):
        start = time.perf_counter_ns()
        for _ in range(n):
            sh(cmd_for(next(uid)), env=env)
        samples.append((time.perf_counter_ns() - start) / 1e6 / n)  # ms/run for this batch
    samples.sort()
    return samples


def main():
    ap = argparse.ArgumentParser(description="Reproduce the kern Performance benchmark.")
    ap.add_argument("--runs", type=int, default=200, help="runs per batch (default 200)")
    ap.add_argument("--repeat", type=int, default=5, help="batches per runtime, for min/median/max (default 5)")
    ap.add_argument("--conc", type=int, default=200, help="parallel starts for the concurrency test (0 = skip; default 200)")
    ap.add_argument("--rootfs", help="an existing Alpine rootfs dir (else pulled with kern)")
    args = ap.parse_args()

    kern = os.environ.get("KERN", "kern")
    if not (have(kern) or os.path.exists(kern)):
        sys.exit(f"kern not found ({kern}) — set KERN=/path/to/kern")

    work = tempfile.mkdtemp(prefix="kern-bench-")
    rootfs = args.rootfs or get_rootfs(kern, work)
    bare_env = dict(os.environ, KERN_SCOPE="1")  # KERN_SCOPE=1 = skip the systemd cgroup scope

    # (label, command-builder, env) for each available runtime; `skipped` records the rest with a
    # reason. On an edge board (Jetson / Pi / Android-kernel SBC) the engines often can't be
    # installed at all — kern, a single static binary, still runs. That gap *is* the point.
    rows = [("kern box --rootfs", lambda i: [kern, "box", f"kb{i}", "--rootfs", rootfs,
                                             "--", "/bin/busybox", "true"], bare_env)]
    skipped = []

    if have("bwrap"):
        rows.append(("bubblewrap", lambda i: [
            "bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--unshare-net", "--bind", rootfs, "/", "--proc", "/proc", "--dev", "/dev",
            "/bin/busybox", "true"], None))
    else:
        skipped.append("bubblewrap — not installed")

    spec_tool = "runc" if have("runc") else ("crun" if have("crun") else None)
    bundle = make_oci_bundle(spec_tool, rootfs, work) if spec_tool else None
    for rt in ("crun", "runc"):
        if have(rt) and bundle:
            rows.append((rt, lambda i, rt=rt: [rt, "run", "--bundle", bundle, f"{rt}{i}"], None))
        else:
            skipped.append(f"{rt} — " + ("not installed" if not have(rt)
                                         else "no OCI runtime to build a bundle"))

    if have("podman"):
        rows.append(("podman run --rm", lambda i: [
            "podman", "run", "--rm", "--network", "none", "alpine", "/bin/true"], None))
    else:
        skipped.append("podman — not installed")

    if have("docker"):
        if sh(["docker", "info"]):
            sh(["docker", "pull", "alpine"])
            rows.append(("docker run --rm", lambda i: [
                "docker", "run", "--rm", "alpine", "/bin/true"], None))
        else:
            skipped.append("docker — installed but the daemon isn't running/reachable")
    else:
        skipped.append("docker — not installed")

    n, repeat = args.runs, args.repeat
    uid = itertools.count()  # globally-unique id per run (no OCI name collisions across batches)
    print(f"\nOne isolated /bin/true — {repeat} batches × {n} runs, time/run = total / {n}.")
    print("(kern here is the bare box, no cgroup cap — like bubblewrap; add a hard cap with the")
    print(" default `kern box` and it is ~5.5 ms, tied with crun.)\n")

    results = []
    for label, cmd_for, env in rows:
        print(f"  benchmarking {label} ...", end=" ", flush=True)
        s = bench(label, cmd_for, n, repeat, uid, env=env)
        lo, med, hi = s[0], s[len(s) // 2], s[-1]
        results.append((label, lo, med, hi))
        print(f"median {med:.1f} ms/run  (min {lo:.1f}, max {hi:.1f})")

    results.sort(key=lambda r: r[2])  # by median
    kern_med = next(med for lbl, lo, med, hi in results if lbl.startswith("kern"))
    width = max(len(l) for l, *_ in results)
    print(f"\n  {'runtime'.ljust(width)}   median   (min–max)        throughput   vs kern")
    print(f"  {'-' * width}   ------   ---------        ----------   -------")
    for label, lo, med, hi in results:
        ratio = med / kern_med
        if med == kern_med:
            rel = "—"
        elif ratio >= 1:  # slower than kern
            rel = f"{ratio:.1f}× slower" if ratio < 10 else f"{ratio:.0f}× slower"
        else:  # faster than kern — report it honestly, don't dress it up
            rel = f"{1 / ratio:.1f}× faster"
        print(f"  {label.ljust(width)}   {med:5.1f}ms  ({lo:4.1f}–{hi:5.1f})   "
              f"{1000 / med:6.0f} runs/s   {rel}")
    if skipped:
        print(f"\n  Not runnable on this machine (kern is — that's the point):")
        for s in skipped:
            print(f"    ✗ {s}")

    # Concurrency — fan out `conc` isolated starts in parallel (all at once), wall-clock + success
    # count. This is the daemonless, lock-free win: kern forks each box independently, while the
    # engines serialize through a daemon. Engines spawn `conc` client processes at once, so this is
    # deliberately heavy — `--conc 0` skips it.
    if args.conc:
        c = args.conc
        print(f"\nConcurrency — {c} isolated /bin/true in parallel (wall-clock, succeeded/total):")
        for label, cmd_for, env in rows:
            sh(cmd_for(next(uid)), env=env)  # warm
            start = time.perf_counter_ns()
            procs = [subprocess.Popen(cmd_for(next(uid)), stdout=DEVNULL, stderr=DEVNULL, env=env)
                     for _ in range(c)]
            ok = sum(p.wait() == 0 for p in procs)
            wall = (time.perf_counter_ns() - start) / 1e9
            print(f"  {label.ljust(width)}   {wall:6.2f} s   {ok}/{c}")

    print("\nTop tier sits within a couple ms (= noise) — nobody 'wins' single-shot latency")
    print("outright. The real gap is to the engines. Full method + table: BENCHMARKS.md\n")

    # Best-effort: reap any OCI container state a crashed run might have left behind.
    for rt in ("runc", "crun"):
        if have(rt):
            out = subprocess.run([rt, "list", "-q"], capture_output=True, text=True).stdout
            for cid in out.split():
                sh([rt, "delete", "-f", cid])
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
