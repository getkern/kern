# Introducing kern: a container runtime that does less than Docker, on purpose

*A fast, rootless sandbox and virtual resource runtime for any workload, including untrusted and
AI-generated code. One ~1.58 MB static binary, one Rust dependency (`libc`), no daemon. It starts a
real, kernel-enforced box in 2.2 ms, embeds from Python or Rust, and runs the same on a laptop, in
CI, or on a Raspberry Pi.*

Most container tooling is built around a daemon. You install a service that stays resident, holds the
image store and the network, and every `run` is a round-trip to it. That buys a lot of features, and
it costs a resident process, a socket to secure, ~293 ms of start latency, and a footprint that keeps
kern off a lot of small machines entirely.

kern is the other trade. There is no daemon. `kern box` forks one short-lived process, sets up Linux
namespaces + seccomp + cgroups, `pivot_root`s into an overlay, and `exec`s your workload, then gets
out of the way. State lives in the kernel, so `kern ps` reads it straight from there. When the box
exits, nothing is left resident.

```sh
kern box dev --image alpine -- sh    # a throwaway, isolated Alpine shell, in a few ms
```

That's a real OCI image, pulled from any registry, running in its own namespaces with an always-on
seccomp filter and a writable overlay that's discarded on exit. No Docker, no container runtime, no
root.

## Two verbs

kern is built around one idea, *virtual resources*. A container is just the first resource it
manages (isolation); the same model extends to CPU, memory, disk and GPIO slices. That collapses to
two verbs:

- **`kern box`**: *isolate this workload.* Its own namespaces, an overlay or read-only root, a
  private process tree, seccomp. The container.
- **`kern run`**: *give this workload a governed slice of resources.* A CPU / memory / I/O quota on a
  host command, no sandbox, just the governor.

They compose: `run` inside `box`. Both ship today.

## Embed it

The same engine runs from your program, one fresh isolated box per call, the shape you want for
untrusted code, agent tools, or per-request workers, with a structured result back:

```python
import kern_sandbox as kern
r = kern.run_code("print(sum(range(100)))")   # network OFF, hard caps, an enforced timeout
print(r.stdout, r.success)                     # → a fresh box, discarded after
```

Safe by default: every *relaxing* argument (`network=True`, extra `mounts`) has to be spelled out, and
the binding owns the timeout, so a `timeout` fault is a fact, not a guess. There's a Rust crate
(`kern-isolation`, `Sandbox::builder()`) with the same story. This is microVM-grade isolation territory, but
*local* and ~1.58 MB, no cloud, no account, no VM.

## Fast, and honest about it

One isolated `/bin/true`, warm image cache, on an x86_64 desktop (Linux 6.17, mean over 200 runs):

| runtime | cold start | |
|---|---|---|
| **kern** `box --rootfs` | **2.2 ms** | overlay + self-pivot + seccomp |
| bubblewrap | 2.9 ms | a sandbox *primitive*, no images, caps, or lifecycle |
| crun | 5.2 ms (not installed on the machine re-measured) | OCI runtime (C) |
| runc (rootless) | 13.8 ms | OCI runtime (Go) |
| podman (rootless) | 287.5 ms | daemonless engine: forks `conmon` + the full OCI stack per run |
| docker run --rm | 292.9 ms | client → daemon round-trip |

The honest version: **nobody wins single-shot latency outright**: the top tier is all within a couple
of milliseconds, i.e. noise. kern leads that tier while being the only one of them that ships a full
daemonless container UX (OCI pull *and build*, overlay, volumes, secrets, `ps`/`exec`/`logs`, compose)
in ~1.58 MB. The real gap is to the *engines*: **~80-133× faster to start** than podman/Docker (the
spread is the two kern paths: 2.2 ms with `--rootfs`, 3.4 ms with `--image`, which also maps a uid
range), which
fork `conmon` or round-trip a daemon every run, and kern keeps **0 RAM resident** where Docker holds
154 to 160 MB before you run anything. Full method, including where kern *ties* (I/O, cold pull, in-box
compute overhead, all physics, not runtime), is in
[BENCHMARKS.md](https://github.com/getkern/kern/blob/main/BENCHMARKS.md).

## Runs where Docker won't

One static musl binary, multi-arch. The same `kern box` runs on an x86_64 desktop, an NVIDIA Jetson,
a Raspberry Pi 5, and an Arduino UNO Q, the last one on an *Android* kernel with a Debian userland,
because the kernel flavor doesn't matter as long as it has unprivileged user namespaces + cgroup v2.
Daemonless is a real win on RAM-constrained boards: 0 resident vs a couple hundred MB.

**Windows, today, via WSL2.** kern runs inside WSL2, a real Linux kernel, so the hard caps
(`--memory` OOM, `--cpus` throttle, port publish) are real there, verified end-to-end on a live
Windows machine. Honest caveat: kern runs *inside* the WSL2 kernel, so it doesn't shed the VM weight
that native Linux does, the win is "no Docker Desktop", not "no VM".

## Where the boundary is

This is the part a skeptic should ask about first, so here it is plainly. kern isolates with Linux
**namespaces + seccomp + a read-only user-namespace root**: a real kernel-level boundary, deny-by-
default on devices, host sysfs/procfs masked. Every pulled blob is sha256-verified and every layer is
vetted in-process (no `..`/absolute/device escapes, decompression- and inode-bomb caps) before an
isolated no-follow merge. One class of sandbox-escape *ordering* bug is even a compile error, not a
test you hope exists, [that's a separate post](what-the-type-system-buys-you.md).

That's strong for first-party and semi-trusted workloads, CI, dev, edge, your own agents' code. It is
**not** a hardware-virtualization boundary. For actively hostile, multi-tenant, untrusted code where
you want a VM boundary, reach for a microVM, a deliberate trade for 2.2 ms starts and a ~1.58 MB
footprint. [SECURITY.md](https://github.com/getkern/kern/blob/main/SECURITY.md) marks every guarantee
that's cooperative or opt-in, and says exactly when to use kern versus a microVM.

## Try it

```sh
cargo install --git https://github.com/getkern/kern getkern --locked
```

It builds the one static binary for your arch from source (kern's only Rust dependency is `libc`; the
image path shells out to the system `curl`/`tar`), no Docker, no daemon. Then:

```sh
kern box dev --image alpine -it -- sh          # a throwaway shell in a real image
kern run --memory 256M --cpus 0.5 -- ./crunch  # govern a host command, no sandbox
kern doctor                                    # will boxes even run on this host? preflight it
```

kern deliberately skips a lot that Docker has, overlay networks, a plugin ecosystem, because the
point is a small, fast, honest core you can read, embed, and put anywhere. Everything above works
today and is tested: clippy-clean, `cargo-deny`-clean, and audited slice by slice. The test counts
are in the README rather than here, because a number in a post nobody rereads goes stale in a week
and this one had (689, when this was written). The CLI isn't frozen until 1.0.

Code, benchmarks, and the honest security account:
**[github.com/getkern/kern](https://github.com/getkern/kern)**.
