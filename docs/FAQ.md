# FAQ

Short, honest answers to the questions that come up first. The threat model in full is
[SECURITY.md](../SECURITY.md); the honest open items are [OPEN_ITEMS.md](../OPEN_ITEMS.md).

## Is kern a Docker replacement?

Partly. kern speaks Docker's **formats** (OCI images, `docker-compose.yml`, Dockerfiles), not its API.
It starts a real, kernel-enforced container from an OCI image in ~3.4 ms against `docker run`'s ~291 ms,
with no daemon, rootless by default, and 0 RAM at rest. It has no overlay networks, no plugin
ecosystem and no Swarm; it does not implement CRI (for Kubernetes, use containerd or CRI-O). Reach for
kern where the daemon, the root, and the hundreds of milliseconds hurt: agent tool-calls, CI jobs,
per-request functions, dev sandboxes, edge and ARM. The full compatibility matrix is
[docs/DOCKER-COMPAT.md](DOCKER-COMPAT.md).

## kern vs bubblewrap?

bubblewrap is a sandbox **launcher**; kern is a **runtime**. bwrap has no OCI image pull, no lifecycle
(`ps`/`stop`/`exec`/`stats`), no resource profiles, no Python/Node SDK, no faults-as-data, no compose,
and a simpler seccomp posture. At namespace parity kern is about 15% faster, but that is not the point:
the value is the runtime around the namespaces, not the raw primitive. If all you need is to unshare a
few namespaces and exec, bwrap is a fine, smaller tool.

## kern vs youki / runc?

youki and runc are **low-level OCI runtimes**: they run a pre-made bundle and are normally driven by an
engine (Docker, Podman, containerd) above them. kern is the whole runtime (pull, box, lifecycle, SDK).
In one same-host measurement (same busybox rootfs, full lifecycle) a youki create+start+delete was
~42 ms against kern's ~4 ms full box, roughly 10x; numbers vary by host and kernel. kern also installs
a deny-by-default seccomp allowlist that a stock low-level runtime does not.

## kern vs E2B / Modal / Daytona?

Those are hosted clouds: they need an account, a network round-trip and per-execution cost, and they do
not run offline, air-gapped, in your CI, or on an ARM board. kern runs on your own machine with nothing
to call. For **actively hostile, multi-tenant** code from strangers on shared hardware they use a
hardware boundary (a microVM); kern's ground is your own or semi-trusted code run locally. Same job,
different substrate.

## Does it run on Windows?

Not natively. kern's isolation is Linux kernel machinery (user namespaces, cgroup v2, seccomp), so it
runs on **Linux, WSL2 and ARM boards** (Raspberry Pi, Jetson, Arduino UNO Q). On Windows, use WSL2: the
release ships a pre-baked WSL rootfs and a small `kern.exe` shim.

## Is it safe to run truly hostile, untrusted multi-tenant code?

The boundary is the Linux kernel, so a kernel privilege-escalation bug is an escape, and an unprivileged
user namespace is itself kernel attack surface. This is the container model, not a kern quirk: Docker
and Podman share the same kernel and the same escape condition, which is why gVisor and Firecracker
exist. For strangers' hostile code on shared hardware, reach for a microVM (Firecracker, Kata) or
gVisor. kern is honest about this in [SECURITY.md](../SECURITY.md) before it makes any claim; its ground
is semi-trusted or your-own code: CI, build steps, dev sandboxes, an agent's tool-calls under your
supervision.

## Why does `kern --version` print `0.0.0` from a source build?

By design. The source is version-free (no stale number lives in git); the version lives in the git tag
and the release. A published release binary reports the release version; a from-source `cargo install`
reports `0.0.0`, which is expected and harmless.

## Where is the GPU support?

Not in this edition. GPU slices are on the [roadmap](../ROADMAP.md); there is no GPU code here yet, so
there is nothing to trust or to attack. kern today virtualizes CPU (`vcpu:`), memory, disk (`vdisk:`)
and devices (`vgpio:`).
