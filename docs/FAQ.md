# FAQ

Short answers to the questions that come up first. The threat model in full is
[SECURITY.md](../SECURITY.md).

## Is kern a Docker replacement?

Partly. kern speaks Docker's **formats** (OCI images, `docker-compose.yml`, Dockerfiles), not its API.
It starts a real, kernel-enforced container from an OCI image in ~3.6 ms against `docker run`'s ~294 ms,
with no daemon, rootless by default, and 0 RAM at rest. It has no overlay networks, no plugin
ecosystem and no Swarm; it does not implement CRI (for Kubernetes, use containerd or CRI-O). Reach for
kern where the daemon, the root, and the hundreds of milliseconds hurt: agent tool-calls, CI jobs,
per-request functions, dev sandboxes, edge and ARM. The full compatibility matrix is
[docs/DOCKER-COMPAT.md](DOCKER-COMPAT.md).

## kern vs bubblewrap?

bubblewrap is a sandbox **launcher**; kern is a **runtime**. bwrap has no OCI image pull, no lifecycle
(`ps`/`stop`/`exec`/`stats`), no resource profiles, no Python/Node SDK, no faults-as-data, no compose,
and a simpler seccomp posture. They are in the same speed class: measured together in one session
they read 2.7 ms each, and kern is applying a memory and PID cap there that bwrap does not apply at
all ([BENCHMARKS.md](../BENCHMARKS.md)). Speed is not the point anyway: the value is the runtime
around the namespaces, not the raw primitive. If all you need is to
unshare a few namespaces and exec, bwrap is a fine, smaller tool.

## kern vs youki / runc?

youki and runc are **low-level OCI runtimes**: they run a pre-made bundle and are normally driven by an
engine (Docker, Podman, containerd) above them. kern is the whole runtime (pull, box, lifecycle, SDK).
In one same-host measurement (same busybox rootfs, full lifecycle) a youki create+start+delete was
~42 ms against kern's ~4 ms full box, roughly 10x; numbers vary by host and kernel. kern also installs
a deny-by-default seccomp allowlist that a stock low-level runtime does not.

## kern vs E2B / Modal / Daytona?

Those are hosted clouds: they need an account, a network round-trip and per-execution cost, and they do
not run offline, air-gapped, in your CI, or on your own hardware. kern runs on your own machine with nothing
to call. For **actively hostile, multi-tenant** code from strangers on shared hardware they use a
hardware boundary (a microVM); kern's ground is your own or semi-trusted code run locally. Same job,
different substrate.

## Does it run on Windows?

Not natively. kern's isolation is Linux kernel machinery (user namespaces, cgroup v2, seccomp), so it
runs on **Linux** (x86_64 and ARM) and **WSL2**. On Windows, use WSL2: the
release ships a pre-baked WSL rootfs and a small `kern.exe` shim.

## Does it run on macOS?

Not natively, and that is a non-goal rather than work left undone: macOS has no namespaces and no
cgroups, so there is nothing there for kern to build a box out of. It does run **on a Mac inside a
Linux VM**, where it is the ordinary Linux kern, same binary and same CLI as your CI box. The Linux
install line sets one up on a Mac: a Lima VM with no Docker inside, kern in it, and a `kern` command
on the Mac that runs it there ([docs/INSTALL.md](INSTALL.md#macos)). Any other Linux VM works too.

**Which guest you pick changes how much of kern you get**, and the gap is bigger than it looks. Both
options below have been observed rather than assumed, and they are not equivalent.

**A Fedora guest gives the whole runtime.** A user on Apple Silicon running Lima with Fedora 43
(`6.17.1-300.fc43.aarch64`) posted their `kern doctor` in
[issue #5](https://github.com/getkern/kern/issues/5): 16 ok and one warning. Unprivileged user
namespaces enabled, AppArmor not restricting them, **`cgroup v2` + a `systemd --user` scope with
resource caps enforced**, caps going straight into `kern.slice` with no per-box systemd round trip,
lingering on, unprivileged overlayfs, `newuidmap`, `pasta`, and Landlock ABI v7. The single warning
was a missing `sshfs`. Nothing switched off. Their host, their output, reported rather than measured
here, which is why it is attributed: Lima's own template list is the place to get a Fedora guest.

**An Ubuntu guest works, with two things switched off.** Verified directly, on a MacBook with Apple
Silicon and an Ubuntu 24.04 guest (colima 0.10.3): kern installs, a box from an OCI image starts,
and the Python SDK drives it. What you give up on that guest:

- **The first box fails on AppArmor**, because Ubuntu 23.10 and newer restrict unprivileged user
  namespaces. `kern doctor` names it first and prints the fix
  (`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`), which a VM restart undoes. The
  VM the installer creates gets kern's own AppArmor profile instead, which survives a restart.
- **The resource caps do not bite**: no `systemd --user` manager and no delegated `memory`
  controller, so a box's `--memory` is accepted and never enforced. kern says so at every box start
  instead of pretending, `--require-limits` refuses to run uncapped, and `kern run --memory` refuses
  there without being asked. The isolation itself (namespaces,
  pivoted root, seccomp, Landlock) is unaffected.

Neither of those applies to the Fedora guest above, which is the whole reason both are documented
instead of one.

Whichever guest you pick, **no GPU and no GPIO** are reachable from a Linux VM on a Mac. Apple
exposes neither, which is why Docker Desktop has no GPU for containers either.

[docs/INSTALL.md](INSTALL.md) has the detail and the way back to enforced caps.

## Can I use kern on another machine?

Over SSH, as any other command: `ssh workstation kern ps`, and `ssh -t workstation kern top` for the
live view. Nothing listens on the remote machine: kern starts, answers and exits.

- **kern has to be on the PATH of a non-interactive shell there.** Installed as root it is in
  `/usr/local/bin`, and it is. A user install puts it in `~/.local/bin`, which a non-interactive SSH
  command does not have on its PATH on Ubuntu: call it as `ssh workstation '~/.local/bin/kern ps'`.
- **A box started with `-d` outlives the SSH session only with lingering on** for that user
  (`loginctl enable-linger`): without it, systemd stops the user's services when the last session
  ends. `kern doctor` checks it.
- **Reuse the connection.** Measured against a remote server: 1.8 s per call with a new SSH
  connection each time, 0.29 s with `ControlMaster auto` and `ControlPersist 60` for that host in
  `~/.ssh/config`.

## Is it safe to run truly hostile, untrusted multi-tenant code?

The boundary is the Linux kernel, so a kernel privilege-escalation bug is an escape, and an unprivileged
user namespace is itself kernel attack surface. This is the container model, not a kern quirk: Docker
and Podman share the same kernel and the same escape condition, which is why gVisor and Firecracker
exist. For strangers' hostile code on shared hardware, reach for a microVM (Firecracker, Kata) or
gVisor. kern is honest about this in [SECURITY.md](../SECURITY.md) before it makes any claim; its ground
is semi-trusted or your-own code: CI, build steps, dev sandboxes, an agent's tool-calls under your
supervision.

## How do my SSH keys and cloud credentials stay out of the sandbox?

Nothing reaches the box by mount or by inheritance. Mounts over `~/.ssh`, `~/.aws`, `~/.kube`,
`~/.gnupg` and the other credential directories are refused, with no opt-out, and the box does not
inherit your environment. What DOES reach it is what you pass with `env=`, so a credential handed over
that way is in the sandbox because you put it there; and there is no network unless you open it. The two threats this separates, a compromised
dependency and a prompt-injected agent, are in
[SECURITY.md](../SECURITY.md#credentials-and-network-in-the-sandbox-sdk).

## Isn't a fresh container per tool-call slow?

Not at this cost: one call measured at about a twentieth of `docker run --rm`, and most of what is left
is CPython starting inside the box. The SDK hides even that two ways: a prewarm pool starts the next box
before it is asked for, and `Sandbox.kernel()` keeps one interpreter warm across cells, so the start is
paid once and in-memory state carries over. The method and the numbers are in
[BENCHMARKS.md](../BENCHMARKS.md).

## Why does `kern --version` print `0.0.0` from a source build?

By design. The source is version-free (no stale number lives in git); the version lives in the git tag
and the release. A published release binary reports the release version; a from-source `cargo install`
reports `0.0.0`, which is expected and harmless.

## Does kern support GPUs?

Yes, as a device: whole cards, never a slice of one. `kern box --gpus 2` hands over two cards, `--gpus all` hands over every card, and `--gpus device=0` hands over that one, which is docker's grammar: a bare number is a COUNT and `device=N` is an INDEX. A card's UUID works where the index does (`--gpus device=GPU-1950be8a-…`), read from the driver's own `GPU UUID` field, and `--device nvidia.com/gpu=0` is the CDI spelling of a card (`=all` for every card; the flag repeats, as in docker and podman). The host's driver libraries are resolved from the driver's own version and bound read-only into the image's library directory, where docker puts them, so the box does not need a CUDA image. A compose service reaches a card four ways, each needing `--allow-device-grants` from the operator: `gpus:`, `deploy.resources.reservations.devices`, a CDI name under `devices:`, or the host nodes under `devices:`. `allow_gpu_grants = true` in your own [`kern.toml`](CONFIG.md) grants the first three (and `runtime: nvidia`) with no flag and nothing else, as the NVIDIA container toolkit does once installed. `runtime: nvidia` is read with NVIDIA's meaning (the GPUs the image's `NVIDIA_VISIBLE_DEVICES` names, `kern box --runtime nvidia` on the command line), under the same operator gate. `NVIDIA_VISIBLE_DEVICES` alone is not a request, and kern names it with the line to write instead. A render node can also be granted as `display` in [`kern.toml`](CONFIG.md). kern does not split a GPU between boxes or cap it per box, and a card you did not name has no device node in the box, so CUDA cannot initialise it there.

**`nvidia-smi` is in the box, where docker puts it.** A grant binds the driver's tools the host
has (`nvidia-smi`, `nvidia-debugdump`, `nvidia-persistenced`, `nvidia-cuda-mps-control`,
`nvidia-cuda-mps-server`) read-only at `/usr/bin`, which is what docker's NVIDIA runtime injects, and
sets `NVIDIA_VISIBLE_DEVICES` to the value docker sets for the same `--gpus`. So the command every
guide prints, `--gpus all nvidia/cuda:…-base nvidia-smi`, runs and lists the granted cards. The tools
are glibc builds: on an alpine image they are in the box and cannot run, under docker too, and kern
says that in the hint under the failure. NVML is there either way: `libnvidia-ml.so` is bound,
`nvmlInit` returns 0, and the device count is the granted card.

**Two cards in one box work for compute, and so do NCCL collectives.** `--gpus all` hands over both, CUDA counts both, kernels execute (a hand-written PTX kernel runs and returns the right answer inside a box), and `ncclAllReduce` across both cards returns the right answer too.

This page said the opposite until 2026-11-12, and the reason is worth keeping, because it is the trap any reader writing their own probe will hit. The earlier measurement used a ctypes harness with **no `argtypes` declared**. Indexing a `(c_void_p * N)` array returns a Python int, and ctypes marshals an undeclared Python int as a C `int`: 32 bits. The 64-bit communicator pointer was being truncated before NCCL ever saw it. A core dump named the instruction, two after a NULL check that passed, loading a field from a base of `0x413c2a90`. Whether that truncation is harmless depends on where the allocator happened to put the communicator: on the host it landed at `0x1823fbc0`, which survives a 32-bit narrowing, and in a box at `0x56105d00b420`, which does not. **The host/box asymmetry that made it look like a sandbox limit was allocator luck.** With the signatures declared, the same collective returns the right answer in a box with one card and with two.

So single-card and multi-card training and inference work. If you write your own CUDA or NCCL probe through ctypes, declare `argtypes` on every call: an undeclared pointer argument is a 32-bit argument.

**The topology reports as on the host.** A `--gpus` box gets a read-only view of the part of `/sys` that places its cards: each granted card's device directory, the attribute files of the PCI bridges above it (never the bridge directories, which list the other devices behind them), the `bus/pci/devices` and `class/pci_bus` entries as links, and the host's CPU and NUMA topology. Measured with two RTX 5060 Ti under one host bridge: `nvidia-smi topo -m` in a box answers `PHB`, as on the host and under Docker, and the topology NCCL dumps (`NCCL_TOPO_DUMP_FILE`) equals Docker's apart from the host hash and the network interface. Nothing under it can be written. On WSL2 the GPU is `/dev/dxg` and has no PCI directory, so there is no topology to give.
kern today virtualizes CPU (`vcpu:`), memory, disk (`vdisk:`) and devices (`vgpio:`).
