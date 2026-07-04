# kern on the edge (ARM / Jetson / Pi)

kern is a great fit for small, RAM-constrained Linux boards — precisely because it has **no
daemon**. On an 8 GB Jetson or a Raspberry Pi, a container *daemon* is a permanent tax:
`dockerd` + `containerd` sit at **~186 MB RSS before you run anything**. kern's runtime cost at
rest is **zero** — each box is one short-lived process at a few MB, started in single-digit ms.
That difference is the whole game on a device where memory is the scarce resource.

## Why daemonless matters more on the edge

| | kern | daemon-based runtime |
|---|---|---|
| resident memory at rest | **0** | ~186 MB (dockerd + containerd) |
| per box | ~7 MB, gone on exit | shared daemon state |
| binary | ~1.5 MB static (musl) | tens of MB + daemon |
| install | drop one static binary | service + socket + root setup |
| privileges | rootless (user namespaces) | typically a root daemon/group |

On a 4–8 GB board, "give back 186 MB and run rootless" is often the difference between *fits* and
*doesn't*. You can run several isolated services, a per-job pipeline, or CI **on the device
itself** without standing up an always-on engine.

## What's validated

kern's isolation (namespaces + cgroups v2 + seccomp + pivot/overlay) is **architecture-neutral**.
It has been run by hand (static `aarch64-musl` binary) on:

- **x86_64** — primary, plus automated CI.
- **NVIDIA Jetson Orin** (L4T, kernel 5.15-tegra, aarch64) — full battery passes: image pull,
  overlay, `-v`/`--env`/`--net`, `exec`, `stats`, and **20 boxes in parallel in ~150 ms**.
- **Raspberry Pi 5** (aarch64).
- **Arduino UNO Q** (Android 6.16.7 kernel, Debian userland, aarch64) — full battery passes:
  image pull, overlay, volumes, env, `--net`, exec, detached services, `--read-only`, and
  parallel fan-out; sub-MB per box. (`--read-only` works because kern remounts an *overlay*
  read-only, not a bind mount — this Android kernel denies the latter in a user namespace.)
  For the same reason, a **read-only *volume* bind** (`-v host:box:ro`) is **not** supported on such
  kernels — a `:ro` bind has no overlay to remount, so kern fails it with a clear message; use a
  read-write `-v` or `--read-only` for the box root instead. (Verified on the UNO Q, kern 0.6.2.)

> Honest status: ARM is **manually validated**, not yet in CI (tracked in the issues). And kern
> on the edge today is the **sandbox/OCI runtime** — fast, tiny, daemonless isolation. **GPU
> slicing is on the roadmap (0.9), not in this release**; don't expect device-GPU virtualization
> here yet.
>
> **"Android kernel" ≠ "Android the OS".** kern runs on a board whose *kernel* is Android's as
> long as the **userland is Linux** (glibc/musl, a shell) with userns + cgroups v2 — the Arduino
> UNO Q is exactly that (Android kernel + Debian userland). It does **not** run on a stock Android
> phone/tablet (Bionic userland, SELinux enforcing, unprivileged userns usually disabled).
>
> uid mapping: the default is a single-uid map (fast + most isolated). Pass `--uid-range` for
> `apt install` and daemons that drop to a non-root user (e.g. Apache → `www-data`); it needs
> `newuidmap`/`newgidmap` + an `/etc/subuid`/`/etc/subgid` allocation. On a board without those
> (no `uidmap` package / no subids — as on some minimal edge images) `--uid-range` warns and stays
> single-uid: the box still runs, but use images with packages **pre-installed** there.

## Requirements on a board

- A Linux kernel with **unprivileged user namespaces** enabled
  (`/proc/sys/kernel/unprivileged_userns_clone` = 1, or the modern default), plus **cgroups v2**.
- For hard memory/PID caps, a **systemd user manager** (`systemd-run --user`). Without it kern
  still runs and isolates; caps degrade to best-effort (see [SECURITY.md](SECURITY.md)).
- `curl` + GNU `tar` for `--image` pulls (or bring a rootfs with `--rootfs`).

## Install (ARM)

```sh
curl -fsSL https://getkern.dev/install.sh | sh     # picks the linux-aarch64 static binary
# or build natively on the board (e.g. Jetson L4T): cargo build --release
```

Prebuilt static binaries are published for `linux-aarch64` as well as `linux-x86_64`.

## Edge-shaped examples

- [examples/edge-many-services.sh](examples/edge-many-services.sh) — many isolated services on
  one small board; `kern stats` shows the few-MB footprint vs a 186 MB daemon.
- [examples/data-pipeline.sh](examples/data-pipeline.sh) — a per-job pipeline (read-only input →
  isolated processing → output volume), one box per sensor/file/tenant.
- [examples/ci-in-a-box.sh](examples/ci-in-a-box.sh) — build/test in a clean box **on the device**.
- [examples/parallel-matrix.sh](examples/parallel-matrix.sh) — fan out isolated jobs with no
  daemon to serialize them.
