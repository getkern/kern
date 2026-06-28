# kern examples

Real, runnable use-cases. Install kern first:

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

<details><summary>…or build from source</summary>

```sh
cargo build --release      # then add target/release to PATH, or use ./target/release/kern
```

Every script honours `KERN=./target/release/kern` (and the SDKs honour `KERN_BIN`) if you'd rather
point at a local build than one on `PATH`.

</details>

All examples are plain shell scripts you can read and run. They use unprivileged user
namespaces (no root, no daemon) and pull images straight from a registry (Docker Hub, GHCR, …)
with `curl` + `tar` — kern needs **no Docker and no container runtime installed**.

**New here? [`showcase.sh`](showcase.sh) runs the whole tour in one go** — a tool from a clean
image, your code in it, governed resources, untrusted code held at arm's length, and a
background service; each isolated, daemonless, and gone when it's done.

**Sceptical? [`hardening.sh`](hardening.sh) tries to break out** — an adversarial battery
(PID / filesystem / capability / device isolation, read-only root, and 50 boxes at once) that
shows the boundaries holding.

| Example | What it shows |
|---|---|
| [run-an-image.sh](run-an-image.sh) | Pull a real OCI image and run a command in an isolated, writable box |
| [throwaway-shell.sh](throwaway-shell.sh) | An ephemeral writable shell — changes vanish on exit, image stays clean |
| [untrusted-code.sh](untrusted-code.sh) | Run code you don't trust: read-only root + seccomp + no network + caps |
| [services-and-ps.sh](services-and-ps.sh) | Detached boxes, `kern ps`, `kern stop` — lifecycle without a daemon |
| [serve-with-port.sh](serve-with-port.sh) | Publish a box port to the host (`-p`), keep it up + health-checked (`--restart` / `--health-cmd`) |
| [governed-run.sh](governed-run.sh) | Govern CPU + memory — `kern run` (no sandbox) and `--memory`/`--cpus` caps (OOM-enforced) |
| [mounts-and-exec.sh](mounts-and-exec.sh) | Data in/out with `-v` (+ `--env`/`--workdir`), and `kern exec` into a running box |
| [with-network.sh](with-network.sh) | Isolated by default; `--net` for outbound (DNS + fetch/install) |
| [observe.sh](observe.sh) | Daemonless observability: `kern logs` / `stats` / `top` |
| [compose-stack.sh](compose-stack.sh) + [stack.toml](stack.toml) | Bring up a multi-box stack in dependency order |
| [fan-out.sh](fan-out.sh) | Run hundreds of isolated jobs in parallel (per-task sandboxing) |
| [inspect-plan.sh](inspect-plan.sh) | `--plan`: see the exact isolation steps before running anything |
| [nested-privileged.sh](nested-privileged.sh) | Run a `kern box` inside a `kern box` — `--privileged` relaxes exactly 5 syscalls (rootless-only), keeps the rest blocked |
| [save-load-interop.sh](save-load-interop.sh) | `kern save` / `kern load` — move an image as a plain tar, Docker-loadable both ways, no registry |

### Things kern makes trivial (that otherwise need a daemon, root, or a hand-built rootfs)

| Example | What it shows |
|---|---|
| [try-any-distro.sh](try-any-distro.sh) | Run a command on Alpine + Debian + Ubuntu instantly — throwaway, nothing installed on the host |
| [build-and-extract.sh](build-and-extract.sh) | Compile in a disposable toolchain; keep the artifact, your host never gets the compiler |
| [parallel-matrix.sh](parallel-matrix.sh) | Run one command across a matrix of images **all at once** (daemonless fan-out — no serialization) |

### Secrets, storage & volumes

| Example | What it shows |
|---|---|
| [secrets.sh](secrets.sh) | `--secret` delivers a secret to `/run/secrets/<name>` (RAM-backed, `0400`, gone on exit) — file (`SRC:NAME`) or stdin (`NAME=-`) form |
| [named-volumes.sh](named-volumes.sh) | `kern volume create/inspect/rm`: a named volume persists across boxes (write in A, read in B); `--size` records a quota (a hard cap needs root/ext4-loop — use `vdisk:` for a rootless-enforced size) |
| [vdisk-scratch.sh](vdisk-scratch.sh) | A `vdisk:` scratch disk from a `[[vdisk]]` profile (`--config`), mounted at `/vdisk/<name>` — a rootless size cap the kernel enforces (writing past it → `ENOSPC`) |

### Lifecycle & operations

| Example | What it shows |
|---|---|
| [copy-files.sh](copy-files.sh) | `kern cp` a single file host↔box, resolved inside the box's root (`openat2` — symlinks can't escape to host paths) |
| [pause-and-attach.sh](pause-and-attach.sh) | `kern pause` / `unpause` freeze & thaw a box (cgroup-v2 freezer), and `kern attach` to reconnect a detached box's live output |
| [monitor-top-stats.sh](monitor-top-stats.sh) | Daemonless observability: `kern stats --json` (per-box CPU/mem), a `kern top` snapshot, `kern inspect --json` |
| [gc-prune-doctor.sh](gc-prune-doctor.sh) | Housekeeping: `kern doctor` preflight, `kern prune` (stopped-box leftovers), `kern gc` (reap dead boxes) |

### Networking & pods

| Example | What it shows |
|---|---|
| [pods.sh](pods.sh) | `kern pod create` shared-network pods: two boxes joined with `--pod` reach each other by name on one shared loopback; `--no-outbound` blocks egress while keeping intra-pod networking |
| [add-host.sh](add-host.sh) | `--add-host NAME:IP` custom `/etc/hosts` entries, plus the `host-gateway` keyword resolving to the host IP |
| [port-publish-advanced.sh](port-publish-advanced.sh) | `-p` beyond a single port: a host↔box port **range**, a `/udp` mapping, and default-loopback vs explicit `0.0.0.0:` bind |
| [tun-device.sh](tun-device.sh) | `--tun` provisions `/dev/net/tun` inside the box (present with `--tun`, absent without) for a userspace VPN |

### Build, registry & platform

| Example | What it shows |
|---|---|
| [build-with-dockerfile.sh](build-with-dockerfile.sh) | `kern build -t` from a Dockerfile (`--build-arg`, `ARG`/`ENV`/`WORKDIR`/`CMD`), then run the built tag |
| [multi-stage-build.sh](multi-stage-build.sh) | `FROM … AS builder` + `COPY --from=`: compile in a fat stage, ship a slim final image with no compiler |
| [platform-pull.sh](platform-pull.sh) | `kern pull --platform linux/amd64` vs `linux/arm64` — proven by decoding the busybox ELF header |
| [tag-and-push-local.sh](tag-and-push-local.sh) | `kern tag` + `kern push` round-trip against a throwaway `registry:2` box on `127.0.0.1:5000` (loopback ⇒ plain-HTTP OK), then pull it back |

### Users, edge & resource profiles

| Example | What it shows |
|---|---|
| [multi-uid.sh](multi-uid.sh) | Who runs inside a box: single-uid default vs `--uid-range` (a ~65k sub-uid range) vs `--user 1000`; degrades honestly when `newuidmap`/`/etc/subuid` are absent |
| [bind-rootfs-edge.sh](bind-rootfs-edge.sh) | `--bind-rootfs` — the edge/Android fast path that binds a `--rootfs` directly instead of an overlay; honest trade: writable & **shared**, not copy-on-write |
| [init-reaper.sh](init-reaper.sh) | `--init` — a reaping PID 1: orphaned children pile up as zombies without it, get reaped (0) with it |
| [resource-profiles.sh](resource-profiles.sh) + [kern-profiles.toml](kern-profiles.toml) | Reusable `[[vcpu]]` / `[[vdisk]]` / `[[vgpio]]` profiles in a kern.toml, attached via `--config` + `vcpu:` / `vdisk:` tokens |

### Real-life scenarios

| Example | What it shows |
|---|---|
| [safe-install-script.sh](safe-install-script.sh) | Vet an untrusted `curl \| sh` script in a throwaway box — no network, no host access |
| [data-pipeline.sh](data-pipeline.sh) | Per-job pipeline: read-only input → isolated processing → output volume |
| [ci-in-a-box.sh](ci-in-a-box.sh) | Build/test a repo in a clean box (laptop or on-device), exit code propagated |
| [web-service.sh](web-service.sh) | Run a web server in a box, publish it to the host with `-p`, and `curl` it |
| [media-transcode.sh](media-transcode.sh) | Transcode media (ffmpeg) in a box, CPU-capped — your host needs no ffmpeg |
| [serverless-per-request.sh](serverless-per-request.sh) | A fresh, isolated box per request — the function / serverless pattern |
| [edge-many-services.sh](edge-many-services.sh) | Many isolated services on a small board — few-MB footprint vs a ~186 MB daemon |
| [device-isolation.sh](device-isolation.sh) | Give a box exactly one hardware device (i2c / serial / spi) and nothing else |

### Side-by-side with other tools

| Example | What it shows |
|---|---|
| [familiar-commands.sh](familiar-commands.sh) | Coming from Docker / AWS / GCP? The same verbs and building blocks, mapped to kern |
| [benchmark.py](benchmark.py) | Reproduce the whole **Performance** table — kern vs bubblewrap / crun / runc / podman / docker (auto-detects what's installed) |
| [compare-vs-docker.sh](compare-vs-docker.sh) | Same isolated `/bin/true`, kern vs `docker run` — timed, and kern needs no daemon |
| [compare-vs-bwrap.sh](compare-vs-bwrap.sh) | Same speed class as bubblewrap, but kern adds OCI images, overlay, and lifecycle |

### Embed kern in your own program

Don't shell out — call kern as a library and get a structured result back (exit code, stdout/stderr
with truncation flags, wall time). Ideal for running LLM/agent-generated code or CI steps.

| Example | What it shows |
|---|---|
| [embed-python.py](embed-python.py) | The `kern_sandbox` Python package: a fresh box per `run_code`, file-state on disk, sandbox faults (timeout/OOM/blocked-escape) as data — not exceptions |
| [embed-rust.rs](embed-rust.rs) | The `kern-isolation` crate's fluent `Sandbox::builder()…build()?.run(...)` → a structured `Outcome` |

### Windows

| Example | What it shows |
|---|---|
| [windows-wsl2.md](windows-wsl2.md) | kern on Windows runs inside WSL2 — same commands, real kernel-enforced caps; honest note that it uses the WSL2 kernel (no VM of its own) |

> Edge / ARM (Jetson, Pi, …): see **[../EDGE.md](../EDGE.md)** — the daemonless footprint is the
> killer feature on RAM-constrained boards.

Every box gets: user + PID + network + UTS + IPC + mount namespaces, a pivoted root, an
always-on seccomp denylist, and cgroup caps (via `systemd-run --user --scope` where available).
See [../SECURITY.md](../SECURITY.md) for the threat model.
