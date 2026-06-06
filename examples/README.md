# kern examples

Real, runnable use-cases. Build kern first:

```sh
cargo build --release      # then add target/release to PATH, or use ./target/release/kern
```

All examples are plain shell scripts you can read and run. They use unprivileged user
namespaces (no root, no daemon) and pull from Docker Hub via `curl` + `tar`.

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

### Things kern makes trivial (that otherwise need a daemon, root, or a hand-built rootfs)

| Example | What it shows |
|---|---|
| [try-any-distro.sh](try-any-distro.sh) | Run a command on Alpine + Debian + Ubuntu instantly — throwaway, nothing installed on the host |
| [build-and-extract.sh](build-and-extract.sh) | Compile in a disposable toolchain; keep the artifact, your host never gets the compiler |
| [parallel-matrix.sh](parallel-matrix.sh) | Run one command across a matrix of images **all at once** (daemonless fan-out — no serialization) |

### Real-life scenarios

| Example | What it shows |
|---|---|
| [safe-install-script.sh](safe-install-script.sh) | Vet an untrusted `curl \| sh` script in a throwaway box — no network, no host access |
| [data-pipeline.sh](data-pipeline.sh) | Per-job pipeline: read-only input → isolated processing → output volume |
| [ci-in-a-box.sh](ci-in-a-box.sh) | Build/test a repo in a clean box (laptop or on-device), exit code propagated |
| [edge-many-services.sh](edge-many-services.sh) | Many isolated services on a small board — few-MB footprint vs a ~186 MB daemon |

### Side-by-side with other tools

| Example | What it shows |
|---|---|
| [benchmark.py](benchmark.py) | Reproduce the whole **Performance** table — kern vs bubblewrap / crun / runc / podman / docker (auto-detects what's installed) |
| [compare-vs-docker.sh](compare-vs-docker.sh) | Same isolated `/bin/true`, kern vs `docker run` — timed, and kern needs no daemon |
| [compare-vs-bwrap.sh](compare-vs-bwrap.sh) | Same speed class as bubblewrap, but kern adds OCI images, overlay, and lifecycle |

> Edge / ARM (Jetson, Pi, …): see **[../EDGE.md](../EDGE.md)** — the daemonless footprint is the
> killer feature on RAM-constrained boards.

Every box gets: user + PID + network + UTS + IPC + mount namespaces, a pivoted root, an
always-on seccomp denylist, and cgroup caps (via `systemd-run --user --scope` where available).
See [../SECURITY.md](../SECURITY.md) for the threat model.
