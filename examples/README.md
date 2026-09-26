# kern examples

Real, runnable use-cases. Install kern first:

```sh
cargo install --git https://github.com/getkern/kern getkern --locked
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
with `curl` + `tar`, kern needs **no Docker and no container runtime installed**.

**New here? [`showcase.sh`](showcase.sh) runs the whole tour in one go**: a tool from a clean
image, your code in it, governed resources, untrusted code held at arm's length, and a
background service; each isolated, daemonless, and gone when it's done.

**Sceptical? [`hardening.sh`](hardening.sh) tries to break out**: an adversarial battery
(PID / filesystem / capability / device isolation, read-only root, and 50 boxes at once) that
shows the boundaries holding.

**In a hurry?** Four scripts are the minimal set, one per everyday task:
[`essentials-run.sh`](essentials-run.sh) (a box from a clean image),
[`essentials-service.sh`](essentials-service.sh) (a published service),
[`essentials-mount.sh`](essentials-mount.sh) (your own code mounted in) and
[`essentials-limits.sh`](essentials-limits.sh) (hard CPU and memory caps).

**The rest is in eight folders**, because a hundred files in one directory is a wall rather than a
library. Every one of them is also a row in the tables below, which are organised by task rather than
by folder:

| folder | scripts | what is in it |
|---|---:|---|
| [`basics/`](basics/) | 19 | one box, mounts, logs, `ps`/`top`, pause, gc |
| [`agents/`](agents/) | 12 | the code-execution tool an LLM calls, warm kernels, embedding this in Python/Node/Rust |
| [`compose/`](compose/) | 13 | multi-box stacks, pods, named volumes, rolling and canary deploys |
| [`build/`](build/) | 11 | `kern build`, Dockerfiles, multi-stage, language toolchains, save/load, registries |
| [`ci/`](ci/) | 8 | the same steps locally and in GitHub Actions, air-gapped, pre-commit |
| [`edge/`](edge/) | 13 | services with a published port, data pipelines, a database box, a watchdog |
| [`resources/`](resources/) | 10 | CPU/memory caps, `vcpu:`/`vdisk:` profiles, fan-out, and the comparisons |
| [`security/`](security/) | 6 | second uid, nesting, device grants, secrets, bind-rootfs edges, the tun device |

| Example | What it shows |
|---|---|
| [run-an-image.sh](basics/run-an-image.sh) | Pull a real OCI image and run a command in an isolated, writable box |
| [throwaway-shell.sh](basics/throwaway-shell.sh) | An ephemeral writable shell, changes vanish on exit, image stays clean |
| [untrusted-code.sh](agents/untrusted-code.sh) | Run code you don't trust: read-only root + seccomp + no network + caps |
| [services-and-ps.sh](basics/services-and-ps.sh) | Detached boxes, `kern ps`, `kern stop`, lifecycle without a daemon |
| [serve-with-port.sh](edge/serve-with-port.sh) | Publish a box port to the host (`-p`), keep it up + health-checked (`--restart` / `--health-cmd`) |
| [governed-run.sh](resources/governed-run.sh) | Govern CPU + memory, `kern run` (no sandbox) and `--memory`/`--cpus` caps (OOM-enforced) |
| [mounts-and-exec.sh](basics/mounts-and-exec.sh) | Data in/out with `-v` (+ `--env`/`--workdir`), and `kern exec` into a running box |
| [with-network.sh](basics/with-network.sh) | Isolated by default; `--net` for outbound (DNS + fetch/install) |
| [observe.sh](basics/observe.sh) | Daemonless observability: `kern logs` / `stats` / `top` |
| [compose-stack.sh](compose/compose-stack.sh) + [stack.toml](compose/stack.toml) | Bring up a multi-box stack in dependency order |
| [fan-out.sh](resources/fan-out.sh) | Run hundreds of isolated jobs in parallel (per-task sandboxing) |
| [inspect-plan.sh](basics/inspect-plan.sh) | `--plan`: see the exact isolation steps before running anything |
| [nested-privileged.sh](security/nested-privileged.sh) | Run a `kern box` inside a `kern box`, `--privileged` relaxes exactly 5 syscalls (rootless-only), keeps the rest blocked |
| [save-load-interop.sh](build/save-load-interop.sh) | `kern save` / `kern load`, move an image as a plain tar, Docker-loadable both ways, no registry |

## Things kern makes trivial (that otherwise need a daemon, root, or a hand-built rootfs)

| Example | What it shows |
|---|---|
| [try-any-distro.sh](basics/try-any-distro.sh) | Run a command on Alpine + Debian + Ubuntu instantly, throwaway, nothing installed on the host |
| [build-and-extract.sh](build/build-and-extract.sh) | Compile in a disposable toolchain; keep the artifact, your host never gets the compiler |
| [parallel-matrix.sh](resources/parallel-matrix.sh) | Run one command across a matrix of images **all at once** (daemonless fan-out, no serialization) |

## Secrets, storage & volumes

| Example | What it shows |
|---|---|
| [secrets.sh](security/secrets.sh) | `--secret` delivers a secret to `/run/secrets/<name>` (RAM-backed, `0400`, gone on exit), file (`SRC:NAME`) or stdin (`NAME=-`) form |
| [named-volumes.sh](compose/named-volumes.sh) | `kern volume create/inspect/rm`: a named volume persists across boxes (write in A, read in B); `--size` records a quota (a hard cap needs root/ext4-loop, use `vdisk:` for a rootless-enforced size) |
| [vdisk-scratch.sh](resources/vdisk-scratch.sh) | A `vdisk:` scratch disk from a `[[vdisk]]` profile (`--config`), mounted at `/vdisk/<name>`, a rootless size cap the kernel enforces (writing past it → `ENOSPC`) |

## Lifecycle & operations

| Example | What it shows |
|---|---|
| [copy-files.sh](basics/copy-files.sh) | `kern cp` a single file host↔box, resolved inside the box's root (`openat2`, symlinks can't escape to host paths) |
| [pause-and-attach.sh](basics/pause-and-attach.sh) | `kern pause` / `unpause` freeze & thaw a box (cgroup v2 freezer), and `kern attach` to reconnect a detached box's live output |
| [monitor-top-stats.sh](basics/monitor-top-stats.sh) | Daemonless observability: `kern stats --json` (per-box CPU/mem), a `kern top` snapshot, `kern inspect --json` |
| [ps-scripting.sh](basics/ps-scripting.sh) | `kern ps` for automation: `-q`, `--filter name=/status=/id=`, `--format '{{.Field}}'` TSV columns; stop a whole fleet with `kern stop $(kern ps -q)` |
| [logs-tail-follow.sh](basics/logs-tail-follow.sh) | `kern logs --tail N` (bounded read near EOF, cheap on GB-size logs) + `-f`/`--follow` live stream; `--tail 0 -f` follows only new output |
| [fleet-watchdog.sh](edge/fleet-watchdog.sh) | A daemonless supervisor in a shell loop: `ps --filter status=running` detects a crashed box, `logs --tail` grabs its crash tail, then it restarts. No daemon, no root |
| [multi-box-logs.sh](basics/multi-box-logs.sh) | Daemonless `compose logs -f`: follow a whole fleet at once with `logs --tail 0 -f` per box, each line prefixed with its box name, merged to one stream |
| [log-triage.sh](basics/log-triage.sh) | Incident triage on a huge log: `logs --tail N` seeks a bounded window near EOF (O(lines shown), not O(file size)), pulling the crash tail off a ~200k-line log instantly, plus a `ps` state snapshot |
| [gc-prune-doctor.sh](basics/gc-prune-doctor.sh) | Housekeeping: `kern doctor` preflight, `kern prune` (stopped-box leftovers), `kern gc` (reap dead boxes) |

## Networking & pods

| Example | What it shows |
|---|---|
| [pods.sh](compose/pods.sh) | `kern pod create` shared-network pods: two boxes joined with `--pod` reach each other by name on one shared loopback; `--no-outbound` blocks egress while keeping intra-pod networking |
| [add-host.sh](edge/add-host.sh) | `--add-host NAME:IP` custom `/etc/hosts` entries, plus the `host-gateway` keyword resolving to the host IP |
| [port-publish-advanced.sh](edge/port-publish-advanced.sh) | `-p` beyond a single port: a host↔box port **range**, a `/udp` mapping, and default-loopback vs explicit `0.0.0.0:` bind |
| [tun-device.sh](security/tun-device.sh) | `--tun` provisions `/dev/net/tun` inside the box (present with `--tun`, absent without) for a userspace VPN |

## Build, registry & platform

| Example | What it shows |
|---|---|
| [build-with-dockerfile.sh](build/build-with-dockerfile.sh) | `kern build -t` from a Dockerfile (`--build-arg`, `ARG`/`ENV`/`WORKDIR`/`CMD`), then run the built tag |
| [multi-stage-build.sh](build/multi-stage-build.sh) | `FROM … AS builder` + `COPY --from=`: compile in a fat stage, ship a slim final image with no compiler |
| [platform-pull.sh](build/platform-pull.sh) | `kern pull --platform linux/amd64` vs `linux/arm64`, proven by decoding the busybox ELF header |
| [tag-and-push-local.sh](build/tag-and-push-local.sh) | `kern tag` + `kern push` round-trip against a throwaway `registry:2` box on `127.0.0.1:5000` (loopback ⇒ plain-HTTP OK), then pull it back |
| [pull-policy.sh](build/pull-policy.sh) | `--pull missing\|never\|always`: reuse cache (missing), fail closed offline (never), and force a fresh pull with an atomic swap a LIVE box survives (always, zero-downtime image refresh) |

## Users, edge & resource profiles

| Example | What it shows |
|---|---|
| [multi-uid.sh](security/multi-uid.sh) | Who runs inside a box: single-uid default vs `--uid-range` (a ~65k sub-uid range) vs `--user 1000`; degrades honestly when `newuidmap`/`/etc/subuid` are absent |
| [bind-rootfs-edge.sh](security/bind-rootfs-edge.sh) | `--bind-rootfs`, the edge/Android fast path that binds a `--rootfs` directly instead of an overlay; honest trade: writable & **shared**, not copy-on-write |
| [init-reaper.sh](basics/init-reaper.sh) | `--init`, a reaping PID 1: orphaned children pile up as zombies without it, get reaped (0) with it |
| [edge-webserver-ssh.sh](edge/edge-webserver-ssh.sh) | A web server on a headless board, published to the LAN, with `--ssh` into the box. The two things that bite on a board: build with `--net` but SERVE without it (`-p` and `--net` don't combine), and `loginctl enable-linger` or a detached box dies at logout. The only example that leaves a box running on purpose (it holds host 8080 + 2222 so you can reach it from another machine); `KEEP=0` makes it clean up instead |
| [resource-profiles.sh](resources/resource-profiles.sh) + [kern-profiles.toml](resources/kern-profiles.toml) | Reusable `[[vcpu]]` / `[[vdisk]]` / `[[vgpio]]` profiles in a kern.toml, attached via `--config` + `vcpu:` / `vdisk:` tokens |

## Real-life scenarios

| Example | What it shows |
|---|---|
| [safe-install-script.sh](agents/safe-install-script.sh) | Vet an untrusted `curl \| sh` script in a throwaway box, no network, no host access |
| [data-pipeline.sh](edge/data-pipeline.sh) | Per-job pipeline: read-only input → isolated processing → output volume |
| [ci-in-a-box.sh](ci/ci-in-a-box.sh) | Build/test a repo in a clean box (laptop or on-device), exit code propagated |
| [web-service.sh](edge/web-service.sh) | Run a web server in a box, publish it to the host with `-p`, and `curl` it |
| [media-transcode.sh](edge/media-transcode.sh) | Transcode media (ffmpeg) in a box, CPU-capped, your host needs no ffmpeg |
| [serverless-per-request.sh](agents/serverless-per-request.sh) | A fresh, isolated box per request, the function / serverless pattern |
| [edge-many-services.sh](compose/edge-many-services.sh) | Many isolated services on a small board, few-MB footprint vs a ~155 MB daemon |
| [rolling-redeploy.sh](compose/rolling-redeploy.sh) | Zero-downtime rolling redeploy: `--pull always` swaps the image atomically (live boxes survive), bring up new instances then retire old ones, fleet never drops below target. Daemonless, no k8s |
| [canary-deploy.sh](compose/canary-deploy.sh) | Canary with keep-old-on-failure: `--pull always` refresh, run one canary, gate on its verdict read back via `logs --tail`; prod is never touched if the canary is unhealthy |
| [scale-test.sh](resources/scale-test.sh) | Burst N isolated boxes (~2.3 ms each, no dockerd), drive the whole set from `ps -q`: count, `--filter` sample, then reap with one `kern stop $(kern ps -q)` |
| [device-isolation.sh](security/device-isolation.sh) | Give a box exactly one hardware device (i2c / serial / spi) and nothing else |

## Per-language dev & build boxes (your host stays clean)

| Example | What it shows |
|---|---|
| [node-app.sh](build/node-app.sh) | Run a Node.js service with no node/npm on the host: `npm install` a dep with `--net`, then serve it network-isolated with `-p` |
| [go-static-build.sh](build/go-static-build.sh) | Build a static Go binary (`CGO_ENABLED=0`) in a `golang` box, then run the extracted artifact in a bare `alpine` box that has no Go |
| [python-data.sh](edge/python-data.sh) | A Python data task with no python/pip on the host: `pip install` in the one `--net` step, then process a bound-in CSV network-off, output to `-v` |
| [rust-build.sh](build/rust-build.sh) | Compile Rust in a `--memory`/`--cpus`-capped `rust` box (governed build), run the extracted binary in a separate minimal box |

## Services & stacks

| Example | What it shows |
|---|---|
| [database-box.sh](edge/database-box.sh) | A stateful `redis` service that outlives its box: detached on a named volume + published port; write a key, discard the box, restart on the same volume, read it back |
| [reverse-proxy-pod.sh](compose/reverse-proxy-pod.sh) | An `nginx` box in front of an app box in one `--pod` (shared loopback, peer-by-name); only nginx's port is published, a host request reaches the app through the proxy |
| [scheduled-job.sh](ci/scheduled-job.sh) | Daemonless cron-like pattern: a loop starting a fresh, capped, self-removing box each interval, honest that kern has no built-in scheduler (pair with host cron) |
| [compose-webstack.sh](compose/compose-webstack.sh) + [compose-webstack.toml](compose/compose-webstack.toml) | A richer `kern compose` stack: a cache with a `--health-cmd` and a web front-end gated on `depends_healthy`, brought up in health order and torn down |
| [docker-compose-file.sh](compose/docker-compose-file.sh) | **The file you already have**: a real `docker-compose.yml` with a health check, a `depends_on` that waits for it, a published port, a named volume and `extra_hosts: host.docker.internal`. Then the sequence a deploy script runs: `up -d --wait`, `ps --format json` (Docker's field names), `exec`, `cp`, `down -v` |
| [compose-declared-ports.sh](compose/compose-declared-ports.sh) | One stack is one pod, so two services cannot both listen on the same internal port; kern refuses that stack up front instead of letting the loser die with `EADDRINUSE` in its own log. Walks `ports:` / `port:` / `expose:`, ranges, and `--no-pod` |
| [compose-systemd-unit.sh](compose/compose-systemd-unit.sh) | Start a stack at boot on a daemonless runtime: `kern compose <file> systemd` prints a unit and installs nothing. Honest that it brings the stack up and down but does **not** supervise it |
| [stack-python-postgres/run.sh](stack-python-postgres/run.sh) | A two-service stack end to end: a Python API and the official `postgres` in one pod, the API reaching the DB on `localhost:5432`, a note written over HTTP and read back out of the database |

## AI / agent sandboxing (run model-generated code safely)

Call the `kern_sandbox` SDK to execute untrusted or LLM-generated code in a fresh box, sandbox events (timeout / OOM-kill / blocked escape) come back as **data**, not exceptions, so an agent loop can read and react to them.

| Example | What it shows |
|---|---|
| [agent-tool-runner.py](agents/agent-tool-runner.py) | The canonical "code execution tool" an LLM calls: run model-generated Python in a network-off box, return `{success, stdout, fault}`, a runaway loop returns a `timeout` fault, an exfiltration attempt gets no route out |
| [code-interpreter.py](agents/code-interpreter.py) | A stateful notebook-style session where **file** state persists turn to turn (write CSV → aggregate → format), a dep installed once via `setup=` |
| [agent-code-interpreter.py](agents/agent-code-interpreter.py) | The same idea taken to its edges: a `pip install` under an **egress allowlist** (PyPI reachable, exfiltration not), stdout **streamed** as it runs, a matplotlib figure returned as a mime-typed result with no Jupyter kernel, timeout/OOM/blocked-syscall as data, snapshot-and-resume, and the same box running JavaScript |
| [warm-kernel.py](agents/warm-kernel.py) | The **warm kernel** (`sbx.kernel()`): one persistent interpreter so **in-memory** state persists across cells and each cell is **sub-millisecond** (vs ~14 ms cold), with rich chart results, confined errors, network still off, and a per-cell timeout that tears it down |
| [kern-mcp setup](../bindings/python/README.md#works-with) | Wire **`kern-mcp`** into Claude Desktop / Cursor / Zed: a local, **network-off** code interpreter, with every knob in one table |
| [per-request-workers.py](agents/per-request-workers.py) | A stdlib-only pool mapping N requests to N fresh throwaway boxes, so one request's timeout/crash is contained to its own box |
| [sandboxed-eval.sh](agents/sandboxed-eval.sh) | The shell angle for agents that shell out: eval an untrusted snippet `--read-only --network none` + capped, using the exit code as the signal (benign / blocked / timeout-killed) |

## Data, batch & scraping

| Example | What it shows |
|---|---|
| [batch-process.sh](edge/batch-process.sh) | Per-file fan-out: each input file processed in its own capped box; one fails on purpose and the batch keeps going; results collected via `-v`, input `:ro` |
| [scrape-in-a-box.sh](edge/scrape-in-a-box.sh) | A network-on but otherwise-locked fetch: `--net` is the sole relaxation; root/PID/mount isolation + caps stay; output to a mounted dir |
| [etl-with-deps.sh](edge/etl-with-deps.sh) | Deps installed once online (a `kern build` `RUN` step) into an image snapshot, then the transform runs that image **network-off** over `:ro` data |
| [parallel-fanout-limited.sh](resources/parallel-fanout-limited.sh) | Bounded-concurrency fan-out: a POSIX sliding window caps in-flight boxes at N so a big batch never spawns them all at once |

## CI & dev-workflow integration

| Example | What it shows |
|---|---|
| [dependency-audit.sh](build/dependency-audit.sh) | Vet an untrusted npm/pip package: fetch with scripts disabled, then run its lifecycle scripts in a **network-cut** box so install-time code can't read host secrets or exfiltrate |
| [git-precommit-sandbox.sh](ci/git-precommit-sandbox.sh) | A git pre-commit hook that runs your linters/tests in a read-only, network-less box; the box's exit code gates the commit |
| [github-actions.yml](ci/github-actions.yml) + [ci-integration.sh](ci/ci-integration.sh) | A minimal GitHub Actions job that installs kern and builds/tests in a capped `kern box`, plus a local script that reproduces the same CI run without pushing |
| [Makefile.kern](ci/Makefile.kern) + [makefile-kern-demo.sh](ci/makefile-kern-demo.sh) | Hermetic `make lint/test/build` where each target runs in a `kern box`, a machine with only kern (no toolchain) can build and test |
| [airgapped-ci.sh](ci/airgapped-ci.sh) | Supply-chain-hardened CI: seed the base image once, then every step is `--pull never` (fails closed on any un-seeded image) and network-off. Deterministic, offline, no surprise pulls |

## Side-by-side with other tools

| Example | What it shows |
|---|---|
| [familiar-commands.sh](basics/familiar-commands.sh) | Coming from Docker / AWS / GCP? The same verbs and building blocks, mapped to kern |
| [run-vs-box.sh](basics/run-vs-box.sh) | The two verbs side by side, because the names collide with Docker's and the collision is backwards: the one spelled `run` is the one that does **not** isolate. Prints uid, hostname, pid 1 and whether `$HOME` is reachable, bare / under `kern run` / under `kern box`, so the difference stops being an argument about names |
| [benchmark.py](benchmark.py) | Reproduce the whole **Performance** table, kern vs bubblewrap / crun / runc / podman / docker (auto-detects what's installed) |
| [compare-vs-docker.sh](resources/compare-vs-docker.sh) | Same isolated `/bin/true`, kern vs `docker run`, timed, and kern needs no daemon |
| [compare-vs-bwrap.sh](resources/compare-vs-bwrap.sh) | Same speed class as bubblewrap, but kern adds OCI images, overlay, and lifecycle |

## Embed kern in your own program

Don't shell out, call kern as a library and get a structured result back (exit code, stdout/stderr
with truncation flags, wall time). Ideal for running LLM/agent-generated code or CI steps.

| Example | What it shows |
|---|---|
| [embed-python.py](agents/embed-python.py) | The `kern_sandbox` Python package: a fresh box per `run_code`, file-state on disk, sandbox faults (timeout/OOM/blocked-escape) as data, not exceptions |
| [embed-node.js](agents/embed-node.js) | The `kern-sandbox` npm package (mirror of the Python one): `runCode`/`withSandbox`, file-state on disk, faults as data on `result.fault`, not thrown |
| [embed-rust.rs](agents/embed-rust.rs) | The `kern-isolation` crate's fluent `Sandbox::builder()…build()?.run(...)` → a structured `Outcome` |

## Windows

| Example | What it shows |
|---|---|
| [Windows via WSL2](../docs/INSTALL.md) | kern on Windows runs inside WSL2, same commands, real kernel-enforced caps, with the measured cost of crossing from PowerShell |


Every box gets: user + PID + network + UTS + IPC + mount namespaces, a pivoted root, an
always-on seccomp allowlist, and cgroup caps (direct in kern's delegated `kern.slice`, or a transient
`systemd-run --user --scope` as fallback).
See [../SECURITY.md](../SECURITY.md) for the threat model.
