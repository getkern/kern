# Docker compatibility

kern speaks Docker's **formats**, so existing images and stacks work, but it does **not** reimplement
the Docker Engine API. It is a lightweight alternative, not a drop-in clone. This page is the full
matrix: what is supported, what is not, and where the differences bite.

| From your Docker setup | kern |
|------------------------|------|
| **OCI images** (Docker Hub, GHCR, quay, Harbor, self-hosted) | ✅ pull & run: multi-arch, `WWW-Authenticate` v2 auth, gzip **+ zstd**, digest-pinned `@sha256:` refs **content-verified** (the manifest is checked against the pin) |
| **`docker-compose.yml`** | ✅ `kern compose <file> [up\|down\|stop\|start\|restart\|ps\|logs\|build\|pull\|config\|systemd]` reads real-world files as-is: `depends_on` (+ `service_healthy`/`_completed` conditions), `healthcheck`, `deploy.resources.limits`, `ulimits`, `sysctls`, `labels`, `extra_hosts`, `init`, `stop_signal`/`stop_grace_period`, **`restart:`** (`always`/`unless-stopped`/`on-failure`), YAML **anchors/merge** (`<<: *x`), **`extends`**, `x-` extension fields, the project **`.env`**, `${VAR:-default}` and bare `$VAR` interpolation, network **aliases**. Multiple files merge (`-f base.yml -f override.yml`), plus `-p`/`--env-file`/`--profile`. `up` **reconciles**: a service still matching the file is left running, a changed one is recreated |
| **Dockerfile** `build` | ✅ `kern build`: all common instructions, **multi-stage**, `COPY --from=…` (a build stage **or** an external image), **COPY globs** (`*.txt`, `src/*`, `[ab].conf`), BuildKit **heredocs**, `ADD <url>` (+ `--checksum`/`--chmod`), `COPY --chmod` (recursive, Docker-parity), `FROM scratch`, `SHELL`, `# escape`/BOM, `--build-arg`, a **whole-build cache**, and honours **`.dockerignore`**. Daemonless: each `RUN` is a real box. The cache is keyed on the whole Dockerfile + context, NOT per layer as Docker's is: an identical build is reused (2040 ms to 24 in one measurement), and changing any instruction re-runs from the first, including steps before the edit |
| **`.dockerignore`** (also **`.kernignore`**) | ✅ excluded from the build context: keeps `.git`/secrets out of the image (last-match-wins, `!` re-include, `**`) |
| **`docker save` / `load` archives** | ✅ `kern save` / `kern load`: export/import an image tar, `docker load`-compatible |
| **`tag` / `push`** to a registry | ✅ `kern tag` / `kern push` |
| **Image management** (`docker images` / `rmi` / `search`) | ✅ `kern images` (list cached), `kern rmi` (remove, frees unshared layers), `kern search` (Docker Hub) |
| **`docker commit`** (container → image) | ✅ `kern commit <box> <image>`: snapshots the box's filesystem to a reusable image (warm start); skips volumes/secrets |
| **Docker Engine API** / `docker.sock` | ❌: tools that attach to the socket (Docker Desktop, some IDE/CI plugins) won't connect |
| **Swarm** (multi-host orchestration) | ❌ and there is no workaround: clustering, service replicas and rolling updates across machines are out of scope for a single-host, daemonless runtime. `kern compose` is one machine, one pod. |

**One stack, one network namespace.** The services of a `kern compose` stack share a
single network namespace, like the containers of a Kubernetes pod: they reach each
other by service name on `127.0.0.1`, with no bridge, no IPAM and no DNS server.
That is what makes a stack start in milliseconds, and it has one consequence worth
knowing before you choose kern: **two services cannot both listen on the same
container port**, even when their published ports differ. Two apps that both default
to `:3000` is the common case, so kern refuses it *before* starting anything and names
both services. The same applies to `net.*` sysctls, which belong to the namespace and
therefore to the whole stack.

**Outbound needs `pasta`, and kern says so when it is missing.** Reaching the internet
from a rootless network namespace needs a userspace network stack, so `kern compose up`
attaches `pasta` (the `passt` package) to the pod for NAT'd egress and DNS. It is on by
default; `--no-outbound` turns it off. If `pasta` is not installed the pod comes up
**loopback-only** and the bring-up line says which of the two you got, rather than
leaving you to discover it when a `pip install` inside a service times out:

```
network: services reach each other by name + outbound to the internet (pasta)
network: loopback-only - services reach each other; NO outbound (install `passt`/`pasta` for egress)
```

`pasta` is the only thing in kern that is worth installing separately, and it buys
exactly this one capability. What it costs, measured on an Intel i7-14700KF, Linux 7.0,
against the same targets from the host in the same session:

| | in a pod | on the host | |
|---|---:|---:|---|
| service to service (shared loopback) | **0.14 ms** p50 | n/a | no bridge, no NAT, no DNS server |
| TCP connect to a public IP | 28.4 ms | 29.3 ms | identical |
| TLS handshake | 34.0 ms | 35.1 ms | identical |
| DNS, name never resolved before | 32.8 ms p50 | 53.3 ms p50 | identical; both are just network latency |
| download throughput | 1.64 MB/s | 1.80 MB/s | about 9% less |

What `pasta` costs is **about 3.6 ms per network round trip**, measured against the same
public IP from inside the pod and from the host: connect 29.8 ms against 26.2, and the
request/response leg after it 30.0 against 26.4. It is a flat per-round-trip cost, so it
shows up multiplied on anything with several: an HTTPS request, whose TLS handshake adds
two more, reads about four times that.

The other asymmetry worth knowing is that a pod has **no DNS cache**: a host running a
caching resolver answers a repeated name in well under a millisecond, while the pod pays
the full lookup every time, so a warm host can look ~29 ms faster per request on a name it
has already seen. That is caching, not NAT: on a name neither side had resolved before, the
pod was the faster of the two.

Declare the port each service listens on and the conflict goes away:

```yaml
services:
  api:    { image: node:20-slim, port: 3000 }
  admin:  { image: node:20-slim, port: 3100 }
```

kern passes it as `PORT`, which most images read, and reserves it for that service, so
peers keep using the name (`http://admin:3100`) with nothing remapped at run time.
Docker's own `expose:` says the same thing and is honoured identically, so a stack that
already uses it needs no edit.

Three spellings, one space: `ports:` (published), `port:` (declared and passed as
`PORT`), `expose:` (declared only). A service that publishes nothing is visible to the
check only if it declares something. Every edge case is decided rather than left to chance
(a conflicting `PORT=` is refused by name, a range in `ports:` is expanded and checked
port by port, a range in `expose:` is never silently expanded, `--no-pod` lifts the
constraint entirely): [compose-declared-ports.sh](../examples/compose-declared-ports.sh) runs
through them.

One deliberate asymmetry: a malformed entry in *your* kern profile is refused with its
line number, while the same entry in someone else's `docker-compose.yml` is warned about
and skipped. Failing a whole stack over one line of documentation is the wrong trade for a
file kern did not write; for a file you did, a typo should be named at once.

`kern compose <file> config` prints what kern understood, reservations included, and
refuses exactly what `up` would refuse: a dry run that disagreed with the bring-up would
be worse than no dry run.

### Starting a stack at boot

kern is daemonless, so after a reboot PID 1 starts, not kern. `kern compose <file> systemd` prints a
unit on stdout and installs nothing: where it belongs is a decision about your machine.

```console
$ kern compose stack.yml systemd > ~/.config/systemd/user/kern-shop.service
$ systemctl --user daemon-reload && systemctl --user enable --now kern-shop.service
$ loginctl enable-linger $USER        # or the unit stops when you log out
```

**The unit adds no supervision beyond each service's own `restart:` policy.** kern's per-service
supervisor already restarts a service that dies mid-run (`on-failure` on a non-zero exit,
`always`/`unless-stopped` on any exit, for the stack's lifetime); what the generated unit does not do
is re-run a stack that failed as a whole, and it says so in its own comments rather than letting you
assume otherwise. Walk-through: [compose-systemd-unit.sh](../examples/compose-systemd-unit.sh).

### Everyday `docker` commands

Most container-lifecycle verbs you type daily have a 1:1 `kern` equivalent (same name where it makes sense):

| `docker …` | `kern …` | Notes |
|---|---|---|
| `run` / `create` | `box` | one verb; `-d` detaches, `-it` for a PTY |
| `exec` | `exec` | joins the box's namespaces |
| `ps` | `ps` | `-a`/`--all` (also lists recently-exited boxes), `-q`, `--filter name=/status=/id=`, `--format '{{.Field}}'`, `--json` |
| `logs` | `logs` | `--tail N`, `-f`/`--follow` (bounded read, cheap on GB-size logs) |
| `stop` / `kill` | `stop` / `kill` | SIGKILL the box's process group |
| `pause` / `unpause` | `pause` / `unpause` | cgroup v2 freezer |
| `attach` | `attach` | Ctrl-C detaches, box keeps running |
| `cp` | `cp` | host↔box, symlinks can't escape the box root |
| `inspect` | `inspect` | `--json` |
| `stats` | `stats` | per-box CPU / memory |
| `top` (box processes) | `exec <box> ps` | plus `kern top`, the live TUI for every box |
| `rename` | `rename` | in place, pid unchanged |
| `update` | `update` | live cgroup caps, no restart (needs a delegated cgroup) |
| `wait` | `wait` | prints the exit code (`137` after `stop`); also resolves a box that has already exited, via its `waitexit` breadcrumb |
| `diff` | `diff` | overlay-upper changes: `C` changed/added, `D` deleted |
| `events` | `events` | poll-based stream (`start`/`die`/`rename`); daemonless, best-effort |
| `commit` | `commit` | box → reusable image (warm start) |
| `start` (resume a *stopped* container) | *(none)* | a box can run **as long as you want** (detach with `-d --restart` for a DB or server that stays up for days) and its **volumes persist on disk**; what's not supported is *resuming* a box you already stopped - you launch a fresh one that re-attaches the same volume |

Multi-service stacks **are** supported: `kern compose` reads your `docker-compose.yml` and brings the
services up in a pod, with `depends_on` ordering and healthchecks, daemonless. What needs a daemon
does not exist here: `swarm` / `service` / `stack`, `docker.sock`, and anything that attaches to it.

`shm_size:` is recognised but intentionally **not** mapped: kern mounts `/dev/shm` unsized and charges
it to the box memory cgroup, so `mem_limit` / `--memory` is the real bound (Docker's 64 MB `/dev/shm`
default is what breaks Postgres under load). Size shared memory with `mem_limit`, not a separate cap.

## Building and publishing images


kern builds OCI images from a Dockerfile **without a daemon**: each `RUN` is a real `kern box`, each
step a content-addressed layer, reused on an unchanged rebuild.

```sh
kern build -t app:1 -f Dockerfile .          # FROM RUN COPY ADD ENV WORKDIR USER CMD ENTRYPOINT SHELL …
kern build -t app:1 --build-arg VER=9 .       # build args; multi-stage (FROM … AS b; COPY --from=b)
kern save app:1 -o app.tar                    # export a docker-load-compatible image tar …
kern load -i app.tar                          # … and import one (docker save format)
kern tag app:1 registry.example/app:1         # give a cached image a second name
kern commit devbox warmenv:1                  # snapshot a running box's fs into a reusable image
kern login registry.example                   # (private) creds stored 0600
kern push registry.example/app:1              # publish as a single-layer OCI image
```

**Warm start (`kern commit`).** Bake an expensive one-time setup (`apt`/`pip` installs, a warmed cache,
compiled artifacts) into a local image once, then start the next box from it instantly. It reads the
box's kernel-merged overlay through `/proc/<pid1>/root`, so whiteouts are already resolved, and skips
every nested mount, so a `-v` volume or a secret is never baked into the image. It's `docker commit`,
daemonless. A filesystem snapshot, not live memory: processes restart fresh (write state to disk if you
need it back).

kern parses **real-world Dockerfiles** as-is (comments inside `\` continuations, `SHELL`, BuildKit
`RUN --mount`/`ADD <url>` with `--checksum`/`--chmod`, `COPY <<heredoc`, `FROM scratch`, `# escape`
and BOM) and honours **`.dockerignore`** (also `.kernignore`), so a `COPY . /app` won't bake your
`.git`, `.env` or secrets into the image. **Multi-stage** builds run each stage in its own box and
confine `COPY --from=<stage>` to that stage's filesystem (a hostile source path or symlink can't read
the host). Layers pull as gzip **or zstd**. `push` normalizes ownership and strips setuid/setgid, so an
untrusted base can't smuggle a privilege-bit into what you publish. (`build`/`push` are the newest
surface, see [Status](../README.md#status).)
