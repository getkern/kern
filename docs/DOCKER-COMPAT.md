# Docker compatibility

kern speaks Docker's **formats**, so existing images and stacks work. It does **not** reimplement the
Docker Engine API. This page is the reference: what is supported, what is not, and where the
differences bite.

Every figure here is measured, against **Docker 29.6.2** on a real daemon (aarch64) and **podman
4.9.3** rootless. [RUNTIME-PARITY.md](RUNTIME-PARITY.md) carries those measurements one by one.

## What "compose compatibility" means, in three numbers

**Corpus: 259 real compose files**, one per repository, sampled across 733. Each number carries its own
definition, because quoting one under another's is a mistake this project made once.

| Question | Answer | What it means |
|---|---|---|
| Does kern **accept** the file? | **247 / 259 = 95%** | `compose config` exits 0. Accepted, not executed. The 12 it refuses, Docker refuses too |
| Accepted with **no difference kern names**? | **198 / 259 = 76%** | no warning at `config` that is a behavioural difference |
| The same, on a host that permits **low ports** | **222 / 259 = 85%** | the identical measurement with `net.ipv4.ip_unprivileged_port_start=0` |

**One cause carries most of the gap and is not kern's.** 24 of the 49 remaining files publish a port
below 1024, which the kernel refuses to bind rootless: podman refuses it too and names the same sysctl,
Docker binds it because it is root. That is the whole distance between 76% and 85%. The rest: no daemon
behind `/var/run/docker.sock` (14), `privileged: true` (7), `runtime:` (2), and one each for seven
other keys.

⚠ Nine of the twelve refusals are not compose files at all (`.bak`, `.dist`, `.old`), and Docker
refuses them too. The denominator keeps them, because removing the files a measurement dislikes is how
a rate goes up.

## What is frozen

**A key kern reads keeps its meaning.** It changes only to correct a mapping that was wrong, and such a
change leads that release's [CHANGELOG](../CHANGELOG.md) entry, naming the key.

**A key kern does not read is never silent.** It is refused, or reported with what kern does instead.
Two silences are deliberate: `x-*` extension fields, and the four keys Docker itself does not act on
under Linux (`cpu_count`, `cpu_percent`, `cpus_shares`, `isolation`).

Both halves are held by a test, not by this page: `surface_tests` in `crates/kern-compose/src/yaml.rs`
carries the frozen key list, and removing a key from the parser fails it by name.

## The perimeter

kern is a substitute for `docker compose` on files that do not need:

  * the Engine API behind `/var/run/docker.sock` (14 files: Traefik's docker provider, Portainer,
    Watchtower, CI-in-docker). A reverse proxy configured BY FILE does work,
  * `privileged: true` without an operator grant (7 files), or `runtime:` (2 files),
  * a host port below 1024 kept where the file wrote it. 38 files publish one; they RUN, moved and
    announced. Outside the perimeter only when the port must BE 80, the ACME HTTP-01 case,
  * `--pod`, where a service binding `127.0.0.1` does not keep it private from its peers,
  * UDP between peers under the `--no-pod` relay wiring,
  * bind-mounted files owned by the uid the service runs as: rootless maps them through the subuid
    range, so a service running as 1000 writes files the host sees as 100999,
  * a stack that returns after a reboot on its own: use `compose systemd` plus `loginctl enable-linger`,
  * a built image being reused when its context changed: kern rebuilds, Docker does not.

Outside that list, on this corpus, kern accepts every file Docker accepts.

| From your Docker setup | kern |
|---|---|
| **OCI images** (Docker Hub, GHCR, quay, Harbor, self-hosted) | ✅ multi-arch, v2 auth, gzip **+ zstd**, digest-pinned `@sha256:` refs **content-verified** |
| **`docker-compose.yml`** | ✅ read as-is, 13 verbs, multi-file merge, `up` reconciles |
| **Dockerfile** `build` | ✅ `kern build`, daemonless: each `RUN` is a real box. `kern build --check` parses and reports, building nothing |
| **`.dockerignore`** (also **`.kernignore`**) | ✅ last-match-wins, `!` re-include, `**` |
| **`docker save` / `load` archives** | ✅ `kern save` / `kern load` |
| **`tag` / `push`**, **`images` / `rmi` / `search`** | ✅ same verbs; `kern rmi` frees unshared layers |
| **`docker commit`** | ✅ `kern commit <box> <image>`; skips volumes and secrets |
| **`docker run` security flags** | ✅ `--apparmor`, `--cap-drop`/`--cap-add`, `--read-only`, `--tmpfs`, `--security-profile untrusted`, `--landlock-rw`; seccomp **always on**. Absent: **SELinux** labelling and a **default** AppArmor profile. [SECURITY.md](../SECURITY.md) |
| **Docker Engine API** / `docker.sock` | ❌ tools that attach to the socket will not connect |
| **Swarm** | ❌ out of scope for a single-host, daemonless runtime |

**What `kern compose` reads**, as-is: `depends_on` (+ conditions), `healthcheck`,
`deploy.resources.limits`, `ulimits`, `sysctls`, `labels`, `extra_hosts`, `init`, `stop_signal`,
`restart:`, `devices`, `dns*`, `logging`, `links`, `ipc`/`pid`, `tmpfs`, `cpu_shares`, `platform`,
`volumes_from`, `shm_size`, `secrets`, YAML anchors and merge, `extends`, `x-` fields, the project
`.env` with `${VAR:-default}`/`${VAR:?err}`, and network aliases.

**What `kern build` supports.** All common instructions, multi-stage (+ `target:`), `COPY --from=…`,
COPY globs, BuildKit heredocs, `ADD <url>` (+ `--checksum`/`--chmod`), `COPY --chmod`, `FROM scratch`,
`SHELL`, `# escape`/BOM, `--build-arg`, a per-instruction cache, and `.dockerignore`. Each layer is
content-addressed and reused while its inputs are unchanged: with a 3 s install step, the rebuild took
64 ms on Linux 7.0, 61 ms on WSL2 and 46 ms on a Jetson. Without an unprivileged overlay that records
deletions the build is **flat** and the cache whole-build; `kern build inspect <id>` says which.

## How a stack is wired

kern picks the wiring from the file, and says which one it picked.

**A namespace per service on a bridge (the default, from two services up).** Docker's arrangement:
each service keeps its own `127.0.0.1` and peers are reached by name. Measured against `--pod` on
`up -d` with warm images: +17 ms for 2 services, +23 ms for 4, +27 ms for 8.

**One shared namespace (`--pod`).** Services reach each other by name on `127.0.0.1`: no bridge, no
IPAM, no DNS server. Two services cannot both listen on the same container port, and kern refuses such
a stack rather than running it with one of them dead. A port bound on the loopback is reachable by
every peer.

**A namespace per service with relays (`--no-pod`).** Chosen automatically when the file's `networks:`
leave two services with nothing in common. Peers are reached through per-service loopback aliases
(`127.0.0.2` upward). The cost is a relay hop: -34% bulk throughput, -16% connection rate.

**`networks:` is enforced in that wiring and inert in a pod.** Two services with no network in common
get no relay and no `/etc/hosts` entry, so the peer's name does not resolve. The boundary is the ABSENCE
of a relay, not a filter, so no rule can be misconfigured into permissiveness. Over 240 real files, 52
have a pair that loses an edge, so `up` names every cut pair first.

**A network shared BETWEEN projects (`external: true`).** `kern network create <name>` makes it, and
services of different files on it reach each other by name. A file naming one that does not exist is
REFUSED, as Docker refuses it. It is relays and not a shared bridge because of rootless Linux: joining
another holder's network namespace needs `CAP_SYS_ADMIN`, placing a link needs `CAP_NET_ADMIN` in the
namespace that owns the target, and a sibling has neither (both measured as EPERM against controls).

**The host is outside the stack under every wiring**, asserted with a positive control.

## Egress

`kern compose up` attaches `pasta` (the `passt` package) for NAT'd egress and DNS; without it a pod
comes up loopback-only and says so. Outside a pod each service gets its own NAT, attached while it is
held at its pre-exec gate, so no workload sees a half-built network.

`internal: true` is a real boundary without a pod: such a service is given no NAT, so there is no
route out of its namespace. Two exceptions are named rather than hidden: a service on the host network
already has the host's connectivity, and one with `restart:` becomes a systemd unit `up` never holds.
Measured from inside a segregated service, a public address connected while the host's own answered
`refused`.

Pasta costs about **3.6 ms per round trip** and about 9% less download throughput.

## Differences that bite

**In one shared namespace the services share `127.0.0.1`.** A port bound on the loopback is reachable
from every peer: admin endpoints, `/metrics`, pprof, anything trusting `127.0.0.0/8` without
authentication. `--no-pod` gives each service its own loopback.

**A published port binds `0.0.0.0`, like Docker.** On the corpus, 203 of 259 files (78%) publish at
least one port. The narrower posture is a CEILING rather than a default, so a downloaded file cannot
defeat it by writing an address:

```toml
[kern]
publish_bind = "127.0.0.1"
```

**A service with no `mem_limit:` gets the host's RAM**, as under Docker. It is not uncapped: the box
carries a `memory.max` and `oom.group = 1`, so a failure stays attributable to its own cgroup.
`[kern] compose_memory_max` restores a strict ceiling; see [CONFIG.md](CONFIG.md).

**An empty NAMED volume is seeded from the image**, contents, owner and mode. Only when empty, and
never for a bind mount of a host path.

**The image's own `HEALTHCHECK` and `STOPSIGNAL` are used** when the file declares none; a
`healthcheck:` in the file replaces the image's entirely, numbers included.

**A service mounting `/var/run/docker.sock` has nothing to talk to.** The mount succeeds and the
service fails later inside its own code.

**`restart:` in a pod does not survive a reboot**, because a systemd unit cannot re-join the pod's
network namespace. Run that service as a standalone box: `kern box <name> --restart unless-stopped`.

**`devices:` is a bind, and its ceiling is the invoking user.** A device the host does not have is
refused by name before the box starts. `/dev/net/tun` maps to `--tun` instead.

**Secrets are delivered at `/run/secrets/<source>`**, mode `0444` or the `mode:` declared. `target:`,
`uid:` and `gid:` are read and named as not applied.

## What is refused rather than dropped

**A path that leaves the compose file's own directory.** Docker accepts `build: /somewhere/else`, a
bind source above the project and a secret file outside it; kern refuses all four, naming the service
and the path. Each is CANONICALISED first, so `../` and a symlink out are the same case.

| in the file | refused when |
|---|---|
| `build: <ctx>` | the context resolves outside the compose directory |
| `dockerfile: <f>` | it resolves outside the **context** (as Docker resolves it) |
| `volumes: - <src>:<dst>` | the bind SOURCE resolves outside the compose directory |
| `secrets: file: <f>` | the file resolves outside the compose directory |

There is **no opt-out**. Move what the stack needs inside the project directory.

⚠️ The context is resolved when the build runs, so `compose config` renders such a file without
complaint and `build`/`up` are where it is refused.

**`${VAR:?message}`** with no value, which is what a compose file writes for a password. Every variable
with no value is named, not just the first.

**`RUN --mount=type=secret` and `type=ssh`**, because dropping the flag runs the command
unauthenticated. `type=cache` and `type=bind` stay dropped: those cost a rebuild, not a wrong answer.

**`external: true` on a volume that does not exist**, as Docker refuses it.

**Two services on the same internal port under `--pod`.** Declare the port each listens on, with
`port:` or `expose:`. kern passes it as `PORT`, a convention and not a contract.

## Resource profiles from a compose file

`x-kern-vcpu`, `x-kern-vdisk`, `x-kern-vgpio` and `x-kern-security-profile` attach a `kern.toml`
profile to a service. `x-` is the specification's extension mechanism, so the file stays portable.

A profile buys only what compose cannot already say: `cpus`, `cpuset` and `mem_limit` are compose's
own and are used directly. `vgpio` is gated, because a profile name means different hardware on
different hosts: `compose config` prints what each resolves to here, and `--allow-device-grants` is
required.

A kind this build does not have is named as ABSENT (`x-kern-vgpu:`); a MISSPELLED key gets a different
sentence, naming the keys kern does read. Both are warnings, because the specification requires every
runtime to ignore an `x-` key. What must never happen is silence: a key nobody read is a CPU slice or a
device the author believes they attached.

## Starting a stack at boot

`kern compose <file> systemd` generates a unit, adding no supervision beyond each service's own
`restart:` policy. A single long-running box installs its own unit automatically; the stack path is
manual on purpose.

## Everyday `docker` commands

| `docker …` | `kern …` | Notes |
|---|---|---|
| `run` / `create` | `box` | one verb. `-d`, `-t`/`-it`, `--entrypoint` replaces ENTRYPOINT and discards CMD, `--network <name>` joins a running pod |
| `exec` | `exec` | joins the box's namespaces; `-t` allocates a PTY, `-i` does not |
| `ps` / `inspect` / `stats` | same | `--filter`, `--format`, `--json`, `--no-trunc`; `inspect -f` takes docker's own paths; `kern top` is the live view |
| `logs` | `logs` | `--tail`, `-f`, `-t`, `--since`/`--until`; the follow is a bounded read |
| `stop` / `kill` | `stop` / `kill` | `stop` signals, waits 10 s, then SIGKILLs. `kill` is immediate |
| `pause` / `unpause` / `attach` | same | cgroup v2 freezer; Ctrl-C detaches and the box keeps running |
| `cp` | `cp` | host↔box; symlinks cannot escape the box root |
| `images` / `rename` / `wait` | same | rename is in place, pid unchanged; `wait` blocks and prints the status |
| `top` (box processes) | `exec <box> ps` | plus `kern top` |
| `update` / `diff` / `events` | same | live cgroup caps with no restart; overlay-upper `C`/`D`; a poll-based, best-effort event stream |
| `commit` | `commit` | box → reusable image |
| `start` / `rm` | `start` / `rm`, for a box started `--keep` | a plain box is a process and its writable layer goes with it. `--keep` keeps that layer, `start` runs the same command on it, `rm` removes both |
| `login` / `logout` / `port` | same | registry credentials; `port` is read from the running box, not from the file |

### Every `docker compose` verb and flag kern accepts

| | |
|---|---|
| **Verbs** | `up`, `down`, `stop`, `start`, `restart`, `ps`, `logs`, `build`, `pull`, `config`, `watch`, `port`, `systemd`, `run`, `cp`, `exec`, `wait`, `events`, `images`, `push`, `rm`, `top`, `version`, `kill`. `create` and `scale` are refused by name: no created-but-not-started state, no replica count |
| **`up`** | `-d`, `--wait`, `--wait-timeout`, `--exit-code-from`, `--abort-on-container-exit`, `--no-deps`, `--build` (`--no-build` is refused, not ignored), `--quiet-pull`, `--force-recreate`, `--no-recreate`, `-V` |
| **`down` / `run`** | `-v`, `--remove-orphans`, `-t`, `--rmi local\|all` · `-d`, `--rm`, `-T`, `--name`, `--entrypoint`, `-e`, `--user`, `--pull`, `--no-deps` |
| **`logs` / `ps`** | `--tail`, `-f`, `-t`, `--since`, `--until`, `--no-log-prefix` · `-q`, `--services`, `--format json` (Docker's field names plus `Publishers`) |
| **`wait` / `push`** | `wait` exits with the status of the first service to stop, as Docker's does; `kern wait <box>` PRINTS the code and exits 0, an older frozen contract. `push` publishes only the services the file BUILDS, skipping by name one that merely names an upstream image |
| **Everywhere** | `-p`, `--env-file`, `--profile`, `--build-arg`, and `--flag=value` wherever `--flag value` works |
| **The file** | positional, behind `-f`, or OMITTED: the directory is searched for `docker-compose.yml`, `compose.yml`, their `.yaml` spellings, and `kern.toml` |
| **Files read** | `docker-compose.override.yml`, `extends: {file: ...}`, the project `.env`, `env_file:` long form, anonymous and project-scoped named volumes, a secret from an environment variable |
| **Keys applied** | `cpu_shares`, `memswap_limit`, `ulimits`, `runtime:`, `ipv4_address:`, `depends_on` conditions, `network_mode: service:X`, an image's own `HEALTHCHECK`/`STOPSIGNAL`/`Cmd`/`Entrypoint`/`Env` |
| **Keys named, not dropped** | an unknown service key (with a near-miss suggestion), every `deploy.*` kern does not apply, and `deploy.resources.reservations` |
| **`network_mode: host`** | applied as Docker applies it, and stated: it removes the service's network isolation, peers stop resolving it by name, and `ports:` becomes a no-op |

What needs a daemon does not exist here: `swarm` / `service` / `stack`, `docker.sock`, and anything
that attaches to it.

`--gpus` does exist, and it is one card per box: `kern box --gpus 0`, or `--device
nvidia.com/gpu=0` for the same card spelled the way CDI spells it. `--gpus all` is refused by name,
because this build grants one card and a flag that takes a word should not do something narrower
than the word says. A card you did not name has no device node in the box, so CUDA cannot
initialise it there; the host's PCI bus stays readable, so how many cards it has is still
discoverable. A compose service still reaches a card through `devices:` plus
`--allow-device-grants`.

### Reaching the host from inside a box: `host.docker.internal`

kern does not invent the name, it gives you the mapping and lets you spell it:

```yaml
services:
  app:
    image: python:3.12-slim
    extra_hosts: ["host.docker.internal:host-gateway"]
```

```sh
kern box app --image python:3.12-slim --add-host host.docker.internal:host-gateway -- python3 app.py
```

`host-gateway` is the keyword; the NAME beside it is yours, so `host.docker.internal`, `dockerhost` and
`gateway` all work. Three spellings are accepted (`extra_hosts`, `--add-host`, and `add_host = [...]`
in a `kern.toml`), and [examples/edge/add-host.sh](../examples/edge/add-host.sh) runs it.

**A box is on its own network namespace by default**, so nothing reaches the host until you say so.

### A private registry: `docker login`

```sh
kern login                      # Docker Hub
kern login ghcr.io              # any registry, prompted for the credentials
kern logout ghcr.io
```

The credentials never touch `argv`: they are stored `0600` in a `0700` directory and handed to `curl`
through a stdin config, so no same-uid process can read them from `/proc/<pid>/cmdline`. A Bearer
challenge only sends them to the advertised realm when that host is the registry host or a subdomain of
its parent domain (the CVE-2020-15157 class). Full model:
[SECURITY.md](../SECURITY.md#registry-authentication).

## Building and publishing images

`kern build` reads a Dockerfile and `kern push` sends the result to a registry. Each `RUN` is a real box
rather than a layer commit, so a build is subject to the same isolation as a run. **`kern commit`** bakes
an expensive one-time setup into a reusable image instead of paying for it on every box start.
