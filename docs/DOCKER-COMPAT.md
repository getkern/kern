# Docker compatibility

kern speaks Docker's **formats**, so existing images and stacks work. It does **not** reimplement the
Docker Engine API. This page is the reference: what is supported, what is not, and where the
differences bite.

Every FIGURE on this page is measured, and the measurement is named where it matters. Statements
about what Docker does are measured against **Docker 29.6.2** on a real daemon (a Jetson Orin Nano,
aarch64) and against **podman 4.9.3** rootless on the development host; where a question was not put
to a daemon, the line says so. [RUNTIME-PARITY.md](RUNTIME-PARITY.md) carries those measurements one
by one.


## What "compose compatibility" means, in three numbers

Three questions, three numbers. Quoting one under another's definition is a mistake this project
made once and corrected, so each carries its definition and its denominator.

**Corpus: 259 real compose files**, one per repository, sampled across 733, listed with the
repository, the path and the sha256 of the bytes measured in `docs/compose-corpus-neutral.tsv`. The
binary is proven to be the working tree; the script refuses to measure otherwise.

| Question | Answer | What it means |
|---|---|---|
| Does kern **accept** the file? | **247 / 259 = 95%** | `compose config` exits 0. Accepted, not executed. The 12 it refuses, Docker 29.6.2 refuses too |
| Accepted with **no difference kern names**? | **198 / 259 = 76%** | no warning at `config` that is a behavioural difference, beyond the deviations declared below |
| The same, on a host that permits **low ports** | **222 / 259 = 85%** | the identical measurement with `net.ipv4.ip_unprivileged_port_start=0`, which is one `sysctl` |

The gap between 95% and 76%, by cause. The second column is files where it is the ONLY cause:

```
 38   24   a privileged host port is republished above 1024 (rootless; not kern's to fix,
           and 0 of 24 on a host whose port floor is 0)
 14    1   no daemon behind /var/run/docker.sock
  7    1   `privileged: true` needs the operator's grant
  2    1   `runtime: nvidia`: the GPU is a device grant here
  1 each   logging driver, ipc:, a fixed address, an out-of-range port,
           security_opt seccomp, an unimplemented key, platform:
```

**One cause is not kern's and carries the rest.** 24 of the 49 remaining files publish a port below
1024, which the kernel refuses to bind rootless: podman refuses the same port and names the same
sysctl, Docker binds it because it is root. That is the whole distance between 76% and 85%.

Of 259 files, the only compose KEY kern reports as unimplemented is `runtime:`, on two files. That
says nothing about keys no file here writes, such as `deploy.replicas` or `userns_mode`.

⚠ Nine of the twelve refusals are not compose files at all (`.bak`, `.dist`, `.old`), and Docker
refuses them too. The denominator keeps them, because removing the files a measurement dislikes is
how a rate goes up.

## The perimeter

kern is a substitute for `docker compose` on files that do not need:

  * the Engine API behind `/var/run/docker.sock` (14 files here: Traefik's docker provider,
    Portainer, Watchtower, CI-in-docker). A reverse proxy CONFIGURED BY FILE rather than by the
    socket does work across projects: see the `external:` network entry below,
  * `privileged: true` without an operator grant on the command line (7 files),
  * `runtime:` (2 files),
  * a host port below 1024 kept where the file wrote it. 38 files publish one; they RUN, moved and
    announced, and `compose ps --format json` reports the real address in `Publishers`. They are
    outside the perimeter only when the port must BE 80, which is the ACME HTTP-01 case,
  * `--pod`, where a service that binds `127.0.0.1` does not keep it private from its peers. It is
    no longer the default and it is no longer where a stack lands without asking; the census that
    measured it (22 stacks read from inside, 2 with a loopback-only listener, both of them nominal)
    is in [RUNTIME-PARITY.md](RUNTIME-PARITY.md),
  * UDP between peers under the `--no-pod` relay wiring,
  * files on a bind mount owned by the uid the service runs as: rootless maps them through the
    subuid range, so a service running as 1000 writes files the host sees as 100999 (section 38),
  * a stack that comes back after a reboot on its own: kern has no daemon, and the path is
    `compose systemd` plus `loginctl enable-linger` (section 39),
  * the image kern already built being reused when its context changed: kern rebuilds, Docker does
    not without `--build`.

Outside that list, on this corpus, kern accepts every file Docker accepts.

| From your Docker setup | kern |
|------------------------|------|
| **OCI images** (Docker Hub, GHCR, quay, Harbor, self-hosted) | ✅ pull & run: multi-arch, `WWW-Authenticate` v2 auth, gzip **+ zstd**, digest-pinned `@sha256:` refs **content-verified** (the manifest is checked against the pin) |
| **`docker-compose.yml`** | ✅ read as-is, 13 verbs, multi-file merge, `up` reconciles. Detail below |
| **Dockerfile** `build` (dry run) | ✅ `kern build --check [ctx]`: parses and reports, builds nothing. Detail below |
| **Dockerfile** `build` | ✅ `kern build`, daemonless: each `RUN` is a real box. Detail below |
| **`.dockerignore`** (also **`.kernignore`**) | ✅ excluded from the build context (last-match-wins, `!` re-include, `**`) |
| **`docker save` / `load` archives** | ✅ `kern save` / `kern load`: `docker load`-compatible |
| **`tag` / `push`** to a registry | ✅ `kern tag` / `kern push` |
| **Image management** (`docker images` / `rmi` / `search`) | ✅ `kern images`, `kern rmi` (frees unshared layers), `kern search` |
| **`docker commit`** (container → image) | ✅ `kern commit <box> <image>`: snapshots the box's filesystem; skips volumes/secrets |
| **`docker run` security flags** | ✅ `kern box`: `--apparmor <profile>`, `--cap-drop`/`--cap-add`, `--read-only`, `--tmpfs`, an opt-in `--security-profile untrusted` bundle, `--landlock-rw`; seccomp is **always on**. Not present: **SELinux** labelling, and a **default** AppArmor profile. Full posture: [SECURITY.md](../SECURITY.md) |
| **Docker Engine API** / `docker.sock` | ❌ tools that attach to the socket will not connect |
| **Swarm** (multi-host orchestration) | ❌ no workaround: out of scope for a single-host, daemonless runtime |

**What `kern compose` reads.** `kern compose <file> [up\|down\|stop\|start\|restart\|ps\|logs\|build\|pull\|config\|watch\|port\|systemd\|run\|cp]` reads real-world files as-is: `depends_on` (+ `service_healthy`/`_completed` conditions), `healthcheck`, `deploy.resources.limits`, `ulimits`, `sysctls`, `labels`, `extra_hosts`, `init`, `stop_signal`/`stop_grace_period`, **`restart:`** (`always`/`unless-stopped`/`on-failure`), `devices`, `dns`/`dns_search`/`dns_opt`, `logging` `max-size`/`max-file`, `links`, `ipc`/`pid`, `tmpfs`, `mem_reservation`, `cpu_shares`, `platform`, `volumes_from`, `shm_size`, `secrets`, YAML **anchors/merge** (`<<: *x`), **`extends`**, `x-` extension fields, the project **`.env`**, `${VAR:-default}`, `${VAR:?err}` and bare `$VAR` interpolation, network **aliases**. Multiple files merge (`-f base.yml -f override.yml`), plus `-p`/`--env-file`/`--profile`. `up` **reconciles**: a service still matching the file is left running, a changed one is recreated

**What `kern build --check` does.** `kern build --check [ctx]` parses the file and reports what kern does with every instruction, building nothing: honoured, or `dropped` with what happens instead. A `COPY` from the context is resolved against it, so a source that escapes or is missing fails the check rather than the build; a glob or a `COPY --from` is left to the build, which is where it becomes answerable. Exit 0 if it builds here, non-zero with the refusal if it does not, so it can gate a pipeline before a base image is pulled

**What `kern build` supports.** `kern build`: all common instructions, **multi-stage** (+ `target:`), `COPY --from=…` (a build stage **or** an external image), **COPY globs**, BuildKit **heredocs**, `ADD <url>` (+ `--checksum`/`--chmod`), `COPY --chmod` (recursive, Docker-parity), `FROM scratch`, `SHELL`, `# escape`/BOM, `--build-arg`, a **whole-build cache**, and honours **`.dockerignore`**. Daemonless: each `RUN` is a real box. The cache is keyed on the whole Dockerfile + context, NOT per layer as Docker's is: an identical build is reused (2040 ms to 24 in one measurement), and changing any instruction re-runs from the first

## How a stack is wired

kern picks the wiring from the file, and says which one it picked.

**A namespace per service, meeting on a bridge (the default, from two services up).** This is
Docker's arrangement: each service keeps its own `127.0.0.1`, so a port it binds on the loopback is
private to it, two services can both listen on the same container port, and peers are reached by
name over a real network. A single-service stack keeps the shared namespace, having no peer to be
separated from.

WHAT IT COSTS, MEASURED end to end on `up -d` with warm images, alternated against `--pod`: +17 ms
for 2 services, +23 ms for 4, +27 ms for 8. It is nearly flat because the two things that made it
per-service are gone - a veth peer is now created directly inside the member's namespace instead of
being moved into it, which saves a full RCU grace period (14-22 ms) per service, and every NAT is
attached concurrently before any service is released instead of one at a time (about 17 ms each).
Before those two, the same eight-service stack cost +239 ms.

**One shared namespace (`--pod`).** Services reach each other by name on `127.0.0.1`: no bridge, no
IPAM, no DNS server, and a bring-up flat in the number of services. Two services cannot both listen
on the same container port here, and kern refuses such a stack rather than running it with one of
them dead. `net.*` sysctls belong to the namespace and therefore to the whole stack. A port a service
binds on the loopback is reachable by every peer, which under Docker it would not be.

**A namespace per service with relays (`--no-pod`).** Chosen automatically when the file's
`networks:` leave two services with nothing in common, because one bridge would put them back on one
network and drop the separation the file asked for. Peers are reached through per-service loopback
aliases (`127.0.0.2` upward) carried by relays, so a namespace still holds only `lo` with no routes.
The cost is a relay hop: measured at -34% bulk throughput and -16% connection rate.

**`networks:` is enforced in that wiring and inert in a pod.** Two services with no network in common
get no relay and no `/etc/hosts` entry, so the peer's name does not resolve at all. The boundary is
the ABSENCE of a relay, not a filter, so no rule can be misconfigured into permissiveness. A service
with no `networks:` key is on the implicit `default` network and is therefore separated from services
that name one; measured over 240 real files, 52 have at least one pair that loses an edge and 40 are
exactly that mixed case, so `up` names every cut pair before starting anything.

**A network shared BETWEEN projects (`external: true`).** A compose file declares it, `kern network
create <name>` makes it, and services of different files on it resolve and reach each other by name -
the reverse-proxy pattern. A file naming one that does not exist is REFUSED, measured against the
reference: `docker compose up` answers `network X declared as external, but could not be found` and
`docker compose config` renders the file anyway, which is what kern does too.

IT IS RELAYS AND NOT A SHARED BRIDGE, and that is a property of rootless Linux rather than a choice.
Measured, each refusal against a control that rules out the tool: from the initial user namespace,
joining another holder's network namespace is EPERM (entering its user namespace first works); from
inside one pod's user namespace, creating a veth whose peer lands in a sibling pod's network
namespace is EPERM (both ends inside one pod works). Joining a network namespace needs
`CAP_SYS_ADMIN` in the caller's own user namespace, and placing a link needs `CAP_NET_ADMIN` in the
one that owns the target; a sibling has neither. A relay needs neither, because its two halves each
enter only their own box. What that costs is a TCP hop and TCP only, and a peer answers on a port the
file DECLARES, exactly as inside a `--no-pod` stack.

EACH MEMBER GETS ONE ADDRESS ON THE NETWORK, `127.1.<network>.<member>`, which every other member
binds locally to reach it and which it uses as its own source address. Those cannot collide with a
stack's own peer aliases, which live in `127.0.0.2` through `127.0.0.254`. A stack that joins later
is wired into the boxes already running - relays into them, and their `/etc/hosts` updated in place -
and `down` takes both away again.

**The host is outside the stack under every wiring.** A listener on the host's own loopback is not
reachable from a service, bridged or podded, and that is asserted with a positive control. Inside the
stack the wirings differ and that difference is the point: the default separates the services'
loopbacks as Docker does, and `--pod` puts them in one trust domain, where a service you do not trust
with its peers does not belong.

## Egress

`kern compose up` attaches `pasta` (the `passt` package) for NAT'd egress and DNS. Without `pasta`
installed a pod comes up loopback-only and the bring-up line says so. Outside a pod each service gets
its own NAT, attached while it is held at its pre-exec gate, so no workload ever sees a half-built
network.

`internal: true` is a real boundary without a pod: a service confined to internal networks is given
no NAT, so there is no route out of its namespace. Two exceptions are named rather than hidden: a
service on the host network already has the host's connectivity, and a service with `restart:` becomes
a systemd unit that `up` never holds. In a pod the key is all-or-nothing and `up` says which answer
the stack got.

The NAT does not reopen what segregation closed: measured from inside a segregated service, a public
address connected while the host's own address answered `refused` on both a real listener and the
segregated peer's published port.

What pasta costs, measured on one host against the same targets: about **3.6 ms per network round
trip**, and about 9% less download throughput. A pod has no DNS cache, so a host running a caching
resolver answers a repeated name faster; on a name neither side had resolved before the pod was the
faster of the two.

## Differences that bite

**In one shared namespace the services share `127.0.0.1`.** A port bound on the loopback is reachable
from every peer, which under Docker it would not be: admin endpoints, `/metrics`, pprof, anything
trusting `127.0.0.0/8` without authentication. `--no-pod` gives each service its own loopback.

**A published port binds `0.0.0.0`, like Docker.** kern used to bind `127.0.0.1`, which was the single
largest source of behavioural difference: on a neutral corpus of 259 files, one per repository, 203
(78%) publish at least one port. The narrower posture is one line, and it is a CEILING rather than a
default, so a downloaded file cannot defeat it by writing an address:

```toml
[kern]
publish_bind = "127.0.0.1"
```

**A service with no `mem_limit:` gets the host's RAM**, as it does under Docker. It is not uncapped:
the box carries a `memory.max` and `oom.group = 1`, so a failure stays attributable to its own cgroup
instead of the host OOM killer picking a victim. `[kern] compose_memory_max` restores a strict ceiling
and caps a bigger `mem_limit:` too; see [CONFIG.md](CONFIG.md).

**An empty NAMED volume is seeded from the image**, contents, owner and mode. Only when the volume is
empty, and never for a bind mount of a host path. A multi-layer image is read through the
kernel-merged overlay view, so a file a higher layer deleted does not come back.

**The image's own `HEALTHCHECK` and `STOPSIGNAL` are used** when the file declares none. A
`healthcheck:` in the file replaces the image's entirely, numbers included, and that includes Docker
25+'s `start_interval:` (how often to probe while inside `start_period:`), which is honoured from both
the file and the image. An explicit
`stop_signal:` wins even when it names `SIGTERM`; a signal name kern does not know leaves the box on
`SIGTERM` rather than refusing to start it.

**A service mounting `/var/run/docker.sock` has nothing to talk to.** kern is daemonless. The mount
succeeds and the service fails later inside its own code. Such a service needs real Docker.

**`restart:` in a pod does not survive a reboot.** A pod member is supervised in-process and restarted
on any exit of its WORKLOAD for the life of the stack, but a systemd unit cannot re-join the pod's
network namespace. A box that never started is the one exception: it exits 125, it has no workload to
restart, and retrying it is budgeted rather than endless.
For reboot-survival run that service as a standalone box: `kern box <name> --restart unless-stopped`,
which has no pod and therefore no pod egress.

**`devices:` is a bind, and its ceiling is the invoking user.** A rootless box reaches exactly what
the person who started it could already reach; a device the host does not have is refused by name
before the box starts. `/dev/net/tun` maps to `--tun` instead, because creating a tunnel interface
needs `CAP_NET_ADMIN` in the box's namespace.

**Secrets are delivered at `/run/secrets/<source>`**, owned by the box's root, mode `0444` (the
specification's default) or the `mode:` the file declares. `target:`, `uid:` and `gid:` are read and
named as not applied.

## What is refused rather than dropped

**`${VAR:?message}`** with no value. That form exists to stop a file being rendered without it, and it
is what a compose file writes for a password. Every variable with no value is named, not just the
first. `${VAR}` and `${VAR:-default}` are unchanged.

**`RUN --mount=type=secret` and `type=ssh`.** Dropping the flag runs the command unauthenticated:
either a 401 pointing at the registry rather than at the discarded flag, or a build that succeeds
against something public and ships the wrong result. `type=cache` and `type=bind` stay dropped,
because those cost a rebuild and not a wrong answer.

**`external: true` on a volume that does not exist**, as Docker refuses it. Create it with
`kern volume create <name>` first, or drop the key and accept that the service starts on empty
storage.

**Two services on the same internal port under `--pod`.** Declare the port each one listens on and
the conflict goes away; `expose:` says the same thing and is honoured identically:

```yaml
services:
  api:    { image: node:20-slim, port: 3000 }
  admin:  { image: node:20-slim, port: 3100 }
```

kern passes it as `PORT`. That is a convention, not a contract: an image reading a variable of its own
needs that one set instead.

## Resource profiles from a compose file

`x-kern-vcpu`, `x-kern-vdisk`, `x-kern-vgpio` and `x-kern-security-profile` attach a `kern.toml`
profile to a service. `x-` is the specification's extension mechanism, so the file stays portable:
Docker ignores the key and runs the service without the profile.

A profile buys only what compose cannot already say. `cpus`, `cpuset` and `mem_limit` are compose's
own and are used directly. A `tmpfs` size cap is honoured and charged to the box's memory cap.

`vgpio` is gated: a profile name means different hardware on different hosts, so `kern compose <file>
config` prints what each name resolves to here, and `--allow-device-grants` (or the operator's own
`kern.toml`) is required before it runs.

**A profile kind this build does not have is named as absent rather than treated as a typo, and the
difference is the whole point of the sentence.** There is exactly one such kind here:
`x-kern-vgpu:`. It is recognised, it is not available in this build, and a file carrying it runs
without it:

```
kern: warning: compose: service 'app': 'x-kern-vgpu:' names the 'vgpu' profile kind, which this
build of kern does not have - the key is ignored, and the service runs without it
```

A MISSPELLED key gets a different sentence, because it is a different problem: telling the author of
`x-kern-vgpu` to check their spelling would be false, and telling the author of `x-kern-vgpi` that
their key belongs to another build would be worse:

```
kern: warning: compose: service 'app': 'x-kern-vgpi:' is not read by this build - kern reads
x-kern-vcpu, x-kern-vdisk, x-kern-vgpio, and x-kern-security-profile
```

Both are warnings and neither stops the stack: the specification requires every runtime to ignore an
`x-` key, so refusing one would be the incompatibility this whole mechanism exists to avoid. What
must never happen is silence, because a key nobody read is a CPU slice or a device the author
believes they attached.

## Starting a stack at boot

`kern compose <file> systemd` generates a unit. It adds no supervision beyond each service's own
`restart:` policy. A single long-running box installs its own unit automatically; the stack path is
manual on purpose.

## Everyday `docker` commands

| `docker …` | `kern …` | Notes |
|---|---|---|
| `run` / `create` | `box` | one verb. `-d`, `-t`/`-it` for a PTY, `--entrypoint` replaces ENTRYPOINT and discards CMD. `--network <name>` joins a running pod, which is what a stack is |
| `exec` | `exec` | joins the box's namespaces with its environment. `-t` allocates a PTY and `-i` does not, as on docker |
| `ps` | `ps` | `-a`, `-q`, `--filter`, `--format`, `--json`, `--no-trunc`, `--last N` |
| `logs` | `logs` | `--tail`, `-f`, `-t`, `--since`/`--until`. The follow is a bounded read, cheap on GB-size logs |
| `stop` / `kill` | `stop` / `kill` | `stop` sends the stop signal, waits 10 s, then SIGKILLs. `kill` is immediate |
| `pause` / `unpause` | `pause` / `unpause` | cgroup v2 freezer |
| `attach` | `attach` | Ctrl-C detaches, box keeps running |
| `cp` | `cp` | host↔box, symlinks cannot escape the box root |
| `inspect` | `inspect` | `--json`, and `-f`/`--format` with docker's own paths (`.State.Status`, `.State.Pid`, `.Config.Image`) |
| `stats` | `stats` | per-box CPU and memory. `--no-stream` prints a snapshot; `kern top` is the live view |
| `images` | `images` | `kern images`, `--json`, `--filter`, `--digests` |
| `top` (box processes) | `exec <box> ps` | plus `kern top`, the live TUI |
| `rename` | `rename` | in place, pid unchanged |
| `update` | `update` | live cgroup caps, no restart (needs a delegated cgroup) |
| `wait` | `wait` | blocks until the box exits and prints its status |
| `diff` | `diff` | overlay-upper changes: `C` changed/added, `D` deleted |
| `events` | `events` | poll-based stream (`start`/`die`/`rename`); daemonless, best-effort |
| `commit` | `commit` | box → reusable image (warm start) |
| `start` (resume a stopped container) | *(none)* | a stopped box is a record, not a paused process: `kern box` starts a new one |
| `login` / `logout` | `login` / `logout` | credentials for a private registry, stored for the user |
| `port` | `port` | `kern port <box> [<container-port>[/tcp\|/udp]]`: the host address serving that port, or every mapping when no port is named. Read from the running box, so it reports what was actually bound rather than what the file asked for |

### Every `docker compose` verb and flag kern accepts

| | |
|---|---|
| **Verbs** | `up`, `down`, `stop`, `start`, `restart`, `ps`, `logs`, `build`, `pull`, `config`, `watch`, `port`, `systemd`, `run`, `cp`, `exec` (with the `--` Docker users type), `wait`, `events`, `images`, `push`, `rm`, `top`, `version`, `kill` (= `stop`). `create` and `scale` are refused by name: kern has no created-but-not-started state and no replica count |
| **`wait`** | exits with the status of the first service to stop, as Docker's does, after waiting for all of them. `kern wait <box>` PRINTS the code and exits 0: that contract is older and frozen |
| **`push`** | publishes only the services the file BUILDS (`build:` plus `image:`). A service that merely names an upstream image is skipped by name: it is not this project's to publish |
| **`up`** | `-d`, `--wait`, `--wait-timeout`, `--exit-code-from`, `--abort-on-container-exit`, `--no-deps`, `--build` (`--no-build` is refused, not ignored), `--quiet-pull`, `--force-recreate`, `--no-recreate` (writing both is refused by name), `-V`/`--renew-anon-volumes` |
| **`down`** | `-v`, `--remove-orphans`, `-t`/`--timeout`, `--rmi local\|all` |
| **`run`** | `-d`, `--rm`, `-T`, `--name`, `--entrypoint`, `-e`, `--user`, `--pull`, `--no-deps` |
| **`ps`** | `-q`, `--services`, `--format json` (Docker's field names beside kern's, plus `Publishers`) |
| **`logs`** | `--tail`, `-f`, `-t`, `--since`, `--until` (a duration, unix seconds, or RFC3339 UTC), `--no-log-prefix` |
| **`images`** | `--format json`, with a `state` per service: `cached`, `dangling`, `absent`, or `build` for a service that has no `image:` to name |
| **`build` / `pull`** | `--build-arg`, `--ignore-pull-failures` |
| **`config`** | `--services` prints the names one per line and nothing else |
| **Everywhere** | `-p`, `--env-file`, `--profile`, and `--flag=value` wherever `--flag value` works |
| **The file** | positional (`kern compose f.yml up`), behind `-f` before the verb, or OMITTED: with no file the directory is searched for `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`, `kern.toml`, so `kern compose up -d` works where `docker compose up -d` does. A bare `kern compose` still prints usage rather than guessing a verb |
| **Files read** | `docker-compose.override.yml`, `extends: {file: ...}`, the project `.env`, `env_file:` long form, anonymous volumes in long form, named volumes scoped to the project, a secret from an environment variable |
| **Keys applied** | `cpu_shares`, `memswap_limit` (a total, unlike cgroup v2's field), `ulimits` (including the one-line mapping form), `runtime:`, `ipv4_address:`, `depends_on` conditions, `network_mode: service:X`, an image's own `HEALTHCHECK` / `STOPSIGNAL` / `Cmd` / `Entrypoint` / `Env`, a healthcheck in exec form, `--tmpfs uid=`/`gid=` |
| **Keys named, not dropped** | an unknown service key (with the near-miss suggestion), `deploy.replicas` / `mode` / `placement` / `update_config` / `rollback_config` / `endpoint_mode`, `deploy.restart_policy`, and `deploy.resources.reservations`: a GPU request says the service runs WITHOUT the device and where a device comes from |
| **`network_mode: host`** | applied as Docker applies it, and stated: it removes the service's network isolation, its peers stop resolving it by name, and any `ports:` it declares is a no-op |

Peers resolve each other by service name, by `networks.<net>.aliases` and by the name a service
announces. `external: true` joins a network shared between projects.

What needs a daemon does not exist here: `swarm` / `service` / `stack`, `docker.sock`, and anything
that attaches to it. Nor does `--gpus`: kern ships no GPU cap and says why in
[GPU-CLAIMS.md](GPU-CLAIMS.md), so a workload that needs the whole card gets the whole card and there
is no quota to ask for.

### Reaching the host from inside a box: `host.docker.internal`

Docker resolves that name inside a container to the host. kern does not invent the name, it gives you
the mapping and lets you spell it, which is the same thing Docker does when you write it yourself:

```yaml
services:
  app:
    image: python:3.12-slim
    extra_hosts: ["host.docker.internal:host-gateway"]
```

or on a box:

```sh
kern box app --image python:3.12-slim --add-host host.docker.internal:host-gateway -- python3 app.py
```

`host-gateway` is the keyword, resolved to the address the box reaches the host on; the NAME beside it
is yours, so `host.docker.internal`, `dockerhost` and `gateway` all work and all mean the same thing.
Three spellings are accepted for the compose key (`extra_hosts`, and the `--add-host` flag, and
`add_host = [...]` in a `kern.toml`), and [examples/edge/add-host.sh](../examples/edge/add-host.sh) runs it.

**A box is on its own network namespace by default**, so nothing reaches the host until you say so:
that mapping IS the saying so.

### A private registry: `docker login`

`kern login` is the same verb with the same shape:

```sh
kern login                      # Docker Hub
kern login ghcr.io              # any registry, prompted for the credentials
kern login registry.example.com --username alice
kern logout ghcr.io
```

It follows the standard registry-v2 challenge, so any compliant registry works, and the credentials
never touch `argv`: they are stored `0600` in a `0700` directory and handed to `curl` through a stdin
config, so no same-uid process can read them from `/proc/<pid>/cmdline`. A Bearer challenge only sends
them to the advertised token realm when that host is the registry host or a subdomain of its parent
domain (the CVE-2020-15157 class), and otherwise fetches the token anonymously and says so. The full
model is in [SECURITY.md](../SECURITY.md#registry-authentication).

## Building and publishing images

`kern build` reads a Dockerfile and `kern push` sends the result to a registry. Each `RUN` is a real
box rather than a layer commit, so a build is subject to the same isolation as a run.

**Warm start (`kern commit`).** Bake an expensive one-time setup (`apt`/`pip` installs, a warmed
cache) into a reusable image instead of paying for it on every box start.
