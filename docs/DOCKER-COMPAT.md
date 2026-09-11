# Docker compatibility

kern speaks Docker's **formats**, so existing images and stacks work. It does **not** reimplement the
Docker Engine API. This page is the reference: what is supported, what is not, and where the
differences bite.

Every FIGURE on this page is measured, and the measurement is named where it matters. Statements
about what Docker does are measured against **Docker 29.6.2** on a real daemon (a Jetson Orin Nano,
aarch64) and against **podman 4.9.3** rootless on the development host; where a question was not put
to a daemon, the line says so. docs/RUNTIME-PARITY.md carries those measurements one by one.


## What "compose compatibility" means here, in three numbers

Three different questions, three different numbers. Quoting one under another's definition is the
mistake this project already made once and corrected (see the v0.9.32 errata in CHANGELOG.md), so
each one carries its definition and its denominator.

Corpus: 259 real compose files, one per repository, sampled across 733 repositories, listed one per
row in `docs/compose-corpus-neutral.tsv` with the repository, the path inside it and the sha256 of
the bytes that were measured. The commit is NOT pinned, so a file may have changed since; the hash
is the only thing that says what was read. Binary proven to be the working tree (the script refuses
to measure otherwise).

| Question | Answer | Definition |
|---|---|---|
| Does kern ACCEPT the file? | **247 / 259 = 95%** | `compose config` exits 0. ACCEPTED, not executed: of 41 files taken further and actually started, 19 did not come up (images that no longer resolve, host paths this corpus cannot carry, a FIFO in a layer, DNS). The 12 kern refuses, Docker 29.6.2 refuses too, so ON THIS CORPUS there is no file Docker accepts and kern rejects. Not a claim about every compose file: kern refuses at `config` two mappings sharing one host port, which Docker accepts and fails at `up`. |
| Is it accepted with NO difference kern names? | **198 / 259 = 76%** | zero warning lines at `config` that are a behavioural difference, BEYOND the deviations declared below. Those deviations have no per-file warning (they apply to nearly every file), so they are declared once here instead of counted 259 times. |
| The same, on a host that permits low ports | **222 / 259 = 85%** | the identical measurement in a network namespace with `net.ipv4.ip_unprivileged_port_start=0`, which is one `sysctl` on a real host. MEASURED, not derived by subtracting a cause: `compose-compat-rate.py --with-low-port-floor` runs both and prints both. |

THE FIRST NUMBER WAS 35% AND THEN 33% WHILE KERN GOT BETTER, and the reason is worth more than the
number. It counts what kern SAYS it does differently, so it falls whenever kern learns of a
difference it used to be silent about - `external:` networks cost two points the day they were
measured. It rose to 72% when the default wiring changed to a network namespace per service, which
is the arrangement Docker has: that single cause carried 135 files, 101 of them with nothing else.

The gap between 95% and 76%, by cause (second column: files for which it is the ONLY cause):

```
 38   24   a privileged host port is republished above 1024 (rootless; not kern's to fix,
           and 0 of 24 on a host whose port floor is 0)
 14    1   no daemon behind /var/run/docker.sock
  7    1   `privileged: true` needs the operator's grant
  2    1   `runtime: nvidia`: the GPU is a device grant here
  1 each   logging driver, ipc:, a fixed address, an out-of-range port,
           security_opt seccomp, an unimplemented key, platform:
```

ONE CAUSE LEFT IS NOT KERN'S AND CARRIES THE REST. 24 of the 49 remaining files publish a port below
1024, which rootless the kernel refuses to bind: podman refuses the same port and names the same
sysctl, Docker binds it because it is root. That is the whole distance between the two numbers in
the table above.

Every one of the 259 files is wired the way Docker wires it, so the shared-loopback cause is gone
from this table and from the runtime. `--pod` still asks for the old wiring and still says what it
costs.

Of 259 real files, the only compose KEY kern reports as unimplemented is `runtime:`, on two files. A
key no file in the corpus uses is not covered by that sentence: it says nothing about
`deploy.replicas`, `cgroup_parent`, `userns_mode` or `mac_address`, which no file here writes.

The corpus is 259 files found by their NAME. Nine of the twelve kern refuses are not compose files
at all (`.bak`, `.dist`, `.old`, `.md`, `-e`), and Docker refuses them for the same reason; the
denominator keeps them because removing the files a measurement dislikes is how a rate goes up.

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
    is in docs/RUNTIME-PARITY.md,
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
| **`docker-compose.yml`** | ✅ `kern compose <file> [up\|down\|stop\|start\|restart\|ps\|logs\|build\|pull\|config\|watch\|port\|systemd\|run\|cp]` reads real-world files as-is: `depends_on` (+ `service_healthy`/`_completed` conditions), `healthcheck`, `deploy.resources.limits`, `ulimits`, `sysctls`, `labels`, `extra_hosts`, `init`, `stop_signal`/`stop_grace_period`, **`restart:`** (`always`/`unless-stopped`/`on-failure`), `devices`, `dns`/`dns_search`/`dns_opt`, `logging` `max-size`/`max-file`, `links`, `ipc`/`pid`, `tmpfs`, `mem_reservation`, `cpu_shares`, `platform`, `volumes_from`, `shm_size`, `secrets`, YAML **anchors/merge** (`<<: *x`), **`extends`**, `x-` extension fields, the project **`.env`**, `${VAR:-default}`, `${VAR:?err}` and bare `$VAR` interpolation, network **aliases**. Multiple files merge (`-f base.yml -f override.yml`), plus `-p`/`--env-file`/`--profile`. `up` **reconciles**: a service still matching the file is left running, a changed one is recreated |
| **Dockerfile** `build` | ✅ `kern build`: all common instructions, **multi-stage** (+ `target:`), `COPY --from=…` (a build stage **or** an external image), **COPY globs**, BuildKit **heredocs**, `ADD <url>` (+ `--checksum`/`--chmod`), `COPY --chmod` (recursive, Docker-parity), `FROM scratch`, `SHELL`, `# escape`/BOM, `--build-arg`, a **whole-build cache**, and honours **`.dockerignore`**. Daemonless: each `RUN` is a real box. The cache is keyed on the whole Dockerfile + context, NOT per layer as Docker's is: an identical build is reused (2040 ms to 24 in one measurement), and changing any instruction re-runs from the first |
| **`.dockerignore`** (also **`.kernignore`**) | ✅ excluded from the build context (last-match-wins, `!` re-include, `**`) |
| **`docker save` / `load` archives** | ✅ `kern save` / `kern load`: `docker load`-compatible |
| **`tag` / `push`** to a registry | ✅ `kern tag` / `kern push` |
| **Image management** (`docker images` / `rmi` / `search`) | ✅ `kern images`, `kern rmi` (frees unshared layers), `kern search` |
| **`docker commit`** (container → image) | ✅ `kern commit <box> <image>`: snapshots the box's filesystem; skips volumes/secrets |
| **`docker run` security flags** | ✅ `kern box`: `--apparmor <profile>`, `--cap-drop`/`--cap-add`, `--read-only`, `--tmpfs`, an opt-in `--security-profile untrusted` bundle, `--landlock-rw`; seccomp is **always on**. Not present: **SELinux** labelling, and a **default** AppArmor profile. Full posture: [SECURITY.md](../SECURITY.md) |
| **Docker Engine API** / `docker.sock` | ❌ tools that attach to the socket will not connect |
| **Swarm** (multi-host orchestration) | ❌ no workaround: out of scope for a single-host, daemonless runtime |

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
`healthcheck:` in the file replaces the image's entirely, numbers included. An explicit
`stop_signal:` wins even when it names `SIGTERM`; a signal name kern does not know leaves the box on
`SIGTERM` rather than refusing to start it.

**A service mounting `/var/run/docker.sock` has nothing to talk to.** kern is daemonless. The mount
succeeds and the service fails later inside its own code. Such a service needs real Docker.

**`restart:` in a pod does not survive a reboot.** A pod member is supervised in-process and restarted
on any exit for the life of the stack, but a systemd unit cannot re-join the pod's network namespace.
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
`kern.toml`) is required before it runs. A profile kind this build does not have is named as absent
rather than treated as a typo.

## Starting a stack at boot

`kern compose <file> systemd` generates a unit. It adds no supervision beyond each service's own
`restart:` policy. A single long-running box installs its own unit automatically; the stack path is
manual on purpose.

## Everyday `docker` commands

| `docker …` | `kern …` | Notes |
|---|---|---|
| `run` / `create` | `box` | one verb; `-d` detaches, `-it` for a PTY, `--entrypoint` replaces the image's ENTRYPOINT and discards its CMD (`--entrypoint ""` clears it) |
| `exec` | `exec` | joins the box's namespaces, with the box's own environment |
| `ps` | `ps` | `-a`/`--all`, `-q`, `--filter name=/status=/id=`, `--format '{{.Field}}'`, `--json` |
| `logs` | `logs` | `--tail N`, `-f`/`--follow` (bounded read, cheap on GB-size logs) |
| `stop` / `kill` | `stop` / `kill` | `stop` sends `--stop-signal` (SIGTERM), waits `--stop-timeout` (10 s), then SIGKILLs what is left. `kill` is an ALIAS, not Docker's immediate kill: to skip the wait use `--stop-timeout 0`. A grace that provably cannot end is skipped, not sat out |
| `pause` / `unpause` | `pause` / `unpause` | cgroup v2 freezer |
| `attach` | `attach` | Ctrl-C detaches, box keeps running |
| `cp` | `cp` | host↔box, symlinks cannot escape the box root |
| `inspect` | `inspect` | `--json` |
| `stats` | `stats` | per-box CPU / memory |
| `top` (box processes) | `exec <box> ps` | plus `kern top`, the live TUI |
| `rename` | `rename` | in place, pid unchanged |
| `update` | `update` | live cgroup caps, no restart (needs a delegated cgroup) |
| `wait` | `wait` | the code the workload exited with, including after a clean `stop`. Exact where the box has its OWN cgroup, best-effort where it does not: on a host with no delegation a clean shutdown can still record `137`. `kern doctor` says which host you are on |
| `diff` | `diff` | overlay-upper changes: `C` changed/added, `D` deleted |
| `events` | `events` | poll-based stream (`start`/`die`/`rename`); daemonless, best-effort |
| `commit` | `commit` | box → reusable image (warm start) |
| `start` (resume a stopped container) | *(none)* | a box runs as long as you want and its volumes persist; what is not supported is resuming one you already stopped. Launch a fresh box against the same volume |

What needs a daemon does not exist here: `swarm` / `service` / `stack`, `docker.sock`, and anything
that attaches to it.

## Building and publishing images

`kern build` reads a Dockerfile and `kern push` sends the result to a registry. Each `RUN` is a real
box rather than a layer commit, so a build is subject to the same isolation as a run.

**Warm start (`kern commit`).** Bake an expensive one-time setup (`apt`/`pip` installs, a warmed
cache) into a reusable image instead of paying for it on every box start.
