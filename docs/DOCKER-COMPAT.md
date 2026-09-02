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
| **`docker run` security flags** (`--security-opt`, `--cap-drop`, `--read-only`, `--tmpfs`) | ✅ `kern box`: **`--apparmor <profile>`** (Docker's `--security-opt apparmor=`, opt-in, enters a pre-loaded LSM profile), `--cap-drop`/`--cap-add`, `--read-only`, `--tmpfs`, an opt-in **`--security-profile untrusted`** bundle (seccomp allowlist + `--cap-drop ALL` + `--read-only`), and `--landlock-rw`; seccomp is **always on**. What kern does **not** have: **SELinux** labelling, and a **default** AppArmor profile (Docker/Podman apply one automatically; kern applies none unless you pass `--apparmor`). Full posture: [SECURITY.md](../SECURITY.md) |
| **Docker Engine API** / `docker.sock` | ❌: tools that attach to the socket (Docker Desktop, some IDE/CI plugins) won't connect |
| **Swarm** (multi-host orchestration) | ❌ and there is no workaround: clustering, service replicas and rolling updates across machines are out of scope for a single-host, daemonless runtime. `kern compose` is one machine, one pod. |

**One stack, one network namespace.** The services of a `kern compose` stack share a
single network namespace, like the containers of a Kubernetes pod: they reach each
other by service name on `127.0.0.1`, with no bridge, no IPAM and no DNS server.
That is what makes a stack start in milliseconds, and it has two consequences worth
knowing before you choose kern.

The first is a limit: **two services cannot both listen on the same
container port**, even when their published ports differ. Two apps that both default
to `:3000` is the common case, so kern refuses it *before* starting anything and names
both services. The same applies to `net.*` sysctls, which belong to the namespace and
therefore to the whole stack.

The second is a trust boundary, and it is the same fact read from the other side:
**a stack is one network trust domain**. Every service reaches every other service's
listening ports, published or not, because they share one loopback. MEASURED: a service
listening on `9999` and publishing nothing is reachable from a peer in the same stack.
The host's loopback is NOT reachable from inside (measured: the host's `:22` listener is
invisible to a service), so the boundary is between the stack and the host, not between
the services of one stack. Put a service you do not trust with its peers in its own
stack, not in this one.

**Outbound needs `pasta`, and kern says so when it is missing.** Reaching the internet
from a rootless network namespace needs a userspace network stack, so `kern compose up`
attaches `pasta` (the `passt` package) to the pod for NAT'd egress and DNS. It is on by
default whenever `pasta` is installed; a compose stack has no flag to turn egress off
(`--no-outbound` is a `kern pod create` option, not a compose one). If `pasta` is not installed the pod comes up
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

kern passes it as `PORT` and reserves it for that service, so peers keep using the name
(`http://admin:3100`) with nothing remapped at run time. Docker's own `expose:` says the
same thing and is honoured identically, so a stack that already uses it needs no edit.

`PORT` is a **convention, not a contract.** Most images read it; an image that reads a
variable of its own needs that one set instead, so for those the edit is this line plus
knowing which variable the image honours. The refusal says so, and it spells the change it
wants, naming the service and a port to use rather than describing the shape of an edit,
because there is no configuration that gives one stack BOTH two services on a single
internal port AND peers that can reach each other on it.

`--no-pod` is not the loss it used to be. Each service gets its own network namespace and a stack-wide
loopback alias, `127.0.0.2` upward; a service resolves its own name to `127.0.0.1`, where its listener
is, and each peer to that peer's alias, where a relay is bound inside this box. MEASURED on a native
Linux host: under `--no-pod` a two-service stack answers `127.0.0.2 srv` for its peer and `127.0.0.1`
for itself, `nc` connects, and the namespace still holds **only `lo` with no routes at all**. Nothing
was traded away to make names work; the reachability is carried by a relay that lives inside the
namespace rather than by an interface added to it. No box gets an `/etc/resolv.conf` either way: peer
names travel through `/etc/hosts`.

A peer also arrives with its OWN address rather than as loopback. The connector binds the calling
service's alias as the SOURCE before it connects, so a service sees `127.0.0.2` for one peer and
`127.0.0.3` for another (verified from inside a box: `netstat -tn` in the target shows the caller's
alias, not `127.0.0.1`). That matters because loopback is the most trusted source in most default
configurations, and a stack run with `--no-pod` asked for separation.

WHAT A SHARED INTERNAL PORT COSTS UNDER `--no-pod` IS MEASURED, NOT ASSUMED. On one port, two
SPECIFIC binds on different addresses do not conflict at all, while a specific bind and a WILDCARD
bind refuse each other in both orders, `SO_REUSEADDR` or not. A service that binds `127.0.0.1:8080`
explicitly leaves `127.0.0.2:8080` free and its relay works; only a service on `0.0.0.0:8080` takes
the whole port.

A compose file declares a port and never an address, so kern reads `/proc/<pid1>/net/tcp` for the box
that would host each relay once the services have bound. The direction whose host binds the wildcard
is named with both remedies; the other direction is served. Two services that both declare 8080 may
therefore lose one direction, both, or neither, and `up` says which. `kern compose ps` keeps printing
any direction that is down.

The two remedies are: change one internal port, or make one service bind `127.0.0.1` explicitly
instead of `0.0.0.0`, which is often a one-line config change against a renumber that touches every
caller.

What relays cost, measured on an x86 desktop with the release binary, against the same stack in a
pod. Throughput and connection rate are the price of the extra hop: bytes cross two TCP connections
instead of one.

| | in a pod | with relays | |
|---|---|---|---|
| bulk transfer | ~1270 MB/s | ~840 MB/s | -34% |
| connection rate | ~1980 conn/s | ~1660 conn/s | -16% |

The userspace copy is NOT what costs it: raising the pump's buffer from 16 KB to 64 KB moved
throughput less than the run-to-run spread (635 to 851 MB/s across repeats either way), so `splice`
would buy nothing here. The extra TCP connection is the cost, and it is inherent to the design.

Bring-up scales sub-linearly in the relay count and the process count does not. Same machine, one
port per service: 2 services is 2 relays and `up` in 187 ms; 8 is 56 relays and 218 ms; 16 is 240
relays and 388 ms; 32 is 992 relays, 1,987 processes, 474 MB of resident memory and 1.54 s. A relay
costs two processes and roughly 240 kB.

That product is why `up` refuses a stack needing more than **1024 relays**, before starting anything.
The 253-service alias range does not bound it: 253 services with one port each would be 63,756 relays
and 127,513 processes, more than the `RLIMIT_NPROC` of the machine this was measured on. A mesh that
wide is not what `--no-pod` is for, and the refusal says so with the arithmetic.

An idle stack costs almost nothing: the holder measures **0.10% of a core** with 56 relays up and
nothing wrong.

A named volume shared by two services that run as **different users** behaves exactly as it does under
Docker, which means the second service can be refused at runtime and nothing warns at start-up.
MEASURED on a Raspberry Pi 5 (which has `newuidmap`, `newgidmap` and both `/etc/sub*id` allocations):
`writer` running as `0:0` creates `/data/f` mode `0640` owned by `0:0`, `reader` running as `1000:1000`
mounts the same volume, `up` exits 0 with no warning, and the read fails with `Permission denied`
INSIDE the reader, seconds later.

kern does not chown a shared volume to fit the second consumer, deliberately: that would silently
rewrite ownership of data the first service owns, and it would differ from Docker on a file layout
people already depend on. The answer is the same one Docker gives, so a stack that works there works
here, and one that does not needs the same fix: matching users, a group both are in, or permissions
that admit both. Under a user namespace the in-box uid is what matters, so `user:` is what decides it.

Note that a service using `rootfs:` rather than `image:` keeps a SINGLE-uid map by default, and a
`user:` naming any other uid is then refused at start-up rather than at runtime, naming
`--uid-range` as the fix. That refusal is the loud half of this; the volume case above is the quiet
half, and it is quiet because it is a filesystem permission and not a mapping.

`kern compose <file> watch [service...]` is the development loop: it watches each selected service's
`build.context` and, on a change, rebuilds that service's image and restarts that service alone,
leaving its peers running. Measured on an x86 desktop, a full edit-to-serving cycle for a
one-instruction image is 258 to 261 ms. It is not Docker Compose's `develop.watch`: kern invents no
new compose key, and follows the build context because that is already the set of files a rebuild
reads. A service that runs a published `image:` has no such set and is excluded, by name.

`kern compose <file> port <service> <container-port>` answers the other direction, like
`docker compose port`: it prints the host address serving that box port, read from the RUNNING box
rather than from the file, and exits non-zero when there is no answer. Scripts can rely on the exit
code: `addr=$(kern compose f port web 8000) || exit 1`.

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

### Resource profiles from a compose file

A `docker-compose.yml` can name a `kern.toml` resource profile through the Compose Specification's
own extension fields:

```yaml
services:
  trainer:
    image: tensorflow/tensorflow:2.20.0
    cpus: 3.0            # already honoured, inline
    mem_limit: 3g        # already honoured, inline
    x-kern-vcpu: ml      # a [[vcpu]] profile in kern.toml
    x-kern-vdisk: scratch
    x-kern-vgpio: leds
    x-kern-security-profile: untrusted
```

`x-kern-security-profile: untrusted` is the one that needs no `kern.toml` at all: it is the opt-in
hardening bundle (seccomp allowlist, `--cap-drop ALL`, `--read-only`) under one name. Compose has no
way to say "this code is not trusted", and the flags it would take instead are easy to get
half-right. Measured on a service carrying it: `touch` in the rootfs answers `Read-only file system`
and `CapEff` reads `0000000000000000`.

They resolve to the `vcpu:`/`vdisk:`/`vgpio:` tokens `kern box` already takes, so `kern.toml` and a
compose file reach the same profiles. `leds` and `vgpio:leds` name the same one.

WHAT THEY BUY, which is only what compose cannot already say. `cpus`, `cpuset` and `mem_limit` are
honoured inline and need no profile. A `vcpu` profile also carries `numa`, `nice`, `backend` and
`extends`; a `vdisk` carries `size`, `persistent`, `backend`, `iops` and `bandwidth`; a `vgpio`
carries nineteen device classes. None of those has a compose spelling.

`x-kern-vgpio` is the one with no equivalent anywhere. A compose file reaches GPIO today by writing
`devices: /dev/gpiochip0`, so the service file decides which hardware it may touch. With a profile
the service declares intent and `kern.toml` holds the grant, so the operator decides what `leds`
resolves to on this host - which matters because the grant is chip-granular rather than per-line.

**The file stays portable, the grant does not.** `x-` is the spec's extension mechanism and Docker
Compose validates these keys and echoes them back unchanged, so one file runs on both runtimes. It
runs there WITHOUT the profile: a service relying on a `vdisk` size cap gets no cap under Docker, and
nothing says so. Keep anything a workload needs for correctness in the inline fields both runtimes
enforce, and use a profile for what only kern can grant.

**A key that GRANTS and a key that CONSTRAINS fail in opposite directions, and the second one is the
dangerous one.** Drop `x-kern-vdisk` and the service gets less than it asked for: it runs slower, or
it fills a disk, and the failure is loud and in front of you. Drop `x-kern-security-profile` - or run
the same file under Docker, which drops it for you - and the service runs with every capability and a
writable rootfs, which is the failure that shows nothing at all. Judge each key by what its absence
does: kern reads this one because the alternative is three separate flags that are easy to get
half-right, but **do not treat a file carrying it as hardened until you know which runtime read it.**
`kern compose <file> config` prints the line, marked as kern-only, so at least the runtime that
enforces it says so out loud. Docker cannot be made to.

**A `tmpfs` size cap is honoured, and it is charged to the box's memory cap.** The short form is what
both runtimes read: `tmpfs: ["/scratch:size=64m"]` keeps its `size=` and drops Docker's other options
with a warning. The cap itself holds - measured on the flag it becomes, a 16m tmpfs written with 64m
leaves a file of exactly 16777216 bytes. But those pages are the box's memory, so a tmpfs larger than
`mem_limit` is an OOM waiting for a workload to find it: measured, a 256m tmpfs under a 64m
`mem_limit` writing 128m is killed, exit 137. Size the two together. The LONG form (`volumes: [{type:
tmpfs, target: /s, tmpfs: {size: N}}]`) is not read - kern warns and skips it, so a service relying on
it gets no tmpfs at all:

```
kern compose: service volume long-form {type: tmpfs, target: /s2, ...} has no usable
              source+target (tmpfs: use kern --tmpfs) - skipped
```

An unrecognised key in the `x-kern-` namespace is NAMED rather than ignored, and a typo and a key
from another build are told apart. The spec says a tool must ignore the extension fields it does not
understand, and every other vendor's prefix is left alone, but this one is kern's, so silence would
mean a mistyped key does nothing and says nothing. The two cases get different sentences because they
need different fixes:

```
x-kern-vgpi:  'x-kern-vgpi:' is not read by this build - kern reads x-kern-vcpu,
              x-kern-vdisk, x-kern-vgpio, and x-kern-security-profile
x-kern-vgpu:  'x-kern-vgpu:' names the 'vgpu' profile kind, which this build of kern
              does not have - the key is ignored, and the service runs without it
```

Telling the author of `x-kern-vgpu` how `x-kern-vdisk` is spelled would send them looking for a
mistake they did not make.

**A `vgpio` profile is gated, and the reason is structural rather than a judgement about severity.**
Every other kind NARROWS: the file names a want, `kern.toml` holds the grant, and the local grant is a
ceiling, so a downloaded file naming `x-kern-vdisk: scratch` cannot get more than this host allows and
"the local one wins" is the conservative answer by construction. A `vgpio` profile does not narrow,
because its resolution is a DEVICE rather than a bound and device nodes have no ordering:
`/dev/gpiochip0` is not a smaller `/dev/gpiochip1`. One host's `leds` may be an LED, another's a relay
board. So a stack that resolves to any host device is refused, naming the exact paths, unless the
person running it passes `--allow-device-grants` - a command-line flag, where the compose file cannot
reach. The gate is on the property (did this resolve to a device?) and not on a list of kinds, so a
future kind that also resolves to hardware inherits it.

**What a name means here is not what it meant there, and `config` says so.** `kern compose <file>
config` prints what each profile resolved to on THIS host: the caps for a `vcpu`, the size and flags
for a `vdisk`, and the device paths for a `vgpio`. One file against two machines used to print the
identical line while one meant a 64 MB scratch and the other a 50 GB persistent one.

**Deliberately not built:** a key carrying the author's expectation (`scratch` was 64m where they
wrote it) so kern could report the difference. A purely COMPARATIVE annotation would pass the delete
test, since removing it removes an explanation and nothing runs less confined. A CONDITIONAL one - the
same key making kern refuse on a mismatch - would not, because it is a constraint expressed in a
portable file that Docker drops in silence. The line is between reporting and refusing, and the second
version is the one to say no to.

The profile must already exist: a compose file names a grant, it does not create one, which is the
whole point of the split. `kern compose <file> config` refuses a name that does not resolve, with the
`kern config add` line that creates it, and it refuses exactly what `up` would - including an
`x-kern-security-profile` value `kern box` does not take, which it asks the runtime's own vocabulary
about rather than keeping a second copy of the list.

`docker compose up -d` is the most common way anyone starts a stack, so `-d`/`--detach` is
accepted and does exactly what it says: `kern compose <file> up` starts the services and
returns, which is Docker's detached behaviour and kern's only one. It is accepted silently
rather than with a "no effect" note, because that note would be false. The presentation and
scheduling flags are the ones with no effect, and they say so when you pass them:
`--ansi`, `--progress`, `--no-ansi`, `--compatibility`, `--dry-run`, and `--parallel`, which
is deliberately not honoured because kern has its own concurrency cap.

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

**A single long-running box installs its own unit, automatically** - the stack path above is manual
because where a stack's unit belongs is a per-machine decision, but one service is not. `kern box
<name> -d --restart always` (or `unless-stopped`, standalone, not a pod member) does more than set a
policy: it writes and `systemctl --user enable --now`s a `~/.config/systemd/user/kern-<name>.service`
(`Restart=always`, `RestartSec=1`) and turns on `enable-linger`, so the box is restarted on any exit
by systemd itself and **survives a reboot and a logout** with no further step. This is real
long-running supervision, delegated to systemd, for the single-box case; `kern stop <name>` removes
the unit. (The one still-maturing piece is the in-process supervisor for `always` **pod members**,
which lives and dies with the stack rather than with systemd.)

### Everyday `docker` commands

Most container-lifecycle verbs you type daily have a 1:1 `kern` equivalent (same name where it makes sense):

| `docker …` | `kern …` | Notes |
|---|---|---|
| `run` / `create` | `box` | one verb; `-d` detaches, `-it` for a PTY, `--entrypoint` replaces the image's ENTRYPOINT and discards its CMD, as docker does (`--entrypoint ""` clears it) |
| `exec` | `exec` | joins the box's namespaces |
| `ps` | `ps` | `-a`/`--all` (also lists recently-exited boxes), `-q`, `--filter name=/status=/id=`, `--format '{{.Field}}'`, `--json` |
| `logs` | `logs` | `--tail N`, `-f`/`--follow` (bounded read, cheap on GB-size logs) |
| `stop` / `kill` | `stop` / `kill` | `stop` sends `--stop-signal` (SIGTERM), waits `--stop-timeout` (10 s) for the workload to flush and exit, then SIGKILLs what is left. `kill` is an ALIAS of it, not Docker's immediate kill: MEASURED at 3019 ms against stop's 3013 on the same three-second grace, so a script that reaches for `kill` to skip the wait wants `--stop-timeout 0`. A grace that provably cannot end is skipped, not sat out: an init with no handler for the signal is one the kernel would discard it for |
| `pause` / `unpause` | `pause` / `unpause` | cgroup v2 freezer |
| `attach` | `attach` | Ctrl-C detaches, box keeps running |
| `cp` | `cp` | host↔box, symlinks can't escape the box root |
| `inspect` | `inspect` | `--json` |
| `stats` | `stats` | per-box CPU / memory |
| `top` (box processes) | `exec <box> ps` | plus `kern top`, the live TUI for every box |
| `rename` | `rename` | in place, pid unchanged |
| `update` | `update` | live cgroup caps, no restart (needs a delegated cgroup) |
| `wait` | `wait` | prints the exit code the workload itself exited with, including after a `stop` that let it shut down cleanly; also resolves a box that has already exited, via its `waitexit` breadcrumb. Reading that code back is exact where the box has its OWN cgroup (a delegated one, or its per-box systemd scope) and BEST-EFFORT where it does not: kern reads the init's status from its unreaped zombie, and only a box it can cap is a box whose reaper it can hold still for the read. On a host with no delegation a clean shutdown can therefore still record `137` - measured at 1 run in 12 there, against 12 in 12 where a cgroup exists. `kern doctor` says which host you are on |
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
