# Docker compatibility

kern speaks Docker's **formats**, so existing images and stacks work. The `docker` command line and
the part of the Docker Engine API that test tools use are translated into kern's own commands; there
is no Docker daemon. This page is the reference: what is supported, what is not, and where the
differences bite.

Every figure here is measured, against **Docker 29.6.2** on a real daemon (aarch64) and **podman
4.9.3** rootless. [RUNTIME-PARITY.md](RUNTIME-PARITY.md) carries those measurements one by one.

## The `docker` command line: `kern-docker`

Scripts that call the `docker` CLI (`docker exec -i db psql < seed.sql`, `docker compose up -d
--build`, `docker run --rm --network shop_default -v data:/x img cmd`) run against kern's boxes
through `kern-docker`, a link to kern that translates the command into kern's own and runs it. No
daemon and no socket: one process, as `kern` is.

| How | What changes |
|---|---|
| `ln -s "$(command -v kern)" ~/.local/bin/kern-docker` | `kern-docker <docker command>` works; nothing else |
| `kern compat docker -- npm run dev` | inside that command, and every process it starts, `docker` and `docker-compose` are kern; nothing outside it |
| `kern compat docker link <dir>` | a `docker` link in `<dir>`, recorded; `kern compat docker status` and `kern doctor` show it and say which `docker` comes first in PATH; `kern compat docker unlink <dir>` removes it |
| `kern compat docker -- npm run dev` in Windows | the same for a Windows command: its PATH starts with a folder holding kern's `docker.exe` and `docker-compose.exe`, which forward to kern in the distro with `C:\` paths translated; the folder goes when the command ends |

A `docker` link to kern made any other way is refused, with the commands above. On Windows there is
no `link`: Docker Desktop's `docker.exe` is in the system PATH, which Windows puts before the user's,
so only a per-command PATH decides which `docker` a script gets. kern never replaces
a file that is not its own, and never hands a command to a docker engine.

**Translated, flag by flag.** A flag passes only when kern's flag of that name means the same:
`run` (onto `kern box`), `create`, `exec`, `ps`, `logs`, `inspect`, `rm`, `stop`, `restart`,
`start`, `kill`, `images`, `rmi`, `pull`, `push`, `tag`, `save`, `load`, `cp`, `stats`,
`wait`, `rename`, `port`, `login`, `logout`, `info`, `build`, `volume ls|rm|create|inspect`,
`network ls|inspect|create|rm`, `container <verb>`, `image <verb>`, and `compose` whole. Any other
flag or verb stops the command with exit 125, naming it: `kern-docker: docker run --log-opt: kern has
no flag with the same meaning, so the command is not run`.

**What differs, and is said.**

- `docker version` and `--version` print kern and kern's version. A script that checks for a
  Docker version number stops there.
- `docker run` without `--network`, or with `--network bridge`, gets kern's default, no network,
  and says so on stderr. `--network <project>_default` joins a running stack with its outbound;
  `--network host` shares this machine's.
- `docker run -d` and `docker create` print the box's name where docker prints an id (`kd-` and 8
  hex digits when no `--name` is given), so `id=$(docker run -d ...)` feeds `docker logs "$id"`.
- `DOCKER_HOST` or `DOCKER_CONTEXT` set, or `-H`/`--context` given, is refused: the command asked
  for a particular engine. `DOCKER_HOST` naming kern's own API socket (what `kern compat docker
  enable` prints to export) names kern, and is not refused.
- A script that calls `docker` by its full path (`/usr/bin/docker`) does not go through PATH, so
  `kern compat docker` does not reach it.

## The Docker socket: `kern compat docker enable`

Programs that speak to the Docker Engine API rather than run the `docker` command (Testcontainers,
docker-py, the `docker` CLI pointed at a socket) drive kern's boxes through a socket of this user,
`0600`, at `$XDG_RUNTIME_DIR/kern/compat-docker.sock`. Every request becomes a `kern` command run by
the same binary, as this user, so every rule kern applies to a box applies here.

| How | What happens |
|---|---|
| `kern compat docker enable` | a `systemd --user` socket unit: the server starts at the first connection (24 ms for the first answer, 9 ms after) and exits after a minute without a client; boxes it started keep running |
| `kern compat docker disable` | the unit off and removed, the socket gone; boxes keep running |
| `kern compat docker serve` | the same server in the foreground, until stopped: where there is no systemd user manager (WSL without systemd, CI, a bare ssh session) |
| `kern compat docker status` | whether the socket is enabled, listening, and its server running |

```sh
kern compat docker enable
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/kern/compat-docker.sock TESTCONTAINERS_RYUK_DISABLED=true
```

The socket lives only in kern's runtime directory, which no box may mount, whole or through a
parent. A container asking for a socket as a bind source (Testcontainers' reaper, Ryuk, asks for
this one) is refused at the create, naming `TESTCONTAINERS_RYUK_DISABLED=true`: whatever runs in a
box holding the socket is this user, and could ask it for any box.

**Ryuk's job, done by kern.** A container labelled with a Testcontainers session
(`org.testcontainers.session-id`) is filed under the process that created it, read from the socket
with its start time, and removed once that process ends, a `kill -9` included: measured 1.0 s after
the kill on Linux. No container holds the socket and no TCP port is opened for it. While such
containers wait, the socket-started server does not exit.

**From Windows: `kern compat docker pipe`.** Windows programs (Testcontainers for Java or .NET, the
`docker` CLI with `-H npipe:////./pipe/kern-docker`) reach the same API on the named pipe
`\\.\pipe\kern-docker`, served by `kern.exe` while that command runs:

```bat
kern compat docker pipe
set DOCKER_HOST=npipe:////./pipe/kern-docker
set TESTCONTAINERS_RYUK_DISABLED=true
```

- The pipe grants access to the account that started it and nobody else (its SID, from the process
  token), refuses remote clients, and is not shared: if another process holds the name, `pipe`
  stops and says so. There is no TCP endpoint.
- Each connection is carried to the distro by one `wsl.exe` (measured on Windows 10: 61 ms for a
  connection, which a docker client keeps open for many requests); the first one starts the server
  there.
- A test session's containers are removed when its Windows process ends: `kern.exe` watches that
  process and tells the distro (measured: 258 ms after the process exited).

| Request | Becomes |
|---|---|
| `containers/create`, `start` | `kern box <name> -d ...`, run at the start; the image, command, entrypoint, env, labels, workdir, user, hostname, published ports (`PortBindings`, `PublishAllPorts`), binds, memory, CPUs, `AutoRemove`, `NetworkMode` default, bridge, host or none |
| `attach`, then `start` (`docker run` without `-d`) | `kern box -d`, its log followed (`kern logs --frames -f`, stdout and stderr apart), and the box's exit code from `kern wait` is the run's |
| `exec`, `exec/{id}/start`, `exec/{id}/json` | `kern exec`, stdout and stderr apart, the exit code, `-t`, `-u`, `-w`, env, detached, and stdin (`-i`) on a hijacked connection, ending when the client closes its side |
| `logs` (`stdout`, `stderr`, `follow`, `tail`, `since`, `timestamps`) | `kern logs`: stdout and stderr apart for a container made through the socket |
| `json` (list and inspect), `wait`, `stop`, `kill` (`signal`), `restart`, `DELETE` | `kern ps`, `inspect --json`, `wait`, `stop`, `kill -s` (a container not running is 409, as Docker answers), `restart`, `rm`; the list's `label`, `name` (a substring, `^`/`$` anchors), `id` and `status` filters, and any other filter refused by name rather than ignored |
| `events` (`type`, `event`, `container`, `label`, `image` filters) | the `create`, `start` and `die` of the containers this socket makes, and `exec_create`, `exec_start`, `exec_die` of their execs (an `event` filter matches the type before the `:`, as Docker's does), sent when they happen; a box started with kern directly makes none, and `since`/`until` are refused |
| `images/create`, `images/json` (`reference`, `dangling` filters), `images/{name}/json`, `images/{name}/history`, `images/load`, `DELETE images/{name}` | `kern pull`, `kern images --json`, `kern image history --json`, `kern load` (the archive streamed to it, any size), `kern rmi` (`force` as `-f`, 409 for an image a container uses); `RepoDigests` is the repository digest the pull recorded; a history step's `Size` is its layer's compressed size (what a pull downloads; kern does not keep a layer's unpacked size) and 0 where kern has none |
| `containers/{id}/stats` (`stream`, `one-shot`), `exec/{id}/resize`, `containers/{id}/resize` | `kern stats --json` with the host's CPU clock, as Docker's `StatsJSON` (`docker stats` computes its CPU% from two readings a second apart, measured 100.09% for one busy core); a resize rewrites the terminal's size file and signals the `kern` that sizes it, and the program in the box gets `SIGWINCH` with the new size |
| `containers/{id}/archive` (`GET`, `HEAD`, `PUT`: `docker cp`, Testcontainers' copies) | `kern cp <box>:<path> -` and `kern cp - <box>:<dir>`, the archive streamed (any size) and every path resolved inside the box; the stat `docker cp` reads first in `X-Docker-Container-Path-Stat`; into a container created and not started, the archive is kept and extracted into the box's root at its start, before its command runs |
| `networks/prune`, `volumes/prune`, `images/prune` with a `label` filter | nothing removed, Docker's empty answer: this API makes no network, volume or image, and that is how a Testcontainers session ends with Ryuk off; without a label filter, 501 |
| `_ping`, `version`, `info` | kern and kern's version in `Platform` and `Components`; `Version` and `ServerVersion` are `24.0.0`, the Docker Engine whose API is 1.43, since clients gate on that number (Testcontainers for Java refuses one below 1.6.0) |

Measured on this machine (Linux x86_64) with the clients themselves, through the socket unit:

| Client | Cases | Time |
|---|---|---|
| `docker` CLI 29.1.3 with `DOCKER_HOST` | 18 of 18: `run --rm` stdout, stderr and exit code, `run` then `ps -a`, `inspect`, `rm`, 50,000 lines, `run -d -p` reached by curl, `exec` exit code, `stop`, `rm`, `--privileged` refused | `docker run --rm alpine` 28 ms, `exec` 15 ms |
| Testcontainers for Python 4.15.0 | Redis module (`GET` answers), Postgres module with SQLAlchemy (`select version()`, its readiness check is an `exec` of `psql`), nginx with a log wait | Redis 136 ms, Postgres 1181 ms, nginx 1048 ms, images cached |
| Testcontainers for Java 1.21.3 (`TESTCONTAINERS_RYUK_DISABLED=true`) | a log wait on a stderr line, `exec` stdout, stderr and exit code, logs by stream, an HTTP wait on a published port, a container that exits failing its start, the session's prune at exit | log wait 361 ms, HTTP wait 123 ms, exited container refused in 54 ms, image cached |
| Testcontainers for Node 12.2.2 | a log wait on a stderr line (it asks `tail=-1`), `exec` exit code, a published port reached by `fetch` | started to ready 7 ms, port 69 ms |
| Testcontainers for .NET 4.17.0 (Windows 10, `npipe://./pipe/kern-docker`, distro without systemd) | a log wait on a stderr line, stdout and stderr apart (it asks for timestamps), `exec` exit code, a published port reached from Windows at `localhost`, a container that exits failing its start | log wait 1306 ms, port 564 to 990 ms, exited container refused in 282 ms |
| Dev Containers CLI 0.91.0 (what VS Code runs) | `devcontainer up` from an image: the workspace mounted with `--mount`, the `start` event, the shell server on `exec -i`, `postCreateCommand`, `remoteEnv`; a second `up` finds and reuses the container; `devcontainer exec` | `up` 373 ms, reuse 360 ms, `exec` 277 ms, image cached |
| docker-py 7.2.0 | 9 of 9 exec cases: stdout and stderr apart, exit codes, env, workdir, user, 200 kB of output, tty, detached, a second start refused with 409, privileged refused | one `exec_run` 6 ms |

**What differs, and is said.**

- A container keeps its filesystem until it is removed: it is a kept box (`--keep`), so `docker stop`
  then `docker start` runs it again on the same files, and `docker rm` removes the layer. Dev
  Containers relies on it at every reopen (measured: the same container back in 326 ms, a file written
  before the stop still there, `postCreateCommand` not run again). Two exceptions keep their writes in
  memory, where they are fastest: a container that removes itself (`--rm`), and one a Testcontainers
  run made, which kern removes when the run ends. A kept box starts in about 25 ms here against 5 ms,
  most of it copying `/etc/hosts` into a layer on disk. `docker start` of a stopped container that kept
  nothing says so instead of starting it.
- `docker run -i` and `-t` (`-it`) run the box in the foreground, its stdin the client's and, with
  `-t`, a terminal sent as one raw stream: `echo x | docker run -i alpine cat` prints `x`, a 1 MB
  stdin arrives whole, `-it sh` is a shell and its exit code is the run's. Such a box is this
  server's child and ends with it, as a terminal ends the command it runs.
- `docker ps -a` lists a container created and not started, or whose start failed, as `Created`,
  and `docker rm` of it removes what a failed start left behind.
- A container started attached (`docker run` without `-d`) is a detached box like any other, so it
  outlives the server and its client (measured: the server killed during a run, the box finished
  and logged every line; a dev container still `Up` after a server restart). The attach follows the
  box's log, stdout and stderr apart, and the exit code comes from `kern wait`; a `--rm` one is
  removed once its output has been read, by the server, so one whose server stopped mid-run is left
  exited until `docker rm`. Against running it in the foreground, `docker run --rm alpine true`
  shows no difference the measurement can see (21.1 and 21.8 ms, medians of 40 paired runs, the
  interval of the difference -0.05 to +1.2 ms).
- Testcontainers' reaper (Ryuk) is refused, as above; with `TESTCONTAINERS_RYUK_DISABLED=true` each
  test removes its own containers, as the `with` block does.
- `--mount` (`HostConfig.Mounts`) becomes kern's `--mount`, of type `bind`, `volume` or `tmpfs`, read-only
  or not, with a tmpfs size; Dev Containers mounts its workspace this way. An option kern's mount does
  not have (a propagation other than `rprivate`, a non-recursive bind, volume driver options, a tmpfs
  mode) is refused by name. A bind (`-v src:dst`) is translated too.
- `logs` keeps stdout and stderr apart for the containers made through the socket, and so do
  `kern logs` and `kern attach` for the same boxes (stdout on stdout, stderr on stderr): their box's log
  records which stretch came from which stream. When the two are written within microseconds of each
  other the order BETWEEN them can differ from the order they were written in, as with Docker's own
  log driver; each stream keeps its own order. A box started with `kern box -d` outside the socket
  keeps one stream, and its `logs` come back as stdout.
- A container's id is derived from its box name, the same every time, and `docker ps` lists kern's
  boxes, not only those made through the socket.
- A box run attached and ended without `--rm` is listed from kern's own exit record (or its kept
  layer) until `docker rm`, as any other container; a restarted server finds it there.
- What kern refuses without a flag is refused here by name with a 400: `Privileged`, `Devices`,
  `DeviceRequests` (GPUs), `CapAdd`, `SecurityOpt`, `VolumesFrom`, `Links`, and the host's pid, ipc or
  uts namespace. An endpoint that is not translated (networks, volumes, build) answers 501 and says
  so; kern never hands a request to a Docker daemon. `docker compose` through the socket therefore
  stops at its first network call, and the 501 names `kern compose -f <file> up`, which runs the
  same file.

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

⚠ **The table was measured before 2026-11-12, and the first row has gone down since.** From that date
`compose config` refuses a path that leaves the project directory (a bind source, a build context or
a secret file written as `../…`), which `compose up` always refused: the preview used to call such a
file accepted and the bring-up then stopped it. On a separate local sample of 110 real files, 8 moved
from accepted to refused, all eight for this reason and no other, and Docker accepts all eight. The
259-file corpus has not been re-run since, so its first row is an upper bound until it is.

## What is frozen

**A key kern reads keeps its meaning.** It changes only to correct a mapping that was wrong, and such a
change leads that release's [CHANGELOG](../CHANGELOG.md) entry, naming the key.

**A key kern does not read is never silent.** It is refused, or reported with what kern does instead.
A key that is not in Docker's compose schema at all (a typo like `enviroment:`) is refused, as Docker
refuses it, naming the key it is one edit from; the schema is the 92 service keys and 9 top-level
keys Docker Compose v5.0.2 accepts, measured one by one.
A value of the wrong shape is refused as Docker refuses it, before any service is read, by the verbs
that build from the file (`up`, `run`, `config`, `build`, `pull` and the like; not `ps`, `logs` or
`down`): kern checks each file (and each `include:`d file) against Docker's own Compose schema, after the same type
conversions and list deduplication, and prints Docker's message with the file's absolute path, such
as `validating /srv/app/compose.yaml: services.web.command.1 must be a string` for
`command: [echo, 1]`. Where two failures are equally deep Docker names either one from run to run;
kern names the first in the file.
Two silences are deliberate: `x-*` extension fields, and the four keys Docker itself does not act on
under Linux (`cpu_count`, `cpu_percent`, `cpus_shares`, `isolation`).

Both halves are held by a test, not by this page: `surface_tests` in `crates/kern-compose/src/yaml.rs`
carries the frozen key list, and removing a key from the parser fails it by name.

## The perimeter

kern is a substitute for `docker compose` on files that do not need:

  * the Engine API behind `/var/run/docker.sock` (14 files: Traefik's docker provider, Portainer,
    Watchtower, CI-in-docker). A reverse proxy configured BY FILE does work,
  * `privileged: true` without an operator grant (7 files), or a `runtime:` other than `nvidia`
    (the corpus's 2 files write `runtime: nvidia`, which kern honours),
  * a host port below 1024 kept where the file wrote it. 38 files publish one; they RUN, moved and
    announced. Outside the perimeter only when the port must BE 80, the ACME HTTP-01 case,
  * `--pod`, where a service binding `127.0.0.1` does not keep it private from its peers,
  * UDP between peers under the `--no-pod` relay wiring,
  * bind-mounted files owned by the uid the service runs as, ROOTLESS: there the caller's directory
    is the box's root, and a service running as 1000 writes files the host sees as the subordinate
    uid, as under rootless docker. As root, kern gives docker's ownership: a directory `chown`ed
    1000:1000 is uid 1000's in the box and what it writes is 1000 on disk (an idmapped mount; a
    directory prepared for kern's earlier mapping keeps working, with a note),
  * a stack that returns after a reboot on its own: use `compose systemd` plus `loginctl enable-linger`,
  * a built image being reused when its context changed: kern rebuilds, Docker does not.

Outside that list, on this corpus, kern accepts every file Docker accepts, with one deliberate
exception described below: a path that leaves the project directory.

| From your Docker setup | kern |
|---|---|
| **OCI images** (Docker Hub, GHCR, quay, Harbor, self-hosted) | ✅ multi-arch, v2 auth, gzip **+ zstd**, digest-pinned `@sha256:` refs **content-verified** |
| **`docker-compose.yml`** | ✅ read as-is, 24 verbs, multi-file merge, `up` reconciles |
| **Dockerfile** `build` | ✅ `kern build`, daemonless: each `RUN` is a real box. `kern build --check` parses and reports, building nothing |
| **`.dockerignore`** (also **`.kernignore`**) | ✅ last-match-wins, `!` re-include, `**` |
| **`docker save` / `load` archives** | ✅ `kern save` / `kern load` |
| **`tag` / `push`**, **`images` / `rmi` / `search`** | ✅ same verbs; `kern rmi` frees unshared layers and, as `docker rmi`, refuses an image a box uses unless `-f` |
| **`docker commit`** | ✅ `kern commit <box> <image>`; skips volumes and secrets |
| **`docker run` security flags** | ✅ `--apparmor`, `--cap-drop`/`--cap-add`, `--read-only`, `--tmpfs`, `--security-profile untrusted`, `--landlock-rw`, `--security-opt no-new-privileges`; seccomp **always on**; setuid works as in docker unless no-new-privileges is asked for. Absent: **SELinux** labelling and a **default** AppArmor profile. [SECURITY.md](../SECURITY.md) |
| **Docker Engine API** / `docker.sock` | ❌ tools that attach to the socket will not connect |
| **Swarm** | ❌ out of scope for a single-host, daemonless runtime |

**What `kern compose` reads**, as-is: `depends_on` (+ conditions), `healthcheck`,
`deploy.resources.limits`, `ulimits`, `sysctls`, `labels`, `extra_hosts`, `init`, `stop_signal`,
`restart:`, `devices`, `dns*`, `logging`, `links`, `ipc`/`pid`, `tmpfs`, `cpu_shares`, `platform`,
`volumes_from`, `shm_size`, `secrets`, `group_add` (names from the image's `/etc/group`), YAML anchors
and merge (in flow style too, `svc: { <<: *tmpl }`, and inside a list item, `- <<: *gpu`), `extends`, `include`, `x-` fields, the `!reset`
and `!override` tags of a `-f` override, the project `.env` with `${VAR:-default}`/`${VAR:?err}`, and
network aliases.

**`include:`** is read in both spellings (`- file.yml`, and `- path:` with a list of overrides,
`project_directory` and `env_file`). Each included model keeps its own `.env` and resolves its
relative paths from its own directory, as docker does: on NVIDIA-Omniverse/usd-search, kern and
docker 5.0.2 list the same 18 services (21 with the GPU files), and a bind written from
`infra/compose/` reaches the same directory under both. A name defined in a file and in a model it
includes is merged the way docker merges it, not refused as the Specification's text says: the
including file wins a single value and lists are joined, and between two includes the earlier one
wins. One difference is deliberate: an included file, and every path inside an included model, must
stay inside the top-level project directory, symlinks included. Docker accepts `include:
../elsewhere.yml`; kern refuses it, the same rule it applies to every other path a compose file
writes, and `--project-root` widens it the same way (see below).

**What `kern build` supports.** All common instructions, multi-stage (+ `target:`), `COPY --from=…`,
COPY globs, BuildKit heredocs, `ADD <url>` (+ `--checksum`/`--chmod`), `COPY --chmod`, `FROM scratch`,
`SHELL`, `# escape`/BOM, `--build-arg`, `RUN --mount` of every BuildKit type (`bind`, `cache`, `secret`,
`ssh`, `tmpfs`) with `--secret`, `--ssh` and `--no-cache`, a per-instruction cache, and `.dockerignore`. Each layer is
content-addressed and reused while its inputs are unchanged: with a 3 s install step, the rebuild took
64 ms on Linux 7.0, 61 ms on WSL2 and 46 ms on a Jetson. Without an unprivileged overlay that records
deletions the build is **flat** and the cache whole-build; `kern build inspect <id>` says which.

## How a stack is wired

kern picks the wiring from the file, and says which one it picked.

**A namespace per service on a bridge (the default, from two services up).** Docker's arrangement:
each service keeps its own `127.0.0.1` and peers are reached by name. Measured against `--pod` on
`up -d` with warm images: +17 ms for 2 services, +23 ms for 4, +27 ms for 8.

**A bridge per network, when the file's `networks:` leave two services with nothing in common.** Each
compose network gets its own bridge, on the subnet the file declares for it or on `10.89.<n>.0/24`;
each service is attached to the bridges of its own networks (`eth0`, `eth1`, ... in the order it lists
them) and to no other, and the pod does not forward between them. A peer is reached by name, on every
port, at its address on the first network the two share; a service on no shared network has neither
the name nor a route. Measured with three services on images that EXPOSE nothing (`web` on `front`,
`db` on `back`, `app` on both), as root and as a user: `web` reached `app` and not `db`, by name or by
address, and `app` had one interface per network. Two members given `NET_ADMIN` that each add a route
through the pod did not reach each other; with forwarding turned on in the pod, they did.

**One shared namespace (`--pod`).** Services reach each other by name at the pod's address
(`192.0.0.8`): no bridge, no IPAM, no DNS server. Two services cannot both listen on the same container
port, and kern refuses such a stack rather than running it with one of them dead. A port bound on the
loopback is reached through `localhost` by every member, which is what one namespace means, and not by
a service's name: measured with a listener on `127.0.0.1` and one on `0.0.0.0`, a peer's
`wget loonly:81` was refused and `wget anyif:81` answered, in all three wirings and under Docker.

**A namespace per service with relays (`--no-pod`).** Only when asked for. A relay reaches the
service at its own address and not at its loopback, so a service bound to `127.0.0.1` is not reached
by a peer, as under Docker. Peers are reached through per-service loopback aliases
(`127.0.0.2` upward). The cost is a relay hop: -34% bulk throughput, -16% connection rate. A relay is
built per known port: what the service declares (`port:`, `expose:`, `ports:`) or, when it declares
none and runs the image's own command, what its image EXPOSEs, so a `redis` or an `nginx` is reachable
as in Docker while a worker that runs `psql` from the `postgres` image does not claim 5432. A service on an
image that EXPOSEs nothing and declares no port gets no relay, and `up` names it; Docker reaches any
port a container listens on, and here that port has to be written as `expose:`. Measured on the
three-service file above under `--no-pod`: with no port declared, a call to a peer by name reached the
CALLER's own listener and returned its own answer.

**`network_mode: service:X` joins X's network namespace, in every wiring.** The service shares X's
`127.0.0.1` and X's route out, so a client put behind a VPN container stays behind it; it has no
address and no name of its own on the stack's networks, and a peer reaches its ports at X's name.
X starts first. `ports:` or `hostname:` on such a service are refused with Docker's words
(`conflicting options: ...`). Measured on a `vpn` + `client` + `web` file, against Docker on the
same file: one namespace inode for `vpn` and `client`, `client` read `vpn`'s loopback-only port,
`client` reached the internet through `vpn`, `web` got `client`'s answer from `vpn:8080` and did not
resolve `client`. On the command line the same is `kern box --network container:<box>`.

**`networks:` is enforced on a bridge per network and under `--no-pod`, and inert in a pod.** Two
services with no network in common share no bridge (or get no relay) and no `/etc/hosts` entry, so the
peer's name does not resolve. The boundary is the ABSENCE of a path, not a filter, so no rule can be
misconfigured into permissiveness. Over 240 real files, 52 have a pair that loses an edge, so `up`
names every cut pair first.

**The project and its names are Docker's.** The project is `-p`, `COMPOSE_PROJECT_NAME`, the file's
`name:`, or the directory's name normalized as Docker normalizes it; every file in one directory is
one project. A service's box is `<project>-<service>-1` and a network is `<project>_<network>`:
`kern box --network <project>_<network>` joins that network of a running stack, with an address of its
own on a stack on a bridge and every name of that network resolving, and the internet through its own
NAT with the host's resolvers unless the file marks that network `internal: true`, as `docker run
--network` does.

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

A box behind pasta has an address of its own (`10.0.2.15`) and reaches the host at the host's address,
never the host's loopback, in either family: a service bound to `127.0.0.1` or `[::1]` on the host is
out of reach from every box. Measured against the 7 loopback-only services of a development machine,
0 opened from a pod, a compose bridge or `--no-pod`, and with an IPv6 default route on the host,
`[::1]` through the IPv6 gateway answered nothing (the previous build reached it). Where the host has
IPv6, a box reaches the IPv6 internet and resolves AAAA (measured on a VPS); Docker gives a container
no IPv6 unless the daemon is configured for it.
Its resolvers are the host's; on a host that resolves through systemd-resolved's `127.0.0.53` stub,
the stub's upstreams.

`internal: true` is a real boundary without a pod: such a service is given no NAT, so there is no
route out of its namespace. Two exceptions are named rather than hidden: a service on the host network
already has the host's connectivity, and one with `restart:` becomes a systemd unit `up` never holds.
Measured from inside a segregated service, a public address connected while the host's own answered
`refused`.

Pasta costs about **3.6 ms per round trip** and about 9% less download throughput.

## Differences that bite

**In one shared namespace the services share `127.0.0.1`.** A port bound on the loopback is reachable
from every member through `localhost`: admin endpoints, `/metrics`, pprof, anything trusting
`127.0.0.0/8` without authentication. The default bridge gives each service its own loopback.

**A published port binds `0.0.0.0` and `[::]`, like Docker.** On the corpus, 203 of 259 files (78%)
publish at least one port. Every form is read as Docker reads it, measured against `docker port`:
`8080:80` and `:8080:80` bind both families, `0.0.0.0:8080:80` IPv4 only, `[::]:8080:80` and
`[::1]:8080:80` (or `::1:8080:80`) that IPv6 address only, and `::8080:80` is refused as Docker refuses
it, `invalid IP address: :`. On a host without IPv6 the `[::]` half of a default bind is dropped, as
Docker drops it. `kern ps` lists both halves, `0.0.0.0:8080->80, [::]:8080->80`. `compose port` prints
an IPv6 address in brackets (`[::1]:18207`), as `docker port` does; `docker compose port` prints it
without (`::1:18207`), which is not a usable URL.

**A published port reaches the box's address, not its loopback, as under Docker.** A service listening
on the box's `127.0.0.1` only is not published, and kern says so once in the box's log; a client
arrives from the box's address and not from loopback, so a server's "trust local connections" rule
does not admit it. Measured against Docker, same images: a listener bound to `127.0.0.1` answered
nothing on either, and Redis in protected mode answered `-DENIED` to a published client on both. Before
this, under kern, the first answered 200 to a LAN client and the second `+PONG`.

The narrower posture is a CEILING rather than a default, for both families, so a downloaded file
cannot defeat it by writing an address:

```toml
[kern]
publish_bind = "127.0.0.1"
```

**A published service also gets a name on this machine**: `compose up` prints
`http://<service>.<project>.localhost[:port]/` beside it, answered by a router of your user on the
loopback addresses. See [CONFIG.md](CONFIG.md#local-names-for-compose-services) for the names, the
port and `[kern] local_domains = false`.

**A service with no `mem_limit:` gets the host's RAM**, as under Docker. It is not uncapped: the box
carries a `memory.max` of its own, so a failure stays attributable to its own cgroup, and an OOM kills
the process the kernel picks, as under Docker.
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

**A relative path that leaves the compose file's own directory.** Docker accepts `build:
../somewhere`, a bind source above the project and a secret file outside it; kern refuses all four,
naming the service and the path. Each is CANONICALISED first, so `../` and a symlink out are the same
case. An ABSOLUTE bind source, or one under `~/`, is mounted as written, as docker mounts it: it is
the file naming a host path outright, so read a downloaded file's `volumes:` before `up`.

| in the file | refused when |
|---|---|
| `build: <ctx>` | the context resolves outside the compose directory |
| `dockerfile: <f>` | it resolves outside the **context** (as Docker resolves it) |
| `volumes: - <src>:<dst>` | a relative bind SOURCE resolves outside the compose directory |
| `secrets: file: <f>` | the file resolves outside the compose directory |

The file cannot widen this; the operator can. `kern compose --project-root <dir>` names a directory
that contains the compose file, and every path in the file may then reach anywhere inside it. Paths
still resolve from the file's own directory, as docker resolves them, so a file kept in `deploy/`
that builds from `..` (measured on LLMSystems/vLLMux, which docker runs and kern refused) runs with
`--project-root .` from the repository and means the same thing it means under docker. A root that
does not contain the file is refused: it widens the project around the file, it does not move it.
Every refusal of this kind names the flag.

**Inside a git repository the repository is the project**, with no flag: a file in `docker/gpu/` may
build from `../..` and bind `../../web` (Kokoro-FastAPI, InvokeAI and vLLMux are laid out this way),
and kern says so once. A relative path that leaves the repository is still refused. A repository
that holds your home directory, such as a dotfiles repository at `~`, widens nothing, because a
relative path would then reach `~/.ssh`. The home it compares against is the password database's for
you and for the file's owner, as well as `$HOME`.

**The host's `/dev/shm` as a bind source.** Docker accepts `-v /dev/shm:/dev/shm`, which guides for
Chrome, Selenium and PyTorch DataLoaders print to get a bigger shared-memory filesystem than docker's
64 MB default. It also hands the container every POSIX shared-memory object your own processes hold,
readable and writable, which is half of what `ipc: host` hands over, and kern refuses `ipc: host`. So
kern refuses the bind too. A box's `/dev/shm` is already its own and sized to `--memory`; set it with
`--shm-size` (compose: `shm_size:`). One object can still be shared by binding its own path under
`/dev/shm`. The host's `/dev/mqueue` is refused for the same reason and more directly: POSIX message
queues live in the IPC namespace itself, and a queue created on the host was measured visible in a
box given that mount.

⚠️ The context is resolved when the build runs, so `compose config` renders such a file without
complaint and `build`/`up` are where it is refused.

**`${VAR:?message}`** with no value, which is what a compose file writes for a password. Every variable
with no value is named, not just the first.

**A `RUN --mount` that cannot be read**: an unknown type, a missing `target=`, a `mode=` that is not
octal. Dropping a mount changes what the command does, so it is never dropped quietly.

**`external: true` on a volume that does not exist**, as Docker refuses it.

**Two services on the same internal port under `--pod`.** Declare the port each listens on, with
`port:` or `expose:`. kern passes it as `PORT`, a convention and not a contract.

## Resource profiles from a compose file

`x-kern-vcpu`, `x-kern-vdisk`, `x-kern-vgpio` and `x-kern-security-profile` attach a `kern.toml`
profile to a service. `x-` is the specification's extension mechanism, so the file stays portable.

A profile buys only what compose cannot already say: `cpus`, `cpuset` and `mem_limit` are compose's
own and are used directly. `vgpio` is gated, because a profile name means different hardware on
different hosts: `compose config` says what each resolves to here (in its summary, on stderr), and
`--allow-device-grants` is required.

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
| `run` | `run` (the same box as `box`, in `docker run`'s shape) | `-d`, `-t`/`-it`, `--entrypoint` replaces ENTRYPOINT and discards CMD, `--network <name>` joins a running pod, a stack, or a stack's `<project>_<network>` |
| `create` | `create` | a kept box recorded and not started; `start` runs it |
| `exec` | `exec` | joins the box's namespaces; `-t` allocates a PTY, `-i` does not |
| `ps` / `inspect` / `stats` | same | `--filter`, `--format`, `--json`, `--no-trunc`; `inspect -f` takes docker's own paths; `kern top` is the live view |
| `logs` | `logs` | `--tail`, `-f`, `-t`, `--since`/`--until`; the follow is a bounded read. Every box's output in one stream, ordered by time: `kern logs --all` (Docker has no CLI equivalent), and live in `kern top`, Logs tab, as Docker Desktop's Logs view (search, level and source filters, CSV export). `--log-driver none` (compose `logging: driver: none`) keeps nothing and `kern logs` says so, as Docker does; `json-file` and `local` are the default, and drivers that ship output elsewhere are refused |
| `stop` / `kill` | `stop` / `kill` | `stop` signals, waits 10 s, then SIGKILLs. `kill` is immediate (SIGKILL, exit 137); `kill -s SIGNAL` sends that signal to the box's init and nothing else, as `docker kill -s HUP` reloads a server; `compose kill` and `compose kill -s` the same, per service |
| `pause` / `unpause` / `attach` | same | cgroup v2 freezer; Ctrl-C detaches and the box keeps running |
| `cp` | `cp` | host↔box: files and directories, links kept as links (`-L` follows SRC), hardlinks kept, `-` a tar on stdout/stdin; symlinks cannot escape the box root |
| `images` / `rename` / `wait` | same | `images --digests` and `{{.Digest}}` show the repository digest a pull recorded (`<none>` for a build, a commit, a load); rename is in place, pid unchanged, and a kept box's layer moves with it; `wait` blocks and prints the status |
| `history` | `image history` | the image's steps, newest first, with `--no-trunc`, `-q`, `--json`: a pulled or loaded image's own history with each layer's compressed size, a built image's Dockerfile steps over its base's, a commit's step; `-` where kern has no size. `kern history` is something else, the boxes run lately |
| `top` (box processes) | `exec <box> ps` | plus `kern top` |
| `update` / `diff` / `events` | same | live cgroup caps with no restart, and a kept box's record for its next start; overlay-upper `C`/`D`, a kept box's too; a poll-based, best-effort event stream |
| `commit` | `commit` | box → reusable image |
| `start` / `rm` | `start` / `rm` | a plain box is a process and its writable layer goes with it. `--keep` keeps that layer, `start` runs the same command on it, `rm` removes both. `rm` takes an exited box out of `ps -a`; `rm -f` stops a running one first and, on a name that is not there, says so and exits 0, as docker does |
| `restart` / `export` / `container <verb>` | same | `restart [-t N]` stops a kept box and starts it again; `export` writes a running box's filesystem as a tar; `container` groups the box verbs, except `run`, `top` and `prune`, which are kern's own words |
| `login` / `logout` / `port` | same | registry credentials; `port` is read from the running box, not from the file |

### Every `docker compose` verb and flag kern accepts

| | |
|---|---|
| **Verbs** | `up`, `down`, `stop`, `start`, `restart`, `ps`, `logs`, `build`, `pull`, `config`, `watch`, `port`, `systemd`, `run`, `cp`, `exec`, `wait`, `events`, `images`, `push`, `rm`, `top`, `version`, `kill`. `create` (a stack is created by `up`; `kern create` makes one box) and `scale` (`up --scale`) are refused by name |
| **`up`** | `-d`, `--wait`, `--wait-timeout`, `--exit-code-from`, `--abort-on-container-exit`, `--no-deps`, `--build`, `--no-build` (both as Docker for a service with `image:` and `build:`; see below), `--quiet-pull`, `--force-recreate`, `--no-recreate`, `-V` |
| **`down` / `run`** | `-v`, `--remove-orphans`, `-t`, `--rmi local\|all` · `-d`, `--rm`, `-T`, `--name`, `--entrypoint`, `-e`, `--user`, `--pull`, `--no-deps` |
| **`logs` / `ps`** | `--tail`, `-f`, `-t`, `--since`, `--until`, `--no-log-prefix` · `-q`, `--services`, `--format json` (Docker's field names plus `Publishers`), a template, or `table ...`; Docker's table by default |
| **`wait` / `push`** | `wait` exits with the status of the first service to stop, as Docker's does; `kern wait <box>` PRINTS the code and exits 0, an older frozen contract. `push` publishes only the services the file BUILDS, skipping by name one that merely names an upstream image |
| **Everywhere** | `-p`, `--env-file`, `--profile`, `--build-arg`, and `--flag=value` wherever `--flag value` works |
| **The file** | positional, behind `-f`, or OMITTED: the directory is searched for `docker-compose.yml`, `compose.yml`, their `.yaml` spellings, and `kern.toml` |
| **Files read** | `docker-compose.override.yml`, `extends: {file: ...}`, the project `.env`, `env_file:` long form, anonymous and project-scoped named volumes, a secret from an environment variable |
| **Keys applied** | `cpu_shares`, `memswap_limit`, `ulimits`, `runtime:`, `ipv4_address:`, `depends_on` conditions, `network_mode: service:X`, an image's own `HEALTHCHECK`/`STOPSIGNAL`/`Cmd`/`Entrypoint`/`Env` |
| **Keys named, not dropped** | an unknown service key (with a near-miss suggestion), every `deploy.*` kern does not apply, and `deploy.resources.reservations` |
| **`network_mode: host`** | applied as Docker applies it, and stated: it removes the service's network isolation, peers stop resolving it by name, and `ports:` becomes a no-op |

What needs a daemon does not exist here: `swarm` / `service` / `stack`, `docker.sock`, and anything
that attaches to it.

`--gpus` does exist and takes docker's grammar, which was measured against docker 29.1.3 rather
than assumed: a bare number is HOW MANY (`--gpus 2`), `device=0` and `device=0,1` name WHICH, and
`all` takes every card; `count=2` and `count=all` work too. A card's UUID works where an index
does, `--gpus device=GPU-1950be8a-…`, resolved from the driver's own `GPU UUID` field; a UUID no
card here carries is refused with the ones that are present. kern accepts `device=0,1` unquoted
where docker needs `"device=0,1"`, and it takes the quoted form too, including the
`--gpus 'all,"capabilities=compute,utility"'` that NVIDIA's documentation prints: that list
selects nothing here and nothing is missing, because a grant binds the driver's whole library set
and its tools, and kern says so rather than refusing the flag. `--gpus 0` is refused rather than guessed: docker
reads it as no gpus and this project's examples read it as card 0, so kern names both readings and
asks for `device=0`. `--device nvidia.com/gpu=0` is the CDI spelling of a card, resolved through
the spec on the host; `--device nvidia.com/gpu=all` is every card, and the flag repeats, so
`--device nvidia.com/gpu=0 --device nvidia.com/gpu=1` is two cards, as it is under docker and
podman (measured: kern used to keep the last flag alone, and refused `all`). A host path,
`--device /dev/X[:/dev/Y[:rwm]]`, binds that node as docker does, beside `--gpus` too, read-only
when the permissions name no `w`; a node the host does not have is refused, never created. The variables the spec
puts in the container are set (`NVIDIA_VISIBLE_DEVICES=void` from NVIDIA's, as docker and podman
set it). The spec's hooks are not run, because a grant is a set of binds; what the NVIDIA hooks do
that a workload depends on, kern does itself: the loader cache and the links below. A card you did not get has no device node in the box, so CUDA cannot initialise it there;
the host's PCI bus stays readable in `/proc/bus/pci`, so how many cards it has is still discoverable.
A granted card's own sysfs directory is bound read-only at `/sys/bus/pci/devices/<bus>`, which is
where NVML reads its PCI identity: `nvidia-smi --query-gpu=pci.bus_id` answers the bus, as under
docker (which mounts the host's whole `/sys`); no other device is in the box's `/sys`.

**On WSL2**, `--gpus` grants the GPU Windows exposes to the Linux guest the way docker does: `/dev/dxg`,
the vendor libraries bound one by one into the image's library directory, the NVIDIA directory of the
driver store at its own path (`/usr/lib/wsl/drivers/nvmdi.inf_amd64_<hash>` on the guest measured),
and `nvidia-smi` at `/usr/bin`, all read-only except the node. `/usr/lib/wsl/lib` is not mounted and
`LD_LIBRARY_PATH` is not touched, so an image that sets its own keeps the driver. Measured on a WSL2
guest with an RTX 3060: a CUDA kernel runs in the box and returns the right answer, and a box
without the flag has no driver; the same holds through compose, the Python SDK and the MCP server,
and from an Alpine guest too, as long as the box's image is glibc, because the vendor's libraries are
glibc builds. A selection is checked against the adapters the guest has, and refused where docker
refuses it: on a one-adapter guest `device=1` and `--gpus 2` fail under both, and a UUID resolves
under both. The adapters are read with the vendor's `nvidia-smi`, and on a musl guest, where that
tool cannot start, they are counted through `/dev/dxg` itself, so the refusals hold there too; a UUID
cannot be read there, so one is accepted unchecked and kern says so. WSL2 has no per-card node, so a
box that asked for fewer adapters than the guest has still sees every one, under docker as well, and
kern says so; for the same reason `--device` (CDI) has nothing to resolve to there. Measured with one
adapter: a guest with two has not been available to measure either runtime on.

**On a Jetson**, `--gpus` grants what NVIDIA's container toolkit grants there in its CSV mode, read
from the same lists (`/etc/nvidia-container-runtime/host-files-for-container.d/*.csv`): the device
nodes, the libraries and their links at the host's own paths, and the libraries' directories written
to the box's `/etc/ld.so.conf.d/00-kern-gpu.conf` before its loader cache is rebuilt, as docker writes
`00-nvcr-*.conf`. The box also gets the chip's identity, `/sys/devices/soc0`, read-only, which the
runtime reads before `cuInit`; the chip's fuses are not granted. Nodes the list names that you cannot
open on the host (the profiler and debugger nodes of the `debug` group) are left out. Measured on a
Jetson Orin Nano (JetPack R36.4.7) with docker 29.6.2 and toolkit 1.16.2 on the same board: docker
needs `--runtime nvidia -e NVIDIA_VISIBLE_DEVICES=all` there (it refuses `--gpus` in CSV mode), and
both runtimes give `python:3.12-slim` a working `cuInit` on `Orin`; kern does it with `--gpus all`,
through the Python SDK and through the MCP server. `--gpus device=<UUID>` takes the UUID the
Jetson's `nvidia-smi` prints, which has no `GPU-` prefix. A box's memory cap bounds GPU memory there
only with nvmap's page pool off: with it on (the default), a box capped at 256 MiB allocated 1 GiB of
GPU memory from pages another process had freed, charged to no cgroup, and with
`/sys/module/nvmap/parameters/enable_page_pools` set to `N` it was stopped every time. `kern doctor`
says which one this board is. The GPU nodes there open only through the `video` group, and docker's
NVIDIA runtime adds that group to the container. A kern box keeps the groups you are in when its
GPU needs one, on any uid map, in a pod, under `--user` and for `exec` and health checks, and says
so; a box on the uid-range map otherwise starts with none. The group cannot be mapped into a range,
so the whole set is kept, as the single-uid map always keeps it.

**Where the libraries land** is docker's rule on both kinds of host: `/usr/lib/x86_64-linux-gnu` for
a Debian-family image (it has `/etc/debian_version`), `/usr/lib64` for any other. Measured against
docker on `ubuntu:24.04`, `fedora:41` and `alpine:3.20`: the same directory under both, and in
`fedora:41` `nvidia-smi` lists the card under both.

THE GRAMMAR IS DOCKER'S AND THE RESULT IS NOT, which is worth knowing before you compare the two.
Measured on one host with two cards, docker 29.1.3 with the NVIDIA toolkit against this build, the
same `--gpus device=0` and the same `python:3.12-slim`:

| | docker | kern |
|---|---|---|
| device nodes in the container | 4 | 7 |
| nvidia/cuda libraries under `/usr/lib/x86_64-linux-gnu` | 20 | 50 |
| `nvidia-smi` and its four neighbours | injected into `/usr/bin` | bound into `/usr/bin` |
| `NVIDIA_VISIBLE_DEVICES` | `0` | `0` |

The last two rows were measured again with `ubuntu:24.04`, for every spelling of the flag: `all`,
`device=0`, `device=1`, `"device=0,1"`, `2`, `1` and a UUID give the same variable, the same five
tools and the same card under both. The variable is what docker writes: `all`, the indices as
written, `0,1` for `--gpus 2`, a UUID as given; and the grant's value replaces one set with `-e`, as
docker's does. A box with no grant has neither, under both.

**The loader cache lists the driver.** Docker's and podman's NVIDIA hook runs the image's `ldconfig`
after the grant; kern did not, so `ldconfig -p` in a granted box listed no `libcuda` and Python's
`ctypes.util.find_library("cuda")` answered `None` where docker answers `libcuda.so.1`. A granted
box now rebuilds the cache before the workload starts, with the image's `ldconfig` run under the
workload's own confinement (every capability dropped but `CAP_DAC_READ_SEARCH`, which reads and
traverses and never writes; the seccomp filter, the AppArmor profile and Landlock allowlist when
asked for, no host environment) and a deadline. Measured on a WSL2 guest: the same answer as
docker's, `--read-only` included. The result is kept in kern's cache directory with the soname links
that run made, keyed on the kern binary, the image's layers and every bind's source, and a later box
of the same image and grant gets both back without running image code: measured on a Jetson, 14.1 ms
for the first box and 0.36 ms for the next, `cuInit` answering 0 in each.

**Vulkan, EGL and OptiX find the driver.** The files NVIDIA's own CDI spec mounts are bound at the
paths it mounts them: the Vulkan ICD and layer in `/etc/vulkan`, the GLVND EGL vendor file and the
EGL platform files, OptiX's `nvoptix.bin`, and the `libGLX_indirect.so.0` and GBM backend links. In
a docker container given that spec, `vulkaninfo` lists the NVIDIA card; with `--gpus` alone docker
mounts none of the files. Not bound, though the spec mounts them: the GSP firmware (the host's
kernel loads it), `xorg.conf.d` (a box runs no X server) and the `nvidia-persistenced` socket, a
channel from the box to a root daemon on the host.

**`--ipc=host`**, which NVIDIA's examples carry, is accepted and not applied: every box has its own
IPC namespace, and kern says so when the box starts. What those examples want from it is a large
`/dev/shm` (docker gives 64 MB by default and the host's with `--ipc=host`); a box's is sized to its
`--memory` cap, and `--shm-size` sets it.

**Replicas** (`up --scale web=3`, `scale:`, `deploy.replicas`) are one box each: `<project>-web-1`,
`<project>-web-2`, `<project>-web-3` (Docker's container names), with their own addresses and ports, a host port range handing
each a port of it. A command naming the service reaches every replica, `port --index` and `exec
--index` one. The service's name lists every replica and a replica's box name resolves, while
`web-2` does not, as under Docker. The order differs: Docker's DNS shuffles the list at every query,
and a hosts file cannot change between two, so each box starts its list at a different replica and
the spread is between clients rather than between one client's connections. A stack that is up can be
rescaled: running boxes keep their addresses (their loopback aliases under `--no-pod`) and learn the
replicas added or stopped.

**Shared IPC between services** works as Docker's: `ipc: shareable` on one service and `ipc:
"service:<it>"` on another put the second in the first's IPC namespace with the same `/dev/shm`
(`kern box --ipc shareable` and `--ipc container:<box>`). As under Docker, the donor must be
`shareable` (otherwise "non-shareable IPC"), and the two must be in one stack or pod: an IPC
namespace is entered from the user namespace that owns it, and a pod's members share one. A shared
`/dev/shm` is a directory under the runtime dir, as Docker keeps a container's on the host, so its
size is bounded by the runtime dir's tmpfs rather than by `--shm-size`.

Docker's default capability list is `compute,utility`, so it selects a subset of the driver's
libraries, adds the driver's command-line tools, and hands over no DRM node. kern binds the
driver's whole library set and the same tools, and the three extra nodes are `nvidia-modeset` and
the card's `/dev/dri` pair, which is what the vendor's own CDI spec names for that card. So a kern
box can encode video and reach the DRM device without asking; a box given a card has MORE of the
driver in it here than the same flag gives under docker, and that is a wider surface for code you
do not trust.

In a compose file, five spellings reach a card and all five need `--allow-device-grants` from the
operator: `gpus:` (the 2.30 shorthand), `deploy.resources.reservations.devices` with a
`capabilities:` list that names `gpu` or sets `driver: nvidia` (or `driver: cdi` with CDI names in
`device_ids`, as docker reads it), CDI names under `devices:` (`nvidia.com/gpu=0`, `=all`, several),
the host nodes themselves under `devices:`, and `runtime: nvidia` with no explicit request beside
it. That last one is read with NVIDIA's meaning: the service gets the GPUs its own
`NVIDIA_VISIBLE_DEVICES` names (the image's `ENV`, which is `all` in a CUDA image, or the file's
`environment:`), as `kern box --runtime nvidia` does, decided once the image is known; `void`,
`none` and an unset variable grant nothing, and an explicit request beside it wins, as under docker.
Measured on devflowinc/trieve's TEI file, which carries `runtime: nvidia` alone: docker gave it the
GPU and kern used to give none. `NVIDIA_VISIBLE_DEVICES` on its own, with no `runtime:`, is still
not a request: whether docker honours it depends on the daemon's default runtime, which a file
cannot show, so kern names it with the line to write instead.

`allow_gpu_grants = true` under `[kern]` in your own [`kern.toml`](CONFIG.md) grants four of the
five with no flag: `gpus:`, the `deploy` reservation, `nvidia.com/gpu` CDI names and `runtime:
nvidia`. It is the decision docker's users make once by installing the NVIDIA container toolkit.
The host nodes under `devices:`, a CDI name of any other class and every other device still need
`--allow-device-grants`, and a config a compose file names cannot set the key.

ONE MORE SHAPE CHANGES ITS ANSWER HERE, and it is the one every guide prints:

```yaml
healthcheck:
  test: ["CMD", "nvidia-smi"]
```

Under docker that service is `healthy`, because the runtime injected the binary, and in a kern box it
is too, because the grant binds it at the same path. It still cannot pass in three cases, and kern
says which when the box starts: the service has no GPU grant, the host's driver has no such tool,
or the probe names a path other than `/usr/bin`. The driver's tools are glibc builds, so an alpine
image cannot run them under either runtime; probe what the grant binds instead, `test -c
/dev/nvidiactl`, which is present with a card and absent without one.

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
`gateway` all work. It resolves to the host's own address, so a port the host serves on its
interfaces is reachable through it, a port kern publishes included (every interface by default): an
open-webui configured for `http://host.docker.internal:7869` reaches the ollama port the same stack
publishes. What the host keeps on `127.0.0.1` is not reachable, through this name or any other
address. Three spellings are accepted (`extra_hosts`, `--add-host`, and `add_host = [...]`
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

What a Dockerfile asks of the builder, and kern does as Docker does (each measured on a published
project that failed before):

- **`RUN --mount=type=bind`** is performed: from the build context by default, `from=` a stage or an
  image, `rw` as a throwaway copy, a relative `target=` under `WORKDIR`. What is mounted is part of the
  layer's cache key, so a changed `uv.lock` reruns the step.
- **`USER` applies to `RUN`**, not only to the image's final command.
- **`COPY` into a path that crosses a symlink of the image** (`/bin` is `usr/bin` on every usr-merged
  base) writes through the link, and the link stays a link.
- **`WORKDIR` creates missing directories owned by the current `USER`**, mode 0755; directories that
  already exist keep their owner and mode.
- **`kern compose up <service>` and `run <service>` build that service and its dependencies**, not every
  `build:` in the file.
- **`RUN --mount=type=secret`** reads what `kern build --secret id=<id>,src=<file>` (or `env=<VAR>`, or
  compose's `build: secrets:`) gave it: a file at `/run/secrets/<id>`, mode 0400, owner 0:0, or with
  `env=` a variable and no file. A secret the build was not given is no mount, unless `required=true`,
  which fails naming it. The value reaches no layer, no cache key and no command line.
- **`RUN --mount=type=ssh`** reaches `kern build --ssh default` (the caller's agent) or `--ssh
  <id>=<key>` (an agent kern starts for the build), through a socket of kern's own at
  `/run/buildkit/ssh_agent.<n>`, mode 0600, with `SSH_AUTH_SOCK` set; `uid=` lets a non-root `USER`
  use it. Compose spells it `build: ssh:`.
- **`RUN --mount=type=cache`** is a directory kept between builds per `id` (default: the target),
  0755 owned 0:0 unless `uid=`/`gid=`/`mode=` say otherwise, shared, `private` or `locked` as
  `sharing=` asks. **`--no-cache`** reuses no layer and starts every cache empty. **`type=tmpfs`** is a
  tmpfs. None of the five leaves anything in the image.

Each of those was measured with BuildKit (buildx v0.39.0) first, and kern gives the same answers on
the same Dockerfile: owners, modes, the variable without a file, the error for a missing required
secret, the cache across three builds and after `--no-cache`, and an image with no trace of a mount.

**`kern build --platform`** builds for another platform: its base images are that platform's (cached
apart from this machine's, which they never replace), and its RUN steps run that architecture's
binaries through the kernel's qemu-user handler (registered with the F flag; kern says what to
install when it is missing). Several platforms, `--platform linux/amd64,linux/arm64`, build one variant
each; the name is this machine's variant, and `kern push` publishes a manifest list, which docker
pulls per platform (measured: `docker run --platform` ran both). `kern pull --platform` fetches into
that platform's cache entry, and compose's `build: platforms:` is passed through. `kern run --platform
linux/arm64` runs that entry (`uname -m` prints `aarch64` on an amd64 machine, as under Docker), the
Docker API's `?platform=` on a create or a pull does the same, and `kern images` names the platform of
every entry that is not this machine's.

**A pull that breaks part-way continues where it stopped**: a transfer cut by the network (an HTTP/2
stream reset, a timeout, a name that did not resolve) is retried up to five times, resuming the bytes
already downloaded. And with `image:` + `build:`, only the registry saying it has no such image (or
will not give it) leads to a build from source; a broken download stops and says to run it again.
- **A service with `image:` AND `build:` runs the image when it is here or can be pulled**, and is built
  only when it cannot be, or when `--build` or `pull_policy: build` asks; kern says which. A service
  with `build:` alone is built when its image is missing, or on `--build`, as Docker builds it; a
  running one is recreated only when the rebuilt image differs from the one it runs.
- **`up --wait` fails on a service that has exited**, with Docker's words (`container <name> exited
  (0)`), except one that exited 0 while another service waits on it with `condition:
  service_completed_successfully`, which passes, as on Docker Compose v5.

**`--pull always` and `pull_policy: always` read the manifest first**, as Docker does: an image whose
config digest is the one already here is not downloaded again, and a changed one is.

**An interrupted pull keeps the layers it completed**, as Docker does: Ctrl-C, a dropped connection or
a killed process leaves the finished layers on disk, each is checked against its digest, and the next
pull does not download them again. A layer cut off part-way is downloaded in full.
