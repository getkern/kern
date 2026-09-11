# Where kern agrees with Docker and podman, and where it deviates on purpose

Every line here is a measurement, not a reading of a specification. Three runtimes, the same image,
the same command:

* **kern**, this tree, x86_64.
* **podman 4.9.3**, rootless, same host.
* **Docker 29.6.2**, rootful, aarch64 (a Jetson Orin Nano, the only host here with a Docker daemon).

The architecture differs on the Docker column. Nothing measured below depends on it: they are
identity, environment and mount rules, decided by runc and the daemon rather than by the ISA.

| # | Question | Docker 29.6.2 | podman 4.9.3 | kern | verdict |
|---|---|---|---|---|---|
| 1 | Supplementary groups for a bare numeric `USER` | `groups=0(root),1000(app)` | same | same | agree |
| 1b | ... for an explicit `--user 1000:1000` | `groups=1000(app)` | same | same | agree |
| 2 | `HOME` for a uid the image does not know | `/` | the WorkingDir | `/` | kern follows **Docker** |
| 3 | `wget http://localhost:PORT` at an IPv4-only listener | **fails** | works | works | kern follows **podman**, deliberately |
| 3b | ... on which network | the default `bridge` | rootless pasta | pod / bridge | see the entry |
| 4 | `HOSTNAME` in the environment | container id, = `hostname` | same | box name, = `hostname` | agree |
| 5 | Identity and cwd of a `HEALTHCHECK` | the container's user, its `WORKDIR` | same | same | agree |
| 6 | A privileged host port, rootless | not measured (see below) | refuses | moves it | kern deviates, documented |
| 7 | Submounts of a `-v` source | carried INTO the container | (as Docker) | left outside | kern deviates: EXPOSURE |
| 7b | ... and does `:ro` cover them | yes, `ro` inside, write refused | (as Docker) | n/a, they are not there | Docker has no `:ro` hole |
| 8 | `cpu_shares: 512` / `1024` / `2048` | `cpu.weight` 59 / 100 / 174 | not measured | same | agree (curve fitted to 10 points) |
| 9 | `mem_limit` alone | `swap.max` = the memory limit | same as Docker | same | agree (the deviation was RETRACTED, see 40) |
| 9b | `memswap_limit` present | `swap.max` = total minus memory | not measured | same, and the same two refusals | agree |
| 10 | `oom_score_adj` of PID 1 | the daemon's (0) | not measured | inherited from the session (100 here) | kern deviates: no daemon to reset it |
| 11 | `/etc/resolv.conf` | the daemon's DNS (`127.0.0.11`) | not measured | the host's nameservers | differs; peers resolve from `/etc/hosts` either way |
| 12 | `logging: max-size` | rotates into `max-file` files | not measured | one window, newest kept | differs: the first line of the window can be cut mid-line |
| 13 | `network_mode: host` | the host's interfaces | not measured | same (measured: `lo enp5s0 wlp4s0`) | agree |
| 14 | A named volume, two different uids | writer AND reader refused (`0:0 755`) | not measured | same | agree |
| 15 | UDP between peers | works (one network) | works | works in a pod, NOT under the relay wiring | kern deviates under `--no-pod`, and says so |
| 16 | Two projects, one volume name | isolated (`pa_shared`, `pb_shared`); the reader gets `EMPTY` | not measured | same, keyed on kern's project name | agree (see below) |
| 17 | `docker-compose.override.yml` beside the file | loaded by `docker compose`, NOT by `-f <file>` | not measured | loaded, and the line is printed | kern follows the no-`-f` form, deliberately |
| 18 | The same port written twice | one mapping, stack runs | not measured | same | agree |
| 19 | Two sources on one volume target | one mount, the LAST source | not measured | same | agree |
| 20 | Two mappings sharing a host port | accepted, **fails at runtime** half-started | not measured | refused at `config` | kern deviates: STRICTER, before anything runs |
| 21 | `up -d` when a service exits immediately | exit **0**, nothing said | not measured | exit **1**, names the service | kern deviates: LOUDER |
| 22 | `up` without `-d` | attaches, streams, Ctrl-C stops the stack | not measured | same **on a terminal**; unchanged when piped | kern follows Docker where it cannot hang a script |
| 23 | `run --rm web sh -c 'exit 7'` | 7, deps up, ports not published | not measured | same on all three | agree |
| 24 | `up --wait`, four cases | 0 / 0 / 1 / 1 | not measured | same | agree |
| 25 | `up --build` after editing the Dockerfile | the OLD image without the flag | not measured | rebuilds either way | kern deviates: always current |
| 26 | `--exit-code-from db` while `tests` exits 3 | **137** (the abort ended db) | not measured | same | agree |
| 27 | `compose ps --format json` | NDJSON since Compose 2.21 | not measured | `kern ps --json`'s shape, own field names | differs in the FIELD NAMES |

---

## 1. Supplementary groups come from the image's `/etc/group`

A `config.User` that names no group gets the memberships its name has in the image's own
`/etc/group`; `1000:0` and an explicit `--user 1000:1000` get none. runc's `GetExecUser` rule.

```
# Docker 29.6.2, image with `USER 1000` and `root:x:0:app`
uid=1000(app) gid=1000(app) groups=0(root),1000(app)
# same image, --user 1000:1000
uid=1000(app) gid=1000(app) groups=1000(app)

# podman 4.9.3, docker.elastic.co/kibana/kibana:8.19.16 (`User "1000"`)
uid=1000(kibana) gid=1000(kibana) groups=1000(kibana),0(root)
# podman, docker.elastic.co/elasticsearch/elasticsearch:8.19.16 (`User "1000:0"`)
uid=1000(elasticsearch) gid=0(root) groups=0(root)
```

kern matches. Before it did, Elastic's Kibana died on `EACCES` reading certificates its own
`setup` service had written `root:root` mode 640, while the Elasticsearch nodes, whose image
declares gid 0 outright, were green.

## 2. `HOME` for a uid the image does not know

```
# Docker 29.6.2: --user 1234 -w /opt/wd  ->  HOME=/
# podman 4.9.3:  --user 1000 on airflow  ->  HOME=/opt/airflow   (the image's WorkingDir)
```

kern prints `/`, following Docker and runc's default user. For a uid the image DOES know, all three
give that user's passwd home (`/home/airflow` for `--user 50000` on `apache/airflow:3.3.1`), which
is what makes `pip install --user` tooling work: with `HOME=/root` the interpreter looks for its
user site-packages in a directory that does not exist, and `airflow version` answers
`ModuleNotFoundError: No module named 'airflow'`.

## 3. `localhost` and an IPv4-only listener: kern deviates from Docker on purpose

Image `python:3.12-alpine`, listener `python -m http.server 5000` (IPv4 only), check
`wget -q -O- http://localhost:5000/`, which is how compose files everywhere spell a health check.

The Docker column is a container on the daemon's default `bridge` network, the podman column is
rootless pasta, and kern is a pod member. The network is named because this is the row most exposed
to "it depends on how the daemon is configured": what decides it is the hosts file and musl's
sorting, not the driver.

```
Docker 29.6.2   hosts: 127.0.0.1 localhost / ::1 localhost ip6-localhost ip6-loopback
                disable_ipv6=0, lo has ::1
                wget localhost   rc=1        <- FAILS
                wget 127.0.0.1   rc=0
podman 4.9.3    hosts: 127.0.0.1 localhost / ::1 ip6-localhost ip6-loopback
                wget localhost   rc=0
kern            follows podman: wget localhost rc=0
```

With both records present, musl prefers `::1` and busybox's `wget` uses the first address only, so
the name cannot reach an IPv4-only server. Docker has the defect; podman avoids it by not claiming
the name for `::1`; kern does the same. A dual-stack listener works everywhere and is why this is not
noticed more often.

This entry corrected a wrong explanation in kern's own source. It used to say a Docker container has
IPv6 disabled so its `::1` is demoted: measured false above, `disable_ipv6` is `0` and the check
still fails.

## 4. `HOSTNAME`

```
Docker 29.6.2:  env=b46a2216132c  uts=b46a2216132c
kern:           env=<box name>    uts=<box name>
```

Agree. kern used to leave it empty on the `exec` and health-probe paths while `hostname` answered
correctly, which broke Airflow's scheduler check (`airflow jobs check --hostname "$${HOSTNAME}"`).

## 5. A health check runs as the container's user, in its WorkingDir

```
# Docker 29.6.2: --user 1000:1000 -w /tmp, probe records `id` and `pwd`
uid=1000 gid=1000 groups=1000
/tmp
status: healthy
```

kern matches on both axes. Running the probe as box root is a false-green generator: it reads what
the workload cannot, reports healthy, and `depends_on: service_healthy` releases a dependent onto a
service that is about to die.

## 6. A privileged host port, rootless

```
$ podman run --rm -p 80:80 alpine true
Error: rootlessport cannot expose privileged port 80, you can add
'net.ipv4.ip_unprivileged_port_start=80' to /etc/sysctl.conf (currently 1024), or choose a larger
port number (>= 1024): listen tcp 0.0.0.0:80: bind: permission denied
```

kern moves the port instead (`80` to `8080`, `443` to `8443`), once for the whole stack, before
anything starts, and prints both numbers; `[kern] privileged_port = "refuse"` gets podman's
behaviour. The reason for the default is measured: 15 of the 39 samples Docker itself ships publish
a privileged port, `80` in fourteen of them.

**Not measured on Docker rootless**: the only Docker host available here runs a rootful daemon,
which binds 80 and therefore cannot answer the question. Nothing in kern depends on the answer, so
this is stated as a podman measurement and no claim is made about Docker rootless.

## 7. Submounts of a `-v` source

```
# Docker 29.6.2 (kernel 5.15.148-tegra), tmpfs at /tmp/kern-sub on the host, then -v /tmp:/x
2 mount lines under /x, and /x/kern-sub IS a mount point inside the container

# the same with -v /tmp:/x:ro
/x           ro,relatime
/x/kern-sub  ro,relatime
touch /x/probe-root      -> Read-only file system
touch /x/kern-sub/probe  -> Read-only file system
```

THE `:ro` HALF, measured because the first half alone does not say which property kern's deviation
protects. Docker's read-only covers the submounts too (5.15 is past the 5.12 that gave
`mount_setattr(MOUNT_ATTR_RDONLY, AT_RECURSIVE)` recursive coverage), so Docker has no read-only
hole here and kern's deviation is about EXPOSURE alone: a recursive bind would put another program's
filesystems inside the box. That is also why kern's error message leads with exposure and not with
`:ro` - the `:ro` argument is not even true of Docker.

Docker binds recursively; kern does not, so those filesystems stay outside the box. They belong to
whoever mounted them, and the box asked for a directory rather than for everything mounted under it.
The kernel then refuses such a bind when the submounts were inherited (`has_locked_children`), and
kern's error names the paths and the reason instead of reporting `Invalid argument`.

## 8. `cpu_shares`, and why the obvious formula is wrong twice

Ten points read off the daemon, one container per value:

```
shares       2     8   100   256   512  1024  2048   8192  65536  262144
cpu.weight   1     3    17    35    59   100   174    532   3023   10000
```

Neither of the two mappings that "look right" reproduces it. A linear scale on 1024 gives 50 where
Docker gives 59 and 6400 where it gives 3023; `1 + (shares - 2) * 9999 / 262142`, which two
independent reviewers and this codebase all remembered as runc's, gives 20 for 512 and would move
the DEFAULT off 100, which the table shows Docker does not do. kern now computes
`ceil(100 ^ ((l - 1)(l + 126) / 1224))` with `l = log2(shares)`, which reproduces all ten.

## 9. `memswap_limit` is a total; `memory.swap.max` is not

Six cases, all measured:

```
--memory 256m                    -> memory.max 268435456   swap.max 268435456
--memory 256m --memory-swap 512m -> memory.max 268435456   swap.max 268435456
--memory 256m --memory-swap 256m -> memory.max 268435456   swap.max 0
--memory 256m --memory-swap -1   -> memory.max 268435456   swap.max max
--memory-swap 512m (no --memory) -> refused: "You should always set the Memory limit when using
                                    Memoryswap limit"
--memory 512m --memory-swap 256m -> refused: "Minimum memoryswap limit should be larger than
                                    memory limit"
```

kern converts by subtraction and copies both refusals. It deviates on ONE row: with no
`memswap_limit`, Docker allows swap equal to the memory limit, so `mem_limit` is really a 2x total;
kern leaves the allowance at 0, so `mem_limit` is the total it appears to be. The failure mode of
the strict side is a loud early OOM; the failure mode of the other is a box growing quietly into
host swap.

## 10. `oom_score_adj`

A kern box inherits the caller's value (100 in a systemd user session here); a Docker container gets
the daemon's, which is 0. There is no daemon to reset it in a rootless runtime, and resetting it to
0 would make a box HARDER for the kernel to pick than the session that started it. The compose key
`oom_score_adj:` is refused by name rather than silently accepted.

## 12. The log window

`logging: options: max-size` is honoured: measured 1k -> 19 lines, 8k -> 224, no key -> all 500, and
the window kept is the most recent one (lines 481-499 of 500), which is the end that matters. Docker
rotates into `max-file` files and therefore never shows a partial line; kern's window can begin
mid-line (`empimento-481`). Nothing is lost that the cap would not have dropped anyway.

## 15. UDP between peers

In a pod the services share one namespace and UDP crosses. Under the relay wiring a peer is reached
through a per-service loopback alias served by a TCP relay, so a datagram does not cross at all. That
is now stated in the wiring note itself rather than only for services that DECLARE a UDP port,
because a service that binds one without declaring it is the common case and was getting silence.

## 16. A named volume belongs to a project

Two directories, two projects, the same volume name; project A writes `/d/who`, project B mounts a
volume with that name and reads it.

```
Docker 29.6.2   b-1 | EMPTY        volumes: pa_shared, pb_shared
kern (before)   B   | FROM_PROJECT_A   one directory, shared by every stack that used the name
kern (now)      B   | EMPTY        volumes: pA-<hash>_shared, pB-<hash>_shared
```

The names that collide are the ordinary ones - `data`, `db_data`, `pgdata`, `redis-data` - so two
Postgres stacks were sharing one data directory.

The scope key differs from Docker's and the difference cuts both ways. Docker keys on the
directory's basename, so `/a/myapp` and `/b/myapp` ARE one project and share volumes; kern's project
name carries a hash of the file's path, so those two do not collide, and the mirror case is that
moving a project directory leaves its volumes behind under the old name. `-p NAME` pins the project
name under either runtime and is the answer to both.

A volume declared `external: true` is never renamed and never removed: the key means it exists
independently of this project.

## 17. The override file

`docker compose` with no `-f` loads `compose.override.yaml` / `.yml` / `docker-compose.override.*`
beside the file it discovered; `docker compose -f docker-compose.yml` does NOT (measured: the
override's `command`, its extra port and its `environment` keys were all absent). `COMPOSE_FILE`
suppresses it as well.

`kern compose <file>` is literally the `-f` form, and follows the OTHER one: it loads the override
and prints the line that says so. The command a compose file's author actually runs is
`docker compose up`, and a stack silently missing its dev overrides is a worse outcome than a stack
that says what it added. `COMPOSE_FILE` pins an exact list here too, and is the way to opt out.

Merge rules, all measured on the same daemon: `command` and `entrypoint` REPLACE; `environment` is a
mapping and merges per key; `ports` append, and an identical entry appears once; `volumes` are keyed
on the container path, so the override's source wins; `healthcheck` merges as a mapping with `test`
replaced; an override may introduce a service, and the merged result must still name an image or a
build context.

## 20. A host port claimed twice

`ports: ["8001:80", "8001:81"]` is accepted by `docker compose config` and fails at `up`, after the
container has been created:

```
Error response from daemon: failed to set up container networking: driver failed programming
external connectivity ... Bind for :::8001 failed: port is already allocated
```

kern refuses the same file at `config`, before anything starts. The identical-mapping case above is
the opposite decision for the opposite reason: `8001:80` twice asks for ONE thing twice, and
`8001:80` with `8001:81` asks for two things that cannot both happen.

## 21-22. `up`, attached and detached

`docker compose up -d` exits 0 even when a service exits 7 immediately; only
`--abort-on-container-exit` or `--exit-code-from` surface it. kern's `up` reports the death, names
the service, and exits 1. A script written against Docker that ignores the status keeps working; one
that checks it now learns something true.

`docker compose up` without `-d` attaches and streams every service's log, prefixed, and Ctrl-C
stops the stack. kern does the same WHEN STDOUT IS A TERMINAL. Piped or redirected - a CI script, a
systemd unit, the SDK - it keeps returning as soon as the stack is up, because a follow that ends
only on a signal would hang a caller that cannot send one. `-d` is explicit and works either way.

## 22b. `up` on a pipe: the deviation, and the contract that forces it

```
Docker 29.6.2, service that loops forever:
  timeout 5 sh -c 'docker compose up 2>&1 | cat'   EXIT=124   (attached, killed by timeout)
  timeout 5 sh -c 'docker compose up > file 2>&1'  EXIT=124
  timeout 5 sh -c 'docker compose up </dev/null 2>&1 | cat'   EXIT=124
  timeout 5 sh -c 'docker compose up -d'           EXIT=0
```

Docker attaches whatever stdout is. kern attaches only on a terminal, and the reason is its own
systemd integration: `kern compose <file> systemd` emits `Type=oneshot` with `RemainAfterExit=yes`,
a shape that requires `up` to EXIT. A unit whose `ExecStart` blocked would sit in `activating` until
`TimeoutStartSec` and then fail, and every stack deployed that way would go with it. Docker's
equivalent unit writes `-d` or uses `Type=simple`.

Two consequences, both shipped rather than assumed: the generated unit now writes `-d` explicitly,
so it does not depend on this decision at all, and a piped `up` prints a note naming what it did.
The decision itself is a function with a test over all four of `(detach, stdout is a tty)`.

## 23. The 12 files kern refuses

Docker 29.6.2 refuses all twelve: three YAML scanner errors, two `services must be a mapping`, two
failed interpolations (`${VAR:?}` with nothing to substitute), and the rest unparseable at load.
Nine of the twelve are not compose files at all by name (`.bak`, `.dist`, `.old`, `.md`, `-e`).

The refusals are agreement with Docker, so the 95% ceiling on the neutral corpus is bounded by files
Docker cannot read either, not by kern's parser.

## 24. `compose run`

```
Docker 29.6.2                                        kern
  run --rm web sh -c 'echo $DATABASE_URL $(pwd)'
    postgres://x /tmp                                  postgres://x /tmp
  the service's depends_on come up, alone              same (db up, web not)
  run --rm web sh -c 'exit 7'   ->  7                  7
  the service's published ports are NOT taken          same (nothing binds 8055)
```

kern brings the dependencies up by re-invoking `up -d <deps>`, so `service_healthy`, `profiles:`
and pod creation are `up`'s and cannot drift from it. The one-off joins the stack's pod when there
is one, so it reaches `db` by name exactly as the service would.

`--service-ports` is not implemented: the ports stay unpublished, which is Docker's default.

## 25. `up --wait`

Four cases, measured on Docker 29.6.2 and reproduced here:

| case | Docker | kern |
|---|---|---|
| no healthcheck, service stays up | exit 0, 1 s | exit 0, 0 s |
| healthcheck flips at 6 s | exit 0, 7 s | exit 0, 6 s |
| healthcheck never passes, `--wait-timeout 8` | exit 1, 8 s | exit 1, 8 s |
| service exits 0 immediately, no healthcheck | exit 1, 1 s | exit 1, 0 s |

The last row is the one worth stating: "ready" means still there, so a one-shot that finished is a
failure for `--wait` under both runtimes, whatever its status.

Default bound: Docker waits forever, kern uses its own condition timeout, the same one
`depends_on: service_healthy` already waits under.

## 26. `--build`

```
Dockerfile edited between two runs, then `up`:
  Docker without --build   VERSIONE_UNO     (the image it built before)
  Docker with --build      VERSIONE_DUE
  kern, always             VERSIONE_DUE
```

kern rebuilds a `build:` service whose context changed, so `--build` names what already happens and
is accepted silently. `--no-build` asks for the stale image and is refused by name.

## 27. `--exit-code-from` and `--abort-on-container-exit`

Stack of `db` (sleeps) and `tests` (exits 3 after two seconds), measured on Docker 29.6.2:

```
up --exit-code-from tests        exit 3    13 s   no container left running
up --abort-on-container-exit     exit 3    13 s
up --exit-code-from db           exit 137  13 s   db was ended BY the abort
up --exit-code-from nosuch       "no such service: nosuch: not found"
```

The third line is the one worth stating: the flag reports the status of the service it NAMES, not
of the service that triggered the teardown, so naming a long-running service gets the code the
teardown left behind. kern reproduces all four.

## 28. `down --remove-orphans`

Docker keys orphans on the project label; kern keys them on membership of the project's POD, which
is the same identity by a different mechanism. Nothing outside the pod is in range, so a same-named
service in another project cannot be caught by it. A `--no-pod` stack has no membership to read and
the flag stops nothing there, which is stated rather than discovered.

## 29. `compose ps` for scripts

`docker compose ps --format json` emits NDJSON, one object per line, since Compose 2.21 (it was a
single array before). kern maps `--format json` onto `kern ps --json`, the renderer the compose view
already shares, so a column cannot differ between the two views.

`--services` answers from the FILE under both runtimes: the list is the same whether the stack is up
or down, which is what makes it usable in a deploy script.

The field NAMES differ from Docker's (`Command`, `CreatedAt`, `ExitCode`, `Health`, `ID`, `Image`,
`Labels`, `Name`, `Project`, `Publishers`, `RunningFor`, `Service`, `State`, `Status`): kern's
`--json` is kern's own shape and is documented with `kern ps --help`. A script that reads
`.Service` or `.Name` ports; one that reads `.Publishers` does not.

## 30. The THIRD number: what the shared loopback actually changes

The compatibility rate counts 136 files carrying kern's "services share 127.0.0.1" note, 107 of them
carrying nothing else, which makes it the largest single cause between the corpus and a clean rate.
The note is an ANNOUNCEMENT: it says the stack was wired into one network namespace. Whether that
changes anything a process can observe is a different question, and neither published number
contains it.

Two observables make a file affected, and `scripts/loopback-census.py` reads both from inside the
running stack:

1. **A loopback-only listener.** A service binding `127.0.0.1:N` or `[::1]:N` is private under
   Docker, where every container has its own loopback, and reachable by every peer under a kern pod.
2. **A collision on an undeclared port.** Two services binding the same port outside `ports:` or
   `expose:` coexist under Docker and cannot under one namespace.

Read from `/proc/net/tcp` and `/proc/net/tcp6` inside a box, which every Linux image has, rather
than from `ss` or `netstat`, which most images do not ship.

```
136   files carry the note
 94   of them declare `build:` and cannot start here (this corpus carries no build contexts)
 41   are image-only
 22   of those came up (the other 19: images that no longer resolve, host paths the corpus
        cannot carry, an external volume, a FIFO in a layer, DNS timeouts)

  2   loopback-semantic = 9% of measured
  0   collision
 20   notice-only
```

THE FIRST RUN OF THIS CENSUS REPORTED 0 OF 19, AND IT WAS WRONG. That probe read `/proc/net/tcp`
with no settle and no way to see a collision at all; with the settle and the collision axis added
(see the section below), the same corpus yields two files whose services bind loopback only:

```
Felix-gg-cloud/ClaudeWorkspace (LinguaLeap)   127.0.0.1:9000
fourers/kafka-cli-app                          127.0.0.1:9093, 127.0.0.1:9094
```

Under Docker those ports are private to their container. Under one shared namespace every peer in
the stack can reach them. That is the exposure this census exists to find, and a broken probe had
called it zero.

BOTH HITS ARE NOMINAL, classified against a criterion written BEFORE the command (a liveness token
is nominal; state, control or a protocol banner is real; and a port the file also PUBLISHES was
never a privacy choice):

  * LinguaLeap's `127.0.0.1:9000` is MinIO, and the file itself publishes `9000:9000` and
    `9001:9001` to the host. The port is exposed to the whole machine by the author's own
    instruction, so its binding is not privacy.
  * kafka-cli-app's `9093` and `9094` are `KAFKA_LISTENERS: CONTROLLER://broker:9093` and
    `PLAINTEXT://broker:9094`: bound to the service's OWN NAME, which in a pod resolves to
    127.0.0.1. Under Docker the same stack's peers reach `broker:9094` just as well. The set of
    processes that can reach it is identical under both runtimes.

A FALSE-POSITIVE CLASS IN THE PROBE, named because it changes the number. A service that binds a
NAME lands on loopback in a pod, and that looks identical to a service that chose loopback for
privacy. `/proc/net` cannot tell them apart; the file can. Two of the two hits are of that kind or
are published outright, so the honest reading of this census is **0 real, 2 nominal out of 22
measured**, not "2 exposures".

What this does and does not say. 2 of 22 measured, which is below the thresholds two independent
reviewers set for changing the wiring default (10% and 15%) and above the zero that was published
first. It says nothing about the 94 `build:` files: see the section on what they declare.

THE DEFAULT CHANGED ANYWAY, AND NOT BECAUSE OF THIS NUMBER. This census was the case FOR the pod and
it held: on the measured sample the shared loopback exposed nothing. Section 43 is the argument that
changed the default regardless, which is a different one - what the reference does, and a cost that
stopped being a cost.

## 31. `config` depends on the image cache, and says so

kern reads each image's `EXPOSE` set to find two services claiming one internal port; that finding
decides whether the stack is wired into one namespace or one per service. The read is
`PullPolicy::Never`, so an uncached image is not read.

```
same file, same binary, one command apart:
  image in the cache     config -> wiring: bridge
  kern rmi <image>       config -> wiring: pod
```

Docker has no equivalent question: every container there has its own namespace, so two services
exposing one port never collide and nothing has to be read to know it.

The behaviour stays, because the alternative is a `config` that downloads images to answer a
question about a file. What changed is that it is stated: `config` prints
`wiring-images-unread: N (service (image), …)` and a note. On the neutral corpus 96 files of 259 are
in that state, which is the bound on how reproducible the compatibility rate is across machines.

## 32. The wiring is decided after the images are resolved, not before

kern reads each image's `EXPOSE` set to find two services claiming one internal port. Before this,
the read happened before anything was pulled, so a machine that had never seen the image decided
blind:

```
two services on memcached:1.6.34-alpine (the collision is only in the image, not in the file)
  cold cache, up -d   wiring: pod     1 service(s) died within 150ms of starting
  warm cache, up -d   wiring: bridge  both services up
```

The verbs that start boxes now resolve the images first. That is also Docker's order: on 29.6.2 a
cold `docker compose up -d` prints every `Pulling` line before the first `Creating`, so the images
are a phase and the containers are made after it. The bytes are the ones the launch would have
fetched moments later.

`config` is unchanged: it is a dry run, it does not pull, and it says what it could not read
(`wiring-images-unread:`).

## 33. What the census can and cannot see

`scripts/loopback-census.py` carries four controls, because two of its buckets were unprovable
without them:

| control | expected | why it exists |
|---|---|---|
| a service binding `127.0.0.1:9999` | `loopback-semantic` | the exposure axis |
| the same stack on `0.0.0.0:9998` | `notice-only` | the negative for that axis |
| two services on `0.0.0.0:7777`, one dies | `collision` | THE AXIS THAT WAS BLIND |
| a bind at t=10s under a 6s settle | `notice-only` | the bound on the claim, stated |

The collision axis cannot be read from `/proc/net`: the process that loses a bind exits and owns no
socket, so two services on one port leave ONE listener, the same picture a single service leaves. It
is read from the service that died, through its own log (`nc: bind: Address in use`).

UDP is read too (`/proc/net/udp`, `/proc/net/udp6`): a statsd or a local syslog on `127.0.0.1:8125`
is the same exposure as a TCP admin port.

What it still cannot see, and neither of these is closed by reading `/proc/net`:

  * A BIND AFTER THE SETTLE. A debugger port opened on first request, an admin socket bound after a
    login, a worker that listens only once its queue answers.
  * IDENTITY OVER TIME. Kafka, MongoDB and Redis Sentinel ANNOUNCE an address to their peers and are
    then contacted at it; what breaks is a rebalance or a failover minutes later, not a socket at
    second six. A census that reads listening sockets once cannot see it, and no probe in the e2e
    battery covers it either. It is named here rather than left for a field report.

## 34. The half that cannot be run: what the files declare

94 of the 136 shared-loopback files declare `build:` and carry no context in this corpus.
`scripts/declared-bind-census.py` reads what they SAY, with no image and no build:

```
94   files examined (services behind an inactive `profiles:` skipped, as Docker skips them)
 0   declare a collision (two services, one container port)
 0   declare a loopback bind (--host/--bind/--inspect=/HOST= naming 127.0.0.1 or localhost)
11   declare 0.0.0.0 explicitly
83   say nothing about binds: the address is in the image's CMD or an application default,
     and only a runtime census can see it
```

An upper bound on "could break in a pod by what the file says", and a lower bound on nothing. The 83
are the honest unknown.

## 35. The config blob: an exact wiring answer for kilobytes

kern reads an image's `EXPOSE` set to decide whether two services claim one internal port. Reading
it from the local cache alone made the answer depend on what had been pulled (section 31).

`kern_oci::fetch_image_config` resolves the manifest through the same prologue `pull` uses and
fetches the config blob only: a JSON document of a few kilobytes named by the manifest, not a layer.
On a 400 MB image it is three requests and single-digit kilobytes.

```
neutral corpus, files whose wiring was decided without reading an image
  before   90 of 259
  after     2 of 259      (two images that cannot be fetched at all)
two consecutive runs      identical
```

It is OPT-IN (`KERN_COMPOSE_FETCH_IMAGE_CONFIG=1`), measured:

```
config, uncached image, default        2 ms     (declares `wiring-images-unread:`)
config, uncached image, opt-in      2084 ms     (exact: `wiring: bridge`)
config, unreachable registry, default  2 ms
config, unreachable registry, opt-in  80079 ms  (10 s connect + 30 s total, several requests)
```

Docker's `config` never touches the network, and a dry run that can take eighty seconds is not one.
`compose-compat-rate.py` opts in because a published number must not depend on a local cache. `up`
does not need it: it resolves its images through the ordinary pull path before deciding the wiring.

Nothing is written to the image store. An entry with a config and no layers would read as "present"
to every other caller and fail the next `kern box --image` on a rootfs nobody extracted; the blob
goes to a scratch directory that is removed either way, and the answer is memoised under
`$XDG_CACHE_HOME/kern/expose` as port numbers and nothing else.

## 36. The 83 that only a build can answer

Of the 136 files carrying the shared-loopback note, 94 declare `build:`; of those, 83 say nothing
about their bind addresses (section 34). No reading of the file and no cached corpus can resolve
them: the address is in the image's `CMD` or in an application default.

`scripts/build-corpus-census.py` closes them the only way available, by cloning the repository the
corpus filename encodes, building, running, and applying the same probe. It reports `not-cloned` and
`not-measured` as their own buckets, so a repository that is gone or fails to build never counts as
clean.

It builds and runs code written by strangers, so it refuses to start without
`--yes-build-foreign-code` and is never invoked by a gate. The number it would produce is not in
this document, because it has not been run against real repositories: what is recorded here is that
the question has an instrument and a denominator, not an answer.

## 37. A service with no memory keys at all

Row 9 covers `mem_limit` and `memswap_limit`. It does not cover the case most files are in: no memory
key at all. Measured on both runtimes, same file, service with no `mem_limit`:

```
                     memory.max            memory.swap.max
Docker 29.6.2        max                   max
kern                 33465032704           0
```

`33465032704` is exactly this host's `MemTotal`, so kern caps a box at the machine's RAM where
Docker caps it at nothing. That half is inert: a process cannot exceed the RAM it can allocate.

THE OTHER HALF WAS NOT, AND IS CLOSED. A service with no memory keys used to get NO SWAP, so a
workload that would have swapped and survived under both references was OOM-killed here at the
host's RAM, with nothing at `config` saying so. It now gets the host's own `SwapTotal`. The table
above is the measurement that found it; section 40 is the retraction and the three rules that
replaced it.

What remains of this row is the ceiling itself: kern writes the machine's numbers where Docker and
podman write `max`. The bound is the same in practice, and the kill stays attributable to the box's
own cgroup rather than to the host OOM killer choosing a victim elsewhere.

## 38. The owner of a file a service writes on a bind mount

```
service with `user: "1000:1000"`, writing into a bind-mounted host directory
  Docker 29.6.2, rootful     the file is uid 1000 on the host
  kern, rootless             the file is uid 100999 on the host
```

kern maps the box's uids through the caller's subuid range, so the box's 1000 is 100999 outside. The
first `ls -la ./data` after a migration shows it. It is structural to running without root and
cannot be removed while kern stays rootless; `podman unshare` is the equivalent tool for handling
such a tree, and `kern` inherits the same problem shape.

## 39. After a reboot

Docker restarts a container with `restart: always` or `unless-stopped` at boot, because the daemon
starts at boot and owns them. kern has no daemon: a stack's services are supervised in-process, and
after a reboot nothing brings them back.

The path is `kern compose <file> systemd`, which emits a unit, plus `loginctl enable-linger` for a
user unit so the session starts without a login. The generated unit prints both commands in its own
header.

This is the deviation a migration meets on its second day rather than its first, and it is in the
perimeter for that reason.

## 40. The swap deviation, retracted

Row 9 used to read "kern deviates: STRICTER". It was decided on a premise that a third runtime
disproves, and it is withdrawn rather than restated.

```
                             Docker 29.6.2   podman 4.9.3 rootless   kern (was)   kern (now)
no memory key at all         max / max       max / max               hostRAM / 0  hostRAM / SwapTotal
mem_limit: 256m              256m / 256m     256m / 256m             256m / 0     256m / 256m
mem_limit + memswap_limit    the subtraction  not measured           same         same
```

THE PREMISE WAS THAT ROOTLESS IMPOSED IT. podman is rootless, on the same host, and gives `max` and
`max`. It did not. And kern's own ceiling with no key written is the HOST'S RAM, not a small number,
so the box was never bounded either: the position was not strict, not Docker, and carried no warning,
which is the one combination this project refuses. A service that would have swapped and survived
under both references was OOM-killed here at the host's RAM, and `config` said nothing.

kern grants what the machine has rather than writing `max`: the bound is the same in practice and the
kill stays attributable to the box's own cgroup instead of the host OOM killer picking a victim
elsewhere. That is the same decision the build path already took, for the same measured reason.

`memswap_limit` is untouched: Docker's key is memory PLUS swap and the v2 field is swap alone, so the
subtraction and its two refusals stand.

## 41. `runtime:`, answered by its value

It is the only compose key the neutral corpus reports as unimplemented, on two files, and both write
`runtime: nvidia`. The two possible answers are opposite requests and get opposite sentences:

  * `nvidia` asks for HARDWARE. kern's equivalent is a device grant: `devices:` in the file plus
    `--allow-device-grants` on the command line, which is the operator's half a file cannot give
    itself. The note predicts the failure without it: the service starts and then fails inside with
    a CUDA or driver error, which reads as a broken driver on the host rather than as that line.
  * any other value (`runsc`, `kata`) asks kern to hand the container to a DIFFERENT runtime. kern
    is one; there is no equivalent, and the workload needs the engine that ships it.

## 42. A key one edit from a real one

After `runtime:` was answered, one corpus file was left in the generic bucket, and its key is
`depend-on:`. Docker ignores it as silently as kern did, so the file loses an ordering constraint
and nothing on either runtime ever mentions it again.

A key one edit away from a known one now says which, with hyphens and underscores folded first (the
vocabulary uses `_`, people type `-`). The radius stops at one edit, and the negative cases are the
point:

```
depend-on    -> depends_on      one deletion once the separators agree
comand       -> command         one deletion
enviroment   -> environment     one insertion, the commonest slip there is
enviroments  -> nothing         two edits
dns          -> nothing         an exact key is not a near miss for a longer one
```

## 43. The default wiring: what it cost to match Docker, and what it bought

From two services up, kern gives each service its own network namespace on a bridge. That is the
arrangement Docker has and it was NOT the default before: a stack was put in one shared namespace,
where a port a service bound on `127.0.0.1` was reachable by every peer.

THE MEASURED CASE FOR THE POD WAS GOOD (section 30): 22 stacks read from inside, 2 with a
loopback-only listener, both of them nominal on a criterion written before the command, 0 collisions.
The pod exposed nothing that was measured. The argument that changed the default is not that number:

  * a runtime whose reason is confinement does not ship a boundary WEAKER than the reference by
    default, and "nothing found in 22 stacks" is not "nothing there" - 94 of the 136 affected files
    could not be started from this corpus at all;
  * the difference was the single largest one left, 135 files of 259 with 101 carrying nothing else,
    so every one of those files ran under a semantics kern had to warn about;
  * the cost stopped being a cost.

WHAT IT COST, BEFORE AND AFTER. Whole `up -d`, warm images, alternated against the same binary with
`--pod`, medians of five (`scripts/wiring-cost.py`):

```
services     pod      bridge before     bridge after
   2       172 ms      238 ms  1.40x     190 ms  1.10x
   4       172 ms      306 ms  1.77x     195 ms  1.14x
   8       174 ms      413 ms  2.37x     202 ms  1.15x
```

Eight services cost +239 ms before and +27 ms after. Two causes, both measured, neither of them the
bridge itself:

**A veth end that MOVES between namespaces waits an RCU grace period.** Five pairs each, in a user
namespace: 14-22 ms to create the pair and then move the peer, 1-2 ms to create the peer directly in
the target by naming its namespace in the CREATE message. kern moved it, once per service, serially.
It now names the namespace (`IFLA_NET_NS_PID` inside the peer's nest, the same message
`ip link add … netns` sends) and a bridged member went from 16-30 ms to 5-6 ms, against a pod
member's 4.

**Every NAT was attached one at a time.** Attaching pasta to a member costs about 17 ms, and the
attach ran inside the loop that releases services in dependency order, which is sequential by
construction. Eight services spent about 140 ms there. The attaches do not depend on each other -
every box is prepared and held at its pre-exec gate before any is released, so every PID 1 already
exists - so they now run concurrently, before the first release. The ordering guarantee is unchanged
and stronger: no service is released until every NAT is up.

Isolating them, eight services on a bridge whose network is `internal: true` and therefore takes no
NAT at all came up in 173 ms against the pod's 171. The bridge itself was free; the two serial waits
were the whole bill.

WHAT IT BOUGHT. The compatibility rate on the neutral corpus went from 87 of 259 to 188 of 259,
33% to 72%, which is exactly the 101 files that carried the shared-loopback note and nothing else.
It is 189 today, the extra file coming from an unrelated fix in the same sprint (an anonymous volume
in long form that was being dropped). The end-to-end battery stayed at 7/7 and the corpus gate still
refuses no file Docker accepts.

WHAT IS STILL THE POD. A single-service stack, which has no peer to be separated from, and `--pod`,
which is one flag and still prints what it costs. A file whose `networks:` separate two services
still gets the relay wiring, because one bridge would put them back on one network.

## 44. An `external:` network between two projects: what the kernel allows, and what was built

13 corpus files declare a network `external: true`, which under Docker means SHARED WITH OTHER
PROJECTS: a proxy in one compose file resolves and reaches the applications in another. 9 of those
files have nothing else between them and a clean run, so it is the largest cause left that is kern's
to close. This section is what was measured before designing anything, because the answer decides the
shape and one of the two candidate shapes is not available at all.

**A SHARED BRIDGE BETWEEN TWO ROOTLESS PODS IS NOT POSSIBLE.** Two refusals, each with a control:

```
from the INITIAL user namespace, setns() into a holder's net namespace   EPERM
  control: enter that holder's USER namespace first, then its net ns     OK
from INSIDE pod A's user namespace, create a veth whose peer goes
  into pod B's net namespace (a SIBLING user namespace)                  EPERM
  control: the same command with both ends inside A                      OK
```

The two controls are what make this a fact about capabilities rather than about tooling. There is no
vantage point: joining a network namespace needs `CAP_SYS_ADMIN` in the caller's OWN user namespace,
which an unprivileged process does not have in the initial one; and placing a link in another
namespace needs `CAP_NET_ADMIN` in the user namespace that owns it, which a process inside a sibling
does not have. A stack's pod would have to be created as a CHILD of the network's user namespace for
this to work, which is a decision taken before either stack exists and drags the whole uid-mapping
question with it.

**THE L4 PATH ALREADY WORKS ACROSS SIBLING USER NAMESPACES.** kern's peer relay forks two halves,
each entering only ITS OWN box, meeting on a socketpair inherited before either entered anything.
Neither half needs any capability over the other's namespace, so the sibling problem above does not
arise. That this holds is not an argument, it is the shipped `--no-pod` wiring: measured, two boxes
of one `--no-pod` stack sit in `user:[4026534370]` and `user:[4026536638]`, two different user
namespaces, and the relay comes up between them. Two projects are the same topology.

**A LATE JOINER CAN BE RESOLVED BY AN ALREADY-RUNNING STACK.** The remaining question was name
resolution: kern writes `/etc/hosts` when a box is created, and stack A is already running when
stack B arrives. Measured on a live box: writing `/proc/<pid1>/root/etc/hosts` from the host is
visible inside immediately, and `getent hosts` answers the new name on the next call. No DNS server
is needed for this, which removes the largest single piece of work the feature seemed to carry.

**WHAT REMAINED, AND IS NOW BUILT.** A network object with a lifetime of its own (`kern network
create|ls|rm`), an address plan shared across projects rather than per pod, and relays built in BOTH
directions when the second stack joins and removed when it leaves. Docker also requires such a
network to exist before a stack may use it, so the CLI gained a verb rather than inferring one.

MEASURED ON THE REFERENCE before the refusal was written, because kern's error message claims parity
with it (Docker 29.6.2, compose plugin v5.3.1):

```
docker compose config   renders the file, says nothing
docker compose up       network X declared as external, but could not be found
```

kern does the same, and its `config` says so in advance instead of leaving it to `up`.

**THE ADDRESS IS THE MEMBER'S IDENTITY ON THE NETWORK**: `127.1.<network>.<member>`, allocated when a
box joins and released when it leaves. Every other member binds it locally to reach that member, and
that member uses it as its own source address when it connects out. A per-joiner index would have
been unsound with three projects - box X would hold an alias numbered 1 written by B and another
numbered 1 written by C, for two different peers - so the number is a fact about the member, not
about the plan that referenced it. The `127.1` prefix cannot meet a stack's own peer aliases, which
are allocated in `127.0.0.2` through `127.0.0.254`, whatever either allocator does.

**END TO END**: two stacks, one network, `API-OK` read by the joiner from the incumbent and
`PROXY-OK` read by the incumbent from the joiner; after the joiner's `down`, the name it published
stops resolving in the other project's box and the network reports one member. The integration test
asserts all four and was checked against four mutations, one per direction, one for the teardown and
one for the refusal.

**AND ONE PREREQUISITE THAT WAS BLOCKING IT, NOW FIXED.** The relay wiring could not enter a box
whose service runs as a non-root user, which is precisely the reverse-proxy population this feature
is for. The cause was `PR_SET_DUMPABLE` (section 45), not the network.

## 45. A uid switch makes a box unreadable until it execs

```
same uid in both arms, nothing between them but the flag:
  dumpable=1   open /proc/<pid>/ns/user   OK
  dumpable=0   open /proc/<pid>/ns/user   Permission denied (errno 13)
```

A credential change clears `PR_SET_DUMPABLE`, and a process that is not dumpable has its
`/proc/<pid>/ns/*` refused to every caller, including the uid that owns it. `execve` recomputes the
flag from the new credentials, so a box that has STARTED is readable and a box that has switched uid
and not yet exec'd is not.

That window is exactly where kern's pre-exec gate holds every box, on purpose: no workload has run,
so no workload can observe a half-built network. A peer relay enters a box by opening those two
files, so the gate's correctness window was the window in which a non-root box could not be entered,
and a stack whose `networks:` segregate failed with an errno that pointed at the network.

The box now restores the flag immediately after the uid switch. The exposure is unchanged: the only
interval affected is the one in which kern's own setup code is the only thing running, and the
classic reason to leave a uid-changed process undumpable is a setuid `execve` afterwards, which
`PR_SET_NO_NEW_PRIVS` already makes inert here.
