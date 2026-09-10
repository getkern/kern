# Changelog

**CLI stability.** Since v0.7.0 the verbs, their flags and the `--json` shapes change incompatibly
only on a minor bump, never on a patch, and only after a deprecation entry here one release earlier.
`--json` is additive, so consumers must ignore unknown fields. A `cli_surface_is_frozen` test fails
the build on any undocumented change. Full detail for any entry is in the git history.

## Unreleased

**A health check runs AS the workload, not as the box's root.** Docker runs a `HEALTHCHECK` as the
container's user, measured rather than assumed (on Docker 29.6.2 a container started
`--user 1000:1000 -w /tmp` reports `uid=1000 gid=1000 groups=1000` and `/tmp` from inside its own
probe); kern ran it as box root, which is a false-green generator rather than a cosmetic
difference: the probe reads a file the service cannot, reports healthy, and
`depends_on: service_healthy` then releases a dependent onto a service about to die of `EACCES`. Not
hypothetical, it is this release's own Elastic stack, whose certificates are `root:root` mode 640.
The probe now drops to the workload's uid, gid and supplementary groups (recorded with the box) and
fails closed if it cannot: a probe that cannot reproduce the workload's identity must not report on
it. `kern exec` deliberately stays box-root, because it is the operator's door into the box and the
frozen CLI has no `--user` on it to get root back with.

**A health check runs where the workload runs.** Docker evaluates a `HEALTHCHECK` in the image's
`WORKDIR`, and a check is written by the same author, in the same file, as the command beside it:
Elastic's official compose file checks `[ -f config/certs/es01/es01.crt ]`, relative to
`/usr/share/elasticsearch`. kern passed no working directory to the probe, so every probe ran in `/`.
Measured with a discriminator: a box with `-w /etc` and `--health-cmd 'test -f hostname'` reported
`unhealthy` while the same box with the absolute path reported `healthy`, and a probe running `pwd`
printed `/`. On the ELK stack it cost the whole bring-up - `setup` stayed unhealthy with the
certificate present, and every service behind `condition: service_healthy` refused to start.

**`HOME` follows the user the box runs as.** kern exported `HOME=/root` for every box whatever user
it ran as, and that is not a cosmetic default: a Python console script installed with
`pip install --user` lives under `$HOME/.local`, so an image that puts its tools there loses them.
Measured on `apache/airflow:3.3.1`, whose passwd says `airflow:x:50000:0:…:/home/airflow`: `airflow
version` printed `ModuleNotFoundError: No module named 'airflow'` under kern and `3.3.1` under
podman. Four of Airflow's own services report unhealthy on that alone, because their checks all
invoke `airflow`. It is now taken from the image's own passwd entry for the running uid (`/` when
the image has no entry, which is runc's default user), as a default under both the image's `Env` and
an explicit `-e HOME=`.

**A workload gets the groups its image puts it in.** kern cleared the supplementary group set before
dropping to the workload's user. Measured against podman and confirmed on Docker 29.6.2, three
cases: an image whose `User` names
no group gets the memberships from its own `/etc/group`, one that writes `1000:0` outright gets
nothing added, and an explicit `--user 1000:1000` gets nothing either - which is runc's rule, not a
choice made here. It cost Elastic's Kibana: the certificates its `setup` service writes are
`root:root` mode 640, `root:x:0:kibana` puts Kibana in group 0, and with the set cleared it died on
`EACCES ... config/certs/ca/ca.crt` while the three Elasticsearch nodes, which have gid 0 outright,
were green.

**`localhost` no longer resolves to an address nothing is listening on.** kern's `/etc/hosts` put
`localhost` on the `::1` line as well, which is what Docker writes. With both records present musl
prefers `::1` and busybox's `wget` uses the first address only, so the name cannot reach an
IPv4-only listener. Measured on three runtimes with one image, an IPv4-only listener and the check
`wget -O- http://localhost:5000/` that compose files are full of: 0 under podman, whose hosts file
does not claim the name for `::1`; failure under kern; and failure under **Docker 29.6.2 as well**,
whose container has IPv6 enabled and `::1` on `lo`. kern now follows podman here, which is a
deliberate deviation from Docker in the direction that makes the check work. The IPv6 loopback keeps
`ip6-localhost` and `ip6-loopback`. See `docs/RUNTIME-PARITY.md`.

**A command run inside a box knows the box's name.** `kern exec` and every health probe ran with
`HOSTNAME=` empty while `hostname` printed the name correctly one command later, because the exec
path passes no name to the environment builder and the empty string was taken literally. Airflow's
scheduler check passes `"$${HOSTNAME}"` to `airflow jobs check`, which was then asking about a host
called "". It is now read back from the UTS namespace the process is already in, so it cannot
disagree with whatever set it.

**A privileged port is moved once for the whole stack, before anything starts.** The shift was
decided inside each box, which cannot see its peers. Measured on a two-service file publishing `80`
and `8080`: `web`'s 80 was moved onto the 8080 `other` had already bound, and `web` died with
`Address already in use` naming neither the move nor the service it collided with - and which service
died depended on which won the race. One plan over the union of the stack's ports cannot do that, and
`kern compose <file> config` now reports the same plan `up` will carry out. With
`privileged_port = "refuse"` the refusal also happens there, naming the service and its ports, rather
than one service failing after its peers have started.

**A refused `-v` says what is under the source.** A volume bind that the kernel rejects reported
`Invalid argument` and nothing else, on a path that exists and is readable. When the source has
filesystems mounted under it, the failure now names them and the reason: a recursive bind would put
those filesystems inside the box, and they belong to whoever mounted them rather than to this
workload. The explanation is selected by the evidence read back at failure time rather than by the
errno, so a kernel that reports something else does not turn the message into a false claim. The
reason given is deliberately not the `:ro` one this first shipped with (a recursive bind leaving
cloned submounts writable under a read-only volume): an outside reviewer pointed out that it expires
the moment anyone reaches for `mount_setattr(MOUNT_ATTR_RDONLY, AT_RECURSIVE)`, which has covered
submounts since 5.12, and an argument with an expiry date is the wrong one to put in an error
message.

**A moved privileged port says what it costs an ACME client.** Every other consequence of the shift
is visible to whoever typed the command; this one is not, because the party that cannot be
redirected is a remote certificate authority. When the moved set contains 80 or 443, the note now
says that a service issuing its own TLS certificates (Caddy's automatic HTTPS, Traefik with Let's
Encrypt) cannot complete an ACME challenge on a moved port. `docs/RUNTIME-PARITY.md` records the rest of the
comparison, including that podman refuses such a port outright where kern moves it.

**`kern compose <file> config` prints the wiring as a field.** The wiring is announced on stderr in
a sentence that names the alternatives, which is right for a reader and wrong for anything that
counts: the pod advisory recommends the bridge in those words, so a census keyed on `"on a bridge"`
counted every POD stack as a bridge and reported 60% bridge on a corpus that is 85% pod. It was
caught only by a count that refused to reconcile. Improving an advisory must not be able to move a
number, so `config` now also prints `wiring: pod|bridge|relay`, one token that says nothing else,
derived from the same two flags the bring-up carries. Prose for the reader, a field for whoever
counts, and never one read as the other. A second line, `wiring-source: auto|flag`, says whether kern
chose it or someone typed it: once a compose key can pin the wiring, the same token will also mean
"the file asked for this", and a file that keeps the pod on purpose is not the divergence a default
change would remove. The value `file` is in the vocabulary and not yet reachable, so adding it later
cannot change what the other two mean.

**`kern compose <file> config` answers the `ipv4_address:` question it used to leave to the bring-up.**
The key is how a whole class of files addresses its own services, and under the per-service wiring a
box claims only its OWN address: the service answers there and a peer connecting to that literal
address has no route to it. kern said so at `up` and nothing at `config`. Measured on the 240-file
STRESS corpus, which is where that shape lives (it was collected with searches aimed at the hard
side, so it is the right set for a regression gate and the wrong one for a rate): of the 30 files
kern wires with relays there, 20 pin a service with `ipv4_address:` and 16 of those got no word from
`config`. Now 3, and those three write `ipv4_address: ${VAR}` with the variable unset, so there is no
address to name and the unset-variable warning is what fires. On the neutral 259-file corpus the
same fix moves nothing, because only 7 files carry the key and the one that reaches this wiring
already had another difference. The sentence comes from
the same function the bring-up calls; only the wiring selection is repeated, because at that point
the file's wiring is known and a running stack's is not.

**A bridge stack is not told about relays it does not have.** The `--no-pod` notes describe peers
reached through per-service loopback aliases and two services sharing an internal port not being
mutually reachable; a bridge has neither property. They were keyed on "each service has its own
namespace", which a bridge also gives, so on Elastic's file kern announced the bridge and then, in
the next line, contradicted the one thing the bridge had just fixed.

**A `ulimit` the kernel will not raise costs headroom, not the whole service.** `memlock: -1` and
`nofile: 65536` are Elasticsearch's standard block and appear in thousands of compose files; a
rootless box cannot raise a HARD bound (that needs `CAP_SYS_RESOURCE` in the initial user namespace),
so the kernel answers EPERM and kern refused to start at all. Measured with OpenCTI's Elasticsearch
block verbatim: the box never ran. A refused RAISE is now clamped to the bound the box inherited and
the difference is named; a refused LOWERING is still a refusal, because a cap that does not bind is
the failure this check exists to prevent.

**A `networks.<net>.aliases` name resolves in every wiring, not only in the pod.** A service that
writes `aliases: [db]` is asking to be reachable as `db`, and a DSN written against that name is why
the key exists. The pod's shared hosts file carried the aliases; on a bridge and under `--no-pod`,
where each box gets `--add-host` entries instead, they were missing - so the same file resolved `db`
in one wiring and answered nothing in the other. Measured on a real dev stack whose postgres declares
`aliases: [db]`: `getent hosts db` answered in the pod and answered NOTHING on the bridge, and now
answers the service's bridge address from a peer and `127.0.0.1` from the service itself. An alias
that cannot be written into a hosts file is refused by name, like a service name.

**A service on the bridge reaches the internet, and has a resolver.** Every bridge member has its
own network namespace, so the pod's single NAT - which lives in the holder's namespace - is not
theirs; each needs its own. kern knew that and then excluded any service writing `restart:`, on the
reasoning that systemd starts those and cannot be held at the pre-exec gate. That reasoning is about
a STANDALONE box: a pod member is put on the in-process supervisor whatever systemd offers, because
it needs the holder's namespace, so it is held like any other. Measured on Sentry self-hosted, which
sets `restart: unless-stopped` on nearly every service: a member's routing table held the on-link
`10.89.0.0/24` and nothing else, there was no `/etc/resolv.conf` at all, and pgbouncer died inside
libevent's `evdns_base_new`. A member now has both routes - peers on the bridge, the internet through
its own NAT - and the resolver that comes with it.

**Compose reads its own variables from the project `.env`, not from the shell alone.**
`COMPOSE_PROFILES` and `COMPOSE_PROJECT_NAME` set there are what Docker calls loading that file
"for self-configuration": kern ignored both, so a project that ships its profile selection in its
`.env` had every profiled service skipped, with a message telling the reader to set a variable their
file already sets. Measured on Sentry self-hosted, whose `.env` opens with
`COMPOSE_PROFILES=feature-complete`: 28 of its 55 services were dropped. The shell still wins, and
`--profile` with it.

**A pass-through name resolves from the `.env` too, in `environment:` and in `build.args`.** Sentry
writes `SENTRY_IMAGE` under `build.args` and `SENTRY_EVENT_RETENTION_DAYS:` under `environment:`,
with the reason in a comment above the keys ("Leaving the value empty to just pass whatever is set on
the host system (or in the .env file)"). kern looked only at the shell, so the image was built `FROM`
nothing and Sentry's config died on `int("")`. A key with NO value is a pass-through (absent when
nothing is bound, as Docker does); a value that RESOLVED to nothing stays the empty string. The two
spellings are indistinguishable after interpolation, so the interpolator now marks the second.

**The wiring decision uses the port collisions kern already prints.** `up` warned "the images of
'postgres' and 'pgbouncer' both EXPOSE 5432/tcp; if both bind it the second fails at runtime with
EADDRINUSE" and then ran the stack in one shared namespace, where pgbouncer died of exactly that. An
image-exposed collision now selects the bridge, the same way a declared one does.

**`up <service>` no longer reports the services it did not start as dead.** The liveness check ran
over the whole file, so a selective bring-up that did exactly what was asked printed "N service(s)
died within 150ms of starting" and exited non-zero.

**A box name may be 200 characters, not 64.** `<project>-<service>` exceeds 64 on any real compose
project - `sentry-self-hosted-snuba-subscription-consumer-generic-metrics-counters` is 71 - and the
service simply refused to start. The new bound is derived from the longest name kern builds
(`kern-box-<name>-<pid>.scope`), which stays inside `NAME_MAX` and systemd's limit.

**A box that dies against its pids cap says so.** The kernel refuses the fork or the thread with
`EAGAIN` and the workload reports whatever it makes of that: ClickHouse aborts with "Couldn't get 512
threads from global thread pool", a sentence about ClickHouse's own settings, produced by kern's
default `--pids-limit` and mentioned nowhere. The refusal count comes from `pids.events`, so the
message claims only what the kernel counted, and it is appended to the box's log FILE rather than
written to stderr: by the time it runs the workload is gone and the reader of that stream can be
gone with it, and `SIGPIPE` is `SIG_DFL` in this binary - the message would then kill the process
whose exit it was explaining, replacing the workload's own code with 141. Measured before it was
believed: reproducibly at 28-way test parallelism, never below 8.

**A stack wired on the bridge no longer claims outbound it does not have.** The summary line printed
"services reach each other by name + outbound to the internet (pasta)" for a stack whose members have
no default route at all: a bridge member is not in the pod's namespace, so pasta's outbound is not
its outbound. Measured inside one: `ip route` shows the on-link `10.89.0.0/24` and nothing else, and
there is no `/etc/resolv.conf` - pgbouncer died in libevent's `evdns_base_new` because of it. The
line now says that, until a member gets a route out.

**A block sequence written at its key's own indentation is no longer dropped in silence.** YAML
lets the `-` sit at the key's column, which is what `docker compose config` prints and how a large
share of hand-written files look:

```yaml
    ports:
    - "8080:80"
```

kern's dedent rule popped the key's level when it saw an item at the same column, so the items
landed nowhere: `ports`, `volumes`, `environment`, `depends_on`, `command` and `healthcheck.test`
parsed as EMPTY, with no warning and exit 0. Measured on a 240-file corpus: 16 files write at least
one sequence this way (`volumes` 20 times, `cap_add` 14, `security_opt` 12, `devices` 11, `ports`
10), and every one of them was being counted compatible, because a rate that reads kern's own
silence cannot see what kern never noticed.

**`.env` values are interpolated, and `env_file:` accepts its long form.** Docker's rule for both
files is that unquoted and double-quoted values have interpolation applied; kern took them verbatim,
so a `.env` that builds one variable out of others - `ZBX_IMAGE_TAG=${OS}-${ZBX_VERSION}-latest`,
which is Zabbix's own - produced image tags no registry can answer for. Single-quoted values stay
literal, and a value that arrives from `.env` is still not interpolated a second time. `env_file:
[{path: …, required: false}]` now reads the path and skips a file that is not there, instead of
passing the whole `{…}` blob to the box as a filename.

**`--env-file` reads the same format `.env` does.** It was a second, cruder parser: split on the
first `=` and keep the rest, so quotes stayed, `export ` was not understood, `K: V` was not either,
and an inline ` # comment` arrived inside the value. Zabbix's `.env_srv` ends a line with
` # Available since 6.0.0`; `zabbix_server` refused to start on `invalid "NodeAddress" configuration
parameter`. One reader now, the compose crate's.

**`extends: {file: …}` - a service inheriting from another compose file - works.** It was a
refusal ("inline the base service"), which is the one thing a project cannot do when the base file
is the thing it maintains: Zabbix's stack is 17 services, every one of them an `extends` into a
sibling file. Merging follows the Specification rather than "the child wins on the whole key":
mappings merge, sequences append, `command`/`entrypoint`/`healthcheck.test` are replaced, and
`volumes`/`secrets`/`configs` are unique by target. That distinction is not academic - a service
that re-declares `networks:` only to add an alias was losing every other network the base put it on.
`depends_on`, `links`, `external_links` and `volumes_from` are not inherited, as the Specification
requires.

**A workload running as its own uid can reopen `/dev/stdout`.** A detached box's stdout is a pipe,
a pipe is born `0600` owned by the caller, and kern maps the caller to root inside the box - so an
image that runs as a non-root user could write to fd 1 but not reopen it. That is how essentially
every containerised web server logs: Zabbix's nginx frontend died at start with `open("/dev/stdout")
failed (13: Permission denied)` on every restart. The pipe is now openable by the box's own uids;
the log file on disk keeps its owner-only mode.

**A healthcheck written in Docker's exec form is run WITHOUT a shell, so an image that has none can
report healthy.** `test: ["CMD", "postgrest", "--ready"]` was joined into a string and handed to
`/bin/sh -c`; an image with no `/bin/sh` - PostgREST, distroless, `FROM scratch` - failed every
probe with `execvp: No such file or directory` and stayed `unhealthy` for its whole life, which is
precisely why such an image writes the exec form. A `depends_on: {condition: service_healthy}` on
it never resolved. The form now travels end to end: compose keeps it, `kern box --health-cmd-argv
<arg>` (repeatable) carries one argv element per flag, and the probe execs it directly. The shell
form (`CMD-SHELL`, a bare string, `--health-cmd`) is unchanged, and the two cannot be mixed on one
command line. Joining also lost argument boundaries: `["CMD", "sh", "-c", "echo a,b"]` used to run
`echo` with no operand.

**An image's own `HEALTHCHECK`, `Cmd`, `Entrypoint` and `Env` no longer lose `<`, `>` and `&`.** The
OCI config reader decoded `\uXXXX` in scalars and not in arrays, so Go's default HTML escaping -
which Docker writes into every image config - turned `>` into the letters `u003e`. Measured on
`supabase/postgres-meta`, whose image healthcheck is a JavaScript arrow function: kern ran a syntax
error every five seconds and reported the service unhealthy while its own `/health` answered 200.
An image already in the cache keeps the corrupted config until it is pulled again (`--pull always`).

**A secret can come from an environment variable, which the Compose Specification allows and kern
skipped.** `secrets: {db_pw: {environment: DB_PW}}` now lands at `/run/secrets/db_pw`; before, the
secret was skipped and the service read a file that was not there. `kern box --secret-env NAME`
takes the content from `KERN_SECRET_NAME` in its own environment, so nothing reaches `argv`, where
`/proc/<pid>/cmdline` would make it readable by every user on the machine.

**`--tmpfs uid=`/`gid=` are applied.** They were recognised and dropped. A user namespace accepts
only an id it maps, so a mount the kernel refuses is retried without the two and says which
happened: asking for an ownership kern cannot give costs the ownership, never the directory.

**A pod can be a BRIDGE, so each service keeps its own `127.0.0.1`.** `kern pod create --bridge
10.89.0.0/24` holds a bridge instead of a shared network namespace, and `kern box --pod-bridge
10.89.0.2/24` joins it with that address. A member then has the arrangement a Docker container has:
its own loopback, which no peer can reach, and its peers at their addresses. The shared namespace
stays the default and stays faster (measured: 3 ms a box against 23 to 36, which is what creating a
`veth` costs); the bridge is linear in the number of services, where kern's other private-loopback
wiring costs a TCP relay per ordered pair per port. `kern compose` does not choose it yet.

**`kern box --ip <addr>`, and with it `ipv4_address:` in a compose file.** A service pinned to an
address under `networks:` had that address exist nowhere: a peer that hard-coded it got no route,
and kern could only say so. The address is now claimed as a `/32` on the box's loopback, so the
literal address answers inside the stack. It claims one address, not a subnet, and adds no route
out. Additive: no existing flag or output changed.

## v0.9.32 - 2026-09-09

**A published port now binds `0.0.0.0`, not `127.0.0.1`. Read this one.** `-p 8080:80` and a compose
`ports: "8080:80"` bind every interface, which is what Docker does and what a file written for Docker
means. Until now kern bound loopback and warned, so a stack that looked published was reachable only
from the host. `[kern] publish_bind` in `kern.toml` is a ceiling no file can widen, and an explicit
`127.0.0.1:8080:80` still means loopback.

**Docker Compose compatibility went from 14% to 94%**, measured before and after on the same neutral
corpus of 259 files, one per repository, sampled across 733 repositories: the share of files kern
runs with no behavioural difference from what the file says. What remains is dominated by keys asking
kern to be less confining than it is (`privileged: true`, `security_opt`) and by `network_mode: host`,
which one namespace per stack cannot express. The earlier "15% irreducible" was an artefact of a
corpus weighted toward those keys.

**Twelve compose keys stopped being warnings and became behaviour**, among them `mem_reservation`
(cgroup `memory.low`), `devices:`, `dns:`, `logging:`, `tty:`, `stdin_open:`, `secrets:` long syntax,
and an image's own `HEALTHCHECK` and `STOPSIGNAL`. A string `command:` is now an argv rather than a
shell line, a tagged block scalar folds, and an empty named volume is seeded from the image as Docker
does.

**`networks:` is a boundary, not a warning.** Under `--no-pod`, services with no network in common
cannot reach each other by name or by address, and `internal: true` is the absence of NAT rather than
a filter, so a published port does not open a way out. In a pod the two say something different, and
both are stated at bring-up. A key that is absent means the `default` network, which is 52 of 187
files rather than the 18 that name one.

**`${VAR:?message}` refuses the file instead of substituting an empty string.** A stack whose
password variable was unset started with an empty one.

**An image's file ownership survives the unpack**, so a service running as a non-root user can write
the directories its image gave it. A named volume inherits the image directory's owner and mode, not
only its contents, and `kern rmi` no longer reports a removal it did not perform.

**A service secret is written with the mode the Compose Specification mandates.** It was `0400` in a
`0700` directory, so no image running as a non-root user could read its own secret. `target:`, `uid:`
and `gid:` were read and dropped in silence; they are applied or named.

**`kern run` no longer pays for a systemd scope it does not need: 4.70 ms to 0.87 ms.** It bought its
caps with a transient `systemd-run --user --scope`, one per invocation; it now caps directly under
kern's delegated `kern.slice`, the way `kern box` already did.

```
                  median     p99      max
before             4.700    5.735   15.304 ms
after              0.870    1.267    1.487
```

The tail moved more than the median because a D-Bus round trip to a shared user manager is a queue.
Throughput at concurrency 200 goes from 86 to 4052 runs per second: a path that serialises on a
shared service gets worse as concurrency rises, and a benchmark at concurrency 1 reports that only as
"slow". Finding the delegated slice turned out not to be the same as being allowed to enter it:
cgroup v2 delegation containment needs write access to the `cgroup.procs` of the common ancestor, and
a host outside that tree gets the scope path rather than an uncapped run.

**`kern exec` stopped refusing where there was no cap to escape**, and its fail-closed refusal now
names both causes and the way through (`KERN_ALLOW_UNCAPPED=1`). A `--health-cmd` probe is never
refused. `kern exec` and every health probe now run with the image's environment rather than a bare
one, and `kern stop` sends the stop signal once instead of twice.

**`kern doctor` names the cgroup it probed** on every row that denies a cap, so the verdict can be
checked against `/proc/<pid>/cgroup` instead of taken on trust, and it asks about both directories a
box can be capped in. `kern inspect --json` gains `memory_max_enforced`, read back from the box's own
cgroup: `memory_max` is the value the box was started with, and on a host that caps another way the
two differ.

**A box's terminal has a name.** `tty` inside an alpine box printed "not a tty" while `isatty` said
otherwise, because the `-it` pair was allocated on the host and the box's private devpts does not
contain it. It is now allocated from the box's own devpts and the master passed back over a
socketpair, so both C libraries resolve it. Certified on Fedora 44, CentOS Stream 10, Rocky Linux
10.2, Debian 13, openSUSE Leap 15.6 and Ubuntu 24.04, three with SELinux Enforcing.

**CLI surface: six flags added, none changed or removed.** `--dns`, `--dns-search`, `--dns-option`,
`--log-max-size`, `--log-max-file`, `--secret-mode`. Additive, so nothing that runs today stops
running.

## v0.9.31 - 2026-09-09

**If you use `kern exec`, this release is the one that makes it obey the box's limits.** It did not.
A command run through `kern exec` was placed in the CALLER's cgroup, outside the box's `--memory` and
`--pids-limit`, and said nothing about it. Measured from the host by pid, with the box's own PID 1 as
the control and the exec'd process verified to be in the box's PID namespace:

```
box PID 1                  .../kern.slice/kern-box-<tag>-<pid>     capped
the kern exec'd process    .../app.slice/app-<the caller>.scope    the CALLER's cgroup
```

A fork bomb or a memory hog started with `kern exec` therefore ran without the ceiling the box was
given. Namespaces and seccomp always held; it is the resource cap that leaked. The placement now
happens BEFORE the namespaces are joined, which is the only order in which the kernel permits it:
afterwards the box's own cgroup is the root of its namespace and the common ancestor cannot be named,
so both `clone3(CLONE_INTO_CGROUP)` and a write to `cgroup.procs` answer ENOENT.

**The cost is real and is stated rather than hidden.** Placing before the `setns` means a
`cgroup.procs` write, which takes an RCU grace period: `kern exec` is back to 11.7-25.8 ms on a quiet
host against 1.7-2.2 without it. The faster path shipped in v0.9.3 was faster because it was not
applying the cap. `clone3(CLONE_INTO_CGROUP)` is still used where it is correct, on the box START
path, which places its child before entering any namespace.

**A command killed by the box's memory cap now says so.** `memory.oom.group` kills the whole box, the
exec'd command included, and it goes by SIGKILL, so the process that would explain it is the one being
killed. Before, the caller saw exit `-9` with empty stdout and empty stderr. A reporter now waits
outside the group and names the cause. The exit code is still `-9`: that part belongs to the kernel.

**A box whose registry record is lost stays visible.** kern's registry lives in
`$XDG_RUNTIME_DIR/kern/instances`, and `/run/user` is swept by `systemd-tmpfiles`, cleared on logout,
and deleted by anyone who reads it as scratch. The box does not care: it keeps running. Before, only
kern forgot, completely - the box vanished from `ps`, `kern stop <name>` answered "no running box",
and nothing could reach it again. `ps` now reads what the kernel still holds and names those boxes
with their supervisor pid on stderr, on hosts with a delegated cgroup and, through `/proc`, on hosts
without one. It does not invent a table row for them: there is no record, so there is no uptime, no
ports and no health to show.

**Multi-stage builds produce an image that runs.** `FROM <stage>` printed `built` and left an image
that failed at `kern box` with "no layers in manifest", because the final image rested on a stage's
overlay chain. The final image is now materialized, fail-closed. `COPY` also stopped flattening
directory modes: a rootfs shipping a 1777 `/tmp` or a 2755 setgid directory came out 0755, and the
program that needed it failed for a reason nothing in the Dockerfile explained.

**Compose reads files it used to refuse, and refuses files it used to accept in silence.** A
`command:` continuation line starting with `-` was read as a sequence entry, so `--source`, `-drive`
and `-netdev` broke a plain folded scalar; two real files from public repositories now parse. `!!str`
is accepted over a scalar and refused over a list or a map, where it used to be dropped in silence
and the box started with something else. `tmpfs:` has ONE grammar again: `kern box --tmpfs
/run:size=64m` used to fail on the exact spelling `kern compose` produced, while `/run:rw` and
`/run:exec` - both valid Docker - were read as sizes and refused. An IPv6 port refusal now names the
missing feature instead of suggesting a typo, and `/dev/shm` and `/dev/pts` say the mount is already
there rather than giving the generic refusal.

**`kern build prune` refuses arguments it used to ignore.** `kern build prune 0` was read as "keep
nothing", ran with the default 20, and reported "kept the 20 newest".

**Fixed, no interface change:** a memoised runtime path outlived the directory it named, so anything
that cleared `/run/user` left every later registry write in that process failing, for the life of the
process; the layer cache treated a sentinel without its directory as a hit, and the build then died
on a `mount(overlay)` ENOENT that named neither.

**Known and unchanged:** the resource caps are verified on one machine. CI does not start boxes, and
the second reviewer's host has no cgroup delegation, so `--memory`/`--pids-limit` enforcement has one
witness. The squash that `FROM <stage>` and `push` share loses hard links and fills sparse files.
Compose networks do not isolate services from each other: one stack is one namespace, and `up` says so.

## v0.9.3 - 2026-09-07

**If you run kern on Ubuntu 23.10 or later, your install needs one action.** That is not a new
feature, it is the answer to "why does no box start", and it is here rather than under new
capabilities because it is the entry a reader scanning for "does this release affect me" needs to
find. Those releases ship `kernel.apparmor_restrict_unprivileged_userns=1`, which permits the
namespace and refuses the rootless uid map, so nothing starts. kern now ships the profile:

```
kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null
sudo apparmor_parser -r /etc/apparmor.d/kern
kern doctor
```

**CLI, additive:** `kern doctor --apparmor-profile` writes that profile to stdout and exits without
running any check. It exists because the install line has to be runnable by the person reading it,
and a repo-relative `packaging/apparmor/kern` is not: the release tarball carries the binary alone
and `cargo install` copies one file, so most readers have no `packaging/` directory. The binary
carries the profile instead. Nothing is removed or renamed.

**What that file does NOT do**, because installing one into `/etc/apparmor.d/` on a program's
say-so deserves the sentence: it grants exactly one permission, `userns`, and confines kern in no
way at all. Not its paths, not its capabilities, not its syscalls. Removing it returns the machine
to its previous state. It is deliberately not a confining profile: kern's job is to confine the
workload, and a second weaker mechanism aimed at kern itself would mostly invite the belief that it
was doing something.

The third command is not politeness. AppArmor attaches at `execve`, so a kern already running when
you load the profile does not pick it up. Measured on Ubuntu 24.04 with the restriction left at 1:
without the profile no box starts, with it `kern box`, `kern pod create` and the full acceptance
matrix all pass, and the sysctl is never touched.

`kern doctor` prints that install line, names the path it is running from because AppArmor attaches
by path, and offers `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` only after it, with
its cost: that one lifts the restriction for every program on the machine and is lost at reboot.

**`kern doctor` said "ready" on a stock Ubuntu 24.04, where no box can start.** Its userns probe
called `unshare(CLONE_NEWUSER)` and stopped there. Ubuntu 23.10 and later ship
`kernel.apparmor_restrict_unprivileged_userns=1`, which PERMITS the namespace and refuses the
rootless uid map, so the probe succeeded on a host where the very command doctor then suggested,
`kern box hello`, failed. Ubuntu is the most common distribution kern is installed on and that was
its default state.

The probe now runs the sequence a box actually runs, in the same order: unshare, deny setgroups,
write the uid map. Measured on a stock cloud image, both directions:

```
default                       ✘ the namespace is allowed and its uid map is REFUSED - no box can start
                              not ready - 1 blocker(s)
apparmor_restrict...userns=0  ✔ enabled
                              ready - `kern box` will run here
```

The AppArmor line no longer hedges with "if boxes fail with EPERM". It reports what the knob is set
to and leaves the verdict to the check that measured it, so a host carrying the restriction with a
profile for the kern binary is told it is fine rather than warned at.

**On a host whose SELinux policy refuses pasta's netns watch, the pod's pasta no longer exits by
itself.** kern retries with `--no-netns-quit` there ([#6](https://github.com/getkern/kern/issues/6)),
and a pasta started without the watch does not notice the namespace disappear, so `kern pod rm` and
`compose down` are what stop it rather than pasta stopping itself. Nothing to do differently; it
matters if you run a mixed fleet, because the hosts that take the retry and the hosts that do not
now have two different pasta lifecycles, and only the first depends on teardown running.

**`stdin_open:` and `tty:` in a docker-compose.yml no longer produce an alarm.** They used to warn
"ignored (unsupported)" matched on the KEY rather than the value, so `tty: false` warned about
nothing and a working stack was told a feature was missing
([#7](https://github.com/getkern/kern/issues/7)). A compose service is always detached, so `tty:`
has nothing to act on and is silent; `kern exec -it <service>` gives a real PTY in the running box
when one is wanted. `stdin_open: true` still warns, because it is a real difference from Docker: the
service's stdin is at EOF rather than held open, so a program that blocks on it exits at once.

**The Rust test suite had never been built for aarch64, though the binary always was.** So every
"the tests pass" statement this project has made was an x86_64 statement, silently, for as long as
ARM has been a supported target. Two lines caused it, both in test code and both invisible on
x86_64-gnu: `pthread_t` is a `c_ulong` on glibc and a `*mut c_void` on musl, and the pointer form is
not `Send`; and `ioctl`'s request parameter is a `c_ulong` on glibc and a `c_int` on musl. It now
builds and runs on ARM: **577/577 on a Raspberry Pi 5 (kernel 6.6) and on a Jetson (5.15-tegra)**,
on the hardware rather than under emulation. Under `qemu-user` one `flock` contention test fails
reproducibly and passes six times out of six on the boards, so that red is an emulation artifact and
not a name-collision bug on ARM.

That is the largest instrument defect in this cycle: not a probe reading the wrong thing, but a
whole suite that was never executed on a target kern ships for.

**A refused netns watch is only fatal in newer passt, and where it is not there is nothing to fix.**
Read out of three installed binaries rather than inferred:

| passt | ships in | on a refused watch |
|---|---|---|
| `0.0~git20230309` | Debian 12 | `inotify_init(): won't quit once netns is gone`, and it keeps the NAT |
| `0.0~git20240220` | Ubuntu 24.04 | `netns dir open: %s, exiting` |
| `0^20250919` | Fedora 43 | `netns dir open: %s, exiting` |

So a Raspberry Pi on Debian 12 needs no retry and never could have: issue #6 cannot occur against
the tolerant build. The condition became fatal between March 2023 and February 2024, which is
exactly the range the retry covers.

**Fixed: `--memory` and `--pids-limit` reported "accepted but NOT enforced here" over a box capped
exactly as asked.** Reported on WSL2 and reproduced on a Raspberry Pi 5 and a Jetson Orin Nano,
where `--memory 256m --pids-limit 64` printed both notices while the box's cgroup held
`memory.max=268435456` and `pids.max=64`. The check was right and was asked in the wrong place. It
read `/proc/self/cgroup`, and on the systemd-scope tier that is the SUPERVISOR, which kern parks in
a sibling leaf so a whole-box OOM cannot take it with the workload. From there the walk goes to the
ancestors and never reaches the box's leaf, which is a sibling rather than a parent; the only
ancestor carrying a memory ceiling is the scope, deliberately set to the request plus kern's
supervisor headroom, so "capped at or below the request" was false by design. Both notices were
wrong on the whole of that tier, and on the direct tier the check never runs at all, so it had never
once fired correctly.

The same mistake had a second instance, found by adding one diagnostic line to the reproduction
script rather than by reading the code. The `KERN_NO_SCOPE` opt-out warned from a point BEFORE the
box exists, where whether the cap will bind is not yet knowable, on the belief that the opt-out
skips the box's own cgroup as well as the scope. It does not. On x86_64 that printed "accepted but
NOT enforced here" while the box held `memory.max=268435456` and a 400 MB load was killed with exit
137. The warning now comes from one place on every box path, after the caps are written, against the
box's own cgroup. The Raspberry Pi finding the opt-out warning was written for is unchanged and
still reported: measured on a Pi 5 and a Jetson, the opt-out leaves `memory.max` and `pids.max` at
`max` and a 400 MB load survives, and kern says so. The notice now follows the cgroup rather than
the code path.

The enforcement byte on `KERN_STARTED_FD` was already correct: it takes the box's directory
explicitly, for this exact reason. So an SDK reading the byte saw "enforced" while a human reading
stderr saw the opposite, in the same run. Both now read one binding, so they cannot disagree. If you
scripted around the false notice, remove the workaround; if you concluded your caps were not
working, they were, and `--memory 256m` was killing at 256 MiB throughout.

**Fixed: a box refused for running out of process slots was told to check user namespaces.** A
reviewer hit it with a tightened `ulimit -u`:

```
error: sandbox: fork(idmap helper) failed: Resource temporarily unavailable (os error 11)
hint: needs unprivileged user namespaces and a valid --rootfs directory
```

The message is exact and the hint names two things that are both already fine, because the code
could not have reached that fork otherwise. `EAGAIN` on a fork is a process-limit problem, and
`RLIMIT_NPROC` is per-UID and counted across the whole system, so another program owned by the same
user can exhaust it, and it counts TASKS rather than processes. That last clause is not a detail:
the reviewer who reported the hint then compared `ulimit -u` against a process count, got 10 against
149, and concluded the kernel was accounting something unobservable. Measured here, an x86_64 desktop
owned 208 processes and 1918 tasks and the limit at which a single fork began to succeed was 1932, so
against the task count the threshold IS the count. The hint now names `ulimit -u`, the task count and
`LimitNPROC=`. Every other setup failure keeps the hint it had. Same shape as the pull hints, which branch on the message
rather than on the variant for exactly this reason.

**`kern --version` now says which build it is.** It answered `0.0.0` for every binary not cut by the
release workflow, which is every binary anyone compiles from source, so two builds of the same tree
were indistinguishable. That is not hypothetical: during the work above, a binary built ten minutes
before the fix was compared against one built after and reported as if it were the same program. A
reviewer made the same point from the other side, noting that a test script had to print a
`sha256sum` to tell two builds apart, and that the workaround existed only because the binary could
not answer.

The version is still the tag and nothing is carved into the source. A release binary prints the tag
exactly as before (`kern 0.9.3`), because the workflow stamps `Cargo.toml` and that value passes
through untouched. A build from source prints `git describe` instead
(`kern v0.9.2-45-gf7622ee-dirty`): the nearest tag, the distance from it, the commit, and whether the
tree was dirty. Where git cannot answer, a source tarball or a vendored build, it falls back to
`0.0.0`, which is today's behaviour, so nothing regresses when the information is unavailable.

## v0.9.2 - 2026-09-06

**Cut for a defect the first person to try compose would hit.** A `docker-compose.yml` with ONE
service came up with no network at all, for the whole 0.9 line. The auto-pod was gated on two
services or more, on the reasoning that a pod's other job is letting services find each other and one
service has nobody to find; but the pod is also the only thing that attaches `pasta`, so a lone
service got no pod, no NAT and no `/etc/resolv.conf`.

It does not present as a missing network, which is why it survived: the image ships its own
`resolv.conf` and it looks healthy, so the failure surfaces as `Could not resolve host` and every
diagnosis goes after DNS. `curl http://1.1.1.1` from inside the box failed in **0 ms**. There was no
route. Reported from a Mac running Lima with a Fedora guest, but the platform was never the variable:
reproduced on x86_64 Linux with pasta installed, changing only the service count.

**Every compose test in this repo ran three services, which is how it shipped.** The single
`services:` in the Rust suite points at an unreachable registry and never starts a box, so the
one-service path had no coverage anywhere. `scripts/acceptance-matrix.sh` now has a case for it, with
its two new assertions exercised in `--self-check` including a negative control on the pre-fix
summary line. The case goes RED on the v0.9.1 binary and green here, confirmed by an external
reviewer on their own host rather than only here.

### Fixed

- **A one-service compose stack had no egress.** The auto-pod condition tested a service COUNT while
  the property it stood in for was "does this stack need a managed network". It now creates a pod
  whenever any service is not on the host net, which is what the comment above it always said it did.
- **`kern pod ls` and `pod ls --json` reported double the members.** They counted lines in the pod's
  shared `hosts` file, and a compose member writes two of them (the qualified `<pod>-<service>` and
  the bare alias) while a `kern box --pod` member writes one. Measured on the shipped v0.9.1: 1, 2 and
  3 services read 2, 4 and 6, while `kern ps` read 1, 2 and 3. Both now read the registry `kern ps`
  reads, scanned once rather than per pod. The two views had been unified so they could not disagree;
  they could not, and both were wrong, while a third reader had the right answer.
- **`compose up` never said whether the stack had egress**, only that services could reach each other,
  so a stack with internet and one without printed the same sentence. On a reused pod that line is the
  only one printed. It now names the state, and `docs/DOCKER-COMPAT.md` lists all five instead of two.
- **`restart:` in a pod does not survive a reboot, and now says so.** A pod member is supervised
  in-process because a systemd unit that outlives the pod holder cannot re-join its namespace. The gap
  predates this release and reached only multi-service stacks; the auto-pod now reaches one-service
  stacks, so `up` prints a note instead of trading reboot-survival in silence.
- **`has_outbound` answered from `resolv.conf` alone.** Kill `pasta` while the holder lives and the
  file stays on disk, so the predicate reported egress for a pod with no route. It now also requires a
  live pasta, verified by `comm` because passt re-execs into an ISA variant and a pid can be reused.
  Found by an external reviewer reading the diff, not by a test here.
- **`kern killall --help`, `kern down --help` and `kern logout --help` printed the whole 184-line
  reference.** The per-verb match read only the first token of each line, and those three are
  documented as the second half of a pair. The test that missed them named fifteen verbs by hand; it
  now reads the list out of the reference, all 51.
- **Nine `kern --help` lines sat outside the description column**, `pod` by twenty because it did not
  fit; `pod` is two lines now. 76 verbs and 83 flags either side, checked by diffing both sets.
- **A damaged image-cache entry was repaired in silence under an SDK.** v0.9.1 gated kern's progress
  on a terminal and took the two repair lines with it, so in a pipe a cached image with no usable
  rootfs, or with no config, was re-fetched with nothing said. They are `kern: note:` now and reach a
  pipe; the ordinary "not cached, pulling once" stays gated. Found by
  `pentest/pentest-cache-edge.sh`, which asserts kern names the missing part.

## v0.9.1 - 2026-09-05

**Faster than v0.9.0 on a bare box start**, 2.300 ms against 2.346 in 21 of 24 paired batches, with
the OOM fix kept. The supervisor's sibling cgroup is created only where it is needed, a scope or
managed unit whose own cgroup is the one armed with `oom.group`: 0.165 ms back, 24 of 24, re-checked
in both layouts on four hosts and four systemd versions (249, 252, 255, 257).

**Cut for one defect the released binary had on most hosts.** `--egress-allow` in v0.9.0 could start
a box against a proxy nothing could reach, and on three of five hosts the pump never got the port
(`cannot bind 127.0.0.1:3128 in box: Address not available`). The pump now raises the box's loopback
itself and refuses to serve if it cannot, so readiness means reachable rather than bound. Reproduced
on an Arduino UNO Q and a Jetson Orin Nano with the shipped v0.9.0 aarch64 binary.
`scripts/acceptance-matrix.sh` exercises it, and says so instead of printing a tick on a host where
it cannot tell the fix from the defect.

### Fixed

- **The MCP server offered a language and then refused it.** The `run_code` schema advertised `sh`
  while a hand-written guard did not. The guard is the schema's list now, and a refusal names the
  accepted values.
- **`kern_execution_policy(cap_drop=("ALL",))` disabled the drop it asked for**, comparing a tuple
  against the string `"ALL"` and producing `drop_all_capabilities=False`. Only exact images convert;
  anything else raises and names the field to set.
- **kern's progress output no longer reaches a pipe.** Nineteen bare `eprintln!` lines now go through
  `progress!`, which prints only when stderr is a terminal. Errors, warnings and `kern: note:` still
  reach a pipe, because that is where they must arrive. `scripts/progress-is-tty-gated.py` keeps it
  true; converting the sites by hand found fourteen and missed five.
- **Three diagnostics reached `code_stderr` as though the workload had printed them**, lacking the
  `kern: ` prefix, plus five `kern compose:` lines whose prefix matched nothing.
- **A cgroup probe printed systemd's bus error onto kern's stderr.** `systemd-run ... -- true`
  inherited its stderr, so on a host with systemd installed but not booted the box's stderr carried
  `Failed to connect to bus`. Both streams are null now; the verdict was never in the output.
- **kern's diagnostics no longer land in a model's context.** `code_stderr`/`codeStderr` is stderr
  without kern's own lines, `runtime_notes`/`runtimeNotes` holds exactly what was removed, and
  `stderr` still holds every byte in order.
- **`kern_execution_policy` accepts `Sandbox`'s vocabulary**, `timeout_s` and `memory_mb` beside
  langchain's `command_timeout` and `memory_bytes`. Passing both halves of a pair is refused.
- **The OOM message never printed when kern runs as root or on a host with no systemd**, which is
  where the cap is most likely to be the only thing between a workload and the machine. The counter
  was read by walking kern's own cgroup ancestors, and on the direct-cap path the supervisor sat
  inside the cgroup `memory.oom.group` was about to kill. Verified on four hosts.
- **The registry recorded the supervisor's cgroup for every box**, and `kern stop` writes
  `cgroup.kill` into the path it records, so a stop would have killed the reporter.
- **A `-v` volume is mounted `nosuid`**, `/workspace` included. A `:ro` volume still fails hard.
- **`/dev/shm` reports the size the box actually has.** Unsized, `statvfs` reported half the host's
  RAM: a box held at 512 MiB told every workload it had 15.6 GB.
- **A warm interpreter could not import anything the image ships.** The driver ran `python3 -S`, so
  `import numpy` worked on a cold `run_code` and raised in a kernel cell. Dropped in both bindings.
- **`kern-sandbox` 0.1.36 on npm could not be installed**, its `package.json` depending on itself.
  Fixed in 0.1.37 and deprecated on npm.

### Changed

- **`deps_readonly` defaults to TRUE**, so a cell cannot change what the next cell imports. The route
  it closes is bytecode: a `.pyc` is validated on the source's timestamp and size, so a rewritten
  `.pyc` with the header re-pasted ran on the next import, invisible to `result.files`. A run-time
  write into `.deps` now gets `EROFS`; `deps_readonly=False` restores the old behaviour. It costs
  nothing at run time, the setup box compiling before the mount closes.
- **A timeout reports `exit_code = 137` in Python**, not `-9`, matching Node, the CLI and docker.
- **`integrations/pi` declares `engines: node >= 22`.** Measured: 20.18.1 fails at import, 22.11.0
  runs all 165 assertions.

### Added

- **`kern box --shm-size SIZE`**, for a workload needing `/dev/shm` sized differently from `--memory`.
- **`prewarm=N` in both bindings**: ~1.6 ms per call instead of ~37.8, measured over ssh, without
  giving up the fresh box, since a prewarmed box serves exactly one cell and is destroyed. A slot
  refills in ~70 ms, so N is a burst budget rather than throughput. Default `0` in the SDK, `1` in
  `kern-mcp`.
- **Every box gets a writable `/tmp`**, 64 MiB of tmpfs charged to the box's own memory cap. Nothing
  in it survives a call. `security_profile="untrusted"` gets none, deliberately.

**kern-sandbox 0.1.41** is documentation only, no code change from 0.1.40: the two package READMEs
moved their operational tail to `SANDBOX-NOTES.md` beside each binding. **0.1.40** answers an external
audit of the SDK, the pi extension and the LangChain integration.
