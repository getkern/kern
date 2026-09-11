# Changelog

**CLI stability.** Since v0.7.0 the verbs, their flags and the `--json` shapes change incompatibly
only on a minor bump, never on a patch, and only after a deprecation entry here one release earlier.
`--json` is additive, so consumers must ignore unknown fields. A `cli_surface_is_frozen` test fails
the build on any undocumented change. Full detail for any entry is in the git history.

## Unreleased

**`compose exec`/`run` accept the `--` every Docker user types.** `kern compose f.yml exec -T web --
echo hi` tried to execute a file named `--` and died with `execvp failed: No such file or directory`,
while the same line without the separator worked, and `kern exec <box> -- echo hi` had always worked:
the two verbs disagreed with each other and with the reference, which accepts it and drops it. Found
by an external reviewer running the commands. Only a leading `--` is dropped, so a later one stays
with the command (`sh -c 'git log --'`).

**The help line for the default wiring described the old default.** It said the stack is split "only
when `networks:` separate two services", which stopped being true when the per-service namespace
became the default: a two-service file with no `networks:` key is wired on a bridge, and the help and
the runtime note said different things about the same stack. The behaviour is unchanged; the sentence
now states the rule the code applies, including the single-service and the segregated cases.

**`docs/INSTALL.md` names the Ubuntu 23.10+ userns policy where a Linux reader will find it.** It was
documented only inside the macOS/colima walkthrough, and only with the machine-wide sysctl. The
requirements section now carries both remedies, says which one is narrow, and states plainly that
both need root once: on such a host a user who cannot get root even once cannot run a box.

**`network_mode: service:X` gets the namespace it asks for, and the note says which one it got.**
The key is the tightest coupling compose can express - the service wants the named one's loopback,
its interfaces, its published ports and its route out, which is how a client is put behind a VPN
container. When the default wiring changed it regressed, and silently: MEASURED on a three-service
file, the stack was wired on a bridge, `client` came up on 10.89.0.3 with `vpn` on 10.89.0.2,
`nc 127.0.0.1 8080` from the client reached nothing, and the traffic the file put behind a VPN went
out directly. There WAS a warning, and it was the pod arm of the note - `every service in this stack
shares ONE network namespace` - printed one line under `wiring: bridge`. Two defects in one output:
a dropped key, and a sentence asserting the opposite of what happened.

A file that asks for a shared namespace now gets the pod, WHEN one can be built. It cannot when two
services collide on a container port, which is exactly the shape these files have (a client and the
VPN in front of it routinely declare the same port); forcing it there turned five real corpus files
into refusals, which the corpus gate caught, and Docker accepts them and lets the second bind fail at
run time. So the order is: honour the key when the wiring that honours it exists, otherwise keep the
bridge and SAY the key is not given. The note's arm is now chosen from the wiring the stack will
actually get, not from whether a pod object exists: a bridge-wired stack IS in a pod, which is why
asking that question printed the wrong arm.

**A pod holder stops holding when its pod stops existing.** A holder keeps one pod's user and net
namespaces alive and is addressed through the pod's directory; when that directory goes, nothing can
name the pod, join it or remove it, and the holder went on holding anyway - forever, with its `pasta`
beside it. MEASURED on the development machine: 140 orphan holders and 116 NAT processes, the oldest
alive for 5.8 hours, all from test runs that pointed `XDG_RUNTIME_DIR` at a temporary tree and
removed it without tearing the pods down. A user whose runtime directory is cleaned on logout reaches
the same state. The holder now polls for its own directory and exits when it is definitely gone, and
every uncertainty resolves to "keep holding": no recorded directory means the old `pause()` forever,
an unreadable directory is not a missing one, and absence must hold across two polls a full interval
apart so a rename is never mistaken for a removal.

AND ITS MEMBERS DECIDE, NOT ONLY ITS DIRECTORY. On a systemd host without `loginctl enable-linger`,
logind removes `/run/user/<uid>` on the last logout while leaving the user's processes running: the
directory rule alone would then release the namespaces of a stack that is still serving, turning
what used to be a logout a stack survived into a sixty-second fuse. The holder exists for its
members, so it asks the kernel whether anything else is in its network namespace and holds if
anything is. The orphan population this was written for has none, so it is still reaped.

**`down` stops a stack's NATs instead of deleting the files that identify them.** Teardown removed
the `outbound/` subtree with `remove_dir_all`, and that subtree is where each box's `pasta.pid` and
`pasta.id` live: the processes were never signalled and the only records that could find them again
went in the same call. It hid behind the healthy case - a NAT that keeps its netns watch exits by
itself, so repeated `up`/`down` cycles showed no drift - and leaked the other population: a host that
refuses the netns-directory open makes pasta fall back to `--no-netns-quit`, and that one waits for a
signal through the pid file that had just been deleted. 27 such processes were found on this machine,
every one from a box running as a non-root user, which is precisely where that open is refused.

`kern gc` reaps the rest: a `pasta` in kern's own directory layout whose watched namespace no longer
exists is terminated, which cleans debris left by any earlier crash. Three conditions decide a
victim, and a pasta whose namespace is gone is doing nothing for anyone by definition.

**A dependency cycle is reported in the file's own words.** `dependency cycle detected among:
fuzzc-06f7c969-a, fuzzc-06f7c969-b` named the boxes kern invented for a file that says `a` and `b`.
Both graph walks built that string separately; there is one function now, and it uses the service
name.

**A `services:` block of the wrong shape is named for what it is.** Written as a LIST - one of the
commonest ways a compose file is mistyped by hand - it produced no services, fell through to the
emptiness check and answered "`services:` is empty" about a file holding two entries. Measured on the
reference, `docker compose config` answers `services must be a mapping` for a list, a scalar and an
empty block alike; kern now says so too, adding the shape it actually found, and keeps its own more
specific sentence for the genuinely empty case.

**A compose refusal no longer ends with advice about the other file format.** Every compose error
printed ``compose: `[box.NAME]` tables with image/rootfs, command, depends_on``, which is kern's TOML
syntax: a refused `docker-compose.yml`, which is nearly every refusal, ended with instructions for a
language the reader is not writing. The hint now names both formats, and is suppressed entirely when
the message already carries its own repair - the rule the volume and OCI errors already follow.

**`kern ps` and `kern top` measure the NAME column instead of assuming it.** It was a fixed sixteen
characters. `ps` pushed every column after a longer name out of line; `top` truncated, which is
worse - a relay-wired compose stack rendered as `psbug-749cf899-f`, `psbug-749cf899-s` and
`psbug-749cf899-a`, three services told apart by one letter in the column whose only job is to tell
them apart. Both now size the column to the names in the table, floored at sixteen so short output is
unchanged and ceilinged at forty-eight so one pathological name cannot push STATUS off the terminal.
Names are never truncated: the name is what `kern stop` takes.

**The SDK's missing-binary error gives the command instead of a link.** `pip install kern-sandbox`
installs the wrapper, not the runtime it drives, and the moment a user meets that fact is this
exception. It answered with a repository URL; it now answers with the installer line the README leads
with, and says which of the two things was installed.

**`scripts/launch-dryrun.py`: the end-to-end rehearsal.** Ten real-world stacks (Postgres+Redis,
Node+Mongo, WordPress+MariaDB, two backends on one port, RabbitMQ, memcached, Adminer, a
`service_healthy` gate, a shared named volume, segregated networks) brought up for real, probed from
INSIDE each stack by reaching a peer by name, and torn down - with every phase bracketed by a census
of boxes, pods, NAT processes, relay directories, cgroups and host veth interfaces that must return
to exactly where it started. Plus Ctrl+C on an attached `up` through a real controlling terminal,
SIGKILL of `up` mid-bring-up, and the Python SDK with and without a binary on PATH.

**A network shared BETWEEN projects: `external: true` works.** A compose file declares it,
`kern network create <name>` makes it, and services of different files on that network resolve and
reach each other by name - the reverse-proxy pattern (Traefik or nginx in one stack, the applications
in others). A file naming a network that does not exist is REFUSED, which is what the reference does:
measured on Docker 29.6.2 with compose plugin v5.3.1, `up` answers `network X declared as external,
but could not be found` while `config` renders the file, and kern now matches both, naming
`kern network create` in the refusal. It was the largest remaining cause that was kern's to close: 13
files of 259 declared one, 9 with nothing else between them and a clean run.

IT IS RELAYS AND NOT A SHARED BRIDGE, because rootless Linux does not offer the bridge. Two refusals,
each checked against a control that rules out the tool: from the initial user namespace, joining
another holder's network namespace is EPERM (entering its user namespace first works); from inside
one pod's user namespace, creating a veth whose peer lands in a sibling pod's namespace is EPERM
(both ends inside one pod works). Joining a network namespace needs `CAP_SYS_ADMIN` in the caller's
OWN user namespace and placing a link needs `CAP_NET_ADMIN` in the one that owns the target, and a
sibling has neither. kern's peer relay needs neither, because its two halves each enter only their
own box - which was verified end to end before any of this was designed, with a hand-written plan
naming one box from each of two separately started stacks.

EACH MEMBER GETS ONE ADDRESS, `127.1.<network>.<member>`, allocated when it joins and released when
it leaves: every other member binds it to reach that member, and that member uses it as its own
source. A per-joiner numbering would have been unsound with three projects, and the `127.1` prefix
cannot collide with a stack's own peer aliases in `127.0.0.2`-`127.0.0.254`. A stack joining later is
wired into the boxes already running - relays into them, and their `/etc/hosts` written in place,
which was measured to be visible inside immediately and needs no resolver process - and `down` takes
both directions away again and leaves the network.

**A compose stack gets a network namespace PER SERVICE by default, which is what Docker does.** From
two services up, each one keeps its own `127.0.0.1` and they meet on the stack's bridge; a port a
service binds on its loopback is now private to it. The old wiring - one shared namespace for the
whole stack, where every peer could reach that port - is `--pod` and prints what it costs. A
single-service stack still gets the shared namespace, having no peer to be separated from, and a
file whose `networks:` separate two services still gets the relay wiring, because one bridge would
put them back on one network.

It was the largest remaining difference from Docker on the neutral corpus: 135 files of 259 carried
the warning and 101 carried nothing else, so the compatibility rate moved from 87 files to 188
(33% to 72%). The measured case for the pod was good and is kept in docs/RUNTIME-PARITY.md section
30 - 22 stacks read from inside, 2 loopback-only listeners, both nominal, 0 collisions - and the
default changed anyway: a runtime whose reason is confinement does not ship a boundary weaker than
the reference by default, and "nothing found in 22 stacks" is not "nothing there", since 94 of the
136 affected files could not be started from that corpus at all.

**The bridge stopped costing 30 ms a service.** It cost +239 ms on an eight-service stack and costs
+27 ms now, and neither cause was the bridge:

  * A veth end MOVED between network namespaces waits a full RCU grace period in the kernel, 14-22 ms
    measured against 1-2 ms to create the peer directly inside the target namespace by naming it in
    the CREATE message. kern moved it, once per service. A bridged member went from 16-30 ms to 5-6,
    against a pod member's 4. A kernel that ignored the attribute would leave the peer behind and the
    member would fail to start, so the fallback checks by LOOKING rather than by the return value,
    and was verified by deleting the attribute: the stack still comes up, 20 ms a service slower.
  * Every NAT was attached one at a time, about 17 ms each, inside the loop that releases services in
    dependency order. They do not depend on each other - every box is prepared and held at its
    pre-exec gate before any is released - so they now run concurrently, before the first release.
    The ordering guarantee is unchanged and stronger: no service is released until every NAT is up.

Eight services on a bridge with no NAT at all (`internal: true`) come up in 173 ms against the pod's
171: the bridge itself was free, and the two serial waits were the whole bill. `scripts/wiring-cost.py`
takes the number, paired and alternated, and refuses to conclude on a loaded machine or when a sample
did not actually bring the stack up.

**The compatibility rate now reports the rootless port floor as a second MEASURED number.** 198 of 259
on this host, 222 of 259 in a network namespace whose `net.ipv4.ip_unprivileged_port_start` is 0,
which is one `sysctl` on a real host. The 22 files between them publish a port below 1024: rootless,
the kernel refuses the bind, so kern moves the port and says so, podman refuses it outright and names
the same sysctl, and Docker binds it because it is root. It is measured by re-running the whole
corpus in that namespace rather than by subtracting a cause from the first number, because a derived
figure printed beside a measured one is how this project has produced wrong numbers before, and
because the subtraction assumes the causes are disjoint - which the second run is what checks.

**The relay wiring reaches into a service that runs as a non-root user.** It could not, and the
message blamed the wrong thing: a stack whose `networks:` segregate died with
`peer relay: binding 127.0.0.2:5432 inside the calling box: errno 13`, and nothing had been bound.

THE CAUSE, measured with a positive control that changes nothing but the flag: a credential change
clears `PR_SET_DUMPABLE`, and a process that is not dumpable has its `/proc/<pid>/ns/*` refused
EACCES to every caller, including the uid that owns it - `open ns/user` answers OK at `dumpable=1`
and `Permission denied` at `dumpable=0`, same uid in both arms. A relay enters a box by opening
exactly those two files, and it does so while the box is HELD AT ITS PRE-EXEC GATE, which is after
the uid switch and before the `execve` that would put the flag back. The window the gate creates for
correctness was the window in which the box could not be entered.

The box now restores the flag itself, immediately after the uid switch. That gives nothing away:
`execve` recomputes `dumpable` from the new credentials a moment later, so the only interval this
changes is the one in which kern's own setup code is the only thing running; and the classic reason
to leave a uid-changed process undumpable is a setuid `execve` afterwards, which `PR_SET_NO_NEW_PRIVS`
already makes inert - the same reasoning this tree records for the `nosuid` remount being defence in
depth rather than load-bearing.

Found on `khaanh112/SkyTimeHub`, the only image-only file in the 259-file neutral corpus that kern
wires with relays: it was the entire runnable sample of that wiring, and it was failing. It now comes
up with all four services and the non-root service reaches its peer by name, three runs out of three.

**And the relay says which step failed when one does.** The status pipe carries the step in the sign
of the value it already sent, so entering the box and binding inside it are no longer reported with
one sentence and an invented errno.

**An anonymous volume in LONG form is mounted, not dropped.** `{type: volume, target: /app/node_modules}`
with no `source:` is the same request as the short `- /app/node_modules`, which kern has honoured
since it was measured breaking a real project: Docker makes a fresh volume, names it itself and
reuses it for that service and path. The long form was skipped with a warning, which is the one
outcome the file cannot mean - the mount exists to stop a bind mount of the project directory from
hiding what the image built, so dropping it hands the service the empty directory it was written to
avoid. Both spellings go through the same naming function, so a file that switches between them gets
one volume and not two.

**`compose exec` runs the command instead of explaining where to run it.** It used to be read as a
service name ("no service 'exec'"), then as a Docker verb kern does not have ("run
`kern exec <box>`"): two wrong answers to the same question, because the reader knows `web` and not
`<project>-<hash>-web`, and looking the box up by hand is the step that sends people back to Docker.
It now resolves the service, refuses a stopped one by naming both `up -d` and `run` for a one-off,
and exits with the COMMAND's status: `exec -T a sh -c 'exit 7'` exits 7 here and under Docker
29.6.2.

**A reboot is named where it is decided, not discovered the next day.** A service with `restart:` in
a pod got a note that said it would not survive a reboot and offered only "run it as a standalone
box", which trades the pod away: no peer-by-name, no shared egress, `depends_on` stops meaning
anything. The note now prints the three commands that keep the stack, filled in with this project's
own unit name, and `doctor` says the other half: lingering being ON is necessary and NOT sufficient,
because nothing in the user manager starts a compose stack without the unit. Docker survives a
reboot because its daemon starts at boot and owns the containers; kern has no daemon, so the unit is
that job.

**`runtime:` is answered by its VALUE.** It is the only key the neutral corpus reports as
unimplemented, on two files, and both write `runtime: nvidia`. A generic "ignored (unsupported)" was
wrong twice: it said nothing about what would happen, and what happens is a CUDA or driver error
inside the service that reads as a broken driver on the host. `nvidia` now names the device-grant
path and predicts that failure; any other value is told that kern IS the runtime and cannot hand the
container to another one. The two are separate answers because they are opposite requests.

**A near-miss service key is named.** After `runtime:` was answered, ONE file was left in the
generic bucket and its key is `depend-on:`, a typo for `depends_on` that costs the file an ordering
constraint and that Docker ignores just as silently. A key one edit away from a known one now says
which, with hyphens and underscores folded first so `depend-on` reaches `depends_on`. The radius
stops at one edit: `enviroment` gets `environment`, `enviroments` gets nothing, and a key that is
nothing like ours gets no suggestion at all, because a suggester that reaches too far sends a reader
to change a line that was never the problem.

**A compose service got no swap, and that decision rested on a premise a third runtime disproves.**
`memory.swap.max = 0` was chosen as "stricter, and said so", believing a rootless runtime had to.
Measured on the same host: podman 4.9.3, rootless, gives `max` and `max` with no memory key and
`256m`/`256m` with `--memory 256m`, exactly as Docker 29.6.2 does. It did not have to. And kern's
own ceiling with nothing written is the HOST'S RAM, not a small number, so the box was never bounded
either: not strict, not Docker, and carrying no warning, which is the one combination this project
refuses. A workload that would have swapped and survived under both references was OOM-killed here.

Three rules now, each the measured behaviour of the two references: nothing written gets the host's
own `SwapTotal`, which is the same decision the build path already took; `mem_limit: 256m` alone
gets a 256m allowance, so a file tuned against Docker's 2x total keeps its headroom; `memswap_limit`
is untouched, since the parser already turns Docker's TOTAL into the v2 swap-only figure by
subtraction. A host with no swap gets no flag, because writing `0` would restate the defect.

The RUNTIME-PARITY row that read "kern deviates: STRICTER" is withdrawn rather than reworded.

**kern names the sysctl that keeps a privileged port where the file wrote it.** podman refuses the
same port with "you can add 'net.ipv4.ip_unprivileged_port_start=80' to /etc/sysctl.conf (currently
1024)", which tells the reader how to make their file work unchanged. kern moved the port and
offered only `privileged_port = "refuse"`: the two options it named were "different" and "broken",
and the one that gives the file what it asked for was missing. The floor in the sentence is read
from the host, so the number is this machine's.

**Three deviations that had no warning and were therefore not in the rate.** An outside reviewer
attacked the definition of the "no named difference" figure: it counts warning lines, and a
difference kern knows about but does not warn about is not in it. Three were found, measured, and
declared:

  * A service with NO memory key gets `memory.max` = the host's RAM and `memory.swap.max` = **0**,
    where Docker 29.6.2 gives `max` and `max`. The cap at host RAM is inert; the zero swap is not, a
    workload that would have swapped and survived is OOM-killed here. It has no warning because it
    applies to nearly every file.
  * A service running as `user: "1000:1000"` writes files a rootful Docker leaves owned by 1000 and
    kern leaves owned by **100999**, through the subuid range. Visible on the first `ls -la ./data`.
  * Nothing brings a stack back after a reboot: kern has no daemon, and `compose systemd` plus
    `loginctl enable-linger` is the path. Docker's daemon restarts its containers at boot.

The rate is now defined as "no difference BEYOND the declared deviations", and the declared list is
complete rather than partial. Counting the three per file instead would put a warning on almost
every file in the corpus and make the number describe nothing.

**`compose ps --format json` carries `Publishers`.** Measured shape on Docker 29.6.2:
`[{"URL":"0.0.0.0","TargetPort":80,"PublishedPort":18080,"Protocol":"tcp"}]`. It is the field a
script reads to find where a service actually answers, and on a rootless runtime that is the one
thing it cannot assume: a file that writes `80:80` is published on **8080**, and the field says so.
`Image`, `Mounts` and `Size` stay absent because the registry holds no value for them.

**The acceptance claim carries its corpus.** "No file Docker accepts and kern refuses" is true on
these 259 files and is not a claim about the class: kern refuses at `config` two mappings that share
one host port, which Docker accepts and fails at `up`, half-started. The 95% is ACCEPTANCE and not
execution: of 41 files taken further and started, 19 did not come up for reasons that are the
corpus's, not kern's.

**`scripts/build-corpus-census.py`** is the only way left to close the shared-loopback question, and
it is built rather than described. 83 of the 136 files that carry the note declare `build:` and say
nothing about their bind addresses: the address lives in the image's `CMD` or an application
default, so neither the file nor a cached corpus can answer. This clones the repository the corpus
filename encodes, builds, runs the stack and applies the SAME probe the image-only census uses
(imported, not copied, so the two cannot drift into measuring different things), and reports its own
denominator: a repository that is gone, private, fails to build or does not come up lands in its own
bucket and is never read as clean.

IT IS NOT RUN BY ANY GATE AND REFUSES TO RUN WITHOUT `--yes-build-foreign-code`, because building a
Dockerfile written by a stranger executes that stranger's `RUN` lines on the machine that runs it.
The plumbing is verified end to end on a synthetic repository that cannot be cloned, which exercises
every step except the build itself. Whether to point it at 83 real repositories is a decision for
whoever owns the machine.

**The wiring answer no longer depends on which images a machine happens to hold.** kern reads an
image's `EXPOSE` set to find two services claiming one internal port, and read it from the local
cache only, so the same file answered `pod` before a pull and `bridge` after one. `kern_oci` now
exposes `fetch_image_config`, which resolves the manifest through the SAME prologue `pull` uses
(the digest pin on a pinned reference, the exact-arch selection with no fallback, the verification
of the sub-manifest against the digest the index named: extracted without a line changed, so the two
callers cannot come to verify different things) and then fetches the config blob and stops. No layer
is downloaded and nothing is written to the image store, which would otherwise read as "this image
is present" to every other caller and fail the next `kern box --image` on a rootfs nobody extracted.

Measured over the neutral corpus: the files whose wiring was decided without reading an image go
from **90 to 2**, the two being images that cannot be fetched at all, and two consecutive runs now
produce identical numbers.

**The fetch is opt-in, and the measurement is why.** A config blob costs ~2 s per uncached image
when the registry answers and EIGHTY SECONDS for a two-service file whose registry does not resolve,
because the timeouts on that path are 10 s connect and 30 s total across several requests. A dry run
that can take eighty seconds is not a dry run, and Docker's `config` never touches the network. So
`config` keeps answering in 2 ms and declaring what it could not read, and
`KERN_COMPOSE_FETCH_IMAGE_CONFIG=1` buys the exact answer for callers that need it.
`compose-compat-rate.py` sets it, because a published number must not depend on a local cache. `up`
never needs it: it resolves its images through the ordinary pull path before deciding.

The answers are memoised in a directory of their own (`$XDG_CACHE_HOME/kern/expose`), holding port
numbers and nothing else, so a second `config` on the same file is offline. A pulled image always
wins over the memo, so a `pull` that changes what a tag means takes effect at once. The filename is
the reference with unsafe characters replaced, which is many-to-one, so each file carries the
reference it was written for and a read that does not match is discarded: a collision costs a
refetch, never a wrong answer.

**The first `up` on a machine that had never pulled an image could break the stack, and the second
one fixed it.** kern reads each image's `EXPOSE` set to find two services claiming one internal
port, and that finding decides the wiring. The read happens before anything is pulled, so on a cold
cache it finds nothing, the stack goes into one namespace, and a service that cannot bind dies.
Measured on two services sharing `memcached:1.6.34-alpine`, whose collision exists only in the
image and nowhere in the file:

```
cold cache, up -d   ->  wiring: pod     ->  "1 service(s) died within 150ms of starting: a"
warm cache, up -d   ->  wiring: bridge  ->  both services up
```

The same command, twice, two outcomes. An outside reviewer predicted the shape from the `config`
behaviour and asked which side of the pull the decision falls on; it fell on the wrong one. The
verbs that are about to start boxes now resolve the images BEFORE deciding, which is also what
Docker does (measured on 29.6.2: every `Pulling` line precedes the first `Creating`). `config` is
unchanged and still a dry run that declares what it could not read.

**The collision axis of `loopback-census.py` was blind, and its zero meant nothing.** A collision is
a bind that FAILED, and the process that lost it exits, so it owns no socket: two services on
`0.0.0.0:7777` in one namespace leave ONE listener in `/proc/net/tcp`, indistinguishable from a
single service. The script had a positive control for the loopback axis and none for this one,
which is exactly the empty green this repo hunts elsewhere. It now reads the axis from the service
that DIED, through its own log, and carries four controls: a real collision is reported
(`nc: bind: Address in use`), the same stack on two different ports is not, a UDP listener on
loopback is caught (`/proc/net/udp` was not being read at all), and a bind that happens after the
settle is missed, which is printed as a bound on the claim rather than left for a reader to assume.
A settle was added for the same reason: `up -d` waits 150 ms, and a loser that binds two seconds
later was being called clean.

**`scripts/declared-bind-census.py`** answers the half no runtime census can reach. 94 of the 136
shared-loopback files declare `build:` and carry no context in this corpus, so they cannot run
here; what they DECLARE can still be read. On those 94: **0 declare a collision, 0 declare a
loopback bind, 11 declare `0.0.0.0` explicitly, 83 say nothing** and are only reachable by
building. Its own first defect is recorded in it: it reported a collision on a file kern correctly
wires as a pod, because the colliding pair sits behind a `profiles:` nobody enabled.

**`compose ps --format json` emits Docker's field names beside kern's.** Matching NDJSON and then
emitting `{"name": …}` would still break the line every deploy script contains,
`compose ps --format json | jq -r .Service`. The object now carries `Name`, `Service`, `Project`,
`State`, `Health`, `ExitCode` and `Command` alongside kern's lowercase keys: different spellings,
no collision, and neither consumer has to know about the other. `Image`, `Publishers`, `Mounts` and
`Size` are absent rather than invented, so a script reading `.Publishers[0]` fails loudly instead of
reading a zero.

**`compose config` was not a pure function of the file, and the rate inherited it.** kern reads each
image's `EXPOSE` set to find two services claiming one internal port, and that finding decides the
WIRING. It reads with `PullPolicy::Never`, so an image that is not in the local cache is not read,
and the same file answers differently either side of a pull. Measured on one corpus file, one
command apart:

```
image in the cache      config -> wiring: bridge
kern rmi <image>        config -> wiring: pod
```

Two files moved between the buckets of the published rate that way, silently, between two runs on
the same binary. Pulling to answer a `config` would be worse, so the dependence stays and is now
NAMED: `config` prints `wiring-images-unread: N (service (image), …)` and a note saying the answer
can change after a pull, and `compose-compat-rate.py` prints how many files of the corpus are in
that state. On the neutral corpus it is **96 of 259**, which is the bound on how reproducible that
rate is across machines, and nothing said so before.

**The third number: what the shared loopback actually changes.** The largest cause between the
corpus and a clean rate is kern's "services share 127.0.0.1" note, on 136 files, 107 of them
carrying nothing else. Two reviewers asked independently whether the wiring default should change,
and both answered that it cannot be decided until somebody measures which of those files are
actually affected. `scripts/loopback-census.py` measures it from inside the running stacks, on two
observables: a service binding `127.0.0.1`/`[::1]` only, which Docker keeps private and one shared
namespace does not, and a collision on a port no service declares, which Docker allows and one
namespace cannot.

Of the 136, 94 declare `build:` and cannot start from this corpus, which carries no build contexts.
Of the 41 image-only files, 22 came up. **2 of the 22 have services that bind loopback only**:
LinguaLeap on `127.0.0.1:9000`, kafka-cli-app on `127.0.0.1:9093` and `:9094`. Under Docker those
ports are private to their container; under one shared namespace every peer reaches them.

THE FIRST RUN OF THIS CENSUS SAID 0 OF 19 AND WAS WRONG, which is recorded here rather than
quietly replaced: that probe had no settle (a service that binds two seconds in was read as
clean) and no way to see a collision at all. The number is 9% of what could be measured, below the
10% and 15% thresholds two independent reviewers set for changing the wiring default and above the
zero first published. Against the cost as it stood then (about 30 ms a service, turning a flat
172 ms bring-up into 402 ms at eight services), it did not move the default. It says nothing about
the 94 `build:` files.

THE DEFAULT MOVED LATER ANYWAY, and this paragraph is kept rather than rewritten because the
reasoning is the record: the census was the case FOR the pod and it held. What changed was the other
side of the trade. The entry at the top of this section has the argument and the numbers, and the
cost it was weighed against is now +27 ms at eight services rather than +239.

**`up --exit-code-from <service>` and `--abort-on-container-exit`.** The CI line that turns a test
service's status into the job's. Docker's three cases, measured on 29.6.2 and reproduced: with
`tests` exiting 3, `--exit-code-from tests` exits 3 and leaves nothing running; the abort alone
exits 3 the same way; and `--exit-code-from db`, where `db` never exits on its own, exits **137**,
because the abort is what ended it. The logs stream while it waits, through the same multiplexer an
attached `up` uses, stopped at the FIRST exit rather than the last. A service the file does not
define is refused, as Docker refuses it.

**`down --remove-orphans`.** A service renamed in the file leaves its old box running, still holding
its published ports, and the next `up` fails on a bind conflict against something the file no longer
mentions. The scope is the project's POD, so another project's `db` is never in range however it is
named, and orphans are stopped BEFORE the pod is removed, because after that there is no membership
left to read.

**`compose ps -q`, `--services` and `--format json`.** The three spellings a deploy script reaches
for. `-q` and `--format` are threaded to `kern ps`, the renderer the compose view already shares, so
the two can never disagree about a column; `--format json` is mapped onto `kern ps --json` rather
than duplicated. `--services` answers from the FILE and not from the registry, which is Docker's
behaviour and the only useful one: the list a script iterates must not depend on whether the stack
happens to be up. The human-readable degraded-edge notes are suppressed under all three, since a
script parsing NDJSON must not be handed a sentence.

**`compose cp <service>:<path> <dst>`.** The same copier `kern cp` uses, with the SERVICE name
resolved to the box name it now has. That resolution is the point: a reader of a compose file knows
`web`, not `<project>-<hash>-web`, and looking it up by hand is the step that sends people to
`exec … | tar`.

### Corrected

**The v0.9.32 entry "Docker Compose compatibility went from 14% to 94%" reported the ceiling under
the definition of a different number.** That entry defines its figure as "the share of files kern
runs with no behavioural difference from what the file says". Measured today on the same neutral
corpus (259 files, one per repository), the same verb (`config`) and a binary proven to be the
current tree, that share is **35%** (91 of 259). The 94% matches the OTHER number the same
measurement produces, the ceiling: files kern accepts and could run clean if every named difference
were closed, today **95%** (247 of 259).

Both numbers, with the definition each one answers:

  * `config-accepted` (the ceiling): 247 of 259 = **95%**. The 12 it excludes are refused, and
    Docker 29.6.2 refuses all twelve, so this bound is the corpus and not kern's parser.
  * `config-clean` (no named difference): 91 of 259 = **35%**. The dominant cause is the shared
    loopback (135 files, 106 of them carrying nothing else).
  * `e2e-semantic` (observables inside live boxes): 7 of 7 probes.

The 14% is NOT reproducible: no corpus, verb or binary is recorded for it, and nothing in this tree
recomputes it. It is withdrawn rather than restated.

The released entry is left as it was, with one line added pointing here: a number corrected in place
in a shipped release is a worse record than one whose correction can be found from where the error
is. Both figures are produced by `scripts/compose-compat-rate.py`, which now refuses to run against
a binary that is not the working tree and fails when any warning it counts is unclassified.

**`compose run`.** The step 2 of nearly every project README (`run --rm web python manage.py
migrate`, `run --rm app npm test`), and the verb two independent reviewers each put first among
what kern was missing. It takes a service's definition, runs it once in the foreground with a
different command, and exits with THAT command's status: `run --rm web sh -c 'exit 7'` exits 7,
which is what a CI job needs to tell a failing test suite from a failing runtime. Measured against
Docker 29.6.2 and matching on all four observables: the service's environment and working directory
reach the one-off (`DATABASE_URL` and `/tmp`), its `depends_on` are brought up and nothing else is,
the exit code is the command's, and the service's published ports are NOT taken - the service's own
box may be holding them. The dependencies are started by re-invoking `up -d <deps>` rather than by a
second copy of the ordering rules, so `service_healthy`, profiles and pod creation cannot drift from
what `up` does. After `run <service>`, every remaining word is the command: `-c` in
`run web sh -c 'exit 7'` was a usage error before, and that is the exact line the READMEs use.

**`up --wait` and `--wait-timeout N`.** The CI pattern `up -d --wait && ./smoke`, without which the
smoke test races the healthchecks. Docker's four cases, measured on 29.6.2 and reproduced: a
service with a healthcheck must reach healthy (one that flips at 6 s returns at 6 s here, 7 s
there), a service without one only has to be running (returns at once), a service that has already
EXITED fails the wait even with status 0, and a check that never passes exits 1 at the timeout. The
default bound is kern's own condition timeout, the one `depends_on: service_healthy` already waits
under; Docker's default is unbounded, and a CLI that hangs forever is the one shape this cannot
take.

**`--build` is accepted and `--no-build` is refused, both for the same measured reason.** With the
Dockerfile edited between two runs, Docker without `--build` printed the OLD marker and kern printed
the new one: kern rebuilds a `build:` service whose context changed. So `--build` names what already
happens and is taken silently, while `--no-build` asks for the stale image kern cannot promise and
says so.

**`--no-deps` reaches `up`.** It arrived with `run` and was honoured only there, which made
`up --no-deps web` a flag that parsed and changed nothing, the defect class this codebase refuses
everywhere else. Measured once it was wired: `up -d web` starts two boxes, `up -d --no-deps web`
starts one. It is the flag in `up -d --no-deps --build web`, the redeploy line that must not restart
the database under the service.

**A workload's exit status is kern's.** `Error::Workload(code)` carries it to the one place that
maps a result to an exit code, so the command layer still returns `Result` and never calls
`process::exit` itself. It prints nothing: the command already said whatever it had to say.

**The regression gate was grading the wrong binary.** `compose-corpus-gate.py` preferred
`target/release/kern` and fell back to debug, while every edit-and-check cycle here builds debug, so
the gate that decides whether a change ships kept measuring a build from before the change. An audit
found SEVENTEEN scripts invoking a binary by a default path and exactly one checking that the binary
was current. The check now lives in `scripts/kernbin.py` and is shared by the rate, the corpus gate,
the wiring census and the e2e battery, and it is the build's IDENTITY rather than its date:
`kern --version` carries `git describe`, so the commit it was built from is compared with `HEAD`.
That catches what a timestamp cannot, and did while it was being written, a release binary a whole
commit behind `HEAD` with an mtime that looked perfectly fresh. Date is consulted only where the
hash cannot decide, for a build from a dirty tree.

**A skipped e2e probe counted as a pass.** The rate excluded skips from its denominator, so a host
where six of seven fixtures never came up printed `1/1 = 100%` and exited 0: the strongest false
green a battery can produce, because the number reads perfect exactly when nothing was measured.
Skips are in the denominator now and are red unless `--allow-skip` says otherwise. The self-test
also rejects a broken fixture that failed because the CHECK THREW: a probe that always crashed used
to satisfy "each probe can go red" while discriminating nothing.

**The 12 files kern refuses, Docker refuses too.** Measured on Docker 29.6.2, all twelve: three
YAML scanner errors, two `services must be a mapping`, two failed interpolations, and the rest
unparseable. The refusals are agreement, not a parser gap, so the 95% ceiling is bounded by files
Docker cannot read either. The rate says so instead of leaving it to the corpus gate.

**`up` deviates from Docker when stdout is not a terminal, and now says so.** Measured on Docker
29.6.2: `timeout 5 sh -c 'docker compose up 2>&1 | cat'` exits 124, a plain redirect exits 124, and
so does a run with stdin closed. Docker attaches whatever stdout is; only `-d` returns. kern returns
on a pipe, because `kern compose <file> systemd` emits a unit that is `Type=oneshot` +
`RemainAfterExit=yes`, which requires `up` to exit: a unit whose `ExecStart` blocked would sit in
`activating` until `TimeoutStartSec` and fail, taking every deployed stack with it. A note on stderr
now names the split, the generated unit spells `-d` so it no longer depends on any default, and the
decision is a function with a test on all four of its cases.

**The Docker-socket warning predicts where the failure will appear.** The service starts, reports
healthy if its check does not exercise the socket, and then fails in ITS OWN log with a connection
error that reads as a Docker problem rather than as kern's note. Measured on the 14 corpus files
that mount it: in 8 the socket-mounting service is the whole stack, in 5 more it is the front proxy
with a dependent, so the rest of the stack rarely survives it either.

**A named volume belonged to every stack that used its name.** kern mounted `data:/var/lib/x` at
`<volumes dir>/data`, with nothing in the path naming the project, so two unrelated stacks that both
declare the ordinary names - `data`, `db_data`, `pgdata`, `redis-data` - shared ONE directory.
Measured on both runtimes with the same two files, project A writing `/d/who` and project B reading
it: Docker 29.6.2 printed `EMPTY` and holds `pa_shared` and `pb_shared`; kern printed
`FROM_PROJECT_A`. Two Postgres stacks were sharing a data directory. Volumes are now named
`<project>_<volume>`, as Docker names them. A volume declared `external: true` keeps its name, since
the key means it exists independently of the project. Nothing is moved: a stack that already has
data under the old unscoped name gets a note with both paths and the `mv` that adopts it, because
two projects may hold data under one legacy name and no rule can decide whose it is.

**`docker-compose.override.yml` was ignored.** `docker compose` with no `-f` loads the override
beside the file it discovered; kern loaded only the base and said nothing, so a project's dev
overrides - source bind-mounts, debug ports, a different command - vanished in silence. kern now
loads it and prints the line that says so. Measured conditions, each against the daemon: an explicit
`-f` suppresses the override there, so does `COMPOSE_FILE`, and the override search is independent
of which base name was used (`docker-compose.override.yml` applies to `compose.yaml`). Passing two
files, naming a file Docker would not have discovered, or setting `COMPOSE_FILE` all keep the old
behaviour.

**An override that restated a port failed the whole stack.** `ports: ["8001:80"]` in the base and
again in the override is the most ordinary line an override contains, and kern refused it:
"publishes host port 8001/tcp more than once". Docker collapses a repeat, in one file and across a
merge alike - measured: one entry at `config`, and the stack runs. kern now collapses the same
three: an identical port appears once, two sources on one container path become the LAST source
(measured: `cat /data/f` prints the second file's contents under Docker), and a repeated environment
key becomes one entry, which is all a mapping could ever have expressed. The replacement keeps the
base's POSITION, so an override replacing `/data` cannot end up mounted on top of `/data/sub` and
hide it. Two mappings that merely share a host port are still refused: Docker accepts that file and
fails at `up`, half-started, with "port is already allocated".

**`compose logs -f` follows the whole stack.** It used to refuse more than one service ("follows ONE
service at a time"), on the belief that each needed a blocking reader. A log file never blocks, so
one poll pass reads them all; output is interleaved and prefixed with the service name, as
`docker compose logs` does.

**`-d` on `compose up` did nothing.** `up` always returned as soon as the stack was started, and
`-d` was accepted as a name for what already happened: measured by diffing the output of `up`
against `up -d` on one file, which differed only in a pid. `up` now streams the stack's logs and
stops it on Ctrl-C, like `docker compose up`, WHEN STDOUT IS A TERMINAL, and `-d` turns that off.
The terminal is the condition because the follow ends only when every service exits or a signal
arrives: every caller that redirects or pipes - a CI script, a systemd unit, the SDK - keeps exactly
the behaviour it had and cannot be left blocking on a signal it has no way to send.

**`compose down -v` removes this project's named volumes.** kern created named volumes and never
removed them, so a stack torn down and started fresh silently reused the previous run's data. The
flag was a usage error before. It deletes only sources that are NAMES, carry this project's prefix,
and are not `external: true`, and it re-checks that the path still resolves under the volumes
directory so a planted symlink cannot redirect a delete.

**A `docker compose` verb was reported as a missing service.** The parser takes the first bare word
that is not one of kern's verbs as the file and every later one as a service, so
`kern compose x.yml exec web sh` answered "no service 'exec' in x.yml" - a sentence about a service
the reader never wrote, for a verb they did. Twelve Docker verbs kern does not have (`exec`, `run`,
`kill`, `cp`, `top`, `stats`, `images`, `events`, `wait`, `ls`, `rm`, `create`) now name themselves
and the kern command that does the job, resolved down to the box name so it can be run as printed. A
service genuinely named `exec` still works, and a genuinely missing service is still reported as
one. Unknown FLAGS now name the flag too, instead of printing a usage dump that does not contain
it, and the dozen most likely Docker flags each say what kern does instead.

**`cpu_shares` produces the weight Docker produces.** kern mapped Docker's shares onto cgroup v2's
`cpu.weight` linearly on 1024, which agrees at the default and nowhere else. Ten points read off a
real daemon (Docker 29.6.2, cgroup v2): 512 -> 59, 1024 -> 100, 2048 -> 174, 65536 -> 3023. The
linear map gave 50, 100, 200 and 6400. The formula `1 + (shares - 2) * 9999 / 262142`, which two
independent reviewers and this codebase all remembered as runc's, gives 20 for 512 and 39 for 1024:
it was about to be shipped on that recollection, and the measurement stopped it. The curve is now
`ceil(100 ^ ((l - 1)(l + 126) / 1224))` with `l = log2(shares)`, which reproduces all ten points.
Where it bites is the mixed case real files are full of, one service with shares against a peer
without: Docker makes that ratio 1 to 5, the linear map made it 1 to 2.

**`memswap_limit` is a total, and cgroup v2's field is not.** Docker's key is memory PLUS swap;
`memory.swap.max` is swap alone, so the conversion is a subtraction. kern forwarded the value
verbatim, so a file asking for 256m of memory and 512m in total got 256m of memory and 512m of
swap - half again what it wrote. Six cases measured on Docker and now matched: the subtraction, the
equal case (no swap), `-1` (unlimited), and both refusals, `memswap_limit` without `mem_limit` and
`memswap_limit` below it. One row deviates on purpose: with no `memswap_limit` Docker allows swap
equal to the memory limit, and kern leaves it at zero so `mem_limit` is the total it appears to be.

**A teardown stops dependents before their dependencies, and waits.** kern signalled the whole stack
at once. Measured with traps that timestamp both the signal and their own exit, on `a` depending on
`b`: both fired in the same centisecond and the whole `down` cost 3011 ms, which is one trap and not
two. An application writing to a database was getting SIGTERM in the same instant as the database.
The teardown now walks the dependency levels backwards and waits for each before signalling the
next: the same file takes 6015 ms and `b` is signalled 10 ms after `a` has finished. A five-level
stack with a ten-second grace can therefore take fifty seconds to stop, which is what Docker does.

**An init that IGNORES the stop signal is given its grace.** kern skips the graceful phase when the
box's init cannot be terminated by the signal, which is what turns `kern stop` on a `sleep` box from
9 s into milliseconds: a PID-namespace init with the DEFAULT disposition never learns the signal
happened, because the kernel discards it. That shortcut was also being taken for an init that
IGNORES the signal, on the reasoning that both arrive at the same place and one merely arrives
later. Measured, and they do not: a box running `trap '' TERM; (sleep 2; write a file) & wait` - a
checkpoint wrapped against the signal, which is what `stop_grace_period` exists for - was killed in
6 ms with the file never written, and with the grace honoured stops in 1003 ms, EARLY, with the file
there. The wait is a poll on the pidfd, so it costs what the process needs rather than the whole
grace. `SIG_IGN` means the author was asked and declined; the default disposition means nobody was
asked, and only the second is a wait for nothing. The fast path for it is unchanged and asserted in
the same tests.

**`HEALTHCHECK` and `STOPSIGNAL` are baked into an image kern builds.** Both were parsed and
dropped, with a note telling the operator to pass `--health-cmd` by hand. That is unusable from
compose, where nobody types a `kern box` line: a service with `build:` whose Dockerfile declares a
check got none, and a peer with `depends_on: condition: service_healthy` on it could never be
satisfied, so kern refused the whole stack at config and the file did not run. Both now reach the
image config, with Docker's precedence measured in both directions: a compose `healthcheck:` or
`stop_signal:` overrides the image's, and without one the image's is used.

**The relay wiring says that it carries TCP.** A service that binds a UDP port without declaring it
got silence: measured, a datagram between two peers arrives in a pod and does not arrive under
`--no-pod`, and the only warning kern had was for services whose DECLARED ports are all UDP. The
wiring note now states the limit itself. In the same pass, `config` stopped saying a port is
"reserved in the pod" for stacks that have no pod.

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

**A peer resolves the name a service ANNOUNCES, not only the one the file writes.** A clustered
service does not publish the string in the compose file: it publishes what `hostname` returns, and
puts that in its membership state. Kafka writes it into `advertised.listeners`, a Mongo replica set
into `rs.initiate`, Redis Sentinel into its gossip, and every peer then dials the announced name.
Measured on a two-service stack where one writes `hostname` to a shared file and the other reads it
back: in a pod both the resolve and the connect succeed, because the pod's shared hosts file carries
an entry per box name; on a bridge the same file answered `NON-RISOLVE` and `nc: bad address`,
because the per-service entries carried the compose name and nothing else. The stack comes up, every
health check passes, and the cluster is dead at its first rebalance. Both the box name and the
service name now resolve in every wiring. Under the relay wiring the name resolves and the connect
still needs a DECLARED port, which the wiring note now states.

**A second number: `scripts/e2e-semantic.py`.** The compatibility rate is read from kern's warnings
at `config`, which makes it blind to everything that only exists once a box runs: the seven defects
closed this week moved it by zero points, and every one of them was found by running a stack and
looking inside it. The battery measures the other half with six probes, each an observable read from
inside a live box or from the timing of a real teardown: the health probe's identity and working
directory, `memory.max`, `ulimit -n`, the teardown order, a peer answered by name, and `HOME`. Each
probe ships with a BROKEN fixture it must report as failing, and `--self-test` runs them: a probe
that cannot go red measures nothing. That check earned its place immediately by catching a probe
reading the HOST's `$HOME`, because a single `$` in a compose file is a compose variable.

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
runs with no behavioural difference from what the file says. [CORRECTED: see "Corrected" under
Unreleased. 94% is the ceiling, not this definition, which measures 35% on the same corpus.] What remains is dominated by keys asking
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
