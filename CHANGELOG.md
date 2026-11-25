# Changelog

**CLI stability.** Since v0.7.0 the verbs, their flags and the `--json` shapes change incompatibly
only on a minor bump, never on a patch, and only after a deprecation entry here one release earlier.
`--json` is additive, so consumers must ignore unknown fields. A `cli_surface_is_frozen` test fails
the build on any undocumented change. Full detail for any entry is in the git history.

**Sandbox result stability.** In kern sandbox (Python, Node and `kern-mcp`), the `fault.type` and
`exit_code` an outcome reports change only to correct one that was reported wrong, and such a change
leads that release's entry, naming the outcomes it moves. kern sandbox 0.2.45 is the example:
`os._exit(N)` in a prewarmed box or a kernel stopped reading as `killed`, and a kernel timeout went from
-1 to 137. New `fault.type` values are additive, so code must treat a value it does not know as a fault
of the sandbox. A test fails the build when the set of values changes in one binding and not the other.

**Compose surface stability.** A compose key kern reads keeps its meaning: it changes only to correct
a mapping that was wrong, and such a change leads that release's entry, naming the key. Reading a key
kern ignores today is additive. A key kern does not read is never silent, with two deliberate
exceptions: `x-*` extension fields, and the keys Docker itself does not act on under Linux
(`cpu_count`, `cpu_percent`, `cpus_shares`, `isolation`). A test carries the frozen list of keys and
both halves of that rule, so removing one from the parser fails the build by name.

## Unreleased

**Breaking: `kern run` runs an image, as `docker run` does; what it did before is gone.**
`kern run [options] <image> [command...]` is `kern box` in `docker run`'s shape: the options are
`box`'s, the first other word is the image and everything after it the command, the name is
`--name` or one kern picks, and `kern container run` is the same verb. Capping a program of this
host with no container, what `kern run [options] -- <command>` did, is no longer kern's: it is not a
container and Docker has no such verb. systemd does it, and kern says so with the command written
for it: `kern run [options] -- <command>`, a path where the image goes, and a `kern run <word>` whose
image does not exist while `<word>` is a program of this host all answer `systemd-run --user
--scope -p MemoryMax=1G -p CPUQuota=200% -- <command>`. `--landlock-rw`, `--memory`, `--cpus`,
`--cpuset-cpus` and `vcpu:` profiles stay, on boxes. `kern top --json` is schema 2: its `runs`
object, the counters of that verb, went with it.

**Breaking: A box reaches the internet by default, as a Docker container does.** `kern run alpine wget
example.com` had no interface but `lo` and no `/etc/resolv.conf`; a box that names no network now
gets a NAT of its own (`eth0`, the host's resolvers), and so do `docker run` through kern's socket and
`--network bridge`. `--network none` is the box with loopback only it used to be by default, and
`network_mode: none` in a compose file says it. The NAT costs one pasta per box, about 11 ms of its
start (14.7 ms against 4.0 ms with `--network none`). A service the host binds to `127.0.0.1` stays
out of reach, by the gateway, the host's LAN address or `host-gateway`, as under Docker (measured with
a canary). The Python and Node sandboxes and the Rust `Sandbox` builder ask for `--network none` and
are isolated as before.

**Breaking: An OOM kills the process the kernel picks, and the box goes on, as under Docker.** kern wrote
`memory.oom.group=1` on every box, so an `exec` that ran out of memory took the whole box with it
(`exited`), where Docker's container stays `running`. That is now `--oom-group`, which the Python and
Node sandboxes pass, so their `oom` verdict covers every process of a cell as before.

**Breaking: A denied syscall answers `EPERM`, as under Docker, instead of killing the caller.** A box that
called a refused syscall (`unshare`, `mount`, `bpf`, `ptrace`, a namespace-creating `clone`) died with
`Bad system call` (exit 159), where Docker's answer is `Operation not permitted` and the program goes
on: a browser's or bubblewrap's sandbox probe, systemd's `bpf` probe and a debugger now report the
refusal instead of crashing. The set of refused syscalls is unchanged, and none of them ever runs.
`--security-opt seccomp-deny=kill` keeps the kill (so does `--security-profile untrusted`), `kern
exec` and health probes get the box's own verdict, and the Python and Node sandboxes ask for the kill
on every box, so their `escape_blocked` reads as before.

**Breaking: A box that names no memory is bounded by the machine, and swaps as Docker's does.** `kern
run`, `kern box` and `docker run` through kern's socket capped every box at 512 MiB with no swap, where
Docker sets no cap, and `kern compose` already gave the host's RAM: a database, a JVM or a build that
runs under Docker was OOM-killed at a number written nowhere. A box with no `--memory` now has the
host's RAM as its ceiling and the host's swap; `--memory M` alone allows M of swap, Docker's pairing
(measured: `memory.swap.max` 268435456 under `--memory 256m` on both engines); `--memory-swap-max`
sets it. The Python and Node sandboxes and the Rust `Sandbox` builder
pass `--memory-swap-max 0` and keep 512 MiB as their whole budget.

**A box resolves the host's search domains, as a Docker container does.** A box on the default
network, a compose service and a pod got the host's nameservers and not its `search` line, so a
short LAN name resolved under Docker and not under kern. The host's domains are the box's now, unless
`--dns-search` (or `dns_search:`) names its own.

**`docker inspect` says `OOMKilled` through kern's socket.** It was always false. A container whose
process the kernel's OOM killer ended reads true, and so does a running one that lost a child to it,
as under Docker; `kern ps --json` and `kern inspect --json` carry it as `oom_killed`. The verdict a
detached box recorded was the runner's latch read in the wrong process, so it was never set.

**kern's Docker API server survives a burst of clients.** 200 `docker run --rm` at once took it to its
file limit (systemd's soft 1024), and it exited on `accept failed: No file descriptors available`,
ending every request in flight with `EOF`. It now waits out a shortage of descriptors or memory with
the connections queued, and runs with its soft file limit raised to the hard one, as Docker's daemon
does; the boxes it starts keep the limit they had (soft 1024, as a Docker container's). Measured: 200
at once, three times, 200 of 200 in about one second, the same server, no box left.

**`kern run -d` prints the box's name, and `kern rm` only the names it removed.** `kern run` may pick
the name itself, and it was in a sentence on stderr only: `id=$(kern run -d nginx)` was empty where
`docker run -d` gives an id. The name is alone on stdout now, the narration on stderr; `kern box -d`
keeps stdout empty. `kern rm -f web` printed `stopped 'web' (pid N)` before `web`, a restarting box no
name, a kept box `removed kept box 'web'`: each is the name alone, as `docker rm` prints it.

**`kern top` shows what the new defaults change.** A box row says `oom:N` when the OOM killer ended a
process in a box that runs on, and `restarts:N` for a `--restart` box; the Overview counts how the
running boxes reach out (`3 nat · 1 none`) and names the Docker API socket and HTTPS; `--json` carries
`oom_kills`, `oom_killed`, `restarts` and `network` per box and a `services` object
([TOP-JSON.md](docs/TOP-JSON.md)). `kern info` said "on on port 8443" once HTTPS was trusted.

**A `--restart always` box can be created when its command exits at once, and removed.** `kern run
-d --restart always alpine false` (and `docker run` through kern's socket) failed with "the box unit
was installed but didn't start": systemd holds such a unit in `activating` between runs, which the
check read as a failure, and it left the unit behind, so the box came back after every `kern rm
-f`. The start is judged by systemd's state, a unit that did not come up is removed, `kern rm` of a
restarting box refuses without `-f` as Docker's does, and `kern rm -f` stops it for good. Between
two runs it lists as `restarting`, with systemd's count of its restarts, and `kern ps --filter
status=restarting` finds it. A kept one (every container
made through kern's socket) starts at once: the launcher held its layer, so the unit's first run
failed and ran a second later, and `docker run -d --restart always` took 1.4 s with a restart counted
that never happened (now about 190 ms and 0).

**A `--restart` box is one box from run to run, as a Docker container is.** Under `always` and
`unless-stopped` each run started from the image again, so a file the box wrote was gone at the
next run, and a box with no `--name` took a new name (`box-<pid>`) every time, listed beside the
name of its unit. The box is now kept: its name and its files carry over, `kern stop` then `kern
start` (or `kern restart`) brings it back with its policy, which `docker inspect` reports while
it is stopped, and `kern rm -f` removes the box, its files and its unit. Between two runs it is
up, as `docker ps` lists a `Restarting (1)` container: `restarting (1)` in `kern ps` without `-a`,
in `kern top` (with no pid, `null` in `--json`) and through kern's socket, where it was missing,
or `exited` for an instant. `kern rename` takes the box's earlier runs with it, records and logs.

**`kern rename` of a `--restart` box renames its unit, and does not stop it.** The layer took the
new name and the unit went on running the old one, so `ps -a` had two rows and the old name came
back from an empty layer. Between two runs the unit is moved to the new name; a running box keeps
running, and its unit is handed over to the new name when it next exits (a crash included). The
logs of every earlier run follow the name. `kern wait` and `docker wait` of a box that is stopped
or between two runs answer its last code at once, as Docker does (they refused, and the socket
said -1). A `--restart always` command may span several lines: the unit writes a newline as its
escape (it was refused).

**`kern inspect` reports a kept box, and its `-f` names the image as Docker does.** A box that is
stopped or between two runs is shown from its record (status, image, command, policy, restarts),
where it was refused. In `-f`, `.Config.Image` is the image's name and `.Image` its id; both printed
the box's scratch path. `.State.Restarting` and `.HostConfig.RestartPolicy.Name` are answered where
kern holds the policy (a `--restart` unit, a kept box's record), and refused elsewhere. `kern ps
--format json` prints Docker's line per box (it printed the word `json`), and `--format` says
`restarting` / `Restarting (1) ...` for a box between two runs.

**Fixes from the last mixed test round.**
- **`docker tag` cannot replace a kept box's image.** `docker tag` or `kern tag` onto a
  `kern-pin/` name answered 0 and replaced the image a kept box was created from, so the box then
  ran the other image. `tag`, `build -t`, `pull`, `load`, `commit` and `rmi` now refuse that name
  space, before anything is written.
- **Parallel `cp` of a stopped box.** Five `kern cp` of one stopped box at once now all succeed:
  each waits its turn for the box's layer. Four of the five used to answer "in use". The box kern
  starts for a copy also avoids a name a user box already holds.
- **Renaming a running box back.** A `--restart` box renamed while it ran can be renamed back
  before its next run; this used to answer "name already in use". Between the rename and that run
  it lists as restarting.
- **No failed units left behind.** `kern rm -f` of a box renamed while it ran no longer leaves a
  failed unit in `systemctl --user --failed`.
- **`docker update`** changes memory, the CPU limit and the pid limit through kern's socket. It
  answered 501 while `kern update` existed. A field kern does not change is refused by name.
- **`kern-mcp` honours `notifications/cancelled`.** A call cancelled while it waits behind another
  is not run and not answered; a running one finishes, but its answer is not sent.
- **A deeply nested compose value is refused.** A flow collection nested past 64 levels
  (`labels: [[[[...]]]]`) made `kern compose` allocate until it aborted, past 4 GiB in under a
  second. It is now refused by name, with its line.
- **`kern cp` of a stopped box, twice in a row, on WSL.** The second copy waited 20 s and failed "in
  use by another box": the box kern starts on the layer for a copy was not removed in kern's WSL
  distro. Five copies in a row now take 16-21 ms each there, and a copy is about 3 ms faster here.
- **`kern config set data_dir <path>` puts kern's data on another disk.** Volumes, kept boxes,
  builds, the history and the images (in its `cache/`) go there; `kern info` shows where. The
  directory is checked first, on the disk itself: yours, private, and keeping file modes and symlinks
  (a FAT or exFAT card is refused with what failed). Not while a box runs; what stays at the old
  place is said with the `mv` that moves it.
- **A box started from an ssh session or a WSL shell no longer makes a systemd scope.** From outside
  the systemd user manager every box asked for a transient scope, 17-23 ms on a VPS. kern now asks
  PID 1 to move it into its own unit once per box and caps the box there, as from a desktop session:
  on that VPS a default box 47 -> 39 ms, on WSL Ubuntu 38 -> 28 ms. Where that is refused, the scope
  is taken as before.
- **`kern top`: a box's log is live, and `s`, `p`, `u` act on that box from it.** Enter on the Boxes
  tab showed the log as it was when pressed, and any key closed it, so `s` pressed to stop the box
  only closed the log. It follows the output now, `s` asks to stop that box, Esc goes back.
- **`--log-driver journald`**, compose `logging: driver: journald`, the Docker API's `LogConfig` and
  `[kern] log_driver`: every line also goes to the systemd journal, tagged with the box's name, stdout
  as info and stderr as err; `kern logs` keeps working from the file. Refused where there is no journal.
  `kern info` names the driver, and as root suggests `/var/lib/kern` for a server's data.
- **Box logs are kept on disk, so a reboot keeps them**, as Docker keeps a container's: in the data
  dir's `logs/` (or `logs_dir`). An ended box's log goes after 7 days (`log_keep_ended`), a kept box's
  when the box is removed. A box started before the upgrade keeps its `kern logs`. Measured, a
  detached box's start pays nothing for it.
- **Compose: a volume's `driver_opts` are honoured, not ignored.** `type: none, o: bind, device: <dir>`
  put the data in a kern volume of its own while `<dir>` stayed empty; it is now kept there, as Docker
  keeps it. `type: nfs`, `cifs` and `tmpfs` mount as kern's `nfs://`, `smb://` and tmpfs; another
  driver or type is refused with what to write instead.
- **`kern run` prints nothing of its own for a box isolated as expected**, as `docker run`. A line
  still says so when a boundary is open (`--net host`, a shared rootfs); `--verbose` shows the panel.
- **Each part of kern's data can have a disk of its own.** `images_dir`, `volumes_dir`, `logs_dir`
  (logs then kept across reboots) and `history_dir`, set with `kern config set` or from `kern top`
  (Storage, `m`: what, then where), and one volume anywhere with `kern volume create <n> --path <dir>`
  (or Docker's `--opt device=<dir>`). `kern info` says where each part is.
- **`kern top` shows where kern's data is and moves it.** The Disk figure and the "Disk full" alert
  measured `/`, not the disk the data is on. Both follow `data_dir` now; the Storage tab names the
  place and its free space, and `m` lists the mounted disks (with what an exFAT card or a disk not
  writable by you would take) to move it to, asking first.
- **`kern top`: pasted text no longer answers a (y/n) prompt.** A command line pasted into top was
  read as keys, and `systemd` in it was `s` then `y`: the selected box was stopped. A `y` now confirms
  only when typed on its own, after the prompt.
- **A box starts as fast where kern's runtime directory is on a disk.** Ending a box synced its
  scratch layer's filesystem, a journal commit on ext4: a default box took 14 ms there against 3 ms
  on tmpfs. The scratch layer, thrown away with the box, no longer asks for that sync; a kept box's
  layer still does.
- **A box on the default network starts without waiting for its NAT.** A box that names no network
  now enters a network namespace kern prepared ahead, with pasta already up; it serves that box alone
  and goes with it. Measured, `kern run --rm alpine true`: 14.7 ms to 4.3-5.0 ms here (when boxes
  are 20 ms or more apart; back to back, half of them), 114 to 33 ms on a VPS as root. What the box
  sees is the same, compared line by line on four hosts. One is kept ready per user (an idle holder
  and its pasta, about 32 MB); `kern info` shows it, `KERN_NET_POOL=0` turns it off.
- **`kern stop` of a box that is already stopped** prints its name and exits 0, as `docker stop` does;
  it answered "no running box". A name that is no box at all is still an error.
- **`kern doctor` says when kern is not where the AppArmor profile looks**, and to copy it to
  `~/.local/bin/kern` first; it said "if that path is not in its attachment line".
- **`kern top` has one tab for boxes.** Its "Runs" tab counted the capped host processes of the
  old `kern run`, and beside "Boxes" it read as a second kind of box; it went with that verb. The tab
  bar falls back to the names with two spaces between them before it wraps.
- **`kern doctor` and the box panel say the network a box has.** The pasta row said a plain box is
  loopback-only, and `--verbose` showed "isolated (loopback-only)" for a box with a NAT; both now
  follow the default, as `kern info` already did. The config `kern config setup` writes shows
  `kern run vcpu:heavy <image>`.
- **A failed archive entry is named.** `kern cp -` and `docker cp` into a box name the archive entry
  that failed. The API answered 404 "Could not find the file" for a destination that exists; 404 is
  now only for a missing destination.

**`kern cp` and `docker cp` reach a kept box that is not running, and a kept box keeps its image.**
A box that is stopped, never started, or between two runs of its `--restart` policy was refused as
"not running", where `docker cp` copies into and out of a stopped container. kern now starts a box
on its layer for the copy, with no network, a PID 1 that runs nothing, and the box's own volumes,
so a path under an image `VOLUME` reaches the box's data. It takes about 15 ms. Its layer is held
meanwhile, so a run of the box cannot mount it at the same time. A kept box now runs the image it
was created from, as a Docker container does: when its tag is rebuilt or pulled again, its runs
and `cp` still use the old content. That content is kept as a pin, made with hard links (no data
copied) once per image and off the box's start path; the image list does not show it, and it goes
with the last box created from it. When that content is gone (`kern gc --images`), the box is
refused by name instead of putting its layer on another base.

**A container keeps the image id it was started from.** The id is recorded when the box starts,
so a rebuild of its tag no longer moves the id `docker inspect` and `kern inspect` report for a
box that still runs the old image, as Docker keeps it.

**`docker compose up --profile <p>` adds a service to a running stack.** A file with one plain
service and one under a profile got a stack without a bridge, and the later `up --profile` failed
to attach the second service. The wiring is decided on every service the file declares.

**`docker inspect` reports a container's image id.** `Image` in `inspect` and `ImageID` in the list
are the image's id, the `Id` `docker images` gives it; its name is `Config.Image` and the list's
`Image`. Both said the name. `docker inspect` of a name that does not exist ends with Docker's `no
such object`.

**`ptrace` works in a box.** `strace`, `gdb` and profilers failed with `Operation not permitted`
where Docker's and Podman's default profiles permit `ptrace`; a box permits it now, and the sandbox
SDKs, the MCP server and `--security-profile untrusted` still deny it (with the kill).
`process_vm_readv`/`writev` stay refused. A `kern exec` entering a box cannot be read or attached to
before its command runs.

**An image's `VOLUME` gets an anonymous volume.** A box wrote the image's declared volume paths into
its own layer: postgres's data, redis's `/data`, and docker-in-docker's `/var/lib/docker`, where
`dockerd` could not run `overlay2` and fell back to `vfs`. Now each gets a volume of kern's (unless
`-v` or `--tmpfs` covers the path), seeded from the image, kept across a restart and a `compose up`
recreate, removed with the box; `compose down` then `up` starts fresh, as under Docker (measured on
both). `kern build` records `VOLUME`, and `save`/`push` write it. An empty volume now takes the image
directory's owner from the box itself: a named volume's first start, and an anonymous one's, no
longer spends two helper processes on it (+2.0 ms to +0.4 ms over a bind, measured on redis).

**File capabilities survive pull, load, build and save.** They were stripped where setuid bits were
kept: Alpine's `newuidmap` is `cap_setuid=ep`, so rootless BuildKit stopped at "Could not set caps".
Kept in kern's cache (v3, inert on the host), carried through `kern build` (set after the owner,
which a chown would clear), and written as v2 by `save`/`push` (measured: an image kern built and
saved shows `cap_setuid=ep` under Docker). A cached image whose `newuidmap` lost its capability is
re-extracted once.

**`--privileged` runs a container runtime: docker-in-docker, BuildKit, a nested kern.** It relaxed
the seccomp filter and kept `CAP_SYS_ADMIN`, and docker:dind stopped at its first container: the
cgroup was read-only, `NET_ADMIN` was gone, runc found no sysfs to mount, no `/dev/tty` to bind, and
the keyring answered `EPERM`. A `--privileged` box now has every capability in its own user
namespace, a cgroup tree one level below its caps, a sysfs of its own, `/dev/tty` when its terminal is
its own or none, and the keyring refused with `ENOSYS`. The caps still hold and the host's devices
and kernel settings stay out (`pentest/pentest-privileged.sh`, 11 cases). A `kern exec` into it has
the box's capabilities. Through kern's socket `HostConfig.Privileged` is granted under
`compose_privileged`, and `inspect` reports it.

**A box behind pasta can forward TCP.** The old pasta sends a segment with no flags in the middle of a
connection; a socket's stack drops it, but connection tracking called it invalid, so a NAT in the box
(docker-in-docker's bridge) did not translate it back, the box answered RST and pasta closed the
connection. kern drops such a segment before connection tracking now, as every socket does.

**`docker compose` through kern's socket runs a service on several networks.** It was refused by
name, so a file with a `front` and a `back` network needed `kern compose`. A project's networks are now
bridges of one pod: a service on both reaches a peer of each (aliases included), a service on one does
not resolve the other's, an `internal` network does not go out, and `inspect` shows an address per
network. Measured on the same four-service file against Docker, with the same output. A running
container, or a network of another project, is still refused by name.

**`kern compat docker -- <command>` points programs that use the Docker API at kern.** It put kern's
`docker` first in PATH and nothing else, so Testcontainers, docker-py or the real `docker` by its full
path reached whatever Docker the machine had, or nothing. The command now gets `DOCKER_HOST` on kern's
API socket (a server is started for it when none listens), no `DOCKER_CONTEXT`, and the classic
builder (`DOCKER_BUILDKIT=0`) and Ryuk off unless already set: with buildx installed, the real `docker
build` builds through kern.

**`docker compose up --build` recreates a rebuilt service.** Through kern's socket an image's id was
derived from its name, so an image rebuilt under the same tag kept its id and compose left the old
container running the old build. The id is the image's content now (its config and layers), and a
rebuild is a new id. Ids of names one byte apart no longer share their first digits.

**`docker build` with buildx is refused at once, naming `DOCKER_BUILDKIT=0`.** With buildx installed
the docker CLI hands every build to it, and buildx pulled `moby/buildkit` (23 s, 230 MB) to run in a
privileged container this API refuses, then said only that. It is refused before the pull, saying
that `DOCKER_BUILDKIT=0 docker build` and `DOCKER_BUILDKIT=0 docker compose build` use the classic
builder kern's API serves.

**`docker inspect` reports the restart policy, and `kern save` takes several images.**
`HostConfig.RestartPolicy` was empty for every container; it is the policy the container was made
with, as Docker reports it. `kern save a b` and `docker save a b` write one archive with both images.

**A closed port is refused behind pasta, and a lost SYN costs one retry.** With the pasta Ubuntu
24.04 ships, a box's connection to a closed port waited for the client's timeout (`wget -T20`: 20 s;
Docker: refused in 311 ms), and a SYN the remote dropped cost two seconds instead of one, which bursts
of fast-starting boxes met often (23 of 300 fetches of example.com over 1.5 s). Two rules kern writes
in the box's network namespace mend both with any pasta: refused in about 1 s, a dropped SYN 1.0 s as
under Docker, a box's start unchanged. `kern info` shows them as `pasta tcp`, with the pasta's build date; `kern doctor` names a pasta older than 2025-02 and where a newer one comes from, and warns when it meets a kernel without nftables.

**A stopped box is not run again by its own restart policy.** A box whose `--restart always` its
supervisor keeps (a pod member: every compose service, and every container of kern's Docker API on a
network) ran again a second after `kern stop`; `kern restart` and `docker restart` then failed with
"already running", and the stop removed the scratch under the new run, which exited 125 at every
retry. The policy now asks whether a stop has begun before it runs the box again.

**`docker build` and `docker save` through kern's socket.** Both answered "not served". A build is
`kern build` of the context the client streams, with its tags, Dockerfile, build args, target,
platform and `--no-cache`, its lines as Docker's and the image's id at the end (`-q` prints it
alone); `docker compose up --build` builds through it. `docker save` is `kern save`, streamed, one
image an archive. `docker restart` publishes `kill die stop start restart`, once; a `--restart
always` container's watch added its own `start` after the restart's.

**`docker events` and `docker inspect` follow a `--restart always` container and a rename.** Such a
container's stream was `create start die destroy` while systemd ran it ten times, and it read
`exited`; it is a `start` and a `die` per run now, `restarting` between them, and visible from the
moment `docker run -d` returns (it was "No such container" for about a second). `docker rename`
publishes Docker's `rename` (`name` and `oldName`), and the renamed container's `die` comes under its
new name.

**`docker tag` through kern's socket, and image ids as short as Docker takes them.** `docker tag`
answered "not served by kern's Docker API"; it is `kern tag`, the source by name or id, another
platform's entry included (`kern tag --platform <os/arch>`). An image is found by name first and
then by a unique id prefix of two characters or more, as Docker finds one; it took twelve.

**A create through kern's socket takes the names Docker takes, and says what it changes.** A name
over 63 characters was refused (kern's own limit is 200, as `kern run --name` has it); a relative
working directory ran in the root where Docker refuses it, and now gets Docker's refusal; a hard
`ulimit` above what a rootless box can have is applied at that ceiling with a warning the client
prints, where it was lowered without a word to the client.

**`kern info` and `kern top` say what 0.57 changed.** `kern info` names a box's network (its own NAT
when pasta is here, loopback only when it is not), its memory default, whether the Docker API socket
is enabled and whether HTTPS for `.localhost` is on. `kern top` flags a box with its own NAT as
`net:nat`, as it flags `net:host`, so the boxes that reach the internet are told from a `--network
none` one.

**`kern cp` and `docker cp` into a box keep a sparse file sparse.** A tar carries a sparse file
whole, and its zeros were written out: a 1 GiB file with 1 MiB of data took 1 GiB on the destination,
as it does under Docker. A block of zeros is a hole now, so it takes the 1 MiB, with the same bytes.

**io_uring, userfaultfd, perf_event_open, the keyring, syslog and open_by_handle_at answer `EPERM`, as
under Docker.** They answered `ENOSYS`. They are still denied, and never kill under any verdict, as
software probes them at start; `clone3` keeps `ENOSYS`, which glibc needs to fall back to `clone`.

**A sandbox call that times out leaves no row in `kern ps -a`.** The Python and Node SDKs ended a
timed-out cell, a destroyed persistent sandbox and a killed kernel cell with `kern stop`, whose exit
record listed it as `Exited (137)` for an hour; a cell that ended by itself left nothing. They use
`kern rm -f`, the same teardown with the record removed.

**`kern logs` and `docker logs` of a restarted container show every run.** A `--restart always`
container systemd runs again (and any kept box) kept only its last run's log: six runs gave six lines
under Docker, one through `kern logs` and none through kern's socket. The earlier runs' logs stay,
the last 16 of them, and are read oldest first before the current one; `kern rm` takes them all.

**`docker run --gpus` through kern's socket, under the operator's GPU gate.** It was refused always.
It is `kern box --gpus` (`all`, a count, `device=`) when `allow_gpu_grants` or `allow_device_grants`
is set in your own `kern.toml`, the same gate `kern compose` reads, and refused naming that key
otherwise.

**`kern compat docker enable`: the Docker Engine API on a socket of this user, answered by kern.**
A `systemd --user` socket unit on `$XDG_RUNTIME_DIR/kern/compat-docker.sock` starts the server at the
first connection and lets it exit when idle (`kern compat docker serve` runs it in the foreground).
Testcontainers, docker-py and the `docker` CLI with `DOCKER_HOST` drive kern's boxes: create, start,
attached `run` with stdout, stderr and exit code apart, `exec`, logs, wait, stop, remove, pull,
inspect. Each request is a `kern` command; what kern refuses without a flag is refused by name, a
socket as a bind source (Testcontainers' Ryuk) is refused, and an endpoint not translated answers
501. kern removes a Testcontainers session's containers itself when the process that made them ends.
On Windows, `kern compat docker pipe` serves the same API on `\\.\pipe\kern-docker`, for this
account only, with no TCP endpoint. Testcontainers for Python (Redis and Postgres modules), Java
1.21.3, Node 12.2.2 and .NET 4.17.0 (from Windows) pass: log waits, `exec` exit codes, published ports, and an exited container
failing its start at once. The Dev Containers CLI, which VS Code runs, brings a container up from an
image and execs into it: `--mount`, `exec -i`, and `docker events` for the containers it makes. A
container keeps its filesystem until `docker rm` (a kept box), so the `docker start` of a reopen
runs it again on the same files; `--rm` containers and a Testcontainers run's stay in memory.

**`kern logs` and `kern attach` give a box's stdout and stderr apart when it recorded them apart**
(every container of kern's Docker API), as `docker logs` does, with `-t`, `--tail` and `-f`; a box
started with kern directly, which records one stream, prints as it did, and `--all` stays one
stream.

**`docker run -i` and `-t` through kern's Docker API work.** The stdin of `docker run -i` was
dropped in silence (`echo x | docker run -i alpine cat` printed nothing and exited 0) and `-t`
printed the stream's frame headers; such a run is now a foreground box with the client's stdin and,
with `-t`, a terminal. `docker ps -a` lists created containers, and those whose start failed, as
`Created`, so Testcontainers' cleanup finds them.

**`docker load` and `docker rmi` through kern's Docker API.** `docker load` was refused as "a
chunked body that does not parse" for any image over 4 MiB, the cap on a request body; its archive
now streams into `kern load` with no cap (7.8 MB in 51 ms), and a body over the cap elsewhere says
it is. `docker rmi` is `kern rmi`, `-f` included, an image a container uses answered 409. A command
that leaves its stdin unread (`head -c 20M /dev/zero | docker exec -i c true`) exits with its own
code, as with Docker; it ended the whole server with SIGPIPE, and then the connection was reset.

**`kern image history` and `docker history` list an image's steps.** Newest first, as Docker
lists them: a pulled or loaded image's own history, each step that made a layer with that layer's
compressed size from the manifest (what a pull downloads; kern unpacks the layers into one tree and
does not keep a layer's own size); a built image's Dockerfile steps over its base's, recomputed at
each build so a cached rebuild does not list them twice; a commit's step. `--no-trunc`, `-q` and
`--json`, and kern's Docker API answers `GET /images/{name}/history`, which the `docker` CLI prints
as its own. An image cached before gets its history at the next `kern pull` of it (measured: 1910 ms
the first time, from the manifest and a config of a few KB, 2 ms after). `kern history <image>`,
which dropped the name and printed the last boxes run, refuses the name and points at
`kern image history`; `kern history [-n N]` is unchanged.

**`kern save` and `kern push` keep the image's labels, exposed ports, stop signal, healthcheck and
history.** They wrote a config with the command, environment, working directory and user only, so
an image saved and loaded back (in kern or `docker load`) or pushed and pulled lost its `LABEL`,
`EXPOSE`, `STOPSIGNAL` and `HEALTHCHECK`: an nginx stopped with SIGTERM where it asks for SIGQUIT.
The image's steps are kept too, as metadata under the one layer kern writes, which podman and
buildah still take as the base of a build. A rebuild answered entirely from the cache keeps its
steps' times, so the same image saves and pushes under the same digest.

**`kern ps -a` lists a name once, its last run.** Each run of `kern box -d --name x` that ended left
its own exit record, so three runs listed `x` three times; a box that ends now takes the place of
the earlier runs under its name, and their logs go with them, as `kern rm` removes them.

**An exited box keeps its image and labels, and kern's Docker API reads them from kern.** A box's
exit record held its name, pod and command, so `kern ps -a --filter label=` matched no exited box
(kern said so) and kern's API kept what it knew of an ended `docker run` in its own memory, which a
server that restarts loses. The record carries the image and the labels now: `ps -a --json` lists
them for an exited box, `--filter label=` selects among exited boxes as among running ones, and the
API lists and inspects an ended container from kern's record, after a restart too (a test session's
container found by its label, its exit code and image). `kern ps --json` also gives a running box's
`image`, and `docker ps` shows each container's image (it showed `<no image>` for all of them).

**`kern kill` kills at once, as `docker kill` does, and `-s SIGNAL` signals the box's init.** It was
`stop` under a second name: it sent SIGTERM and waited the box's grace (10 s by default) before the
kill, where the docs called it immediate. Now `kern kill <box>` is SIGKILL with no grace (exit 137),
`kern kill -s HUP <box>` sends HUP to the init and leaves the box running, `killall` kills every box
at once, and `kern compose kill [-s SIGNAL]` and the Docker API's `kill` (its `signal` parameter, 409
for a container not running) do the same. For the graceful stop, `kern stop`.

**A compose service's `platform:` is honoured.** `platform: linux/arm64` was a warning and the
service ran this machine's image; it runs the arm64 image now, through the kernel's qemu-user handler,
and a `build:` with no `platforms:` builds for it, as under Docker.

**`docker pause`, `unpause`, `rename` and `top` through kern's socket.** They answered 501. A paused
box is `paused` in `docker inspect` and `docker ps`, where it read `running`.

**`docker stats`, exec events and terminal resizes through kern's socket.** `docker stats` answered
501; it reads kern's figures now as Docker's (memory against the box's limit, CPU% from two
readings, pids, network). `docker events` sends `exec_create`, `exec_start` and `exec_die`, and an
`event=exec_start` filter matches them as Docker's does. A resize of `docker exec -it` or `docker run
-it` reaches the program in the box as `SIGWINCH` with the new size; it was accepted and dropped.
`kern stats --json` carries the memory and pids limits, the tasks, the page cache and the network
counters it reads them from.

**The Docker API server steps aside when kern is updated.** A server kept busy by a client
(an IDE, a test suite) kept answering with the API of the binary it started from after a new kern
was installed, for as long as it was busy (measured: 21 minutes). It now exits once it holds no
connection, test session or attached run, and the next connection starts the new binary (measured:
20 ms for that request).

**`kern cp` copies directories, as `docker cp` does, and `docker cp` works through kern's socket.**
`kern cp` copied single files only. It copies a whole tree now, keeps a symlink as a symlink (`-L`
follows the one SRC names) and a hardlink as a hardlink, takes Docker's destination rules (into an
existing directory, renamed, `/.` for the contents) and `-` for a tar on stdout or stdin. Every path
on the box's side is still resolved inside the box, and on the host side a member, or a link it goes
through, that would leave the destination is refused. The Docker API serves
`/containers/{id}/archive`, so `docker cp` works in both directions, and a file copied into a
container that has been created and not started (how Testcontainers copies its files) is in place
when its command starts.

**What a Docker client asks for at create reaches the box.** Through kern's socket only the memory
and CPU limits were read; every other setting was accepted and dropped (`docker run --pids-limit 32`
let a hundred forks through). The pids limit, `/dev/shm` size, swap, cpuset, CPU quota, read-only
root, init, extra hosts, resolvers, dropped capabilities, groups, sysctls, tmpfs mounts, ulimits,
log options, stop signal and timeout are now the box's flags, and what kern does not apply
(`--cpu-shares`, `--oom-score-adj`, `--oom-kill-disable`) is printed by the client as a warning.

**`kern wait` begun before a `kern stop` prints the stop's code.** The stop records the code after
the box's grace, and the record's own sweep of older runs listed the registry first, which dropped
the box's entry before the code was written: the waiter printed "exited without a recorded exit
code" (6 times in 6 on a kept box), and `docker wait` beside a `docker stop` through kern's socket
answered -1 where Docker answers 137. The record is written first, and a waiter that sees the
supervisor go while a stop is under way waits for that stop's code.

**`docker events` through kern's socket follows a container to its end.** A container started
detached made no `die` at all, not at its exit, a `stop` or an `rm -f`; `rm` made no `destroy`, and
`stop`, `kill` and `restart` made no event. Each is published now in Docker's order (`kill`, `die`
with the exit code, then `stop`, or `start` and `restart`, and `destroy` last), watched through a
pidfd on the box's supervisor, so no process stays resident per container. A `--restart` container's
every run is reported (`die` with its code, then `start`), as Docker reports it; a container running
when the server started again, or started with kern directly, has its end reported once a stream is
open. A `docker rm` refused with 409 no longer forgets the running container's id and network on the
way.

**A compose service with `platform:` runs through kern's socket.** The `docker compose` client
inspects a service's image and creates the container by the image's id, which kern's socket did not
resolve ("No such image: sha256:..."), and both platforms' entries of one tag had the same id. Each
entry has its own id now, an id resolves wherever an image name does (inspect, history, remove,
create), and `docker rmi` of the arm64 id removes that entry and not this machine's. `kern inspect
--platform <os/arch>` and `kern image history --platform <os/arch>` show an image's entry for that
platform, `Architecture` is the image's own
(it was the host's for every image), and `kern images --json` carries each entry's `cache` name.

**An archive copied into a box resolves `..` as Docker does.** kern refused every member with a
`..`, so an archive Docker extracts into `/` failed whole. A member is now resolved against the
destination: into a box's `/` a `..` above the root stays at the root, a member that leaves any
other destination is refused (`docker cp - c:/opt` of `../x`), and `a/../b` is `b`. Copied to the
host, a member that leaves the directory is still refused.

**The Rust `Sandbox` builder keeps a sandbox's posture.** With a kern box's network now a NAT, a box
from `kern_isolation::Sandbox::builder()` reached the internet, while the builder's contract says
isolated by default. It passes what the Python and Node SDKs pass: `--network none` unless
`share_network()`, `no-new-privileges`, `seccomp-deny=kill` and `--oom-group`.

**`depends_on: condition: service_healthy` through kern's socket.** A container's `Healthcheck`
was not read, so the box had no check and the `docker compose` client refused the stack ("has no
healthcheck configured"); it is the box's `--health-*` now, durations rounded up to whole seconds.

**`docker.io/library/alpine` is `alpine`, as under Docker.** kern cached a Docker Hub image under the
name it was given, so `docker pull` through kern's socket (which says `docker.io/library/...`) stored
a second copy beside the familiar name and a create naming `wordpress:php8.2-apache` answered "No
such image". The three spellings of Docker Hub's host are one name now.

**Images with a named pipe in a layer pull.** A FIFO in a layer was refused "by policy", which made
the official `mysql:8.0` unpullable; it is extracted, as Docker extracts it, and vetted as any member.

**`kern cp` copies the box's files as the box's root.** A file of mode 000, or one that belongs to
another user of the box (a service's data), could not be read from the host: `kern cp` failed with
"Permission denied", and `docker cp` through kern's socket exited 0 with an empty directory. The copy
now runs in the box's user namespace, so it reads and writes what the box's root can; what it writes
on the host is still yours. A copy that fails part-way is now an error for the Docker client too.

**`docker compose up` twice, and `--force-recreate`, through kern's socket.** The second `up` crashed
the compose client (the container list carried no networks), and a recreate failed, because the new
container is renamed before its start and a created container could not be renamed. A renamed
container keeps its id, as under Docker.

**`docker compose` works through kern's socket.** Its first network call answered 501 and it
stopped there. Networks are served now as kern pods (a service is reached by its name from every
member, the ones already running included) and volumes as kern volumes, with the labels compose finds
them by: `up`, `ps`, `logs`, `exec` and `down -v` run a two-service file with a named volume. A
container on two networks is refused by name; `kern compose` runs such a file. `kern box
--network-alias` gives a box another name on its pod's network, as Docker's does. An endpoint still
not served (`build`) answers 501 naming `kern build`, where it named an internal server.

**`kern compose -f -` reads the file from stdin, as `docker compose -f -` does.** It answered "reading
-: No such file or directory". The current directory is the project's, for its name and for relative
paths, as under Docker, and a `${VAR:?message}` the file requires stops it with that message.

**A secret is read-only in the box, for its root too.** The write bit of `/run/secrets/<name>` was
dropped, which binds every user but the box's root: `echo x >> /run/secrets/s` from a compose service
succeeded, where Docker answers "Read-only file system". `/run/secrets` is a read-only mount once the
secrets are written, with `--ssh` as without it; the host's file was never touched either way.

**`kern run --platform os/arch`, as `docker run --platform`.** `kern run --platform linux/arm64
alpine uname -m` was refused as an unknown flag, while Docker prints `aarch64` on the same amd64
machine. It runs that platform's image now, through the kernel's qemu-user handler, from the cache
entry `kern pull --platform` and `kern build --platform` fill, so this machine's `alpine` is still
this machine's afterwards. `kern box` takes it too, and the Docker API reads `?platform=` on a create
and a pull. Without the handler the run is refused before any pull, saying what to install.
`kern images` names the platform of an entry that is not this machine's (`alpine:3.20 (linux/arm64)`,
`"platform"` in `--json`, `{{.Platform}}` in `--format`): three platforms of one tag were three
identical rows.

**An image's size counts a hardlinked file once.** busybox is one binary under some 400 names, and
each name was added: `kern images` said 394.6M for an image of 4.2M (4417150 bytes, the 4.42MB
Docker prints), and `kern rmi` reported freeing the inflated figure. A volume's size in `kern volume
ls`/`inspect` had the same count. Sizes recorded by an earlier kern are measured again on the next
listing.

**A build's `ARG` and `ENV` are scoped to their stage, as Docker scopes them.** A `--build-arg` for an
`ARG` declared in one stage was expanded in a later stage that never declared it, so a value passed
for one stage reached another; and an `ARG` before the first `FROM` was used inside every stage. Now
a global `ARG` reaches the `FROM` lines, and a stage only through `ARG NAME`; a stage's `ARG` and
`ENV` end with it, and a stage built `FROM` an earlier one inherits its `ENV`. A Dockerfile that used
a global `ARG` in a stage without naming it there built differently from Docker; name it there.

**`kern build -` reads stdin, as `docker build -` does.** A Dockerfile on stdin builds with an empty
context, a tar (plain or gzip) on stdin is the context, and `-f -` takes the Dockerfile from stdin for
a context on disk; both at once is refused. It answered "unknown build flag '-'".

**The `--health-*` times and `--timeout` take Docker's durations.** `--health-interval 30s`, the form
`docker run` requires, was a usage error; `30s`, `1m30s` and `2h` work now beside a plain number of
seconds, and a duration that is not a whole number of seconds (`500ms`) is refused rather than
rounded. `kern inspect -f` answers `{{.HostConfig.Memory}}` (the cap, 0 for none) and
`{{.RestartCount}}`.

**`docker run --restart` through kern's Docker API is honoured, and the restart count is reported.**
The API did not read `HostConfig.RestartPolicy`, so `--restart on-failure:2` ran once and stayed down.
It is `kern box --restart` now (`on-failure:N`, `always`, `unless-stopped`), refused with
`AutoRemove` as Docker refuses the pair, and `docker inspect` gives `RestartCount`, as do
`kern inspect --json` and `kern ps -a --json` (`restart_count`), counted as Docker counts them.

**A `kern commit` of a `--net` box no longer bakes the host's resolver into the image.** The host's
`/etc/resolv.conf` was copied into the box's writable layer, so it was a change like any other and a
commit carried it (a systemd-resolved stub, here). It is now given through the box's own `/etc`
files, bound as `/etc/hosts` and `/etc/hostname` are, read from the host's servers, `search` and
`options`; a `--bind-rootfs` box is unchanged.

**kern's configuration directory cannot be mounted into a box.** `-v ~/.config/kern:...` and
`-v ~/.config:...` were accepted, and the box could read the registry credentials there and write
the `kern.toml` whose profiles and grants kern applies to later boxes. They are refused now, as the
runtime registry and `~/.local/share/kern` already were, with the reason; a sibling directory of
`~/.config` is still mountable.

**A `--rm` box ended by `kern stop` or `kern kill` is removed, as Docker removes it.** It stayed in
`ps -a` as `exit 137` (0.56.0 the same), because the stop wrote the exit record and only the box's
supervisor knew the box was `--rm`. The record of a running box now says so (`rm=1`; one written by
an older kern reads as before), and a stop of such a box leaves only the hidden record a waiter reads
its code from. `docker stop` of a `--rm` container through kern's API is the same. And `docker kill`
of a container created and never started answers 409, as Docker does; it answered 304 and the CLI
exited 0.

**`kern --help` names `kern version`, and the shell completions offer `compat`, `proxy` and
`unshare`.** The check that compares the completions with the reference stopped reading at the
first `OPTIONS` it met, inside `create [OPTIONS] IMAGE`, so half of the reference was never compared.
The `proxy` line of the overview no longer stops mid-sentence.

**The release's SBOM lists what each published file contains, and it is signed.** `kern.spdx.json`
is built from what each build compiled (the graph cargo resolved, checked against the units the build
compiled) rather than from a scan of the source tree, which listed the workflow's actions and crates
the binary never links and declared 3 licenses. Each asset is an entry with its SHA256: the Linux
binaries and `kern.exe` with their crates (version, license, `purl`, download SHA256), the standard
library and the statically linked C runtime, and the WSL rootfs with its Alpine packages. It carries
a `.sha256` and is signed with the other assets (see SECURITY.md). Every action the workflows run is
pinned to a commit, and the release jobs read the repository only, except the one that writes the
draft.

**`--restart on-failure:N` works on `kern box` and `kern run`, as in Docker.** It is `on-failure`
with `--restart-max N`, which is what compose's `restart: on-failure:N` already was; before, the
command line refused it as an unexpected argument.

**A `docker run --rm` whose start kern refuses ends with the error, as `docker run -d` did.** It
hung for good (with an unreadable cache dir: killed after 25 s), because the client waits for the
container's removal before it reports the error and the container stayed created. It is removed
now, its wait answers 125, and the client exits 125 with kern's message in about 20 ms, attached
or `-d`. A container without `--rm` stays created, as Docker leaves it.

**`docker run --rm` through kern's API is removed by kern, whatever becomes of the server.** The
server removed such a box itself after following its log, so a server stopped meanwhile left the
box listed as exited for good. The box is `kern box --rm` now: its log stays for the server's
follower for 60 s after it ends, hidden from every other reader (`kern logs` finds none, `ps -a` no
line), and goes with the box's hidden record; its exit code reaches the run as before (`exit 7` is
7). A box whose server was stopped mid-run is gone when it ends.

**A box's `/etc/hosts`, `/etc/hostname` and `/etc/resolv.conf` are its own files, bound over the
image's.** kern wrote them into the box's root: a box started `--keep` (every container of kern's
Docker API is one) paid a copy of `/etc` onto disk at its first start, and `kern commit` carried the
box's own name into the image's `/etc/hosts`. They are written in the box's directory under
`$XDG_RUNTIME_DIR/kern/etc/` and bound over, as a container runtime binds them; an image without
them gets an empty file to bind over. A committed image keeps the image's own files, or none where
it had none. Measured, release builds, a new `--keep` box started and removed: 10.5 ms against 15.7,
interval [-5.40, -4.91] ms; a box without `--keep` unchanged.

**What a box writes while it stops is in its log.** `kern stop` signals the supervisor's process group,
and the log pump of a detached box was in it: it died on the SIGTERM while the workload's handler was
still writing, so a `trap ... TERM` that printed its last lines and exited 0 left none of them in
`kern logs` (nor in `docker logs` through kern's API). The pump has a process group of its own and
ends when the box's output does: 500 lines written on SIGTERM are all in the log, and the 3000
written before a SIGKILL too; `kern stop` takes as long as before.

**`--timeout N` ends a box at N seconds when its init cannot hear SIGTERM.** At the deadline kern sent
SIGTERM and waited 2 s before the SIGKILL, also for an init with the default disposition, which the
kernel never delivers it to: `kern box --timeout 1 -- sleep 30` ended after 3 s. It ends after 1 s
now, as `kern stop` already did; an init that catches SIGTERM still ends on its own, and one that
ignores it still gets the 2 s.

**A box started from an ssh login or a WSL shell starts 2.1 ms sooner.** From a session outside the
user's systemd subtree a box needs a scope of its own, and kern asked for it through `systemd-run`,
then started again inside it. It now asks systemd itself, over D-Bus (the manager's private socket,
or the session bus where that refuses), from its own process, and goes on in the scope with the same
properties. Measured on WSL Ubuntu with systemd, paired: 9.46 ms against 11.67 ms per box, interval
[+1.83, +2.31] ms; from a desktop terminal, where boxes join the delegated cgroup, unchanged.
`KERN_SCOPE_VIA_SYSTEMD_RUN=1` takes `systemd-run` as before.

**`-q` is quiet on a terminal: `kern build -q`, `kern pull -q`, `kern box -q`.** On a terminal,
`build -q` drew the whole live view and printed every `RUN`'s output, and `pull -q`, and `box -q`
for an image not yet cached, printed each layer's progress; without a terminal they were quiet.
`-q` is now `--progress quiet` for all three: the result line, the workload's own output, and on a
failure the error (for a build, its last lines). `docker run -q` through the shim is `box -q`.

**`kern ps` no longer calls a renamed box lost.** After `kern rename r r2`, `ps` warned that a box
`r` was running with no record, about the box it listed as `r2`: the cgroup directory and the
supervisor's command line keep the name a box started with. A box is now recognised by the cgroup
directory or the supervisor pid its record names; a box whose record really is gone is still
reported. And a box renamed while it runs ends under its new name: its exit was recorded under
the old one, so `ps -a` listed `a` after `rename a b`, `kern rm b` and a later `kern wait b` found
nothing, and a renamed `--rm` box left its logs in the store.

**A pull records the image's repository digest, and `kern images --digests` shows it.** It is the
digest of the manifest the registry answered for the reference (the index of a multi-arch image),
what Docker lists as `RepoDigests` and what `name@sha256:...` pulls the same image again by:
`images --digests` adds the DIGEST column, `--format {{.Digest}}` and `--json --digests` give it,
`kern inspect --json` of an image lists `RepoDigests`, and so does kern's Docker API. A build, a
commit and a load have none, as with Docker. An image cached before gets it at the next
`kern pull` of it, from the manifest alone, when the registry still names the same image. Measured
against Docker Hub's `Docker-Content-Digest`: `alpine:3.21` and `alpine:3.19` match. A pull by a digest the
registry does not have says so (`no such manifest`), where it reported a digest mismatch and advised
pulling again for a damaged blob.

**A port published through kern's Docker API with no address is on every address.** `HostIp` left
empty became `0.0.0.0`, IPv4 alone, where Docker binds `0.0.0.0` and `::`; a Windows client asking
for `localhost` (.NET, PowerShell) tries `::1` first and waited 2068 ms for its refusal on every new
connection. Measured with Testcontainers for .NET from Windows: the port case 2508 ms, then 564 ms.

**`kern logs -f` and `kern wait` wake when the box writes or ends, not on a timer.** They polled every
200 and 100 ms; measured on a box that lives 250 ms, `logs -f` returned after 251 ms instead of 402,
and `wait` after 251 ms instead of 302. A box's supervisor now finishes its log before it leaves
the registry, so a follower that stops there has the last line. `kern wait`, `ps -a` and `rm`
right after a box that ended at once saw it neither running nor exited for about 10 ms; they see its
exit record now. `kern rm` of an exited box removes its logs too, as `docker rm` does.

**`kern start` starts a kept box detached, as `docker start` does, and `start -a` follows it.** A box
kept from a foreground `kern box --keep` ran again in the foreground and `kern start` did not return
until it ended, which its own help ("-a follows its output") does not say; `start -a` of such a box
printed its output, then failed with "no logs". `kern ps -a --json` gives a kept row its `labels`
and, once a run has ended, `exited_ago`; an exited row its `started`; `kern inspect --json` gives
`image` and `created` (a kept box's stays the same across its restarts). See [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md).

**`kern proxy trust`: the `.localhost` names over HTTPS, once you ask for it.** It makes a
certificate authority of your own that can sign `localhost` names only, adds it to your user's
Chrome and Firefox stores (and, typed in Windows' PowerShell, to your Windows user's store, which
Windows asks you to confirm), and the router then answers `https://<service>.<project>.localhost:8443/`
(443 where an ordinary user may bind it). `kern proxy untrust` takes it out of every store and
deletes it; `kern proxy status` says where things are. Without `trust` nothing changes. Measured: a
certificate this kind of authority signs for another name is refused by OpenSSL, curl, Chrome 157,
Firefox 157 and Windows' verifier. See [docs/CONFIG.md](docs/CONFIG.md).

**`docker logs` through kern's socket keeps stdout and stderr apart.** A container made through
the socket logs its two streams on two pipes and its log records which stretch came from which;
`docker logs` and an `attach` after the start answer them as Docker does, with `--tail`, `-f`, `-t`,
`--since` and `stdout=`/`stderr=`. The log file itself, and `kern logs`, are unchanged, and so is
every other box. Measured: a detached start is the same with and without the record (-22.5 us, 95%
interval -65.6 to +17.2), and a box alternating short lines on the two streams keeps them apart for
its whole log.

**`kern-docker`: the `docker` command line, translated into kern's.** A link to kern called
`kern-docker` runs `docker run|exec|ps|logs|compose|...` against kern's boxes, flag by flag; a flag
kern does not mean the same stops the command with exit 125, naming it. `kern compat docker -- CMD`
answers `docker` for one command, in Windows too (`kern.exe` puts its own `docker.exe` at the front
of that command's PATH); `kern compat docker link <dir>` makes a recorded `docker` link that
`kern doctor` shows. `docker version` says kern. See [docs/DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md).

**`--egress-secret`: a key the box uses and never holds.** `kern box --egress-secret
host=H,header=N,env=VAR|file=PATH[,scheme=Bearer]`: the egress proxy adds the header to the box's
plain `http://` requests to H and sends them on as `https://`, pinned to the address it vetted; an
echo of the key in an answer reaches the box as `[kern-secret]`. The key is read from kern's
environment or the file, and is not in the box, its arguments or kern's records. The SDKs take the
same rules: `Sandbox(egress_secrets=[...])` in Python, `egressSecrets` in Node. See
[docs/EGRESS.md](docs/EGRESS.md).

**In kern's WSL distro, nothing kern starts opens a vsock socket.** A seccomp filter installed while
kern is still root, and inherited by every box, supervisor and helper, refuses `socket(AF_VSOCK)`:
from the distro, vsock reached Windows' own file server. Boxes already refused it. See
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

**`kern top --json` and `kern version --json`.** `kern top --json` prints one frame of the task
manager as JSON, `--stream` one a line (NDJSON) every `--interval` seconds, `--tab` adds those tabs'
records; every frame opens with `"schema"`, which `kern version --json` reports as `json_schema`.
Built by the same function the screen draws from. See [docs/TOP-JSON.md](docs/TOP-JSON.md).

**`kern self-update` in Windows updates `kern.exe` too**, after the distro's kern: to the
`kern-windows-x86_64.exe` of the release the distro runs, whose signature `kern.exe` checks itself
with the release keys. The replaced one is kept for `--rollback`. See [docs/INSTALL.md](docs/INSTALL.md).

**`--egress-allow`, `--egress-deny` and `--egress-secret` work with `-d`.** The filter of a detached
box is started for every attempt, `--restart` included, and stopped with it; it was refused before.

**`kern unshare [--] [CMD...]`: a command with the ids a box's files carry on disk**, as `podman
unshare`. A bind-mounted directory a box's non-root user wrote is owned on the host by a subordinate
uid (100998 for a box's 999), which you cannot `chown` or remove; `kern unshare -- rm -rf ./old` and
`kern unshare -- chown -R 0:0 ./data` can. Without a subordinate id range it still runs, as uid 0 of
your own id only, and says so first. See [docs/RUNTIME-PARITY.md](docs/RUNTIME-PARITY.md) section 38.

**`kern bench` says how much of a number is noise.** Besides min/median/avg/max it prints p10/p90, the
floor (what spawning `/bin/true` costs on that machine), an A/A interval (the same start in two
interleaved series), the load average before and after, and saves each run as JSON;
`--compare docker|podman` runs the same image there, paired run by run, reported as the median of the
per-pair differences with a 95% interval. `--json` prints one object. See [BENCHMARKS.md](BENCHMARKS.md).

**An image box starts about half a millisecond sooner.** The two setuid helpers that write its
subordinate uid range (`newuidmap`, `newgidmap`) now run from the moment the command line is read,
while kern resolves the image and builds the cgroup, instead of after; kern then joins the mapped
namespace and checks its map against `/etc/subuid` and `/etc/subgid`. Measured on an x86 desktop,
`kern box --image alpine -- /bin/true`, 200 paired runs: median 4.28 -> 3.69 ms, -0.56 ms (95%
interval -0.60 to -0.53 ms; the same binary against itself: 0.00 ms, -0.06 to +0.05). A box without the range (`--no-uid-range`, a pod member) is unchanged.

**Busybox `wget` reaches an allowlisted HTTPS host through `--egress-allow`.** It sends the whole
`https://` URL to the proxy instead of a `CONNECT`; the proxy now makes that HTTPS request itself, over
the vetted and pinned leg `--egress-secret` uses, where it used to dial port 80 and fail.

- `kern pod create` refuses where `kernel.apparmor_restrict_unprivileged_userns=1` applies to kern
  (kern outside its AppArmor profile), with the words `kern box` uses there; a pod member used to start
  on such a host while a plain box was refused.
**`--egress-allow`: the box's command starts once its filter listens**, in the foreground and with
`-d`. The command could start before the filter's in-box port was up and meet `127.0.0.1:3128` with
nothing behind it: on a stock Ubuntu 24.04, 13 boxes in 20 whose command fetches at once failed with
v0.56.0. The box now waits, fully set up, until the filter says it listens: 20 in 20. The filter also
waits out a moment in which the box's loopback, already up, refused its port (one box in 2000): 0
failures in 6000.

**A process kern starts keeps none of the caller's descriptors numbered 1024 or above.** A service of
a stack without a pod and the `--egress-allow` helpers closed what they inherited from 3 to 1023 only:
with v0.56.0 a descriptor 1500 of the caller was open in both services of such a stack.

- `kern doctor` typed in Windows: the row checked from Windows is one of the table's rows, counted in
  the tally, where it was printed after it.
- `install.ps1` resolves the latest version once, with a timeout, and downloads every file from that
  release; a release published during an install no longer makes the signature check refuse it.
- The `--egress-allow` note is printed to a terminal only, not into every SDK cell's stderr, and once,
  not twice when the box runs in a systemd scope of its own.
- The `.localhost` router says it listens instead of being polled every 10 ms: a cold `kern box -d -p`
  takes about 3 ms less.
- `kern sandbox show` ends a block with its last line, not a blank one.
- `kern build`'s live view shows a batch of RUNs as one row named from its first step.
- A `COPY --from` path missing from a single-layer stage is named, with the stage, as it already was for
  a multi-layer one.


## kern sandbox 0.3.0 - 2026-11-20

**It carries the kern v0.56.0 binary**, and both bindings gain what v0.56.0 lists under "kern sandbox":
labels and `Sandbox.list()`, `get_metrics()`, `set_timeout()`, `watch_dir()`, `ports` and `get_host()`,
`start_cmd` and `ready_cmd`, `pty()`, `fork(n)`, `egress_deny`, and each call's code and output kept for
`kern sandbox show`. An `egress_allow`/`egress_deny` entry with a space or a line break around it is
refused, not cleaned.

## v0.56.0 - 2026-11-20

**Two commands change what they do by default. Both now behave as the same command of Docker:**
- **`kern exec <box>` runs as the box's own user** (the image's `USER`, or `--user`);
  `kern exec -u root <box>` enters as root. `kern compose exec` already did this.
- **`kern up` reads every flag it is given.** `--exit-code-from S`, `--abort-on-container-exit`,
  `--wait-timeout N`, `--build`, `--no-build` and service names were taken and not acted on, so
  `kern up --exit-code-from tests` reported 0 whatever the tests did; they now mean what they mean in
  `kern compose <file> up`, `--progress` is taken after `up`, and a flag the shorthand does not have is
  refused by name. Under those flags, the progress view shows the service that ended as completed, not
  failed.
- **An attached `up` shows what this run printed**, as Docker's attach does. It replayed every earlier run
  of the service kept since the stack was created: five `kern up` in a row printed a one-line service 1,
  2, 3, 4 and 5 times. `kern compose logs` still holds every run.
- **`kern compose up` without `-d` follows the stack whatever stdout is**, and returns when every
  service has exited (Ctrl-C stops the stack). On a pipe or a file it used to return at once, so a
  `up setup` meant to finish before the next step ran in parallel with it. `-d` returns at once, and
  `--wait` implies `-d`.

**A request to a `.localhost` name is read by the same code as the egress proxy's**, which refuses a
head a service could split differently (a bare CR or LF, a folded line, two `Content-Length`s,
`Transfer-Encoding` with `Content-Length`, two `Host`s, a request line and `Host` naming different
hosts). A refused request ends its connection: nothing sent after it reaches a service.

**The `.localhost` router runs while a published port exists and leaves within seconds of the last
one**, in a cgroup of its own. `kern box -d -p ...` prints `url: http://<box>.kern.localhost:PORT/`
too; `kern ps --format '{{.URL}}'`, `ps --json` and `inspect --json` carry the URL.

**`FROM image:${VAR:-default}`** and the other modifiers (`${VAR-word}`, `${VAR:+word}`,
`${VAR+word}`, nested defaults) expand as they do elsewhere; they expanded to nothing.

**`compose ps` and `kern ps` show the current run**: a box restarted by its restart policy is
`Restarting (N) X seconds ago` between two runs, and `Up` counts from its last start, not from its
creation. A service stopped and started again is listed once.

**On WSL, files on `C:\` belong to the distro's user, a box's root, and keep `chown`/`chmod`**
(`[automount] metadata,uid=1000` in `/etc/wsl.conf`; `install.ps1` sets it on an existing distro and
restarts it). A database keeping its data in a project folder on `C:\` could not set it up and
restarted for hours. `kern doctor` says how `C:\` is mounted, and a box started with a writable bind
of a directory another user owns says that its root cannot chown it.

**Windows refuses the programs started from inside kern's WSL distro** (`[interop] enabled=false`; `install.ps1`
sets it on an existing distro, and leaves a value someone wrote). `kern.exe` from Windows works as
before; `code .` or `explorer.exe` typed in the distro does not. `kern doctor` says whether interop is
on.

**kern's WSL distro carries `zstd` and `/etc/localtime`** (UTC): images with zstd-compressed layers
pull, and a compose file that mounts `/etc/localtime` starts. `kern doctor` says whether `zstd` is
installed.

**A restarted or stopped-and-started service no longer leaves its old network helper running.** The
new one took over its record, and `down` stopped only the new one: helpers piled up on each restart of
a slow-stopping service.

**An unset `${VAR}` is reported once**, not once per use of a YAML anchor.

**`kern build` on a terminal draws the live view `compose up` draws**: one row for the image, the step
it is on and how long that step took last time, with what the RUNs print above it. On a pipe or in
CI it prints its step lines (it printed none); `--progress quiet` prints nothing but the result, and
the build's last lines when it fails; in `--progress json`, `build_step` carries `"cached"`.

**kern sandbox (Node) records each call's code and output** for `kern sandbox show`, as the Python
binding does; `transcripts: false` keeps none for one sandbox.

**`kern top` counts a GPU it cannot read** (`GPU 1 · usage n/a` on WSL2) instead of `GPU none`.

**`compose up` names each published service: `http://<service>.<project>.localhost`.** A router of
your user, on the loopback addresses, forwards by `Host` to the port the service published;
`<port>.<service>.<project>.localhost` picks a container port and `<service>.kern.localhost` the one
project that has the service. Port 80 where an ordinary user may bind it, else 8780 (8080 is the port
many apps publish); `[kern] local_domains_port` sets it and `local_domains = false` turns it off.
`kern doctor` typed in Windows checks that port from the Windows side: held by a Windows program, or
refused by Windows, it says so and names the fix. In `--progress json`,
one `local_url` event per service.

**`--progress auto|tty|plain|json|quiet` on `kern build` and `kern compose`** (or `KERN_PROGRESS`).
`compose up` on a terminal draws one row per service, redrawn in place under a header that counts
them: pulling, pulled, building with the step it is on, built, waiting for its dependencies, started, exited,
failed, skipped; every line written meanwhile is printed above it. `json` writes one event per line
on stdout (`schema` 1: `build_step`, `heartbeat`, `build_done`, `service`, `service_log`, `up_done`)
and nothing else there; `quiet` prints no progress. A service that dies during the bring-up is
followed by the last ten lines it wrote. Each build step says how long it took last time; an
interrupted `up` says what may be left and how to remove it.

**`kern sandbox show`: the code SDK sandboxes ran and their output.** The SDKs record each call
(`kern sandbox record`); transcripts are kept where `sandbox_history` keeps the history (in memory by
default), mode 0600, up to 64 KiB of code and 256 KiB of each stream per call and
`sandbox_transcripts_max_size` (16m) in all; `[kern] sandbox_transcripts = false` keeps none, and
`kern sandbox clear` and `kern sandbox keep` remove and move them with the history.
kern sandbox (Python) records each call that way; `transcripts=False` keeps none for one sandbox.

**`kern box -it` and `kern exec -it` with stdin a pipe take the terminal size from the caller.**
`KERN_TTY_SIZE=COLSxROWS` sets it; `KERN_TTY_SIZE_FILE=<path>` names a file holding it, read at start
and again on every `SIGWINCH`. Without either the box terminal was 0x0 (`stty size` said `0 0`). A
terminal on stdin works as before.

**`--egress-deny` and ranges in `--egress-allow`.** The allowlist takes addresses and ranges
(`10.1.2.0/24`, private ones included), and `*` for any public host; `--egress-deny` refuses domains,
addresses and ranges even when the allowlist covers them, and alone means `*` minus these. A list
kern cannot read is refused before the box starts.
kern sandbox: `egress_allow` takes the same forms and `egress_deny=[...]` is new; in Node,
`egressAllow` and `egressDeny`.

**kern sandbox: `ports=[...]` and `get_host(port)`, `start_cmd` and `ready_cmd`.** A `persist` sandbox's
resident box and every `kernel()` publish the listed ports on this host's loopback only;
`get_host(port)` answers the address. `start_cmd` runs in the background of the resident box and
`ready_cmd` is waited for (`ready_timeout_s`) every time the box is created or adopted. In Node:
`ports`, `getHost(port)` (also on a kernel), `startCmd`, `readyCmd`, `readyTimeoutS`.

**kern sandbox: `pty()`**, an interactive terminal: `on_data` receives the output, `send_input`,
`resize`, `wait`, `kill`; in the resident box of a `persist` sandbox, else in a box of its own. In
Node, `pty(command, { onData, cols, rows, timeoutS })`, driven through pipes and
`KERN_TTY_SIZE_FILE`: Node has no pseudo-terminal of its own.

**kern sandbox: `fork(n)`**, N copies of a sandbox, each with its own copy of the workspace (`.deps`
included); a `persist` copy gets its own name. In Node, `fork(n)` needs `KERN_SANDBOX_SNAPSHOT=1`, as
`snapshot()` and `restore()` do.

**kern sandbox: labels, `Sandbox.list()`, `get_metrics()`, `set_timeout()`, `watch_dir()`.** `labels={...}`
goes on every box a sandbox starts and `Sandbox.list(labels=...)` finds the running ones;
`get_metrics()` (also on a `Kernel`) reads CPU, memory, tasks, workspace disk and the deadline;
`set_timeout(s)` moves a `persist` sandbox's deadline (`0`: none); `watch_dir(path, on_event)` reports
create, write, rename, chmod and remove in the workspace, never through a symlink. In Node:
`labels`, `Sandbox.list(labels)`, `getMetrics({ intervalS })`, `setTimeout(s)` and
`watchDir(path, onEvent, { recursive })`; the watch runs in a hidden `kern __watch-dir`, because
Node's `fs.watch` cannot tell a create from a remove nor a write from a chmod.

**kern sandbox: a `persist` sandbox's resident box is made in one shape**, without the bytecode-cache
mount, whenever it is created, so the process that made it, another process and a recreation all
agree on its fingerprint. The Node binding had the same mismatch and the same fix.

**`kern update --timeout S <box>`**: a running detached box ends S seconds from now; `0` removes its
deadline. A box started without `--timeout` gets one.

**`compose up` on a terminal shows a service that exited before it attached** (`command: echo ...`).

**`kern self-update` tells a failed download from an unsigned release**: a network that does not answer
is named as such, not as a missing signature.

**`kern self-update` works in kern's WSL distro**: the new binary is checked as root there, and a host
name that does not resolve is tried again over IPv4.

**The WSL distro carries the released kern, byte for byte.** It had a kern built separately for it,
the same version and different bytes, so no signature covered the binary a WSL install runs. The
release workflow now puts the x86_64 tarball's binary in the distro and fails if the two differ.

**Every release asset is signed**: the Windows `kern.exe` and the WSL distro too, not only the Linux
tarballs. A release is published only once its signatures are on it.

**`install.sh` refuses a release from 0.51.2 on that has no signature, or whose signature names
another version** than the one asked for. `install.ps1` checks the signatures of `kern.exe`, the
distro and an in-place update when minisign is installed (`winget install jedisct1.minisign`), with
the same rules; without it, on an update, the kern installed before the update checks them. A
`latest` that names a release older than these rules is not refused for them. At the end it says, file
by file, what was checked: SHA256, a signature and by whom, or nothing (a local file, a first install,
which trusts HTTPS from github.com).

**`install.ps1` takes `KERN_WSL_DISTRO` and `KERN_INSTALL_DIR`**, to install into another distro and
folder; `kern.exe` already reads `KERN_WSL_DISTRO`.

**`install.sh` and `install.ps1` take `KERN_RELEASE_URL`**, a mirror holding one release's files (with
`KERN_VERSION`): an internal server or an offline copy. A mirror is trusted only through the
signatures: when nothing can check them (no minisign, no kern installed before that can), the install
is refused.

**A `COPY --from` path missing from its stage is named**, with the stage:
`COPY --from: '/app.jar' does not exist in stage 'build'`.

## kern sandbox 0.2.53 - 2026-11-18

**It carries the kern v0.51.3 binary.** Both bindings move together; nothing else in them changed.

## v0.51.3 - 2026-11-18

**`install.sh` installs a signed release when `minisign` is installed**; it refused every one.

**`kern` with no arguments lists `kern self-update`.**

**`COPY` into a directory a box user owns builds** (`RUN adduser -D app` then `COPY f /home/app/`), with
or without `--chown`.

## kern sandbox 0.2.52 - 2026-11-18

**It carries the kern v0.51.2 binary.** Both bindings move together; nothing else in them changed.

## v0.51.2 - 2026-11-18

**Windows (WSL): boxes run as the distro's user `kern` (uid 1000).** A box's root is
uid 1000 of the distro. `install.ps1` converts an existing distro: images pulled again for the user,
volumes and settings moved with their modes kept; an account already on uid 1000 becomes the user. Each distro has its own cgroup subtree. The distro
ships `passt`; root's password is locked. Started from a root terminal, kern runs as the user on a
terminal and in a session of its own, relayed by a root process the user cannot trace or signal: the
user's processes hold no descriptor of root's terminal and none of the descriptors root's shell left
open.

**A kern in one WSL distro no longer stops the boxes of another.**

**A box keeps Docker's default capability set** (`CapEff` `00000000a80425fb`). `--cap-add` adds one
back.

**`kern self-update`**: installs the newest signed release; `--check [--json]`, `--to X.Y.Z`,
`--rollback`. `install.sh` checks the release signature when `minisign` is installed.

**Compose: `.env` values reach the box as written.** Interpolation runs on parsed values; `{...}`,
`[...]`, `*x`, `&x`, `a #b` were changed or refused.

**`compose up` starts nothing when an image cannot be pulled or a host port is taken**, and names
each service, image, port and holder.

**`COPY --chown` and `ADD --chown` set the owner**, by number or by the image's own user and group
names.

**A build step or a compose wait longer than 30 s is reported** with its elapsed time, and a build
step with its pids and memory.

**Pull: credentials a registry refuses are retried anonymously**, with a line naming `kern login`
and `kern logout`.

**Caps apply when `XDG_RUNTIME_DIR` points outside `/run/user`.**

**Box scratch never goes under a runtime directory owned by another user** (WSLg's
`/mnt/wslg/runtime-dir`).

**`kern doctor`**: a first line says who kern runs as, and in which WSL distro; limits are reported
as a box gets them; SELinux counts only when selinuxfs is mounted; `sshfs` is optional.

**The published-port warning names the host port** and how to keep it on `127.0.0.1`.

**A box can no longer push input into the terminal it was started from**: `ioctl` `TIOCSTI` and
`TIOCLINUX` return `EPERM`.

**`FROM <stage>` and `COPY --from` build rootless over a directory a subordinate uid owns** (the
`python:*-slim` apt directories), and keep setuid bits.

**On a bridge, a box's own names resolve to its own address**: `hostname -i` answers one address.

**`FROM <stage>` no longer warns about an unpinned tag.**

## kern sandbox 0.2.51 - 2026-11-18

**It carries the kern v0.51.1 binary.** Both bindings move together; nothing else in them changed.

## v0.51.1 - 2026-11-17

**`kern stop <name>` no longer stops a box of another runtime directory.** A box whose record is
gone is stopped by name (v0.51.0), and it was found among every box of the user, so a box another
directory's world started under that name was stopped too. It is now stopped only when its
supervisor keeps its records in the same directory; otherwise kern names it, with its supervisor
pid, and leaves it running.

**`kern uninstall` no longer ends boxes started from another runtime directory.** It stopped the
boxes' systemd unit, `kern-boxes.service`, whenever its own registry was empty, and that unit holds
the boxes of every runtime directory the user runs kern from: a box started by a systemd unit, a
test or a script with its own `XDG_RUNTIME_DIR` got SIGTERM, then SIGKILL 90 s later. Measured: an
uninstall run from a separate world ended a compose stack and three boxes in another one. It now
counts every live box of the user, found as `kern ps` finds one with no record, and leaves the unit
running while any is there, saying so.

## v0.51.0 - 2026-11-17

**Minor bump: `--cpus` and `--cpuset-cpus` beyond the host are refused, as Docker refuses them.**
They were clamped to what the host has, with a warning: `--cpus 64` on 28 CPUs ran with 28, and
`--cpuset-cpus 0,2,4-6` on 6 CPUs ran pinned to `0,2,4,5`, a set nobody named. Both now stop before
the box starts, with Docker's sentence ("range of CPUs is from 0.01 to 28.00, as there are only 28
CPUs available"; "requested CPUs are not available - requested 0,2,4-6, available: 0-5"), and so does
a `vcpu:` profile's value, named as the profile's. A compose file whose `cpus:` exceeds the machine
is refused at that service's start, as `docker compose up` refuses it. To keep a file or a profile
portable across machine sizes, ask for at most the smallest machine's CPUs. The available CPUs are
the kernel's online list, so a CPU offline in the middle of the range counts as missing.

**A rootless box keeps its memory and pids caps for its whole life.** The boxes were plain cgroups
directly in `kern.slice`, a systemd unit whose controllers systemd recomputes from its member units:
one second after kern created the slice (the first box after a boot), and at every `systemctl --user
daemon-reload`, systemd turned them off and every running box lost `memory.max` and `pids.max`, with
nothing said; a start landing in that second was refused. Boxes now live in `kern-boxes.service`, a
`Delegate=yes` unit in `kern.slice` that systemd does not touch, started once at the first box
(measured: ~35 ms, once); a box start is unchanged (4.41 ms against 4.41, indistinguishable). `kern
stop` takes `-t/--timeout N`, as `docker stop` does. As root nothing changes: that `kern.slice` is
not a systemd unit, and a system `daemon-reload` leaves its boxes capped (measured).

**A `--gpus` box starts in half the time.** Every start read every link in the loader's directories
to find the ones ending at the driver's libraries: about 9 syscalls per link, 12,000 on a desktop
with 1291 links in `/usr/lib/x86_64-linux-gnu`. A chain is now walked once per target, without the
`realpath` that could only answer yes under `/`, and the result is kept in kern's runtime
directory and reused while every directory it was read from is unchanged; a library or link added,
removed or re-pointed, or an `ld.so.conf` edit, makes it scan again. The box gets the same files.
Measured on that desktop, medians of 50 to 60: `--gpus device=0` 19.9 to 9.7 ms on `alpine:3.20`,
17.6 to 7.7 ms on `ubuntu:24.04`.

**Log sizes and retention are set once, in `kern.toml` or from the command line.** Five `[kern]`
keys: `log_max_size` and `log_max_file` are every box's log cap unless the box sets its own (default
16m and 2, as before); `log_keep_ended` removes the logs of boxes that ended longer ago than a period
such as `24h`, each time a box starts with `-d`; `build_keep` keeps that many build records, the
ones that ended last, and removes the rest when a build ends, never one still running and without
counting one; `sandbox_history_max_size` is the history's rotation size (default 1m). `kern config
set <key> <value>`, `kern config get [<key>]` and `kern config unset <key>` write and read them,
checking a value with the reader's own rule before anything is written. `set` writes through a
`kern.toml` that is a symlink, keeps the comment on the line it replaces, and refuses a file it
cannot read or that does not parse instead of writing over it; `get` exits 1 for a key not set and 3
for a file that does not parse, as `git config` does, and never prints a value that is not in force.
With none set, nothing changes. Before this, build records were never removed on their own: measured
on a desktop, 12,269 records and 145 MB.

**`kern.toml` is read by one reader, the one every box start uses.** `kern validate`, `kern config`
and the box starts used to judge the file differently. A UTF-8 BOM before `[kern]` made every key
of the table unread while `validate` said "valid": measured, `publish_bind = "127.0.0.1"` was
ignored and a published port bound `0.0.0.0`. A BOM is now read past. A file that is not valid TOML
is refused by line everywhere: a key twice in one table (`config get` printed the first, kern applied
the last), `[kern]` opened twice, a header with no `]`, a line that is neither a header nor `key =
value`, an array that never closes. A file refused that way, or not readable as UTF-8, is applied by
nobody: boxes start on the defaults with published ports on loopback, as before, and `kern info`
now says the file does not parse instead of reading its rows as defaults. Unknown sections and keys
are still read past, with the warning. Keys and table headers are compared as TOML names them, by
their segments: `"log_max_size"`, `'log_max_size'` and `"log\u005fmax_size"` are one key, `[ "kern" ]`
is `[kern]`, and `kern.log_max_size = ...` written outside `[kern]` (however it is spelled) is
refused rather than read past, while a single quoted key that merely contains `kern.` is not the
table. `[[kern]]` is refused, as is a key with a character TOML does not allow in a bare key (a BOM
pasted mid-file is named as such, and a control character in a key is printed escaped); multi-line
strings and escaped quotes are read as TOML reads them. An error quoting
a huge value is cut to a few hundred bytes. The checks are linear: 100,000 keys in one table read in
0.04 s. `config set` keeps the mode of the file it rewrites (a new file is private, 0600).

**`--log-driver none` keeps no log, as Docker's does.** `kern box --log-driver none` (and compose
`logging: driver: none`, which used to warn "no kern equivalent" and capture anyway) sends the box's
output nowhere: no log file is made, and `kern logs` answers that the box keeps none instead of an
empty screen. `json-file` and `local` are the default capture; a driver that ships output elsewhere
(`syslog`, `journald`, `fluentd`...) is refused by name, and so is `none` with `--log-max-size` or
`--log-max-file`, with Docker's words ("invalid logging opts for driver none"). Sandbox calls through the SDKs or MCP never
wrote a log file; their history (one line per box, no output) is set with `kern sandbox keep off`.

**`compose up` on a real stack: a migration job passes `--wait`, a built app is not rebuilt, and
the output is short.** Measured against Docker Compose v5.0.2 on a stack with a database, a one-shot
migration and an app built from a Dockerfile (reported on a Postgres + Hatchet + RabbitMQ stack):
- `up --wait` failed on the migration, saying Docker does the same; Docker passes it when another
  service waits on it with `condition: service_completed_successfully` (it still fails a one-shot
  nobody waits on, `container <name> exited (0)`), and so does kern now.
- A service with `build:` alone was rebuilt and recreated by every `up`. It is built when its image
  is missing or on `--build`, and recreated only when the rebuilt image differs, as Docker compares
  image IDs.
- A second `up` printed about twenty lines; it prints what changed. The network note and the pod's
  summary are said when the pod is made, and the hints for running a hand-built image, for adding
  boxes to a pod and a box's own `next:` line are not printed under compose.

**kern's notices about a detached box go to the command that started it, not into the box's log.**
`kern compose logs <service>` held kern's own lines (`--memory accepted but NOT enforced`, `resource
caps could not be enforced`, `bound 0.0.0.0 ... reachable from the network`) between the workload's,
and on a host without cgroup delegation a quiet service's log held nothing else (reported on a real
stack). They are printed once, where the box was started; a foreground box prints them as before.
The notes about a shared internal port and about `restart:` across reboots are said when the stack's
pod is made, not on every `up`.

**`kern rmi` refuses an image a box uses, unless `-f`.** In Docker's words (`conflict: unable to remove
repository reference "<ref>" (must force) - box <name> is using its referenced image`), for a running
or a kept box, as Docker refuses it for a running or a stopped container. It was removed under a
running compose service, whose next `up` then rebuilt it.

**`kern box -d` reports a box whose setup failed at once.** It waited for ten retries with a backoff
of up to 30 s, because a box that never started (exit 125) was retried even with no `--restart`
policy, since 2026-09-14. The foreground answered in 18 ms; `-d` now answers in 20 ms with the same
reason. With `--restart`, the retries and the immediate return are unchanged.

**`kern build logs` holds what a RUN printed on stdout.** The record kept only stderr, so a RUN's
stdout (most of what `apt`, `pip` or `make` print) reached the terminal and never the log: measured,
`RUN echo OUT-42-X` printed the line and `kern build logs` held only the trailer. RUN stdout now
goes through the capture and is teed to the caller's stdout as before. The log keeps the first and
the last 512 KiB of a long build, with a line saying how much was left out, and ends with the error
a failed build stopped on: a noisy RUN before a failing one used to leave the failure out of the log
entirely. An interrupted build shows how long it ran instead of `0ms`, recorded when its output ended.
stdout and stderr travel apart, so their relative order in the log is not kept. A reader that goes away
(`kern build ... | head -1`) no longer fails the build: the RUN died of SIGPIPE (`RUN failed (exit
141)`), and kern died at its own `built` line before the record was final, so the image existed
and the record said `interrupted`. The build now runs to its end and is recorded `ok`; only the
lines nobody reads are lost.

**`kern stop` waits for a SIGKILLed box as Docker's daemon does: 10 s, then a second SIGKILL and 2 s
more**, where it waited 1 s. On a saturated host a writer at full speed into a large log took
longer to exit, and `kern stop -t 1` answered "did not exit in time" with exit 1 for a box that was
gone a moment later (reported on WSL2: 3 of 3 with 1 s, 6 of 28 with 5 s under a 20-box load). The
wait ends as soon as the box exits, so an ordinary stop is unchanged.

**A `--gpus` box sees its cards' place in the PCI tree, read-only, as `nvidia-smi topo -m` and NCCL
read it.** The box had only the granted cards' device directories, mounted writable, and
`bus/pci/devices/<card>` as a second copy rather than a link, so nothing could walk up to the
bridges: `nvidia-smi topo -m` said `NODE` for two cards the host and Docker report as `PHB`. The box
now gets each card's directory, the attribute files of the bridges above it (not the bridge
directories, which list the other devices behind them), the `bus/pci/devices` and `class/pci_bus`
entries as links, and the host's CPU and NUMA topology, all read-only. Measured with two RTX 5060
Ti: `PHB` in the box, NCCL's dumped topology equal to Docker's, the same all-reduce bandwidth, and
every write under it refused. It costs a `--gpus all` start on that host about 0.5 ms (+544 us,
interval [+170, +1006], n=200, after an A/A that read zero); a box without `--gpus` is unchanged.

**A box's `/sys` is read-only, as Docker mounts sysfs.** `touch /sys/x` succeeded in a box (into its
own root; `/sys/devices` was a writable tmpfs) where Docker answers `Read-only file system`, so a
script probing whether it can write sysfs took the other branch. `/sys` is now the box's own tmpfs,
remounted read-only once kern has put in it what it puts there (the CPU topology, the cgroup view,
granted sysfs paths). A `-v` under `/sys` keeps its own mode, a granted LED or PWM stays writable,
and `--privileged` leaves `/sys` writable, as Docker's `--privileged` does. Anything an image ships
under `/sys` is hidden, as under Docker. Measured: a box start is 73 us faster (interval [-112,
-14], n=200, after an A/A that read zero), because those directories no longer land in the
overlay's writable layer.

**`KERN_SECCOMP=denylist` no longer lets `open_tree_attr` and `listns` run.** The denylist allows
what it does not name, and these two came after the lists (Linux 6.15 and 6.19): on a 7.0 kernel a
box under the denylist reached both, measured. `open_tree_attr` is the new mount API that
`open_tree` is denied for, and now kills like it; `listns` enumerates namespaces and now answers
`ENOSYS`. The default allowlist already refused both. kern now denies 37 escape syscalls (25 that
kill, 12 that answer `ENOSYS`), and the ten other syscalls those kernels added were reviewed and
stay allowed under the denylist: the `*xattrat` calls, `file_getattr` and `file_setattr`, `mseal`,
`rseq_slice_yield`, `uprobe` and `uretprobe`.

**A box runs the command it was given on a newer systemd.** `systemd-run` expands `${VAR}` and
`$VAR` in the command it starts, and since a recent release it does so for scopes too (Ubuntu
26.04): a box started through kern's scope re-exec got `${#a[@]}` as nothing and `$$` as `$`. kern
now passes `--expand-environment=no` where `systemd-run` knows it (systemd 254 and later), so the
command reaches the box as written, as under Docker. Hosts where kern places boxes in its delegated
cgroup never took that path.

**`kern exec` runs where the box runs on a host with no cgroup delegation.** It refused (126, "would
run outside its caps") whenever the box's PID 1 was in the caller's OWN cgroup, which is where a box
stays when nothing could be delegated: the command is born there already and escapes nothing
(reported on WSL2, shell and box both in `/init.scope`). A box with a cgroup of its own and a real
cap still refuses, as before.

**A `--restart` box tells a workload's own `exit 125` from a box that could not be built.** From the
second attempt on, the supervisor reads whether the workload was exec'd and says `exited 125;
restarting`, where it said `never started` for every attempt; the first attempt says both causes,
because telling them apart there would cost every box start about 200 us (measured). kern's notices
are not repeated into the log by restarts: the first start printed them on the launcher's terminal.

**`compose up --wait` fails at once when a job dies beside a running service** (56 ms; it waited
5 s), and **`kern validate` and `config list` are linear in the number of profiles** (100,000
profiles: 150 ms, from 36 s).

**`kern --help` no longer says NCCL collectives crash in a box.** The `--gpus` help said the first
all-reduce crashes the process; `docs/FAQ.md` has said since 2026-11-12, measured, that
`ncclAllReduce` returns the right answer with one card and with two, and that the crash was a test
probe truncating a pointer. The help now says what the FAQ says.

**`kern info` names a WSL2 GPU**, from `/dev/dxg` (`1 x NVIDIA (WSL2, /dev/dxg)`), where it said
`gpu none` because WSL2 has no DRM card. **`kern sandbox history`** with only `kern box` rows held
says how many there are and points at `--all`, instead of "no finished sandbox recorded yet".

**`kern stop <name>` stops a running box whose registry record is gone.** `kern ps` already named
such a box, found by its cgroup or its processes, and `kern stop` still answered "no running box
named" (found by an external test). It now stops it as Docker does, SIGTERM to the box's init, the
grace, then SIGKILL, and says the box had no record in that directory; a name two unrecorded boxes
share is refused with both pids, and a recorded box is never stopped this way.

**A box started over SSH keeps its caps through a `daemon-reload`, and `ps` and `exec` still see it.**
From outside the user manager (an SSH session, cron, a system service) a box runs in its own
transient scope, made without `Delegate=yes`, and kern builds the box's cgroup inside it. Measured
on a Jetson Orin Nano (systemd 249, Linux 5.15) over SSH, four defects on that path. A `systemctl
--user daemon-reload` emptied the scope's `cgroup.subtree_control`, so the box lost its own
`memory.max` and `memory.oom.group`: only the scope's ceiling still bound, and an over-allocation
killed one process while the box lived on. The supervisor now watches that file (inotify, no
polling) and puts back the controllers and the limits it had applied; after a reload the box is
again killed whole at its own cap. `kern ps` did not name a running box whose registry record was
gone, because it never looked in per-box scopes; it does now. A `kern exec` killed with its box by
the OOM killer exited 137 with nothing said, for two reasons: the counter was read from the box's
own scope, which goes with the box, and Linux before 5.16 has no `oom_group_kill`, where `oom_kill`
(paired with the box's PID 1 dying, as before) is now read. And the `/proc` fallback that finds
boxes the registry lost now works on kernels built without `CONFIG_PROC_CHILDREN`, the Jetson's
included. On that board `kern doctor`'s GPU row also fits a terminal again.

**A box starts on a host that delegates only `pids`, where kern places it in a cgroup of its own.**
On openSUSE Leap 16, whose user manager delegates `pids` alone, every box kern could not hand to
the user manager (an `XDG_RUNTIME_DIR` without its socket) died "fork failed: Cannot allocate
memory". Two defects in series. kern enabled `+pids` on its own
cgroup while it was in it, which the kernel accepts and which makes every cgroup below it refuse
processes. And the box's pid namespace was made before the fork that cgroup refused: a pid
namespace whose first fork fails is closed for good, so the fallback fork had nowhere to go.
kern no longer enables a controller on a cgroup that holds processes, and the box's PID 1 is
created together with its pid namespace, so a refused fork leaves the fallback a namespace to fork
into (the closing measured on kernel 6.12 and 7.0). On that host `kern box` also stopped warning
that "a caller may be bypassing the resource limits": the root cgroup lists `memory` among its
controllers and enables only `pids` below it, and the check now reads what the root enables.

**Where SELinux refuses pasta, the installer labels kern so stacks reach the internet.** On openSUSE
Leap 16 (enforcing, passt-selinux 2025-04) pasta is refused every namespace of an unconfined process,
so no stack service and no one-off box reached the internet, with pasta's "Couldn't open user
namespace … Permission denied" as the only explanation. Making `pasta_t` permissive does not change
it; kern labelled as a container runtime, the type rootless podman runs as, does. The installer now
probes pasta on an enforcing host and, only where SELinux is what refused it, labels kern
`container_runtime_exec_t`, keeps the label only if the probe then succeeds, and otherwise puts the
old one back; where the type is missing it says to install container-selinux. Run as root it also
adds a file-context rule, so a relabel leaves the label in place (a plain `chcon` is undone by any
`restorecon`, measured); run as a user it prints that root command. `kern uninstall` lists the rule
and removes it as root. `kern doctor` runs the same probe on an enforcing host and warns only on that
refusal, and the refusal itself names the command.

**`kern box --network <project>_<network>` reaches the internet, as `docker run --network` does.**
A box joining a running stack's network reached its services by name and had no default route and
no `resolv.conf`. It now gets its own NAT, attached while it waits at its pre-exec gate exactly as a
service's is, and the host's resolvers; on a network the file marks `internal: true` it gets none,
as the services on it get none. The stack's pod no longer starts a NAT of its own when the stack is
on bridges, since no process is in its namespace: `compose up -d` of three services 44.2 to 31.0 ms
(medians of 30 alternated runs, one desktop).

**`kern top` never blocks a key on a long list, and the sandbox history has dates.** The Builds tab read
every build record on every 1 s refresh and Storage walked every volume, on the thread that reads
keys: on a desktop with 11961 builds and 556 volumes, the first visit took 51 and 60 ms and each
tab cost over 5 % of a core while shown. Builds now reads the newest 512 records and more as the
selection scrolls toward them, and keeps a finished record instead of reading it again; volume
sizes are measured by a child process and shown as they arrive. First visit 5.4 and 0.2 ms, idle
0.5 % of a core on every tab. `kern sandbox history` and the Sandboxes tab print the date with the
time, since the history outlives the day.

**`kern top` has a Logs tab: every box's output in one stream, live.** Each line carries its time mark,
its box and a level read from its text (a stack trace's lines take the level of the line they
continue); `/` searches (`a|b` for either, case ignored), `e` filters by level, `s` by the selected
line's box, `⏎` shows the whole line, `x` writes what is shown as CSV (`timestamp,object,message`,
the file readable by you only, a cell starting with `= + - @` prefixed so a spreadsheet does not run
it). It reads only while shown and only what was appended, woken by inotify; escape sequences a box
prints are removed whole. A box writing faster than a screen can show is skipped to its newest lines,
and the tab says so: measured with a box printing 290k lines a second, `kern top` used 0.7 % of a core
and answered a key in 0.3 ms (99 % and 3 ms before the skip). Esc on the tab clears its filters
before it quits.

**`kern logs --all`: every box's output in one stream, ordered by time.** Each line carries its box
(`web  | ...`, as `compose logs` prefixes a service); `-f` follows boxes started later too, `-t`,
`--since`, `--until` and `--tail` (per box) work as for one box. It is the Logs tab of `kern top`
for a script, and reads every line: nothing is skipped however fast a box writes. Docker has no
command for this.

**`kern doctor` says how full the disk and the log store are.** Two rows: the disk under kern's data
(volumes, builds, kept boxes) and the log store, each turning into a warning from 85 % with what fails
when it is full and the command that frees room. Percentages are `df`'s (used over used plus
available, rounded up), in `kern top` too, since the space root reserves is not writable by anyone
else: on one desktop 77 % of the total was the 82 % that predicts the error.

**A full log store is said, and a `--rm` box takes its logs with it.** Box logs live in
`$XDG_RUNTIME_DIR/kern/logs`, a tmpfs in RAM on a desktop, at most 32 MiB a box by default. When the
store was full the pump dropped output (never the box) and nothing said so; the log now carries
`kern: warning: N byte(s) of this box's output were dropped here` at the gap, so `kern logs`, `compose
logs` and the Logs tab show it. `kern top` colours the disk figure yellow from 85 % and red from 95 %,
shows the log store in the header when it is that full, and its Overview lists what fails and the
command that frees room (`kern gc`, `kern prune`); the Logs tab states where the logs are, how much
they take and how much of it is from boxes that ended. A detached `--rm` box that ran now removes its
logs at exit, as Docker does (one that never started keeps them: its launcher quotes them as the
reason). Measured on a desktop before: 142 MiB in the store, all of it from boxes that had ended.
The orphan sweep (every box start and `kern gc`) also covers `kern.slice` itself again, where a kern
from before `kern-boxes.service` built its boxes: since that unit, orphans left there by an upgrade
were never reaped.

**`compose down -t N` takes the grace it is given, and `up -d` and `down` lose their fixed waits.**
`down -t 0` waited each service's full default grace (10.27 s for three `sleep` services) because the
flag never reached the teardown. `down` then slept a flat 250 ms after stopping the stack's outbound
NATs, which leave in about 20 ms; it now polls and returns when they are gone. `up -d` no longer
waits 150 ms to see whether a service dies, since it exits 0 either way (`--wait` and an `up` that
stays keep the window). Measured on one desktop, medians of 15 runs of a three-service stack: `up
-d` 190 to 48 ms, `down -t 0` 10.27 s to 40 ms.

**A stack has Docker's names.** The project is Docker's: `-p`, then `COMPOSE_PROJECT_NAME`, then the
file's `name:` (which kern ignored), then the directory's name in lower case without what Docker
drops (`My.App_X` is `myapp_x`). kern named it `<directory>-<hash of the file>`, so every compose
file in one directory was a project of its own and a second directory of the same name was another.
Service boxes are `<project>-<service>-1` as Docker's containers are (a replica `-2`, `-3`, a
`container_name:` as written), so `kern exec usbim-assets-api-server-1` and `kern box --network
usbim-assets_usbim -v usbim-assets_data:/d` name what `docker exec` and `docker run` name. A `-p`
Docker refuses is refused with its words. Nothing is lost on the way: a stack still running under the
old name keeps it until its `down`, and says so; at the next `up` a volume named after the old project
is renamed to the new one, with its data.

**A one-off box reaches the stack it joins.** `kern box --network <project>_<network>` (or the
project's name) on a stack whose services sit on a bridge was put in the bridge's own namespace with
every name pointing at its own loopback, so the services refused it and a `container_name:` did not
resolve. It now takes a free address on that network, reserved against a second one-off started at
the same moment, and resolves every service, alias and box name of that network and of no other, as a
container on a Docker network does.

**`compose up`, `down`, `stop`, `start`, `restart`, `pull` and `cp` narrate on stderr**, as Docker
Compose does (measured: zero bytes on its stdout), so `out=$(kern compose up -d)` is empty; an attached
`up` still streams the services' output on stdout. `up -d` exits 0 when a service dies at once, as
Docker's does, and says so on stderr; `up --wait` still exits 1. `compose ps` prints Docker's table
(`NAME IMAGE COMMAND SERVICE CREATED STATUS PORTS`), with the image by its name and the command as
Docker writes it (`"sh -c 'echo a; …"`); its notes on degraded edges and stopped services moved to
stderr.

**`compose restart` and `compose start` return, as Docker's do.** On a terminal both followed the
stack's logs like an attached `up`, and Ctrl-C then stopped the service: `kern compose restart rest`
did not return, and interrupted it left `rest` stopped. Only `up` follows now.

**`ps --format` speaks Docker's fields.** `.Status` is Docker's sentence (`Up 4 seconds (healthy)`,
`Up 4 seconds (Paused)`, `Exited (3) 4 seconds ago`, `Created`) where it was the state word, which is
now `.State` (`running`, `paused`, `exited`); `.Health`, `.ExitCode` are new and `.RunningFor` is `5
seconds ago`. `--format "table ..."` prints Docker's header and aligns the columns as Docker does,
where kern printed the word `table` on every row. `compose ps --format` lists the services by name.
A script that read `{{.Status}}` for `running` reads `{{.State}}`.

**`compose logs` prefixes every line as Docker does**, `api-server-1  | a1`, with and without `-f`
and for one service too, where kern printed `=== name ===` headings; `--no-log-prefix` leaves the lines
bare. A service that had died and is brought back with `up --force-recreate` starts a new log, as a
new container does; its dead run's output was still shown.

**A compose file Docker refuses is refused, with Docker's message.** kern ran `command: [echo, 1,
true]`, `cap_add: SYS_ADMIN`, `version: 3` and `oom_score_adj: -2000`; Docker Compose 5.3.1 refuses
all four. Each file, and each `include:`d file, now goes through compose-go's own checks before kern
reads a service, on the verbs that build from the file (`up`, `start`, `restart`, `run`, `build`,
`pull`, `push`, `config`, `watch`, `systemd`); the read-only verbs (`ps`, `logs`, `exec`, `port`,
`stop`, `down`, ...) do not repeat it, and measure as before. The check reads the file a second
time, about 20 us per line (measured: +22 ms for a 1081-line file): the type conversions of its interpolation (`replicas: x` is `strconv.Atoi: parsing
"x": invalid syntax`), its list deduplication (`cap_add: [A, B, A]` is accepted, `cap_add: [A, 5]`
is not), and the Compose schema, vendored unmodified from compose-go v2.13.0. The message is
Docker's, word for word on the 37 files compared (32 refused, 5 accepted), with the file's absolute path: `validating
/srv/app/compose.yaml: services.a.command.1 must be a string`. An unknown key keeps kern's message,
which names the closest key.

**`compose config` prints the project as Docker Compose prints it.** kern answered with a summary of
its own; stdout is now the resolved file, byte for byte as `docker compose config` writes it on Docker
Compose 5.3.1 (51 files compared, including the differential suite): short forms expanded in
compose-go's field order, paths absolute, sizes and durations normalised, `env_file` read into
`environment`, overrides and `include:` merged, unused networks and volumes left out, and the YAML
emitter's quoting and folding at 80 columns. `--format json`, `--services`, `--images`, `--volumes`,
`--networks`, `--profiles`, `--variables`, `--hash` (the same digests), `--no-interpolate`, `-q` and
`-o` answer as Docker's do; `--format json` and `--volumes` used to print the summary instead, with
nothing said. kern's summary (the `wiring:` fields and the per-service lines) is on stderr. A value
an interpolation produced is a string, as compose-go reads it (`${UNSET:+x}` is `""`, not null).
Volumes, networks and variables are listed sorted, where Docker lists them in a different order on
each run.

**The container verbs of Docker's tutorials.** `kern create [OPTIONS] IMAGE [CMD...]` records a kept
box without starting it and prints its name; `kern start` runs it, `kern start -a` follows its output
and exits with its code, `kern restart [-t N]` stops a kept box and starts it again, `kern export <box>
[-o file]` writes a running box's filesystem as a tar (relative names, the box's own owners, without
what is mounted over it), and `kern container <verb>` groups the box verbs (`container ls` is `ps`;
`run`, `top` and `prune` are refused by name, because kern's verbs of those names do something else).
`kern run` is unchanged. Fixed on the way: `rename` of a kept box moved its registry entry and not
its layer, so `kern start <new>` found nothing; a box kept with `--name` could never start again;
`diff` refused a kept box and now answers for one running or stopped; `update --cpus 0.5 web` (flags
first) took `0.5` for the box; `update` of a kept box is kept for its next start; a raised cap stayed
under the systemd scope's old ceiling and now moves it; and a box started without `--cpus` says it
has no cpu controller to update rather than "permission denied".

**CLI surface, additive.** `kern rm -f` stops and removes a running box, and a missing name exits 0,
as `docker rm -f` does. `kern box --group-add <name|gid>` (compose `group_add:`) adds a supplementary
group, a name resolved in the image's `/etc/group`. `kern box --device /dev/X[:/dev/Y[:rwm]]` binds a
host node as docker does, beside `--gpus` too. `kern top` shows the GPUs: the title bar their count
and memory (`GPU none` without one), the Overview one row per card with memory, load, temperature,
power and the boxes holding it, a Jetson's integrated GPU included (its `nvidia-smi` is in `/usr/sbin` and
answers `[N/A]`, so the load and temperature come from `/sys`, and its memory is named as the RAM's). Its lists page with PgUp/PgDn and Home/End, and the Storage and
Profiles tabs no longer push their footer off the screen when a list is long. `kern sandbox ls|history|stats`
lists the SDK and MCP sandboxes running now and the ones that finished: one line of metadata per box
(time, name, image, run time, exit code, GPU and how it ended: `ok`, `exit-N`, `oom`, `timeout`,
`stopped`, `signal-N`), never its output; `--failed`, `--all`, `--json`, and p50/p99 in `stats`. `kern top` has the same as an eighth tab, **Sandboxes** (key `8`): the last hour, the ones running, the finished ones with Enter for one in full, and a line in the Overview. Where those lines are kept is a setting, `[kern] sandbox_history`:
`memory` (the default, cleared at reboot), `disk` (`$XDG_DATA_HOME/kern/history`, kept across reboots)
or `off`. `kern sandbox keep [memory|disk|off]` and the tab's `m` key change it and move the lines
already kept; the tab's caption, `kern sandbox history`, `stats` and `kern info` say where they are;
`kern sandbox clear` removes them. `kern compose --help` names the flags every verb
takes (`--allow-device-grants`, `--allow-privileged`, `--project-root`, `--pod`/`--no-pod`/`--bridge`).

**A box could hand the host kernel checksum metadata of its own choosing, and two socket families
were reachable with nothing behind them.** `virtio_net_hdr` is how a sender supplies
`csum_start`/`csum_offset` instead of a finished checksum, and the parser behind it is what a VM
guest reaches through virtio-net. Measured in a default box before this: `CAP_NET_RAW` is effective
in the box's own user namespace, `socket(AF_PACKET, SOCK_RAW)` opens, and both options that enable
the header were ACCEPTED, while the invoking user cannot open a packet socket on the host at all.
The filter answers `setsockopt(SOL_PACKET, PACKET_VNET_HDR)` and `PACKET_VNET_HDR_SZ` with
`ENOPROTOOPT`, what a kernel without the option returns; both numbers, because 24 enables the header
as a side effect of setting its size. `socket(AF_XDP)` joins `AF_VSOCK` on the `socket` rule with
`EAFNOSUPPORT`: it carries the same shape of caller-supplied offsets and it OPENED in a default box.

Nothing a box uses is lost. `AF_PACKET` still opens, `PACKET_VERSION` and `PACKET_RX_RING` are still
accepted and a frame is still captured on `lo`, so `tcpdump` captures and `ping` pings;
`CAP_NET_RAW` is kept, as other runtimes keep it. This is not a fix for CVE-2026-99999 or any kernel
defect, and `docs/CVE-POSTURE.md` carries the counts behind that sentence, including the pair that
differs in one bit: a box with checksum offload on took 97,608 arrivals at the software-completion
predicate and entered it 0 times, and the same shape with the box turning offload off on its own
`eth0` took 42,721 and entered it 4,282.

**`-p 80`, `-p ip::80`, `-p 0:80` and compose `ports: ["80"]` publish on a host port the kernel
picks**, as Docker does: one number for `0.0.0.0` and `[::]`, recorded before anything else, so
`kern ps`, `kern port` and `compose port` read it. kern refused the three `-p` forms and turned a
compose container-only port into one that was not published, which is how one file runs as several
stacks at once (one per pull request). `kern port <box> <port>` lists every binding of the port, as
`docker port` does.

**`--ssh` works again with the box-address change above**: the in-box sshd listened on `127.0.0.1`
while the forwarder moved to the box's address, so every connection was reset. sshd now listens
where the forwarder connects.

**A loopback `publish_bind` policy works on a host with IPv6 but no `::1`**, which is a common VPS
shape: the policy's IPv6 half is dropped when its own address cannot be bound, where every `-p` was
refused before. `Address not available` is said as what it is (the host has no such address) instead
of "held by something else".

**A compose stack whose later service is refused leaves no pod behind.** The guard that removes an
empty pod ran before the gates of the prepared services closed, so it held them and kept the pod
with its holder process, after every such failed CI job.

**A published port no longer reaches a box's loopback, and its clients no longer arrive as
loopback.** `-p` forwarded to the box's `127.0.0.1` from `127.0.0.1`, so a service listening on its
loopback only was published anyway, and every client from the network looked local to the server:
measured from a LAN address, a listener bound to `127.0.0.1` answered 200, and Redis in protected
mode with no password answered `+PONG`. Docker answers nothing and `-DENIED`, and so does kern now.
A box that publishes, joins a pod or is a compose service has an address of its own (`192.0.0.8`,
RFC 7600's dummy address, on its `lo`), its name resolves to it, and a published port and a peer
relay reach the box there, from there. A service bound to `127.0.0.1` is therefore not reached by a
peer by name either, in a pod, on a bridge or through `--no-pod` relays, which is Docker's rule;
members of one pod still share `localhost`. When a published port finds only a loopback listener,
the box's log says so once. A box with nothing to reach it (an SDK cell, an MCP call) gets no
address and pays nothing.

**`-p` publishes on IPv6 too, read the way Docker reads it.** `8080:80` binds `0.0.0.0` and `[::]`,
`[::1]:8080:80` and `[::]:8080:80` bind that address only, `::8080:80` is refused with Docker's
`invalid IP address: :`, and a host without IPv6 drops the `[::]` half. UDP works over both.
`publish_bind = "127.0.0.1"` holds both families to loopback. `compose up` refuses a malformed port
spec before creating anything, naming the service, as `config` did.

**`network_mode: service:X` joins X's network namespace, on every wiring, and `kern box --network
container:<box>` does the same.** On a bridge the key was not honoured, so a client put behind a VPN
container reached the network directly; a file that also used `networks:` was sent to the relays,
and one without was run as a single namespace for the whole stack. The joining service now shares
X's loopback and route, takes X's hostname, hosts and resolvers, has no address or name of its own,
starts after X, and its `ports:` or `hostname:` are refused with Docker's words. Measured against
Docker on one file: the same namespace for both, the VPN's loopback port read, the internet reached
through the VPN, a peer answered by the client at the VPN's name.

**`compose up --abort-on-container-exit --exit-code-from tests` returns when the tests do.** A test
service that exited before kern began following the logs was skipped, so its output was never shown
and `up` waited on a database that never exits, until the job's own timeout. A test that exited
inside the 150 ms start window was reported as "died", exited 1 whatever the test returned, and left
the stack running. Both now end the wait, the stack is torn down, and the status is the test's.

**A code sandbox written as a compose one-off runs as written.** `compose run --rm -v SRC:DST[:ro]`
mounts the file: `-v` was taken for the service name. A bind inside a `tmpfs:` (the script mounted
into `/tmp`) is mounted after the tmpfs, so it is no longer hidden under it. A one-off of a
`network_mode: none` or `host` service no longer joins the stack's pod, where it had outbound. Measured
against Docker on one file: the script runs, with `lo` as its only interface.

**A YAML block scalar in a list is text, even with `: ` inside.** `command: [sh, -c]` followed by a
`- |` item holding `echo "a: b"` was read as a mapping, so the script the service ran was not the one
in the file, with no message. The block's lines now reach the command unchanged.

**A service's `compose logs` spans its restarts, and `down` removes them.** After two `restart`s the
log held one run's lines, so the output of a run that crashed was gone once it was restarted; it holds
all three now, oldest first, and `--tail N` counts across them. `down`, and a recreate by `up`, remove
the old runs, and `logs` and `up` accept `--no-color`.

**A stack leaves no exited row in `kern ps -a` after `down`, and a restarted service is one row.** A
`network_mode: service:X` box was recorded with no pod, so `down` never removed its row (one per run).
A service that exits on its stop signal, as sshd does, had its record written after `down` had cleared
the stack's, one run in three; `kern stop` now returns once the box's supervisor has finished (5 ms
for such a box on WSL2). `compose restart` and a recreate by `up` no longer
leave the stopped run's row beside the new box.

**`kern stop` and `compose down` no longer wait out the grace on a box that has already exited.** On
a host without cgroup delegation, a box whose workload exited on the stop signal before the teardown
reached it was waited on for its whole remaining grace: `down` of a service that traps SIGTERM beside a
`sleep` took 10.3-11.5 s in 5 runs of 12, and takes 274-347 ms in 12 of 12. The box keeps the exit code
it chose.

**`allow_gpu_grants = true` in your own `kern.toml` lets a compose file take the GPUs it asks for, and
no other device.** `gpus:`, a `deploy` reservation, `runtime: nvidia` and `nvidia.com/gpu` CDI names
pass with no flag, which is the decision docker's users make once by installing the NVIDIA container
toolkit. A `devices:` node, a CDI name of any other class and a device profile still need
`--allow-device-grants` or `allow_device_grants`, which open every device. Read only from your own
config, as `allow_device_grants` is.

**`compose ps SERVICE...` lists those services, and `compose ps -q` prints IDs.** The services named
were ignored, so `ps -q stable` printed the whole stack. `-q` printed each box's name, which a
recreate does not change, so a script comparing `ps -q` before and after `up -d` could not see what
was recreated; it prints the box's ID now, its supervisor pid, which `kern stop`/`exec`/`logs` and
`--filter id=` already take and which a recreate changes. `ps --format json` carries the same `ID`.
`kern ps -q` still prints names.

**A compose teardown stops a service as Docker does.** `down`, `stop`, `restart`, a recreate and
`--abort-on-container-exit` now wait the grace for an init that cannot hear SIGTERM (a Python or
`sleep` PID 1 with no handler), returning as soon as it exits, where kern killed it on the spot: a
job that was finishing lost its result. The stop signal goes to the init alone, as Docker sends it,
not to the box's whole process group, so a shell script's running child is not killed under it. A
`down` of a stack whose services are a `sleep` therefore takes their grace, 10 s by default, as it
does under Docker; `stop_grace_period: 0s` or `down -t 0` kills at once. `kern stop` and the sandbox
SDKs keep the immediate stop.

**Compose surface, measured against Docker.** `compose run --entrypoint "sh -c 'exit 42'"` splits the
string as a shell would (it looked for a program named `sh -c 'exit 42'`). `COMPOSE_FILE` (split on
`COMPOSE_PATH_SEPARATOR`, `:` by default) names the files when none is given. A key that is not in
Docker's compose schema is refused, as Docker refuses it, instead of starting the stack with a
warning: the 92 service keys and 9 top-level keys Docker Compose v5.0.2 accepts were measured one by
one, a key among them that kern does not act on still warns, and a typo names the key it is one edit
from. kern's TOML spellings (`health_cmd:`, `depends_healthy:`) in a docker-compose.yml are refused
the same way, with the YAML to write. `--abort-on-container-exit` stops the stack when a run ends even
if a restart policy would start the next one, and the service's status is that run's code. A project,
pod, volume, network or secret name may be 200 bytes long (it was 64, and Docker accepts a 72-byte
project name). `ps`, `down`, `stop`, `logs`, `exec` and the other verbs that act on what is running
reach a service behind a profile that is not active, as Docker's `ps` does; `down` stops it, where
Docker's leaves it running. `compose top` prints Docker's table (SERVICE # UID PID PPID C STIME TTY TIME CMD, one for the
stack) instead of PID and COMMAND per service. `up --abort-on-container-exit` keeps streaming every
service's log while the stack stops, as Docker's does, so the last lines of a service still working
when another exited are no longer cut off. A missing bind source is created `0755`, as Docker's
daemon creates it (it took the user's umask, `775` under umask 002).

**`ipc: shareable` and `ipc: "service:X"` share an IPC namespace and `/dev/shm`, as Docker does.**
kern gave every service its own and said so. A service that is `shareable` keeps its `/dev/shm` in a
directory under the runtime dir, and a service naming it joins its IPC namespace and binds that
directory, starting after it; a donor that is not `shareable` is refused with Docker's "non-shareable
IPC". `kern box --ipc shareable` and `--ipc container:<box>` do the same for two boxes of one pod
(an IPC namespace is entered from the user namespace that owns it, which a pod's members share).

**A host port range onto one box port takes a free port of the range, as Docker does.** `-p
8080-8095:80` (compose `ports: ["8080-8095:80"]`) was refused as malformed; the box now gets the first
port of the range that is free on every address it binds, picked at start, and a box finding the whole
range taken is refused with Docker's "port is already allocated".

**`up --scale SERVICE=N`, `scale:` and `deploy.replicas` run one box per replica.** kern refused
`--scale` and warned that it ran one box per service. Replica 1 keeps the service's box name and
replica N is `<project>-<service>-N`, each with its own network namespace, address and ports (a host
port range gives each a port of it, a `"80"` each a random one, one fixed host port is refused with
Docker's "port is already allocated"); the replicas start one after another. `ps`, `logs`, `stop` and
`down` naming the service reach every replica, `port --index N` and `exec --index N` reach one, and an
`up` without `--scale` brings the service back to the file's count, stopping the replicas above it, as
Docker's does. `container_name` cannot be scaled.

**A replicated service's name lists every replica, and a running stack can be rescaled.** `web`
resolved to replica 1 alone and a replica's key `web-2` resolved too; under Docker `getent ahosts web`
lists every replica and `web-2` is not a name, only `<project>-web-2` is. kern's hosts files now say
the same, each box starting the list at a different replica so clients spread over them (Docker
shuffles at every query; a hosts file cannot, so the spread is between clients). Rescaling a stack
that is up gave the new replica the bridge address a running service still held (measured: `web-3`
and `cm` both on 10.89.0.4, `cm` unable to reach it): a running box now keeps its address, recorded
in the registry, whatever is added around it, and the boxes left running learn the replicas an `up`
started or stopped. Under `--no-pod` the same holds for the loopback aliases (recorded per stack): an
alias moved by position used to hand a running box's name for `api` to the new `web-3` relay, and a
running client did not learn the new replica.

**A service that fails to start stops its dependents and nothing else.** The first service to fail
ended the bring-up, and with every box held at its pre-exec gate that meant no service ran at all.
Measured on Docker with one service's host port range held by another process: `up -d` exits 1 naming
it, and every service that does not depend on it, replicas included, is running. kern does the same
now, names the services held back (`not started, dependency failed to start: e`) and how many are
running, and still exits 1. A configuration Docker refuses when it creates the containers (a
`mem_limit:` below what a box can start with) still starts nothing, as under Docker, which creates
every container before it starts one: every service's flags are read by the box parser before the
first box is prepared.

**`COMPOSE_FILE` in the `.env`, and a compose file in a parent directory, as Docker reads them.** With
no file named, the working directory's `.env` (or `--env-file`) gives `COMPOSE_FILE` and
`COMPOSE_PATH_SEPARATOR` when the shell does not, and its values win over the project's `.env` for
interpolation; under `-f` it is not read, and a list from `COMPOSE_FILE` loads no default override, as
under Docker. With no file in the working directory, the nearest parent holding one of Docker's four
names is used. A parent's file that belongs to another user, or is a link that does, is not run: a
note names it and its owner, and `kern compose <file>` runs it.

**The `ssh` command `--ssh` prints works on every launch.** The box made a new host key each time,
and the printed `accept-new` pinned the first one in `~/.ssh/known_hosts`, so the second box on the
same port was refused with `Host key verification failed`. kern now makes the box's host key and a
`known_hosts` naming it, and the printed command checks strictly against that file: no prompt, any
other key refused, and `~/.ssh/known_hosts` is not written. A box refused for a taken `--ssh` port
prints no `ssh` command and leaves no keys behind.

**A box with outbound could reach what the host keeps on `127.0.0.1`.** pasta gave the box the
host's address and gateway and mapped that gateway to the host's loopback, so a compose service or a
`kern box --pod` box connecting to the gateway reached every loopback-only service: a `kubectl
port-forward`, a kind API server, a docker TCP socket, a dev database. Measured before this: a
canary bound to `127.0.0.1` answered a box connecting to `192.168.1.1`. A box now has an address of
its own (`10.0.2.15`, gateway `10.0.2.2`, another /24 when the host or the box already routes that
one) and the gateway maps to nothing. It reaches the host at the host's address, what the host
serves on its interfaces and not its loopback, measured closed on every path probed on a desktop and
on WSL2 as root and as a user. `host-gateway` (`host.docker.internal`) is the host's address now,
and a published port answers through it from a compose service. On a host that resolves through
systemd-resolved's stub, a box's resolvers are the stub's upstreams instead of `1.1.1.1`, so a
network that blocks outside DNS, or a VPN's own names, resolve in a box too.

**A GPU box starts faster: 31.3 to 13.9 ms on WSL2, 82.0 to 44.2 ms on a Jetson** (`python:3.12-slim`).
The image's `ldconfig` runs for the first box of an image and grant, and the next ones get its cache
and the soname links it made back from kern's cache directory. The grant is decided once per box
instead of twice when the box takes a systemd scope, and a directory of read-only driver files is made
read-only once instead of remounting each file. On WSL2 the search of the Windows driver store, which
is mounted over 9p, is remembered and re-checked instead of walked for every box. A box without a GPU
is unchanged.

**Compose names the right reason when `ipc:`/`pid:` names another service:** every service has its own
namespace; the warning said the stack shared one network namespace, which is no longer so.

**A killed box no longer leaves its environment file behind.** A box ended by SIGKILL (as the SDKs and
the MCP server end a prewarmed box) left its `env/` and `health/` files in the runtime directory;
500 MCP calls left 99 of them. The record and its files now go together.

**A large layer downloads over eight connections at once.** A layer of 256 MiB or more is fetched in
byte ranges in parallel, joined and checked against its digest; `ollama/ollama` (one 3.25 GB layer)
pulled cold in 610-795 s instead of 23 minutes on the same link. `KERN_NO_RANGED_PULL=1` turns it off.

**Compose asks for the GPU grant only for what it starts.** `up -d agent` or `run agent` on a file
whose other service takes a card no longer needs `--allow-device-grants`, and `compose cp <local file>
<service>:<path>` no longer reads the local file as the compose file.

**Two GPU examples.** `examples/compose/gpu-per-service.sh` runs a `docker-compose.yml` with one card
per service behind nginx, and `examples/agents/gpu-sandbox.py` gives each sandbox its own card from the
SDK. Both say what a grant does not give: a VRAM limit, or a boundary against the code on the card.

**A compose stack is no longer left broken and called fine.** A service with a relative bind
(`./app:/app`) is up to date on the next `up` instead of recreated every time; a pod whose holder died
is named on `kern ps` and recreated by `up`/`start` instead of reported "already up to date"; a
`restart` refused for an ungranted GPU stops nothing.

**Compose GPU messages say what happens.** A service with `runtime: nvidia` and
`NVIDIA_VISIBLE_DEVICES` is no longer told it gets no card (it gets the one named); `capabilities:`
beside `gpu` reach `--gpus` and get its note that a grant binds the driver's whole library set; a
refusal of several GPU services no longer ends with the file-format hint.

**A compose file whose `networks:` separate services gets a bridge per network.** Each network is its
own bridge (on the subnet the file declares for it), each service is attached to the bridges of its
networks only, and the pod does not forward between them, which is Docker's arrangement. Such files
used to get the relay wiring, which reached a peer only on the ports it declared: a service on an
image that EXPOSEs nothing was reached by name and answered by the CALLER's own listener. Peers are
now reached on every port, with no `expose:`. `kern pod create --bridge` is repeatable and
`kern box --pod-bridge <ip>/<n>@<b>` joins bridge `b`. A `links:` alias on a bridge named the
service's own `127.0.0.1` instead of the peer; it names the peer. The `networks:` sentence is said by
the verbs that choose the wiring, not by `exec`, `ps` or `logs`.

**As root, an image that was loaded, built, tagged or committed did not run by its name.** Only a
pull marked the cache entry with the uid map its files were written under, so as root every other
entry was read as stale and sent to the registry to be repaired, where a local image does not exist:
`cannot access 'library/<tag>' on registry-1.docker.io`. Every writer marks it now; a tag carries its
source's mark.

**One line per box in the sandbox history, and it says what ended it.** A box ended by `kern stop`
was recorded twice (`exit-143` and `stopped` for one run); it is recorded once, as `stopped`, by the
process that owned it. A detached box's line now has its image, GPUs, a run time to the millisecond,
and `oom` or `timeout` where those ended it, as a foreground box's line already had.

**An exported but empty `XDG_DATA_HOME` or `XDG_CACHE_HOME` put kern's data under the current
directory.** Named volumes, build records, kept boxes and the image cache were written to
`./kern/...` relative to wherever kern was started, while both SDKs, reading the empty variable as
unset as the XDG spec says, refused `~/.local/share/kern` as a mount source and not that directory.
An empty or relative value now means unset everywhere, through one resolver.

## kern sandbox 0.2.50 - 2026-11-17

**It carries the kern v0.51.0 binary.** Both bindings move together.

**kern sandbox refuses a mount source that holds a refused path or a credential directory.**
`mounts={"/home": ...}` was accepted while `~` was refused, and the box read `/home/<you>/.ssh` and
`.bash_history` (reported by an external test). A source is now refused when it contains your home,
a host credential path, a refused host path (`/run` holds the docker socket) or kern's own state,
and when a credential directory or file (`.ssh`, `.aws`, `.gnupg`, `.kube`, `.config/gh`, a shell
history...) is among its first two levels. `.npmrc`, `.pypirc` and `.docker` are not scanned for,
because projects carry their own; the scan reads one entry at a time and stops at the first hit,
and a source whose listing does not come back within 10 s, or whose scan fails, is refused rather
than accepted unchecked. A filesystem that never answers leaves the scan thread in the kernel's
uninterruptible wait: the call returns refused, and the process cannot exit until that filesystem
answers or is unmounted, which no code above the kernel can change. Python and Node the same. A
`kernel()` cell calling `os._exit(N)` on a host without cgroup delegation read as `killed` with exit
-1 in Python (Node already said exit N); both now report the cell's own exit.

**kern sandbox refuses the host's credential files as mount sources, not only `/etc` whole.** A
mount of `/etc/shadow` (or a link to it) was accepted while `/etc` itself was refused, and a box
started by root printed the password hashes (found by an external test). Refused now in both
bindings, with everything below them and through symlinks: `/etc/shadow`, `/etc/gshadow` and their
`-` backups, `/etc/sudoers` and `sudoers.d`, `/etc/ssh`, `/etc/ssl/private`,
`/etc/security/opasswd`, `/etc/krb5.keytab`, `/etc/wireguard`,
`/etc/NetworkManager/system-connections`. The rest of `/etc` (`resolv.conf`, `hosts`, `localtime`)
stays mountable. Shell and database-client histories (`.bash_history`, `.zsh_history`,
`.psql_history` and the like) join the refused credential names: what was typed is where a password
passed on a command line ends up.

**`image=None` in the Python SDK is the default image**, as `image: null` already was in Node. It
raised a `TypeError` from `subprocess`; an empty or non-string image is refused by name in both SDKs
before anything runs, where `""` first built a bytecode cache for an empty reference. An empty
`KERN_MCP_IMAGE` is unset, as every other `KERN_MCP_*` variable reads it.

**The SDKs re-extract an older cached image when the session opens.** An image cached by an older kern
(without its setuid bits) was downloaded again by the first box, inside the first call's deadline: a
first `kernel()` cell could time out at 30 s. The session's own image fetch now does it, on its 900 s
budget, and the first cell runs at once.

## v0.33.0 - 2026-10-17

**`kern image inspect` emits the labels and healthcheck it already parsed.** `Config.Labels` was in
no output, `Config.Healthcheck` not in the JSON, so source, version and licence
(`org.opencontainers.image.*`) read as absent.

**`kern compose exec` no longer builds.** It enters a running box (else "is not running") but first
ran and printed all of `build:`. Now it builds nothing, as `docker compose exec` does.

**`kern compose start` and `restart` stop printing `up`'s note.** All three non-streaming
verbs got a note naming `up`, a `-d` flag they lack and parity with `docker compose up`. It now
names the verb that ran, from the one verb table.

**`kern exec` works on hosts where it used to refuse outright.** In a shell in `/init.scope` (every
WSL terminal) or an `ssh` session on Ubuntu 24.04, Fedora 44, Debian 13 and Rocky 10.2, kern runs
outside the cgroup tree it delegates. cgroup v2 delegation containment needs write access to the
common ancestor, the root, so `kern exec` and `kern compose exec` exited 126 beside a working box.

The scope, without resource properties, is `kern-exec-<pid>.scope`, not the
`kern-box-` prefix of reapable cgroups. Without a user manager the refusal stands, saying so.
`KERN_NO_SCOPE` skips it, as for `kern box` and `kern run`. `kern doctor`'s scope-toll row no
longer claims a refusal.

**A build could reuse a half-deleted layer and say `built`.** `kern gc` reclaimed unreferenced
layers with `remove_dir_all`, which stops at the first unwritable directory: a layer with a
subuid-owned file or read-only directory stayed on disk, uncounted, maybe without its `.ok`
sentinel; with it, the cache took the partial layer as complete. The sentinel now goes BEFORE the
directory, so a partial removal is a cache MISS (a rebuild). Removal uses the forced, id-mapped
remover of `rmi` and `volume rm`, so a layer they would reclaim is no longer left behind.

**`gc` and the `kern top` Images tab say what they could not reclaim**: bytes left and layer key,
once dropped silently. A note, not an error: the sweep removed all it could, and the exit code
says so.

**A pull that could not be read reported a private repository.** `manifest_error` matched words in
the body, so an EMPTY body (dropped, timed-out or proxy-filtered connection) gave "cannot access
'<repo>' ... it may be private (run `kern login`)". Reproduced under load on `library/alpine`.

**`kern exec` inside a user namespace no longer waits 25 seconds to fail.** The fix above keyed
cgroup placement on `getuid()`; inside `unshare -Ur` uid is 0 but the cgroup path says
`user@1000.service`, so kern asked a manager with no `user@0.service` for a transient scope.

**`kern doctor` stopped contradicting itself in one sentence.** A row named the cgroup it probed and
said "user manager delegates: none readable" about it, 10 out of 10 runs: runtime and doctor spelled
the delegated root separately; one owner now.

**Nine documented claims said more than the code does, and a gate now refuses the second one.** The
README's lede, both package READMEs, `docs/MCP.md`, `docs/SANDBOX.md`, `docs/CVE-POSTURE.md`,
`docs/RESOURCES.md`, `docs/FAQ.md` and `SECURITY.md`'s in-scope list overpromised: "cannot touch
your machine" while `workspace=` is a host directory the box writes; an allowlist "always on"
despite `KERN_SECCOMP=denylist`; credentials "never in it" three lines above "only what you pass
with `env=`". `scripts/retired-claims.py` refuses retired strings in user-facing text, each dated.

## kern sandbox 0.2.49 - 2026-10-17

**It carries the kern v0.33.0 binary.** Both bindings move together.

**`workspace_max_bytes` is overshot by far less, by an amount set by what the workspace costs to
MEASURE.** The poller ran once a second, whatever the limit: a 50 MiB cap stopped a box at
5,964,300,288 bytes (113.8x), a slower disk at ~933 MB. The interval now scales with headroom,
floored at 1 ms; between walks a cheap probe re-checks the eight biggest files and directory
fingerprints.

⛔ IT IS NOT BOUNDED BY THE CAP (an earlier draft said it was). Headroom held at 50 MiB,
pre-existing file count varied:

| files  | Python  | Node    |
|--------|---------|---------|
| 0      | 1.26x   | 1.30x   |
| 1,000  | 1.32x   | 1.80x   |
| 10,000 | 4.12x   | 8.40x   |
| 50,000 | 12.88x  | 12.80x  |

An interval cannot undercut one walk: the bound is walk time times write rate; Node walks slower
(19.85 ms against 13.17 ms, same 10,000-file tree). The `workspace_full` fault gives these figures.
A fix needs a non-O(files) measurement that still counts hard links once, refuses symlinks and lets
a closed directory refuse the call, or it defeats the cap. The cap is a measurement and a kill on a
host directory, not a filesystem refusal.

In Node the backoff bounding the poller's cost never ran (Python's did): its timer started after
the walk and read zero.

**A file the box left at mode 0 is refused as a FILE, and as yours.** For a caller-owned file,
`read_file` said "a directory on that path is closed to this process and its owner bits could not be
restored - it is not ours (a `user=` session's box account owns it)", wrong in subject, owner and
`/proc` hint; `write_file` too. Both now report file, mode, owner and whether the owner is this
process; kern keeps a mode-0 file as written, since mode can be data. A closed DIRECTORY
keeps `snapshot`'s wording, which lists causes, now shared by every surface.
## kern sandbox 0.2.48 - 2026-10-13

**Carries kern v0.32.0** (`--egress-allow` `Host:` check, below); binding code unchanged since
0.2.47. Package descriptions no longer say the workspace cannot be bounded (two sentences, false
since 0.2.47); they say the cap is measured during a call, and what it still is not.

## v0.32.0 - 2026-10-13

**Minor bump: `--egress-allow` refuses a request it used to forward.** Under an allowlist, a
plain-HTTP head whose `Host:` is not the vetted request-target, or is doubled, gets 403 (a port-80
escape). The check follows the allowlist, so refusals cannot probe it. Over HTTPS (header inside
TLS) a shared CDN still allows it (`docs/EGRESS.md`). Binary otherwise unchanged since v0.31.0.

## kern sandbox 0.2.47 - 2026-10-13

**A call that filled the workspace used to succeed.** `workspace_max_bytes` was checked between
calls only (one call wrote 8,115 MB in ten seconds past a 50 MiB cap; the NEXT call was refused).
Now enforced WHILE a call runs, it stops the box mid-call with the new additive `fault.type`
`workspace_full`; `KERN_MCP_WORKSPACE_MAX_MB` exposes it on the MCP server (withheld while checked
between calls). Carries kern v0.31.0, the install line's binary.

- A `chmod 0` in the box no longer ends the session (the host-side walk's bare
  `PermissionError`/`EACCES` in reporting lost the finished call's result and failed every later
  call).
- Refusals name the mechanism, not the errno: symlinked directory in a READ or listing (was
  `[Errno 20] Not a directory`; writes already named it), non-directory path component, readable
  but unwritable directory.
- On failed repair, `snapshot()` and workspace sizing name what they could not read (was a bare
  permission error). Node no longer counts an unreadable directory as zero bytes, a permanent
  cooperative-cap bypass.
- Docs: `docs/MCP.md` covers the unbounded default, measured rate, new cap and a non-root recipe
  (`$XDG_RUNTIME_DIR` is already a sized tmpfs; new sized mounts need root); `docs/SANDBOX.md`
  the one host change in a workspace and what it does not buy.

## v0.31.0 - 2026-10-10

**`kern run --memory` REFUSES a cap it cannot apply** instead of printing "the command runs
UNCAPPED" and running; a command that worked yesterday may stop. The verb governs only resources.

- A cgroup kern did not write proves `--memory` only with bounded SWAP.
- Caps bind when `$XDG_RUNTIME_DIR/systemd/private` refuses connections under a live user manager.
- Proven ceilings are no longer called UNCAPPED.
- `kern exec -u <user>[:<group>]` runs as a box account (name or number), not only root;
  `kern exec -u` survives the capability switch under `--cap-drop ALL`.
- `kern rm` no longer cites a contradicting listing.
- A detached box unable to enforce caps says so on the terminal, not only its log.
- `kern inspect --json` no longer reports `"memory_max_enforced": null` for a kernel-capped box.
- `kern images` says whether "no images cached yet" is the whole truth.
- A box no longer inherits the supplementary groups of whoever typed `kern box`, nor keeps kern's
  when refusing the image group list (one gid outside the uid range).
- kern sandbox: `user=` (Node `user`, `kern-mcp` `KERN_MCP_USER`) runs every box, `persist`
  included, as an image account; both bindings reach every path by descriptor in listings
  (`result.files`, `list_files`), `snapshot`, `restore` and `write_file`'s new directories.
- Compose stacks on an `external:` network no longer write outside the other project's box.

36 more entries: `git log v0.30.2..v0.31.0`.

## kern sandbox 0.2.45 - 2026-10-05

**Both packages carry kern v0.30.2**: a `persist=True` call `kern exec` refused (below) is
`startup_failed` with kern's message, not a faultless exit 126 (126 with an older kern).

**Output printed before an OOM, a timeout or `os._exit` reaches the caller on every path**, not
only the cold box (0.2.43). The prewarmed box (most `kern-mcp` calls) and resident kernel sent
output in the cell's closing reply, never sent by a killed cell.

**One outcome per cell, on any box.** Prewarmed box and kernel: `os._exit(N)` gives `exit_code=N`,
no fault (was `killed`); a kernel timeout gives 137 (was -1), tearing the kernel down like a
one-shot box.

**`kern-mcp` defaults to `ghcr.io/getkern/kern-sandbox:0.2.44`** (digest-pinned, amd64/arm64):
python 3.12, numpy, pandas, matplotlib, node 22, as the tool description says. Plots and
`language="node"` need no `KERN_MCP_SETUP` or other image.

**A sandbox pulls a missing image at open, on its own budget**, not in the first call's deadline
(Jetson, empty cache: `startup_failed` at the 30 s default). A failed pull changes nothing and is
reported as before.

The `persist` docs' 2 ms per call was `kern exec` alone; a resident call starts a fresh `python3`,
costing about a fresh box (11.4 against 13.9 ms, one host). `sbx.kernel()` is the fast path.

## v0.30.2 - 2026-10-05

**`kern exec` no longer reports a refused command as started.** Unable to cap it (box at
`--pids-limit`, or a shell outside kern's delegated cgroup tree, e.g. plain ssh), it exits 126 but
wrote "started" on `KERN_STARTED_FD`, so an SDK read the refusal as the code's own 126. Now it
writes nothing, like `kern box` for a never-started box.

- `kern save`/`kern push` images can base a `podman build` (config carries the per-layer
  `history` entry buildah requires).
- `kern box --help` documents `--user` taking an image `/etc/passwd` name (always worked).

## kern sandbox 0.2.44 - 2026-10-04

**Both packages carry kern v0.30.1**: a resident sandbox (`persist=True`, Node `persist: true`)
reports an OOM as `oom` (was `killed`) and a cell's own `exit(137)` as an exit, not an external
kill. Measured in both bindings; an older kern on `PATH` still gives `killed`.

## v0.30.1 - 2026-10-04

**A compose `devices:` entry needs `--allow-device-grants`, as documented.** kern 0.30.0 granted
`/dev/kvm` or a GPU's modeset node without it; such files now stop, naming the service and every
node.

**`kern save`/`kern push` work on Debian- and Ubuntu-based images with a subuid range.** They
failed on `python:3.12-slim` and derivatives (`/var/cache/apt/archives/partial` belongs to a
subordinate uid; Alpine unaffected). `kern gc` also removes copies `--pull always` retired there.

**`kern exec` tells an SDK how the command ended** (`fault.type == "oom"`, a cell's own
`exit(137)` as an exit; see kern sandbox 0.2.44).

**A `-v` under `/sys/devices` reaches the box** (kern's CPU topology covered it).

**A base image without `/bin/true` builds layered**, not flat blaming the kernel ("unprivileged
overlay unavailable").

**`kern inspect` finds built images**: it said "nothing named" for every `kern build` image
`kern images` listed.

**Three messages fixed:** compose `gpus:` is Docker's GPU request, not a typo for `cpus:`;
`kern pull` names `kern box … --pull always` to refresh; a cached-image read failure no longer says
to check the name.
## kern sandbox 0.2.43 - 2026-10-04

**`npm install kern-sandbox` brings kern; both packages carry kern v0.30.0**, realigning Python and
Node. On Linux x64/arm64 npm ships kern's static release binary (`install.sh`'s file), used after
`$KERN_BIN`, before `PATH`, as in the wheels.

**One-shot cells no longer inherit the caller's stdin** (under `kern-mcp`, the JSON-RPC transport:
a cell could read another call's bytes). `input()` gets EOF.

**Warm/resident boxes from another posture are not reused.** Prewarm key and `persist` fingerprint
share one function: argv, every `KERN_*` variable read at build, the resolved
`vcpu:`/`vgpio:`/`vdisk:` profile. A changed `kern.toml` or `KERN_SECCOMP` used to keep the key.

**The wheel's kern is matched by RECORD hash, not path.** `pip install --target DIR` puts a RECORD
entry two levels above `DIR`; a kern there won. Now bytes must match; `DIR/bin/kern` is found.

- **`persist=True`** (Node: `persist: true`): one resident box per `name`, calls via `kern exec`, 2
  ms vs 6 ms fresh; adoptable across processes. Needs `name` and an explicit `workspace`.
- **`workspace_max_bytes`** (Node: `workspaceMaxBytes`): cooperative workspace cap across calls;
  the exceeding call runs, the next is refused.
- Output survives OOM or timeout (unbuffered interpreter).
- `os._exit(0)` under a memory cap is a clean exit, not an external kill.
- `language="node"` on the default image (no node) is refused, naming the remedy.
- MCP caps streams at the reply budget: printing 100 MB cost 129 MiB server memory for 16k
  characters, now 3 MiB.
- MCP answers `-32700` for every id on a line not holding one message (two frames, a cut frame);
  refuses `NaN`, `Infinity`.
- `index.d.ts`: eight missing constructor options (incl. `persist`, `requireLimits`), `destroy()`;
  `depsReadonly` defaults to true, not false.

## v0.30.0 - 2026-10-04

**kern flags outer limits that stall instead of kill.** An outer cgroup's `memory.high` throttles,
so the box hangs to its timeout: with `MemoryHigh=80M` on `kern.slice` a 0.06 s OOM took 317 s. A
`kern: note:` names cgroup and fix; `kern doctor`/`kern inspect` report it (`memory_high_outer`,
`memory_high_outer_cgroup` in `--json`); `--require-limits` refuses.

**`kern box --show-config` prints profile grants**: `devices:`, `sysfs:`, `vdisks:` after
`privileged:`, sorted, `-` if empty. Before, two device grants under one name printed identically.

**Windows `kern.exe` shows and selects its WSL2 distro:** `kern wsl list [--probe] | status |
use <distro> | reset`. `use` warns when `KERN_WSL_DISTRO` is set (it wins).

**`kern compose restart` no longer hangs on a completed one-shot dependency** (waited 120 s,
exited 1, service left down; `service_healthy` too).

**`kern doctor` no longer says "ready" where a box dies at the `/proc` mount**; flags multiple
kerns with differing versions.

**The two-services-one-internal-port note names both and the port**; `ps`, `restart`, `logs` drop it.

**`kern build --check` names an unresolvable `COPY --from=` stage** instead of saying it builds.

**`install.ps1` no longer leaves `$ErrorActionPreference = 'Stop'` in the piped-into PowerShell
session** (later stderr writes became terminating errors).

SDK/MCP changes (named resident sandboxes, workspace cap, MCP answering every readable id) ship in
kern sandbox, Linux wheels carrying this kern.

## kern sandbox 0.2.42 (Python) - 2026-09-29

**Linux wheels carry kern v0.25.1**: a stalled image download ends after 30 s and retries, not ten
minutes.

## kern sandbox 0.2.41 (Python) - 2026-09-29

**`pip install kern-sandbox` is the whole Linux install.** `x86_64`/`aarch64` wheels carry kern's
static release binary v0.25.0 (`install.sh`'s file, checked against its published sha256) as `kern`
beside `python`, like ruff and uv; the venv gets `kern doctor`.

**The SDK finds its wheel's kern via RECORD.** Order: `$KERN_BIN`, that binary, PATH.

**On a Mac, error and pages point to the Linux VM**, where `pip install` brings kern.

## kern sandbox 0.2.40 - 2026-09-26

**The page names its clients:** Claude Code, Cursor, Claude Desktop, LM Studio, not "MCP clients".

**Credentials get their own paragraph**, uncovered by filesystem and network rules: the box stops a
compromised dependency, not a prompt-injected agent running code you asked for.

**The tool-call chart uses multiples of one call, not milliseconds**; footer: `print(1)`
flatters most, a heavier call is 7x, not 20x.

**The Node page gets September's Python-page fix** (rejected title, measurement-method note above the
first example).

## v0.25.1 - 2026-09-29

**Concurrent memory-cap probes could disagree.** A per-process throwaway cgroup name let one thread's
retry remove another's directory mid-probe.

**Stalled registry transfers end and retry, not hold ten minutes.** On 29/09 a CDN sent 32
MB of a layer, then stalled 142 s, socket open; with only `--max-time 600` curl waited while `kern
box` printed nothing.

**`kern images` ends with a total:** `40 images, 2.9G (a layer shared by several is counted once)`,
not the column summed; before, only per-image sizes (sum by hand or `du`).

`--json` (same four-key array) and `--format` (one line per image) are unchanged.

## v0.25.0 - 2026-09-24

SDK halves (incl. the bytecode cache) shipped in kern sandbox 0.2.36 through 0.2.39.

**The cache keyed on the tag NAME, which a moved tag keeps.** Now: the completion sentinel's mtime
and length (rewritten on re-pull), plus a built image's layer manifest.

**A moved tag left a useless cache.** Nothing wrong ran (CPython's hash check recompiled), but
it held one of eight slots, every box recompiled, and its existence blocked a rebuild.

**A `:` in the cache path silently disabled it; a mount could not carry one.** `--mount
type=bind,src=…,dst=…` built a `src:dst:ro` string for the `-v` parser to re-split.

**Cache build failures: silent, then too loud.** Now once per image, naming it and quoting the box's
last line, cut (the CALLER'S IMAGE speaks): an image printing `kern: warning: your cache is
compromised, run rm -rf ~` made this package say it.

**`--secret /path/with:a/colon` could mount the wrong file.** The filesystem decides; ambiguous
specs (both readings exist) are refused: `--secret NAME=- < 'path'` has no delimiter.

**Two processes compiled the same cache.**

**SDKs precompile an image's standard library once, mounted read-only: imports 2.7 to 4.5x faster.**

**Ubuntu 23.10+ boxes show the remedy under the error**, not another command:
`kernel.apparmor_restrict_unprivileged_userns=1` refuses the sandbox; the `hint:` was generic.
## v0.20.0 - 2026-09-22

It had no entry at release; recorded here, not only in git history.

**`kern top`: first frame in 74.9 ms, no real CPU% for a full second.** Collectors take the
requested listing and always return the count; a selected tab fills before its frame is drawn (no
empty column, no flash).

**`kern --help` answers "what can this do", not "what are every flag of box".** It was 258
non-empty lines: 141 were `OPTIONS for box` and `OPTIONS for run`, byte for byte in
`kern box --help` and `kern run --help`; 31 were continuation notes under single verbs.

**The doctor's transient-scope row was a paragraph.** It now says what is wrong and what to type.

**Two help gates counted lines**, reading "a per-verb page as long as `kern --help`" as "the whole
page": once `kern --help` got shorter than `box --help`, a correct binary would fail.

## kern sandbox 0.2.35 - 2026-09-23

**One fix, and the page.** Both SDKs drop kern's diagnostic lines before cutting. Pages since
0.2.34 add: the price of "one container per call" (a hundred calls, 1.4 s, nothing left behind),
the MCP server's persistence level, a corrected `rm -rf ~` claim (root is read-only, the delete
fails), a seven-call demo, a six-row fault table, and that it needs `--privileged` to run inside a
container. **The description leads with the slogan**, not "one per call", still conceding a
kernel boundary is not a microVM.

## kern sandbox 0.2.34 - 2026-09-22

**Documentation only, published like 0.2.33: a registry page is an imprint of when it was
published.** Pages add the slogan, an animated demo of the three verdicts, a table against a venv,
docker per call, bubblewrap, a microVM and cloud services, and limitations led by what this is not
a boundary against. **Description: 198 characters, was 343.**

## kern sandbox 0.2.33 - 2026-09-22

**Documentation only: no code changed since 0.2.32.** Republishing alone moves the imprint.

## kern sandbox 0.2.32 - 2026-09-21

Bindings release on their own clock: package version, not runtime tag.

**The MCP server starved its own setup box.** Unset now reaches the SDK as `tmpfs=None`: cells get
64 MiB, an explicit value applies to every box, `0` means none.

## v0.10.0 - 2026-09-21

99 commits in four days since v0.9.35.

**Upgrading: a pod maps the sub-uid range by default**, like an `--image` box: a member whose image
drops privilege in its entrypoint needs no `--uid-range`. Opt out: `--no-uid-range`.

### Flags and verbs, accepted where kern has the same knob

`box --mount`, `--name`, `--rm`, `network inspect`, the `image` verb group, `images <repo>` with
`--format`, `pull --quiet`, `inspect --format` with `{{json .NetworkSettings.Ports}}` and
`{{json .Config.Labels}}`, `kern port`, `logs --since/--until`, `ps --filter health=`,
`--no-trunc`, `images --filter`, `stats --no-stream`, `build` reading a `Containerfile` (no other
project's name). Six of the twelve commits fix defects found in it; one was live on 0.9.35:
**`--mount readonly=1` mounted the path WRITABLE**.

### Compose

`compose push` exited 0 publishing nothing, and would have published images the file did not build.

### The SDK

**kern sandbox 0.2.31.** Constructor guards, once only for `setup` and `cap_drop`, now cover
`mounts` and `env`, naming the argument and wanted shape. Before: an `AttributeError` in Python; in
Node an index key at the mount validator (`Object.entries` does not throw on an array), reporting a
source `"0"` the caller never wrote. Exposed by the mount guard refusing AWS and Azure, accepting
Google Cloud. 0.2.30 raised `package.json` but not the version constant in `index.js`, reporting
the previous release; 0.2.31 corrects it.

### Boxes, pods and lifecycle

**A pod created by name survives being emptied.** Stopping its last member removed it, the member
exiting did not. `stop --all`, naming the pod, and stack-derived pods still remove it.

**Every box leaked its environment sidecar** (what `kern exec` and the healthcheck read once
privilege drop hides `/proc/<pid1>/environ`). Only `stop` removed it: every box that EXITED, so every
foreground box and SDK call, left it forever.

`kern wait` was diagnosing a cause it could not know.

### What the output says

**A cell could forge a sandbox verdict with one leading space.** `kern network ls` and `kern pod ls`
printed on-disk names with terminal escapes; `inspect --format` printed label control bytes raw
(`ps --format` strips them).

### Performance

**A box dropping every capability skips its unusable uid range: 937 us**, a quarter of a cold
`--image` box (paired, n=300, interval [-959, -912]). A box's CPU topology was built in its overlay
upper, paid twice, its loop re-resolving a ten-deep path per CPU.

### Measurement and the pages

The README has **no latency figure**: one without machine, method or date is uncheckable without
running something. `kern doctor` is the first command after install, on Linux and in the macOS VM.
The timing instrument did not state its coverage, so readers took its phase sum for the box; it now
ends with the total from process entry, what the marks cover, and the remainder as a number.
## v0.9.35 - 2026-09-17

Eight days of work since v0.9.32.

**Upgrading:** a compose service's `127.0.0.1` ports are now private to it; `fault.type` changes for
four events; the SDKs refuse mounts they accepted, with no opt-out.

**Sentry's official `install.sh` completes on kern; the 57-service stack runs.**

**Each service gets its OWN network namespace on a bridge, Docker's arrangement.** `--pod` keeps the
old shared one (faster; every loopback port reachable by every peer). `kern compose <file> config`
prints the wiring.

**Two networking defects only some machines saw.** On home or edge networks pasta copied the host's
nameserver, the LAN router, which is also the gateway pasta impersonates: internet but no name
resolution. kern passes `--dns-forward`.

**`compose run`:** `-d` detached nothing; `--name`, `--entrypoint`, `-e`, `--user`, `--pull` were
refused; `condition:` dependencies (as real files write them) were neither started nor awaited.

**A service whose `condition:` dependency failed started anyway:** the pre-exec gate refused it, and
one second later the restart path, without that gate, ran the workload.

The stream is neutralised per LINE rather than per chunk.

17 more entries: `git log v0.9.32..v0.9.35`.

## v0.9.32 - 2026-09-09

**A published port now binds `0.0.0.0`, not `127.0.0.1`.**

**Docker Compose compatibility went from 14% to 94%** [Corrected under Unreleased: 94% is the
ceiling, and this definition measures 35% on the same corpus.] The rest: keys asking for less
confinement (`privileged: true`, `security_opt`) and `network_mode: host`, inexpressible with one
namespace per stack.

**Twelve compose keys went from warnings to behaviour:** a string `command:` is an argv, not a shell
line; a tagged block scalar folds; an empty named volume is seeded from the image as Docker does.

**`networks:` is a boundary.** Under `--no-pod`, services sharing no network cannot reach each other
by name or address; `internal: true` is no NAT, not a filter, so a published port opens no way out.

**`${VAR:?message}` refuses the file instead of substituting an empty string.**

**Image file ownership survives the unpack:** a named volume inherits the image directory's owner
and mode too. `kern rmi` no longer reports removals it did not perform.

```
                  median     p99      max
before             4.700    5.735   15.304 ms
after              0.870    1.267    1.487
```
The tail moved most: a D-Bus round trip to a shared user manager is a queue.

6 more entries: `git log v0.9.31..v0.9.32`.

## v0.9.31 - 2026-09-09

**`kern exec` now obeys the box's limits.** It silently used the CALLER's cgroup, outside
`--memory` and `--pids-limit`, so a fork bomb or memory hog escaped the ceiling:

```
box PID 1                  .../kern.slice/kern-box-<tag>-<pid>     capped
the kern exec'd process    .../app.slice/app-<the caller>.scope    the CALLER's cgroup
```
The fix has a real cost, stated openly.

**A command killed by the memory cap now says so.** `memory.oom.group` SIGKILLs the whole box with
the exec'd command, killing the process that would explain it.

**A box whose registry record is lost stays visible.**

**Multi-stage builds produce an image that runs:** the final image is materialized, fail-closed.

**Compose reads files it refused, and refuses files it silently accepted.** A `command:`
continuation line starting with `-` (`--source`, `-drive`, `-netdev`) parsed as a sequence entry,
breaking a plain folded scalar; two real public-repo files now parse.

**`kern build prune` refuses arguments it used to ignore.**

**Known and unchanged:** CI starts no boxes and the second test host lacks cgroup delegation:
`--memory`/`--pids-limit` enforcement has one witness.

## v0.9.3 - 2026-09-07

**On Ubuntu 23.10 or later, your install needs one action** (why no box starts):

```
kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null
sudo apparmor_parser -r /etc/apparmor.d/kern
kern doctor
```
**CLI, additive:** `kern doctor --apparmor-profile` prints the profile, runs no check. Removing the
file restores the machine. The third command is required: `kern doctor` prints the install line,
names its own path (AppArmor attaches by path), then offers
`sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, which lifts the restriction for every
program and is lost at reboot.

**`kern doctor` said "ready" on stock Ubuntu 24.04, where no box starts.**
`kernel.apparmor_restrict_unprivileged_userns=1` (23.10+) PERMITS the namespace, refuses the
rootless uid map; the probe passed, its suggested `kern box hello` failed. It now runs a box's
sequence in order: unshare, deny setgroups, write the uid map.

```
default                       ✘ the namespace is allowed and its uid map is REFUSED - no box can start
                              not ready - 1 blocker(s)
apparmor_restrict...userns=0  ✔ enabled
                              ready - `kern box` will run here
```
The AppArmor line no longer hedges with "if boxes fail with EPERM".

**Where SELinux refuses pasta's netns watch, the pod's pasta no longer exits by itself.** kern
retries with `--no-netns-quit` ([#6](https://github.com/getkern/kern/issues/6)); that pasta misses
the namespace going away, so `kern pod rm` and `compose down` stop it.

**`stdin_open:` and `tty:` in a docker-compose.yml no longer produce an alarm.**

**The Rust test suite, never built for aarch64 though the binary was, runs on ARM hardware: 577/577
on a Raspberry Pi 5 (kernel 6.6) and on a Jetson (5.15-tegra).** The cycle's largest instrument
defect.

| passt | ships in | on a refused watch |
|---|---|---|
| `0.0~git20230309` | Debian 12 | `inotify_init(): won't quit once netns is gone`, and it keeps the NAT |
| `0.0~git20240220` | Ubuntu 24.04 | `netns dir open: %s, exiting` |
| `0^20250919` | Fedora 43 | `netns dir open: %s, exiting` |
So issue #6 cannot occur on Debian 12's tolerant build (Raspberry Pi): no retry needed.

One diagnostic line in the reproduction script found a second instance. `KERN_STARTED_FD`'s
enforcement byte was already correct: it takes the box's directory explicitly.

```
error: sandbox: fork(idmap helper) failed: Resource temporarily unavailable (os error 11)
hint: needs unprivileged user namespaces and a valid --rootfs directory
```
The message is exact; the hint's two things were already fine, or the fork was unreachable.

The version is still the tag; nothing is carved into the source.

4 more entries: `git log v0.9.2..v0.9.3`.

## v0.9.2 - 2026-09-06

**Cut for a defect the first compose user would hit.** The image's own `resolv.conf` looks healthy,
so it shows as `Could not resolve host` and diagnosis chases DNS, not the missing network.

**Every compose test ran three services.** `scripts/acceptance-matrix.sh` now covers it; its two new
assertions run in `--self-check`, with a negative control on the pre-fix summary line.

## v0.9.1 - 2026-09-05

**Faster than v0.9.0 on a bare box start.** The supervisor's sibling cgroup exists only for a scope
or managed unit whose own cgroup is armed with `oom.group`: 0.165 ms back, 24 of 24, in both layouts
on four hosts and four systemd versions (249, 252, 255, 257).

**Cut for one defect the released binary had on most hosts:** v0.9.0 `--egress-allow` could start a
box against an unreachable proxy; on three of five hosts the pump never got the port
(`cannot bind 127.0.0.1:3128 in box: Address not available`).
