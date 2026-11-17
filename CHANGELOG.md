# Changelog

**CLI stability.** Since v0.7.0 the verbs, their flags and the `--json` shapes change incompatibly
only on a minor bump, never on a patch, and only after a deprecation entry here one release earlier.
`--json` is additive, so consumers must ignore unknown fields. A `cli_surface_is_frozen` test fails
the build on any undocumented change. Full detail for any entry is in the git history.

**Sandbox result stability.** In kern-sandbox (Python, Node and `kern-mcp`), the `fault.type` and
`exit_code` an outcome reports change only to correct one that was reported wrong, and such a change
leads that release's entry, naming the outcomes it moves. kern-sandbox 0.2.45 is the example:
`os._exit(N)` in a prewarmed box or a kernel stopped reading as `killed`, and a kernel timeout went from
-1 to 137. New `fault.type` values are additive, so code must treat a value it does not know as a fault
of the sandbox. A test fails the build when the set of values changes in one binding and not the other.

**Compose surface stability.** A compose key kern reads keeps its meaning: it changes only to correct
a mapping that was wrong, and such a change leads that release's entry, naming the key. Reading a key
kern ignores today is additive. A key kern does not read is never silent, with two deliberate
exceptions: `x-*` extension fields, and the keys Docker itself does not act on under Linux
(`cpu_count`, `cpu_percent`, `cpus_shares`, `isolation`). A test carries the frozen list of keys and
both halves of that rule, so removing one from the parser fails the build by name.

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

## kern-sandbox 0.2.50 - 2026-11-17

**It carries the kern v0.51.0 binary.** Both bindings move together.

**kern-sandbox refuses a mount source that holds a refused path or a credential directory.**
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

**kern-sandbox refuses the host's credential files as mount sources, not only `/etc` whole.** A
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

## kern-sandbox 0.2.49 - 2026-10-17

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
## kern-sandbox 0.2.48 - 2026-10-13

**Carries kern v0.32.0** (`--egress-allow` `Host:` check, below); binding code unchanged since
0.2.47. Package descriptions no longer say the workspace cannot be bounded (two sentences, false
since 0.2.47); they say the cap is measured during a call, and what it still is not.

## v0.32.0 - 2026-10-13

**Minor bump: `--egress-allow` refuses a request it used to forward.** Under an allowlist, a
plain-HTTP head whose `Host:` is not the vetted request-target, or is doubled, gets 403 (a port-80
escape). The check follows the allowlist, so refusals cannot probe it. Over HTTPS (header inside
TLS) a shared CDN still allows it (`docs/EGRESS.md`). Binary otherwise unchanged since v0.31.0.

## kern-sandbox 0.2.47 - 2026-10-13

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
- kern-sandbox: `user=` (Node `user`, `kern-mcp` `KERN_MCP_USER`) runs every box, `persist`
  included, as an image account; both bindings reach every path by descriptor in listings
  (`result.files`, `list_files`), `snapshot`, `restore` and `write_file`'s new directories.
- Compose stacks on an `external:` network no longer write outside the other project's box.

36 more entries: `git log v0.30.2..v0.31.0`.

## kern-sandbox 0.2.45 - 2026-10-05

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

## kern-sandbox 0.2.44 - 2026-10-04

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
`exit(137)` as an exit; see kern-sandbox 0.2.44).

**A `-v` under `/sys/devices` reaches the box** (kern's CPU topology covered it).

**A base image without `/bin/true` builds layered**, not flat blaming the kernel ("unprivileged
overlay unavailable").

**`kern inspect` finds built images**: it said "nothing named" for every `kern build` image
`kern images` listed.

**Three messages fixed:** compose `gpus:` is Docker's GPU request, not a typo for `cpus:`;
`kern pull` names `kern box … --pull always` to refresh; a cached-image read failure no longer says
to check the name.
## kern-sandbox 0.2.43 - 2026-10-04

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
kern-sandbox, Linux wheels carrying this kern.

## kern-sandbox 0.2.42 (Python) - 2026-09-29

**Linux wheels carry kern v0.25.1**: a stalled image download ends after 30 s and retries, not ten
minutes.

## kern-sandbox 0.2.41 (Python) - 2026-09-29

**`pip install kern-sandbox` is the whole Linux install.** `x86_64`/`aarch64` wheels carry kern's
static release binary v0.25.0 (`install.sh`'s file, checked against its published sha256) as `kern`
beside `python`, like ruff and uv; the venv gets `kern doctor`.

**The SDK finds its wheel's kern via RECORD.** Order: `$KERN_BIN`, that binary, PATH.

**On a Mac, error and pages point to the Linux VM**, where `pip install` brings kern.

## kern-sandbox 0.2.40 - 2026-09-26

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

SDK halves (incl. the bytecode cache) shipped in kern-sandbox 0.2.36 through 0.2.39.

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

## kern-sandbox 0.2.35 - 2026-09-23

**One fix, and the page.** Both SDKs drop kern's diagnostic lines before cutting. Pages since
0.2.34 add: the price of "one container per call" (a hundred calls, 1.4 s, nothing left behind),
the MCP server's persistence level, a corrected `rm -rf ~` claim (root is read-only, the delete
fails), a seven-call demo, a six-row fault table, and that it needs `--privileged` to run inside a
container. **The description leads with the slogan**, not "one per call", still conceding a
kernel boundary is not a microVM.

## kern-sandbox 0.2.34 - 2026-09-22

**Documentation only, published like 0.2.33: a registry page is an imprint of when it was
published.** Pages add the slogan, an animated demo of the three verdicts, a table against a venv,
docker per call, bubblewrap, a microVM and cloud services, and limitations led by what this is not
a boundary against. **Description: 198 characters, was 343.**

## kern-sandbox 0.2.33 - 2026-09-22

**Documentation only: no code changed since 0.2.32.** Republishing alone moves the imprint.

## kern-sandbox 0.2.32 - 2026-09-21

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

**kern-sandbox 0.2.31.** Constructor guards, once only for `setup` and `cap_drop`, now cover
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
