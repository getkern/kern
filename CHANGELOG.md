# Changelog

**CLI stability.** Since v0.7.0 the verbs, their flags and the `--json` shapes change incompatibly
only on a minor bump, never on a patch, and only after a deprecation entry here one release earlier.
`--json` is additive, so consumers must ignore unknown fields. A `cli_surface_is_frozen` test fails
the build on any undocumented change. Full detail for any entry is in the git history.

## kern-sandbox 0.2.40 - 2026-09-26

**The page says what it works with, by name.** Claude Code, Cursor, Claude Desktop and LM Studio,
instead of "MCP clients", which a reader has to already know they are one of.

**Credentials get their own paragraph, because filesystem and network do not cover them.** A
compromised dependency is stopped by the box; a prompt-injected agent is not, because it runs the
code you asked for. Mounts over 17 credential directories are refused with no opt-out, and they are
now named.

**The tool-call chart is in multiples of one call, not milliseconds**, and carries the range in its
own footer: `print(1)` is the workload that flatters it most and a heavier call is 7x rather than
20x. No millisecond and no CPU model is left on either page.

**The Node page had the opening the Python page replaced in September** and never got the same fix:
the rejected title, and a note about measurement method above the first example. Both pages now open
the same way.

## Unreleased
**`kern images` listed a size per image and never said what they came to.** Every row carried its
own number and nothing added them up, so the only way to learn the total was to sum the column by
hand or walk the directory with `du`.

The listing now ends with one line: `40 images, 2.9G (a layer shared by several is counted once)`.

**It is not the column added up, and that distinction is the whole feature.**

`--json` is unchanged, still an array with the same four keys, and `--format` still prints one line
per image and nothing else: a script reading either sees exactly what it saw before.

## v0.25.0 - 2026-09-24
The SDK halves of this shipped as kern-sandbox 0.2.36 through 0.2.39 while the runtime waited for
this tag; every entry below that names the bytecode cache is in those packages already.

**The cache's identity read the tag's NAME, which is the one thing a moved tag does not change.** It
now uses the stamp kern itself treats as "this image's content changed", the completion sentinel's
mtime and length, which a re-pull rewrites; the layer manifest of a built image is in it too.

**A moved tag left a cache that no longer helped and that nothing rebuilt.** Nothing wrong was ever
run - the cache validates on the source's hash, so CPython rejects stale bytecode and compiles from
source - but the cache kept one of its eight slots, every box paid the compile again, and nothing
replaced it because a cache "existed".

**A cache path containing a `:` silently disabled the bytecode cache, and a mount could not carry
one at all.** `--mount type=bind,src=…,dst=…` exists to carry each field separately and was building
a `src:dst:ro` string for the `-v` parser to split again, so it destroyed the very thing it was for.

**A failing cache build said nothing, and then said too much.** It is reported once per image now,
naming the image and quoting the box's own last line - and that line is the CALLER'S IMAGE speaking,
so it is quoted and cut rather than pasted: an image printing `kern: warning: your cache is
compromised, run rm -rf ~` made this package say it, in its own voice.

**`--secret /path/with:a/colon` could mount the wrong file.** The filesystem decides it now, and a
spec where both readings name a real file is refused rather than guessed: `--secret NAME=- < 'path'`
has no delimiter at all.

**Two processes compiled the same cache.**

**The SDKs precompile an image's standard library once and mount it read-only, and imports get 2.7
to 4.5x faster.**

**A box on Ubuntu 23.10+ now reads the remedy under the error instead of being sent to another
command.** `kernel.apparmor_restrict_unprivileged_userns=1` refuses the sandbox, the message was
already exact about what happened, and the `hint:` line was the generic one.

## v0.20.0 - 2026-09-22
Cut without an entry of its own at the time; these are its changes, written down here rather than
left only in the git history.

**`kern top` drew its first frame in 74.9 ms and showed no real CPU% for a full second.** Each
collector now takes the listing it is asked for and returns the count either way, and the tab a
reader switches to fills itself in before that frame is drawn, so there is no empty column and no
flash.

**`kern --help` answers "what can this do", not "what are every flag of box".** It printed the whole
reference: 258 non-empty lines, of which 141 were the `OPTIONS for box` and `OPTIONS for run` blocks
that `kern box --help` and `kern run --help` already serve byte for byte, and another 31 were
continuation notes under single verbs.

**The doctor's transient-scope row was a paragraph.** It now says what is wrong and what to type.

**Two help gates were anchored on a line count** and would have failed a correct binary: they read
"a per-verb page as long as `kern --help`" as "it is answering with the whole page", which stopped
being true the moment `kern --help` became shorter than `box --help`.

## kern-sandbox 0.2.35 - 2026-09-23
**One fix, and the page.** Both SDKs now drop kern's diagnostic lines before cutting.

What the registry pages gain since 0.2.34: the price beside "one container per call" (a hundred
calls, 1.4 s, nothing left behind), which persistence level the MCP server gives, a corrected `rm
-rf ~` claim (the root is read-only, so the delete fails), a seven-call demo, the fault table at six
rows, and the line saying it does not run inside a container without `--privileged`.

**The package description leads with the slogan** instead of "one per call", and keeps the sentence
conceding that a kernel boundary is not a microVM.

## kern-sandbox 0.2.34 - 2026-09-22
**Documentation only, and published for the same reason 0.2.33 was: a registry page is an imprint of
the moment it was published.**

What the registry pages gain: the slogan, the animated demo of the three verdicts, the table
comparing this to a venv, docker per call, bubblewrap, a microVM and the cloud services, and a
current-limitations section that leads with what this is not a boundary against.

**The package description is 198 characters instead of 343.**

## kern-sandbox 0.2.33 - 2026-09-22
**Documentation only: no code changed between 0.2.32 and this.** Republishing is the only way to
move that imprint.

## kern-sandbox 0.2.32 - 2026-09-21
The bindings are released on their own clock, so this section carries a package version rather than
a runtime tag.

**The MCP server starved its own setup box.** Unset now reaches the SDK as `tmpfs=None`: cells still
get 64 MiB, an explicit value still applies to every box, `0` still means none.

## v0.10.0 - 2026-09-21
Four days of work since v0.9.35, and 99 commits.

**Read these first if you are upgrading.** **A pod maps the sub-uid range by default**, as an
`--image` box already did, so a member running an image that drops privilege in its entrypoint works
without `--uid-range`; `--no-uid-range` is the opt-out.

### Flags and verbs, accepted where kern has the same knob

`box --mount` and `--name`, `--rm`, `network inspect`, the `image` verb group, `images <repo>` with
`--format` and `pull --quiet`, `inspect --format` answering `{{json .NetworkSettings.Ports}}` and
`{{json .Config.Labels}}`, `kern port`, `logs --since/--until`, `ps --filter health=`, `--no-trunc`,
`images --filter`, `stats --no-stream`, and `build` reading a `Containerfile` so a project need not
carry another project's name.

Six of the twelve commits that built this surface are FIXES the reviews found in it, and one was
live on 0.9.35: **`--mount readonly=1` mounted the path WRITABLE**, which is the worst shape a
compatibility gap can take, the flag asking for less privilege granting more.

### Compose

`compose push` exited 0 having published nothing, and would have published images the file did not
build.

### The SDK

**kern-sandbox 0.2.31.** The constructor guards that existed for `setup` and `cap_drop` and not for
the rest: `mounts` and `env` in the wrong shape name the argument and the shape they want, instead
of escaping as an `AttributeError` in Python or reaching the mount validator as an index key in
Node, where `Object.entries` does not throw on an array and reported a source of `"0"` the caller
never wrote.

The mount guard refused AWS and Azure and accepted Google Cloud, which is the asymmetry that made it
visible.

0.2.30 was published with `package.json` raised and the version constant in `index.js` left behind,
so the package reported the previous release; 0.2.31 corrects it.

### Boxes, pods and lifecycle

**Stopping a pod's last member removed the pod, and letting that member exit on its own did not** A
pod created by name now survives being emptied; `stop --all`, naming the pod itself, and a pod
derived from a stack still tear one down.

**Every box leaked its environment sidecar.** kern records a box's environment so `kern exec` and
the healthcheck can read what `/proc/<pid1>/environ` stops giving them once the box drops privilege,
and only `stop` ever removed it: a box that simply EXITED left it behind forever, which is every
foreground box and every SDK call.

`kern wait` was diagnosing a cause it could not know.

### What the output says

**A cell could forge a sandbox verdict with one leading space** `kern network ls` and `kern pod ls`
printed a name off disk without stripping terminal escapes; `inspect --format` printed a label's
control bytes raw where `ps --format` strips them.

### Performance

**A box that drops every capability stops paying for a uid range it cannot use: 937 us** , a quarter
of a cold `--image` box, measured paired at n=300 with an interval of [-959, -912].

The CPU topology a box sees was built in its overlay upper and paid for twice; that same loop re-
resolved a ten-deep path once per CPU.

### Measurement and the pages

The README publishes **no latency figure** at all: a front page states a number with no machine,
method or date beside it, and it is the one claim there nobody can check without running something.

`kern doctor` is now the first command after install, on Linux and inside the macOS VM.

The timing instrument could not state its own coverage, so a reader summed its phases and believed
the sum was the box; it now closes with the total from process entry, what the marks cover, and the
remainder as a number.

## v0.9.35 - 2026-09-17
Eight days of work since v0.9.32.

**Read these first if you are upgrading:** each compose service gets its own network namespace on a
bridge, so a port a service binds on its `127.0.0.1` stays private to it; `fault.type` reports a
different value for four events; and the SDKs refuse mounts they used to accept, with no opt-out.

**Sentry's official `install.sh` completes on kern, and the 57-service stack runs.**

**Each service gets its OWN network namespace on a bridge, which is Docker's arrangement.** `--pod`
keeps the old single shared namespace, which is faster and makes every loopback port reachable by
every peer, and `kern compose <file> config` prints which wiring a bring-up will use.

**Two networking defects that only some machines could see.** On a home or edge network a box had
internet and could not resolve a name, because pasta copies the host's nameserver into the box and
on such a network that address is the LAN router, which is also the gateway pasta impersonates; kern
passes `--dns-forward` now.

**`compose run` was missing most of what a script passes it.** `-d` detached nothing; `--name`,
`--entrypoint`, `-e`, `--user` and `--pull` were refused; the one-off started none of the
dependencies written with a `condition:`, which is how every real file writes them, and did not wait
for them.

**A service whose dependency failed was held back and then started anyway.** With a `condition:` on
a dependency that fails, the pre-exec gate refused the exec, and one second later the restart path,
running without that gate, ran the workload.

**A database that was ready in ten seconds reported `starting` for five minutes.** Both are honoured
now, from the image config and from a Dockerfile's `HEALTHCHECK --start-interval`, and `kern box
--health-start-interval <sec>` exposes it.

**An explicit `docker.io/` prefix broke every pull** `docker.io` and `index.docker.io` resolve to
Docker Hub's API host now, and `docker.io/alpine` means `library/alpine` exactly as bare `alpine`
does.

**Defaults and refusals a real file runs into.** `compose pull` no longer goes to a registry for
images the file said never to pull.

**The sandbox SDKs: `fault.type` changes value for the same event, which is why 0.2.0 was a MINOR
bump.** An external `kern stop` was `oom` and is now `killed`; a workload that CHOOSES `exit 137` is
no longer a fault; a crash is `fault=None` with `128+signal`; a `KERN_BIN` that is not kern raises
instead of reporting success.

**A box that never started is a verdict of its own, not an exit code to guess at.**

**The SDKs refuse a mount that would hand the box the sandbox's own control plane.** Workspace I/O
refuses what it cannot contain and says which: an absolute path, a `..` escape, a symlinked
component at any depth, a device planted at the name, a file over `max_bytes`.

**The MCP server names the kern that ran the code** An argument a tool does not have is refused with
`-32602` rather than dropped, and box output reaching a model has terminal escapes stripped and both
surfaces' framing neutralised, so a forged marker reads `[printed by the code, not the sandbox:
...]`.

**`kern-pi` 1.0.1 on npm.**

**Runtime and CLI.** A service stopped and started again was unreachable by its peers for 29
seconds, because its `veth` got a random MAC each time; a member's address is derived from its IP
now, as Docker's is, and the same restart takes 176 ms.

**`kern logs -t` prints when each line was written.** Docker has had `--timestamps` since forever
and a reader comparing a box's output against anything else needed it.

**What `-t` is not.** `-f` is a diagnostic stream and not an audit log: under load a line written
between the tail read and the follow can be dropped, which is stated in `--help` rather than fixed
with machinery nobody asked for.

**The Pi extension neutralises box output that becomes model text.** A cell that prints `[sandbox:
oom]` or `[exit 137, ...]` is forging a verdict about itself in the channel a model decides with,
and the SDK's other two agent surfaces have refused that for a while: this one did not.

The stream is neutralised per LINE rather than per chunk.

**`kern logs -f` stopped showing output after the first rotation, and said nothing.** It followed an
open descriptor rather than the name, so when the pump renamed the active log and opened a fresh one
the follower kept polling a file nobody writes to any more.

**A timestamp can no longer go backwards, whatever the index says.** The cost is stated in the code
- across a seam the column repeats an instant instead of showing a slightly older one - and it can
never invent a time that is too new.

**`kern logs` could report that a busy box writes no log at all.** A rotation renames the active
file and opens a new one, and a reader that resolved the name in between found nothing, or opened a
descriptor to a file that had just been renamed away.

**The compatibility rate ships with its corpus and its definition.**

**Tests, gates and examples.**

## v0.9.32 - 2026-09-09
**A published port now binds `0.0.0.0`, not `127.0.0.1`. Read this one.** Until now kern bound
loopback and warned, so a stack that looked published was reachable only from the host.

**Docker Compose compatibility went from 14% to 94%** [Corrected under Unreleased: 94% is the
ceiling, and this definition measures 35% on the same corpus.] What remains is dominated by keys
asking kern to be less confining than it is (`privileged: true`, `security_opt`) and by
`network_mode: host`, which one namespace per stack cannot express.

**Twelve compose keys stopped being warnings and became behaviour** A string `command:` is now an
argv rather than a shell line, a tagged block scalar folds, and an empty named volume is seeded from
the image as Docker does.

**`networks:` is a boundary, not a warning.** Under `--no-pod`, services with no network in common
cannot reach each other by name or by address, and `internal: true` is the absence of NAT rather
than a filter, so a published port does not open a way out.

**`${VAR:?message}` refuses the file instead of substituting an empty string.**

**An image's file ownership survives the unpack** A named volume inherits the image directory's
owner and mode, not only its contents, and `kern rmi` no longer reports a removal it did not
perform.

**A service secret is written with the mode the Compose Specification mandates.**

**`kern run` no longer pays for a systemd scope it does not need: 4.70 ms to 0.87 ms.** It bought
its caps with a transient `systemd-run --user --scope`, one per invocation; it now caps directly
under kern's delegated `kern.slice`, the way `kern box` already did.

```
                  median     p99      max
before             4.700    5.735   15.304 ms
after              0.870    1.267    1.487
```
The tail moved more than the median because a D-Bus round trip to a shared user manager is a queue.

**`kern exec` stopped refusing where there was no cap to escape** , and its fail-closed refusal now
names both causes and the way through (`KERN_ALLOW_UNCAPPED=1`).

**`kern doctor` names the cgroup it probed** on every row that denies a cap, so the verdict can be
checked against `/proc/<pid>/cgroup` instead of taken on trust, and it asks about both directories a
box can be capped in.

**A box's terminal has a name.** It is now allocated from the box's own devpts and the master passed
back over a socketpair, so both C libraries resolve it.

**CLI surface: six flags added, none changed or removed.** `--dns`, `--dns-search`, `--dns-option`,
`--log-max-size`, `--log-max-file`, `--secret-mode`.

## v0.9.31 - 2026-09-09
**If you use `kern exec`, this release is the one that makes it obey the box's limits.** A command
run through `kern exec` was placed in the CALLER's cgroup, outside the box's `--memory` and `--pids-
limit`, and said nothing about it.

```
box PID 1                  .../kern.slice/kern-box-<tag>-<pid>     capped
the kern exec'd process    .../app.slice/app-<the caller>.scope    the CALLER's cgroup
```
A fork bomb or a memory hog started with `kern exec` therefore ran without the ceiling the box was
given.

**The cost is real and is stated rather than hidden.**

**A command killed by the box's memory cap now says so.** `memory.oom.group` kills the whole box,
the exec'd command included, and it goes by SIGKILL, so the process that would explain it is the one
being killed.

**A box whose registry record is lost stays visible.**

**Multi-stage builds produce an image that runs.** The final image is now materialized, fail-closed.

**Compose reads files it used to refuse, and refuses files it used to accept in silence.** A
`command:` continuation line starting with `-` was read as a sequence entry, so `--source`, `-drive`
and `-netdev` broke a plain folded scalar; two real files from public repositories now parse.

**`kern build prune` refuses arguments it used to ignore.**

**Fixed, no interface change:**

**Known and unchanged:** CI does not start boxes, and the second test's host has no cgroup
delegation, so `--memory`/`--pids-limit` enforcement has one witness.

## v0.9.3 - 2026-09-07
**If you run kern on Ubuntu 23.10 or later, your install needs one action.** That is not a new
feature, it is the answer to "why does no box start", and it is here rather than under new
capabilities because it is the entry a reader scanning for "does this release affect me" needs to
find.

```
kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null
sudo apparmor_parser -r /etc/apparmor.d/kern
kern doctor
```
**CLI, additive:** `kern doctor --apparmor-profile` writes that profile to stdout and exits without
running any check.

**What that file does NOT do** Removing it returns the machine to its previous state.

The third command is not politeness.

`kern doctor` prints that install line, names the path it is running from because AppArmor attaches
by path, and offers `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` only after it, with
its cost: that one lifts the restriction for every program on the machine and is lost at reboot.

**`kern doctor` said "ready" on a stock Ubuntu 24.04, where no box can start.** Ubuntu 23.10 and
later ship `kernel.apparmor_restrict_unprivileged_userns=1`, which PERMITS the namespace and refuses
the rootless uid map, so the probe succeeded on a host where the very command doctor then suggested,
`kern box hello`, failed.

The probe now runs the sequence a box actually runs, in the same order: unshare, deny setgroups,
write the uid map.

```
default                       ✘ the namespace is allowed and its uid map is REFUSED - no box can start
                              not ready - 1 blocker(s)
apparmor_restrict...userns=0  ✔ enabled
                              ready - `kern box` will run here
```
The AppArmor line no longer hedges with "if boxes fail with EPERM".

**On a host whose SELinux policy refuses pasta's netns watch, the pod's pasta no longer exits by
itself.** kern retries with `--no-netns-quit` there
([#6](https://github.com/getkern/kern/issues/6)), and a pasta started without the watch does not
notice the namespace disappear, so `kern pod rm` and `compose down` are what stop it rather than
pasta stopping itself.

**`stdin_open:` and `tty:` in a docker-compose.yml no longer produce an alarm.**

**The Rust test suite had never been built for aarch64, though the binary always was.** It now
builds and runs on ARM: **577/577 on a Raspberry Pi 5 (kernel 6.6) and on a Jetson (5.15-tegra)**,
on the hardware rather than under emulation.

That is the largest instrument defect in this cycle: not a probe reading the wrong thing, but a
whole suite that was never executed on a target kern ships for.

**A refused netns watch is only fatal in newer passt, and where it is not there is nothing to fix.**

| passt | ships in | on a refused watch |
|---|---|---|
| `0.0~git20230309` | Debian 12 | `inotify_init(): won't quit once netns is gone`, and it keeps the NAT |
| `0.0~git20240220` | Ubuntu 24.04 | `netns dir open: %s, exiting` |
| `0^20250919` | Fedora 43 | `netns dir open: %s, exiting` |
So a Raspberry Pi on Debian 12 needs no retry and never could have: issue #6 cannot occur against
the tolerant build.

**Fixed: `--memory` and `--pids-limit` reported "accepted but NOT enforced here" over a box capped
exactly as asked.** Reported on WSL2 and reproduced on a Raspberry Pi 5 and a Jetson Orin Nano,
where `--memory 256m --pids-limit 64` printed both notices while the box's cgroup held
`memory.max=268435456` and `pids.max=64`.

The same mistake had a second instance, found by adding one diagnostic line to the reproduction
script rather than by reading the code.

The enforcement byte on `KERN_STARTED_FD` was already correct: it takes the box's directory
explicitly, for this exact reason.

**Fixed: a box refused for running out of process slots was told to check user namespaces.**

```
error: sandbox: fork(idmap helper) failed: Resource temporarily unavailable (os error 11)
hint: needs unprivileged user namespaces and a valid --rootfs directory
```
The message is exact and the hint names two things that are both already fine, because the code
could not have reached that fork otherwise.

**`kern --version` now says which build it is.**

The version is still the tag and nothing is carved into the source.

## v0.9.2 - 2026-09-06
**Cut for a defect the first person to try compose would hit.**

It does not present as a missing network, which is why it survived: the image ships its own
`resolv.conf` and it looks healthy, so the failure surfaces as `Could not resolve host` and every
diagnosis goes after DNS.

**Every compose test in this repo ran three services, which is how it shipped.**
`scripts/acceptance-matrix.sh` now has a case for it, with its two new assertions exercised in
`--self-check` including a negative control on the pre-fix summary line.

### Fixed

- **A one-service compose stack had no egress.** It now creates a pod whenever any service is not on
  the host net, which is what the comment above it always said it did.

- **`kern pod ls` and `pod ls --json` reported double the members.** They counted lines in the pod's
  shared `hosts` file, and a compose member writes two of them (the qualified `<pod>-<service>` and
  the bare alias) while a `kern box --pod` member writes one.

- **`compose up` never said whether the stack had egress** On a reused pod that line is the only one
  printed.

- **`restart:` in a pod does not survive a reboot, and now says so.** The gap predates this release
  and reached only multi-service stacks; the auto-pod now reaches one-service stacks, so `up` prints
  a note instead of trading reboot-survival in silence.

- **`has_outbound` answered from `resolv.conf` alone.** It now also requires a live pasta, verified
  by `comm` because passt re-execs into an ISA variant and a pid can be reused.

- **`kern killall --help`, `kern down --help` and `kern logout --help` printed the whole 184-line
  reference.** The test that missed them named fifteen verbs by hand; it now reads the list out of
  the reference, all 51.

- **Nine `kern --help` lines sat outside the description column** , `pod` by twenty because it did
  not fit; `pod` is two lines now.

- **A damaged image-cache entry was repaired in silence under an SDK.** They are `kern: note:` now
  and reach a pipe; the ordinary "not cached, pulling once" stays gated.

## v0.9.1 - 2026-09-05
**Faster than v0.9.0 on a bare box start** The supervisor's sibling cgroup is created only where it
is needed, a scope or managed unit whose own cgroup is the one armed with `oom.group`: 0.165 ms
back, 24 of 24, re-checked in both layouts on four hosts and four systemd versions (249, 252, 255,
257).

**Cut for one defect the released binary had on most hosts.** `--egress-allow` in v0.9.0 could start
a box against a proxy nothing could reach, and on three of five hosts the pump never got the port
(`cannot bind 127.0.0.1:3128 in box: Address not available`).

### Fixed

- **The MCP server offered a language and then refused it.** The guard is the schema's list now, and
  a refusal names the accepted values.

- **`kern_execution_policy(cap_drop=("ALL",))` disabled the drop it asked for**

- **kern's progress output no longer reaches a pipe.** Nineteen bare `eprintln!` lines now go
  through `progress!`, which prints only when stderr is a terminal.

- **Three diagnostics reached `code_stderr` as though the workload had printed them**

- **A cgroup probe printed systemd's bus error onto kern's stderr.** Both streams are null now; the
  verdict was never in the output.

- **kern's diagnostics no longer land in a model's context.** `code_stderr`/`codeStderr` is stderr
  without kern's own lines, `runtime_notes`/`runtimeNotes` holds exactly what was removed, and
  `stderr` still holds every byte in order.

- **`kern_execution_policy` accepts `Sandbox`'s vocabulary** Passing both halves of a pair is
  refused.

- **The OOM message never printed when kern runs as root or on a host with no systemd**

- **The registry recorded the supervisor's cgroup for every box**

- **A `-v` volume is mounted `nosuid`**

- **`/dev/shm` reports the size the box actually has.**

- **A warm interpreter could not import anything the image ships.**

- **`kern-sandbox` 0.1.36 on npm could not be installed**

### Changed

- **`deps_readonly` defaults to TRUE** A run-time write into `.deps` now gets `EROFS`;
  `deps_readonly=False` restores the old behaviour.

- **A timeout reports `exit_code = 137` in Python**

- **`integrations/pi` declares `engines: node >= 22`.**

### Added

- **`kern box --shm-size SIZE`** , for a workload needing `/dev/shm` sized differently from
  `--memory`.

- **`prewarm=N` in both bindings** : ~1.6 ms per call instead of ~37.8, measured over ssh, without
  giving up the fresh box, since a prewarmed box serves exactly one cell and is destroyed.

- **Every box gets a writable `/tmp`**

**kern-sandbox 0.1.41**
