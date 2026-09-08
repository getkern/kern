# Changelog

**CLI stability.** Since v0.7.0 the verbs, their flags and the `--json` shapes change incompatibly
only on a minor bump, never on a patch, and only after a deprecation entry here one release earlier.
`--json` is additive, so consumers must ignore unknown fields. A `cli_surface_is_frozen` test fails
the build on any undocumented change. Full detail for any entry is in the git history.

## Unreleased

**Agent skills:** add self-contained Kern guidance for Claude Code and GitHub Copilot, including CLI, Compose, and `kern-sandbox` workflows.

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
