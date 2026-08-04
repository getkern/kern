# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to SemVer.
Pre-1.0: the CLI and config surface are NOT frozen; minor versions may change them.

**Deprecation policy (pre-1.0).** "Not frozen" does not mean "breaks without warning". When a
flag or config key changes:

- **Same meaning, new name** → the old name keeps working as a **deprecated alias** that prints a
  one-line warning to stderr, for **at least 2 minor releases** before it is removed. Your scripts
  keep running; you get a heads-up to update them.
- **Different meaning** → the old name is **rejected with an error** that explains the change and
  names the replacement (never silently reinterpreted, which would corrupt behaviour). Example:
  `--memory-swap` (Docker's mem+swap *total*) is refused with a pointer to `--memory-swap-max`
  (the cgroup v2 swap *allowance*), the two mean different things, so aliasing would lie.

Removals and deprecations are always listed under **Deprecated** / **Removed** here first.

## [0.6.34], 2026-08-03

### Fixed

- **`--pids-limit` could be accepted and silently not enforced, and the warning that exists for it
  was looking in the wrong place.** Measured on a Raspberry Pi 5: `--pids-limit 999999999` exited 0
  with the box's `pids.max` reading `max`, so the box ran with no fork-bomb guard and nothing said
  so. On the same host 64, 256 and 1000000 were honoured exactly, which is what makes this the write
  failing rather than the value being clamped. Reproduced on the Jetson and the UNO Q.

  `warn_unenforced_caps` already covered pids, and that is why it stayed quiet: it asked
  `capped_in_tree`, which walks UP from the box's cgroup and stops at the first real limit. Walking
  up from the box on the Pi finds `pids.max=max` at the box itself, at `app.slice` and at
  `user@1000.service`, then `pids.max=20370` at `user-1000.slice` and returns satisfied. But 20370
  is systemd's session-wide `TasksMax` for the whole user, shared with every other process they run.
  It is not a per-box limit and it does not become one by being finite: a fork bomb inside the box
  would exhaust it against the session, which is the outcome `--pids-limit` exists to prevent.

  The trap was already written down, in the fail-closed block of `apply_caps`, in those words, and
  that block correctly keys on the box's own read-back instead. The rule was applied in one place
  and not the other, which is this project's `derived-condition-duplicated` defect class rather than
  a new one. `capped_here` is now the leaf-only counterpart to `capped_in_tree`, pids uses it, and a
  test pins the difference so a refactor that collapses them fails rather than going quiet.

  Memory and CPU keep the tree walk, and that is correct rather than an oversight: a parent
  `memory.max` really does bound this box, while a parent `pids.max` does not bound it alone.
  Checking only the leaf costs no false warning, verified on the same host where 64, 256 and 1000000
  all land in the box's own cgroup exactly.

  A second gap in the same area is closed with it: the direct cgroup path warned for I/O, memory and
  CPU and not for pids, so a box whose pids write failed there was silent too. Four knobs, four
  warnings, and `every_cap_knob_has_a_not_enforced_warning` asserts a fifth cannot be added without
  one.

  Verified on six targets: silence for the values that apply, the warning for the one that does not.
  x86_64 and the Contabo VPS take the direct path and refuse the box outright, which is the stricter
  and already-correct behaviour there; the Pi 5, the Jetson, the UNO Q and WSL2 warn.

- **`clone`/`clone3` reached the namespace creation that `unshare`/`setns` are killed for.**
  `unshare` and `setns` have been in the kill set since the filter existed, so the documented model
  was that a box cannot make a namespace. It could. `clone` and `clone3` take the same `CLONE_NEW*`
  flags and were deliberately not denied, because they are how every program forks. Measured in
  three separate processes inside a box: `unshare(CLONE_NEWUSER)` died with SIGSYS while
  `clone(CLONE_NEWUSER)`, `clone(CLONE_NEWUSER|CLONE_NEWNS)` and `clone3(CLONE_NEWUSER)` all
  succeeded, and the child came back holding every capability kern drops before exec, **bounding set
  included** (`CapBnd` `00000110bdacffff` to `000001ffffffffff`, all 13 restored).

  It was never a host escape, which is why it is a Fixed and not a Security advisory: the uid stays
  `65534`, a capability held in a nested user namespace grants nothing over host-owned objects, and
  seccomp is inherited across `clone` and cannot be dropped under `NO_NEW_PRIVS`, so every syscall
  those capabilities would unlock stayed refused. Verified end to end at the time: `mount` from
  inside that nested namespace was SIGSYS-killed, so the read-only and masked-`/proc` contract held.
  What it did break was the documented claim, and defence in depth was thinner than the page said.

  The two halves need different mechanisms, and that is forced by seccomp, not chosen. `clone`
  cannot be denied by number without killing `fork`, `vfork`, `posix_spawn` and `pthread_create`
  with it, so its flags are read out of the register they arrive in (`args[0]`) and only
  `CLONE_NEWNS`/`NEWCGROUP`/`NEWUTS`/`NEWIPC`/`NEWUSER`/`NEWPID`/`NEWNET` are killed. `clone3` puts
  the same flags in a struct behind a pointer, which a BPF filter **cannot dereference**, so there
  is no way to allow an ordinary `clone3` while refusing a namespace one: it is refused wholesale
  with `ENOSYS`, the answer Docker and podman give for the same reason. `ENOSYS` rather than a kill
  is what keeps that safe, because every libc that uses `clone3` probes it and falls back to
  `clone`: glibc 2.34+ does exactly this, older glibc never calls it, musl never calls it. A
  rootless `--privileged` box omits the flag check as well, for the same reason it omits `unshare`.

  The count is now **34 syscalls denied**, 24 by SIGSYS and 10 by `ENOSYS`. `clone` is not among
  them and never will be: it is the only rule in the filter that inspects an argument rather than a
  number, and `the_clone_flag_check_is_the_last_block_and_its_jumps_land_correctly` walks the
  emitted BPF instructions to assert it, because a wrong jump offset still loads, still runs, and
  silently permits or refuses the wrong thing. The block has to be last, since reading `args[0]`
  overwrites the accumulator every preceding comparison depends on.

  Verified on **six targets** with the same probe, all identical: namespace clones and `unshare`
  SIGSYS-killed, `fork`/`vfork`/`pthread_create` x8/`system()` untouched, `clone3` returning
  `ENOSYS`. x86_64 (Linux 7.0), a Contabo VPS (Ubuntu 24.04, KVM), WSL2 (6.18), Raspberry Pi 5
  (6.6.51), Jetson Orin Nano (5.15-tegra) and an Arduino UNO Q (Android 6.16.7). Against real
  workloads on **glibc 2.41**, the version that probes `clone3` first: 16 Python threads,
  `subprocess`, `os.fork`, `multiprocessing.Pool`, 8 Node `worker_threads`, `child_process`,
  `apt-get update`, `apk add gcc`, and a `gcc` compile-and-run. All four pentest suites still pass
  (74 assertions) and the `kern run` battery is 74/74 on all six.

  One defect in the change was caught only by cross-compiling: `BPF_JSET` was
  `#[cfg(target_arch = "x86_64")]`, since the x32-ABI kill had been its only user, and the flag
  check made that a compile error on aarch64. No amount of x86 testing would have shown it.

- **`--cpuset-cpus` silently dropped the pin when no requested CPU existed.** On a 28-CPU machine,
  `kern run --cpuset-cpus 28 -- cmd` exited 0, printed nothing, and ran with `Cpus_allowed_list:
  0-27`: the caller asked to be confined to one CPU and got the whole machine. Same for 29, 100 and
  every value up to the point where systemd's own parser overflows. `kern box` had it too, through
  the same function.

  The code did this on purpose, and the reasoning is in the comment it shipped with: an all-invalid
  pin was passed through untouched "so the backend still rejects an all-invalid pin loudly rather
  than us silently running unpinned". Measured, that is false for the values people actually
  mistype. Only absurd ones (`999999`) overflow systemd's parser and fail loudly; an off-by-one on
  the CPU count is accepted, applied to nothing, and reported as success. The fallback worked
  exactly where it was not needed and failed on the realistic case, and a unit test asserted the
  pass-through, so the wrong behaviour was pinned rather than caught.

  A list in which nothing exists is now refused with the count and the valid range: `--cpuset-cpus
  28: this machine has 28 CPU(s), numbered 0-27, so none of the CPUs you asked for exist. Refusing
  rather than starting with no pin at all.` Refusing rather than clamping is deliberate and differs
  from `--cpus`: clamping `--cpus 999` to 28 moves toward the request, while clamping
  `--cpuset-cpus 28` to `0-27` inverts it. A partially valid list still clamps and says so
  (`0,28` becomes `0`), and the last real CPU is still accepted, so the refusal is not over-broad.

  Found by an extreme pass over `kern run`, the least-exercised verb in the tree: 74 assertions over
  exit-code propagation, stream fidelity (10 MB stdout byte-exact, NUL-safe), whether the memory and
  CPU caps are real (they are: SIGKILL past `--memory 64m`, 50% of a core under `--cpus 0.5`), the
  `--` contract, hostile cap values, signals and orphans, cgroup cleanup, and 50 concurrent runs.
  Two of the 74 failed on the first pass. One was this. The other was the harness counting every
  `kern` process on the machine rather than the ones it started, which reported four survivors that
  belonged to a stale 0.6.31 on `PATH`, a bug fixed two releases ago.

- **A `vgpio` device that is not on this host was skipped without a word.** Every other outcome in
  that resolver speaks: a dangerous node is refused by name, an unrecognised kind is flagged, a node
  the caller cannot open is called out with the fix. A path that simply does not exist was the last
  silent arm, and a typo looks exactly like a portable profile from there: `/dev/i2c-l` for
  `/dev/i2c-1` skips as quietly as a Pi profile attached on a desktop, and the box then starts
  without the device its author asked for. It is now a note rather than an error, so a profile shared
  across machines still runs, and a misspelling is visible.

- **A pod with `pasta` installed was told to install `pasta`.** `setup_outbound` returned one `bool`
  for four different outcomes, so `pod create` printed "NO outbound (install `passt`/`pasta` for
  egress)" whether pasta was missing, present but refusing to start, or working with no DNS. Found on
  WSL2 with `/usr/bin/pasta` present and the pod still coming up loopback-only, being told to install
  what it already had. pasta's own explanation was going to `/dev/null`.

  It now reports the cause: missing, or installed-and-failed with pasta's first line of stderr
  carried through, or NAT-up-but-no-DNS, which used to be reported as no outbound at all even though
  the pod could reach an IP. All three verified separately, including with a stub `pasta` that exits
  non-zero: the line reads "pasta IS installed but did not start: pasta: cannot open netns: Operation
  not permitted".

- **`kern cp` reported a syntax error when the syntax was right and the box was simply not there.**
  `as_box_ref` returned `None` for three different reasons, and the caller could only tell one story
  about all three: `kern cp f.txt nobox:/tmp/x` answered "kern cp needs a box: one side must be
  `<box>:<path>`", which is exactly the thing the caller had got right. Docker answers "No such
  container: nobox". It now answers "no box named 'nobox' is running", with the `kern ps` hint.

  The reading order is deliberate: an existing host path still wins over the box interpretation, so
  `kern cp weird:name.txt web:/tmp/` keeps working, and a first field containing a slash is a path
  rather than a name. Only a spec that is box-shaped AND names nothing on disk is reported as a
  missing box. Both cases are pinned by tests, including the colon-in-a-filename one that the fix
  had to avoid breaking.

- **`kern images` told you to reclaim a dangling entry with a command that does not reclaim it.**
  The footer read "N dangling (missing layers) - reclaim with `kern rmi <image>` or `kern gc`".
  `kern gc` prunes, sweeps orphaned build layers and box scratch, removes retired `--pull always`
  dirs and stale wait records, and does not touch the image list. Verified on a real dangling
  `ubuntu:latest`: it survived `gc` and went on the first `rmi`. The footer now names `rmi` only.

  Naming a command that does not work mattered more than usual here because of what the reader
  reaches for next: `kern gc --images` is not a stronger reclaim, it calls `remove_tree_forced` on
  the whole cache. Someone chasing one broken entry down that path deletes every image they have.
  Its help line said "Full cleanup: prune + scratch + build layers (+ --images)" and now says
  plainly that `--images` DELETES every cached image.

- **A volume written by a box was undeletable, and the error sent the reader nowhere.** Every OCI
  image box gets the uid RANGE by default, so a database image writes files owned by a uid that
  exists only inside that box's user namespace. `kern volume rm` then fails with
  `Permission denied (os error 13)` and the host user cannot fix it by any means available from the
  host. The hint under it said "run `kern volume ls` to see existing volumes", which is true and
  useless. Reproduced with `postgres:16-alpine`: its `pgdata/` comes out owned by a mapped uid.

  The message now names the cause and prints the two commands that actually work, ready to paste:
  empty the volume from INSIDE a box, which holds the mapping, then remove the husk. Verified by
  running exactly what it prints, and the volume was gone. The generic hint is also dropped whenever
  a volume error carries its own remedy, because a one-line pointer under two paste-ready commands is
  noise, and noise under an instruction is how the instruction gets skipped. `Error::Volume` now
  branches on the message, the same shape `oci_hint` already used.

- **The `--timeout` watchdog leak was fixed in one of the two watchdogs.** 0.6.32 replaced the
  foreground watchdog's `sleep(N)` with a pidfd wait, and closed the leak it described. The
  **detached** path has its own watchdog, `spawn_timeout_stop`, and it kept the bare sleep. So
  `kern box x -d --timeout N` followed by `kern stop x` still left one process asleep for the
  remainder of `N`, reparented to init: 884 KB and a pid per stopped box, until its deadline.

  Found by measurement, not by reading: a bottleneck audit ran 200 boxes and then eight detached
  ones, and `kern ps` reported 0 boxes while `ps` reported 9 live `kern` processes. Isolated to one
  command: `--timeout 20`, `kern stop` after a second, the process still there at t=15 s and gone at
  t=20, exactly the deadline. `strace` showed it going from `setsid` straight to
  `clock_nanosleep(25s)` with no `pidfd_open` anywhere, which is what separated it from the
  already-fixed twin.

  It now waits on a pidfd pinned to the supervisor, with `N` as a cap, through the same
  `wait_for_box_exit` the foreground watchdog uses. Keying on the supervisor loses nothing here,
  unlike in the foreground case: this watchdog only ever acts `if registry::pair_alive(&name,
  sup_pid)`, so a dead supervisor already meant "do nothing", and the pidfd also pins that exact
  supervisor so a recycled pid cannot make the pair-probe match a different box. Verified: `stop`
  now leaves 0 processes where it left 1, eight detached boxes stopped in bulk leave 0 where they
  left 8, and the deadline still fires on time (`-d --timeout 5` around a `sleep 60` stops the box
  at 5 s).

- **`apk` could not install anything in the WSL distro kern ships, so the command the installer
  itself prints at the end of a successful install did not work.** `install.ps1` closes with "the
  distro is a minimal Alpine, so for the SDKs add a runtime first: `apk add python3 py3-pip`". On
  the published 0.6.32 distro that fails with `ERROR: unable to select packages: python3 (no such
  package)`, and so does every other `apk add`, while the network is fine: `curl` to
  `dl-cdn.alpinelinux.org` returns 200 in 0.23 s from inside the same distro.

  `/etc/apk/repositories` was absent. The rootfs build passes the repositories to `apk.static` as
  `-X` flags, which configure that one invocation and write nothing into the rootfs, so `--initdb`
  left a distro with a working `apk` binary and no repositories at all. The build now writes the
  file. Verified by building the rootfs and reading it back out of the tarball, and on the machine
  by writing the same two lines by hand: `apk update` then resolves **24171 packages**,
  `apk add python3` installs 3.12.13, and `apk add openssh-client` supplies the `ssh-keygen` that
  `kern box --ssh` needs on the host side. The tarball stays 9.5 MB.

  This only ever affected kern's own pre-baked WSL distro. On a normal Linux host the package
  manager is the user's own and was never touched.

- **A `box` flag typed on `run` now explains the two verbs instead of misdirecting.**
  `kern run --image alpine -- sh` answered `unknown flag (put \`--\` before the command)`, which is
  wrong twice: the `--` is not the problem, and the obvious next attempt is
  `kern run -- --image alpine`, which hands the flag to the workload. `run` has no image and no
  namespaces by design, so no placement of `--` was ever going to work.

  It matters more than a bad hint usually does, because this is the one place a Docker reflex meets
  kern and the two verbs are inverted relative to it: `docker run` starts a container, `kern run`
  caps a process on the host and sandboxes nothing. Measured, `kern run -- sh -c 'id -u; hostname'`
  reports the host's uid, the host's hostname and `systemd` as pid 1, identical to running the
  command bare. Someone typing `kern run --read-only --network none -- ./untrusted` on that reflex
  believes they are isolated and is not, and nothing in the output said otherwise.

  Forty `box` flags now produce `` `kern run` has no --read-only. It caps a process on the host: no
  image, no namespaces, no sandbox. That flag belongs to the sandboxed verb: kern box <name> --image
  <ref> [-- CMD...] ``. A flag that is nobody's still gets the generic answer, since there is no verb
  to redirect to. `every_box_only_flag_is_really_a_box_flag` checks the list against the `box` parser
  itself rather than a second hand-kept copy, so the redirect can never name a flag `box` rejects.

### Documentation

- **`--egress-allow` needs a client that speaks proxy, and now says so.** kern hands the box the
  allowlist as a forward proxy and exports `http_proxy`/`https_proxy` into it, so `curl`, `pip`,
  `npm` and Python's HTTP stacks work unchanged. Alpine's default `wget` is busybox's, which does not
  implement the `CONNECT` tunnel HTTPS through a proxy needs: measured, `http://` works and
  `https://` fails with `wget: error getting response`. That is the first thing anyone testing the
  feature on the smallest image will hit, and it reads as the allowlist refusing a host it did not
  refuse. `docs/EGRESS.md` now has the table and the one-line fix.

- **What `pasta` costs is now a number instead of a gap.** The pod-egress section shipped with an
  unattributed +21.7 ms on time-to-first-byte, honest but unexplained. Measured properly against the
  same public IP from inside a pod and from the host: connect 29.8 ms against 26.2, and the
  request/response leg 30.0 against 26.4. It is **about 3.6 ms per network round trip**, flat, which
  is why an HTTPS request reads about four times that: its TLS handshake adds two more round trips.
  The gap was never mysterious, it was one cost multiplied by the number of trips.

  Three attempts to measure it failed first, all for the same reason and none of them kern's: a
  compose stack with a SINGLE service creates no pod, so there was no pasta, no egress, and `curl`
  inside the box had nothing to answer. The docs page also carried its opening paragraph twice, in
  two wordings; the second is gone.

- **Pod egress was undocumented.** `kern compose` attaches `pasta` for NAT'd outbound and DNS when
  it is installed, degrades to a loopback-only pod when it is not, and `--no-outbound` opts out.
  None of that appeared in any `.md`: the words `pasta` and `passt` were in zero documentation files
  (the only greps that matched were `passthrough`), so it existed solely in source comments and in
  one line printed at bring-up. `docs/DOCKER-COMPAT.md` now states it next to the shared-namespace
  model it belongs to, with what it costs, measured rather than asserted: service to service inside
  a pod 0.14 ms p50, TCP connect and TLS handshake identical to the host through pasta, cold DNS
  identical (32.8 ms in the pod against 53.3 on the host, both plain network latency), throughput
  about 9% lower. The one real asymmetry is that a pod has no DNS cache, so a host running a caching
  resolver answers a repeated name in under a millisecond while the pod pays the full lookup; the
  first measurement of that gap read as +29 ms of "NAT overhead" and was caching on the host side,
  which is why the cold-resolution control is in the table.

### Security

- **A registry's error text is scrubbed of control characters before it reaches the terminal.** The
  change above carries a remote server's own message into kern's error output, and that message is
  attacker-influenceable by definition: a hostile or compromised registry could answer with ANSI
  escapes and repaint the line, erase what came before it, or move the cursor, so a refusal could be
  made to read as a success. kern already strips control characters from every other untrusted
  string it shows, through `ui::scrub`; this path was carrying one through without it.

  Verified against a registry written to attack it: a `message` containing `ESC[2K ESC[1A ESC[32m
  PUSH RIUSCITO BEL` and a newline. Before, `cat -v` showed the escapes intact in kern's output;
  after, zero. What survives is inert printable text, and the newline is gone too, which is also
  what keeps a multi-line reply from breaking the single-line error format. `pasta`'s stderr, added
  in the same release, is scrubbed as well: it is a local binary and not the same threat, but one
  unscrubbed path is one the next reader has to reason about.

### Changed

- **A registry that refuses a token request now reports what the registry said.** `kern push` to
  ghcr.io failed with `no auth token in token response` and a hint to run `kern login`, addressed to
  a user who had just logged in successfully. The registry's own answer was in the body and was
  being discarded: `{"errors":[{"code":"DENIED","message":"requested access to the resource is
  denied"}]}`. That message is carried through now, with the part the reader cannot infer, that the
  credentials did reach the registry so the question is what that account may do with that name, not
  whether to authenticate again. Verified against ghcr.io itself. (The failure that prompted it was
  a GitHub *organisation* name used where the *user* name goes; the old text gave no way to see it.)

- **The `ssh` command line `--ssh` prints is now portable, and no longer tells you to switch host
  key checking off.** It read
  `ssh -p N -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1`. A box
  started inside kern's WSL distro is most often reached with Windows' own `ssh.exe`, where the null
  device is `NUL`; run the printed line verbatim there and it fails with
  `Host key verification failed`, measured, then works once `/dev/null` becomes `NUL`. So the hint
  did not work on the one platform for which kern ships a bridge.

  It now prints `-o StrictHostKeyChecking=accept-new` and no known-hosts override at all: one flag
  instead of two, identical on Linux and Windows, and it keeps the protection that matters.
  Verified in both directions: run verbatim against a host never seen before it connects with no
  prompt, `known_hosts` grows by one line and `ssh-keygen -F` finds the entry; regenerate the box's
  host keys and reconnect and it is refused, which `StrictHostKeyChecking=no` would not have done.
  `accept-new` needs OpenSSH 7.6 (2017), older than any Windows that ships `ssh.exe`.

- **The README quoted a multiplier its own table does not produce, and the page it cites for method
  quoted a different one.** The Performance section read "the gap that matters is to the engines,
  ~132x", two lines under a table giving kern 2.2 ms against podman 281.5 and docker 294.4, which is
  128x and 134x. The reader who followed the link to `BENCHMARKS.md` for the method found ~120x
  there. Neither figure was invented: `BENCHMARKS.md` divides the engines by kern **capped**
  (2.45 ms) and says so, the README's table measures it uncapped. Three numbers for one ratio on the
  launch page, and the largest of them was the one in the headline. The README now states the range
  its own table produces, 128 to 134x, and `scripts/stale-numbers.py` has a rule so 132x cannot come
  back.

- **The example count had drifted, and ten examples were unreachable from the index.** The README
  said "Ninety runnable examples" in two places while `examples/README.md` listed 84. Neither was
  right: examples had been added with no row in the index, so `agent-code-interpreter.py`,
  `docker-shim.sh`, `compose-declared-ports.sh`, `compose-systemd-unit.sh` and the two-service
  `stack-python-postgres/` walk-through existed and nothing in the tree pointed at them. Two of them
  were reachable only from a sentence in `docs/DOCKER-COMPAT.md`, the rest from nowhere. They are in
  the index now, and both counts read the number of rows it actually has.

- **The demo's alt text contradicted the demo.** `assets/demo.svg` describes itself to a screen
  reader as "docker run takes about 308 ms" while the terminal drawn in the image reads ~289 ms. The
  description is what a reader who cannot see the picture is given, so it was the only version of
  that number some readers got, and it was the stale one.

- **The Quickstart pointed at a file the reader does not have.** `kern compose stack.toml up` names
  a `stack.toml` that exists in the repo as `examples/stack.toml`; the line now says where to get
  one, so the only Quickstart entries that cannot be pasted verbatim are the ones that need a
  terminal or a program of your own.

## [0.6.32], 2026-08-02

### Fixed

- **`--timeout` left a watchdog process behind whenever the supervisor was killed rather than
  allowed to exit.** `--timeout N` forks a watchdog in the HOST namespace, before the box's
  `unshare(CLONE_NEWPID)`, so that it can signal the box's ns-init. It then slept `N` out, and the
  only thing that stopped it early was the supervisor's own cancellation on a normal exit. Kill the
  supervisor before it reaches that line and the watchdog was orphaned for the remainder of the
  deadline: 884 KB, one pid and one entry in every `ps`, for as long as the deadline had left.

  `kern stop` alone is a race (it SIGKILLs pid 1, then sweeps the supervisor's process group), and
  measured over six trials it leaked 0 of 6 that way. SIGKILLing the supervisor directly leaked
  **6 of 6**, and that is not a synthetic case: it is exactly what the Python and Node bindings do
  after `kern stop`, which is how **fourteen** of these accumulated in one evening of running the
  SDK suites, each carrying the SDK's 86405 s deadline, so each due to sleep for a day.

  The watchdog now waits on a **pidfd** for the box's exit with the deadline only as a cap, so it
  leaves the instant there is nothing left to guard, whoever killed the supervisor and whether or
  not anyone got to cancel it. The deadline itself is unchanged and still fires: a box that outlives
  it gets SIGTERM, then SIGKILL after the same 2 s grace, and the grace now also ends early if the
  box dies on the SIGTERM. Every failure mode of the new wait (no `pidfd_open`, an unreadable clock,
  an fd that cannot be polled, EINTR) degrades to sleeping the deadline out, which is precisely the
  old behaviour, so a signal can never fire EARLY on a box that still has time left.

  It deliberately does NOT key on the supervisor's death: SIGKILL a supervisor and the box's pid 1
  is orphaned but keeps running, and enforcing the deadline on exactly that box is the watchdog's
  reason to exist. Keying on the box's own exit keeps the safety net and removes the leak.

  This also closes the entry in `OPEN_ITEMS.md` that described the SDK suites as leaving **boxes**
  behind. That description was wrong, and the correction is recorded there: the survivors were not
  boxes. Examined rather than counted, each was `kern` at 884 KB RSS, 0% CPU, one thread, asleep in
  `hrtimer_nanosleep`, with no children and the HOST's namespaces. The box really was gone and
  `kern ps` was right to show nothing. Both SDK suites now finish from a clean slate with **zero**
  kern processes alive.

  Pinned by `stopping_a_box_leaves_no_timeout_watchdog_behind`, which fails against 0.6.31.

- **kern-sandbox 0.1.13: every wait in both bindings was on a clock instead of on an event.** Three
  separate places, one shape, each measured before and after.

  **Python, every call.** The binding enforced its own deadline with `Popen.wait(timeout=...)`,
  which does not block on the child: it polls on an exponential backoff (`delay = 0.0005`, then
  `delay = min(delay * 2, remaining, .05)`) whose wake-ups land at 0.5, 1.5, 3.5, 7.5, 15.5 and
  31.5 ms. Work finishing at 13.6 ms was not noticed until 15.5, and 200 identical calls landed on
  three discrete values rather than a distribution: 188 at 15-16 ms, 10 at 31-32, 2 at 64. It is now
  a `poll(2)` on a **pidfd**, readable the instant the box exits, with the deadline enforced by the
  kernel. Re-measured over 200 calls: p50 **15.75 to 13.91**, p90 **31.86 to 16.16**, p99 **64.03 to
  34.34**, floor **15.61 to 11.74**, and the quantisation is gone. A bare `run(["true"])`, pinned by
  the same rounding to the 7.5 ms wake-up, is **4.03 ms**, which puts the binding's own overhead
  over a native `kern box` at **0.23 ms** where the published figure was +3.9. `select` was not
  used: it is bounded by `FD_SETSIZE` on the fd NUMBER, so a caller holding many sockets would get a
  `ValueError` out of a library that has nothing to do with its fd count.

  **Node, after every call.** A 250 ms `setInterval` armed on every call was never cleared by the
  code that resolves it; it cleared itself on its own next tick, and until then it kept the event
  loop alive. Measured between a call resolving and the process being able to exit: **224 to 232 ms
  of dead time, against 19 to 27 ms of real work**. The interval only existed to notice a flag set
  in one place, so it is deleted and that one place acts directly. Re-measured: **0.2 ms**.

  **Node, closing a persistent kernel.** `close()` did `await setTimeout(150)` unconditionally,
  whether or not the box had already gone: **152 ms measured** for a box that exits in a few. It now
  waits on the child's own `exit` event with that 150 ms as a cap only. Re-measured: **16 to 18 ms**,
  the remainder being the `kern stop` it spawns, which is real work.

  Six regression tests, all verified to fail against 0.1.12. The Python ones assert the MECHANISM
  rather than a duration (a timed wait is simply not allowed to happen while a pidfd is available),
  so they cannot flap on a loaded machine, and both fallback branches are exercised: with
  `os.pidfd_open` deleted, and with it raising ENOSYS as a syscall filter would. The ENOSYS branch
  was hit 71 times in one suite run, so it is live code and not decoration.

- **A stale cross-reference put two different numbers on the same measurement.** `BENCHMARKS.md`
  pointed at "the 3.6 ms OCI-image row above" while the row, the README table and the rest of
  `BENCHMARKS.md` all say **3.4 ms**. Both binding READMEs and the launch blog post carried the same
  stale 3.6. All aligned on the measured figure.

- **`OPEN_ITEMS.md` shipped three of its sections twice, and the second copy was the OLD text.**
  Including the claim that the 0.1.12 concurrency tests left 60 boxes of their own, which the newer
  copy immediately above it explicitly retracts. A reader scrolling down found a retracted claim
  presented as current. The stale block is removed.

## [0.6.31], 2026-08-01

### Fixed

- **A published port stalled 40 ms on every reused connection: Nagle was left on in the forwarder.**
  `kern box -p` pumps bytes in userspace, and neither side of that pump set `TCP_NODELAY`. A response
  written as headers-then-body therefore waited on the peer's delayed-ACK timer, and it bit ONLY on a
  kept-alive connection: the normal mode for HTTP/1.1, gRPC, Postgres and Redis.

  Measured with nginx behind `-p`, one keep-alive connection: **59 requests/s with p99 pinned at
  exactly 42.0 ms** at every concurrency level, against **2614/s when every request opened a FRESH
  connection**. A proxy that is 44x faster when you stop reusing the connection is the signature of a
  timer rather than of load, and a constant p99 to one decimal place is not contention.

  With `TCP_NODELAY` on both the accepted socket and the socket into the box:

  | keep-alive connections | before | after |
  |---:|---:|---:|
  | 1 | 59 req/s | **12,479** |
  | 4 | 272 | 19,605 |
  | 16 | 832 | 19,425 |
  | 32 | 1,780 | 18,364 |

  p99 goes from a pinned 42.0 ms to 0.27 ms at one connection, and the forwarder now measures at
  parity with not having one: 19,425 req/s through `-p` against 17,185 for the same nginx reached
  directly over `--net`. Bandwidth was never the problem and is unchanged, 1195 MB/s against 1250 on
  a 32 MiB body, which is why this survived: anyone benchmarking a published port with a large
  download would have seen nothing wrong.

  Found by benchmarking a real application rather than `/bin/true`. The regression test asserts the
  option reads back from `getsockopt` with the control that a fresh socket has Nagle ON, so it cannot
  pass vacuously, and it was watched failing when the level is `SOL_SOCKET` instead of `IPPROTO_TCP`.

  A shell-level case was written for `pentest-ports.sh` and then REMOVED, which is worth recording:
  neither an echo server nor a two-write responder reproduces the stall, because both close the
  connection after one exchange and the defect needs a reused one. Measured at 0.18 and 0.63 ms
  against an unfixed binary, so it would have shipped as coverage that could never fail.

- **kern-sandbox 0.1.12: two concurrent calls on one `Sandbox` fought over a single file.** Both
  bindings wrote the workload's environment to one fixed host-side path, `<workspace>/.kern-env`,
  unlinking it and re-creating it with `O_EXCL|O_NOFOLLOW` on every call. That create is a security
  property, it refuses to write through a symlink the box may have planted, and it is unchanged; the
  defect was the shared NAME. In Python the loser of the race got a bare `FileExistsError` straight
  out of `run_code`: 11 of 40 concurrent calls failed that way, measured. In Node it was worse than
  an error, because one call removed the file while kern was still starting for another and had not
  read it yet, so that box died with
  `error: sandbox: cannot read --env-file '...': No such file or directory`. The README advertises
  100 concurrent calls, so this was on the documented path, not an exotic one. The file is now named
  per call and removed on every exit path, including the two spawn failures, where it used to be left
  behind: a persistent `workspace=` accumulated one per session. Verified by reverting each fix and
  watching the new tests fail with those exact messages, then 100/100 concurrent calls succeeding
  with zero files left.

- **A mistyped flag on `kern pull` or `kern push` was skipped, and its VALUE became the image.**
  `parse_pull` takes the first argument that does not start with `-`, and the arm above it discarded
  anything that did, so one transposition was enough: `kern pull --platfrom linux/arm64 alpine:3.19`
  tried to pull an image literally named `linux/arm64`, dropped the `alpine:3.19` the caller asked
  for, and reported `cannot access 'linux/arm64' ... it may be private (run kern login)`. The user is
  sent to authenticate over a spelling mistake, and the image they actually named appears in no
  message at all. `push` had the same shape through its `filter(|a| !a.starts_with('-'))`. Thirty
  other verbs already called `reject_unknown_flags`; these two were the ones that did not. Found by
  probing every verb with a deliberately bogus flag and comparing behaviour, not by reading.

### Documentation

- **The SDK README quoted a speed trade that no longer exists, and the wrong side of it.** It read
  "`enforce_limits=False` is about twice as fast", and gave `run(["true"])` as ~3.5 ms without
  enforcement against ~7.5 with it. Measured today on the machine the table names, same session,
  `python:3.12-slim`: **7.56 ms and 7.58 ms**, a ratio of 1.00, and isolating the switch on the bare
  binary puts it at **0.15 ms, 1.05×**. The claim dated from when a cap meant a `systemd-run` scope
  per box; since 0.6.15 kern applies caps in its own delegated slice, which `BENCHMARKS.md` already
  documented. The advice was therefore inverted: the README offered giving up hard memory and PID
  enforcement to buy milliseconds that are no longer there. Under 100 concurrent calls the same holds,
  1.04× on wall clock against the quoted ~5×. The Node README had already been corrected
  ("`false` is best-effort and NO faster"); the two contradicted each other.

  Every other number in that section was re-measured beside it rather than inherited: `run_code`
  16.0 ms against Docker's 286 ms (the README said 344, so it overstated the gap), native box start
  2.57 ms from a rootfs and 3.62 ms from an image, and the wrapper's own overhead, +3.9 ms, which the
  old table contradicted by placing the wrapped call BELOW the native one.

- **Both binding READMEs and both package manifests described kern differently from the README.**
  All four now carry the project's tagline. This ships with 0.1.12 rather than alone, so the text on
  GitHub and the text on PyPI and npm change together instead of drifting apart.

- **Two placeholders vanished when GitHub rendered the changelog.** `removed build '<id>'` sat in
  prose rather than in a code span, and a `<name>` line used backslash-escaped backticks inside a
  code span, a form markdown does not support, which closed the span early. GitHub parsed both as
  HTML tags and dropped them, so the text read `removed build ''`. Confirmed by rendering the file
  through GitHub's own API and counting: 2 of 2 `<id>` and 21 of 21 `<name>` now survive, where
  before it was 1 and 20. The whole 30-file corpus was checked the same way and has no others.

- **Three numbers did not follow from the tables printed beside them.** `BENCHMARKS.md` claimed
  `~267× Docker` for the 200-box fan-out where its own row gives 15.96 s against kern's 0.09, which
  is ~177×; the TL;DR claimed `~125×` and quoted `Docker ~289 ms` where the table says 292.9, so the
  ratio is ~133× against the `--rootfs` path and ~80× against `--image`. `blog/introducing-kern.md`
  said `~2.3 ms` in prose and `2.2 ms` in its own table two screens down, gave podman/Docker as
  288/289 against the table's 287.5/292.9, and claimed `~80-160×` where no pair of its rows produces
  160. Every ratio in the docs now derives from a number printed next to it.

- **`examples/README.md` had no `## ` heading at all** (fifteen sections were `### ` directly under
  the title) and `docs/CONFIG.md` opened with an `### ` before its first `## `. GitHub builds its
  outline sidebar from those levels, so both documents nested wrongly. Anchors are derived from the
  heading TEXT, so no link changed.

- **The blog posts used a different one-line description of kern than the README.** Both now open
  with the project's stated tagline.

## Earlier releases

0.6.30 and everything before it live in the signed tags: `git show v0.6.30`, or the
[tag list](https://github.com/getkern/kern/tags). All 26 tags are signed and timestamped to
Bitcoin ([provenance/](provenance/)).

[0.6.34]: https://github.com/getkern/kern/releases/tag/v0.6.34
[0.6.32]: https://github.com/getkern/kern/releases/tag/v0.6.32
[0.6.31]: https://github.com/getkern/kern/releases/tag/v0.6.31
