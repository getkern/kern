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

## [0.6.50]

Post-0.6.43 hardening. 750 Rust tests, clippy `-D warnings`, verified on x86_64 and on three aarch64
boards (kernels 6.16 / 6.6 / 5.15).

### Security

- **A box can no longer forge another box's recorded security posture.** `kern exec` reconstructs a
  box's capability and seccomp posture from its registry record; a box that bind-mounted the registry
  (`-v $XDG_RUNTIME_DIR/kern:/dst`) could rewrite a peer's record and elevate that peer's `exec`
  (proven: `capdropall=0` + `capadds=21` re-added `CAP_SYS_ADMIN`, `CapEff` going from `0` to
  `00000110bda4ffff`). `-v` now refuses any source that resolves onto the trust-bearing registry dirs
  (`instances/`, `claims/`, the exit dir) or a parent that contains them, in every equivalent path form
  (trailing slash, `.`/`..`, a symlink, the parent), because the source is canonicalised before the
  containment check. The refusal now also matches by `(device, inode)` IDENTITY, not only by path: a
  `mount --bind` of the registry to another location gives it a different canonical path but the same
  inode, which a path-only matcher would have waved through - closed, and consistent with the vgpio
  device guard, which already denies by major/minor identity.
- **`socket(AF_VSOCK, …)` is refused with `EAFNOSUPPORT`** in both the denylist and the allowlist. The
  network namespace does not contain vsock (it is not an IP address family), so on a host with a
  `vsock` transport loaded (WSL2, where `VMADDR_CID_HOST` reaches the Windows side) a box could
  otherwise reach the host past its loopback netns. Closes the one place kern's default was wider than
  moby's on `socket`; verified with a discriminant (the same call succeeds outside a box and returns
  `EAFNOSUPPORT` inside one).
- **The capability bounding-set drop is VERIFIED, not deduced.** After `PR_CAPBSET_DROP`, kern confirms
  each dropped capability is actually gone with `PR_CAPBSET_READ` and fails closed if any is still
  present, instead of trusting the per-call errno. The per-cap `prctl` probe (a handful of microsecond
  calls over exactly the dropped caps) replaced reading and parsing the ~1 KiB `/proc/self/status` on
  every box start, which measured as the dominant cost of the campaign's box-start overhead - removing
  it returns cold start to the pre-campaign baseline (~20 us apart, within noise) with the SAME check.
- **`CAP_SYS_PTRACE` is dropped by default** (14 dangerous caps, up from 13): dropping the cap closes
  the `/proc/<pid>/mem` cross-process read, not only the `ptrace` syscall the filter already killed.
- **The seccomp mode is RECORDED and reproduced.** A box records its filter mode; `kern exec` and the
  health probe install the RECORDED mode instead of re-reading `KERN_SECCOMP` from the caller's
  environment. An absent or corrupt posture record makes `exec` refuse (fail-loud), never silently
  falling to a weaker filter.
- **`KERN_MAX_CONCURRENT` is enforced atomically** under a `flock`, closing the TOCTOU window where
  concurrent starts could exceed the fleet cap (6 parallel starts under a cap of 3 admit exactly 3).
- **Detached boxes whose supervisor is SIGKILL'd are reaped via `cgroup.kill`** (kernel 5.14+), which
  reaches grandchildren a bare `rmdir` would leak.
- **`KERN_SECCOMP=allowlist-audit` warns at box start** that it is a VALIDATION mode, less confined
  than the default (its log-and-run terminal lets `clone3`/`io_uring` and every other ENOSYS-denied
  call RUN), and not a production posture. The kill set still kills.
- **An fd inherited from kern's caller no longer leaks into the box (CVE-2016-9962 class).** kern marks
  every descriptor IT opens `CLOEXEC`, so none of its own fds crossed `execvp` - but a descriptor the
  CALLER left open (an SDK spawning boxes while holding a socket or a host file, a CI runner, a
  supervisor) is not kern's to mark, and passed straight through into the workload as a live handle to a
  host object OUTSIDE the box's rootfs. Proven: a file the box could not see by path (`/tmp/host-secret`
  on the host, invisible in alpine's rootfs) was read through the leaked fd. The box workload path and
  `kern exec` now `shed_inherited_fds` immediately before `execvp` - the same primitive the `-p`/egress
  helper children already used - keeping only the readiness pipe; the `--init` reaper is covered too
  (it would otherwise keep the fds readable via `/proc/1/fd`).
- **A pulled layer's setuid/setgid bit is STRIPPED off every file at extraction.** The layer re-emit
  pass already dropped device nodes; it now also clears `0o6000` from every regular file (recomputing
  the tar checksum so the block still extracts), and preserves the sticky bit and setgid-on-directory
  (legitimate `/tmp` and group-inheritance modes). A setuid bit was already inert on both supported
  paths - the box root mount is `MS_NOSUID` and rootless extraction owns every file as the caller, not
  root - so this changes nothing there; it makes the on-disk rootfs safe by construction on the one path
  those defenses do not cover, a `pull --dest` tree executed OUTSIDE a box or a `pull` run as real root.
  The prior code comment claimed the tar vetter rejected setuid; it did not, and the claim is now true.

### Added

- **A CI gate now catches a new kernel syscall the default denylist would silently allow.** A denylist
  permits everything it does not name, so every kernel release that adds a syscall widens the box's
  surface with no human in the loop. `scripts/gen-seccomp-allowlist.py --check` (already run in CI) now
  also verifies that every `__NR_*` the kernel headers define is allowed (moby set), denied
  (`KERN_DENIED`), or on an explicit REVIEWED list of obsolete/box-local calls - and fails, naming the
  syscall, when a new one is neither. Checks x86_64 and aarch64.

### Fixed

- **A detached box's captured log is size-capped, so it can't DoS the user session.** `kern box -d`
  sent the workload's stdout/stderr straight to `$XDG_RUNTIME_DIR/kern/logs/<box>.log` with no bound; a
  box that writes without end (`yes`, a crash loop) filled the small tmpfs-backed runtime dir, and a
  full `/run/user/<uid>` breaks the user session (systemd-user, Wayland can no longer create sockets or
  state). The log now flows through a forked pump into a single-generation ring (`<log>` + `<log>.1`),
  bounded at 32 MiB per box; a full disk (`ENOSPC`) drops output rather than blocking or killing the
  workload. `kern logs -f` may skip lines across a rotation (as Docker's does). The pump detaches its own
  stdio to `/dev/null` so `kern box -d` still returns immediately when its stdout is a pipe. It moves
  bytes with `splice(2)` (ZERO-COPY pipe->file, no userspace `read`+`write` pair), so draining a
  gigabyte-per-second flood costs one in-kernel copy instead of two - roughly halving the pump's CPU,
  which runs outside the box's cgroup cap - and falls back to `read`+`write` on a filesystem that refuses
  `splice`. Verified on x86_64 (6.8, WSL2 6.18) and aarch64 (tegra 5.15): capped, no hang, no fallback.
- **An OOM in a box kills the WHOLE box, not one process.** kern now sets `memory.oom.group = 1` on each
  box cgroup, so when the box hits its `memory.max` the kernel kills every process in it at once instead
  of the single highest-`oom_score` task - which could leave PID 1 alive and the box half-dead but still
  reading `running`. Best-effort (the file exists only where the `memory` controller is delegated, which
  the "--memory not enforced" warning already reports).
- **A `kern ps`/`gc` under fd exhaustion no longer prunes or mis-reaps a live box.** The orphan liveness
  probe (`stat`/`open` on the recorded cgroup) treated every error as "cgroup gone"; under `EMFILE`/
  `ENOMEM`/`ESTALE` that would drop a live record (recreating the ghost) or, worse, misclassify. The
  probe is now three-state - only `ENOENT`/`ENOTDIR` prove the cgroup is gone; a transient error yields
  `Unknown`, which never prunes and never reaps and is re-evaluated on the next pass (it is never
  persisted). The reap refuses on the same transient errors, so it never drops a record it could not
  evaluate.
- **A detached box whose supervisor is SIGKILL'd/OOM'd no longer becomes an unreachable "ghost".**
  `kern ps`, `stop`, and `exec` tracked a box by its SUPERVISOR pid; its cgroup is named after PID 1 (a
  different pid). When the supervisor died but PID 1 and the `-p` forwarder lived on (still holding the
  host port), the pid-based commands read the box as dead and DROPPED it from the registry, so `kern
  stop <name>` answered "no running box" and the port could not be reclaimed through kern - while `gc`
  read it as alive (its cgroup-name pid was still live) and never reaped it. The registry entry now
  records the box's dedicated `kern-box-*` cgroup path, and liveness is a THREE-state verdict from
  cgroup-v2 `cgroup.events` (`populated`), which needs no live pid and cannot be fooled by pid reuse:
  supervisor alive → `running`; supervisor dead, cgroup populated → `orphaned` (shown in `kern ps` and
  `--filter status=orphaned`, no longer hidden); cgroup empty/absent → `exited` (record pruned). `kern
  stop` and `kern gc` reap an `orphaned` box with `cgroup.kill`, which frees the held port. A box with no
  dedicated cgroup (no systemd-user) records no path and keeps the previous supervisor-pid liveness.
  The reap is IDENTITY-safe against pid reuse: the `kern-box-<name>-<pid>` path embeds a PID, so a later
  box could come to occupy it, and `cgroup.kill` on the path alone would kill the WRONG box. The record
  also stores the cgroup dir's `(st_dev, st_ino)`, and both liveness and reap confirm it - the reap opens
  the dir once, `fstat`s the pinned fd, and writes `cgroup.kill` via `openat` on that fd, so an identity
  mismatch (path recreated as a different cgroup) reads as exited and nothing is killed, TOCTOU-free.
- **A non-UTF-8 argument no longer crashes kern.** `main` read the command line with `std::env::args()`,
  which PANICS on an argument that is not valid UTF-8, so a box name or a `-v` path carrying a raw `0xFF`
  or a truncated multibyte char aborted the process before it could reject the input. It now reads with
  `args_os()` and converts lossily, so an invalid argument fails the name/path validator with a message.
- **The instance record is written atomically.** `register` did a plain `fs::write` (open `O_TRUNC`,
  then write), so a `SIGKILL`/OOM between the truncate and the last byte left a TRUNCATED record - and
  the capability/seccomp posture lines are written last, so a peer's `kern exec` could reconstruct a
  WEAKER posture from the half that survived. It now stages the record in a hidden temp and `rename`s it
  over the entry: a reader sees the whole record or none. Additionally, `exec` now refuses a record that
  carries `capdropall` but is missing `capdrops`/`capadds` (a truncation past the drop lists), rather
  than rebuilding a posture from the surviving fields.
- **systemd detection no longer depends on `XDG_RUNTIME_DIR` alone.** `user_systemd_present` (which
  decides the direct cgroup cap path) measured only `$XDG_RUNTIME_DIR/systemd`, so an unset or
  scratch-subdir `XDG_RUNTIME_DIR` made kern miss a running systemd and fall to the best-effort path
  with the requested cap unenforced. It now checks the standard `/run/user/<uid>/systemd` (built from
  `getuid`) first, and the env-named location as a fallback - a misconfigured runtime dir no longer
  disables cap enforcement.
- **`kern doctor` write-probes the real capability target** instead of asserting memory enforcement,
  reporting the cap state honestly (enforced / present-but-not-delegated / absent / unknown).
- **A requested resource cap that cannot be enforced is no longer SILENT.** When kern cannot place a
  box in a delegated cgroup - no systemd user manager was reachable (its marker is
  `$XDG_RUNTIME_DIR/systemd`, so a wrong or unset `XDG_RUNTIME_DIR` silently disables the direct path),
  or the host is genuinely systemd-less - an explicit `--memory`/`--pids-limit`/`--cpus` was accepted
  and enforced NOTHING, with no message. It now warns that the box runs UNCAPPED and names the likely
  cause (check `XDG_RUNTIME_DIR`; `kern doctor` shows the delegation state). Under a normal login or
  desktop session the cap is enforced exactly as before, so this path stays quiet there. The
  once-per-process "controller absent from this tree" notice covered only a controller missing
  entirely; this covers the box that could not be placed where the present controller would bite.
- **`--pids-limit 1` is refused at parse, by name.** A box needs one `pids.max` slot for its own PID 1
  and at least one more for the workload, so `1` failed the setup fork with a bare "fork failed" that
  never mentioned the cap. The floor is now `>= 2`, rejected with a message that names `--pids-limit`
  and explains the minimum, before any box work.
- **Multiple `vcpu:` profiles on one box now warn.** They do not merge (the first to set each field
  wins, as documented), so a second `vcpu:` was silently a no-op on any field the first set. kern now
  names which profile is in force and which are ignored, and points at `extends` for layering.
  `vgpio:`/`vdisk:` still stack silently, since several of those are legitimate.

## [0.6.43], 2026-08-04

### Fixed

- **`volume ls --json` named volumes that do not exist, and `kern top` could delete the wrong one.**
  The scan stripped control characters out of a name before anything saw it, so the listing reported
  3 of 38 names that are not on disk. A script doing `kern volume rm "$name"` then fails or, when the
  stripped form collides with another volume's real name, removes a volume nobody selected. `kern
  top`'s remove prompt fed the same stripped string to its destructive action.

  A name is now carried twice, because it answers two questions and one string cannot do both: the
  stripped form for a terminal, the exact form for a syscall. The exact one is escaped on the way
  into JSON, so the byte survives without ever reaching a terminal raw. Found by planting directories
  under `volumes/`, not by reading: a name with a control byte cannot be created THROUGH kern, which
  bounds the exposure and does not make a misdirected delete acceptable.

  With it, the contradiction the fix exposed: `ls` listed names that `inspect`, `rm` and `-v` all
  refuse, because `validate` enforces the creation charset. Loosening it is the wrong direction, it
  is also what keeps a name to a single path component, so each entry now carries `usable` and the
  table marks it.

- **`kern <verb> --help` printed the whole 160-line reference on a terminal.** The per-verb filter
  matched on de-coloured lines, and de-coloured them by stripping control characters and then
  replacing the palette strings: the first step removes the ESC byte, so `[1m` survived as printable
  text and every replacement searched for a sequence that was no longer there. Nothing matched and
  the filter fell back to the full page.

  It shipped because the test could not see it: with stdout captured, stdout is not a tty, the
  palette is empty, and with an empty palette the broken code is correct. A terminal saw 161 lines
  where the captured run saw 75. There is now a unit test on `strip_ansi` with the escape codes
  written out, and an end-to-end test under a real pty.

- **Ten verbs the reference documents could not be tab-completed**: `commit`, `rmi`, `rename`,
  `update`, `wait`, `diff`, `events`, `up`, `down`, `uninstall`. The completion list and the
  `COMMANDS:` block are two hand-written descriptions of one parser; the file even carried the
  comment "kept in one place so all three shells stay in sync", which was true of the three shells
  and silent about the other place. `the_completions_and_the_reference_agree` compares them now.

- **Four read verbs refused `--json`**: `volume ls`, `pod ls`, `config list` and `diff`, while `ps`,
  `images`, `stats`, `inspect` and `builds` accepted it. A script reading those four had to parse a
  table, and `kern diff` prints `C /path` separated by one space with the path chosen by the
  workload. `volume inspect` gained it too. `every_read_verb_accepts_json` keeps the set closed.

- **`kern run` accepted six flags and the reference named two.** `--cpuset-cpus`, `--config` and
  `--memory-swap-max` were documented nowhere. Found by the duplicate-flag gate, which reported that
  `run` advertised no flags at all.

- **`volume inspect` spelled an absent quota `none`**, which reads as "nothing allowed" as easily as
  "no ceiling", while `volume ls` printed `∞` for the same volume. The table already refused a bare
  `-` for exactly that ambiguity and the rule had not been applied here. Three views, one fact:
  `unlimited`, `∞`, and `null` in JSON.

- **A box with no memory cap on a host that cannot enforce one said nothing.** Every box carries a
  cap, the default 512 MiB when none is typed, so "this cap cannot be enforced" is true of every box
  on such a host. The warning was gated on the user having typed `--memory`, so the common case ran
  with unbounded RAM in silence. An outside tester on a host like that reported the limits as "soft"
  with no way to tell a degraded host from a degraded runtime.

  What kept it gated was a real objection: a line on every 2 ms box start is noise that trains the
  reader to skip it. The resolution is that this is a property of the HOST, not of the box, so it is
  stated once per host, claimed with `O_CREAT|O_EXCL` so two boxes starting in the same instant race
  in the kernel and exactly one prints. A `Once` alone cannot do it: it is per process, and every box
  is a new process. An explicit `--memory` keeps its per-invocation warning, since asking for a
  specific ceiling and not getting it is a different failure from starting a default box. Where the
  marker cannot be written at all, the notice repeats rather than going quiet.

  Verified end to end against a host that does not delegate the controller, reproduced in a mount
  namespace with a `/sys/fs/cgroup` carrying no `memory` in any node: first box warns, second is
  silent, `--memory 64m` warns again. The discriminant is the published 0.6.38 binary in the same
  namespace, which prints nothing at all. Measured cost of moving the check onto every box start:
  33 us between the two binaries, against 48 to 66 us of spread between two runs of the same one,
  so not distinguishable from zero at this resolution.

- **`kern box --help` listed `--timeout` twice**, and the entry a reader reaches first was the one
  that omits what actually happens: SIGTERM at n seconds, SIGKILL 2 seconds after that. An outside
  tester read the short entry, saw a box still alive at n, and reported the timeout as broken. It is
  not: measured at a constant 2.0 s of grace on 1, 2 and 5 second timeouts, and the process dies of
  SIGKILL because it is PID 1 in its namespace and the kernel gives PID 1 no default SIGTERM action.
  `no_verb_advertises_a_flag_twice` now refuses a flag listed twice in one verb's help.

- **`--plan` resolved profiles against a different `kern.toml` than the launch would.** `box_plan`
  called `config::load(None)`, which reads `$KERN_CONFIG` or `~/.config/kern/kern.toml`, while the
  launch reads the path given to `--config`. So `kern box app --config ./kern.toml vcpu:slim --plan`
  answered `cannot attach: no [[vcpu]] profile named 'slim' in kern.toml` about a profile declared
  in the file it had just been handed, and the launch then attached it.

  A preview that denies what will happen is worse than no preview, because it is believed. It was
  introduced by the change in this same release that made `--plan` report all three profile kinds:
  the reporting was right and the source was not, and the manual check that accepted it used
  `KERN_CONFIG`, which is the one path that worked.

  The regression test asserts the discriminant rather than the symptom: `--config <path>` and
  `KERN_CONFIG=<path>` name the same file, so they must produce the same preview. Asserting only
  "does not say cannot attach" would go quiet again the moment a third config source is added.

- **A crafted `kern.toml` could repaint kern's own output.** A `backend` value holding the real
  bytes `ESC[2K ESC[1A ESC[32m` came out unfiltered, so the refusal erased its own line, moved the
  cursor up and repainted in green: a rejection could be made to read as a success. A carriage
  return did the same to the start of the line. Five fields leaked, measured: the profile name, the
  size, and the `backend` of all three kinds. A `kern.toml` is not always the user's own file, since
  it travels with a project and `--config`/`KERN_CONFIG` take a path.

  This is output integrity, not a boundary: nothing about it escapes a box or grants a capability.

  It is scrubbed at the two places an error reaches the user rather than at the ~27 sites that
  format a config value, because the next message added would not be. No error message in this CLI
  is multi-line, checked across every construction, so removing control characters joins nothing and
  a clean message is unchanged. What survives is inert printable text.

  With it, the LENGTH half of the same problem: a 4 KiB backend produced a 4362-byte error line.
  Bounded to 300 characters with the count named, truncating on CHARACTER boundaries, since slicing
  UTF-8 at a byte offset can split a character.

- **A physical block whose id was the reserved sentinel was accepted, and the two halves disagreed
  about it.** `[[disk]] id = "ram"` made `backend = "ram"` mean two things: validation read the
  reserved word and the resolver found the declared pool. Renaming that block would have moved the
  profile from a real disk to a tmpfs without a word. The declared ids are scanned before the
  sentinel shortcut now, so the collision is refused whatever the backend says, and a collision
  later in the list is caught too.

- **Three asymmetries between the profile kinds, found by building the parity matrix rather than by
  reading.** `vcpu:`, `vgpio:` and `vdisk:` are one model attached the same way, and three places
  treated one of them differently:

  `kern run` told you it ignores a `vdisk:` and said nothing about a `vgpio:`, which under `run` is
  cooperative metadata (`KERN_VGPIO_NAME`/`_PINS`) and confines nothing, because there is no mount
  namespace either way. A device grant that silently grants nothing is the worst shape this can
  take. Both notices are also emitted once now: `run` re-execs through `systemd-run --user --scope`
  and printed the vdisk line twice on the default path, which only `KERN_NO_SCOPE=1` hid.

  `--plan` previewed `vgpio:` device grants and neither the caps nor the disk, so a box carrying all
  three previewed one. The comment justifying the vgpio case stated the principle exactly: a preview
  that lists three mounts while saying nothing about `/dev/i2c-5` is not a preview of what will be
  created. It now reports all three, resolved with the same calls the launch makes, and a profile
  that cannot attach says so at plan time.

  The dangling-backend error told every kind to "use `backend = \"{sentinel}\"` for the whole host".
  For a `vdisk:` the sentinel is `ram`, and this module's own doc comment says `ram` is a RAM-backed
  tmpfs: the message misdescribed the fix it was recommending. It also said "declare a matching
  [[disk]]" without saying how.

  Fixed by construction rather than by wording: the sentinel, its description, the `kind:` prefix and
  the physical block name were four parallel arguments that all had to agree, and now come from one
  `ProfileKind`. A call site names the kind; it cannot hand one kind another's strings. The message
  names `kern config setup` and `kern top` as the two ways to declare a physical block.

- **An official image failed on a host without `newuidmap` and kern said nothing.** The `--image`
  path maps a uid RANGE by default so an image can drop privilege in its entrypoint; where the
  helpers or an `/etc/subuid` allocation are missing, kern falls back to the single-uid map. Measured
  with `nginx:alpine`: `chown nginx:nginx /tmp` succeeds with the range and returns
  `chown: /tmp: Invalid argument` without it, so the image dies on an error naming neither.

  Deliberately not "warn earlier", which would put a line on every box start on such a host. The note
  is emitted only when the range was wanted, could not be built, AND the box exited non-zero.
  Verified on hardware: it fires on the Arduino UNO Q, which has no `newuidmap`, and stays silent on
  the Raspberry Pi 5, which has one.

- **`kern-sandbox` did not drop capabilities** (0.1.14, both bindings), on the one path whose purpose
  is running code nobody has read, while the README told CLI users to write `--cap-drop ALL` for
  exactly that case. A `run_code` box held `CapEff 00000110bdacffff`; it holds `0000000000000000`
  now. Measured to cost nothing on the supported workloads. Not behaviour-free in one case, which is
  why the opt-out exists: a workload binding a port below 1024 inside the box needs
  `CAP_NET_BIND_SERVICE`. Pass `cap_drop=()` or `capDrop: []`.

- **kern reported only the FIRST line of `pasta`'s stderr** when a pod could not get outbound
  networking. On WSL2 that line is "Started as root, will change to nobody.", true and useless: the
  reason is four lines below. All of them are joined now, capped and scrubbed.

- **`docs/CONFIG.md` documented 39 of the 49 `[box.NAME]` keys the parser accepts.** Missing:
  `add_host`, `expose`, `init`, `labels`, `port`, `restart_max`, `stop_grace_period`, `stop_signal`,
  `sysctls`, `ulimits`. Two of them, `port` and `expose`, also break the document's own rule that
  every key maps to a CLI flag, because they are pod-scoped; the rule now states its exceptions.

- **`SECURITY.md` contradicted itself on the syscall counts**, saying "34 denied: 24 kill plus 10
  ENOSYS" in one bullet and "9 plus 24 is the 33" two paragraphs below, half-updated when `clone3`
  joined the set. The test covered only the first sentence.

- **Eight dead internal links**, in `ROADMAP.md`, `docs/DOCKER-COMPAT.md`, `docs/INSTALL.md` and
  `docs/RESOURCES.md`: README sections that had been renamed, a roadmap that became its own file,
  and one pointing at a section of the same file whose title changed from "&" to "and".

- **Two sentences claimed to describe the CURRENT release while naming an older one**, and **two
  manifests that ship in the release carried a version nothing could inherit**: `windows/kern-win`
  at 0.6.7, and `crates/kern-cli` requiring its four siblings at 0.6.7.

- **The README said bubblewrap was "0.8 ms ahead"** while its own table read kern 2.2 against
  bubblewrap 3.0, and **said a thousand boxes start in 0.65 s** where BENCHMARKS.md measures 0.61.

### Changed

- **The documentation is about half the words it was, with no measurement removed.** What came out
  was duplication and narration: sections titled RESOLVED in a file of open items, entries about the
  test suite rather than the product, paragraphs explaining what an earlier version of the same file
  had got wrong. Every table, figure and caveat stayed.

- **The source comments are all in English.** Eighty-nine lines across six files were in Italian,
  along with the assertion messages a failing test prints.

- **The project names a maintainer.** `NOTICE`, the CLA and `Cargo.toml` said "kern contributors" and
  "the project maintainer", a group and a party that appear nowhere else in the repo.

- **The README's `vdisk` example declared only `backend = "ram"`**, which reads as the only backend
  there is. It now shows a `[[disk]]` pool beside it, and says a profile names exactly one pool out
  of however many are declared.

### Added

- **Five gates, because each defect above is a class rather than an incident.**
  `scripts/stale-numbers.py` reads the version from `Cargo.toml` and flags any sentence claiming to
  be current while naming a different one, checks the manifests that cannot inherit it, and carries
  the two figures above. `every_box_key_is_documented` asserts every compose key appears in
  `docs/CONFIG.md`. `scripts/test-count.py` counts all three suites without running them and
  compares against the README. Each is verified in both directions.

- **A Resource profiles section in the README**, with every command in it executed rather than
  written: `vgpio:` grants exactly the node it names, measured against a host carrying three.

- **A `--json` line in the Quickstart**, because every read verb now answers in JSON and a reader
  scanning the page would not otherwise know. The `jq` example it shows was run against a box with a
  failing health check, so `.health == "unhealthy"` is a value that occurs, not one imagined.

### Verified on hardware

The 0.6.43 binary was run on all six targets, the two defects above checked on each rather than
assumed from x86: `kern <verb> --help` filtered to the verb under a real pty (161 lines to 75), and
a volume directory carrying a raw `ESC` in its name round-tripped through `volume ls --json` as
`` with `"usable":false`, never as a raw byte.

- **UNO Q** (Android + Debian, aarch64), **Raspberry Pi 5** (aarch64), **Jetson Orin Nano**
  (tegra 5.15, aarch64): all three green, cross-built with `aarch64-linux-gnu-gcc`.
- **WSL2** (`PCALEX`, musl x86_64): green, and 50 box starts end-to-end at 5 ms each. The
  uncapped-host notice stayed silent, correctly, because this kernel delegates the `memory`
  controller.
- **VPS** (getkern.dev, Ubuntu 24.04, x86_64, the one target not configured by hand): green.
  `doctor` reports the AppArmor userns restriction; with it relaxed a box runs, and `--privileged`
  is refused as root, as designed.

## Earlier releases

0.6.34 and everything before it live in the signed tags: `git show v0.6.34`, or the
[tag list](https://github.com/getkern/kern/tags). All 30 are signed, and 29 of them carry an
OpenTimestamps proof ([provenance/](provenance/)), of which 28 are confirmed in a Bitcoin block: every
proof for a release before this one is anchored. The current release's proof is stamped and pending,
since a calendar has to reach a transaction and then six confirmations, which takes a few hours. The
one tag with no proof at all is v0.6.8, which predates the practice; stamping it today would attest to
today, not to its release.

[0.6.50]: https://github.com/getkern/kern/releases/tag/v0.6.50
[0.6.43]: https://github.com/getkern/kern/releases/tag/v0.6.43
