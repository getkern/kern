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

## [0.6.38], 2026-08-04

### Fixed

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

## Earlier releases

0.6.34 and everything before it live in the signed tags: `git show v0.6.34`, or the
[tag list](https://github.com/getkern/kern/tags). All 28 are signed, and 27 of them carry an
OpenTimestamps proof anchored to Bitcoin ([provenance/](provenance/)). The exception is v0.6.8,
which predates the practice; a proof stamped today would attest to today, not to its release.

[0.6.38]: https://github.com/getkern/kern/releases/tag/v0.6.38
