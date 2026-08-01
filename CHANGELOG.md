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

## [0.6.30], 2026-08-01

### Added

- **`pentest/`: the runnable evidence behind the isolation claims.** Four adversarial suites that ask
  the kernel what is true rather than asking kern to report on itself, 76 cases on the host they were
  measured on: that a
  published port cannot tunnel into a host service, that `--ssh` does not hand out the host's shell
  (it did, once, banner byte-identical), that `kern exec` does not escape the box, that a box cannot
  raise its own `memory.max` and sees no cgroup above its own, that an ungranted device does not
  cross (asserted against a box WITHOUT the grant, because "the device is in the box" means nothing
  otherwise), and that a SIGKILLed supervisor does not leave a host port held. They had lived outside
  the repository, which meant the answer to "how do I check this myself" was "you cannot".

  `toy-registry.py` and `run-with-local-registry.sh` remove the registry from the loop entirely: a
  one-layer OCI image is built from a directory already on disk and served on `127.0.0.1`, where kern
  speaks plain HTTP by design and pins TLS everywhere else. On a host with an empty image cache the
  wrapper builds a rootfs from the host's own busybox. This is not convenience: running these suites
  against Docker Hub across six machines exhausted the unauthenticated pull limit, and for hours
  afterwards every host answered 429, one suite reporting eight FAILs that were entirely the registry.

  Measured on x86_64 at 0.6.30: ports 32/0/0, cache-edge 24/0/0, vdisk-web-ssh 10/0/2, combo 8/0/0,
  identical against `alpine` and against the loopback fixture. Deliberately NOT wired into CI, and
  the reason is written down: the GitHub runner refuses unprivileged user namespaces under its
  AppArmor profile, so most cases would skip there and the green would mean nothing.

### Security

- **An OCI whiteout that could not be applied was reported as applied.** `remove_no_follow` returned
  `()`, so a refused unlink was indistinguishable from a completed one and `merge_layer` returned
  `Ok`: the file the image declared deleted stayed in the rootfs, and nothing said so. The condition
  needs no crafted image. `merge_dir` copies the staging directory's mode onto the destination BEFORE
  recursing into it, so a layer that both makes a directory read-only and deletes a file inside it
  removes kern's own write permission on the parent first, and the unlink fails `EACCES`. Whiteouts
  are how an image removes a secret, a setuid binary or a vulnerable library that an earlier layer
  added, so this is the difference between the rootfs the manifest describes and the rootfs on disk.

  Both removal helpers are now fallible and every call site propagates. A refused removal is retried
  once with kern's own write+search permission restored on the PARENT directory (unlinking is governed
  by the parent's mode, and kern extracted that parent, so it owns it); the parent's mode is put back
  on both the success and the failure path, so the image's declared permissions still win. If the
  removal still cannot be done, the pull FAILS naming the path and both OS errors. No-follow survives
  the retry: the choice between `remove_dir_all` and `remove_file` comes from the original
  `symlink_metadata`, so a symlink is unlinked and never traversed and a racing replacement cannot
  turn a file removal into a directory walk. `clear_dir` (opaque whiteouts) gets the same treatment,
  including a `read_dir` failure, which it used to swallow whole; a missing directory stays the
  desired end state rather than an error.

  Found by a mechanical sweep rather than by reading: of 40 discarded outcomes in `pull.rs`, 14 are in
  tests and 22 are cleanup or `kill`/`wait`/`flush` after a decision. Four were not, and this was the
  one that decides rootfs contents. The regression test constructs the permission precondition and
  skips itself under DAC override, where the precondition cannot exist.

- **A whiteout of a read-only DIRECTORY TREE now succeeds instead of failing the pull.** Widening the
  victim's parent is not enough: emptying `foo/` needs write+search on `foo` itself and on every
  directory below it. `chmod 555 /opt/foo` in one layer and `rm -rf /opt/foo` in a later one is an
  ordinary Dockerfile, and docker and containerd extract as root and never meet the case, so refusing
  that pull would have been a regression against them rather than a hardening. Image content is now
  deleted by a no-follow tree walk that repairs kern's own permissions as it descends: iterative with
  an explicit stack, so a deep tree cannot exhaust the call stack; post-order, so a directory goes
  only after its children; and the file-vs-directory decision comes from `symlink_metadata` at every
  level, so a planted `dir/escape -> /elsewhere` is unlinked as a link and never descended. The test
  plants exactly that symlink and asserts its target survives.

- **A registry rate limit was reported as a malformed manifest.** Docker Hub answers an over-quota
  anonymous pull with HTTP 429 and `{"errors":[{"code":"TOOMANYREQUESTS","message":"You have reached
  your unauthenticated pull rate limit..."}]}`. That body carries none of the auth keywords the error
  classifier looked for, so it fell through to "no layers in manifest", under a hint telling the user
  to check the image name and tag - of an image whose name and tag were perfectly correct. Hit while
  verifying this session's work across six machines, which is how it was found. The registry's own
  `message` is now quoted rather than paraphrased (it carries the current limit and the URL that
  explains it), `MANIFEST_UNKNOWN`/`NAME_UNKNOWN` are reported as an absent manifest, and the hint
  under a rate limit no longer contradicts the error above it.

- **`cargo test` deleted the image cache of the machine it ran on.** `help_and_parser_agree` runs each
  hardened verb to check that the parser accepts every flag `--help` advertises, and two of those verbs
  - `gc` and `prune` - delete for a living. Only `XDG_RUNTIME_DIR` was redirected, so the destructive
  verbs operated on the developer's real image cache. Three images on this machine had lost their
  rootfs that way, one of them three days before anyone noticed, and a node SDK integration test had
  been failing ever since for what looked like an unrelated reason. Isolated by bisecting the test
  binaries against a snapshot of the cache. The suite now redirects `HOME`, `XDG_CACHE_HOME`,
  `XDG_DATA_HOME`, `XDG_CONFIG_HOME` and `XDG_RUNTIME_DIR` into one private temp tree; `HOME` matters
  because every directory resolver falls back to it when its XDG variable is unset.

- **`remove_image` ignored the cache it was handed.** It takes a cache directory as a parameter, which
  is what lets a test drive it against a fabricated tree, and then called `sweep_orphan_layers()` -
  which resolved `cache_dir()` on its own and swept the REAL layer store. A unit test deleting from a
  temp cache therefore reclaimed layers from the developer's, which is how a five-day-old
  `ubuntu:latest` lost its layers. The sweep takes the cache as a parameter now, so an argument that
  exists for testability is honoured all the way down.

- **A cache directory holding only prefetch blobs is no longer "complete".** `dir.is_dir()` is true for
  a directory that contains nothing but kern's own `.kern-layer-*` downloads, which is what an
  extraction that never merged leaves behind. The completeness test now rejects that shape, and keeps
  accepting an EMPTY directory: a finished extraction consumes each blob as it goes, so "no entries at
  all" means the image genuinely had none, and rejecting it would re-pull that image on every
  invocation forever. The re-fetch message also names the part that is actually missing - it reported
  "cached without its config" for an entry whose config was present and whose rootfs was blob-only.

- **Zero `unwrap`/`expect`/`panic!` left in production code.** The workspace had sixteen, each safe by
  construction and each an abort if that construction were ever wrong - and `panic = "abort"` gives no
  second chance. They are now stated rather than asserted: the `[[cpu]]`/`[[vcpu]]`/`[[gpio]]`/
  `[[gpio.usb_ports]]`/`[[vgpio]]`/`[[disk]]`/`[[vdisk]]` context arms return a line-numbered config
  error, the `COPY`/`ADD` arity checks destructure instead of checking-then-popping (so the check and
  the use cannot drift), the two `/proc/self/fd/<n>` C strings and the `/proc/<pid>/root` one return an
  error, the compose topological sort skips an unknown successor rather than aborting a parser that
  also runs under the fuzzer, and `--plan` shows what it recorded instead of aborting a read-only
  command. Verified through the CLI, not just the compiler: a `[[gpio.usb_ports]]` outside a `[[gpio]]`,
  an `ADD` with two URLs and a `COPY` with no destination each produce their line-numbered error, and a
  valid config with a `[[gpio.usb_ports]]` table still grants its device.

- **Every mode change in the image-merge path now acts on a descriptor, not a name.** The permission
  repair added for read-only whiteout trees used `std::fs::metadata` + `set_permissions`, both of which
  FOLLOW symlinks, on paths built from attacker-supplied layer content. `merge_dir`'s
  `whiteout_dir_symlink_free` guard already refuses such paths, but that is a check-then-use. A
  `DirHandle` opened with `O_DIRECTORY | O_NOFOLLOW` now backs every read and write of a directory
  mode, and one handle is held across both the widen and the restore so the two provably act on the
  same object. Demonstrated: with the path-based version, a planted `link -> outside` moved kern's
  `u+wx` onto a 0500 directory outside the image; with the descriptor-based one it does not, and the
  open is refused for a symlink and for a regular file alike.

- **`kern pull` declared a dangling image ready to run.** A cache entry was considered complete on its
  sentinel and its config sidecar, never on the ROOTFS those two describe. With `<ref>/` pruned or
  cleaned by hand, `kern pull` printed "already cached" and "run it: kern box …" while `kern images`
  said `dangling` about the same ref at the same instant, because `image_stat` already knew that no
  flat dir, no diff and no manifest means nothing to run. `kern box --image <ref>` then died with
  `mount(overlay) failed: No such file or directory`, naming neither the image nor the cause. Found by
  a node SDK integration test that had been failing for thirteen days on a developer machine for
  exactly this reason.

  The question "is this entry usable?" was being asked in four places with three different answers; it
  is one predicate now, used by the `--pull never` gate, the fast path, the post-lock re-check and the
  "already cached" message. That also closes a `--pull never` hole: with the sentinel present and the
  sidecar missing, the old top-of-function check passed, the fast path was skipped and control fell
  into the fetch block, so `--pull never` went to the network.

- **An interrupted REPAIR left a rootfs that read as complete.** The sentinel is written last precisely
  so an interrupted extraction reads as absent, but that only holds when there was no sentinel to begin
  with. Repairing an entry whose rootfs had gone kept the stale sentinel and sidecar in place, so an
  interruption partway left a directory holding nothing but prefetch blobs behind a sentinel still
  saying "complete", and the next resolve handed that empty rootfs to overlayfs. Reproduced by
  interrupting a repair with a closed pipe (SIGPIPE mid-extraction). Both files are now removed BEFORE
  the rootfs is touched, so an interrupted repair reads exactly like an interrupted first pull, and the
  pre-clean of the partial directory is no longer discarded either.

- **Both SDK bindings let the sandboxed code declare its own failed run successful.** The kernel reply
  is JSON written INSIDE the box, by the code the sandbox exists to contain - the comment beside it said
  as much. Every field was defensively coerced, which is right for `stdout`, `stderr` and `results`, and
  wrong for exactly one: `rc` fell back to `0`, and `success` is `exit_code == 0 and fault is None`. A
  cell could therefore report a failed run as successful by omitting one key or sending a string.
  Python was the worse of the two, defaulting a MISSING key to 0 as well. An absent or non-integer `rc`
  is now a protocol violation handled like the malformed replies beside it: the in-box runner always
  emits `"rc"`. Python also rejects a JSON `true`, which subclasses `int` there and would have become
  exit code 1. The decode was extracted into one named method per binding so the untrusted-input
  boundary is a single place a test can drive directly.

- **The TUI performed destructive actions and lifecycle keys without reporting a refusal.** Both
  paths reuse the CLI helpers inside `quiet_io`, which redirects fd 1 and fd 2 to `/dev/null` so a
  helper's `println!` cannot corrupt the alt-screen; it also sent their error messages there, and the
  `Result` itself was discarded. A refused stop or pause left an unchanged list, a key that appeared
  to do nothing and no reason anywhere; a confirmed `volume rm` or `image rm` that was refused (still
  in use) left the item on screen after the `y`. `quiet_io` now carries the helper's result out of the
  muted section, and both paths report through the overlay pane the log view already uses.

- **`builds::remove` answered the wrong question.** It returned `existed`, sampled BEFORE the removal,
  and discarded the removal's own result, so it reported "was there a record?" while both callers read
  it as "was the record deleted?". `kern build rm <id>` printed `removed build '<id>'` for a record
  still on disk, and `kern build prune` counted it among the pruned. Three outcomes cannot travel in a
  bool sampled at the wrong moment: it returns `Ok(true)` (gone), `Ok(false)` (never there) or `Err`
  (there and not removable), and both callers now say which.

- **An image's config sidecar was written best-effort.** That is not the trade the `.ok` sentinel
  beside it makes: a missing sentinel means the image is not recognised and the next run rebuilds it,
  which is wasteful and self-correcting, while a missing config means the image IS recognised and
  simply has no entrypoint, no env and no user, so the box silently falls back to a shell and the
  workload runs with a different identity than the image declares. `write_image_config` is fallible
  and all six production call sites (pull, load, commit, two build paths) refuse rather than publish
  an image without its config.

- **A quota'd volume could be mounted EMPTY over data that still existed.** The one-time seeding of a
  freshly created ext4 image from the volume's plain `data/` dir ran through `cp -a` with both the
  spawn error and the exit status discarded. The two backends are distinct on-disk locations, so a
  failed copy mounts an empty volume while the data sits elsewhere: the workload sees nothing, may
  recreate or overwrite it, and nothing said the copy had not happened. It now refuses the box start
  and names where the existing data still is.

- **Smaller, same class.** The overlay work dir is cleared as a precondition now (overlayfs requires
  it empty) instead of surfacing later as a bare `mount: invalid argument`; a box whose
  `/etc/resolv.conf` could not be placed says so rather than leaving "DNS does not resolve in here"
  with no stated cause; and the two `registry::register` calls that record a box's PID 1 report when
  they fail, because that field is what `kern exec` joins and a stale `0` made it fail with "box is
  not running" about a running box.

- **`kern rename` could report success while the box kept its old name.** The displayed name comes
  from the `name=` field INSIDE the registry entry body (`load_live` then `parse`), not from the entry
  file name. `rename` renamed the FILE with `?` and rewrote the BODY with a discarded result, so a
  failed rewrite left the file called `<new>-<pid>` with a body still saying `<old>` and returned
  `Ok`: the user is told the rename worked, `kern ps` keeps showing the old name, and the two halves
  of the entry disagree about the box's identity. The body is now rewritten FIRST, on the entry that
  still exists, so a refused rewrite changes nothing at all; if the file rename then fails, the body
  is put back and the error is returned. `atomic_rewrite` is fallible, removes its staged temp when
  the rename over the entry fails, and treats a MISSING entry as "the box is gone", which is not an
  error. The regression test asserts the whole contract rather than one branch: either the box answers
  to the new name, or nothing changed.

- **`kern update` recorded new caps best-effort and said nothing when it could not.** The cgroup write
  has already happened at that point, so the kernel IS enforcing the new limit and failing the command
  would be the wrong trade; the registry rewrite therefore stays best-effort. It now says so when it
  fails, because otherwise `ps` and `inspect` keep showing the previous cap with nothing to attribute
  the discrepancy to.

- **`kern volume create --size N` reported success when the quota had not been written.** The cap
  lives ONLY in the volume's `meta.json`: `size_limit()` reads that file and returns `None` when it
  cannot, and `None` means "no cap" everywhere downstream. `create` wrote it with a discarded result,
  then printed the volume name and returned success, so a failed write produced a volume that exists,
  is reported created, and has no quota. `volume edit` has always propagated the identical write,
  which is how the inconsistency surfaced: one operation, two dispositions. The realistic trigger is a
  full disk, where `create_dir_all` costs a few inodes and succeeds while the file write hits
  `ENOSPC`, losing the cap at the moment it would have mattered. The auto-create inside
  `resolve_named` stays best-effort and now says why in the code: that sidecar carries only a
  timestamp, never a `size_limit`, so a volume created implicitly by `-v name:/path` has no
  enforcement to lose and a box start should not fail over it.

- **A pull could leave a full copy of every layer on disk, silently.** Staging is extracted with
  `--same-permissions`, so an image shipping a read-only directory made the four
  `remove_dir_all(&staging)` cleanups fail with `EACCES`; all four discarded the result, so the disk
  grew with nothing to attribute it to. Three of them are cleanup after a decision and stay
  best-effort, but now name the path when they fail. The fourth is not cleanup at all: it clears a
  leftover staging BEFORE extracting into it, and `create_dir_all` succeeds whether or not the
  directory was emptied, so a swallowed failure there would extract on top of content the run never
  produced and merge the union as if it were the layer. That one now refuses. Verified: three real
  multi-layer images pull and run, and the cache holds zero leftover staging directories afterwards.


### Fixed

- **Three of the four suites declared `#!/bin/bash` and none of them needs bash.** Verified by running
  all four under `dash`, with identical results. kern's own target hosts include an 8.5 MB Alpine
  with no bash, which is exactly where the evidence most needs to be runnable.

- **`pentest-combo.sh` failed where it should have skipped.** An image with no `/usr/sbin/sshd`
  produces a published `--ssh` port that nothing answers, and the two assertions below it then read
  "ssh into the box did not run a command", blaming kern for a missing package. It now asks the
  RUNNING box whether the binary is there and skips with the reason. The four suites also took three
  different positional signatures; they are now all `<kern> [image]`, with combo's sshd image moved
  to `SSHIMG`, and two of them no longer default to a `/tmp` path left over from a debugging session.

- **`kern doctor` named a systemd manager that wasn't there.** The lingering check asked "am I root?"
  before "is there a manager at all?", so on a WSL2 distro without systemd it answered "running as
  root: boxes go to the system manager". The conclusion was right and the reason was invented.
  Measured on WSL2 (kernel 6.18-microsoft-standard, `/proc/1/comm` = init, no `/run/systemd/system`)
  on 2026-08-01. Verified on all three branches afterwards: no systemd at all, root with systemd, and
  rootless with lingering on.

### Documentation

- **`SECURITY.md` said "Current status (0.6.9)"**, twenty-one releases behind, and had no answer to
  "how do I verify this". It now names the version it describes and points at `pentest/`.

- **`provenance/README.md` sent people to the wrong program.** `pip install opentimestamps-client` is
  refused on Debian 12+, Ubuntu 23.04+ and anything else following PEP 668; the shell then suggests
  `apt install ots`, which is Open Text Summarizer, an unrelated program that cannot read these files.
  Someone checking a release could reasonably conclude the proof was broken. Now: pipx or a venv, an
  explicit warning about the apt package of the same name, and `ots info` + `sha256sum` promoted as
  the check that needs no Bitcoin node. Also corrects a claim: `ots verify` was described as using "a
  local or public Bitcoin node", and there is no public fallback.

- **Every version link in this file now points at a release that exists.** Eleven definitions pointed
  at `releases/tag/v0.1.0` through `v0.6.4`: the July clean-slate reset re-dated the history and those
  tags did not survive it, so the oldest release on GitHub is v0.6.5 and all eleven answered 404. The
  mirror-image half was just as wrong: v0.6.5 through v0.6.29, which DO have releases, had no
  definition at all, so their headings rendered as bare `[0.6.29]` brackets linking nowhere. A version
  with a tag now links to its release, a version without one drops the brackets and reads as plain
  text. Verified by requesting all of them.

- **The project-status line was two releases and 21 tests behind.** It read "0.6.27 ... 667 Rust, 61
  Python and 50 Node tests"; the measured counts are 688, 62 and 51. The binary-size row in
  `BENCHMARKS.md` said aarch64 `~1.3 MB` where the published artifact is 1.50 MB, so it is now quoted
  from the release tarballs, with a note that a local build here produces a smaller binary than the
  one anyone actually downloads.

## [0.6.29], 2026-08-01

### Security

- **`-p` and `--ssh` are now REFUSED with `--net`: a shared network gives the box no port of its own,
  and publishing one meant publishing a host service under the box's name.** With `--net` the box has
  no network namespace, so the forwarder's `127.0.0.1:<box_port>` is the host's, and nothing in the
  kernel distinguishes the box's listener from any other process on the machine. If the box's service
  is not up (it crashed, it is still starting, it was never in the image) the mapping serves whatever
  host process owns that number, while `kern ps` shows it as the box's.

  `--ssh` is the case that made this concrete. Measured on 2026-07-31 with an image containing **no
  sshd at all**: the banner on the published port was byte-identical to the host's own
  (`SSH-2.0-OpenSSH_9.6p1`), while kern printed `ssh -p <port> … root@127.0.0.1` as the way into the
  box. On a host with no sshd it is no better, the box's own sshd binds the host's `:22` and is exposed
  to the whole network on the standard port.

  Both are refused with an error naming the way forward, and `--pod` really is one: verified that a
  pod box has outbound (`wget http://example.com` succeeds) **and** working `-p` at the same time, so
  nothing that worked before is lost. The forwarder carries the same rule independently, refusing to
  forward if it is ever handed a box in its own network namespace, so the guarantee does not rest on
  one CLI check. Same principle as `--egress-allow`, which already refuses `--net` because it filters
  the box's OWN network.
- **`kern exec` into a `--net` box always failed, with the wrong reason.** It joined the box's user
  namespace and then tried to `setns` into the box's *network* namespace, which under `--net` is the
  HOST's, owned by the initial user namespace where the process no longer holds `CAP_SYS_ADMIN`. The
  refusal surfaced as "cannot join the box's namespaces (must be the same user that started it)" when
  it was in fact the same user. `kern exec` now skips any namespace the box already shares with the
  caller, decided by namespace identity before the first `setns` and failing closed (an unreadable
  namespace is treated as separate and left for `setns` to refuse). Verified on x86_64, a Raspberry
  Pi 5, an Arduino UNO Q and a Jetson Orin Nano: exec into a `--net` box now works and still sees only
  the box's pid namespace (4 processes against the host's 176 to 588).
- **A `vgpio` device grant could be dropped in silence.** Only `i2c` normalized the shorthand
  CONFIG.md documents; every other bus was taken verbatim, so the documented
  `spi = ["0.0"]  # /dev/spidev0.0` reached the `/dev/`-confinement gate as a bare string, failed it,
  and vanished. The box started, said nothing, and had no SPI device. Found on a Raspberry Pi 5 with a
  real `/dev/spidev10.0`. `spi` now resolves `BUS.CS` (validated all-digits before the path is built,
  so `"0.0/../../etc/shadow"` cannot concatenate its way out of `/dev`), and **every** unresolvable
  entry in every field now prints why it was skipped instead of disappearing. Verified against a
  negative-control box on all three ARM boards: the granted node is present, and an ungranted
  `/dev/gpiochip0` that exists on the host is still refused.

### Fixed

- **A published port is now bound before the box is declared started.** The forwarder used to bind
  only after the box existed, so a host port taken in the window between the `-p` preflight (which
  runs early, before the image, mounts and cgroup work) and the bind left `kern box` printing
  "✔ started", `kern ps` printing the mapping, and nothing listening. The only trace was a message on
  a stderr that a detached box swallows. Each forwarder now binds the moment it is forked and reports
  the outcome, and a failure refuses the box, naming the port and the OS reason. The same change
  removes two silent `continue`s that dropped a mapping entirely when `pipe` or `fork` failed. No
  measurable cost: 4.6 ms/box with `-p` against 5.1 ms without, 20 runs each.
- **A SIGKILLed supervisor no longer orphans its port forwarder.** The forwarder is torn down by an
  RAII Drop, and a Drop does not run on SIGKILL. That is not an exotic case: the supervisor sits in
  the BOX's cgroup, so an OOM inside the box kills it outright. The forwarder then survived, blocked
  in `accept()` on a host port that `kern ps` could no longer name and `kern stop` had no box to
  stop. Found by looking at `ps` rather than at kern: **six** of them alive on a development machine
  on 2026-08-01, each holding a host port for over an hour, produced by a test that deliberately OOMs
  a 64 MB box. Each forwarder now arms `PR_SET_PDEATHSIG(SIGKILL)` against the supervisor, with the
  `getppid()` re-check that closes the fork-to-prctl window. Verified by `kill -9` on the supervisor:
  before, the port stayed bound indefinitely; after, it is released. This hole predates the RAII
  change (the hand-written `stop()` calls did not run on SIGKILL either).
- **A `-p` box that fails to start no longer leaves host ports held.** The forwarders are forked
  before the `unshare`, with about a dozen fallible steps between that and a running box, and each was
  an early return that left the bound ports to be released whenever the process happened to exit. They
  are now owned as one RAII set whose drop stops them, which covers every one of those paths instead
  of the two success sites that were stopped by hand.

- **`kern exec` now joins the box's cgroup namespace.** An exec'd command read the HOST's cgroup path
  out of `/proc/self/cgroup` (`0::/user.slice/user-1000.slice/user@1000.service/kern.slice/kern-box-…`)
  while the box's own workload correctly read `0::/`: the same box, two answers, with the host's slice
  layout and the caller's uid disclosed to whatever ran under `kern exec`. On a host that runs boxes
  in per-box systemd scopes the new reading also makes the existing "this exec runs outside the box's
  caps" warning verifiable rather than merely stated: `/proc/self/cgroup` renders as
  `0::/../../../session-N.scope`, which says outright that the process sits outside the box's cgroup.

- **A `vdisk:` profile that names a disk pool could be RAM-backed without saying so.** The
  ext4-on-loop backend is only used for a FOREGROUND box (its teardown is bounded to the box's run),
  so `-d` and `-it` take the tmpfs path even as root with loop devices and `mkfs.ext4` present. The
  fallback only printed anything when the profile ALSO set `iops`/`bandwidth`/`persistent`, or asked
  for at least 1 GiB, so the ordinary case (a disk pool, a modest size) was told nothing at all. Found
  on a root VPS on 2026-08-01: `backend = "disk:pool"`, `size = "64m"`, `df` inside the box said
  `tmpfs`. An explicit disk backend that ends up RAM-backed now says which of the two reasons applies
  (foreground-only, or missing privilege) and CONFIG.md states the condition. The disk path itself is
  verified working on that host: `/dev/loop0 ext4`, a 256 MB write into a 64 MB vdisk refused at
  60080 KB, and the workload still running afterwards, which is what a quota is supposed to do.
- **`kern doctor` told every root host to enable systemd lingering, which fixes nothing there.** As
  real root kern drives the SYSTEM manager, so boxes are not under `user@<uid>.service` and no login
  session can stop them. The check now branches on the same predicate that picks the manager
  (`systemd_scope_mode`) rather than re-deriving it. Measured on a Contabo VPS: a detached box as root
  was still running with its port bound 30 s after every session closed, lingering off throughout.

### Added

- **`kern doctor` now answers "will a detached box survive my logout?"** It usually will not, and that
  is the one question a headless board makes urgent. Each box lives in a transient systemd scope under
  `user@<uid>.service`; without **lingering**, systemd stops that service when the user's last session
  ends, killing every box under it and removing the `/run/user/<uid>` registry with them. Measured on a
  Raspberry Pi 5 on 2026-08-01: a detached box publishing `0.0.0.0:8099` was gone 20 s after the last
  ssh session closed, with no process left and `kern ps`, the port and `kern logs` all empty. After
  `loginctl enable-linger`, the same box kept serving the page to another machine over the LAN with no
  session open at all. The check reads `/var/lib/systemd/linger/<user>` (a file test, no subprocess),
  stays quiet where there is no user manager to stop anything (WSL2), and names the exact command.
  Both branches verified on the board.
- `examples/edge-webserver-ssh.sh`: a web server on a headless board, published to the LAN, with
  `--ssh` into the box. It shows the shape that works, which is build with `--net` and **serve
  without** it, and checks lingering before it starts. Every claim in it was measured on a Raspberry
  Pi 5: fetched from another machine over the LAN with no session open, and an ssh session that saw
  hostname `edgeweb`, 8 processes where the host had 154, `memory.max` at the 128m cap, and no host
  disk.

### Changed

- **The reported symptom that started all of this** was `kern box --net -p …` on a Raspberry Pi 5
  showing the mapping in `kern ps` with nothing reachable. Reproduced on x86_64 and on the Pi: the
  host port DID listen, and every connection was accepted and instantly reset (`curl: (56)`), UDP
  silently dropped. The cause was the `setns(CLONE_NEWNET)` `EPERM` described above. It is not fixed
  by making the combination work, because a working version publishes the wrong thing; it is fixed by
  refusing it and pointing at `--pod`.

## [0.6.28], 2026-07-31

### Fixed

- **`--timeout N` is documented as what it does: SIGTERM at N, SIGKILL two seconds later.** The
  flag was described as "auto-stop after N seconds" in the help, the doc comment and CONFIG.md, and
  none of the three mentioned the grace, so `--timeout 30` in a job that budgets exactly 30 s
  overruns by 2. Found because a test asserted the wrong semantics and failed; the behaviour is
  unchanged and matches `docker stop`, it had simply never been timed. The 2 s is the foreground
  watchdog's own and is unrelated to `--stop-timeout`, which defaults to 10.

- **`waitpid` and `poll` are now restarted on `EINTR`.** Both return -1 when a signal is delivered
  while they block, and all ten call sites read that -1 as a real outcome: an interrupted `waitpid`
  left its `status` untouched and the caller decoded whatever it was initialised to as the child's
  exit code, and an interrupted `poll` was indistinguishable from "the timeout expired, nothing to
  read". kern installs a handler for almost nothing, which is why this looked unreachable, but kern
  does not run alone: a `SIGWINCH` from a resized terminal reaches `kern top`, a profiler's
  `SIGPROF` reaches anything run under one, and a shell's job-control signals reach a foreground
  box. The retry lives in one new module (`eintr`) rather than at ten sites, because a condition
  re-derived at every call site is how this project has produced its most expensive defects.
- **A restarted `poll` no longer restarts its clock.** The naive retry re-issues `poll` with the
  ORIGINAL timeout, so a steady drip of signals extends a bounded wait without limit: the 10 s cap
  on the `doctor` overlay probe could have become unbounded. The remaining time is now computed
  from a `CLOCK_MONOTONIC` deadline, which is what a bounded wait was always supposed to mean.
- **`kern top` polled a descriptor it did not own.** The event loop builds a two-slot `pollfd`
  array but only the first slot is valid when the inotify watch could not be opened, and the
  count guarding that was computed and then not used, and it is now clamped to the array length so
  the slice cannot panic inside the event loop. Found while routing the call through the wrapper.
- **`reap()` refuses a non-positive pid.** `waitpid(-1, ..)` means "any child", not "this child": a
  failed `fork()`'s -1 passed through would have reaped whatever exited first, which on the
  foreground box path is plausibly the box's own PID 1 that another wait is about to collect.
- **`poll` degrades honestly when `CLOCK_MONOTONIC` is unavailable.** The deadline helper returned
  0 on error, which yielded an instant phantom timeout the caller reads as "nothing to read". It
  now returns `None` and the wait falls back to a plain restart.

## [0.6.27], 2026-07-30

### Fixed

- **`kern bench --bind-rootfs` accepted the flag and dropped it.** Every "bind" figure ever quoted
  from `kern bench` was therefore an overlay figure under a bind label. It mattered on exactly one
  board: the Arduino UNO Q's Android kernel spends 22.4 ms in the overlay mount alone against ~0.1 ms
  on x86, so the mislabelled number was 33.5 ms where the real bind path is 9.6. bench now passes the
  flag through and names it in its own header, since two very different numbers otherwise print
  identically. The test asserts the PARSED command rather than the exit code, because the old code
  also exited 0 for that invocation: only the parsed value separates "accepted and honoured" from
  "accepted and discarded".

- **A flag kern does not understand is now refused on every verb, not on 14 of 38.** Four exited 0
  with an invented flag, the worst shape of all: `volume ls --json` printed the human table and
  reported success, so a script parsing it got prose with no way to tell. `search`, `completions` and
  `pod ls` did the same. Ten more dropped the flag and failed later for an unrelated reason, which
  reads as a kern bug until you find the flag was never applied: stop, kill, killall, pause, unpause,
  attach, cp, inspect, diff, wait, rename, update, tag, commit, rmi, events. One shared
  `reject_unknown_flags` reaches all of them rather than a second copy of the rule.

- **`kern pod create -p 8080:80` was advertised and not implemented.** The usage line offered `-p` and
  the parser had no field for it, so the pod came up with nothing published. A port belongs to the box
  that serves it; the error now says exactly that and gives the command.

### Added

- **`kern doctor` now measures two costs it used to leave invisible, and names the way out of each.**

  The per-box systemd toll: an SSH login sits under the SYSTEM systemd manager while kern's delegated
  `kern.slice` lives under the USER manager, and cgroup v2 refuses to migrate a process across that
  boundary. Verified on an Arduino UNO Q rather than assumed: creating a cgroup under `kern.slice`
  succeeds, writing `memory.max` succeeds, writing the pid into `cgroup.procs` is REFUSED. So the
  fallback is correct, and it is also avoidable. Enter the tree once with `systemd-run --user --scope
  bash` and every box takes the direct path with caps still enforced: **11.7 to 3.0 ms** on a Pi 5,
  12.8 to 4.6 on a Jetson, **91.9 to 35.5** on the Arduino, and 11.3 there with `--bind-rootfs`. That
  also settles the bubblewrap comparison on the boards: kern enforcing a memory limit is 4.2 ms
  against bubblewrap's 5.6 on the Jetson and 11.3 against 15.0 on the Arduino.

  The overlay mount: `mount -t overlay` costs **22 ms** on the Arduino's Android kernel against ~0.1 ms
  on x86, which is most of a box's start time there, and "overlayfs: available" said nothing about it.
  The cost is fixed, which is what makes it diagnosable: identical with a 517-file lowerdir and with an
  empty one, identical on ext4 and on tmpfs, five consecutive mounts within 0.4 ms of each other, the
  module already loaded, and a tmpfs mount in the same namespace costing 6.1 ms against overlay's 28.2.
  Not the disk, not the image, not an autoload, not `mount()` in general.

  Both figures are measured on the host in front of you, and both measurements were wrong twice before
  they were worth shipping (a cold first sample overstating the systemd toll by 3.6x; a missing
  `uid_map` write making the overlay probe measure nothing at all, then a version that timed the
  `uid_map` write itself and flickered between 20 and 5 ms). The record is in the code.

- **`kern gc --images` never cleared a real image cache, and reported success.** An extracted OCI
  image ships read-only directories with their original modes (alpine's `/proc` is `r-xr-xr-x`;
  amazonlinux adds `/root`, `/boot`, `/sbin`), and unlinking a child needs WRITE on its parent, so
  `remove_dir_all` stopped at the first one. So does `rm -rf`, which leaves the tree and still exits 0.
  One cache held 62 such directories and 3.0 GB the documented command could not reclaim, and the
  failure printed to stderr while returning success, so `kern gc --images && echo cleaned` printed
  "cleaned" over an untouched cache. Removal now restores `u+rwx` on directories as it descends and a
  failure is a non-zero exit. Every failure names its path and its cause, including the one case that
  is genuinely unremovable: a file owned by a subuid from a `--uid-range` build, which an unprivileged
  user cannot chmod.

- **Every failed pull leaked one empty cache directory.** A bad tag, an image that does not exist, and
  a Ctrl-C mid-download each produced one; 24 had accumulated. The `--pull always` branch already
  cleaned up its staging directory on error and the `missing` branch did not, so the same rule was
  written once and forgotten once. `--dest <dir>` deliberately still does not: that directory is the
  caller's.

### Changed

- **Third measurement round on the boards, and it is the one that ships.** With the bench defect fixed,
  every cell was re-taken in a single sitting, three repeats each, on idle hosts, with `memory.max`
  read back from inside a box to prove the caps were live: Pi 5 **11.9 ms**, Jetson **13.4**, Arduino
  **91.7**, x86 **2.6**, all with caps enforced.

  **The scope accounts for the whole board gap, and the arithmetic closes.** `systemd-run --user
  --scope /bin/true` timed on its own costs 9.4 / 9.0 / 59.9 ms on the three boards, against capped-
  minus-uncapped gaps of 9.2 / 9.3 / 58.2 on those same boards: agreement within 1.7 ms everywhere.
  On x86 the same scope costs 4.2 ms and kern does not pay it, capping directly in its own delegated
  slice for 0.3 ms instead.

  At the same level of work kern is ahead of bubblewrap on every host where both are installed: 2.2
  vs 3.0 on x86, 3.5 vs 5.6 on the Jetson, 9.6 vs 15.0 on the Arduino.

  **What is not explained:** the Pi 5 and Jetson read 17.1 and 14.3 ms in the previous round and 11.9
  and 13.4 in this one, on the same hardware with the same binary and the caps verified enforced in
  both. The bench defect does not account for it, since it only ever affected `--bind-rootfs`. No
  cause is offered here because none was established.

## [0.6.26], 2026-07-30

### Fixed

- **An exported-but-empty `KERN_*` flag silently turned enforcement off.** `KERN_NO_SCOPE=` with no
  value, and the `export FOO=${FOO:-}` idiom every CI script uses, both leave the name present with an
  empty value. Every boolean flag read it with a bare `is_some()`, which meant "on".

  On a host where the systemd transient scope IS the enforcement, that is not cosmetic. Measured on a
  Raspberry Pi 5: with an empty `KERN_NO_SCOPE`, `--memory 256m` left `memory.max` at `max`,
  `--pids-limit 30` left `pids.max` at `max`, and a workload three times over its RAM cap exited 0
  instead of 137. kern printed nothing. The same box with the variable absent enforced all of them.

  Empty now counts as unset, through one `env_flag` used by every site, which is the rule the project
  already applied to `KERN_CONFIG` and `XDG_CONFIG_HOME` and had never given the boolean flags.

- **`KERN_NO_SCOPE=1` no longer accepts a cap it will not enforce.** The opt-out is legitimate and
  stays: it takes a box from 15.5 ms to 4.1 ms on that Pi. What was wrong is that it said nothing while
  `--memory` and `--pids-limit` stopped working, which is the defect class this release exists to close.
  It now warns through the same `warn_unenforced_caps` the other unenforceable-cap paths use.

### Changed

- **The ARM board figures in BENCHMARKS.md were re-measured and they moved upward**, from 2.1/3.6/9.9 ms
  to 17.1/14.3/93.2 on the Pi 5, Jetson and Arduino UNO Q. Not a regression: v0.6.9, v0.6.20, v0.6.24 and
  v0.6.25 were each benched on the same Pi in one sitting and read 13.9, 12.0, 11.9 and 11.7, so the
  newest is the fastest of the four. Those four compare with each other and not with the table above,
  which was re-measured later, after the boards were reset.
  What changed is the boards, which now have the memory controller delegated
  and therefore pay for enforcement they previously could not perform. Chased to its cause:
  `systemd-run --user --scope /bin/true` alone costs 13.7 ms there, against 14.3 for a whole `kern box`,
  and removing it removes the caps with it. bubblewrap is now faster than kern on the two boards where
  both are installed, and that is stated rather than left to be discovered.


## [0.6.25], 2026-07-30

### Added

- **`kern uninstall`, and `uninstall.ps1` on Windows.** There was no uninstall at all, on any platform.
  Removing kern meant knowing that its state is spread over four XDG locations plus the systemd units
  `--restart` writes, and on Windows over a registered WSL distro, a shim folder and a PATH entry. On
  the machine where this was noticed those paths held **5.2 GB** and 14 named volumes, none of which any
  documented command could find, let alone remove.

  It is a **dry run by default**. It prints each path, its size, and whether it is data you made (a
  named volume, your `kern.toml`) or a cache a `pull` restores, then stops; `--yes` performs it. A verb
  that erases named volumes on the strength of its name alone is one nobody tries in order to find out
  what it does. `--keep-images` spares the cache, for starting the config over without refetching
  gigabytes.

  It only removes paths kern **owns**, each taken from the function that creates it rather than written
  out again here, so moving a location cannot leave this deleting the wrong tree. The binary goes only
  when it is the running one **and** sits where an installer puts it, so a build in a source tree
  survives `uninstall` run from that tree. `/var/lib/kern` is never touched, and the output says so:
  kern-public does not create it, and a `[[disk]]` a user pointed there is their data in their location.
  It refuses outright while boxes are running rather than deleting the state of a live sandbox.

- **A `kern.cmd` fallback next to `kern.exe` on Windows.** An antivirus deleted a freshly downloaded,
  checksum-verified `kern.exe` four times on one machine (Malwarebytes, with Defender in passive mode),
  leaving an install whose Linux side was perfect and whose `kern` command did nothing. The installer now
  writes a batch companion every time, not only after a failure: `PATHEXT` resolves `.EXE` before `.CMD`,
  so it is inert while the exe exists and takes over by itself if the exe disappears a week later, with no
  installer re-run. Its two limits are printed in the file and by the installer: no Windows-path
  translation (`-v /mnt/c/data:/data` rather than `-v C:\data:/data`), and it is not an executable, so the
  Python and Node SDKs still need the exe.

  The installer's antivirus advice is now derived from the machine instead of assuming Defender. It reads
  `root/SecurityCenter2` and the `WinDefend` service, names the product actually guarding the host, and
  only suggests `Add-MpPreference` when that service is running: on the machine above the command failed
  with `0x800106ba` because Windows had stopped Defender in favour of the third-party product, so the one
  remedy the installer offered could not work.

- **The Windows installer no longer reports a working install as unverified.** `install.ps1` runs with
  `$ErrorActionPreference = 'Stop'`, and Windows PowerShell 5.1 promotes a native command's stderr to a
  TERMINATING error. The shim writes one line to stderr on every first run ("locating your WSL distro"),
  so verification landed in its `catch` and printed "kern.exe is present but could not be run" for a
  bridge that worked - on every clean install, twice observed end to end. It now captures stdout and
  stderr to separate files and reads the verdict from stdout, which also yields a real exit code: a
  program that prints a version but exits non-zero is no longer accepted.

  The two shim messages that reach a Windows console are ASCII now. `…` arrived as `ÔÇª`.

  The Windows script is a dry run on the same terms. Two details are load-bearing: it contains no `exit`
  statement, because it is meant to be run as `irm … | iex` and an `exit` there closes the user's
  PowerShell window along with the output; and it re-broadcasts `WM_SETTINGCHANGE` after editing the
  PATH, exactly as the installer does when it adds the entry, otherwise new terminals keep receiving the
  stale block until a logoff and the removal looks like it never happened.

### Changed

- **`kern pull <image>` now fills the image cache instead of dropping a rootfs in the current
  directory.** The two verbs were writing to different stores: `pull` extracted to `$PWD/<ref>-<hash>`
  while `box --image` filled `~/.cache/kern/images`, so `pull X` followed by `box --image X`
  **re-downloaded the whole image**, `kern images` did not list what had just been pulled, and
  `tag`/`push`/`save` could not see it. Anyone pulling before going offline arrived offline without
  the image.

  It also littered. Every pull left an extracted rootfs wherever it ran, and two such directories
  (`alpine_3_19-…`, `linuxserver_openssh-server_latest-…`) were sitting untracked in a working tree
  when this was found. The previous release fixed the same class for the examples; this is the root.

  And it broke a shipped example. [tag-and-push-local.sh](examples/tag-and-push-local.sh) says "make
  sure we have a source image cached" directly above its `kern pull alpine`, then calls `kern tag`,
  which reads the cache. On a clean cache that failed with "no such image 'alpine'". It passed only
  when an earlier command happened to have cached the ref. It now runs end to end: pull, tag, push,
  and pull back from the registry.

  `--dest <dir>` is unchanged and still extracts a plain rootfs, for `--rootfs` and for copying to an
  air-gapped host. The cache fill goes through the same function `box --image` uses, so there is one
  definition of the lock, the staging swap, the `.ok` completeness sentinel and the `.image` config
  sidecar rather than two that can drift.

  Policy is *missing*, not *always*: there is no blob cache, so re-fetching would transfer every byte
  again on every invocation (measured: 4.1 s then 3.3 s for the same alpine, both full downloads). A
  deliberate refresh is `kern box --image <ref> --pull always`, which the output names.

- **`--platform` without `--dest` is now refused, with the reason.** The cache key is the reference
  alone and carries no platform component, and the cache path fetches the host architecture, so
  storing a foreign-arch rootfs there would poison it - the same class as the platform cache-poisoning
  fixed earlier. Refusing names `--dest` as the way to do it; silently writing a directory would have
  given one verb a third behaviour. `--platform` **with** `--dest` is untouched, which is how every
  example already used it.


## [0.6.24], 2026-07-29

### Fixed

- **`--cpus` could be accepted and silently not enforced, and `doctor` called it enforced.** On a
  host whose `cpu` controller exposes only the *weight* interface and no `cpu.max` (no
  `CONFIG_CFS_BANDWIDTH`), a CPU quota becomes a share. kern said nothing, and `kern doctor` printed
  a green "resource caps enforced" because it checked whether the **memory** controller was delegated
  and generalised the verdict to all three knobs. Measured on an Arduino UNO Q's Android kernel
  (6.16): `cgroup.controllers` lists `cpu`, and `cpu.max` exists nowhere in the chain.

  Two causes, both now closed. The **scope** path handed the caps to `systemd-run` as
  `MemoryMax=`/`CPUQuota=`/`TasksMax=` and never re-checked; systemd accepts a property the kernel
  cannot honour and reports nothing. The direct path had verified its own writes since 0.6.x, so the
  rule existed and only one of the two callers used it: `warn_unenforced_caps` now reads the
  EFFECTIVE chain from inside the scope, for `kern box` and `kern run` alike. And `doctor` now probes
  for `cpu.max` itself instead of inferring it from a delegated controller name, because "this cgroup
  can distribute CPU" and "this cgroup can cap CPU" are different questions.

  Unchanged where the interface exists: on x86_64 a capped box still prints nothing and the doctor row
  stays green. The warning only speaks when it has something true to say.

## [0.6.23], 2026-07-29

### Changed

- **The binary now describes itself the way everything else does.** Running `kern` with no
  arguments, and `kern --help`, called it *"a fast, lightweight sandbox & virtual resource manager"*,
  while the README, the site and the package all say *"a fast, **rootless** sandbox and virtual
  resource **runtime**"*. The first line a user reads after installing dropped the one word that
  distinguishes kern from every other runtime, and called it a manager where everything else calls
  it a runtime. Aligned in all four places it appeared, including the crate description.

- **`kern top` no longer states what another runtime cannot do.** Three lines of help text in the
  Runs tab carried absolute claims about a competing tool ("what X can't do at scale", "X has no
  analogue this fast"). Nothing measured supports an absolute claim of that shape, and a product's
  own UI is the worst place to make one. The lines now describe what a run *is* (a CPU/mem-capped
  process with cgroup caps and no namespaces, counted as aggregate throughput rather than listed
  row by row), which is the useful part and is true on its own. Comparisons stay where the numbers
  are: [BENCHMARKS.md](BENCHMARKS.md).
- **Third-party marks are now named as such.** [TRADEMARK.md](TRADEMARK.md) gains an "Other people's
  marks" section: kern is independent and unaffiliated, third-party names appear nominatively (a
  file format it reads, a registry it talks to, a syntax it accepts), and they belong to their
  owners. Two error messages that justified a rule by citing another tool now simply state the rule.

### Fixed

- **`kern rmi` reported freeing space it had not freed.** An image layer can carry a directory with
  no owner write bit (`dr-xr-xr-x` is ordinary in Fedora-based images: `quay.io/podman/stable` has
  hundreds of them). Unlinking a file needs write on its PARENT, so `remove_dir_all` stopped at the
  first such directory and left the rest of the tree on disk, while the command printed the size it
  had measured *before* deleting. Measured on that image: **"removed image, freed 600.5M" with
  456 MB still on disk**. The delete now restores owner `u+rwX` on its own copy and retries, so the
  same case goes from 624 MB to 4 KB. Saying a thing happened when it did not is the costliest
  defect shape here, and on an SD-card board it is the difference between a full disk and an empty
  one.

- **The "every service is behind an inactive profile" error told you to set the wrong names.** It
  listed the SERVICES that were skipped and then said to put them in `COMPOSE_PROFILES`, which
  activates nothing, because a service name is not a profile name. Measured on a real file: the
  message suggested `hoppscotch-backend`, which does nothing, where `backend` is what works. It now
  names the services that WOULD run and, separately, the profiles that would enable them, checked
  against the same file: five of the eight it lists bring the stack up, and the other three surface
  a different, real conflict inside those services rather than the profile being wrong.

- **`kern exec` into a paused box hung forever.** A paused box sits in a frozen cgroup, so the
  exec'd process is placed there and never scheduled: the command produced no output, no error and
  no exit, and the only way out was Ctrl-C. `ps` had reported the box as `paused` all along, so the
  state was known, it just was not consulted before the exec. It now fails in **2 ms** with the
  reason and the way out (`kern unpause <box>` first). `kern cp` from a paused box is untouched and
  still works, because it reads `/proc/<pid>/root` and needs nothing scheduled.

- **`kern top` scrolled its own screen on any tab with a full list.** The row budget reserved 9 lines
  for chrome, but the frame chrome is 7 and every list pane adds 5 of its own (a blank, its caption,
  a blank, the column header, the trailing `… N more`), so 12 lines were spoken for before the first
  row of data. While a list was short nothing showed; as soon as one filled the budget the frame ran
  over by exactly 3. Measured: Images and Builds rendered **33 lines into a 30-row terminal**, and
  the same +3 at 20, 24, 40 and 50 rows. Three lines past the last row scroll the alternate screen,
  which carries the **tab bar off the top** and makes every repaint start one line lower: the
  flicker, and the missing header.

  The budget is corrected, and `render` now caps its own output at the terminal height, so the
  invariant lives in one place and a test holds it across seven tabs and seven window sizes. The cap
  also covers what the budget cannot: a pane with fixed content (the Overview) has a minimum height,
  and in a 10-row window it loses its bottom rows instead of corrupting the screen.

- **`kern top` dropped every key of a burst except the first.** The loop read up to eight bytes and
  dispatched `buf[0]`, discarding the rest. A terminal hands over several bytes in one read whenever
  keys outrun one loop turn: a held key repeating, a paste, or any laggy link, which over ssh to a
  board is the normal case rather than the exception. Measured: eight keys typed as one burst left
  the TUI unresponsive until it was killed 12 s later, because the `q` at the end was never seen;
  the same keys one at a time answered in 274 ms. A read is now split into individual key events and
  queued, one dispatched per turn, and a queued key skips the poll entirely instead of waiting on
  it. After the fix the same burst quits in **274 ms**, and a thirty-key burst in 275 ms.

  Escape sequences stay whole, which is why this is not a plain per-byte loop: an arrow key is three
  bytes that mean one event, and splitting it would type a stray `[` into a form. A bare `Esc` is
  still delivered on its own, so it still closes a modal.

- **`kern tag` produced an image that would not run.** The destination's config sidecar was copied
  first and the "clear any prior image at the destination" sweep ran second, deleting the file that
  had just been written. A tagged image therefore lost its entrypoint, cmd, env, workdir and user,
  and `kern box --image <newtag>` answered `this image declares no entrypoint or command in kern's
  cache`. The sweep now runs before anything is written to the destination, which is where a
  "replace what is there" step belongs. Re-tagging over an existing image is pinned by test too,
  since that is the case the sweep exists for.

- **`WORKDIR /app` + `COPY . .` failed to build.** The relative destination was joined onto the
  workdir as a literal `/app/.`, and `cp` cannot create a directory named `.`, so the build died with
  `COPY '.' → '.' failed`. That is the shape most application Dockerfiles have. It survived because
  every neighbour worked: `COPY . /app` (absolute destination), `COPY main.py .` (file source), and
  `COPY . .` with no `WORKDIR` all took other paths, so only a DIRECTORY source with a relative dot
  destination under a non-root workdir hit it. The destination now has its `.` and empty segments
  collapsed before use. `..` is deliberately left in place: `sanitize_rootfs_rel` refuses it, and
  resolving it here would turn a rejected escape into an accepted write (checked: a
  `COPY f /../../../tmp/x` is still refused with `escapes the image rootfs`).

- **`alpine` and `alpine:latest` were two different images.** The registry request was always right
  (`parse_ref` defaults a missing tag to `latest`), but the **cache key** was derived from the
  reference as typed, so one image pulled both ways was stored twice. Four things followed, all
  measured before the fix: two rows in `kern images` holding **8.7 MB each of identical content**;
  `kern rmi alpine` freeing 8.0 MB and leaving `alpine:latest` behind; `kern gc` blind to the pair
  (it freed 261 B); and, the half you actually hit, a `save` + `load` round trip **renaming** an
  image, so a build tagged `myapp` came back as `myapp:latest` and `--image myapp` stopped
  resolving.

  A reference now gets its implied tag once, in `kern_oci::normalize_ref`, before anything keys a
  cache dir, a sidecar or a lookup on it. The rule that decides whether a reference is already
  tagged lives in exactly one function (`split_tag`) used by both the normalizer and the registry
  parser, so the two cannot drift: a registry **port** is not a tag (`localhost:5000/img` becomes
  `localhost:5000/img:latest`, not a tag of `5000/img`), and a **digest** is never given one
  (`img@sha256:…` is returned untouched, because it pins harder than a tag). `rmi` normalizes both
  sides of its comparison, so either spelling deletes the image you are looking at, and `kern
  images` prints the canonical form so every row is a reference you can paste straight back.

  **One-time cost, stated exactly.** The cache key changes, so an image cached by an earlier version
  is not found under the new key and is pulled once more. Nothing is deleted, and the old entry stays
  on disk: `kern gc` does **not** reclaim it (measured: 0 B freed), because it is a complete, valid
  cache entry and not garbage. Until you remove it, `kern images` lists it as a second row with the
  same name, since both spellings now print canonically. `kern rmi <ref>` therefore removes **every**
  entry that reference resolves to and reports the total, so one `kern rmi alpine` reclaims the pair
  (measured: 16.0 MB from two 8.0 MB entries) while `alpine:3.19` and every unrelated image are left
  untouched.

- **`-v .:/app` was refused as an invalid volume name.** Every `-v` source without a leading `/` was
  classified as a *named volume*, so the most ordinary bind there is (mount the project you are
  standing in) reached the volume-name validator and came back as `invalid volume name '.'`. The
  same line through the compatibility shim failed the same way, which is what that shim exists to
  prevent. `-v` now applies the conventional rule: a source is a **path** when it is absolute or
  starts with `./` / `../` (or is exactly `.` / `..`), and a **name** otherwise. The two negatives
  are unchanged and pinned by test, because they are how a fix like this breaks: `-v sub:/app` is
  still a named volume (not the `./sub` directory), and `-v foo/bar:/app` is still an error.

  The compose layer already resolved its own `./` binds against the compose file's directory, and
  still does: relative sources from a `.yml` continue to resolve there, not against the current
  directory. Only the CLI flag changed, where the base is the current directory. No containment
  guard is applied to the CLI form on purpose: a direct invocation can already name any absolute
  path, so resolving a relative one grants nothing new, while refusing `../shared:/x` would break a
  legitimate call. Other path-taking flags (`--env-file`, `--secret`) never had the ambiguity and
  were already correct.

### Profiles and `kern.toml`

Nine defects found by exercising the profile surface end to end on five machines, including the
three ARM boards. Every one of them is the same shape: two places deciding the same thing.

- **The writer and the reader used a different file.** `KERN_CONFIG` was honoured when *reading*
  (`kern config list`) and ignored when *writing*: `config add`/`rm`/`setup`/`edit`, and also
  `kern validate` and `kern info`, went straight to `~/.config/kern/kern.toml`. Point `KERN_CONFIG`
  at a project config and the listing showed that file while the edit silently landed in the global
  one, with no message on either side. One `config::active_path()` now answers "which file is in
  effect" for every caller. Verified on all three boards: an add against a `KERN_CONFIG` fixture
  lands there, and `list`, `validate` and `info` all report the same path.

- **`kern config list` showed unusable profiles as healthy.** A profile with no `backend` cannot
  attach - `kern validate` says so, naming file, profile and fix - but the listing printed it like
  any other. Two read verbs over one file gave two verdicts because one never asked. The listing now
  runs the same check and marks the entry, with a trailing count pointing at `kern validate`.

- **The summary could not tell a real device grant from nothing.** `vgpio` entries reported only
  `N pin(s)`, so a profile carrying `i2c = ["/dev/i2c-5"]` printed `0 pin(s)`, the same line as one
  that grants nothing, in the one command that answers "what do my profiles hand out?". It now
  counts declared devices and lines across every field (never `net`, which vgpio parses but does not
  attach).

- **A device path that escapes `/dev` was stored and then refused at every launch.**
  `--i2c /dev/../etc/shadow` passed the writer's prefix test; the resolver then skipped it on every
  box start ("outside /dev/"). `is_dev_path` now walks `.`/`..` and refuses anything that does not
  land under `/dev/`, which is the rule the resolver already applied. The lexical check is not a
  substitute for the resolver's `canonicalize`: a *symlink* out of `/dev` is still the resolver's
  job, and the comment says so.

- **The only mandatory field was the hardest one to reach.** `backend` is required on every profile
  and lives inside the TUI's "Advanced" fold, below every detected-device row - so the more hardware
  a host has, the further down it sits. Measured: a Pi 5 (no i2c nodes) puts it six rows down, a
  Jetson (seven i2c buses, four spi ports, four uarts) far below that, on exactly the boards where a
  vgpio profile is the point. Filling the visible form and pressing Enter answered with a message
  written in TOML rather than in the form's language. Both writers now pre-pick the kind's sentinel
  (`host`, or `ram` for vdisk) and write it EXPLICITLY: creating a vgpio profile in `kern top` went
  from 28 keystrokes to 9. The file still never carries an implicit default, a hand-edited profile
  with no backend still fails loudly, and `--update` never rewrites a backend the caller did not
  mention.

- **`kern box --plan` previewed the mounts and not the hardware.** A `vgpio:` profile hands over real
  device nodes; the preview listed three mount steps and said nothing about `/dev/i2c-5`. It now
  resolves the attached profiles against this host - the same call the launch makes, so preview and
  launch cannot disagree - and reports the binds, the sysfs paths, the pins (naming the
  chip-granular limit), or the reason a profile cannot attach.

- **A granted device you cannot open looked like a kern bug.** kern deliberately does not elevate: a
  rootless box inherits the caller's access, so a node at `root:root 0600` is visible inside the box
  and refuses to open. Nothing said so. A box start now names the device, its uid/gid/mode, and the
  two ways out. One-directional by construction: the box runs as this user or a mapped subuid with no
  more access, so "the caller cannot open it" implies the box cannot either.

- **`kern config setup --force` overwrote a config with no way back.** It now copies the previous
  file to `kern.toml.bak` first and prints where it went, or says plainly that the backup failed.

- **A flag the read-only config verbs do not take was ignored.** `kern config list --json` printed
  the human listing and exited 0, so a script that asked for JSON got prose and could not tell. Any
  unrecognised flag on `list`/`edit`/`setup`/`probe`/`clear` is now refused by name.

- **A shipped config example did not work, and said the opposite.** [docs/STORAGE.md](docs/STORAGE.md)
  presented a complete `~/.config/kern/kern.toml` with `backend` commented out and annotated
  "default is automatic" - false since 0.6.11, and copying that file gets it refused. Found by
  extracting every TOML snippet from the shipped docs and running it through `kern validate` rather
  than by reading them. The remaining snippets that do not validate standalone are the per-field
  reference excerpts, which show a profile without its physical block on purpose and are annotated
  `REQUIRED`; the "copy-paste this starter" block in [docs/CONFIG.md](docs/CONFIG.md) validates, and
  so does the output of `kern examples`.

- **Two of the three SDK examples in the README did not run.** The Node one built a `Sandbox` and
  called `runCode` without opening it, so it threw on the first useful line; the Python one passed
  `memory="512m"` where the constructor takes `memory_mb`, so it raised a `TypeError`. Both are in
  the section that shows what embedding kern looks like. Found by extracting every `python`/`js`
  block from the shipped docs and executing it against the PUBLISHED packages, which is now a
  harness: 6 runnable examples, all passing, 12 fragments (excerpts with no import) reported as
  skipped rather than counted as passing.

- **The README quoted the same timings sixteen times too often.** Every repeated number is a place
  that must be updated when it is re-measured, and this release already had a count drift. Prose
  restatements of figures that live in the comparison tables are gone (66 mentions to 60 overall,
  27 to 21 in prose, `~2.3 ms` from ten to five); the opening pitch, the at-a-glance line and every
  table keep theirs, because that is where a number belongs.

- **`KERN_CONFIG` was called "documented" and was not.** It appears in no README, no `docs/`, and no
  `--help`, while now governing which file every read AND write touches.
  [docs/CONFIG.md](docs/CONFIG.md) gains a "Which file is in effect" table covering `--config`,
  `KERN_CONFIG` and the default location, and says that `kern info` prints the path in effect.
  `--plan`'s help line now mentions the device grants it prints.

Two things that looked like defects and are not, checked before changing them: `--cpus 99999` is
accepted at write time on purpose (a config is portable) and the runtime clamps it to the host's
CPUs with a warning; an oversized RAM-backed `vdisk` mounts, and the runtime already states that it
is tmpfs, ephemeral, and charged to RAM, and points at `--memory`.

### Bindings (`kern-sandbox` 0.1.11, on PyPI + npm)

- **The bindings reported the wrong version of themselves.** `kern_sandbox.__version__` and the Node
  `version` export both read `0.1.8` while `pyproject.toml` and `package.json` declared `0.1.10`, so
  the published 0.1.10 package identified itself as 0.1.8. The visible consequence was in the MCP
  server: the `serverInfo.version` returned at `initialize`, which is what an MCP client logs and
  displays, named a release two versions old. The version was stated in two places per binding and
  they drifted, the same duplicated-derived-value defect as `-v .:/app` and the tag default in this
  release. Both literals now match their manifest, verified through a real stdio handshake rather
  than by reading the source.

## [0.6.22], 2026-07-28

### Fixed

- **`kern top` showed a pod's members by their project prefix, not their service name.** The name
  was truncated to sixteen characters and the project scope alone is longer, so every member of a
  stack rendered as the same string and the one column that tells them apart told you nothing.
  `kern ps` had stripped the prefix all along: two views of one registry disagreeing about what a box
  is called. The rule now lives in `ui::display_box_name`, which both call.

### Changed

- **Every timing in the README and BENCHMARKS.md was re-measured on one machine, on one night.** The
  table was from June on Linux 6.17 and had drifted: podman was quoted at 155 ms and measures 288,
  Docker at 308 and measures 289, a bare box at ~2 ms and measures 2.3. The demo GIF and SVG carried
  the old figures in their pixels and were regenerated from the generator that now ships beside them.
- **`KERN_TIMING` instruments the parent**, which had none: half of a box start was invisible.
  `parent:name-check`, `parent:config+volumes`, `parent:claim`, `parent:unshare(ns)+idmap`,
  `parent:setup->spawn`, `box lifetime (spawn->exit)`, `parent:teardown`.

  What it found: `unshare(CLONE_NEWNET)` costs 430 us on this kernel, 17% of a box start, and is the
  largest single item. It is the kernel's price for network isolation; `--net` skips it.

  It also settled a question that a summary had answered wrongly. Against 0.3.0 on the same machine:
  an UNCAPPED box went from 1.7 to 2.2 ms (thirteen mounts that mask `/proc` and close an escape
  through `core_pattern`, plus a seccomp filter grown from 79 to 170 us), while the box a user
  actually runs went from **4.92 ms to 2.45**, because 0.3.0 re-execed through `systemd-run` eleven
  times per start and this does not.

## [0.6.21], 2026-07-28

Compose compatibility, measured against 109 real `docker-compose.yml` files (all of
`docker/awesome-compose`, plus Airflow, Sentry, Supabase, Appwrite, Kafka, Temporal, Immich,
Mastodon, GitLab, Nextcloud, Grafana, MinIO, Keycloak, Odoo, Drupal, Moodle, Saleor, Vendure,
Windmill, Dify, Directus and the rest: 12,111 lines) and against `docker compose config` itself
rather than against an assumption.

95 of the 109 now parse as they are, up from 90. Of the 14 that do not, 5 are refused by Docker
too, 7 are pod port collisions that `--no-pod` accepts, and 2 diverge on purpose.

### Added

- **A container-only port is accepted, as a DECLARED port.** `ports: ["8000"]` and
  `ports: ["${UNSET}:8000"]` were refused; Docker normalises both to `target: 8000` with no
  published port and assigns an ephemeral one at `up`. kern has no ephemeral allocator, and
  inventing one would publish a port the file never named on a number nobody can predict, so the
  entry joins the pod-wide space `expose:` and `port:` already feed, with a warning saying no host
  port was published and how to ask for one. The preflight still sees it, so a collision against it
  is still refused. Supabase, Budibase, Jitsi and OpenCTI reach this form through an unset variable.

### Fixed

- **A `depends_on` typo was silently dropped.** The pruning loop removed every absent name, so the
  topological sort never saw it and the ordering the file asked for vanished behind one vague line
  that pointed at profiles. A name skipped by an inactive profile is still pruned; a name that was
  never defined is now refused and quoted, as Docker refuses it. Cross-file dependencies
  (`-f base.yml -f db.yml`) are unaffected.
- **An `image:` beginning with `-` was accepted by compose** while the docker shim refused the
  identical string as flag injection. Not exploitable (kern passes it as a value; it failed at the
  registry with a message about the wrong thing) but one rule had two answers again.
- **A per-service `networks:` with no top-level block passed in silence.** Docker refuses that file;
  kern dropped the segmentation and said nothing. Stated once per run, not once per service: eight
  identical lines on a seven-service file is how a reader learns to skim past warnings.
- **`services:` is empty** was the answer for a file with ten services, all behind inactive profiles.
  Right outcome, wrong noun. It now names them and says to set `COMPOSE_PROFILES`.
- **An empty file was answered with a TOML noun** (`no [box.NAME] tables found`) for a document
  saved as `.yml`. An empty file has no format to guess.
- **The installer gave up on a WSL2 distro** whose curl is built against c-ares: an AAAA lookup
  against the WSL NAT resolver goes unanswered while the A record resolves. One IPv4 retry, saying
  why. `kern pull` was never affected.
- **`examples/benchmark.py` took over ten minutes**, because a fixed 1000 runs per runtime is three
  seconds for kern and five minutes for docker. Each batch now fits a time budget and prints the
  run count it actually used: 118 s, same numbers.

## [0.6.20], 2026-07-28

One fix, found on a Raspberry Pi 5 two hours after 0.6.19 shipped.

### Fixed

- **The `docker` shim was broken through a symlink, for every non-root user.** Installed the way
  the README documents (`ln -s "$(command -v kern)" ~/.local/bin/docker`), `docker run --rm alpine
  echo hi` failed with `usage: kern run: unknown flag`.

  kern re-execs itself under `systemd-run --scope` to apply cgroup caps, and that path is taken by
  an ordinary user, not by root. The re-exec replayed the argv the user TYPED and located the binary
  with `current_exe()`, which resolves the symlink: the second pass got `argv[0] = kern`, no longer
  recognised itself as the shim, and handed untranslated docker syntax to kern's own `run` verb.

  Two independent losses that combine only through a symlink. Installed as a copy named `docker` it
  worked, which is how it passed every check that had been run before a board ran it as a real user.

  The re-exec now replays the argv kern decided rather than the one it was given. `kern box
  --restart`, which freezes the argv into a systemd unit, had the same defect and worse consequences:
  it would have written docker syntax into a file that fails at every boot.

  Verified on the Pi 5, the Jetson Orin Nano and the Arduino UNO Q: 17/17 each, symlink and copy,
  with `--device` still refused by name.

## [0.6.19], 2026-07-28

Docker compose parity for web stacks, plus three defects found by running the work on real hardware.

### Added

- **`docker` / `docker-compose` shim.** Invoked under either name (a symlink is enough), kern
  translates the argv and runs an existing script unchanged. Every flag lands in one of three
  buckets: forwarded, dropped as a no-op, or refused by name. There is no fourth bucket where a
  flag is silently ignored.
- **`kern compose`, ten verbs**: `up`, `down`, `stop`, `start`, `restart`, `ps`, `logs`, `build`,
  `pull`, `config`, reading a `docker-compose.yml` or a kern profile.
- **`kern compose <file> systemd`.** Prints a systemd unit on stdout and installs nothing. kern is
  daemonless, so coming back after a reboot is the one thing it cannot do for itself. The unit
  states in a comment that it does not supervise, rather than letting the reader assume it does.
- **`port:` and Docker's `expose:`.** Declare the port a service listens on inside the pod. kern
  reserves it (a second service claiming it is refused before anything starts) and passes `port:`
  to the service as `PORT`. This is the way out of the one constraint the pod model imposes.
- **Profile keys that had a CLI flag but no config key**: `init`, `add_host`, `ulimits`, `labels`,
  `sysctls`, `restart_max`, `stop_signal`, `stop_grace_period`.

- **`kern bench` accepts `--image`.** It took only `--rootfs <dir>`, so the one command the README
  points a newcomer to needed two others first. With `--image` it spawns the same `kern box --image`
  a user would run, and warms the cache before timing so a first-run pull is not counted.
- **The two id-map helpers run concurrently.** `newuidmap` and `newgidmap` ran back to back, two full
  spawn/exec/wait cycles. They write different files for the same target and share no state, so
  nothing ordered them: overlapping them takes an image box from ~4.0 to ~3.4 ms. Both are waited
  even when the first fails, or the unreaped child would linger as a zombie for the box's lifetime.

### Fixed

- **`kern stop` waited the full grace period for a signal the box could not receive.** A PID-namespace
  init discards any signal it has no handler for, so an ordinary command (`sleep`, most binaries)
  never dies from SIGTERM and the graceful phase became a 10-second wait for an event that could not
  happen: 9013 ms to stop one box, and a `compose down` of four services would have taken 36 s. kern
  now reads `SigCgt` and skips the graceful phase when the init provably cannot catch the signal, so
  that box stops in 4 ms while a service that DOES trap it still gets its full grace.

- **`kern stop --all` deleted systemd unit files it had never written.** It identified its own
  persistent boxes by file name, so any `kern-*.service` in the user's unit directory was removed,
  including one written by hand. Ownership is now asserted positively, from a marker inside the
  file; anything unmarked is left alone.
- **An `--image` box announced a single-uid map it did not have.** The heads-up about an image
  running as a non-root user checked two of the four conditions that turn the uid range on, so it
  reported a missing map that was in fact present and advised a flag change that would have done
  nothing.
- **`--show-config` reported `uid_range: false` for every image box**, while the box itself mapped
  a range. The dry run now reports the same decision the box makes, and names its source.
- **`docker compose up -d` failed** with kern's usage text. The compose path had no bucket for
  `-d`, which asks for what kern already does.
- **Override files silently dropped four fields** (`port`, `restart_max`, `stop_signal`,
  `stop_grace_period`): they reached the struct but not the merge.
- **`compose config` reported a stack that `up` refused as clean.** The pod-global check (two
  services on one internal port, a shadowed host entry) was gated at each call site instead of
  inside itself, and the three sites drifted: `up` ran it, `systemd` ran it ungated, and `config`,
  the verb whose whole job is answering "will this come up?", never called it. A dry run that
  disagrees with the bring-up is worse than no dry run. The gate now lives in the function, so no
  caller can restate it differently.

### Changed

- The compose sub-verb list, the help line and the usage message are one list. `systemd` shipped
  working but absent from both, because the list was written out three times by hand.
- **A malformed `expose:` entry is treated differently by design, and now says so.** In a kern
  profile it is refused with its line number; in a `docker-compose.yml` it is warned about and
  skipped, because failing someone else's whole stack over one line of pure documentation is the
  wrong trade. Both spellings share the one parser, so a valid entry always means the same thing.
  The two dispositions had drifted apart under a comment asserting they could not, which is what
  happens when nothing asserts them together: a test now does.


## [0.6.18], 2026-07-26

OCI compatibility with fail-closed security: an image that ships an inert device node in a layer
(Amazon Linux, and any base that bakes a `/dev/*` node) now pulls and loads, instead of being refused
with "layer has a device node". The isolation posture is unchanged and stays fail-closed.

### Changed
- **OCI pull/load: strip device members instead of refusing the whole layer.** A new in-process pass
  (`strip_device_members`) re-emits the decompressed layer as a PLAIN tar with every char/block device
  member (typeflag `3`/`4`) removed and every other member copied VERBATIM, then the UNCHANGED vetter
  (`check_layer_safe`) RE-VETS that output before a single byte is extracted. `tar` then extracts the
  device-free plain tar, so no device node can reach the box rootfs on any tar implementation (GNU or
  BusyBox) or privilege (root or rootless): the extractor never sees a device. This ELIMINATES the
  vetter-vs-extractor divergence surface (kern is now the source of the tar `tar` extracts) rather than
  widening it. The box still gets its own fresh `/dev` and drops `CAP_MKNOD`, so an image's device
  paths are inert regardless. Fail-closed: any device the strip missed, or any corruption it
  introduced, is rejected by the re-vet, never extracted. The vetter itself is byte-identical (its
  20+ tests and the fuzz target are unchanged). Box-start latency is unaffected (the filter runs only
  at pull/load, never on the box hot path). Validated: 3 new unit tests, a 7.2M-run fuzz pass (ASAN,
  no crash), the full suite, all 8 test distros plus amazonlinux, and BusyBox tar extraction.

## [0.6.15], 2026-07-26

Hot-path cgroup cleanup and finer setup profiling. No isolation-core or behaviour change: cap
enforcement is verified identical (memory.max/cpu.max/pids.max readback, a real OOM kill at the cap,
and 50 concurrent capped boxes), the full suite and the adversarial break-out battery both stay
green.

### Changed
- **cgroup: enable only the delegated controllers, in a single write.** A cgroup-v2
  `cgroup.subtree_control` write is atomic, so the previous fixed `+memory +pids +cpu +cpuset +io`
  batch failed *entirely* on a typical user session (where `cpuset`/`io` are not delegated) and fell
  back to five per-controller probe writes, most of them failing, on every box. It now reads the
  parent's exported `cgroup.controllers` first and batches only what is actually available, so the
  one write always succeeds: six syscalls down to one, no failing probes. The set of controllers
  enabled is unchanged, so `--memory`/`--cpus`/`--pids` enforcement is identical.

### Added
- Finer `KERN_TIMING` phases for box setup: `pivot+mount_proc`, `proc-mask` and `cgroup-view` are
  reported separately (previously one `pivot+proc`), so the built-in profiler shows where setup time
  actually goes. Observability only, no behaviour change.

## [0.6.14], 2026-07-23

Everyday-CLI parity on the read/inspect and lifecycle commands (no isolation-core change).

### Added
- **`kern logs --tail N`** prints only the last N lines; **`-f`/`--follow`** streams new output until
  the box exits (Docker `logs -f`), sharing the poll loop with `kern attach`. `--tail` seeks a bounded
  window near EOF, so it stays cheap on a multi-gigabyte log (cost is O(lines shown), not O(file size)).
- **`kern ps -q` / `--quiet`** prints box names only, one per line (scriptable, e.g.
  `kern stop $(kern ps -q)`); **`kern ps --filter`** accepts `name=<substr>`, `status=running|paused`,
  and `id=<pid>` (AND semantics; an unsupported key fails fast); **`kern ps --format '{{.Field}}'`**
  renders a bounded placeholder set (`{{.Names}}`, `{{.Pid}}`, `{{.Status}}`, `{{.RunningFor}}`, …) and
  errors on an unknown token (no Go-template logic; `--json` remains for arbitrary shaping).
- **`kern box --pull never`** fails when the `--image` is not already cached instead of pulling over
  the network; **`--pull always`** forces a fresh pull with an **atomic cache swap** (a box already
  running on the old image is undisturbed, its overlay-lower dentry stays pinned; a locally-built image
  is used as-is); `missing` is the default. Retired image dirs are reaped by `kern gc` when idle.
- **Five more Docker-parity box verbs**: **`kern rename <old> <new>`** (rename a running box in place,
  pid unchanged); **`kern update <box> [--memory M] [--cpus N] [--pids-limit P]`** (change cgroup v2
  caps live, no restart); **`kern wait <box>...`** (block until each box exits, print its exit code);
  **`kern diff <box>`** (overlay-upper filesystem changes: `C` created/modified, `D` deleted); and
  **`kern events`** (poll-based stream of box `start`/`die`/`rename`; daemonless, best-effort - it can
  miss a start+stop that both fall inside one poll gap).

### Fixed
- **Box cgroup stats/pause/update resolve via the box's own pid1**, not the supervisor pid. On the
  direct `kern.slice` cap path the supervisor stays in the launcher's cgroup by design, so
  `stats`/`pause`/`update`/`ps --filter status=paused` previously read the wrong cgroup there; they now
  key off the host-namespace box init, correct on both the direct and the re-exec scope path.
- **`kern rename` builds on aarch64/x86_64-musl**: the atomic name swap now issues `renameat2` via the
  raw syscall (the musl `libc` bindings do not expose the wrapper), so release builds link on every
  target.

## [0.6.13], 2026-07-23

Schema consistency and a README pass.

### Changed
- **`[[disk]]` now identifies with `id`**, matching `[[cpu]]` and `[[gpio]]`. The rule is now uniform:
  physical blocks (`[[cpu]]`/`[[gpio]]`/`[[disk]]`) use `id`, virtual profiles
  (`[[vcpu]]`/`[[vgpio]]`/`[[vdisk]]`) use `name`. `name` on a `[[disk]]` keeps working as a
  back-compat alias, so existing configs load unchanged; `kern config setup` and `kern examples` now
  emit `id`.

### Documentation
- The terminal demo was self-contradictory: it showed an 8 GB scratch inside a 2 GB cap, but a rootless
  `vdisk` is a RAM tmpfs charged to `--memory`, so it would OOM. Retuned to 8 GB RAM + a 2 GB scratch,
  and the docs now say a `[[disk]]` backend is a real ext4 quota only when privileged (rootless it is a
  RAM tmpfs, size it under the memory cap).
- The `--secret` quickstart now runs as written: it opens the one host it needs with `--egress-allow`
  (the network is isolated by default) and uses Alpine's busybox `wget` instead of a `curl` that isn't
  installed.
- The named-device-set pitch now acknowledges CDI (the Container Device Interface) and states the real
  edge: a line of TOML with the engine included and deny-by-default, versus a JSON spec plus a
  supporting engine.
- The WSL2/`memory`-controller note is consolidated under Requirements & limitations (Install and
  Platforms point to it); the Security intro describes the default copy-on-write overlay root precisely;
  the benchmark CPU is labeled 20-core / 28-thread.

## [0.6.12], 2026-07-22

A fix so `kern config setup` produces a config that passes `kern validate`.

### Fixed
- **`kern config setup` generated `[[vcpu]]` profiles without a `backend`**, so the starter config it
  tailors for a host failed its own `kern validate` under 0.6.11's mandatory-backend rule. Both
  generated vcpu profiles now carry `backend = "cpu:0"` (vdisk/vgpio already did). Verified end to end
  on x86_64, Jetson Orin (aarch64), and Raspberry Pi 5. A regression test now runs `config setup` and
  asserts `kern validate` accepts the output.

### Documentation
- README: an architecture diagram, links to the security-relevant source (isolation, seccomp, cgroup,
  OCI pull), and a Requirements & limitations section.
- CONFIG.md: a full `[[vgpio]]` device-field reference and an extreme-clarity hand-editing guide; the
  starter snippet now shows the hardware blocks (`[[cpu]]`/`[[disk]]`/`[[gpio]]`) alongside the profiles.

## [0.6.11], 2026-07-22

A stricter, unambiguous resource-profile schema.

### Changed
- **`backend` is now REQUIRED on every `[[vcpu]]`/`[[vgpio]]`/`[[vdisk]]` profile** (breaking,
  pre-1.0). A profile must name the host resource it slices: a declared `[[cpu]]`/`[[gpio]]`/`[[disk]]`
  id, or a reserved keyword . **`host`** (the whole host CPU, or the host's own device nodes) or
  **`ram`** (a RAM-backed vdisk). This removes an ambiguity where a backend-less profile, or a typo in
  a backend, silently attached to a default/RAM resource. A missing or dangling backend is now
  rejected with a clear, actionable error at `kern validate`, at `kern box`/`kern run` attach time, at
  `kern config add`, and in the `kern top` form (which offers `host`/`ram` first). Migration: add
  `backend = "host"` (vcpu/vgpio) or `backend = "ram"` (vdisk) to a bare profile, or name a declared
  physical block. See `kern examples`.

## [0.6.10], 2026-07-22

A resource-isolation fix for `kern exec`.

### Fixed
- **`kern exec` now inherits the box's `--memory`/`--pids` caps.** An exec'd command joins the box's
  cgroup before entering its namespaces (the same "cap before fork" order the box's own PID 1 uses),
  so a fork bomb or memory hog run via `kern exec` is bounded by the box's limits, like `docker
  exec`. Previously it stayed in the launcher's cgroup and could exceed them. On the rootless
  per-box-scope path (e.g. an SSH login session on an edge board) the kernel won't let `kern exec`
  migrate into the box's transient scope; there it can't be enforced, so kern now warns when the box
  has explicit caps instead of leaking it silently. Namespaces + seccomp isolate the exec'd command
  either way. See [SECURITY.md](SECURITY.md).

## [0.6.9], 2026-07-21

A small CLI addition plus a big step for the language bindings (shipped separately as `kern-sandbox`
0.1.7 on PyPI + npm): a persistent warm interpreter that turns the code-interpreter path sub-millisecond.

### Added
- **`kern top` now shows a box-start rate.** The Boxes tab surfaces a per-second box-start rate with a
  sparkline, mirroring the existing runs rate, read from the daemonless mmap counter (offset 16). It is
  reader-side only: zero cost on the box-start hot path.

### Bindings (`kern-sandbox` 0.1.7, on PyPI + npm)
- **Warm kernel (`Sandbox.kernel()` / `Kernel`), Python and Node.** One persistent, warm Python
  interpreter in a long-lived box: cells run in a single resident process, so in-memory state persists
  across cells and the per-cell cost drops from a full CPython boot (about 10 ms) to sub-millisecond
  (about 300x, 25k cells/s). It captures the same rich mime-typed results as `run_code`, tears the box
  down on a per-cell timeout, caps oversize replies (a host-memory guard), and isolates the control
  channel on private fds so raw writes, C extensions and subprocess output are captured rather than
  corrupting the protocol (a raw `os.fork()` no longer spawns rogue clones). Trade: call-fast, not
  call-isolated (one process, one box, still network-off and resource-capped).
- **MCP kernel mode (`KERN_MCP_KERNEL=1`).** Routes the MCP server's Python `run_code` through a warm
  kernel, still network-off, respawning transparently on a timeout.

## [0.6.8], 2026-07-20

Coherence and agent-DX release: the 0.6.7 isolation features are now visible in `kern top`/`inspect`
and reachable from the language bindings, with live streaming and a workspace checkpoint.

### Added
- **`kern inspect` and `kern top` now surface the 0.6.7 isolation policies.** `inspect` shows the
  configured `mem-cap`/`pids-cap`, plus `landlock`, `egress` and `pod` when set (and the same fields in
  `--json`); the Boxes tab in `kern top` flags an egress/landlock box with a cyan badge, and the Overview
  shows a fleet-budget line when `KERN_FLEET_*` is in force. A box's requested caps and policies are
  recorded in its registry entry so they can be read back.
- **`--egress-allow` and `--landlock-rw` are now listed in the box help.**
- **Language bindings (Python + Node) gained the runtime features:** `profiles=["vcpu:…","vgpio:…",
  "vdisk:…"]` (attach a kern.toml resource profile, strictly validated), `egress_allow=[domains]` (a
  domain allowlist for the untrusted run box, mutually exclusive with full network), `on_stdout`/
  `on_stderr` live output callbacks (best-effort, the full capped output is still captured), and
  `snapshot`/`restore` of the workspace (a portable `.tar.gz` filesystem checkpoint, not a memory
  snapshot). `run_code` also accepts `language="node"`.

### Changed
- The Python binding no longer injects a `KERN_ACCEPT_EULA` variable (the public build has no EULA gate);
  the vestigial passthrough was removed from the bindings, examples and tests.

### Security
- **Snapshot `restore` is hardened against a hostile archive:** absolute paths, `..` traversal, symlink/
  device/hardlink members, a trailing-slash that could make a stat follow a planted symlink, a member
  size past the archive, a non-octal or negative size, and a bad ustar checksum are all refused; writes
  use `O_NOFOLLOW` with a symlink-rejecting parent descent. The Node hand-rolled tar reader is **opt-in**
  behind `KERN_SANDBOX_SNAPSHOT=1` (fail-closed) while it matures; the Python path uses the stdlib
  `tarfile`. The `egress_allow` and `profiles` values are strictly validated so a binding argument can
  never smuggle a CLI flag.

## [0.6.7], 2026-07-19

Agent and fleet sprint: run LLM/agent-generated code and dense per-request workloads with a real
egress boundary, a write-allowlist, warm-start snapshots, and honest fleet budgets.

### Added
- **`--egress-allow d1,d2,…` restricts a box's outbound traffic to a domain allowlist.** The box runs
  in an isolated network namespace and reaches the internet only through a kern-run filtering proxy
  that permits exactly the listed domains (ports 80/443). An agent can `pip install` from the index
  you allow but cannot exfiltrate to an arbitrary host. SSRF-guarded: a domain that resolves to any
  non-public address (loopback, RFC1918, link-local, CGNAT, reserved) is refused, and the request head
  is checked for smuggling. One inherent gap stays documented, not hidden: a domain sharing a CDN IP +
  SNI with an allowed one can be reached. Threat model and gaps in [docs/EGRESS.md](docs/EGRESS.md).
- **`--landlock-rw <path>` confines a box's writes with the Landlock LSM.** The box root is read+exec
  and writes are allowed only under the paths you name, a kernel-enforced second boundary the workload
  can't lift, fail-safe on symlinks.
- **`kern commit <box> <image>` snapshots a running box into a reusable image (warm start).** Bake an
  expensive one-time setup (`apt`/`pip`, a warmed cache) once, then start from it in milliseconds. A
  filesystem snapshot, not live memory: volumes and secrets are skipped, never baked in. It is
  `docker commit`, daemonless.
- **Fleet budgets.** `KERN_MAX_CONCURRENT` is a cooperative admission cap (best-effort, may overshoot
  under a parallel burst); `KERN_FLEET_MEMORY_MAX` / `KERN_FLEET_PIDS_MAX` place a REAL summed cap on
  `kern.slice` when boxes share it (root/direct-cap path), and warn + no-op on rootless per-box scopes
  where a summed cap can't be enforced. Scope stated honestly in [docs/CONFIG.md](docs/CONFIG.md).
- **`kern pod --uid-range`** maps a pod's members through a subuid range.
- **Node / TypeScript `kern-sandbox` binding**, 1:1 with the Python one, for embedding a fresh isolated
  box per call from JS/TS agents.

### Changed
- **A box now reads its own resource caps from inside.** Its cgroup namespace gets a read-only view of
  its own cgroup, so a JVM, .NET or Node runtime sees its real `--memory` limit (`memory.max`) by
  default instead of the host's, and **`/dev/shm` is a real tmpfs** so Postgres, Python `multiprocessing`
  and Chromium run out of the box.

### Security
- Egress path hardened end to end: resolved-IP vetting (whole name refused if any record is non-public),
  IPv4-mapped-IPv6 canonicalization, CGNAT / `240/4` / reserved ranges refused, bare-LF request-smuggling
  rejection, userinfo stripped from the authority, and slowloris / idle-relay bounds on the proxy.
- `kern commit` snapshots under an RAII cgroup freeze (TOCTOU-safe), with an async-signal-safe thaw so
  an interrupted commit never leaves a box frozen.

### Housekeeping
- Prose and CLI output swept free of em-dashes for brand consistency; crate `description` fields tidied.

## [0.6.5], 2026-07-18

### Added
- **`COPY`/`ADD` expand `*`, `?` and `[…]` globs against the build context** (Docker parity, verified
  against `docker build`): `COPY *.txt /app/`, `COPY src/* /app/`, `COPY [ab].conf /etc/` now copy each
  match into the destination directory; an unmatched glob is a clear error. Previously a glob source was
  taken literally and failed with "No such file". (A build-context *symlink* matched by a glob is still
  resolved/confined rather than preserved verbatim, kern's stricter no-leak copy behaviour.)

### Changed
- **Resource-profile keys are now spelled exactly like their CLI flags (BREAKING, see Rejected below).**
  `[[vcpu]]`: `vcpus` → `cpus` (CPU-time quota), `cpus` → `cpuset` (core pinning), `priority` → `nice`;
  `[[cpu]]`: `vcpus` → `cores`. The field in a profile now matches the flag you'd pass 1:1, removing a
  config-vs-flag inversion footgun. A `kern.toml` written for ≤ 0.6.4 must rename these keys (the old
  names are refused with a pointer, not silently reinterpreted, see **Rejected**).
- **`--memory` now warns, once and clearly, when the kernel can't enforce it.** On kernels that don't
  delegate the cgroup v2 `memory` controller, Microsoft's default WSL2 kernel, or Raspberry Pi OS
  without `cgroup_enable=memory`, a `memory.max` write is accepted but never bites, so the box would
  silently run uncapped. kern now detects the missing controller (env-independent) and prints an
  actionable heads-up (how to enable it on WSL, and that Docker/Podman hit the same limit there),
  instead of implying the cap is in force. The box still runs and stays fully isolated (namespaces +
  seccomp are unaffected); only the RAM cap is skipped. No change on a normal host, where the cap is
  enforced as before.

### Fixed
- **Pod holder no longer hangs a piped `compose up` / `pod create`.** The `__pod-holder` daemon inherited
  the caller's stderr and, being long-lived, held it open for the pod's whole life, so `kern compose up
  2>&1 | …`, `$(kern pod create …)`, or a CI log pipe never saw EOF and appeared to hang. The holder now
  redirects stdout + stderr to `/dev/null` once it prints `pod-ready`, and the parent's readiness wait is
  bounded (a wedged holder can't hang `pod create`).
- **`kern push` packs an owner-safe tar on a BusyBox host.** GNU tar takes `--owner=0`/`--group=0`;
  BusyBox tar rejects them, so pushing from Alpine or WSL errored. kern now detects the tar flavour and
  packs root-owned layers either way.
- **`kern box` now works out-of-the-box INSIDE a Docker/Podman container (CI runners).** The box
  overlay scratch defaults to `/run/user/<uid>`/`/tmp`, which inside a container sit on the
  container's own overlayfs, and the kernel rejects a nested-overlay upperdir with a bare
  `EINVAL`. kern now probes the scratch candidates and skips any that live on overlayfs, falling
  back to `/dev/shm` (a real tmpfs even in Docker; size-capped, announced on stderr). If every
  candidate is overlayfs the mount error is now actionable, "set `XDG_RUNTIME_DIR` to a tmpfs/disk
  path, or in Docker add `--tmpfs /run`", instead of `Invalid argument`.
- **`COPY <dir> <dest>/` now copies the directory's CONTENTS into `<dest>`, matching Docker** (verified
  against `docker build`), instead of nesting them under `<dest>/<dirname>/`. A directory source always
  has its contents copied (`COPY d /target/` → `/target/f1`, never `/target/d/f1`); a file copied into a
  directory still keeps its basename. Previously `COPY . /app/` (and any `COPY dir /existing-dir/`)
  wrongly nested the whole tree one level deep.
- **`COPY --chmod=<octal>` is now honoured for a context `COPY` and a `COPY --from`**, not only for
  `ADD <url>` / `COPY <<heredoc`. The mode is applied recursively to every copied file and directory
  (matching Docker); without `--chmod` the source mode is still preserved. Previously a
  `COPY --chmod=755 app /app` silently kept the source's mode (e.g. 0644). `--chmod` is now part of a
  cached layer's key, so two builds that differ only in `--chmod` no longer share a layer.
- **Windows `install.ps1`: the in-place update now actually runs** (was always falling back to a
  cache-wiping re-import). `wsl -- wslpath` eats backslashes in a Windows path, so the swap target
  resolved empty; the path is now passed with forward slashes.

### Security
- **Dangerous character devices are refused at bind time**, mirroring the resolver's fixed-identity deny
  on the pinned fd: raw memory (major 1: mem/kmem/port/kmsg), generic SCSI (major 21), and the stable
  misc majors `/dev/kvm` (10:232) and `/dev/net/tun` (10:200). If host root swaps a vetted char node for
  a dangerous one between the parent's resolve and the child's bind, the pinned-fd re-check still refuses
  it. Legitimate `vgpio:` devices (gpiochip, i2c, spi) are unaffected.

### Rejected (not aliased)
- **The pre-0.6.5 resource-profile key names are refused with a clear error, not silently reinterpreted.**
  Under the new scheme a bare `cpus` means the *quota* where it used to mean the *pinset*, so aliasing
  would change behaviour silently. Per the deprecation policy above, `[[vcpu]]` `vcpus`/`priority` and
  `[[cpu]]` `vcpus` are rejected with a message naming the replacement. Update `kern.toml`: `[[vcpu]]`
  `vcpus`→`cpus`, `cpus`→`cpuset`, `priority`→`nice`; `[[cpu]]` `vcpus`→`cores`.

## 0.6.4, 2026-07-15

### Added
- **`kern build` parses real-world Dockerfiles.** Comments inside `\` line-continuations, the `SHELL`
  instruction, BuildKit flags (`RUN --mount=…`, `FROM --platform=…`, `COPY/ADD --chown/--chmod/--link/
  --checksum`), the `# escape=` directive, a leading BOM, automatic `TARGETARCH`/`TARGETOS` build args,
  multi-name `ARG`, `FROM scratch`, and blank lines inside a continuation now parse instead of erroring.
- **`ADD <url>` and `COPY <<heredoc`.** `ADD` from an HTTPS URL (HTTPS-only, `--checksum` verified,
  `--chmod` honoured so a fetched binary is executable) and heredoc `COPY <<FILE … FILE` (the
  write-a-file-inline pattern) are supported, matching the common "download a static binary" recipe.
- **`.dockerignore` + `.kernignore`.** Build-context filtering with faithful Docker semantics:
  last-match-wins, `!` re-include, `*` non-recursive vs `**`, a filtered copy that does not follow
  symlinks out of the context, and a canonical context root (fail-closed, never fail-open).
- **Compose: real-world YAML.** Anchors/aliases/merge keys (`<<: *x`), the anchor forms real stacks use
  (Airflow/Sentry/Penpot), block scalars (`|`/`>`), multi-line & following-line flow, multi-line quoted
  scalars, same-file `extends`, `networks.*.aliases`, and mixed list/map `environment` salvage (which
  makes some engines panic). Real-world compose files now parse essentially 100%.

### Fixed
- **Windows `install.ps1` updates in place and keeps the image cache.** The updater no longer
  `wsl --unregister`s the distro (which wiped every cached image on each update); it swaps the binary
  in place and only falls back to a re-import, with a warning, if that is not possible.
- **`kern.toml` multi-line TOML arrays** (as `kern setup` writes them) now parse.
- The RAM-backed (tmpfs) vdisk scratch warning now says it is **EPHEMERAL**, not merely that it
  "counts against RAM".

## 0.6.3, 2026-07-13

### Added
- **Guided, "impossible to get wrong" profile forms in `kern top`.** Creating a vcpu/vgpio/vdisk
  profile now picks from what the host actually exposes instead of typing `/dev/` paths: detected
  devices are checkbox lists, absent kinds are read-only "none on this host" notes, `backend` is a
  single-select radio of the configured `[[gpio]]`/`[[cpu]]`/`[[disk]]` ids, and every typed field
  (numbers, sizes, names, the `extra` /dev path) is validated live with a three-state ✓ / "keep
  typing" indicator, a plain-language help line explains each field.
- **One validation rule shared by live-typing, save and load.** `config::field_state` is derived from
  the save authority (`profile_line` / `validate_profile_name`), so a value that types cleanly always
  saves and vice-versa, no per-field char-class list to drift, no dead-ends.
- **Whole-profile validation at save.** A `backend`/`extends` that references no configured
  `[[gpio]]`/`[[cpu]]`/`[[disk]]`/profile is refused before the write, with a clear message.

### Security
- **Capability-based `/dev` deny-list for vGPIO passthrough.** Refuses, by kernel IDENTITY
  (major/minor) where fixed and by name/path otherwise, every node that grants host control or raw
  memory/storage: block devices; mem/kmem/port/kmsg/oldmem; sg\*/nvme\* char storage controllers,
  bsg, dm/loop/btrfs control; VFIO (incl. the 6.x cdev); kvm/vhost\*/vbox\*; uinput/uhid/hidraw\*/
  hiddev\*; watchdog\*/mtd\*/nvram; net/tun, ppp; fuse/udmabuf; mei\*; dax\*; the privileged DRM
  `card*` modeset node; console/virtual-consoles/vcs\*/cuse. Render-only GPU (`renderD*`), rtc and
  serial ttys stay allowed. A specific USB device (`/dev/bus/usb/<bus>/<dev>`) is a scoped passthrough;
  the whole bus is refused.
- **fd-pinned device binds close the check→mount TOCTOU.** The runtime walks `/dev/…` one hop at a
  time (`openat(O_PATH|O_NOFOLLOW)`), pins the exact inode and binds from `/proc/self/fd`, so a name
  swapped at any depth between the resolver's check and the mount can't redirect it.
- **`extra` is a validated `/dev` path** (not free text); `i2c` entries are validated at save; the
  resolver still canonicalizes and re-checks every path under `/dev/` at launch.

### Fixed
- The `leds` picker drops netdev/keyboard-LED noise (`enp5s0-0::lan`, `input3::capslock`) and keeps
  real board LEDs. `midi` and `display` now actually detect devices (`display` offers the allowed
  `renderD*` GPU node) instead of always showing "none detected".
- `save_named_block` is fail-closed: it refuses to write a `kern.toml` that would not re-parse.

## 0.6.2, 2026-07-12

### Added
- **Nested boxes, `kern box --privileged`.** A full `kern box` can now run *inside* another
  (docker-in-docker style). The always-on seccomp filter blocks namespace + mount syscalls by
  default; `--privileged` re-allows **exactly five**: `unshare`/`setns`/`mount`/`umount2`/
  `pivot_root`, so a nested box can create its own namespaces and rootfs. Everything else stays
  blocked (kexec, modules, `bpf`, `io_uring`, keyring, `ptrace`, the new mount API), so it is
  materially stronger than a Docker `--privileged` container (which drops seccomp wholesale). It is
  **rootless-only**: honoured only when the box's root maps to an unprivileged host uid, decided by
  reading the effective `/proc/self/uid_map` after the namespace is set up (so a `--pod` box is
  judged by its holder's map, not the caller's euid), and refused outright as real root. Documented
  in [SECURITY.md](SECURITY.md); validated on x86_64 + aarch64 (incl. an Android-kernel board).
- **`kern build`: BuildKit `RUN` heredocs**: `RUN <<EOF … EOF` (the body runs as a shell script),
  `RUN <interp> <<EOF` (body fed on the command's stdin), `<<-EOF` tab-dedent, and `<<'EOF'` quoted
  delimiters. Unterminated / stacked / `COPY` heredocs error clearly (never a silent mis-parse).
- **`kern build`: `COPY --from=<external-image>`**: copy files straight out of an external image
  (`COPY --from=nginx:alpine /etc/nginx/nginx.conf /`), not just an earlier build stage. A build stage
  always wins over a same-named image; the image is pulled with the full hardening and its files are
  copied through the same confined (`openat2 RESOLVE_IN_ROOT`, no-follow, `..`-reject) path as a stage.
- **`kern compose`: Docker v3 `deploy.resources.limits`** (`memory`/`cpus`/`pids`) are now honoured as
  hard caps, where rootless Docker ignores them without cgroup v2+systemd, kern enforces them. A
  `limits:` block that maps nothing (a typo) warns instead of silently running uncapped.
- **`kern compose`: multi-line arrays** (`command = [\n …\n]`) in a native TOML stack now parse.

### Fixed
- **Multi-stage builds** failed at the first stage's `RUN` with a fork-safety refusal, the build's
  transcript recorder held a background thread, so `COPY --from`'s merged-view `fork()` saw a
  multi-threaded process. The recorder is now a child process; the build stays single-threaded.
- **`redis:latest` (Redis 8) and other io_uring-probing images** were SIGSYS-killed mid-startup and
  now run, see Security below.
- Clearer parse errors: an unterminated quoted compose value and an unterminated `RUN` heredoc now
  report the offending line instead of failing later with a confusing downstream error.
- Dropped a dead `KERN_ACCEPT_EULA` passthrough and its stale comments from the embedding SDK, the
  public build has no EULA gate (and never claimed one in docs).

### Security
- **seccomp: deny-but-degrade for probe-and-fallback syscalls.** `io_uring`, `userfaultfd`,
  `perf_event_open`, the keyring family and `syslog(2)` now return `ENOSYS` instead of a `SIGSYS`
  kill. They are still fully DENIED, the syscall never runs, so the isolation is identical, but
  software that merely probes an optional fast-path (e.g. Redis 8's io_uring) now falls back cleanly
  instead of dying. Real escape vectors (kexec, kernel modules, the mount API, `bpf`, `ptrace`, the
  nesting set) still hard-KILL. The two sets are asserted disjoint.

## 0.6.1, 2026-07-08

**docker-compose YAML compatibility**, **image registry `push`**, and a split-out, fuzzed compose
parser, each built dev → test → clean-code → security-audit (multi-agent, adversarially verified).

### Added
- **docker-compose YAML support**: `kern compose` now reads a `docker-compose.yml` (not only the
  native kern TOML stack): services, `image`/`build`, `command`/`entrypoint`, `environment`/
  `env_file`, `ports`, `volumes`, `depends_on` (incl. `condition: service_healthy` /
  `service_completed_successfully`), `healthcheck`, `secrets`, resource/cap/hardening keys. The
  parser is hand-rolled and **dependency-free**; the unmappable long tail **degrades with a warning**
  rather than silently mis-converting. Structural YAML we don't support (anchors/aliases →
  billion-laughs, tab indent, block scalars, multi-doc, tags) is **refused up front** with a precise
  line.
- **full `${VAR}` interpolation modifier set**: Docker's `${VAR:-default}` / `${VAR-default}`,
  `${VAR:+replace}` / `${VAR+replace}`, and `${VAR:?msg}` / `${VAR?msg}`, with the `:` meaning
  "treat empty like unset". Previously only `${VAR:-default}` (unset-only) was handled, so an
  `:+` replacement or an empty-value default silently produced the wrong string. Verified identical
  to `docker compose` on the same file.
- **nested `${VAR}` interpolation**: `${A:-${B:-default}}` now resolves the inner expression first,
  then the outer (Docker parity), via a balanced-brace scan; previously the whole thing passed through
  verbatim. Depth-capped (16) so an adversarial `${${${…}}}` can't drive unbounded recursion
  (fuzzed: 800k+ runs, terminates).
- **compose `tmpfs` with options**: Docker's `- /scratch:size=10M,mode=1770,uid=1000` was forwarded
  whole to `--tmpfs`, which took the entire option string as the size and **aborted the service**.
  Now the `size=` option is kept (`--tmpfs /scratch:10M`) and the rest is dropped with a warning.
- **compose `profiles`**: a `profiles:`-tagged service was warn-and-ignored but **still started**,
  a service meant to be OFF ran on a plain `up`. Now it is inactive unless one of its profiles is
  enabled via `COMPOSE_PROFILES` (Docker semantics; `*` enables all), and a `depends_on` toward a
  dropped profiled service is pruned rather than failing the topo sort.
- **`kern push`**: publish a cached image (rootfs + config) to an OCI registry v2 (schema-2
  manifest), `docker pull`-compatible. WRITE-scoped auth via `kern login`; all requests HTTPS-pinned.
  Verified end-to-end against a local `registry:2`: push → pull-back reproduces an identical rootfs
  (byte-for-byte file set) that boots a box.
- **`kern-compose` crate**: the compose parser is now its own CLI-free library crate, **fuzzed in
  isolation** (`fuzz/compose_yaml`, property: parse never panics + a parse is always
  topo-orderable-or-cycle). `toml_lite` (the shared quoted-string/bool/array/comment scanners) moved
  to `kern-common`.

### Security
- **Python binding: workload env goes via a private `--env-file`, not argv**: `Sandbox(env={...})`
  passed each value as `--env K=V` on the `kern box` argv, visible in `ps` / `/proc/<pid>/cmdline` to
  any local user (a credential leak for a component whose job is running untrusted code beside secrets).
  The env is now written to a `0600` file in the binding's own `0700` workspace and passed as
  `--env-file`; a newline/NUL in a key or value is rejected. Verified: env still reaches the box, the
  value no longer appears in any `kern`/box process argv.
- **`kern run --` honors end-of-options for profile tokens**: `kern run -- vcpu:heavy prog` peeled
  `vcpu:heavy` as a `[[vcpu]]` profile despite the `--`, replacing the pinned program with its own first
  argument (a `--`-contract violation, and divergent from the `box` path). `run` now preserves the
  leading `--` so the profile-peeler treats everything after it as the literal command. No escape (run
  is unsandboxed and execs argv directly), but the arg-parsing confusion is fixed.
- **seccomp: deny io_uring and the kernel keyring**: `io_uring_setup/enter/register` (a large,
  historically bug-rich async-I/O surface behind real container-escape CVEs) and
  `add_key/request_key/keyctl` are now in the always-on box denylist, matching Docker's default
  profile / gVisor. A sandboxed workload never needs them. A regression test pins the critical set.
- **box `--ssh`: disable TCP/tunnel forwarding**: the throwaway sshd now sets `AllowTcpForwarding no`,
  `PermitTunnel no`, `GatewayPorts no`, so a login can't port-forward out of the box (it already binds
  loopback-only inside the box netns, uses pubkey-only auth, and modern ciphers).
- **`--secret NAME=value` warning is honest about persistence**: the inline form is not only visible
  in `ps` (ephemeral) but recorded in the systemd journal on the cgroup-scope re-exec, where it
  outlives the box. The warning now says so and steers to `NAME=-` (stdin) or a file, which never hit
  argv.
- **push: refuse a cross-host upload redirect**: an untrusted registry answering the blob-upload
  `POST` with an absolute `Location:` on another host could exfiltrate the auth token / `kern login`
  credentials and the private layer to that host (CVE-2020-15157 class). The Location is now required
  to be the **same host and port** as the registry; an HTTPS→http downgrade, a loopback→internal-IP
  bounce (SSRF), or a same-host **different-port** bounce (a distinct internal service) is rejected.
- **compose warnings sanitize terminal control characters**: a warning interpolates untrusted compose
  text (service names, keys, values, paths); a hostile file could embed ANSI escapes / cursor moves /
  carriage returns in, say, an unknown field name and inject them into your terminal (spoofed or hidden
  output) when the parser warned about it. All warnings now escape control chars to `\xNN`
  (centralized in `warn`, so every call is covered). Build-context and bind-source `../` traversal were
  already refused; service names that look like flags (`--privileged`) were already rejected.
- **OCI: reject a tar link/dir header with a non-zero size (extractor-desync escape)**: a hostile
  layer could set a false `size` on a symlink/hardlink/directory header (which carry no data). The
  in-process vetter skipped `size` bytes trusting the lie, but a non-GNU `tar` (**BusyBox**, on the
  musl/edge boards kern targets) reads those bytes as the NEXT header, so an escaping symlink
  (`esc → /etc/shadow`) hidden in the "data" slipped past the escape guard and was extracted. The
  vetter now rejects a non-zero size on typeflags `1`/`2`/`5`, so it and every extractor agree on where
  each header ends. (**Critical**; found in a hacker-mode audit.)
- **OCI push: don't send credentials to a same-parent-domain sibling auth realm**: the push
  credential-leak fix covered the blob-upload redirect but not the auth challenge: `realm_host_trusted`
  trusted **any** subdomain of the registry's parent domain, so on shared hosting a hostile
  `registry.acme.com` could point its token realm at an attacker-controlled `attacker.acme.com` and
  harvest the long-lived write password. Trust is now the exact host or a **hardcoded** known
  registry↔auth pair (Docker Hub), never a generic parent-domain rule. (**High**.)
- **cpuset huge-range memory-exhaustion DoS**: `cpuset: 0-999999999` (accepted by the format check)
  expanded to a ~8 GB `Vec` before the per-index bound ran. The range is now clamped to `CPU_SETSIZE`
  before expansion. (**High**.)
- **compose parser panic-hardening**: an untrusted `healthcheck.interval` with a huge digit-run
  (`6000000000000000h`) no longer overflow-panics (debug) or wraps to a nonsense value (release);
  `parse_duration_secs` uses checked arithmetic and falls back to the box default. An anchor/alias is
  now refused in **every** position, value (`k: *a`), list-item (`- *a`), inline collection (`[*a]`,
  `{k: *a}`), and inline **map key** (`{&a k: v}`), where it previously reached the box as the literal
  `*a`. The guard is defined by construction (a `&`/`*` that starts a token outside quotes, not a
  hand-kept opener list) and a 50k-case property test proves it against an independent oracle. `${A${B}}`
  no longer leaks a stray `}`, and `${VAR}` inside a comment no longer raises a spurious unset-var warning.

### Fixed
- **`kern <cmd> --help` shows the help**: every subcommand (`box`, `run`, `pull`, `push`, `compose`,
  `exec`, …) rejected `--help`/`-h` as an "unknown flag" error; only the first-position `kern --help`
  worked. The universal `<tool> <cmd> --help` habit now prints the full reference instead of an error.
  A `--help` after `--` (part of the box/run command) is still passed through to the workload.
- **compose `entrypoint` + `command` composition**: a **shell-form** entrypoint (`entrypoint: /x`)
  now ignores `command` (Docker semantics) instead of appending it as shell positional params (which
  silently dropped the command); an **exec-form** (list) entrypoint still composes `entrypoint ++
  command`.
- **push: pushed layers are root-owned (0:0)**: the layer tar previously carried the invoking
  user's UID/GID (e.g. `1000`), so a pulled image had host-UID-owned files. Now normalized to `0:0`
  with `--owner=0 --group=0`, matching real Docker layers. Verified: push → pull-back yields
  root-owned files and stays `docker pull`-compatible.
- **compose list-form env host pass-through**: a `environment: [- API_KEY]` entry with no `=` is
  Docker's host pass-through (inherit `API_KEY` from the host env). The bare `API_KEY` was forwarded
  to the box's `--env K=V` parser, which rejected it and **aborted the whole service**. Now: present
  in the host → `API_KEY=<value>`; absent → omitted (Docker semantics), never a malformed `--env`.
- **compose long-form volumes**: a `volumes: [{type: bind, source: S, target: T, read_only: true}]`
  entry was forwarded to the box's `-v` as the raw `{…}` and **aborted the service**. Now reconstructed
  to `S:T[:ro]` (verified: the bind mounts and `read_only` is kernel-enforced). An anonymous/tmpfs
  long-form (no `source`) is warned-and-skipped, not forwarded as a malformed `-v`.
- **compose `healthcheck.timeout` / `start_period` durations**: these map to `--health-{timeout,
  start-period}`, which take integer **seconds**, but Docker writes them as durations (`30s`, `1m30s`,
  `0s`). The raw string was forwarded verbatim, so a standard `timeout: 30s` aborted the box
  (`usage: --health-start-period <seconds>`). They now convert through the same `parse_duration_secs`
  as `interval`; `start_period: 0s` (no grace) correctly reaches the box as `0`. (Found by an extreme
  vs-Docker test.)

### Changed
- `kern_common::toml_lite::strip_comment` is now **escape-aware** (a `\"` no longer closes a string,
  so a `#` after it stays in the value). This is a **bug-fix** bundled with the `toml_lite` move, it
  affects both the compose parser and the `kern.toml` profile loader, and only changes output for the
  rare line with an escaped quote before an unquoted-looking `#` (previously that value was truncated).

## 0.5.7, 2026-07-03

**The full 0.5 launch.** kern grows from a fast sandbox/OCI runtime into a **feature-complete
daemonless container + resource runtime**: the entire private feature set minus GPU/intelligence.
Every slice was built dev → test → clean-code → security-audit → perf; no stubs ship. 214 tests,
clippy/`cargo-deny`-clean, security-audited. (Image registry **push** and GPU slices are
deliberately out, see the README roadmap.)

### Added
- **Full volume system**: `-v src:dst[:ro]` bind mounts (symlink-safe), **named volumes**
  (`-v data:/work`, auto-created; `kern volume create/ls/rm/inspect/prune`) with an optional
  **per-volume quota** (`--size`, ext4-on-loop when privileged / honest fallback otherwise), and
  **network volumes** (`nfs://`/`smb://`/`sshfs://`) mounted rootless via FUSE/GVFS.
- **`--secret NAME=value` / `NAME=-` / `SRC[:NAME]`**: deliver a secret as `/run/secrets/NAME`
  (mode `0400`) on a RAM tmpfs; never in the image, argv (stdin form), or the workload's env.
- **`--ssh <port>` / `--ssh-key`**: a throwaway `sshd` inside the box (auto-generated ed25519 keypair
  or your pubkey), published on the host port, a ready-to-`ssh` workspace.
- **Networking & identity**: `--network host|none` (unifies `--net`), `--hostname`, **`--tun`**
  (`/dev/net/tun` for WireGuard/VPN), `--user UID[:GID]` (drops privilege, fails closed if unmapped).
- **`--pids-limit`, `--tmpfs PATH[:size]`**: fork-bomb cap and a fresh `nosuid,nodev` box tmpfs.
- **`--cap-add` / `--cap-drop CAP|ALL`**: configure capabilities on the always-dropped baseline.
- **Box operations**: **`kern cp <box>:<src> <dst>`** (symlink-confined via `openat2 RESOLVE_IN_ROOT`,
  CVE-2019-14271-safe), **`kern pause`/`unpause`** (cgroup freezer), **`kern attach`** (live output).
- **Advanced health**: `--health-retries` / `--health-start-period` / `--health-timeout`, and
  **`--health-action <restart|stop|none>`** (act when a box turns unhealthy, `restart` implies the
  on-failure policy; `stop` tears the box down).
- **`--timeout <sec>`**: auto-stop a box after N seconds (foreground, `-it`, and detached). The
  watchdog runs in the host namespace so it can reliably terminate the box's PID-namespace init.
- **`--env-file <file>`** (repeatable, `K=V` lines, `#` comments), layered under `--env` (explicit
  wins); **`--nice <n>`** (-20..19); **`--io-weight <n>`** (cgroup v2 `io.weight`, best-effort);
  **`--config <path>`** (a specific `kern.toml` for `vcpu:`/`vgpio:`/`vdisk:` profile tokens);
  **`--show-config`** (print the resolved configuration and exit, a dry run); **`-q`/`--quiet`**
  (suppress the foreground status panel).
- **`vdisk:` / `vgpio:` profiles**: a size-capped disk at `/vdisk/<name>` (tmpfs / ext4-loop, with
  `--iops`/`--bandwidth` → `io.max`) and per-peripheral GPIO/I2C/SPI/LED passthrough (deny-by-default).
- **Operations**: `kern doctor` (host preflight), `info`, `bench`, `history`, `recover`, `gc`,
  `kill`/`killall`, `completions <bash|zsh|fish>`; registry **`login`/`logout`** (private-image pulls,
  credentials `0600`, passed to `curl` off-argv); `config [edit|setup|probe|clear]`.
- **Any-registry image pulls**: auth now follows the standard registry-v2 `WWW-Authenticate`
  challenge (Bearer token or HTTP Basic), so `--image ghcr.io/…`, GitLab, quay, Harbor and
  self-hosted registries work, not just Docker Hub. Every request is TLS-pinned (`--proto =https`,
  https-only redirects, `--` URL terminator); credentials go to the token endpoint / registry
  off-argv via a `curl -K` STDIN config.
- **`--image` now honors the image's OCI config**: `Entrypoint`/`Cmd`/`Env`/`WorkingDir`/`User` are
  applied as defaults, so `kern box --image redis` runs the image's real entrypoint (like
  `docker run`), not a bare shell, with the image's env and workdir. Explicit flags always win:
  `-- CMD` replaces `Cmd` (kept under `Entrypoint`, docker-style), `--env`/`--env-file` override the
  image env, `--workdir`/`--user` override theirs. The (sha256-verified) config blob is cached
  alongside the rootfs so a cache hit reapplies it without re-pulling.
- **`--restart always` / `--restart unless-stopped`**: a persistent, reboot-surviving box **without a
  kern daemon**: kern writes a `systemd --user` unit (`~/.config/systemd/user/kern-<name>.service`),
  enables it, and turns on linger, so systemd, already running, restarts the box on any exit and
  brings it back at boot. Resource caps (`--memory`/`--memory-swap-max`/`--cpus`/`--pids-limit`) are
  enforced by the unit's own service cgroup. The box still shows in `kern ps`/`logs`/`exec`; `kern
  stop` (and `stop --all`) disable and remove the unit so it neither restarts nor returns at reboot.
  `--restart` also now takes a **policy** (`no` | `on-failure` | `always` | `unless-stopped`, Docker
  names); bare `--restart` stays `on-failure` (kern's in-process supervisor, unchanged). Command args
  are systemd-quoted and control-char-rejected so the unit can't be injected into.
- **`kern pod`**: shared-network **pods** for multi-service stacks: boxes in a pod reach each other
  **by name** on `127.0.0.1` (like a Kubernetes pod). `kern pod create <name>` spawns a holder that
  owns the pod's user+net namespace; `kern box <n> --pod <name>` joins it (its own mount/pid/uts/ipc
  ns stay private, only user+net are shared, so pod members are co-trusted) and is registered in a
  shared `/etc/hosts` mapping every member → `127.0.0.1`. Publish a pod service to the host with `-p`
  on its box. `kern pod ls` / `kern pod rm`. Daemonless; pod join is ~6 ms (a `setns`, cheaper than a
  fresh box) and a reused holder PID is rejected via its net-ns inode identity. **Outbound**: if
  `pasta`/`passt` is installed, `kern pod create` attaches it to the pod (rootless userspace NAT) so
  pod services also reach the internet, with DNS wired up automatically, no config; if it isn't, the
  pod is loopback-only (inter-service only) and says so. The dependency is **optional** (kern needs
  nothing extra to run, pasta only unlocks outbound). **`kern compose <file>` auto-pods**: a
  multi-service stack is put in a pod named after the file, so services reach each other **by name
  with zero config** (`--no-pod` opts out); `kern compose <file> down` stops the stack and removes the
  pod. `compose up` of a 2-service stack (pod + NAT + both boxes) is ~38 ms.
- **`kern build`**: build a local image from a **Dockerfile subset**, daemonless
  (curl/tar/cp): `kern build -t <name> [-f Dockerfile] [--build-arg K=V] [<context>]`. `RUN` executes
  inside a real `kern box` (host net, full userns/seccomp/cap isolation); `COPY`/`ADD` copy from the
  context; `ENV`/`WORKDIR`/`USER`/`CMD`/`ENTRYPOINT`/`EXPOSE`/`ARG`/`LABEL` accumulate into the image
  config. Builds are **layered**: the base is a shared read-only overlay lower and only the *diff* is
  stored (KB, not a full base copy), so a build's time and disk are independent of the base size, and
  a rebuilt/derived image is prune-safe (the base is re-resolved by ref). Where unprivileged overlay
  isn't available it transparently falls back to a flat copy build (`KERN_BUILD_FLAT=1` forces it).
  The result lands in the image cache so `kern box --image <name>` runs it with **no pull** (it reuses
  the OCI-config sidecar).
  Supported instructions are honoured with Docker semantics (ENTRYPOINT resets the base CMD; RUN/CMD/
  ENTRYPOINT are left for the shell, only ARG/ENV substitute); unsupported ones (multi-stage,
  `VOLUME`/`HEALTHCHECK`/`ADD <url>`/`COPY --from`) are **rejected with a clear error**, never
  silently ignored. COPY/WORKDIR destinations are `..`- and symlink-escape-proof (can't write outside
  the image rootfs). Consecutive `RUN` steps are **batched into one box** (each still in its own
  `/bin/sh -c`, `&&`-chained for fail-fast + per-RUN cwd reset) and build boxes skip the transient
  systemd scope, so a 10-`RUN` build is ~25 ms instead of ~160 ms, and build time is independent of
  the base image size. Builds are **layer-cached** (Docker-style): every unit (a RUN batch, a COPY, a
  WORKDIR) is a content-addressed layer keyed by everything before it + its own inputs (a COPY folds
  in the copied file contents), so an unchanged rebuild reuses cached layers and re-runs nothing,
  and a code change reuses the expensive dependency layers before it. An unchanged rebuild is ~13 ms
  and the cache is shared across images.
- **`--cpuset-cpus <list>`** (on `box` and `run`), pin a box to specific CPUs (`0-3`, `0,2,4`).
  Applied via **`sched_setaffinity`** (the workload inherits the affinity across `exec`), so it
  **works rootless with no cgroup `cpuset` delegation**: which is frequently unavailable on a user
  session even when `cpu`/`memory` are. On hosts where the `cpuset` controller *is* delegated, the
  cgroup `cpuset.cpus` / systemd `AllowedCPUs` write also applies as the harder, unwidenable path.
  The list is structurally validated (`N` or `N-M`, `N<=M`, no empty tokens) so a typo can't
  silently yield an unpinned box and nothing arbitrary reaches the kernel file. (Cooperative for the
  trust model, a hostile workload could widen its own affinity; `--memory`/`--cpus` are the hard,
  cgroup-enforced governance.)
- **`--memory-swap-max <size>`** (on `box` and `run`), swap allowance, mapped 1:1 to cgroup v2
  `memory.swap.max` (a *separate* limit from `--memory`; default `0` = swap off). This is the
  honest v2-native knob, **not** Docker's combined mem+swap total. Accepts an explicit `0` (swap off).
- **`kern run --config <kern.toml>`**: a specific config for `run`'s profile tokens (`vcpu:`/…),
  matching `kern box --config` so the two verbs share one profile surface.
- **I/O limits are feedback-first**: a `--iops`/`--bandwidth`/`--io-weight` request that the host's
  cgroup `io` controller isn't delegated to enforce now prints a clear "not enforced" note instead of
  silently doing nothing.
- **`kern inspect <name> [--json]`**: full detail for one running box (pid/pid1, rootfs, command,
  uptime, ports, health, and live mem/cpu/tasks). Untrusted fields are escape-scrubbed.
- **`kern prune`**: garbage-collect the leftover log/health sidecars of boxes that are no longer
  running; reports what it reclaimed (or "nothing to prune"). Live boxes are never touched.
- **Frozen TOML box schema** ([docs/CONFIG.md](docs/CONFIG.md)), `[box.NAME]` tables mirror the
  full `kern box` CLI (was only `image`/`rootfs`/`command`/`depends_on`): `memory`/`cpus`/`cpuset`/
  `swap_max`/`pids_limit`/`io_weight`/`nice`/`timeout`, `workdir`/`read_only`/`uid_range`/
  `bind_rootfs`/`hostname`/`user`/`tmpfs`, `net`/`tun`/`ports`/`ssh`/`ssh_key`,
  `env`/`env_file`/`secrets`, `cap_add`/`cap_drop`, and the full
  `restart`/`timeout`/`health_*` supervision set. One rule, **TOML mirrors the CLI**: so the same
  table is what a future `--profile` will reuse; the key names and array-vs-table shape (including
  the remaining reserved keys for later slices) are frozen from 0.5.0. Unknown keys are still
  rejected with the offending line.

### Security
Each feature slice was adversarially audited; highlights:
- **seccomp x32-ABI kill**: on x86_64, x32 syscalls (which share the x86_64 arch token) are killed,
  closing the classic bypass where the x32 alias of a denied syscall slipped past a number-only denylist.
- **`kern cp` is symlink-confined**: the in-box path resolves under `openat2(RESOLVE_IN_ROOT |
  RESOLVE_NO_MAGICLINKS)` on `/proc/<pid1>/root`, so a hostile image can't redirect a copy to a host
  file (the CVE-2019-14271 class). Regular files only, size-capped.
- **`--user` fails closed**: if the requested uid can't be mapped, the box refuses to start rather
  than silently running as in-box root.
- **`--user` + `--cap-drop ALL` compose correctly**: the capability drop is now split around the
  user switch (drop the *bounding* set → `setgid`/`setuid` → clear the *effective* set), so the
  canonical hardened profile (`--user 1000 --cap-drop ALL --read-only …`, e.g. for running untrusted
  code) no longer fails with a spurious "gid isn't mapped" from `CAP_SETGID` being dropped too early.
- **In-box PTYs**: the box now mounts a private `devpts` at `/dev/pts` (+ a `/dev/ptmx`
  multiplexer, `nosuid,noexec,newinstance`), so programs *inside* the box can allocate a controlling
  terminal. Interactive `ssh` into an `--ssh` box (and `screen`/`tmux`/`script`) work instead of
  failing "PTY allocation request failed". (`kern box -it` was unaffected, it uses a host PTY.)
- **Box root is `nosuid,nodev`**; `--secret` never touches the image/argv/env; registry credentials
  are `0600` and passed to `curl` via stdin config, never `/proc/<pid>/cmdline`.
- **Device access is deny-by-default** and covered by an adversarial test: a box's `/dev` is a fresh
  tmpfs with only a safe allowlist (`null/zero/full/random/urandom`); a raw disk / `/dev/mem` is
  absent and a fabricated device node is inert (userns `SB_I_NODEV`). See SECURITY.md.

### Rejected (not aliased)
- **`--memory-swap`**: refused with an error pointing to `--memory-swap-max` (different meaning on
  cgroup v2; silently aliasing it would lie). Per the deprecation policy above.

### Fixed
- **Duplicate box names are refused.** Starting a box whose name is already held by a *running* box
  now errors (`a box named '<n>' is already running`) instead of silently stacking a second box that
  made `stop`/`logs`/`exec` ambiguous. A repeated `kern compose … up` no longer accumulates
  duplicate services. A stopped box's name is immediately reusable.
- **Pod teardown no longer leaks its NAT daemon.** `pasta`/`passt` re-execs into an ISA-optimised
  variant (`pasta.avx2`, …), so the identity check that guards against PID reuse never matched and
  the outbound daemon survived every `kern pod rm` / `kern compose … down`. It is now matched by
  process-name family and reliably reaped.
- **Concurrent `kern pod create <same-name>` can no longer orphan a holder.** The mkdir loser used to
  reclaim the winner's still-initialising pod directory and spawn a second namespace holder; it now
  detects the in-progress claim (with a bounded wait so a slow host can't race the marker) and backs
  off, so exactly one holder is ever created.
- **A `[[vcpu]]` `extends` cycle no longer crashes kern.** A `kern.toml` where a profile extends
  itself (directly or through a chain) sent `resolve_vcpu` into unbounded recursion and aborted the
  process with a stack overflow; cycles are now detected and reported (`[[vcpu]] 'extends' cycle: a
  -> b -> a`).
- **`KERN_CONFIG` is now honoured.** The documented `KERN_CONFIG` environment variable (an explicit
  `kern.toml` path, overridden only by `--config`) was ignored, the default location was always
  used. It now works, and a missing/malformed file named that way is a clear error, not a silent
  fallback.
- **`--secret NAME=value` now warns that the inline value is visible in `ps`.** The value sits in the
  process's argv, so for a detached box it stayed readable in `/proc/<pid>/cmdline` for the box's
  whole lifetime; the warning steers to the non-leaking forms (`NAME=-` stdin, or a `SRC:NAME` file),
  which were already leak-free.
- **`kern stats <name>...` now filters to the named boxes** (Docker-parity) instead of silently
  ignoring the argument and printing every box; a requested name that isn't running is reported.
- **A paused box now shows as `paused`** in `kern ps` (HEALTH) and `kern top` (STATUS), previously a
  frozen box (`kern pause`) looked identical to a running one, even though the freeze was real.
- **A `-p` host port already in use now fails fast with a clear error** ("cannot publish host port
  N: …, already in use") instead of the box printing "✔ started" while its forwarder silently
  failed to bind (its error was swallowed for detached boxes). The port is pre-flighted before the
  box starts.
- **`--memory` / `--cpus` now warn honestly when the host can't enforce them.** On a rootless host
  whose user slice lacks a delegated `memory`/`cpu` controller (e.g. some Raspberry Pi setups), the
  cap was silently ignored, the box looked capped but wasn't. kern now checks the *effective* limit
  up the whole cgroup tree (so it never false-warns on a host where the systemd scope is the real
  enforcer) and prints a one-line "not enforced" note only when nothing in the chain caps it.
- **A non-root `--user` now actually works in the default (overlay) box.** Previously any
  `--user <non-zero-uid>` failed with `execvp: Permission denied`: overlayfs presents the merged
  root's mode as the private upper dir's, which was `0700`, so a dropped, capability-less uid
  couldn't even traverse `/`. The box root is now `0755` (a normal root fs) when a non-root `--user`
  is requested, still private on the host (its `0700` parent scratch dir is unchanged), so only the
  in-box view changes. Default boxes (running as the box's root) are untouched. For a `--bind-rootfs`
  tree you still control the perms; the exec-failure hint now names the uid/rootfs cause instead of
  the misleading "command must exist … loader" message.

## 0.4.0, 2026-06-28

The resource-governor verb (`kern run`), tunable CPU/memory caps, interactive PTY, port
publishing, restart/health supervision, and a defense-in-depth hardening pass (least-privilege
capabilities, loopback-by-default ports, a `syslog` seccomp block) from an adversarial pentest.

### Added
- **`kern box` status panel**: a foreground box now prints an aligned, colour-coded posture summary
  (cmd · fs · net · seccomp/caps/userns guard · limits · mounts; `-it` adds an exit hint) with an
  **actionable warning block** for
  the deliberately-open choices (`--net`, `--bind-rootfs`), each with a one-line fix. Colour is
  semantic (green = isolated, yellow = open-but-chosen), the seccomp count is read live (never
  drifts), untrusted fields (image ref, command) are **stripped of terminal-escape sequences**
  before display (no ANSI/title/cursor spoofing), and it degrades cleanly: ASCII glyphs when the
  locale isn't UTF-8, width from
  `TIOCGWINSZ`/`$COLUMNS`, **plain when `NO_COLOR`** is set. Printed to **stderr only when stderr is
  a TTY**, so pipes, scripts and `kern logs` stay clean; a detached box prints a one-line
  `✔ started <name>` with the next-step commands instead.
- **Unified table styling**: `kern ps`/`stats`/`images`/`search` now share the panel's visual
  standard on a TTY: a **dim header**, **bold-cyan NAME**, **semantic colour** for status (green
  `healthy` / red `unhealthy` in `ps`, a green ✓ for an official image in `search`), and `ps`
  truncates a long `COMMAND` to the terminal width with a dynamically-sized `PORTS` column so the
  table never wraps. All of it is **gated to a TTY**: piped/`NO_COLOR` output stays plain and
  full-width for scripts, and column alignment is computed on the uncoloured cells.
- **`kern box … -p [ip:]host:box` (port publishing)**: reach a service inside an isolated box from
  the host. A rootless userspace TCP forwarder is forked **before** the sandbox `unshare` (so it
  stays in the host network namespace, binding the host port); per connection it forks a
  single-threaded connector that joins the box's user+net namespaces (as `kern exec` does) and
  connects to the box's `127.0.0.1:<box>`. The optional bind IP **defaults to `127.0.0.1`**
  (loopback-only); pass `-p 0.0.0.0:H:B` to expose on all interfaces (a warning is printed).
  Repeatable; foreground + detached; torn down when the box exits.
- **`kern box -d --restart`**: restart a detached box if it exits non-zero (on-failure policy),
  up to a cap (10) with a 1 s backoff so a box that crashes on every start eventually gives up.
  Each attempt runs in a fresh child (the sandbox `unshare` mutates its caller, so it can't be
  re-run in place).
- **`kern box -d --health-cmd <cmd> [--health-interval N]`**: a sidecar process probes the box
  (`/bin/sh -c <cmd>` via `kern exec`, exit 0 = healthy) every N seconds (default 30) and records
  `healthy`/`unhealthy` for `kern ps`. It follows `--restart`s (re-reads the box's PID 1 each round).
- **`kern ps` shows `HEALTH` and `PORTS` columns** (and the same fields in `--json`): the current
  health status and the published `-p` mappings (e.g. `8080->80, 127.0.0.1:443->443`). The `PORTS`
  column sizes to its widest value and, on a TTY, `COMMAND` is truncated to the terminal width so a
  long command never wraps the table (like `docker ps`); piped output prints the full command.
- **`kern box … -it` and `kern exec … -it` (interactive PTY)**: allocate a pseudo-terminal so a
  box (or a command exec'd into a running box) runs a real interactive shell/REPL: it gets a
  controlling tty (`isatty` true), the host terminal goes raw, the window size is copied in and
  `SIGWINCH` resizes are forwarded, and the exit code propagates. `box -it` is foreground only
  (rejects `-d`). The byte pump is single-threaded by design, the sandbox fork must run in a
  single-threaded process, so there's no fork-in-thread hazard. (`exec -it` shares the same
  PTY plumbing as `box -it` via a common `adopt_controlling_tty` helper.)
- **`kern run [--memory M] [--cpus N] [--] <cmd...>`**: the resource-governor verb: run a command
  under cgroup CPU/memory caps **without** a sandbox (no namespaces/seccomp). It `exec`s the command
  (no fork) so it's the leanest path, a transient capped cgroup + `exec`, and propagates the
  command's exit code. `--cpus` is clamped once to the host's physical CPU count (consistent across
  the systemd scope and the in-namespace cgroup).
- **`--memory`/`-m` and `--cpus` per box**: tunable resource caps (previously a fixed 512 MiB /
  uncapped CPU). `--memory 512m|1g|<bytes>` sets a hard memory ceiling (the box is OOM-killed at the
  limit); `--cpus 1.5` caps CPU to 1½ cores (K8s semantics, clamped to the host's CPU count). Both
  the transient systemd scope and the best-effort in-namespace cgroup honor them; the CPU cap is
  best-effort where the cgroup CPU controller isn't delegated (e.g. some Android kernels).

### Security (defense-in-depth, from an adversarial pentest of the box)
- **`-p` binds `127.0.0.1` by default** (was `0.0.0.0`), a published service is no longer
  accidentally exposed to the LAN. Use `-p 0.0.0.0:H:B` to bind all interfaces deliberately (a
  warning is printed when you do). `kern ps` now shows the bind address per mapping.
- **Least-privilege capabilities**: the box drops never-needed dangerous caps (SYS_MODULE,
  SYS_RAWIO, SYS_BOOT, SYS_TIME, SYSLOG, MAC_ADMIN/OVERRIDE, AUDIT_CONTROL/READ, WAKE_ALARM,
  PERFMON, BPF, SYS_PACCT) from its effective/permitted/inheritable **and** bounding sets just
  before exec, so neither the workload nor a setuid/file-cap binary can wield them. Workload caps
  (CHOWN, DAC_*, SETUID/SETGID, NET_BIND/RAW/ADMIN, SYS_CHROOT, MKNOD, …) are kept, `apk`/`apt`,
  `chown`, and privilege-drop still work. (These caps are namespaced, i.e. already grant no host
  power; this shrinks the surface against cap-gated kernel bugs.) Pentest confirmed the box blocks
  mount/pivot/setns/unshare (seccomp), device/kernel-memory access, the classic container escapes
  (core_pattern, cgroup release_agent CVE-2022-0492, sysrq), fork-bomb (pids cap), and cross-box
  FS/PID/net access.

### Fixed
- **A box's loopback (`lo`) is now brought up** in its isolated network namespace, so `127.0.0.1`
  works inside the box (a fresh net ns leaves `lo` DOWN). `--net` boxes keep the host's loopback.

### Changed
- **Release profile is now `opt-level = "z"` (size-optimised).** The new 0.4 features grew the
  binary; since kern's cold start is syscall-bound (`unshare`/`mount`/`exec`), not CPU-bound, size
  codegen shrinks it ~14% (musl x86_64 804 → **688 KB**, glibc **594 KB**) with **no** latency cost
 , measured a hair faster (better I-cache). There is no hot CPU path to slow down.

## 0.3.3, contextual hint for box-not-running errors

### Fixed
- **`stop`/`exec`/`logs` on a box that isn't running now show the right hint** ("run `kern ps` to
  see running boxes") instead of the generic sandbox-setup hint ("needs unprivileged user
  namespaces and a valid --rootfs directory"), which was misleading for a simple lookup miss. New
  `Error::NotRunning` variant separates a lookup miss from a sandbox-setup failure.

## 0.3.2, `kern stop` takes multiple names + `--all`

### Added
- **`kern stop <name>...`** now stops **every** name given (previously it stopped only the first and
  silently ignored the rest), and **`kern stop --all`** stops every running box. A requested name
  that isn't running is reported on stderr instead of being silently dropped.

## 0.3.1, `--uid-range` fallback hardening

### Fixed
- **`--uid-range` now degrades gracefully when `newuidmap`/`newgidmap` are present but fail at
  runtime** (the helper isn't setuid-root, or there's no matching `/etc/subgid` allocation,
  common on CI runners and minimal hosts). Previously this aborted the box; now, since the process
  is already in a fresh user namespace, it falls back to the safe single-uid map (box uid 0 →
  caller) with a clear notice, mirroring how an *absent* helper already degraded. A `box`
  therefore always starts, with or without a usable subordinate-id range. The single-uid map write
  is now shared by the default and the fallback paths.

## 0.3.0, Real sandbox execution

### Added
- **`kern box <name> (--image <ref>|--rootfs <dir>) [-- cmd...]` runs a command in a real
  sandbox**: a fresh user + PID + net + UTS + IPC + mount namespace (single-uid map, no host
  privilege gained), an overlay root `pivot_root`-ed in (writable by default; `--read-only`
  remounts it read-only), a private `/proc`, then `exec`. Exit code propagated. Defaults to
  `/bin/sh`.
- `kern-isolation`: `RealMounts` (the libc `MountOps` impl) + `run_in_sandbox`. The real path and
  the `--plan` recorder flow through the **same** `Rootfs` typestate, so the read-only-after-pivot
  ordering is compile-enforced for real execution too.
- **`kern box -d` (detached)** + **`kern ps [--json]`**: a detached box forks a supervisor that
  registers itself under `$XDG_RUNTIME_DIR/kern/instances/`; `kern ps` lists running boxes and
  **prunes dead entries on read**: observability with no daemon. Survives a corrupt registry
  file (skipped, not a crash).
- **OCI pull**: `kern pull <image>` and `kern box <name> --image <ref> -- <cmd>` download an OCI
  image (registry v2, anonymous Docker Hub auth, multi-arch manifest/index → this host's arch)
  via `curl` + GNU `tar`, extract layers and apply whiteouts (with the symlink-escape guard),
  into a local rootfs (cached for re-runs). Verified: `kern box web --image alpine` pulls Alpine
  and runs it sandboxed (read-only root, isolated net/UTS, uid 0-in-ns).
- **Pull hardening (adversarial images)**: each layer is vetted **before extraction** (absolute
  paths, `..` traversal, device nodes, 2 GiB decompression-bomb cap), then extracted into an
  **isolated staging dir** and merged with **no-follow** semantics, a symlink planted by an
  earlier layer cannot be traversed by a later layer's writes (cross-layer escape closed
  structurally). Whiteouts (incl. opaque dirs) are applied during the merge under the guard.
- **`kern compose <file>`**: a minimal TOML orchestrator (no external crate). `[box.NAME]` tables
  with `image`/`rootfs`, `command`, `depends_on`; boxes start detached in dependency order
  (cycles + unknown deps are reported). Track the stack with `kern ps`.
- **Writable boxes (overlayfs)**: a box defaults to a writable root, the image/rootfs is the
  read-only lower, a private upper takes writes (the image stays immutable, scratch is removed on
  exit). `--read-only` remounts that overlay read-only (incl. `/dev`), so the box has no writable
  surface. (Overlay is used for both modes; a bind remount-RO is denied on some kernels.)
- **`kern stop <name>`**: stop running box(es), SIGKILL the supervisor's process group (tears
  down the box's PID namespace), drop the registry entry, remove the writable scratch.
- **Observability (`kern top` / `kern stats` / `kern logs`)**: daemonless live + point-in-time
  views, read straight from each box's cgroup and a per-box log. `kern top` auto-refreshes
  (uptime, memory, CPU% from `cpu.stat` deltas); `kern stats [--json]` is a one-shot table/JSON of
  memory + cumulative CPU; `kern logs <name>` replays a detached box's captured stdout/stderr
  (the supervisor now tees stdio to `$XDG_RUNTIME_DIR/kern/logs/<name>-<pid>.log`, readable
  post-mortem). All three reuse the same registry, so they need no daemon and prune dead boxes.
- **Volumes (`-v src:dst[:ro]`, repeatable)**: bind a host directory or file into the box, the
  sanctioned way data crosses the boundary. Source fds are captured *before* pivot and bound in
  *after*, so the target always resolves inside the box; `:ro` is enforced (a remount-read-only
  bind). A writable volume stays writable even under a `--read-only` root.
- **`kern exec <name> [--env K=V] [--workdir <dir>] [-- cmd]`**: run a command inside an
  already-running box by joining its user → mount → ipc → uts → (net) → pid namespaces (then
  forking into the pid namespace). The exec'd process gets the box's seccomp filter for parity
  and the exit code is propagated. Must be the same user that started the box.
- **`--env K=V` / `-e` (repeatable) and `--workdir <dir>` / `-w`** for `kern box` (and `kern
  exec`): layer environment on top of the clean base env, and `chdir` into a working directory.
- **`--net` (opt-in networking)**: share the host network namespace so the box has outbound
  connectivity (the default stays isolated, loopback-only). The host's `/etc/resolv.conf` is
  copied into the box's writable layer so DNS resolves out of the box. Trade-off: `--net` means
  **no network isolation**: see SECURITY.md.
- **Prebuilt binaries + `install.sh`**: a release workflow builds static (musl) `linux-x86_64`
  and `linux-aarch64` binaries with SHA256SUMS on each version tag; `curl -fsSL
  https://getkern.dev/install.sh | sh` downloads the right one (checksum-verified), no Rust
  toolchain needed.
- **uid/gid range mapping**: when `newuidmap`/`newgidmap` and an `/etc/subuid`+`/etc/subgid`
  allocation are present, the box maps a full id range (box uid 0 → caller; box ids 1..N →
  subordinate ids) instead of a single uid, so `apt install` (which `chown`s to other uids) and
  daemons that drop to a non-root user (e.g. **Apache → `www-data`**) work. Falls back to the
  dependency-free single-uid map when the helpers/subids aren't available. No host privilege
  gained either way. Verified: real `apt install apache2` + `apache2` serving on Ubuntu in a box.

### Fixed
- **`cmd > /dev/null` now works inside a box.** The `/dev` tmpfs was mounted with the default
  sticky, world-writable mode (1777); with `fs.protected_regular` (≥1, default on most distros)
  an `O_CREAT` open of a device node the box doesn't own in a sticky world-writable directory is
  rejected with `EACCES`, breaking the near-universal redirect. `/dev` is now mounted `mode=755`
  (owned by the box's root), and device nodes are bound by their real host path *before* pivot
  (a post-pivot `/proc/self/fd` bind left them read-only). The hostile-`/dev`-symlink guard is
  preserved (a symlinked `/dev` is replaced with a real directory first; a normal `/dev` is
  untouched). Regression test added.
- **Concurrent boxes sharing one bind rootfs.** Several `--read-only` / `--rootfs` boxes started
  in parallel off the *same* rootfs raced on a `.old_root` put-old directory created/removed in
  that shared directory (and it couldn't be created on a read-only source). The pivot is now a
  **self-pivot** (`pivot_root(".", ".")` + `umount2(".", MNT_DETACH)`, the runc approach) that
  needs no put-old subdirectory, so nothing is written to the rootfs. 12 boxes sharing one bind
  rootfs now start 12/12 (was ~9/20); overlay boxes were already unaffected. Regression test added.
- **`-v` volume targets are resolved symlink-safe.** A volume's in-box target path is now resolved
  with an `openat(O_NOFOLLOW)` component walk confined to the new root, so a hostile image that
  ships a symlink at the mount point can't redirect the bind (and a host write) through it, the
  bind is refused instead. Regression test added.
- **Unknown `box`/`exec` flags are now rejected, not ignored.** A typo'd `--read-only` no longer
  silently runs a *writable* box, an unrecognized flag is a usage error.
- Audit hardening: closed an fd leak on an error path in the volume-target walk; reject a NUL byte
  in a `-v` target early; documented that `--net` also exposes host abstract-namespace UNIX sockets.

### Security (audit hardening)
- **pull integrity**: every blob is verified to hash to its `sha256:` digest before use
  (compromised/MITM registry + corrupt-download defense, beyond TLS).
- **registry**: a box's kernel start-time is recorded and checked, so a reused pid can't be
  mistaken for a live box (no false "running", no `stop` signalling an unrelated process).
- **seccomp**: denylist extended to the new mount API (`open_tree`/`move_mount`/`fsopen`/
  `fsconfig`/`fsmount`) and `unshare` (nested-userns escape) and `process_vm_readv`/`writev`
  (ptrace-equivalents), closing gaps that contradicted the "blocks further mount/namespace
  manipulation" claim.
- **pull**: hardlink entries whose target escapes the rootfs (absolute / `..`) are now rejected.
- **image cache**: gated on a completion sentinel (no more "non-empty dir = valid" → no partial/
  poisoned rootfs); cache dir created mode `0700` under `~/.cache` (not a predictable `/tmp` path).
- **registry**: a pid that now belongs to another user (`EPERM`) is treated as gone, `kern stop`
  won't signal an unrelated process group via pid reuse.
- **sandbox**: a failed old-root unmount is now fatal (a leftover `/.old_root` would expose the
  host filesystem) rather than best-effort.

### Security
- **`search`/`images` strip terminal escapes from untrusted registry data.** A Docker Hub repo
  description/name (anyone can publish one) or a crafted cached image ref could carry ANSI/OSC
  escape sequences; printed raw they spoof the terminal (cursor/title/clipboard). The table path now
  strips control chars and `--json` escapes them as `\u00XX` (valid JSON, no injection).
- **`kern search` HTTP is bounded + HTTPS-pinned**: the Hub request caps the response
  (`--max-filesize`, no OOM from a huge body), pins the request **and every redirect** to HTTPS
  (`--proto`/`--proto-redir`, no `file://`/SSRF via a hostile redirect), and limits redirect count.
- **`kern top` restores the terminal on a fatal signal**: `SIGHUP` (SSH disconnect) / `SIGTERM` /
  `SIGINT`/`SIGQUIT` while the TUI is in raw mode + the alternate screen now runs an
  async-signal-safe handler (`tcsetattr` + reset escapes) before re-raising, no stranded terminal.
- **Full namespace isolation**: user + PID + **network** (only loopback) + **UTS** (hostname =
  box name) + **IPC** + mount. Verified live: host sees 528 procs, the box sees ~3; only `lo`
  in the box's network namespace.
- **Always-on seccomp denylist**: kexec, kernel-module (un)loading, ptrace, reboot, swap,
  further mount/`pivot_root`/`setns` are killed with SIGSYS; a wrong-arch syscall is killed too.
- **cgroup caps (memory 512 MiB + tasks 512)**: when a systemd user manager is present, `kern
  box` re-execs inside a transient `systemd-run --user --scope` (verified: `TasksMax=512`,
  `MemoryMax=512M`, **`MemorySwapMax=0`** so the memory cap is a HARD total, a workload over
  512 MiB is OOM-killed instead of silently swapping); otherwise a best-effort cgroup v2 path
  applies where delegated, degrading gracefully (no orphan cgroup) elsewhere.

- **`examples/`**: runnable, live-verified use-cases, run an image, throwaway shell, untrusted
  code (read-only + seccomp + no net), detached services + `ps`/`stop`, a `compose` stack, and
  per-task fan-out.

- **Minimal `/dev`**: a box gets `null`/`zero`/`full`/`random`/`urandom` on a fresh **tmpfs**
  `/dev` set up **after** pivot, host device fds are captured pre-pivot and bound in via
  `/proc/self/fd`, so a hostile rootfs with a symlinked `/dev` can't redirect writes to the host,
  and the image's own `/dev` is never mutated. (No `/dev/tty`, avoids TIOCSTI injection; never
  `/dev/mem`/disks; userns can't `mknod`.)
- **pull**: a non-`sha256:` (unverifiable) digest is now **refused**, not silently accepted.
- **Clean environment**: the box starts with a small, sane env (`PATH`/`HOME`/`TERM`/`HOSTNAME`),
  not the host's, host secrets/tokens and kern internals (`KERN_SCOPE`) no longer leak in.
- **Concurrent pulls** of the same image are serialized with a per-image `flock` (with a
  double-checked sentinel), so parallel `kern box --image X` from a cold cache all succeed.

- **`BENCHMARKS.md`**: measured multi-runtime comparison (vs Docker / runc / bubblewrap), bare
  box ~3 ms, full `--image` ~7 ms, ~100× faster to start than `docker run` (and ~267× under
  parallelism), footprint, and resource-cap results.

### Added
- **`kern --help` now shows the `KERN` wordmark + colour**: a cyan/bold ASCII logo, bold section
  headers, cyan verbs, dim notes. Colour is emitted **only** when stdout is a TTY and `NO_COLOR`
  is unset, so piped output and scripts (and `kern --version`) stay plain. Dependency-free (a tiny
  `ui` module of raw escape strings); no EULA/demo banners, the public build stays clean.
- **`kern top` is now an interactive task-manager TUI** (when stdout is a TTY), an htop-style
  full-screen view with tabs (**Overview** · **Boxes**), live refresh, and keyboard nav (`Tab`/
  `←→`/`1`/`2` to switch, `q`/`Esc`/`Ctrl-C` to quit). Boxes-only (the public build has no GPU/
  vCPU to monitor). Pure `libc` termios + ANSI, **no curses/ratatui dependency**; the terminal is
  put in raw mode + the alternate screen and **restored on drop** (clean teardown even on Ctrl-C
  or panic). Piped/non-TTY falls back to a one-shot table. New `registry::tasks` reads the box
  cgroup `pids.current` for the **PIDS** column.
- **`kern search <query>`**: search Docker Hub for images (name, stars, official flag,
  description), the same registry `kern pull` uses. Backed by a new `kern-oci` HTTP/JSON path
  (`net` + `json` modules, shared with `pull` so there's one curl wrapper and one string-scanner).
- **`kern images [--json]`**: list the images pulled into the local cache, by their *original*
  ref (recovered from the pull sentinel), with on-disk size and age, like `docker images`.

### Changed
- **`--bind-rootfs`, a fast path for kernels with a slow overlayfs.** The default still overlays
  the rootfs (immutable, shareable, sub-millisecond on normal kernels). But some Android-derived
  kernels mount an overlay in ~31 ms (vs ~8 ms for a bind; the syscall is 104 µs on x86). On an
  Arduino UNO Q this made the default box (34 ms) lose to bubblewrap (15 ms); with `--bind-rootfs`
  kern binds the rootfs directly and starts in **9.9 ms, faster than bubblewrap**: while still
  doing more (seccomp, real `/dev`, lifecycle). Trade-off (hence opt-in, `--rootfs`-only, not with
  `--read-only`): the source is mutable and shared. A hidden `KERN_TIMING=1` prints per-phase
  startup µs and found the bottleneck. Bind mode is hardened to stay within that trade-off and not
  exceed it: the root bind is **non-recursive** (`MS_BIND`, not `MS_REC`) so host filesystems
  mounted *under* the rootfs dir aren't leaked into the box, and bind mode does **not** inject
  `/etc/resolv.conf` (the overlay path writes it to a private scratch; a host-side write into the
  user's rootfs could follow a symlink and clobber a file outside it, so a bind-mode box uses the
  resolv.conf its rootfs already ships).
- **Single-uid map is now the default; `--uid-range` is opt-in** (faster *and* more isolated).
  Previously every box with an `/etc/subuid` allocation auto-mapped a 65k sub-uid range, which
  costs two `newuidmap`/`newgidmap` subprocesses at start and enlarges the namespace's id surface.
  The default is now the dependency-free single-uid map (box uid 0 = caller, nothing else), a bare
  box cold-starts in **~2.5 ms (beats bubblewrap, ties rootless runc, ~145× faster than Docker)**.
  Pass `--uid-range` for workloads that need multiple uids inside the box (`apt`/`dpkg`, daemons
  that drop to `www-data`); if requested but unavailable it warns and falls back to single-uid.
- **Security: id-map helpers resolved by trusted absolute path only.** `newuidmap`/`newgidmap` are
  now located in `/usr/bin`,`/bin`,`/usr/sbin`,`/sbin` instead of via `$PATH`, so a writable PATH
  entry (e.g. `~/.local/bin`) can't shadow the system binary and feed a bogus uid mapping. The
  `/etc/subuid` lookup matches the login **name** first (numeric-uid row only as fallback, as
  shadow does), and the helper handshake is EINTR-safe and **fails closed**: any error in helper
  resolution, subuid parsing, the pid handshake, or the final verdict aborts rather than running a
  partially-mapped box. No privilege can be gained either way (the setuid helpers re-validate the
  allocation in the kernel).
- **Pull progress feedback**: `kern pull` and a cold `kern box --image` now report each step to
  stderr, `resolving`, layer count, per-layer `K/N` with a **live download progress bar** (curl
  `-#`), `verifying + extracting`, and a `✓ pulled` summary, so a download never looks frozen. A
  warm cache stays silent (no noise). The `box --image` path also prints a one-time
  "not cached, pulling once" notice so it's clear why there's a wait.
- **Compose progress**: `kern compose` now reports the resolved start order up front
  (`→ bringing up N box(es) in order: a → b → c`) and a `[i/N] starting '<name>'  <source> (after …)`
  line per box, so a multi-box stack (and any cold image pulls inside it) shows live progress
  instead of going quiet until the final summary.
- **Clearer "command not found" in a box**: a failed `execvp` now reports
  `cannot start '<cmd>' in box: <err>` with a hint (use a full path; a dynamically-linked binary
  needs its loader/libraries in the rootfs) instead of a bare `execvp failed: … (os error 2)`.
  Applies to both foreground (inline) and detached boxes (visible via `kern logs <name>`).
- **Truthful detached start (`kern box -d`)**: a readiness pipe (`FD_CLOEXEC` write end, closed by
  the box's successful `execvp` → EOF) makes the launcher print `started` only once the box is
  actually up, and ``box '<name>' exited before starting, run `kern logs <name>` `` (exit 1) if it
  dies first. No sleep, no poll, the only added latency is the box's real start time (~4 ms; ~7 ms
  with the systemd cgroup scope), the same a foreground box already pays. `compose` inherits this:
  a dependent box now starts only after its dependency is genuinely running.
- **Overlay scratch on tmpfs**: the writable upper/work layer now lives under `$XDG_RUNTIME_DIR`
  (tmpfs) instead of the disk cache, `box --image` cold-start dropped from ~25-32 ms to ~6 ms,
  and the writable layer is ephemeral and counts against the box's memory cap.
- `MountOps` is now fallible (`Result`), so the recorder and the real syscall path share one
  ordered, error-checked op log. First real dependency: `libc` (the single kernel boundary).
- Missing required arguments now produce a clear `usage:` error instead of a misleading
  "not implemented" (e.g. `kern pull` with no image, `kern box NAME` with no rootfs/image).

### Not yet (roadmap)
- `kern run` resource quotas (CPU/memory), tunable `--memory`/`--cpus`, interactive PTY (`-it`),
  port publishing (`-p`), image build, and GPU slices. See the README roadmap.

## 0.2.0, Sandbox hardening

### Added
- `kern-isolation`: **mount-ordering typestate** `Rootfs<Mounted>` → `create_old_root()` →
  `Rootfs<OldRootReady>` → `into_readonly()`. Remounting the root read-only before pivoting in
  is now a **compile error**, not a sandbox-escape bug.
- `kern-isolation`: `MountMode` enum (overlay / bind / tmpfs) driving the initial root mount.
- `kern-cli`: `SandboxCtx` step sequence wired to the typestate.
- `kern box <name> --plan`, print the ordered isolation sequence (mount → pivot → read-only).
  Privilege-free; uses the validated `BoxName` newtype (rejects path traversal).

### Changed
- `overlay_ro_sequence` is now driven through the typestate; the characterization golden is
  **byte-identical** (the refactor changed no observable behaviour).

### Security
- `BoxName` hardened to a conservative charset (`[A-Za-z0-9_.-]`, no leading `-` or `.`, max 64
  chars). Blocks path traversal, NUL, whitespace, control characters, shell metacharacters and
  argument-injection by construction. Fuzzed with 40+ hostile inputs: zero crashes/panics.

## 0.1.0, Foundation

### Added
- Workspace foundation: `kern-cli` (binary `kern`), `kern-common`, `kern-oci`, `kern-isolation`.
- Module-based CLI (no `include!()`): command parsing/dispatch + `--no-gpu` global flag.
- `kern-oci`: whiteout path-safety helper with a symlink-escape regression test.
- `kern-isolation`: the `MountOps` characterization seam (refactor-safety net).
- Project docs: README, SECURITY, ARCHITECTURE, CONTRIBUTING, CLA, CODE_OF_CONDUCT.
- CI: build + test + clippy + fmt + cargo-audit + cargo-deny on x86 (skip-graceful for HW).

[0.6.31]: https://github.com/getkern/kern/releases/tag/v0.6.31
[0.6.30]: https://github.com/getkern/kern/releases/tag/v0.6.30
[0.6.29]: https://github.com/getkern/kern/releases/tag/v0.6.29
[0.6.28]: https://github.com/getkern/kern/releases/tag/v0.6.28
[0.6.27]: https://github.com/getkern/kern/releases/tag/v0.6.27
[0.6.26]: https://github.com/getkern/kern/releases/tag/v0.6.26
[0.6.25]: https://github.com/getkern/kern/releases/tag/v0.6.25
[0.6.24]: https://github.com/getkern/kern/releases/tag/v0.6.24
[0.6.23]: https://github.com/getkern/kern/releases/tag/v0.6.23
[0.6.22]: https://github.com/getkern/kern/releases/tag/v0.6.22
[0.6.21]: https://github.com/getkern/kern/releases/tag/v0.6.21
[0.6.20]: https://github.com/getkern/kern/releases/tag/v0.6.20
[0.6.19]: https://github.com/getkern/kern/releases/tag/v0.6.19
[0.6.18]: https://github.com/getkern/kern/releases/tag/v0.6.18
[0.6.15]: https://github.com/getkern/kern/releases/tag/v0.6.15
[0.6.14]: https://github.com/getkern/kern/releases/tag/v0.6.14
[0.6.13]: https://github.com/getkern/kern/releases/tag/v0.6.13
[0.6.12]: https://github.com/getkern/kern/releases/tag/v0.6.12
[0.6.11]: https://github.com/getkern/kern/releases/tag/v0.6.11
[0.6.10]: https://github.com/getkern/kern/releases/tag/v0.6.10
[0.6.9]: https://github.com/getkern/kern/releases/tag/v0.6.9
[0.6.8]: https://github.com/getkern/kern/releases/tag/v0.6.8
[0.6.7]: https://github.com/getkern/kern/releases/tag/v0.6.7
[0.6.5]: https://github.com/getkern/kern/releases/tag/v0.6.5
