# Changelog

**CLI stability.** Since v0.7.0 the verbs, their flags and the `--json` shapes change incompatibly
only on a minor bump, never on a patch, and only after a deprecation entry here one release earlier.
`--json` is additive, so consumers must ignore unknown fields. A `cli_surface_is_frozen` test fails
the build on any undocumented change. Full detail for any entry is in the git history.

**Sandbox result stability.** In kern-sandbox (Python, Node and `kern-mcp`), the `fault.type` and
`exit_code` an outcome reports change only to correct one that was reported wrong, and such a change
leads that release's entry, naming the outcomes it moves. kern-sandbox 0.2.45 is the example:
`os._exit(N)` in a prewarmed box or a kernel stopped reading as `killed`, and a kernel timeout went from
-1 to 137. New `fault.type` values are additive, so code must treat a value it does not know as a fault
of the sandbox. A test fails the build when the set of values changes in one binding and not the other.

**Compose surface stability.** A compose key kern reads keeps its meaning: it changes only to correct
a mapping that was wrong, and such a change leads that release's entry, naming the key. Reading a key
kern ignores today is additive. A key kern does not read is never silent, with two deliberate
exceptions: `x-*` extension fields, and the keys Docker itself does not act on under Linux
(`cpu_count`, `cpu_percent`, `cpus_shares`, `isolation`). A test carries the frozen list of keys and
both halves of that rule, so removing one from the parser fails the build by name.

## v0.31.0 - 2026-10-10

**`kern run --memory` REFUSES where it used to warn and run, and this one leads because it can stop
a command that worked yesterday.** The verb governs resources and nothing else, and it was accepting
a cap it could not apply: it printed "the command runs UNCAPPED" and executed the command anyway. A
test doing `kern run --memory 16m -- sh -c 's=x; while :; do s=$s$s; done'` - a doubler whose only
brake is the cap - then reached 25.5 GB on a maintainer's desktop and the kernel's OOM killer took
the largest process on the machine, which was the editor, with every session in it. It now refuses,
and only when `--memory` was named and no ceiling at or below it can be PROVEN: an ancestor cgroup
that really caps is read and accepted, a container with a cgroup namespace is read through its own
`/sys/fs/cgroup/memory.max`, and `--cpus` alone never refuses, because an unenforced share makes a
command slow and slow does not take a host down. `KERN_ALLOW_UNCAPPED=1` runs anyway; a bare
`kern run` with no cap flags is unchanged. If a host of yours starts refusing, `kern doctor` names
the local change that would make a cap bind there, and the refusal names the cause it measured.

- A cgroup kern did not write counts as proof of a `--memory` only when its SWAP is bounded too.
  kern's own cap writes `memory.swap.max = 0`, so an ancestor accepted in its place has to be at
  least as strong, and systemd's default `memory.swap.max=max` is not: an independent reviewer
  measured a scope with `MemoryMax=48M` accepted as proof of a 64 MiB request, and the command
  allocated 100 MB and exited 0 on 48 MiB of RAM plus the host's swap. A level now states
  `memory.max` plus the swap it opens, unbounded swap makes it state nothing at all, and a host with
  no swap keeps `memory.max` as the whole ceiling. `kern inspect`'s `memory_max_enforced` reads the
  same rule, so the surface that reports and the one that refuses cannot disagree about one chain;
  a box with its own cgroup is unaffected, because kern writes the swap limit itself.
- Caps now bind on a host whose `$XDG_RUNTIME_DIR/systemd/private` refuses connections while the
  user manager is alive. kern asked that socket alone whether `systemd-run --user` could reach the
  manager; where it answers ECONNREFUSED but the session bus is live and `systemd --user` is
  running, kern concluded there was no manager, declined both cap paths, and applied no cap at all -
  silently, every time, on an ordinary delegated desktop. The probe now accepts a second door, the
  session bus TOGETHER with the manager's own process read from the cgroup systemd puts it in; the
  bus alone is still refused, because a `dbus-launch` session with no manager would send kern into a
  `systemd-run` that fails after it has replaced itself. `kern doctor` inherited the fix: it had been
  showing a green "caps enforced" row on a host where `kern run --memory` enforced nothing.
- kern no longer calls a command UNCAPPED when the ceiling is proven. Inside a container with a
  cgroup namespace and a real `memory.max`, `kern run --memory 64m` correctly ran and then said it
  was running uncapped: "kern wrote no cgroup of its own" is not the same fact as "nothing caps this
  command", and the two sentences disagreed about one command.
- `kern exec -u <user>[:<group>]` runs the command as that account of the box, a name or a number,
  where `kern exec` could only be box root. The name is looked up in the box's own `/etc/passwd` and
  `/etc/group` as they are when the command runs, so an account created inside the box is found, and
  the group and supplementary groups follow the rules of `kern box --user`. HOME becomes that user's
  home unless the image or `-e` set one. An id the box does not map is refused with what the box does
  map: on a single-uid box, `-u 1000` used to fail as "could not drop to the box's own user", exit 126.
- `kern exec -u` no longer fails on the capability switch in a box started with `--cap-drop ALL`.
  The exec dropped every capability before switching identity, `CAP_SETUID` included, and failed
  closed with "could not drop to the box's own user"; `kern compose exec` of a service with
  `cap_drop: [ALL]` and a `user:` failed the same way. The command still ends with every capability
  set empty. ONE CONDITION REMAINS, and a field report measured it because this entry did not say
  so: `--cap-drop ALL` with no `--cap-add` also drops the box's default sub-uid range (the range is
  there so a box can own files as another uid, which no capability makes possible anyway), so a
  non-root account is not in the map and `kern exec -u nobody` is refused. Add `--uid-range` to such
  a box and it works. The refusal now names that cause instead of naming `--no-uid-range` and
  `/etc/subuid`, neither of which was the reader's, and `kern box --help` states the interaction on
  both flags.
- `kern rm` no longer sends the reader to a listing that contradicts it. A field report removed a
  kept box's layer from outside, so there was no layer to remove, but the transient exit record was
  still in the registry and `kern ps -a` listed that name in its exited section; the refusal said "no
  kept box 'x'" and pointed at `kern ps -a` for the list. Both sentences were true and together they
  said the opposite. It now names the section the row is in and the verb that clears it, and a name
  in no section at all keeps the shorter sentence.
- A detached box that cannot enforce its caps says so on the terminal, not only in its log. A
  detached box's stderr IS its log, so `kern box -d --memory 64m` on a host with no cgroup delegation
  printed `✔ started 'x' [pid N, detached]` and nothing else, while both notices - "`--memory`
  accepted but NOT enforced here" and "the box runs UNCAPPED, with no OOM / fork-bomb backstop" -
  went to a file the operator had not been told to read. The same box in the foreground printed them
  on the terminal, so one flag decided whether kern reported its own uncapped state. A field report
  measured it (`memory.max: max` with `--memory 64m` in force nowhere, the workload allocating 200 MB
  under a 64 MiB request); it is reproduced in this repo's own tests. The notices now go to both, and
  the log keeps its copy. `--allow-uncapped` and `KERN_QUIET` silence them exactly as before -
  the second copy is the same sentence, gated at the same place - and `--require-limits` still
  refuses to start, where the notice appears once, inside the log the error quotes, rather than
  twice. That refusal now also names the measured cause (which `XDG_RUNTIME_DIR`, or which missing
  manager) instead of a remedy chosen for a host it may not be on.
- `kern inspect --json` no longer reports `"memory_max_enforced": null` for a box the kernel does
  cap. The field read `memory.max` at ONE level, reached through the gate that decides which cgroups
  kern may `rmdir` or `cgroup.kill`, so it had two blind spots: a box kern could not place in a
  cgroup of its own (the field report's case: `"memory_max": 67108864` next to `null`, where `null`
  is what `kern doctor` tells a reader means "nothing in force"), and an ANCESTOR's ceiling, which is
  the one the kernel enforces on a box whose own level says `max`. It now reads the chain the kernel
  reads, from the box's own cgroup whoever named it, pinned to the live PID 1. `kern inspect` prints
  `64M (in force: 256M)` where it used to print `64M (requested, NOT enforced here)` about a box held
  to 256M. `null` now means what `doctor` says it means.
- `kern images` says whether "no images cached yet" is the whole truth. A field report ran `rm -rf`
  over the cache to free space: the removal took everything it could and stopped at the files a
  uid-mapped extraction had left owned by a subordinate uid, so the index was gone and 5.2 MB were
  not. `kern images` then said the cache was empty, and `kern rmi` - whose own error sends the reader
  to `kern images` - said "no such image". Each sentence was true and together they said the files
  were not kern's. The empty listing now names what is there and `kern gc --images`, which reclaims
  it (measured: 5.1 MB freed on that wreck). The walk runs only when there is nothing to list, so a
  normal cache pays nothing for it.
- A box no longer inherits the supplementary groups of whoever typed `kern box`. With no `--user`
  there was no identity to set, so nothing cleared them: a field report read it off `id` inside a
  plain box, thirteen `65534(nobody)` entries beside `0(root)`, which are the caller's host groups
  seen through a map that does not contain them. Measured before changing it, because the one thing
  those groups could have bought is access to a bind mount the caller reaches only through a group: a
  host file `----r----- alex:disk` mounted with `-v` was ALREADY refused inside the box with the
  groups in place. So the list granted nothing and its only effect was that output. Podman drops them
  too.
- A workload whose image group list the box refuses (one gid outside the uid range) no longer keeps
  kern's own groups. It ran with the host user's groups as the box sees them, `0(root)` among them;
  it now gets none, and the warning says the gid is outside the map. Box root on the single-uid map,
  where no group can give it anything, no longer gets that warning on every run.
- kern-sandbox: `user=` (Node `user`, `kern-mcp` `KERN_MCP_USER`) runs every box as an account of the
  image, `persist` calls included. An image that declares a non-root `USER` now works without it:
  every call on one failed with `Permission denied` on its own script in `/workspace`, exit 2. A
  non-root account shares the workspace through a POSIX ACL, and what it closes to the host (0600,
  0700) is reached through a short-lived box of the same image running as that account, its owner.
- kern-sandbox: listing the workspace (`result.files`, `list_files`), `snapshot`, `restore` and the
  directories `write_file` creates now reach every path by descriptor, in both bindings. By path, a
  box running beside the call could swap a directory for a symlink at the right moment: measured on
  0.2.45 with the swap injected there, the listing returned a host file, the snapshot archived it, the
  restore wrote into the host directory and `write_file` created a directory in it. `restore` applies
  `filter="data"`'s rules on every Python version, not only from 3.12.
- A compose stack joining an `external:` network no longer writes outside the other project's box. Its
  names were appended to that box's `/etc/hosts` through `/proc/<pid1>/root` by path, which resolves
  an absolute symlink against the host's root: measured on 0.30.2 with the default seccomp filter, a
  box whose PID 1 had `chroot`ed into a tree with `etc/hosts` linked to a host file had the other
  stack's `up` append to that host file, mode 600, outside every box. The file is now resolved inside
  the box's root, must be a regular file, and is read and written through one descriptor.
- `kern exec` re-applies the box's `--landlock-rw` allowlist, and so does the health probe. A Landlock
  restriction is inherited only from the process that applied it, and an exec's parent is the host
  CLI: measured on 0.30.2, `kern exec` into a box started `--landlock-rw /data` wrote to another mount
  that the box's own workload could not write.
- `kern recover` and `kern gc` no longer remove the scratch of a box that another `kern` is still
  building. That box has no registry entry yet, so it looked orphaned, and its overlay mount then
  failed with `mount(overlay) failed: No such file or directory`: measured, 42 of 160 boxes started by
  four workers beside a `recover` loop, none without it. kern-sandbox runs `recover` when a prewarmed
  session closes, so several `kern-mcp` servers on one machine broke each other's calls this way. A
  scratch directory is now kept while the process that created it runs. An older kern on the same
  machine still sweeps them until it is updated; the error now says a directory was removed while the
  box was being built, where it said the host could not build a box and pointed at `kern doctor`.
- `kern commit` copies a running box by descriptor, each entry opened relative to its parent with
  `O_NOFOLLOW`, so a directory the box replaces with a symlink while the commit walks cannot point the
  copy at host files. The descriptors held are one per level of depth.
- A `kern exec` command, between its fork and its `execve`, is no longer reachable through `/proc` by
  a process in the box running as the same uid: the flag the kernel consults was restored after the
  identity switch, and is now cleared for the whole of that window.
- An image `/etc/group` that names the workload's user in more than 65 536 groups gives it the first
  65 536 with a warning, where `setgroups` refused the whole list and the warning blamed the gid map.
- kern-sandbox: listing the workspace holds one descriptor per level of depth, not one per directory.
  The first descriptor-based walk held every sibling open, so a wide tree (a `node_modules`) ran out
  past the soft limit and those subtrees were missing from `result.files` and `list_files` with
  nothing said; Node also hit V8's argument limit and leaked the descriptors. A resource error in
  the walk is now raised; only an entry that went away is skipped.
- kern-sandbox: `workspace_max_bytes` (Node `workspaceMaxBytes`) can no longer be defeated by a
  directory the box makes unreadable to the host. It counted as zero, so one `chmod 0` hid whatever
  was in it from every later check; a session that cannot measure it now refuses the call.
- kern-sandbox: `snapshot` into a path inside the workspace no longer archives the archive itself, a
  resource or I/O error while archiving is raised instead of leaving the file out, and `restore`
  writes every byte of a member or fails, where a short write left the file truncated. Node's
  `restore` reads the ustar `prefix` field, so a member path of 101 to 255 bytes (as Python writes
  them) lands in its directory instead of at the workspace root, and a GNU long-name archive is
  refused by name. A symlink in a path given to `write_file` or `restore` is named as one again.
- kern-sandbox: a `kernel()` cell returns the matplotlib figures it drew, once, and no longer those of
  the cells before it. Every figure stayed open, so every later cell re-sent every figure of the
  session and paid a PNG encode for each: measured, a cell that only assigns a variable took 65 ms
  after five figures, 0.04 ms now. A figure is closed once its cell has returned it, as Jupyter's
  inline backend does, so a later `plt.*` call draws on a new figure. A `Figure` value (`fig`,
  `display(fig)`, a subclass included) is drawn as PNG, so a figure the code holds can be shown again;
  one that is the cell's last value is not repeated by the end-of-cell capture, and one drawn on after
  `display(fig)` still comes back finished. One figure that cannot be drawn no longer stops the others,
  on the cold path as in the kernel. Both bindings.
- `kern-mcp`: when the SDK had already cut a call's output at 1 MiB, the clip notice says "truncated at
  least N chars", N counted on the stream as the code printed it. It counted from what the SDK kept,
  so 2 MB and 100 MB both read "truncated 1032576 chars". A cell printing the floored notice is
  labelled as printed by the code, like the exact one.
- `kern save -o` and `kern cp` write a file beside the kern registry: `kern save -o
  /run/user/1000/img.tar` was refused as "writing into the kern registry", and so was every write next
  to a non-default `XDG_RUNTIME_DIR`. The mount guard refuses any ancestor of the registry, which is
  right for a mount and wrong for one new file; a write is now refused where it lands in the registry,
  directly in its root, or on the root's own name.
- kern-sandbox: the file holding a call's `env=` is no longer written into the workspace, but into a
  0700 directory of the session's own (under `$XDG_RUNTIME_DIR` when that is private), removed when the
  session closes. In the workspace every box could read it, a box running beside the call included;
  measured, a box on 0.2.45 saw its own `.kern-env.pysbx-...` in `/workspace`. A process killed mid-call
  left it there for `snapshot` to archive, measured, `env=` values included. The directory is never
  inside the workspace: with `workspace="/tmp"` and no private runtime directory it is made elsewhere,
  and the session is refused if there is nowhere else. A call made while the session closes is refused
  instead of running without `env=`. Regular files an older version left behind (a call's, and the
  persistent box's, which no version removed) stay out of listings and snapshots by their exact names.
  Both bindings; a failed `setup` in Node's `open()` now removes the temporary workspace, as Python's did.
- kern-sandbox: a snapshot records the image and CPU its `.deps` were installed for, as its first member,
  and `restore` into a different image or CPU warns: measured, a compiled package restored into another
  Python failed to import as `ModuleNotFoundError: No module named 'orjson.orjson'`, naming nothing
  else. An archive without the record restores as before. Both bindings read each other's.
- kern-sandbox: `snapshot` no longer writes members its own `restore` refuses. On 0.2.45 a workspace
  holding one symlink, FIFO or hard link gave a snapshot that `restore` refused whole ("unsafe member
  type in snapshot"). Symlinks, FIFOs, devices and sockets are now left out and named in a warning, and
  a hard link's second name is archived as a file of its own. Such a snapshot made by 0.2.45 still
  cannot be restored by `restore`, whose refusal of link members is unchanged; `tar -x` extracts it.
- kern-sandbox: `snapshot` and `restore` given a path inside the workspace open it by descriptor, as every
  other host-side write there is. By path, a symlink the box planted at a predictable name such as
  `ckpt.tar.gz` sent the archive onto the host file it named, and a planted `restore` source read a host
  archive into the workspace. Both bindings. The record a snapshot carries is read by one rule in both
  (strict UTF-8 JSON, the number 1, printable ASCII fields); a crafted record no longer crashes Python's
  `restore` or reaches the terminal as escape sequences.
- kern-sandbox (Node): `snapshot` into the workspace no longer archives the previous snapshot at that
  path, and `restore` writes every byte of a member or fails, where a short write left it truncated.
- docs: INSTALL.md says to keep a project inside the WSL distro and not under `/mnt/c`, with the cost
  measured on one Windows 10 host: a `kern build` of 2000 files took 0.18 s inside and 17 to 19 s under
  `/mnt/c`, where one read of each file alone costs 6.5 s.
- `kern build` keeps its per-instruction cache on WSL2 and on a Jetson (tegra 5.15): editing a source
  file after a 3 s install step rebuilds in 54 ms and 49 ms there, where it re-ran every step (3.1 s).
  Both fell back to the flat path, whose cache is whole-build, because their kernels recorded no deletion
  in kern's overlays. kern mounts every overlay inside a user namespace, whose root cannot write the
  `trusted.*` attributes overlayfs keeps its whiteout and opaque markers in, and unlike 7.0 these kernels
  do not move them to `user.*` unless asked with `userxattr`. kern asks for it where the layer being
  written can hold `user.*`, which is a property of that filesystem and is measured per mount rather than
  assumed: tmpfs took no `user.*` before Linux 6.6, so on tegra 5.15 asking for it turned a working
  `rm -rf` in a box into an I/O error, while on WSL2 6.18 NOT asking was what produced one. A kernel
  before 5.11, which does not know the option, is answered by trying the other form, and a kernel that
  refuses it for its own reasons says so in a note instead of falling back in silence. Measured on all
  three hosts: a box can delete a directory of its own image and it stays deleted, and a base directory
  deleted and recreated in a build step stays deleted both in the image and through `COPY --from`.
- `kern build inspect <id>` and `kern builds --json` carry `strategy`: `layered`, or `flat: <reason>`.
  Whether a build had a per-instruction cache was only ever said on a progress line, which is printed to
  a terminal and nowhere else, so in CI or a script a build that lost the cache looked like a slow
  machine. Records written by an earlier version have no such field and read as empty.
- `kern build` prints its step lines again on a terminal. Its log capture points stderr at a pipe for
  the whole build, so the terminal check answered no and none were printed, the line saying why a build
  went flat included (measured on 0.30.2 under a pty). That line now also names the probe step that
  failed, where it said only that the probe "could not run".
- `kern box --image` no longer waits forever on an image whose `/etc/passwd` or `/etc/group` is a FIFO,
  and reads neither file past 8 MiB. 0.30.2 resolving `USER nobody` in an image built with
  `mkfifo /etc/passwd` never started the box.
- `kern ps`, `stats`, `history`, `volume ls`, `network ls` and `pod ls` line up names longer than 48
  characters: off a terminal always, on a terminal as far as its width allows. Past 48 a row used to
  overflow and push its other columns out of line whatever the output was going to.
- `kern doctor` names the Windows side of WSL only inside WSL. On a native Linux host the row about
  two kern binaries that disagree on version also said that a `kern.exe` on the Windows side was not
  visible and to run `kern wsl list --probe` from Windows.
- kern-sandbox: the error for `language="node"` on an image without node no longer says that no image
  kern defaults to carries node, which stopped being true when kern-mcp's default image carried it.
- `kern box <name> --keep`, `kern start <name>` and `kern rm <name>`: a box whose writable layer is
  kept, and a verb that runs it again on what it left. A kern box is a process and its layer is
  scratch under `$XDG_RUNTIME_DIR`, so stopping one threw away everything it had written and there
  was no verb to run it again. Measured on one workload, a counter in `/root`: a kept box reads
  `run #1`, `run #2`, `run #3` across three starts, where an ordinary box reads `run #1` every time.
  Nothing changes without `--keep`, which is the default this does not touch: a plain box still
  leaves nothing behind. The layer lives under `$XDG_DATA_HOME/kern/boxes/<name>/`, which survives a
  reboot, beside the `kern box` argv the box was made with, verbatim and byte for byte, and the
  directory it was given in: `kern start` re-runs that command, so a flag added to `kern box` is
  carried with no change there. A `-v` source or an `--env-file` that has gone since fails the start
  with kern's own message and leaves the box stopped. `kern ps -a` lists kept boxes in a section of
  their own with the exit code of their last run, in `--json`, through `--format`, in `-q` and under
  `--filter status=kept`, which is the query that means "what `kern start` can run" and the source
  the shell completion for both verbs reads. A kept box is in none of the plain views, whose contract
  is the boxes that are up. A box that is up is refused by both verbs,
  naming its pid and `kern exec <name> <cmd>` for the box that is already running. `kern gc` and
  `kern recover`, whose job is to remove what a box left behind, leave a kept layer alone: measured
  between two starts, and the SDK runs `recover` whenever a prewarmed session closes. `kern start`
  checks the record before replaying it: size-bounded, and a `kern box <name> ...` command line for
  that name, or it is reported with `kern rm` rather than run. `--overlay-upper`,
  the one mechanism that could have carried this, could be written once and never reused: a used
  overlay workdir holds a mode-000 `work/work` that the clearing could not traverse, so a second
  start failed with `Permission denied`. That is fixed, and the work directory is cleared at every
  start.
- A test carries the compose keys kern reads, so dropping one fails the build by name, and the other
  half of the rule at the top of this file (a key kern does not read says so) is asserted key by key.
  It found one thing on the way in: `extends:`, which kern implements and folds in before the key
  match runs, was listed among the keys reported as "ignored (unsupported)". That arm was unreachable
  and says so now.
- An audit of this branch (functionality, security, performance and a cleanliness pass) found
  fourteen things in the work above, and they are fixed here. The ones that change what you get:
  - A kept box's record is one file, written to a temporary name and renamed into place. In place, a
    reader caught it mid-rewrite: measured, 20 `kern start` of one kept box at once and one of them
    answered "no kept box", and at the unit 1968 of 4082 concurrent reads saw neither the old record
    nor the new one. The record is also written AFTER the name is claimed, so the 19 losers of that
    race no longer rewrite the winner's record and recreate its directory on their way out.
  - `kern start` only replays a record that begins `box <name>` for the box being started, and the
    image `kern ps -a` shows is read from that argv rather than from a header field. A record written
    by hand could otherwise start a box under a DIFFERENT name with flags the operator never typed,
    while the `ps -a` row showed the image it wanted them to see (measured, both halves).
  - The kept-box store is refused as a mount source, as the runtime registry already was: it holds
    the command line `kern start` runs, so a box given that tree could leave `-v $HOME:/host
    --privileged` behind for the operator's next `kern start`. Its ancestors go with it, which is why
    `-v ~/.local/share` is refused now; a path beside the store is unaffected.
  - A box's writable layer is never written through a symlink planted at `upper` or `work`, and
    `kern rm` does not walk one planted at the box's own name. Measured: the first wrote a box's
    `etc`, `root` and `sys` into the link's target, and the second chmodded an arbitrary tree to 0700
    and printed "removed kept box" with exit 0.
  - A record that is a FIFO no longer hangs `kern ps -a` and `kern start` for ever (measured,
    `timeout 10` returned 124 for both), a symlink at its name is not followed, and a record kern
    cannot read says so and points at `kern rm` instead of claiming the box does not exist.
  - `kern box <name> --keep` works for every name `kern box` accepts. It kept nothing, and said
    nothing, for a name longer than 64 bytes: the store used a stricter name rule than the CLI, and 71
    bytes is the length of the compose service name that set the CLI's limit.
  - `kern ps -a` reads the registry once instead of once per kept box, and does not scan the store at
    all when no kept row can survive the query. Measured: with 200 registry entries and 100 kept
    boxes the scan cost 3.22 ms of reading one directory 101 times, now 0.57 ms; `ps -a --last 1`
    and `--filter status=running` cost 5.6 and 6.1 ms with 1000 kept boxes, now nothing measurable.
    `--filter name=` is answered from the directory entry, before a record is opened.
  - `ps -a --last N` lists the N most recent boxes that RAN and no kept rows, where it printed N plus
    every kept box (1002 rows for `--last 2`). `--filter status=created` no longer matches a kept box
    that never ran, which contradicted the flag's own usage message.
  - A kept box costs about 5.2 ms more to start than a plain one, and all of it is the kernel working
    on an overlay whose upper is on a real filesystem rather than the runtime tmpfs: measured, with
    the layer on tmpfs the difference is not measurable (+0.015 ms, 95% [-0.060, +0.088], n=300).
    `kern start` costs 0.69 ms more than `kern box --keep` of the same workload, which is the second
    `execve` of kern that replaying the recorded argv needs. The plain box path is unchanged
    (+0.007 ms, 95% [-0.022, +0.040], n=300).
  - `--secret NAME=value` now says that `--keep` writes the value into the box's record too, beside
    `ps` and the systemd journal.
- A functional audit of the same branch found nine more, including the two that could corrupt a
  layer. Fixed here:
  - Two boxes can no longer mount one kept layer. The registry's name claim does not cover it,
    because the registry and the layer live in different places: measured two ways, `kern box w1
    --keep -d` then `kern rename w1 w2` then `kern start w1`, and one `$XDG_DATA_HOME` with two
    `$XDG_RUNTIME_DIR`s (which is what a `kern compose systemd` unit produces). Both gave two live
    overlay mounts of one upperdir, which the kernel itself calls undefined behaviour in `dmesg`, and
    the second start also cleared the live mount's work directory. The layer is now locked for as
    long as the box runs, and a second box is refused with the pid holding it.
  - `kern box <name> --keep --image <other>` is refused when the layer was written against a
    different image, instead of running the new image with the old delta on top: measured, a file
    written by an alpine run was live inside a debian box, and the record then claimed the new image
    for a layer that was half the old one. `kern rm <name>` is the way to change image.
  - A detached kept box records how its run ended. `-d` is the shape this feature is for, and only
    the foreground path recorded it, so the durable record said "never ran" for ever while the
    transient one said `exit 137`: measured, the same box in two sections of one `ps -a` saying two
    different things, and `ps -a -q` printing its name twice for a script to act on twice. The code
    is recorded by whichever side ends the box (its supervisor, or the `kern stop` that killed it),
    a box that traps the signal and exits 0 is recorded as 0, and a name with a kept layer is one
    row.
  - `kern uninstall` lists the kept layers as data you made. Measured: 21 MB of a user's own files,
    in a directory kern created, under a summary that said "0 B is data you made".
  - `kern inspect <name>` of a kept box says what it is and that `kern start` runs it, where it said
    "nothing named '<name>'" about a layer `kern ps -a` was listing.
  - `kern ps -a` lines its columns up when a kept name is the longest one: the width came from the
    live and exited rows only, so a long kept name pushed every column after it out of line, in a
    pipe, where the alignment is exact.
  - A refusal about the command line no longer leaves a kept box behind. `kern box x --keep -it -d`
    fails on the flag pair, 600 lines after the record used to be written, and left a `ps -a` row and
    a directory for a box that had never existed and could never start. The record is now written
    past every argument check and still before the box runs, so a box refused by the HOST (a mount,
    a uid map) is still one `kern start` can retry.
- kern-sandbox: an archive one binding writes restores to the SAME TREE in the other, which it did
  not, in four ways, each measured on one tree:
  - **Modification times are carried and applied.** Python wrote the real ones and Node wrote `0` and
    applied none, so a restored tree had the moment of the restore there and the moment of the
    snapshot here. That is what an incremental tool reads: `make`, `tsc --incremental`, `pytest --lf`,
    and CPython's own `(mtime, size)` check on a `.pyc` under `.deps`. Node's constant was there for
    a deterministic archive, and nothing in either package's tests, READMEs or docs asked for one,
    while the docs do promise a snapshot moves the files a session wrote to another machine.
  - **An empty directory survives.** Node wrote no directory members at all: measured, a workspace
    holding `emptydir/` and `full/f` gave an archive of `full/f` alone, and restoring it produced
    `full` and nothing else.
  - **A file keeps its owner permission bits**, so an executable comes back executable; Node wrote a
    constant `0644` and ignored the archive's mode on restore. Group and other bits are deliberately
    NOT carried, in both: on a workspace shared with a `user=` account the group bits are the POSIX
    ACL's mask, and the ACL does not travel in a tar, so restoring them turned a mask into real group
    access.
  - **A path of 101 to 255 bytes round trips.** Node's writer refused every path over 100 bytes while
    its own reader has read the ustar `prefix` field since this branch, so it could not write what it
    could read, and a Python-written archive with such a path threw from its re-emission path after
    part of the tree had been written.
  Ownership is now `0/0` with no account names in both (a Python archive listed the host user's name
  on every member it read directly and `0/0` on the ones it read through the helper box, so one
  archive carried two conventions), and a crafted numeric field cannot overflow its 11 octal digits
  on the way in or reach `utimes` on the way out. Four combinations of writer and reader are asserted
  against one expected tree, and five sabotages of the four properties each fail it.
- kern-sandbox: `snapshot()` works for a non-root `user=` session with anything the host cannot read,
  which is the case the helper box exists for. It failed every time: the host side stops at the
  archive's end-of-archive marker and then killed the helper, which was still tearing its box down,
  and read the `-9` as the box user's failure - measured 9 times out of 9 (a 0700 directory, a 0600
  file, and both), each reported as "the box user could not read ... exit -9" about a stream read in
  full. Node did it correctly, so this was also a Python/Node split on a documented API.
- `kern-mcp`: a stream this reply did not cut carries no truncation notice. `truncated` is one flag
  for both streams, so a call whose stderr was cut told the model "truncated at least 1 chars" about
  a stdout it had whole (measured: `print("hi")` beside 2.2 MB of stderr).
- kern-sandbox: the helper box and the uid probe clear the image's ENTRYPOINT. kern prepends it to
  what follows `--`, so they ran `ENTRYPOINT sh -c <script>` and the image chose what came out - and
  those results are parsed, not displayed: `read_file` returns the stream as the file's bytes, the
  listing reads stat records out of it, `snapshot` reads a tar. An image whose entrypoint printed one
  line prepended that line to every `read_file`; one that rejects an unknown first argument failed
  every call with a sentence about missing tools. Both bindings.
- kern-sandbox: the image's own `USER` goes through the same check as `user=`. An image declaring
  `USER --privileged`, `USER ' root'` or a 300-character name put that value on the argv unexamined,
  and root-ness is now decided by the uid the probe measured rather than by the spelling, so an image
  whose `USER` names box root under another name (`N0tR00t` mapped to uid 0) cannot make the helper
  box run as root of the uid range. Both bindings.
- kern-sandbox: a listing shows every file in the workspace again. The names an older version's env
  file could have (`.kern-env.pysbx-<12 hex>`, `.kern-env.kern-sbx-<191 characters>`) were skipped by
  `list_files`, `result.files` AND `snapshot`, and every one of those shapes is one a cell can create:
  a box could hide a file from the three channels that answer "what did this cell leave behind". They
  stay out of SNAPSHOTS, which travel and must not carry a stale `env=` value; the only name hidden
  from a listing is the exact legacy `.kern-env`. Both bindings.
- kern-sandbox: box-produced text that reaches a message of ours is quoted, in five more places (the
  uid probe's output, the helper box's stderr in three messages, and a path a box chose in the
  workspace-cap refusal). A filename inside a directory the box closed to the host appears verbatim
  in `du`/`find`/`stat` diagnostics, and busybox does not quote its own; measured, a forged
  `[sandbox: oom]` verdict and a screen-clearing escape reached the caller through them. `kern-mcp`
  also neutralises its `kern error:` reply, which was the one box-influenced string in that server
  that did not go through the labeller.
- kern-sandbox: `snapshot` of a directory the host cannot read vets the member names it takes from
  the box's own `tar`, so an archive cannot carry `../../../.ssh/authorized_keys`; `restore` keeps a
  member's OWNER bits only, because a mode out of an archive carries the source workspace's ACL mask
  in its group bits and the ACL does not travel (measured: 0600 in, 0640 out with `group::r--` on the
  restored copy); and a crafted mtime (`1 << 70`) no longer escapes `restore` as an `OverflowError`
  after part of the tree is written. A `user=` session that is given a workspace of yours now says
  that it added an ACL to every file under it, that it is not removed when the session closes, and
  which `setfacl` undoes it.

## kern-sandbox 0.2.45 - 2026-10-05

**Both packages carry kern v0.30.2**, so a `persist=True` call that `kern exec` refused (an ssh session
outside the delegated cgroup tree is the common case) is `startup_failed` with kern's own message, where
it read as the code's own exit 126 with no fault. With an older kern it still reads as 126.

**Output printed before an OOM, a timeout or `os._exit` now reaches the caller on every path.** 0.2.43
made this true for a cold box only. The prewarmed box, which serves most `kern-mcp` calls, and the
resident kernel run a driver that sent a cell's output in the reply that ends the cell, and a killed
cell never sends one. The Node binding's cold box also lacked the unbuffered flag. The driver now
streams output while the cell runs, and a SIGKILL loses at most the last millisecond of it. Measured,
driver alone: 10 000 prints in one cell cost 14.3 ms where they cost 1.6 ms when the driver only
collected them (9.8 ms on a cold box); a cell with one print costs 0.013 ms more.

**One cell, one outcome, whichever box runs it.** On the prewarmed box and in the kernel, `os._exit(N)`
returns `exit_code=N` with no fault, where it returned `killed`. A kernel timeout returns 137, where it
returned -1: the timeout tears the kernel down, as it does a one-shot box. Kernel output over
`max_output_bytes` is cut and the session goes on, where it ended the interpreter and its state. When a
cell ends the interpreter with no fault, `kern-mcp` still says the session was replaced.

**`kern-mcp` runs `ghcr.io/getkern/kern-sandbox:0.2.44` by default**, pinned by digest: python 3.12
with numpy, pandas and matplotlib, and node 22, for amd64 and arm64. A model that plots or asks for
`language="node"` no longer needs `KERN_MCP_SETUP` or another image, and the tool description says
what the image has. The image is 145 MB against 46 for `python:3.12-slim`; the server starts the
download when it starts. `KERN_MCP_IMAGE=python:3.12-slim` restores the previous default.

**Opening a sandbox pulls a missing image first, on its own budget.** The first box used to pull it
inside its call's deadline: on a Jetson with an empty cache the first cell answered `startup_failed`
at the 30 s default. A pull that fails changes nothing, and the box reports it as before.

The `persist` docs said a call costs 2 ms; that was `kern exec` alone. A resident call still starts a
fresh `python3` and costs about what a fresh box does (11.4 against 13.9 ms on one host);
`sbx.kernel()` is the fast path.

## v0.30.2 - 2026-10-05

**`kern exec` no longer reports a command it refused as one that started.** When it cannot put the
command under the box's caps (a box at its `--pids-limit`, or a shell outside the cgroup tree kern
delegates, which an ordinary ssh session is) it refuses with exit 126, and it also wrote the "started"
bytes on `KERN_STARTED_FD`, so an SDK read the refusal as the code's own exit 126. It writes nothing
now, as `kern box` does for a box that never started.

- An image `kern save` or `kern push` wrote can be the base of a `podman build`: the config carries the
  `history` entry buildah requires for each layer.
- `kern box --help` says `--user` also takes a name from the image's `/etc/passwd`, which it always did.

## kern-sandbox 0.2.44 - 2026-10-04

**Both packages carry kern v0.30.1**, so a resident sandbox (`persist=True`, Node `persist: true`)
reports an OOM as `oom` where it reported `killed`, and a cell's own `exit(137)` as an exit with no
fault where it reported an external kill. Measured in both bindings; with an older kern on `PATH`
both still read `killed`.

## v0.30.1 - 2026-10-04

**A compose `devices:` entry needs `--allow-device-grants`, as the pages already said.** kern 0.30.0
gave a box `/dev/kvm` or a GPU's modeset node from a compose file run with no flag. Such a file now
stops with a message naming the service and every node; pass `--allow-device-grants` to run it.
`/dev/net/tun` is unaffected.

**`kern save` and `kern push` work on Debian- and Ubuntu-based images on a host with a subuid
range.** Both failed there, on `python:3.12-slim` and on anything built on it, because the image's
`/var/cache/apt/archives/partial` belongs to a subordinate uid; Alpine was unaffected. `kern gc` also
removes the copies `--pull always` retires, which it left behind on the same hosts.

**`kern exec` tells an SDK how the command ended.** A resident sandbox (`persist=True`) now returns
`fault.type == "oom"` for an OOM where it returned `killed`, and a cell's own `exit(137)` reads as an
exit instead of an external kill.

**A `-v` aimed under `/sys/devices` reaches the box.** The CPU topology kern writes there covered it.

**A base image without `/bin/true` builds layered**, instead of building flat and blaming the kernel
("unprivileged overlay unavailable").

**`kern inspect` answers for a built image.** It said "nothing named" for every image `kern build`
made, while `kern images` listed it.

**Three messages name the right thing:** compose `gpus:` is described as Docker's GPU request rather
than a typo for `cpus:`; `kern pull` names `kern box … --pull always` to refresh an image; and a failure
reading a cached image no longer says to check the image's name.

## kern-sandbox 0.2.43 - 2026-10-04

**`npm install kern-sandbox` brings kern with it, and both packages carry kern v0.30.0.** On Linux
x64 and arm64 the npm package carries kern's static release binary, the same file `install.sh`
serves, and the Node binding takes it after `$KERN_BIN` and before `PATH`, as the Python wheels do.
Python and Node are at one version again.

**A one-shot cell no longer inherits the caller's stdin.** Under `kern-mcp` that descriptor is the
JSON-RPC transport, so a cell could read bytes meant for another tool call. `input()` now gets EOF.

**A warm or resident box built under another posture is no longer handed over.** The prewarm pool's
key and the `persist` fingerprint now come from one function: the argv, every `KERN_*` variable kern
reads when it builds a box, and what a `vcpu:`/`vgpio:`/`vdisk:` profile resolves to. A changed
`kern.toml` definition or `KERN_SECCOMP` used to leave the key unchanged. A kern too old to print a
profile's device grant is refused for `vgpio:` and `vdisk:` profiles, and the pool steps aside.

**The wheel's kern is identified by the hash its RECORD lists, not by the path.** `pip install
--target DIR` writes a RECORD entry that points two levels above `DIR`, and a kern there was taken
over the wheel's own. Now a candidate is taken only when its bytes match, and `DIR/bin/kern` is found.

- **`persist=True`** (Node: `persist: true`) keeps one resident box per `name` and runs every call in
  it with `kern exec`: 2 ms a call against 6 ms for a fresh box, and another process adopts it. It
  needs `name` and an explicit `workspace`. A box under another posture is refused naming both
  fingerprints. One destroyed by an OOM or by its TTL is recreated once, with a warning that says
  what was lost. `setup=` runs in its own network-on box before the resident one starts.
- **`workspace_max_bytes`** (Node: `workspaceMaxBytes`) caps what a workspace accumulates across
  calls. It is cooperative: the call that exceeds it runs, and the next is refused.
- Output survives an OOM or a timeout: the interpreter runs unbuffered.
- `os._exit(0)` under a memory cap is reported as a clean exit, not as an external kill.
- `language="node"` is refused on the default image, which has no node, and the refusal names the
  remedy.
- The MCP server caps each stream at its reply budget. A cell printing 100 MB used to cost 129 MiB of
  server memory to show 16k characters; it now costs 3 MiB.
- The MCP server answers `-32700` for every id on a line that is not one message (two frames, a frame
  cut short), and refuses `NaN` and `Infinity`.
- `index.d.ts` declares the eight constructor options it lacked, among them `persist` and
  `requireLimits`, plus `destroy()`. It also stops saying `depsReadonly` defaults to false: the
  default is true.

## v0.30.0 - 2026-10-04

**kern says when a limit above a box will stall it instead of letting it be killed.** Past a
`memory.high` on a cgroup above the box the kernel throttles allocations rather than OOM-killing, so a
box that should die at its cap hangs until its timeout: with `MemoryHigh=80M` on `kern.slice`, an OOM
that takes 0.06 s took 317 s. kern now prints a `kern: note:` naming the cgroup and the command that
lifts it, `kern doctor` and `kern inspect` report it (`memory_high_outer` and
`memory_high_outer_cgroup` in `--json`), and `--require-limits` refuses to start such a box. Drop the
flag to start it anyway; `KERN_QUIET=1` silences the note. kern never changes the limit.

**`kern box --show-config` prints what a profile grants, not only its cgroup numbers.** Three lines
follow `privileged:`: `devices:`, `sysfs:` and `vdisks:`, each sorted, `-` when empty. Two different
device grants under one profile name used to print identical output. The lines are added; every
existing one is unchanged.

**On Windows, `kern.exe` says which WSL2 distro it runs in and lets you choose:** `kern wsl list
[--probe] | status | use <distro> | reset`. `use` warns when `KERN_WSL_DISTRO` is set, because that
variable wins over the stored choice.

**`kern compose restart` no longer hangs on a one-shot dependency that already completed.** It
waited 120 s, exited 1 and left the service down; `service_healthy` dependencies waited the same way.

**`kern doctor` no longer says "ready" on a host where a box dies at the `/proc` mount**, and it
reports when more than one kern is installed and the versions disagree.

**The note about two services on one internal port names both services and the port**, and `ps`,
`restart` and `logs` no longer print it.

**`kern build --check` names a `COPY --from=` stage it cannot resolve** instead of saying the file
builds here.

**`install.ps1` no longer leaves `$ErrorActionPreference = 'Stop'` in the PowerShell session it was
piped into**, where every later command writing to stderr became a terminating error.

The sandbox SDK and MCP server changes on this line (resident named sandboxes, a workspace cap, an
MCP server that answers every request id it can read) ship as kern-sandbox, with Linux wheels that
carry this kern.

## kern-sandbox 0.2.42 (Python) - 2026-09-29

**The Linux wheels carry kern v0.25.1**, so `pip install kern-sandbox` brings the pull that ends a
stalled image download after 30 s and retries it, instead of waiting ten minutes. Nothing else in the
package changes; the Node package is unchanged.

## kern-sandbox 0.2.41 (Python) - 2026-09-29

**`pip install kern-sandbox` is the whole install on Linux.** The wheels for `x86_64` and `aarch64`
carry kern's static release binary, v0.25.0, the same file `install.sh` serves and checked against
its published sha256. pip installs it as `kern` next to `python`, the way ruff and uv ship theirs,
so the venv has `kern doctor` too. The universal wheel stays, unchanged, for every other platform.
Measured in a fresh venv with no `kern` on PATH: `run_code` ran on x86_64 and on a Raspberry Pi 5,
and `uvx --from kern-sandbox kern-mcp` answered a `run_code` call over stdio.

**The SDK takes the kern its own wheel installed, and finds it through the package's RECORD.** The
order is `$KERN_BIN`, then that binary, then PATH. Not by looking next to the interpreter: a
user-scheme install shares `~/.local/bin` with `install.sh`, and a kern found there by position can
be a copy installed by hand months earlier.

**On a Mac, the error and the pages say where the code goes**: inside the Linux VM, where the same
`pip install` brings kern. The Node package is unchanged and still needs the install script.

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

## v0.25.1 - 2026-09-29

**Two threads asking whether memory caps work could get two different answers.** The probe named
its throwaway cgroup once per process, so a second thread removed the first one's directory to
retry, and the first then probed a directory that was no longer its own. Measured with six threads
on one unchanged host: 33 of 40 rounds disagreed; after the fix, 0 of 40. `kern doctor` never saw it
because it asks twice in sequence; a library caller with two threads decides from that answer
whether a box starts with caps or is refused.

**A registry transfer that stalls is ended and retried, instead of holding the pull for ten
minutes.** Measured on 29/09: a CDN connection delivered 32 MB of a layer and then nothing for 142 s
with the socket still open, and with only `--max-time 600` curl waited out the whole window while the
`kern box` that needed the image printed nothing. Every blob download now gives up below 1 KiB/s for
30 s and tries again, twice, a second apart; a registry that keeps stalling fails in about a minute
and a half with curl's own message. A test reproduces the stall on a loopback server, and fails in
60 s without the guard.

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
