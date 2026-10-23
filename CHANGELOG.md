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

## Unreleased

**A box could hand the host kernel checksum metadata of its own choosing, and two socket families
were reachable with nothing behind them.** `virtio_net_hdr` is how a sender supplies
`csum_start`/`csum_offset` instead of a finished checksum, and the parser behind it is what a VM
guest reaches through virtio-net. Measured in a default box before this: `CAP_NET_RAW` is effective
in the box's own user namespace, `socket(AF_PACKET, SOCK_RAW)` opens, and both options that enable
the header were ACCEPTED, while the invoking user cannot open a packet socket on the host at all.
The filter answers `setsockopt(SOL_PACKET, PACKET_VNET_HDR)` and `PACKET_VNET_HDR_SZ` with
`ENOPROTOOPT`, what a kernel without the option returns; both numbers, because 24 enables the header
as a side effect of setting its size. `socket(AF_XDP)` joins `AF_VSOCK` on the `socket` rule with
`EAFNOSUPPORT`: it carries the same shape of caller-supplied offsets and it OPENED in a default box.

Nothing a box uses is lost. `AF_PACKET` still opens, `PACKET_VERSION` and `PACKET_RX_RING` are still
accepted and a frame is still captured on `lo`, so `tcpdump` captures and `ping` pings;
`CAP_NET_RAW` is kept, as other runtimes keep it. This is not a fix for CVE-2026-99999 or any kernel
defect, and `docs/CVE-POSTURE.md` carries the counts behind that sentence, including the pair that
differs in one bit: a box with checksum offload on took 97,608 arrivals at the software-completion
predicate and entered it 0 times, and the same shape with the box turning offload off on its own
`eth0` took 42,721 and entered it 4,282.

## v0.33.0 - 2026-10-17

**`kern image inspect` emits the labels and healthcheck it already parsed.** `Config.Labels` was in
no output, `Config.Healthcheck` not in the JSON, so source, version and licence
(`org.opencontainers.image.*`) read as absent.

**`kern compose exec` no longer builds.** It enters a running box (else "is not running") but first
ran and printed all of `build:`. Now it builds nothing, as `docker compose exec` does.

**`kern compose start` and `restart` stop printing `up`'s note.** All three non-streaming
verbs got a note naming `up`, a `-d` flag they lack and parity with `docker compose up`. It now
names the verb that ran, from the one verb table.

**`kern exec` works on hosts where it used to refuse outright.** In a shell in `/init.scope` (every
WSL terminal) or an `ssh` session on Ubuntu 24.04, Fedora 44, Debian 13 and Rocky 10.2, kern runs
outside the cgroup tree it delegates. cgroup v2 delegation containment needs write access to the
common ancestor, the root, so `kern exec` and `kern compose exec` exited 126 beside a working box.

The scope, without resource properties, is `kern-exec-<pid>.scope`, not the
`kern-box-` prefix of reapable cgroups. Without a user manager the refusal stands, saying so.
`KERN_NO_SCOPE` skips it, as for `kern box` and `kern run`. `kern doctor`'s scope-toll row no
longer claims a refusal.

**A build could reuse a half-deleted layer and say `built`.** `kern gc` reclaimed unreferenced
layers with `remove_dir_all`, which stops at the first unwritable directory: a layer with a
subuid-owned file or read-only directory stayed on disk, uncounted, maybe without its `.ok`
sentinel; with it, the cache took the partial layer as complete. The sentinel now goes BEFORE the
directory, so a partial removal is a cache MISS (a rebuild). Removal uses the forced, id-mapped
remover of `rmi` and `volume rm`, so a layer they would reclaim is no longer left behind.

**`gc` and the `kern top` Images tab say what they could not reclaim**: bytes left and layer key,
once dropped silently. A note, not an error: the sweep removed all it could, and the exit code
says so.

**A pull that could not be read reported a private repository.** `manifest_error` matched words in
the body, so an EMPTY body (dropped, timed-out or proxy-filtered connection) gave "cannot access
'<repo>' ... it may be private (run `kern login`)". Reproduced under load on `library/alpine`.

**`kern exec` inside a user namespace no longer waits 25 seconds to fail.** The fix above keyed
cgroup placement on `getuid()`; inside `unshare -Ur` uid is 0 but the cgroup path says
`user@1000.service`, so kern asked a manager with no `user@0.service` for a transient scope.

**`kern doctor` stopped contradicting itself in one sentence.** A row named the cgroup it probed and
said "user manager delegates: none readable" about it, 10 out of 10 runs: runtime and doctor spelled
the delegated root separately; one owner now.

**Nine documented claims said more than the code does, and a gate now refuses the second one.** The
README's lede, both package READMEs, `docs/MCP.md`, `docs/SANDBOX.md`, `docs/CVE-POSTURE.md`,
`docs/RESOURCES.md`, `docs/FAQ.md` and `SECURITY.md`'s in-scope list overpromised: "cannot touch
your machine" while `workspace=` is a host directory the box writes; an allowlist "always on"
despite `KERN_SECCOMP=denylist`; credentials "never in it" three lines above "only what you pass
with `env=`". `scripts/retired-claims.py` refuses retired strings in user-facing text, each dated.

## kern-sandbox 0.2.49 - 2026-10-17

**It carries the kern v0.33.0 binary.** Both bindings move together.

**`workspace_max_bytes` is overshot by far less, by an amount set by what the workspace costs to
MEASURE.** The poller ran once a second, whatever the limit: a 50 MiB cap stopped a box at
5,964,300,288 bytes (113.8x), a slower disk at ~933 MB. The interval now scales with headroom,
floored at 1 ms; between walks a cheap probe re-checks the eight biggest files and directory
fingerprints.

⛔ IT IS NOT BOUNDED BY THE CAP (an earlier draft said it was). Headroom held at 50 MiB,
pre-existing file count varied:

| files  | Python  | Node    |
|--------|---------|---------|
| 0      | 1.26x   | 1.30x   |
| 1,000  | 1.32x   | 1.80x   |
| 10,000 | 4.12x   | 8.40x   |
| 50,000 | 12.88x  | 12.80x  |

An interval cannot undercut one walk: the bound is walk time times write rate; Node walks slower
(19.85 ms against 13.17 ms, same 10,000-file tree). The `workspace_full` fault gives these figures.
A fix needs a non-O(files) measurement that still counts hard links once, refuses symlinks and lets
a closed directory refuse the call, or it defeats the cap. The cap is a measurement and a kill on a
host directory, not a filesystem refusal.

In Node the backoff bounding the poller's cost never ran (Python's did): its timer started after
the walk and read zero.

**A file the box left at mode 0 is refused as a FILE, and as yours.** For a caller-owned file,
`read_file` said "a directory on that path is closed to this process and its owner bits could not be
restored - it is not ours (a `user=` session's box account owns it)", wrong in subject, owner and
`/proc` hint; `write_file` too. Both now report file, mode, owner and whether the owner is this
process; kern keeps a mode-0 file as written, since mode can be data. A closed DIRECTORY
keeps `snapshot`'s wording, which lists causes, now shared by every surface.
## kern-sandbox 0.2.48 - 2026-10-13

**Carries kern v0.32.0** (`--egress-allow` `Host:` check, below); binding code unchanged since
0.2.47. Package descriptions no longer say the workspace cannot be bounded (two sentences, false
since 0.2.47); they say the cap is measured during a call, and what it still is not.

## v0.32.0 - 2026-10-13

**Minor bump: `--egress-allow` refuses a request it used to forward.** Under an allowlist, a
plain-HTTP head whose `Host:` is not the vetted request-target, or is doubled, gets 403 (a port-80
escape). The check follows the allowlist, so refusals cannot probe it. Over HTTPS (header inside
TLS) a shared CDN still allows it (`docs/EGRESS.md`). Binary otherwise unchanged since v0.31.0.

## kern-sandbox 0.2.47 - 2026-10-13

**A call that filled the workspace used to succeed.** `workspace_max_bytes` was checked between
calls only (one call wrote 8,115 MB in ten seconds past a 50 MiB cap; the NEXT call was refused).
Now enforced WHILE a call runs, it stops the box mid-call with the new additive `fault.type`
`workspace_full`; `KERN_MCP_WORKSPACE_MAX_MB` exposes it on the MCP server (withheld while checked
between calls). Carries kern v0.31.0, the install line's binary.

- A `chmod 0` in the box no longer ends the session (the host-side walk's bare
  `PermissionError`/`EACCES` in reporting lost the finished call's result and failed every later
  call).
- Refusals name the mechanism, not the errno: symlinked directory in a READ or listing (was
  `[Errno 20] Not a directory`; writes already named it), non-directory path component, readable
  but unwritable directory.
- On failed repair, `snapshot()` and workspace sizing name what they could not read (was a bare
  permission error). Node no longer counts an unreadable directory as zero bytes, a permanent
  cooperative-cap bypass.
- Docs: `docs/MCP.md` covers the unbounded default, measured rate, new cap and a non-root recipe
  (`$XDG_RUNTIME_DIR` is already a sized tmpfs; new sized mounts need root); `docs/SANDBOX.md`
  the one host change in a workspace and what it does not buy.

## v0.31.0 - 2026-10-10

**`kern run --memory` REFUSES a cap it cannot apply** instead of printing "the command runs
UNCAPPED" and running; a command that worked yesterday may stop. The verb governs only resources.

- A cgroup kern did not write proves `--memory` only with bounded SWAP.
- Caps bind when `$XDG_RUNTIME_DIR/systemd/private` refuses connections under a live user manager.
- Proven ceilings are no longer called UNCAPPED.
- `kern exec -u <user>[:<group>]` runs as a box account (name or number), not only root;
  `kern exec -u` survives the capability switch under `--cap-drop ALL`.
- `kern rm` no longer cites a contradicting listing.
- A detached box unable to enforce caps says so on the terminal, not only its log.
- `kern inspect --json` no longer reports `"memory_max_enforced": null` for a kernel-capped box.
- `kern images` says whether "no images cached yet" is the whole truth.
- A box no longer inherits the supplementary groups of whoever typed `kern box`, nor keeps kern's
  when refusing the image group list (one gid outside the uid range).
- kern-sandbox: `user=` (Node `user`, `kern-mcp` `KERN_MCP_USER`) runs every box, `persist`
  included, as an image account; both bindings reach every path by descriptor in listings
  (`result.files`, `list_files`), `snapshot`, `restore` and `write_file`'s new directories.
- Compose stacks on an `external:` network no longer write outside the other project's box.

36 more entries: `git log v0.30.2..v0.31.0`.

## kern-sandbox 0.2.45 - 2026-10-05

**Both packages carry kern v0.30.2**: a `persist=True` call `kern exec` refused (below) is
`startup_failed` with kern's message, not a faultless exit 126 (126 with an older kern).

**Output printed before an OOM, a timeout or `os._exit` reaches the caller on every path**, not
only the cold box (0.2.43). The prewarmed box (most `kern-mcp` calls) and resident kernel sent
output in the cell's closing reply, never sent by a killed cell.

**One outcome per cell, on any box.** Prewarmed box and kernel: `os._exit(N)` gives `exit_code=N`,
no fault (was `killed`); a kernel timeout gives 137 (was -1), tearing the kernel down like a
one-shot box.

**`kern-mcp` defaults to `ghcr.io/getkern/kern-sandbox:0.2.44`** (digest-pinned, amd64/arm64):
python 3.12, numpy, pandas, matplotlib, node 22, as the tool description says. Plots and
`language="node"` need no `KERN_MCP_SETUP` or other image.

**A sandbox pulls a missing image at open, on its own budget**, not in the first call's deadline
(Jetson, empty cache: `startup_failed` at the 30 s default). A failed pull changes nothing and is
reported as before.

The `persist` docs' 2 ms per call was `kern exec` alone; a resident call starts a fresh `python3`,
costing about a fresh box (11.4 against 13.9 ms, one host). `sbx.kernel()` is the fast path.

## v0.30.2 - 2026-10-05

**`kern exec` no longer reports a refused command as started.** Unable to cap it (box at
`--pids-limit`, or a shell outside kern's delegated cgroup tree, e.g. plain ssh), it exits 126 but
wrote "started" on `KERN_STARTED_FD`, so an SDK read the refusal as the code's own 126. Now it
writes nothing, like `kern box` for a never-started box.

- `kern save`/`kern push` images can base a `podman build` (config carries the per-layer
  `history` entry buildah requires).
- `kern box --help` documents `--user` taking an image `/etc/passwd` name (always worked).

## kern-sandbox 0.2.44 - 2026-10-04

**Both packages carry kern v0.30.1**: a resident sandbox (`persist=True`, Node `persist: true`)
reports an OOM as `oom` (was `killed`) and a cell's own `exit(137)` as an exit, not an external
kill. Measured in both bindings; an older kern on `PATH` still gives `killed`.

## v0.30.1 - 2026-10-04

**A compose `devices:` entry needs `--allow-device-grants`, as documented.** kern 0.30.0 granted
`/dev/kvm` or a GPU's modeset node without it; such files now stop, naming the service and every
node.

**`kern save`/`kern push` work on Debian- and Ubuntu-based images with a subuid range.** They
failed on `python:3.12-slim` and derivatives (`/var/cache/apt/archives/partial` belongs to a
subordinate uid; Alpine unaffected). `kern gc` also removes copies `--pull always` retired there.

**`kern exec` tells an SDK how the command ended** (`fault.type == "oom"`, a cell's own
`exit(137)` as an exit; see kern-sandbox 0.2.44).

**A `-v` under `/sys/devices` reaches the box** (kern's CPU topology covered it).

**A base image without `/bin/true` builds layered**, not flat blaming the kernel ("unprivileged
overlay unavailable").

**`kern inspect` finds built images**: it said "nothing named" for every `kern build` image
`kern images` listed.

**Three messages fixed:** compose `gpus:` is Docker's GPU request, not a typo for `cpus:`;
`kern pull` names `kern box … --pull always` to refresh; a cached-image read failure no longer says
to check the name.
## kern-sandbox 0.2.43 - 2026-10-04

**`npm install kern-sandbox` brings kern; both packages carry kern v0.30.0**, realigning Python and
Node. On Linux x64/arm64 npm ships kern's static release binary (`install.sh`'s file), used after
`$KERN_BIN`, before `PATH`, as in the wheels.

**One-shot cells no longer inherit the caller's stdin** (under `kern-mcp`, the JSON-RPC transport:
a cell could read another call's bytes). `input()` gets EOF.

**Warm/resident boxes from another posture are not reused.** Prewarm key and `persist` fingerprint
share one function: argv, every `KERN_*` variable read at build, the resolved
`vcpu:`/`vgpio:`/`vdisk:` profile. A changed `kern.toml` or `KERN_SECCOMP` used to keep the key.

**The wheel's kern is matched by RECORD hash, not path.** `pip install --target DIR` puts a RECORD
entry two levels above `DIR`; a kern there won. Now bytes must match; `DIR/bin/kern` is found.

- **`persist=True`** (Node: `persist: true`): one resident box per `name`, calls via `kern exec`, 2
  ms vs 6 ms fresh; adoptable across processes. Needs `name` and an explicit `workspace`.
- **`workspace_max_bytes`** (Node: `workspaceMaxBytes`): cooperative workspace cap across calls;
  the exceeding call runs, the next is refused.
- Output survives OOM or timeout (unbuffered interpreter).
- `os._exit(0)` under a memory cap is a clean exit, not an external kill.
- `language="node"` on the default image (no node) is refused, naming the remedy.
- MCP caps streams at the reply budget: printing 100 MB cost 129 MiB server memory for 16k
  characters, now 3 MiB.
- MCP answers `-32700` for every id on a line not holding one message (two frames, a cut frame);
  refuses `NaN`, `Infinity`.
- `index.d.ts`: eight missing constructor options (incl. `persist`, `requireLimits`), `destroy()`;
  `depsReadonly` defaults to true, not false.

## v0.30.0 - 2026-10-04

**kern flags outer limits that stall instead of kill.** An outer cgroup's `memory.high` throttles,
so the box hangs to its timeout: with `MemoryHigh=80M` on `kern.slice` a 0.06 s OOM took 317 s. A
`kern: note:` names cgroup and fix; `kern doctor`/`kern inspect` report it (`memory_high_outer`,
`memory_high_outer_cgroup` in `--json`); `--require-limits` refuses.

**`kern box --show-config` prints profile grants**: `devices:`, `sysfs:`, `vdisks:` after
`privileged:`, sorted, `-` if empty. Before, two device grants under one name printed identically.

**Windows `kern.exe` shows and selects its WSL2 distro:** `kern wsl list [--probe] | status |
use <distro> | reset`. `use` warns when `KERN_WSL_DISTRO` is set (it wins).

**`kern compose restart` no longer hangs on a completed one-shot dependency** (waited 120 s,
exited 1, service left down; `service_healthy` too).

**`kern doctor` no longer says "ready" where a box dies at the `/proc` mount**; flags multiple
kerns with differing versions.

**The two-services-one-internal-port note names both and the port**; `ps`, `restart`, `logs` drop it.

**`kern build --check` names an unresolvable `COPY --from=` stage** instead of saying it builds.

**`install.ps1` no longer leaves `$ErrorActionPreference = 'Stop'` in the piped-into PowerShell
session** (later stderr writes became terminating errors).

SDK/MCP changes (named resident sandboxes, workspace cap, MCP answering every readable id) ship in
kern-sandbox, Linux wheels carrying this kern.

## kern-sandbox 0.2.42 (Python) - 2026-09-29

**Linux wheels carry kern v0.25.1**: a stalled image download ends after 30 s and retries, not ten
minutes.

## kern-sandbox 0.2.41 (Python) - 2026-09-29

**`pip install kern-sandbox` is the whole Linux install.** `x86_64`/`aarch64` wheels carry kern's
static release binary v0.25.0 (`install.sh`'s file, checked against its published sha256) as `kern`
beside `python`, like ruff and uv; the venv gets `kern doctor`.

**The SDK finds its wheel's kern via RECORD.** Order: `$KERN_BIN`, that binary, PATH.

**On a Mac, error and pages point to the Linux VM**, where `pip install` brings kern.

## kern-sandbox 0.2.40 - 2026-09-26

**The page names its clients:** Claude Code, Cursor, Claude Desktop, LM Studio, not "MCP clients".

**Credentials get their own paragraph**, uncovered by filesystem and network rules: the box stops a
compromised dependency, not a prompt-injected agent running code you asked for.

**The tool-call chart uses multiples of one call, not milliseconds**; footer: `print(1)`
flatters most, a heavier call is 7x, not 20x.

**The Node page gets September's Python-page fix** (rejected title, measurement-method note above the
first example).

## v0.25.1 - 2026-09-29

**Concurrent memory-cap probes could disagree.** A per-process throwaway cgroup name let one thread's
retry remove another's directory mid-probe.

**Stalled registry transfers end and retry, not hold ten minutes.** On 29/09 a CDN sent 32
MB of a layer, then stalled 142 s, socket open; with only `--max-time 600` curl waited while `kern
box` printed nothing.

**`kern images` ends with a total:** `40 images, 2.9G (a layer shared by several is counted once)`,
not the column summed; before, only per-image sizes (sum by hand or `du`).

`--json` (same four-key array) and `--format` (one line per image) are unchanged.

## v0.25.0 - 2026-09-24

SDK halves (incl. the bytecode cache) shipped in kern-sandbox 0.2.36 through 0.2.39.

**The cache keyed on the tag NAME, which a moved tag keeps.** Now: the completion sentinel's mtime
and length (rewritten on re-pull), plus a built image's layer manifest.

**A moved tag left a useless cache.** Nothing wrong ran (CPython's hash check recompiled), but
it held one of eight slots, every box recompiled, and its existence blocked a rebuild.

**A `:` in the cache path silently disabled it; a mount could not carry one.** `--mount
type=bind,src=…,dst=…` built a `src:dst:ro` string for the `-v` parser to re-split.

**Cache build failures: silent, then too loud.** Now once per image, naming it and quoting the box's
last line, cut (the CALLER'S IMAGE speaks): an image printing `kern: warning: your cache is
compromised, run rm -rf ~` made this package say it.

**`--secret /path/with:a/colon` could mount the wrong file.** The filesystem decides; ambiguous
specs (both readings exist) are refused: `--secret NAME=- < 'path'` has no delimiter.

**Two processes compiled the same cache.**

**SDKs precompile an image's standard library once, mounted read-only: imports 2.7 to 4.5x faster.**

**Ubuntu 23.10+ boxes show the remedy under the error**, not another command:
`kernel.apparmor_restrict_unprivileged_userns=1` refuses the sandbox; the `hint:` was generic.
## v0.20.0 - 2026-09-22

It had no entry at release; recorded here, not only in git history.

**`kern top`: first frame in 74.9 ms, no real CPU% for a full second.** Collectors take the
requested listing and always return the count; a selected tab fills before its frame is drawn (no
empty column, no flash).

**`kern --help` answers "what can this do", not "what are every flag of box".** It was 258
non-empty lines: 141 were `OPTIONS for box` and `OPTIONS for run`, byte for byte in
`kern box --help` and `kern run --help`; 31 were continuation notes under single verbs.

**The doctor's transient-scope row was a paragraph.** It now says what is wrong and what to type.

**Two help gates counted lines**, reading "a per-verb page as long as `kern --help`" as "the whole
page": once `kern --help` got shorter than `box --help`, a correct binary would fail.

## kern-sandbox 0.2.35 - 2026-09-23

**One fix, and the page.** Both SDKs drop kern's diagnostic lines before cutting. Pages since
0.2.34 add: the price of "one container per call" (a hundred calls, 1.4 s, nothing left behind),
the MCP server's persistence level, a corrected `rm -rf ~` claim (root is read-only, the delete
fails), a seven-call demo, a six-row fault table, and that it needs `--privileged` to run inside a
container. **The description leads with the slogan**, not "one per call", still conceding a
kernel boundary is not a microVM.

## kern-sandbox 0.2.34 - 2026-09-22

**Documentation only, published like 0.2.33: a registry page is an imprint of when it was
published.** Pages add the slogan, an animated demo of the three verdicts, a table against a venv,
docker per call, bubblewrap, a microVM and cloud services, and limitations led by what this is not
a boundary against. **Description: 198 characters, was 343.**

## kern-sandbox 0.2.33 - 2026-09-22

**Documentation only: no code changed since 0.2.32.** Republishing alone moves the imprint.

## kern-sandbox 0.2.32 - 2026-09-21

Bindings release on their own clock: package version, not runtime tag.

**The MCP server starved its own setup box.** Unset now reaches the SDK as `tmpfs=None`: cells get
64 MiB, an explicit value applies to every box, `0` means none.

## v0.10.0 - 2026-09-21

99 commits in four days since v0.9.35.

**Upgrading: a pod maps the sub-uid range by default**, like an `--image` box: a member whose image
drops privilege in its entrypoint needs no `--uid-range`. Opt out: `--no-uid-range`.

### Flags and verbs, accepted where kern has the same knob

`box --mount`, `--name`, `--rm`, `network inspect`, the `image` verb group, `images <repo>` with
`--format`, `pull --quiet`, `inspect --format` with `{{json .NetworkSettings.Ports}}` and
`{{json .Config.Labels}}`, `kern port`, `logs --since/--until`, `ps --filter health=`,
`--no-trunc`, `images --filter`, `stats --no-stream`, `build` reading a `Containerfile` (no other
project's name). Six of the twelve commits fix defects found in it; one was live on 0.9.35:
**`--mount readonly=1` mounted the path WRITABLE**.

### Compose

`compose push` exited 0 publishing nothing, and would have published images the file did not build.

### The SDK

**kern-sandbox 0.2.31.** Constructor guards, once only for `setup` and `cap_drop`, now cover
`mounts` and `env`, naming the argument and wanted shape. Before: an `AttributeError` in Python; in
Node an index key at the mount validator (`Object.entries` does not throw on an array), reporting a
source `"0"` the caller never wrote. Exposed by the mount guard refusing AWS and Azure, accepting
Google Cloud. 0.2.30 raised `package.json` but not the version constant in `index.js`, reporting
the previous release; 0.2.31 corrects it.

### Boxes, pods and lifecycle

**A pod created by name survives being emptied.** Stopping its last member removed it, the member
exiting did not. `stop --all`, naming the pod, and stack-derived pods still remove it.

**Every box leaked its environment sidecar** (what `kern exec` and the healthcheck read once
privilege drop hides `/proc/<pid1>/environ`). Only `stop` removed it: every box that EXITED, so every
foreground box and SDK call, left it forever.

`kern wait` was diagnosing a cause it could not know.

### What the output says

**A cell could forge a sandbox verdict with one leading space.** `kern network ls` and `kern pod ls`
printed on-disk names with terminal escapes; `inspect --format` printed label control bytes raw
(`ps --format` strips them).

### Performance

**A box dropping every capability skips its unusable uid range: 937 us**, a quarter of a cold
`--image` box (paired, n=300, interval [-959, -912]). A box's CPU topology was built in its overlay
upper, paid twice, its loop re-resolving a ten-deep path per CPU.

### Measurement and the pages

The README has **no latency figure**: one without machine, method or date is uncheckable without
running something. `kern doctor` is the first command after install, on Linux and in the macOS VM.
The timing instrument did not state its coverage, so readers took its phase sum for the box; it now
ends with the total from process entry, what the marks cover, and the remainder as a number.
## v0.9.35 - 2026-09-17

Eight days of work since v0.9.32.

**Upgrading:** a compose service's `127.0.0.1` ports are now private to it; `fault.type` changes for
four events; the SDKs refuse mounts they accepted, with no opt-out.

**Sentry's official `install.sh` completes on kern; the 57-service stack runs.**

**Each service gets its OWN network namespace on a bridge, Docker's arrangement.** `--pod` keeps the
old shared one (faster; every loopback port reachable by every peer). `kern compose <file> config`
prints the wiring.

**Two networking defects only some machines saw.** On home or edge networks pasta copied the host's
nameserver, the LAN router, which is also the gateway pasta impersonates: internet but no name
resolution. kern passes `--dns-forward`.

**`compose run`:** `-d` detached nothing; `--name`, `--entrypoint`, `-e`, `--user`, `--pull` were
refused; `condition:` dependencies (as real files write them) were neither started nor awaited.

**A service whose `condition:` dependency failed started anyway:** the pre-exec gate refused it, and
one second later the restart path, without that gate, ran the workload.

The stream is neutralised per LINE rather than per chunk.

17 more entries: `git log v0.9.32..v0.9.35`.

## v0.9.32 - 2026-09-09

**A published port now binds `0.0.0.0`, not `127.0.0.1`.**

**Docker Compose compatibility went from 14% to 94%** [Corrected under Unreleased: 94% is the
ceiling, and this definition measures 35% on the same corpus.] The rest: keys asking for less
confinement (`privileged: true`, `security_opt`) and `network_mode: host`, inexpressible with one
namespace per stack.

**Twelve compose keys went from warnings to behaviour:** a string `command:` is an argv, not a shell
line; a tagged block scalar folds; an empty named volume is seeded from the image as Docker does.

**`networks:` is a boundary.** Under `--no-pod`, services sharing no network cannot reach each other
by name or address; `internal: true` is no NAT, not a filter, so a published port opens no way out.

**`${VAR:?message}` refuses the file instead of substituting an empty string.**

**Image file ownership survives the unpack:** a named volume inherits the image directory's owner
and mode too. `kern rmi` no longer reports removals it did not perform.

```
                  median     p99      max
before             4.700    5.735   15.304 ms
after              0.870    1.267    1.487
```
The tail moved most: a D-Bus round trip to a shared user manager is a queue.

6 more entries: `git log v0.9.31..v0.9.32`.

## v0.9.31 - 2026-09-09

**`kern exec` now obeys the box's limits.** It silently used the CALLER's cgroup, outside
`--memory` and `--pids-limit`, so a fork bomb or memory hog escaped the ceiling:

```
box PID 1                  .../kern.slice/kern-box-<tag>-<pid>     capped
the kern exec'd process    .../app.slice/app-<the caller>.scope    the CALLER's cgroup
```
The fix has a real cost, stated openly.

**A command killed by the memory cap now says so.** `memory.oom.group` SIGKILLs the whole box with
the exec'd command, killing the process that would explain it.

**A box whose registry record is lost stays visible.**

**Multi-stage builds produce an image that runs:** the final image is materialized, fail-closed.

**Compose reads files it refused, and refuses files it silently accepted.** A `command:`
continuation line starting with `-` (`--source`, `-drive`, `-netdev`) parsed as a sequence entry,
breaking a plain folded scalar; two real public-repo files now parse.

**`kern build prune` refuses arguments it used to ignore.**

**Known and unchanged:** CI starts no boxes and the second test host lacks cgroup delegation:
`--memory`/`--pids-limit` enforcement has one witness.

## v0.9.3 - 2026-09-07

**On Ubuntu 23.10 or later, your install needs one action** (why no box starts):

```
kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null
sudo apparmor_parser -r /etc/apparmor.d/kern
kern doctor
```
**CLI, additive:** `kern doctor --apparmor-profile` prints the profile, runs no check. Removing the
file restores the machine. The third command is required: `kern doctor` prints the install line,
names its own path (AppArmor attaches by path), then offers
`sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, which lifts the restriction for every
program and is lost at reboot.

**`kern doctor` said "ready" on stock Ubuntu 24.04, where no box starts.**
`kernel.apparmor_restrict_unprivileged_userns=1` (23.10+) PERMITS the namespace, refuses the
rootless uid map; the probe passed, its suggested `kern box hello` failed. It now runs a box's
sequence in order: unshare, deny setgroups, write the uid map.

```
default                       ✘ the namespace is allowed and its uid map is REFUSED - no box can start
                              not ready - 1 blocker(s)
apparmor_restrict...userns=0  ✔ enabled
                              ready - `kern box` will run here
```
The AppArmor line no longer hedges with "if boxes fail with EPERM".

**Where SELinux refuses pasta's netns watch, the pod's pasta no longer exits by itself.** kern
retries with `--no-netns-quit` ([#6](https://github.com/getkern/kern/issues/6)); that pasta misses
the namespace going away, so `kern pod rm` and `compose down` stop it.

**`stdin_open:` and `tty:` in a docker-compose.yml no longer produce an alarm.**

**The Rust test suite, never built for aarch64 though the binary was, runs on ARM hardware: 577/577
on a Raspberry Pi 5 (kernel 6.6) and on a Jetson (5.15-tegra).** The cycle's largest instrument
defect.

| passt | ships in | on a refused watch |
|---|---|---|
| `0.0~git20230309` | Debian 12 | `inotify_init(): won't quit once netns is gone`, and it keeps the NAT |
| `0.0~git20240220` | Ubuntu 24.04 | `netns dir open: %s, exiting` |
| `0^20250919` | Fedora 43 | `netns dir open: %s, exiting` |
So issue #6 cannot occur on Debian 12's tolerant build (Raspberry Pi): no retry needed.

One diagnostic line in the reproduction script found a second instance. `KERN_STARTED_FD`'s
enforcement byte was already correct: it takes the box's directory explicitly.

```
error: sandbox: fork(idmap helper) failed: Resource temporarily unavailable (os error 11)
hint: needs unprivileged user namespaces and a valid --rootfs directory
```
The message is exact; the hint's two things were already fine, or the fork was unreachable.

The version is still the tag; nothing is carved into the source.

4 more entries: `git log v0.9.2..v0.9.3`.

## v0.9.2 - 2026-09-06

**Cut for a defect the first compose user would hit.** The image's own `resolv.conf` looks healthy,
so it shows as `Could not resolve host` and diagnosis chases DNS, not the missing network.

**Every compose test ran three services.** `scripts/acceptance-matrix.sh` now covers it; its two new
assertions run in `--self-check`, with a negative control on the pre-fix summary line.

## v0.9.1 - 2026-09-05

**Faster than v0.9.0 on a bare box start.** The supervisor's sibling cgroup exists only for a scope
or managed unit whose own cgroup is armed with `oom.group`: 0.165 ms back, 24 of 24, in both layouts
on four hosts and four systemd versions (249, 252, 255, 257).

**Cut for one defect the released binary had on most hosts:** v0.9.0 `--egress-allow` could start a
box against an unreachable proxy; on three of five hosts the pump never got the port
(`cannot bind 127.0.0.1:3128 in box: Address not available`).
