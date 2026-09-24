# Changelog

**CLI stability.** Since v0.7.0 the verbs, their flags and the `--json` shapes change incompatibly
only on a minor bump, never on a patch, and only after a deprecation entry here one release earlier.
`--json` is additive, so consumers must ignore unknown fields. A `cli_surface_is_frozen` test fails
the build on any undocumented change. Full detail for any entry is in the git history.

## Unreleased

**The SDKs precompile an image's standard library once and mount it read-only, and imports get 2.7 to
4.5x faster.** A box compiles the image's stdlib in the background, into a per-image directory under
`$XDG_CACHE_HOME`, and every later box mounts that tree READ-ONLY with `PYTHONPYCACHEPREFIX`. On by
default in both bindings, one cache shared by them, `pyc_cache=False` / `pycCache: false` to turn it
off. Measured with the arms alternated and a null control first: `import json,re` in a fresh box goes
from 182.6 to 67.4 ms on a small VPS and from 46.1 to 17.1 on a desktop; three heavier imports go
from 572.8 to 196.1 ms. `print(1)` is unchanged, which is the honest half - the gain is in imports,
which is what code written by a model actually does. READ-ONLY is the design: a shared WRITABLE
bytecode cache is code execution between calls, since a `.pyc` is validated on its source's timestamp
and size. The cache validates on the source's HASH instead of its timestamp, so an image rebuilt with
fixed timestamps (BuildKit's `rewrite-timestamp`, apko, Nix, distroless) cannot make a box run stale
code. The first session pays for the build and uses it from the call after it lands; a cache another
process swept away is rebuilt rather than adopted empty.

**A box on Ubuntu 23.10+ now reads the remedy under the error instead of being sent to another
command.** `kernel.apparmor_restrict_unprivileged_userns=1` refuses the sandbox, the message was
already exact about what happened, and the `hint:` line was the generic one. It now prints
`kern doctor`'s own text, so the exact command to run appears under the error with the real path of
the binary.

**`kern top` drew its first frame in 74.9 ms and showed no real CPU% for a full second.** Both were
work nobody had asked for. The tab bar prints a count per tab, so every list has to be ENUMERATED on
every frame, but only the tab on screen needs its CONTENTS read, and the two costs are nothing alike:
on a host with 342 volumes, 316 images and 921 build records, one frame issued 2186 `open` calls and
46085 `lstat`, almost all of it for panes that were not being drawn. Each collector now takes the
listing it is asked for and returns the count either way, and the tab a reader switches to fills
itself in before that frame is drawn, so there is no empty column and no flash. Sharing one
layer-size map across an image sweep removed a second copy of the same waste: layers are shared
between images and the on-disk sidecar is per layer, so a single listing re-read the same file once
per referring image, 889 reads for 364 layers. The first frame is 5.6 ms, 2678 syscalls. The first
frame with a true CPU percentage in it, which needs two samples and so cannot be immediate, is
130 ms rather than 1011: the first wait is short and the steady one stays at a second.

**`kern --help` answers "what can this do", not "what are every flag of box".** It printed the whole
reference: 258 non-empty lines, of which 141 were the `OPTIONS for box` and `OPTIONS for run` blocks
that `kern box --help` and `kern run --help` already serve byte for byte, and another 31 were
continuation notes under single verbs. Five screens scrolling past the first command somebody types
after installing. It is 95 lines now, every verb still listed, and nothing is lost: what it hides,
`kern <verb> --help` shows, which is where someone asking about a verb looks. There is still exactly
ONE reference text and two filtered views of it, so the views cannot drift from it.

**The doctor's transient-scope row was a paragraph.** It carried two measurements taken on other
machines (an Arduino UNO Q and a Raspberry Pi 5), the exit code `kern exec` uses, an environment
variable and what a health probe does. Read on WSL by someone who had just installed kern, that is a
debug dump about somebody else's hardware. It now says what is wrong and what to type. The
per-host figure it used to print is gone too: a number in an advisory line ages, cannot carry its
method, and is not what the reader acts on. The measurements are in BENCHMARKS.md, with the machine
and the method beside them. The TUI's `gone in ~1 ms` goes for the same reason.

**Two help gates were anchored on a line count** and would have failed a correct binary: they read
"a per-verb page as long as `kern --help`" as "it is answering with the whole page", which stopped
being true the moment `kern --help` became shorter than `box --help`. They now assert the property
directly, that a per-verb page carries neither the `COMMANDS:` section nor another verb's option
block, which is strictly stronger: sabotaged, it catches the fallback in four places.

## kern-sandbox 0.2.35 - 2026-09-23

**One fix, and the page.** When a box failed to start, the `SandboxError` message was the first 500
characters of kern's stderr, and kern writes its notes and warnings before the error. Inside a
container, the shape a Google Colab runtime has, a 391-character warning pushed the cause to
character 557, so the message said the box "still runs" about a box that had not started. Both SDKs
now drop kern's diagnostic lines before cutting.

What the registry pages gain since 0.2.34: the price beside "one container per call" (a hundred calls,
1.4 s, nothing left behind), which persistence level the MCP server gives, a corrected `rm -rf ~`
claim (the root is read-only, so the delete fails), a seven-call demo, the fault table at six rows,
and the line saying it does not run inside a container without `--privileged`.

**The package description leads with the slogan** instead of "one per call", and keeps the sentence
conceding that a kernel boundary is not a microVM. 217 characters, under npm's 255.

## kern-sandbox 0.2.34 - 2026-09-22

**Documentation only, and published for the same reason 0.2.33 was: a registry page is an imprint of
the moment it was published.** 0.2.33 went out at 19:00 and the launch page was rewritten for three
hours afterwards, so PyPI and npm were serving the 2937-word version while GitHub served a 1236-word
one. Same package, two different products depending on where a reader landed. The rule this repeats
is its own: close the page, then publish.

What the registry pages gain: the slogan, the animated demo of the three verdicts, the table
comparing this to a venv, docker per call, bubblewrap, a microVM and the cloud services, and a
current-limitations section that leads with what this is not a boundary against.

**The package description is 198 characters instead of 343.** npm truncates at 255, so the sentence
conceding that a kernel boundary is not a microVM was being cut off the page it belongs on, which is
worse than a long description: a claim arriving without its caveat.

## kern-sandbox 0.2.33 - 2026-09-22

**Documentation only: no code changed between 0.2.32 and this.** The package page on PyPI and npm is
an IMPRINT of the moment it was published, not a view of the repository: 0.2.32 went out before the
page was cut in half, before the comparison chart, and before the install block named the
`python3-venv` package that Debian and Ubuntu ship separately. A reader arriving from the registry
rather than from GitHub was reading yesterday's page and hitting `ensurepip is not available` with no
hint. Republishing is the only way to move that imprint.

## kern-sandbox 0.2.32 - 2026-09-21

The bindings are released on their own clock, so this section carries a package version rather than
a runtime tag. It needs no new binary: v0.10.0 runs it.

**The MCP server starved its own setup box.** It always passed an explicit
`tmpfs`, and the SDK skips only its OWN default there, so `KERN_MCP_SETUP="pip install numpy pandas
matplotlib"`, the block printed in the package README, failed with `OSError [Errno 28] No space left
on device`. Unset now reaches the SDK as `tmpfs=None`: cells still get 64 MiB, an explicit value
still applies to every box, `0` still means none. The test that covered this asserted the knob and
not the argument, so the new one reads what the server hands to `Sandbox(...)`.

## v0.10.0 - 2026-09-21

Four days of work since v0.9.35, and 99 commits. Each line is the change; how a defect was found and
why the fix is shaped that way is in the commit it came from (`git log v0.9.35..v0.10.0`).

**Read these first if you are upgrading.** The binary answers to `kern` and to nothing else. **A pod
maps the sub-uid range by default**, as an `--image` box already did, so a member running an image
that drops privilege in its entrypoint works without `--uid-range`; `--no-uid-range` is the opt-out.
**`ps --last N`** lists the N most recent boxes across live and exited, newest first.

### Flags and verbs, accepted where kern has the same knob

`box --mount` and `--name`, `--rm`, `network inspect`, the `image` verb group, `images <repo>` with
`--format` and `pull --quiet`, `inspect --format` answering `{{json .NetworkSettings.Ports}}` and
`{{json .Config.Labels}}`, `kern port`, `logs --since/--until`, `ps --filter health=`, `--no-trunc`,
`images --filter`, `stats --no-stream`, and `build` reading a `Containerfile` so a project need not
carry another project's name.

Six of the twelve commits that built this surface are FIXES the reviews found in it, and one was
live on 0.9.35: **`--mount readonly=1` mounted the path WRITABLE**, which is the worst shape a
compatibility gap can take, the flag asking for less privilege granting more. `--mount` is now parsed
with the reference's CSV grammar rather than a quote toggler, which had changed the path being
mounted; its keys are case-insensitive and its paths are not; `type=bind` with a missing source is
refused instead of creating it and starting a box whose mount is empty; `type=tmpfs,...,readonly`
mounts read-only; and the keys kern has no equivalent for are refused BY NAME rather than by a
grammar dump. `--filter label=k=` matches a label stored with an empty value. `--rm` and `--restart`
are no longer both applied. `images <repo>` is no longer dropped when a flag comes first.
`network inspect -f '{{.Name}}' proxy` no longer inspects a network called `{{.Name}}`.
`{{json .Name}}` prints `"/web"`, quoted. A label that went in and could be filtered on now comes
back out.

### Compose

`compose push` exited 0 having published nothing, and would have published images the file did not
build. `compose wait` exited 0 whatever the service did. `compose down -v` could not remove the one
volume every stack has. `up --no-deps` waited out its whole timeout on a dependency that had already
completed. `up --force-recreate`, `--no-recreate` and `-V/--renew-anon-volumes` are honoured.
`kern compose <verb>` finds the file the way `kern up` already did. A trailing backslash in a
`command:` deleted a character and sometimes an argument; an escaped quote truncated it silently.
`kern box --network <name>` joins a running pod, which is what a stack is. A new gate runs a real
deployment's command shapes against a real stack.

### The SDK

**kern-sandbox 0.2.31.** The constructor guards that existed for `setup` and `cap_drop` and not for
the rest: `mounts` and `env` in the wrong shape name the argument and the shape they want, instead
of escaping as an `AttributeError` in Python or reaching the mount validator as an index key in Node,
where `Object.entries` does not throw on an array and reported a source of `"0"` the caller never
wrote. `on_stdout`/`on_stderr` must be callable. A callback that RAISES is still swallowed, because
it must not kill the output drain and hang the box on a full pipe, but says so once with a
`RuntimeWarning` instead of leaving a successful-looking run whose callback never saw a line. A
`workspace` pointing at a FILE is refused by name rather than raising `FileExistsError` out of
pathlib.

The mount guard refused AWS and Azure and accepted Google Cloud, which is the asymmetry that made it
visible. `kern-pi`'s lock pinned an SDK nineteen releases old while its own range resolved to the
current one on the registry.

0.2.30 was published with `package.json` raised and the version constant in `index.js` left behind,
so the package reported the previous release; 0.2.31 corrects it. npm cannot unpublish, so 0.2.30
stays on the registry reporting 0.2.29.

### Boxes, pods and lifecycle

**Stopping a pod's last member removed the pod, and letting that member exit on its own did not** -
the same end state with two outcomes depending on how it was reached. A pod created by name now
survives being emptied; `stop --all`, naming the pod itself, and a pod derived from a stack still
tear one down. What a pod shares is asserted rather than described: members share the **user** and
**network** namespaces and nothing else, with mount, pid, ipc, uts and cgroup private to each, each
assertion carrying a negative control.

**Every box leaked its environment sidecar.** kern records a box's environment so `kern exec` and the
healthcheck can read what `/proc/<pid1>/environ` stops giving them once the box drops privilege, and
only `stop` ever removed it: a box that simply EXITED left it behind forever, which is every
foreground box and every SDK call. Measured after one day of benchmarking, 4433 files and 13 MB in a
tmpfs with zero boxes alive. Removed in the teardown now, and `prune` sweeps the directory for the
box whose supervisor was killed first.

`kern wait` was diagnosing a cause it could not know. `kern rmi` charged the image you named for
somebody else's debris. A pod name reaching the JOIN path was not validated, only the one reaching
CREATE. `kern login` checks credentials before storing them and has a real `--password-stdin`.
`exec -i` no longer allocates a pseudo-terminal, so `exec -i <box> psql … < file.sql` reaches EOF
instead of hanging. `build -t a -t b` keeps both names. `kern build --check` reports what kern does
with a Dockerfile without building it.

### What the output says

**A cell could forge a sandbox verdict with one leading space**, and the fix is a prefix at column
zero plus two witnesses. **A registry could reorder the line kern printed** without using a single
control character. `kern network ls` and `kern pod ls` printed a name off disk without stripping
terminal escapes; `inspect --format` printed a label's control bytes raw where `ps --format` strips
them. Four tables had a fixed NAME width and `kern history` printed two different boxes as one line.
A piped `kern top` reported every box at 0% CPU. `kern top` can reach past the first screenful, says
what its Boxes tab lists, and a shifted key acts on the whole tab after asking. Three `doctor` rows
were a paragraph wide, and the GPU row is no longer a warning. `ps -a`'s help says the exited rows
are DETACHED boxes, because the exit note is written by the supervisor and a foreground box has none.

### Performance

**A box that drops every capability stops paying for a uid range it cannot use: 937 us**, a quarter
of a cold `--image` box, measured paired at n=300 with an interval of [-959, -912]. Mapping the range
forks two setuid helpers, and under `--cap-drop ALL` it buys nothing: `chown` to another uid fails
inside the box either way. Any `--cap-add` cancels the skip, which is the conservative reading, and
`--uid-range`, a non-root `--user` and `--ssh` still outrank it.

The CPU topology a box sees was built in its overlay upper and paid for twice; that same loop
re-resolved a ten-deep path once per CPU.

### Measurement and the pages

The README publishes **no latency figure** at all: a front page states a number with no machine,
method or date beside it, and it is the one claim there nobody can check without running something.
The canonical figure is the `box --image` row of BENCHMARKS.md, which carries all three, and
`stale-numbers.py` checks every other claimant against it. That figure is **3.6 ms**, and the page
says what it is: the fastest replica of an idle machine, where of 34 replicas taken the same day none
came in below it, the median of all was 4.05, and one unchanged binary spread 3.65 to 4.31 within a
few hours. A reader measuring nearer 4 on a working machine is seeing the same box on a different
afternoon.

`kern doctor` is now the first command after install, on Linux and inside the macOS VM. The note that
Ubuntu 23.10+ needs one root command first was already in the README, two hundred lines below the
install block, arriving after the moment it is needed.

The timing instrument could not state its own coverage, so a reader summed its phases and believed
the sum was the box; it now closes with the total from process entry, what the marks cover, and the
remainder as a number. Two comments in one codebase disagreed about the label filter, and the
measurement settled it.

## v0.9.35 - 2026-09-17

Eight days of work since v0.9.32. Each line is the change; how a defect was found and why the fix is
shaped that way is in the commit it came from (`git log v0.9.32..v0.9.35`).

**Read these first if you are upgrading:** each compose service gets its own network namespace on a
bridge, so a port a service binds on its `127.0.0.1` stays private to it; `fault.type` reports a
different value for four events; and the SDKs refuse mounts they used to accept, with no opt-out.
Every one of them is described below.

**Sentry's official `install.sh` completes on kern, and the 57-service stack runs.** Measured end to
end against `getsentry/self-hosted` at 26.8.0: every image built, the migrations, `compose up
--wait` reporting `57 service(s) ready`, the web UI answering 200 and the API 200, then `down`
stopping 57 of 57 with nothing left. One edit to the official tree was needed and is not kern's to
make: its minimum-version gate compares `docker version` against Docker's numbering, and kern
reports kern's version. Twenty-one defects were fixed to get there, and fourteen of them are in the
`docker` and `compose` surfaces rather than in the sandbox.

**Each service gets its OWN network namespace on a bridge, which is Docker's arrangement.** A port a
service binds on its `127.0.0.1` stays private to it. `--pod` keeps the old single shared namespace,
which is faster and makes every loopback port reachable by every peer, and `kern compose <file>
config` prints which wiring a bring-up will use.

**Two networking defects that only some machines could see.** On a home or edge network a box had
internet and could not resolve a name, because pasta copies the host's nameserver into the box and
on such a network that address is the LAN router, which is also the gateway pasta impersonates; kern
passes `--dns-forward` now. And on every host whose NIC is called `eth0` (WSL2, most cloud VMs) a
multi-service stack had no outbound at all, a regression against v0.9.32: pasta named its tap after
the host's interface and collided with the name kern gives the workload's. kern names that interface
itself now, per namespace.

**`compose run` was missing most of what a script passes it.** `-d` detached nothing; `--name`,
`--entrypoint`, `-e`, `--user` and `--pull` were refused; the one-off started none of the
dependencies written with a `condition:`, which is how every real file writes them, and did not wait
for them. Its stdout is the workload's now, too: kern's build lines and pod narration went to the
same stream, so `state=$(docker compose run --rm -T svc ...)` captured kern's sentences ahead of the
answer.

**A service whose dependency failed was held back and then started anyway.** With a `condition:` on
a dependency that fails, the pre-exec gate refused the exec, and one second later the restart path,
running without that gate, ran the workload. In the same area: a `restart:` service never restarted
after its first exit, and a failed `up` left its surviving boxes rebuilding forever. A box that
never started is not a workload that exited, and the three cases are now told apart.

**A database that was ready in ten seconds reported `starting` for five minutes.** Docker 25+ splits
the probe cadence in two, `Interval` for the steady state and `StartInterval` for the start period,
and kern read only the first: an image declaring `Interval 300s, StartPeriod 300s, StartInterval 5s`
had its first probe land 300 seconds in, and everything gated on `service_healthy` waited with it.
Both are honoured now, from the image config and from a Dockerfile's `HEALTHCHECK --start-interval`,
and `kern box --health-start-interval <sec>` exposes it.

**An explicit `docker.io/` prefix broke every pull**, and it is not an exotic spelling: it is
Podman's recommended style and what Immich's official compose file ships. `docker.io` and
`index.docker.io` resolve to Docker Hub's API host now, and `docker.io/alpine` means
`library/alpine` exactly as bare `alpine` does.

**Defaults and refusals a real file runs into.** A service with no `pids_limit:` gets 2048 tasks,
not the sandbox's 512, because ClickHouse aborts under 512. `compose pull` no longer goes to a
registry for images the file said never to pull. `ulimits:` written as a one-line mapping is applied
instead of reaching the box with its braces. `network_mode: host` is applied as Docker applies it
and now SAYS what it removes. A GPU reservation says the service runs WITHOUT the device. A
dependency that never becomes healthy fails naming the box and carrying its own repair, rather than
advice about how to write a compose file.

**The sandbox SDKs: `fault.type` changes value for the same event, which is why 0.2.0 was a MINOR
bump.** An external `kern stop` was `oom` and is now `killed`; a workload that CHOOSES `exit 137` is
no longer a fault; a crash is `fault=None` with `128+signal`; a `KERN_BIN` that is not kern raises
instead of reporting success. `fault` is read from kern's own descriptor, so a cell cannot forge a
verdict from its output. 0.2.0 through 0.2.22 are on PyPI and npm, and 0.2.22 is what a bare
`pip install kern-sandbox` or `npm i kern-sandbox` resolves to today.

**A box that never started is a verdict of its own, not an exit code to guess at.** It is
`fault.type == "startup_failed"` from `run_code`/`run` and raises from `kernel()`. Branch on
`fault`, not on `exit_code`: a box that never ran exits 1 exactly like a script that did.

**The SDKs refuse a mount that would hand the box the sandbox's own control plane.** kern's state
(`$XDG_RUNTIME_DIR/kern`, `$XDG_DATA_HOME/kern`, the image cache, the config dir), the host's own
sources (`/`, `/etc`, `$HOME`, the docker socket) and any path with a credential directory in it
(`.ssh`, `.aws`, `.kube`, `.npmrc` and the rest). There is no opt-out, deliberately: a job that
needs one credential should be given that one file in the workspace. Workspace I/O refuses what it
cannot contain and says which: an absolute path, a `..` escape, a symlinked component at any depth,
a device planted at the name, a file over `max_bytes`.

**The MCP server names the kern that ran the code** (`[exit 0 in kern 0.9.32]`), and its tool
description leads with what a client's own shell cannot do. An independent test wired the server into Cursor
correctly and the agent answered from its own python, never calling the tool. An argument a tool
does not have is refused with `-32602` rather than dropped, and box output reaching a model has
terminal escapes stripped and both surfaces' framing neutralised, so a forged marker reads `[printed
by the code, not the sandbox: ...]`.

**`kern-pi` 1.0.1 on npm.** 1.0.0 asked for `kern-sandbox: ^0.1.41`, and for a zero-major version a
caret range stops at the next minor, so a Pi user's model was reading fault verdicts from before
this year's chain.

**Runtime and CLI.** A service stopped and started again was unreachable by its peers for 29
seconds, because its `veth` got a random MAC each time; a member's address is derived from its IP
now, as Docker's is, and the same restart takes 176 ms. A `build:` on a Debian or Ubuntu base could
not be built at all, because those images ship directories at mode 0700 owned by a subordinate uid.
`docker version --format` ignored its template and exited 0, so a script reading it carried on with
the wrong string. An image cached by an older kern is refreshed rather than re-fetched. `kern
inspect <image>` answers for an image, and a `--format` field kern cannot answer truthfully is
refused by name rather than answered wrongly. `EXPOSE` reaches the image config. `--memory 64` is 64
BYTES and the message says so. A FIFO as a volume source is refused instead of hanging the box
forever.

**`kern logs -t` prints when each line was written.** Docker has had `--timestamps` since
forever and a reader comparing a box's output against anything else needed it. The time comes from a
`<log>.idx` sidecar the log pump writes beside each log, so the log file itself stays byte-for-byte
what the box printed and the pump keeps its zero-copy `splice` path: nothing is parsed or reframed on
the way through. A mark is recorded at most every 100 ms, so a stamp is the start of the
bucket a line falls in and never later than the line itself. The index is bounded at a sixteenth of
the log's own cap: past that its marks are thinned by half and the interval doubles, so a box that
runs for days loses resolution instead of growing a file without limit. A log written by an older
kern has no index and prints `-` in the time column rather than a time nobody recorded, and so does a
rotated generation, because rotation makes every offset in the index mean a different byte.

**What `-t` is not.** `-f` is a diagnostic stream and not an audit log: under load a line written
between the tail read and the follow can be dropped, which is stated in `--help` rather than fixed
with machinery nobody asked for. Time is never reordered. And a byte-capped rotation splits whatever
line it lands in, so the first bytes of a fresh generation are the tail of a line that started in the
previous one; `-t` stamps that fragment like any other line, correctly but confusingly.

**The Pi extension neutralises box output that becomes model text.** A cell that prints
`[sandbox: oom]` or `[exit 137, ...]` is forging a verdict about itself in the channel a model decides
with, and the SDK's other two agent surfaces have refused that for a while: this one did not. It now
does, on the paths where bytes become text - a command's stdout and stderr, grep's file contents, a
directory listing, a glob's paths - and deliberately NOT on `readFile`, which returns a Buffer and
serves images: stripping control bytes there would corrupt every PNG the agent reads. Neutralise at
the text boundary, never at the byte boundary.

The stream is neutralised per LINE rather than per chunk. The markers are anchored at a line start
and output arrives in arbitrary pieces, so a chunk can begin mid-line and a marker can be split
across two: measured, per-chunk both misses a marker broken in half and labels one that is merely
quoted in the middle of a sentence.

**`kern logs -f` stopped showing output after the first rotation, and said nothing.** It followed an
open descriptor rather than the name, so when the pump renamed the active log and opened a fresh one
the follower kept polling a file nobody writes to any more. Measured: a box that printed 120 lines
after its rotation showed **zero** of them, while all three generations sat on disk. Rotation is the
default at 16 MiB, so this was every long-running box, and `kern attach` had it too. It follows the
name across rotations now, the way `tail -F` does and `tail -f` does not.

**A timestamp can no longer go backwards, whatever the index says.** At a rotation seam the last line
of one generation and the first of the next are answered by two different indexes, which measured 103
ms backwards across the seam. Rather than chase every ordering between a pump that renames, truncates
and compacts and a reader that polls, the reader holds a floor: a stamp is never older than one
already printed. The cost is stated in the code - across a seam the column repeats an instant instead
of showing a slightly older one - and it can never invent a time that is too new. A reader whose file
was rotated away says `-` instead, because the index in front of it describes a different file.

**`kern logs` could report that a busy box writes no log at all.** A rotation renames the active file
and opens a new one, and a reader that resolved the name in between found nothing, or opened a
descriptor to a file that had just been renamed away. Resolving and opening are one retried operation
now. Found at roughly 1 read in 6000 by a new concurrency battery,
`scripts/logs-timestamp-battery.py`, which drives six readers against a box rotating every few KB and
one whose index compacts underneath them, and looks for a time that goes backwards, a torn record read
as valid, and a line with no time column anywhere but at the end.

**The compatibility rate ships with its corpus and its definition.** The v0.9.32 claim of "14% to
94%" was the CEILING under a permissive definition; the strict one measures 35% on the same 259
files. Both numbers are in [DOCKER-COMPAT.md](docs/DOCKER-COMPAT.md) with the census scripts that
produce them.

**Tests, gates and examples.** 1340 Rust, 512 Python and 110 Node tests, with the count gated
against the README. New batteries and gates, all in CI: `fault-taxonomy-battery.py` (27 cases),
`docker-vocabulary.py`, `md-links.py`, `launch-dryrun.py`, `e2e-semantic.py`,
`build-corpus-census.py`, `declared-bind-census.py`, and a `loopback-census.py` whose zero means
something. `examples/` moved from 103 flat files into eight directories, nothing deleted.


## v0.9.32 - 2026-09-09

**A published port now binds `0.0.0.0`, not `127.0.0.1`. Read this one.** `-p 8080:80` and a compose
`ports: "8080:80"` bind every interface, which is what Docker does and what a file written for Docker
means. Until now kern bound loopback and warned, so a stack that looked published was reachable only
from the host. `[kern] publish_bind` in `kern.toml` is a ceiling no file can widen, and an explicit
`127.0.0.1:8080:80` still means loopback.

**Docker Compose compatibility went from 14% to 94%**, measured before and after on the same neutral
corpus of 259 files, one per repository, sampled across 733 repositories: the share of files kern
runs with no behavioural difference from what the file says. [Corrected under Unreleased: 94% is the
ceiling, and this definition measures 35% on the same corpus.] What remains is dominated by keys asking
kern to be less confining than it is (`privileged: true`, `security_opt`) and by `network_mode: host`,
which one namespace per stack cannot express. The earlier "15% irreducible" was an artefact of a
corpus weighted toward those keys.

**Twelve compose keys stopped being warnings and became behaviour**, among them `mem_reservation`
(cgroup `memory.low`), `devices:`, `dns:`, `logging:`, `tty:`, `stdin_open:`, `secrets:` long syntax,
and an image's own `HEALTHCHECK` and `STOPSIGNAL`. A string `command:` is now an argv rather than a
shell line, a tagged block scalar folds, and an empty named volume is seeded from the image as Docker
does.

**`networks:` is a boundary, not a warning.** Under `--no-pod`, services with no network in common
cannot reach each other by name or by address, and `internal: true` is the absence of NAT rather than
a filter, so a published port does not open a way out. In a pod the two say something different, and
both are stated at bring-up. A key that is absent means the `default` network, which is 52 of 187
files rather than the 18 that name one.

**`${VAR:?message}` refuses the file instead of substituting an empty string.** A stack whose
password variable was unset started with an empty one.

**An image's file ownership survives the unpack**, so a service running as a non-root user can write
the directories its image gave it. A named volume inherits the image directory's owner and mode, not
only its contents, and `kern rmi` no longer reports a removal it did not perform.

**A service secret is written with the mode the Compose Specification mandates.** It was `0400` in a
`0700` directory, so no image running as a non-root user could read its own secret. `target:`, `uid:`
and `gid:` were read and dropped in silence; they are applied or named.

**`kern run` no longer pays for a systemd scope it does not need: 4.70 ms to 0.87 ms.** It bought its
caps with a transient `systemd-run --user --scope`, one per invocation; it now caps directly under
kern's delegated `kern.slice`, the way `kern box` already did.

```
                  median     p99      max
before             4.700    5.735   15.304 ms
after              0.870    1.267    1.487
```

The tail moved more than the median because a D-Bus round trip to a shared user manager is a queue.
Throughput at concurrency 200 goes from 86 to 4052 runs per second: a path that serialises on a
shared service gets worse as concurrency rises, and a benchmark at concurrency 1 reports that only as
"slow". Finding the delegated slice turned out not to be the same as being allowed to enter it:
cgroup v2 delegation containment needs write access to the `cgroup.procs` of the common ancestor, and
a host outside that tree gets the scope path rather than an uncapped run.

**`kern exec` stopped refusing where there was no cap to escape**, and its fail-closed refusal now
names both causes and the way through (`KERN_ALLOW_UNCAPPED=1`). A `--health-cmd` probe is never
refused. `kern exec` and every health probe now run with the image's environment rather than a bare
one, and `kern stop` sends the stop signal once instead of twice.

**`kern doctor` names the cgroup it probed** on every row that denies a cap, so the verdict can be
checked against `/proc/<pid>/cgroup` instead of taken on trust, and it asks about both directories a
box can be capped in. `kern inspect --json` gains `memory_max_enforced`, read back from the box's own
cgroup: `memory_max` is the value the box was started with, and on a host that caps another way the
two differ.

**A box's terminal has a name.** `tty` inside an alpine box printed "not a tty" while `isatty` said
otherwise, because the `-it` pair was allocated on the host and the box's private devpts does not
contain it. It is now allocated from the box's own devpts and the master passed back over a
socketpair, so both C libraries resolve it. Certified on Fedora 44, CentOS Stream 10, Rocky Linux
10.2, Debian 13, openSUSE Leap 15.6 and Ubuntu 24.04, three with SELinux Enforcing.

**CLI surface: six flags added, none changed or removed.** `--dns`, `--dns-search`, `--dns-option`,
`--log-max-size`, `--log-max-file`, `--secret-mode`. Additive, so nothing that runs today stops
running.

## v0.9.31 - 2026-09-09

**If you use `kern exec`, this release is the one that makes it obey the box's limits.** It did not.
A command run through `kern exec` was placed in the CALLER's cgroup, outside the box's `--memory` and
`--pids-limit`, and said nothing about it. Measured from the host by pid, with the box's own PID 1 as
the control and the exec'd process verified to be in the box's PID namespace:

```
box PID 1                  .../kern.slice/kern-box-<tag>-<pid>     capped
the kern exec'd process    .../app.slice/app-<the caller>.scope    the CALLER's cgroup
```

A fork bomb or a memory hog started with `kern exec` therefore ran without the ceiling the box was
given. Namespaces and seccomp always held; it is the resource cap that leaked. The placement now
happens BEFORE the namespaces are joined, which is the only order in which the kernel permits it:
afterwards the box's own cgroup is the root of its namespace and the common ancestor cannot be named,
so both `clone3(CLONE_INTO_CGROUP)` and a write to `cgroup.procs` answer ENOENT.

**The cost is real and is stated rather than hidden.** Placing before the `setns` means a
`cgroup.procs` write, which takes an RCU grace period: `kern exec` is back to 11.7-25.8 ms on a quiet
host against 1.7-2.2 without it. The faster path shipped in v0.9.3 was faster because it was not
applying the cap. `clone3(CLONE_INTO_CGROUP)` is still used where it is correct, on the box START
path, which places its child before entering any namespace.

**A command killed by the box's memory cap now says so.** `memory.oom.group` kills the whole box, the
exec'd command included, and it goes by SIGKILL, so the process that would explain it is the one being
killed. Before, the caller saw exit `-9` with empty stdout and empty stderr. A reporter now waits
outside the group and names the cause. The exit code is still `-9`: that part belongs to the kernel.

**A box whose registry record is lost stays visible.** kern's registry lives in
`$XDG_RUNTIME_DIR/kern/instances`, and `/run/user` is swept by `systemd-tmpfiles`, cleared on logout,
and deleted by anyone who reads it as scratch. The box does not care: it keeps running. Before, only
kern forgot, completely - the box vanished from `ps`, `kern stop <name>` answered "no running box",
and nothing could reach it again. `ps` now reads what the kernel still holds and names those boxes
with their supervisor pid on stderr, on hosts with a delegated cgroup and, through `/proc`, on hosts
without one. It does not invent a table row for them: there is no record, so there is no uptime, no
ports and no health to show.

**Multi-stage builds produce an image that runs.** `FROM <stage>` printed `built` and left an image
that failed at `kern box` with "no layers in manifest", because the final image rested on a stage's
overlay chain. The final image is now materialized, fail-closed. `COPY` also stopped flattening
directory modes: a rootfs shipping a 1777 `/tmp` or a 2755 setgid directory came out 0755, and the
program that needed it failed for a reason nothing in the Dockerfile explained.

**Compose reads files it used to refuse, and refuses files it used to accept in silence.** A
`command:` continuation line starting with `-` was read as a sequence entry, so `--source`, `-drive`
and `-netdev` broke a plain folded scalar; two real files from public repositories now parse. `!!str`
is accepted over a scalar and refused over a list or a map, where it used to be dropped in silence
and the box started with something else. `tmpfs:` has ONE grammar again: `kern box --tmpfs
/run:size=64m` used to fail on the exact spelling `kern compose` produced, while `/run:rw` and
`/run:exec` - both valid Docker - were read as sizes and refused. An IPv6 port refusal now names the
missing feature instead of suggesting a typo, and `/dev/shm` and `/dev/pts` say the mount is already
there rather than giving the generic refusal.

**`kern build prune` refuses arguments it used to ignore.** `kern build prune 0` was read as "keep
nothing", ran with the default 20, and reported "kept the 20 newest".

**Fixed, no interface change:** a memoised runtime path outlived the directory it named, so anything
that cleared `/run/user` left every later registry write in that process failing, for the life of the
process; the layer cache treated a sentinel without its directory as a hit, and the build then died
on a `mount(overlay)` ENOENT that named neither.

**Known and unchanged:** the resource caps are verified on one machine. CI does not start boxes, and
the second test's host has no cgroup delegation, so `--memory`/`--pids-limit` enforcement has one
witness. The squash that `FROM <stage>` and `push` share loses hard links and fills sparse files.
Compose networks do not isolate services from each other: one stack is one namespace, and `up` says so.

## v0.9.3 - 2026-09-07

**If you run kern on Ubuntu 23.10 or later, your install needs one action.** That is not a new
feature, it is the answer to "why does no box start", and it is here rather than under new
capabilities because it is the entry a reader scanning for "does this release affect me" needs to
find. Those releases ship `kernel.apparmor_restrict_unprivileged_userns=1`, which permits the
namespace and refuses the rootless uid map, so nothing starts. kern now ships the profile:

```
kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null
sudo apparmor_parser -r /etc/apparmor.d/kern
kern doctor
```

**CLI, additive:** `kern doctor --apparmor-profile` writes that profile to stdout and exits without
running any check. It exists because the install line has to be runnable by the person reading it,
and a repo-relative `packaging/apparmor/kern` is not: the release tarball carries the binary alone
and `cargo install` copies one file, so most readers have no `packaging/` directory. The binary
carries the profile instead. Nothing is removed or renamed.

**What that file does NOT do**, because installing one into `/etc/apparmor.d/` on a program's
say-so deserves the sentence: it grants exactly one permission, `userns`, and confines kern in no
way at all. Not its paths, not its capabilities, not its syscalls. Removing it returns the machine
to its previous state. It is deliberately not a confining profile: kern's job is to confine the
workload, and a second weaker mechanism aimed at kern itself would mostly invite the belief that it
was doing something.

The third command is not politeness. AppArmor attaches at `execve`, so a kern already running when
you load the profile does not pick it up. Measured on Ubuntu 24.04 with the restriction left at 1:
without the profile no box starts, with it `kern box`, `kern pod create` and the full acceptance
matrix all pass, and the sysctl is never touched.

`kern doctor` prints that install line, names the path it is running from because AppArmor attaches
by path, and offers `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` only after it, with
its cost: that one lifts the restriction for every program on the machine and is lost at reboot.

**`kern doctor` said "ready" on a stock Ubuntu 24.04, where no box can start.** Its userns probe
called `unshare(CLONE_NEWUSER)` and stopped there. Ubuntu 23.10 and later ship
`kernel.apparmor_restrict_unprivileged_userns=1`, which PERMITS the namespace and refuses the
rootless uid map, so the probe succeeded on a host where the very command doctor then suggested,
`kern box hello`, failed. Ubuntu is the most common distribution kern is installed on and that was
its default state.

The probe now runs the sequence a box actually runs, in the same order: unshare, deny setgroups,
write the uid map. Measured on a stock cloud image, both directions:

```
default                       ✘ the namespace is allowed and its uid map is REFUSED - no box can start
                              not ready - 1 blocker(s)
apparmor_restrict...userns=0  ✔ enabled
                              ready - `kern box` will run here
```

The AppArmor line no longer hedges with "if boxes fail with EPERM". It reports what the knob is set
to and leaves the verdict to the check that measured it, so a host carrying the restriction with a
profile for the kern binary is told it is fine rather than warned at.

**On a host whose SELinux policy refuses pasta's netns watch, the pod's pasta no longer exits by
itself.** kern retries with `--no-netns-quit` there ([#6](https://github.com/getkern/kern/issues/6)),
and a pasta started without the watch does not notice the namespace disappear, so `kern pod rm` and
`compose down` are what stop it rather than pasta stopping itself. Nothing to do differently; it
matters if you run a mixed fleet, because the hosts that take the retry and the hosts that do not
now have two different pasta lifecycles, and only the first depends on teardown running.

**`stdin_open:` and `tty:` in a docker-compose.yml no longer produce an alarm.** They used to warn
"ignored (unsupported)" matched on the KEY rather than the value, so `tty: false` warned about
nothing and a working stack was told a feature was missing
([#7](https://github.com/getkern/kern/issues/7)). A compose service is always detached, so `tty:`
has nothing to act on and is silent; `kern exec -it <service>` gives a real PTY in the running box
when one is wanted. `stdin_open: true` still warns, because it is a real difference from Docker: the
service's stdin is at EOF rather than held open, so a program that blocks on it exits at once.

**The Rust test suite had never been built for aarch64, though the binary always was.** So every
"the tests pass" statement this project has made was an x86_64 statement, silently, for as long as
ARM has been a supported target. Two lines caused it, both in test code and both invisible on
x86_64-gnu: `pthread_t` is a `c_ulong` on glibc and a `*mut c_void` on musl, and the pointer form is
not `Send`; and `ioctl`'s request parameter is a `c_ulong` on glibc and a `c_int` on musl. It now
builds and runs on ARM: **577/577 on a Raspberry Pi 5 (kernel 6.6) and on a Jetson (5.15-tegra)**,
on the hardware rather than under emulation. Under `qemu-user` one `flock` contention test fails
reproducibly and passes six times out of six on the boards, so that red is an emulation artifact and
not a name-collision bug on ARM.

That is the largest instrument defect in this cycle: not a probe reading the wrong thing, but a
whole suite that was never executed on a target kern ships for.

**A refused netns watch is only fatal in newer passt, and where it is not there is nothing to fix.**
Read out of three installed binaries rather than inferred:

| passt | ships in | on a refused watch |
|---|---|---|
| `0.0~git20230309` | Debian 12 | `inotify_init(): won't quit once netns is gone`, and it keeps the NAT |
| `0.0~git20240220` | Ubuntu 24.04 | `netns dir open: %s, exiting` |
| `0^20250919` | Fedora 43 | `netns dir open: %s, exiting` |

So a Raspberry Pi on Debian 12 needs no retry and never could have: issue #6 cannot occur against
the tolerant build. The condition became fatal between March 2023 and February 2024, which is
exactly the range the retry covers.

**Fixed: `--memory` and `--pids-limit` reported "accepted but NOT enforced here" over a box capped
exactly as asked.** Reported on WSL2 and reproduced on a Raspberry Pi 5 and a Jetson Orin Nano,
where `--memory 256m --pids-limit 64` printed both notices while the box's cgroup held
`memory.max=268435456` and `pids.max=64`. The check was right and was asked in the wrong place. It
read `/proc/self/cgroup`, and on the systemd-scope tier that is the SUPERVISOR, which kern parks in
a sibling leaf so a whole-box OOM cannot take it with the workload. From there the walk goes to the
ancestors and never reaches the box's leaf, which is a sibling rather than a parent; the only
ancestor carrying a memory ceiling is the scope, deliberately set to the request plus kern's
supervisor headroom, so "capped at or below the request" was false by design. Both notices were
wrong on the whole of that tier, and on the direct tier the check never runs at all, so it had never
once fired correctly.

The same mistake had a second instance, found by adding one diagnostic line to the reproduction
script rather than by reading the code. The `KERN_NO_SCOPE` opt-out warned from a point BEFORE the
box exists, where whether the cap will bind is not yet knowable, on the belief that the opt-out
skips the box's own cgroup as well as the scope. It does not. On x86_64 that printed "accepted but
NOT enforced here" while the box held `memory.max=268435456` and a 400 MB load was killed with exit
137. The warning now comes from one place on every box path, after the caps are written, against the
box's own cgroup. The Raspberry Pi finding the opt-out warning was written for is unchanged and
still reported: measured on a Pi 5 and a Jetson, the opt-out leaves `memory.max` and `pids.max` at
`max` and a 400 MB load survives, and kern says so. The notice now follows the cgroup rather than
the code path.

The enforcement byte on `KERN_STARTED_FD` was already correct: it takes the box's directory
explicitly, for this exact reason. So an SDK reading the byte saw "enforced" while a human reading
stderr saw the opposite, in the same run. Both now read one binding, so they cannot disagree. If you
scripted around the false notice, remove the workaround; if you concluded your caps were not
working, they were, and `--memory 256m` was killing at 256 MiB throughout.

**Fixed: a box refused for running out of process slots was told to check user namespaces.** A
independent test hit it with a tightened `ulimit -u`:

```
error: sandbox: fork(idmap helper) failed: Resource temporarily unavailable (os error 11)
hint: needs unprivileged user namespaces and a valid --rootfs directory
```

The message is exact and the hint names two things that are both already fine, because the code
could not have reached that fork otherwise. `EAGAIN` on a fork is a process-limit problem, and
`RLIMIT_NPROC` is per-UID and counted across the whole system, so another program owned by the same
user can exhaust it, and it counts TASKS rather than processes. That last clause is not a detail:
that test who reported the hint then compared `ulimit -u` against a process count, got 10 against
149, and concluded the kernel was accounting something unobservable. Measured here, an x86_64 desktop
owned 208 processes and 1918 tasks and the limit at which a single fork began to succeed was 1932, so
against the task count the threshold IS the count. The hint now names `ulimit -u`, the task count and
`LimitNPROC=`. Every other setup failure keeps the hint it had. Same shape as the pull hints, which branch on the message
rather than on the variant for exactly this reason.

**`kern --version` now says which build it is.** It answered `0.0.0` for every binary not cut by the
release workflow, which is every binary anyone compiles from source, so two builds of the same tree
were indistinguishable. That is not hypothetical: during the work above, a binary built ten minutes
before the fix was compared against one built after and reported as if it were the same program. A
independent test made the same point from the other side, noting that a test script had to print a
`sha256sum` to tell two builds apart, and that the workaround existed only because the binary could
not answer.

The version is still the tag and nothing is carved into the source. A release binary prints the tag
exactly as before (`kern 0.9.3`), because the workflow stamps `Cargo.toml` and that value passes
through untouched. A build from source prints `git describe` instead
(`kern v0.9.2-45-gf7622ee-dirty`): the nearest tag, the distance from it, the commit, and whether the
tree was dirty. Where git cannot answer, a source tarball or a vendored build, it falls back to
`0.0.0`, which is today's behaviour, so nothing regresses when the information is unavailable.

## v0.9.2 - 2026-09-06

**Cut for a defect the first person to try compose would hit.** A `docker-compose.yml` with ONE
service came up with no network at all, for the whole 0.9 line. The auto-pod was gated on two
services or more, on the reasoning that a pod's other job is letting services find each other and one
service has nobody to find; but the pod is also the only thing that attaches `pasta`, so a lone
service got no pod, no NAT and no `/etc/resolv.conf`.

It does not present as a missing network, which is why it survived: the image ships its own
`resolv.conf` and it looks healthy, so the failure surfaces as `Could not resolve host` and every
diagnosis goes after DNS. `curl http://1.1.1.1` from inside the box failed in **0 ms**. There was no
route. Reported from a Mac running Lima with a Fedora guest, but the platform was never the variable:
reproduced on x86_64 Linux with pasta installed, changing only the service count.

**Every compose test in this repo ran three services, which is how it shipped.** The single
`services:` in the Rust suite points at an unreachable registry and never starts a box, so the
one-service path had no coverage anywhere. `scripts/acceptance-matrix.sh` now has a case for it, with
its two new assertions exercised in `--self-check` including a negative control on the pre-fix
summary line. The case goes RED on the v0.9.1 binary and green here, confirmed by an external
independent test on their own host rather than only here.

### Fixed

- **A one-service compose stack had no egress.** The auto-pod condition tested a service COUNT while
  the property it stood in for was "does this stack need a managed network". It now creates a pod
  whenever any service is not on the host net, which is what the comment above it always said it did.
- **`kern pod ls` and `pod ls --json` reported double the members.** They counted lines in the pod's
  shared `hosts` file, and a compose member writes two of them (the qualified `<pod>-<service>` and
  the bare alias) while a `kern box --pod` member writes one. Measured on the shipped v0.9.1: 1, 2 and
  3 services read 2, 4 and 6, while `kern ps` read 1, 2 and 3. Both now read the registry `kern ps`
  reads, scanned once rather than per pod. The two views had been unified so they could not disagree;
  they could not, and both were wrong, while a third reader had the right answer.
- **`compose up` never said whether the stack had egress**, only that services could reach each other,
  so a stack with internet and one without printed the same sentence. On a reused pod that line is the
  only one printed. It now names the state, and `docs/DOCKER-COMPAT.md` lists all five instead of two.
- **`restart:` in a pod does not survive a reboot, and now says so.** A pod member is supervised
  in-process because a systemd unit that outlives the pod holder cannot re-join its namespace. The gap
  predates this release and reached only multi-service stacks; the auto-pod now reaches one-service
  stacks, so `up` prints a note instead of trading reboot-survival in silence.
- **`has_outbound` answered from `resolv.conf` alone.** Kill `pasta` while the holder lives and the
  file stays on disk, so the predicate reported egress for a pod with no route. It now also requires a
  live pasta, verified by `comm` because passt re-execs into an ISA variant and a pid can be reused.
  Found by an independent test reading the diff, not by a test here.
- **`kern killall --help`, `kern down --help` and `kern logout --help` printed the whole 184-line
  reference.** The per-verb match read only the first token of each line, and those three are
  documented as the second half of a pair. The test that missed them named fifteen verbs by hand; it
  now reads the list out of the reference, all 51.
- **Nine `kern --help` lines sat outside the description column**, `pod` by twenty because it did not
  fit; `pod` is two lines now. 76 verbs and 83 flags either side, checked by diffing both sets.
- **A damaged image-cache entry was repaired in silence under an SDK.** v0.9.1 gated kern's progress
  on a terminal and took the two repair lines with it, so in a pipe a cached image with no usable
  rootfs, or with no config, was re-fetched with nothing said. They are `kern: note:` now and reach a
  pipe; the ordinary "not cached, pulling once" stays gated. Found by
  `pentest/pentest-cache-edge.sh`, which asserts kern names the missing part.

## v0.9.1 - 2026-09-05

**Faster than v0.9.0 on a bare box start**, 2.300 ms against 2.346 in 21 of 24 paired batches, with
the OOM fix kept. The supervisor's sibling cgroup is created only where it is needed, a scope or
managed unit whose own cgroup is the one armed with `oom.group`: 0.165 ms back, 24 of 24, re-checked
in both layouts on four hosts and four systemd versions (249, 252, 255, 257).

**Cut for one defect the released binary had on most hosts.** `--egress-allow` in v0.9.0 could start
a box against a proxy nothing could reach, and on three of five hosts the pump never got the port
(`cannot bind 127.0.0.1:3128 in box: Address not available`). The pump now raises the box's loopback
itself and refuses to serve if it cannot, so readiness means reachable rather than bound. Reproduced
on an Arduino UNO Q and a Jetson Orin Nano with the shipped v0.9.0 aarch64 binary.
`scripts/acceptance-matrix.sh` exercises it, and says so instead of printing a tick on a host where
it cannot tell the fix from the defect.

### Fixed

- **The MCP server offered a language and then refused it.** The `run_code` schema advertised `sh`
  while a hand-written guard did not. The guard is the schema's list now, and a refusal names the
  accepted values.
- **`kern_execution_policy(cap_drop=("ALL",))` disabled the drop it asked for**, comparing a tuple
  against the string `"ALL"` and producing `drop_all_capabilities=False`. Only exact images convert;
  anything else raises and names the field to set.
- **kern's progress output no longer reaches a pipe.** Nineteen bare `eprintln!` lines now go through
  `progress!`, which prints only when stderr is a terminal. Errors, warnings and `kern: note:` still
  reach a pipe, because that is where they must arrive. `scripts/progress-is-tty-gated.py` keeps it
  true; converting the sites by hand found fourteen and missed five.
- **Three diagnostics reached `code_stderr` as though the workload had printed them**, lacking the
  `kern: ` prefix, plus five `kern compose:` lines whose prefix matched nothing.
- **A cgroup probe printed systemd's bus error onto kern's stderr.** `systemd-run ... -- true`
  inherited its stderr, so on a host with systemd installed but not booted the box's stderr carried
  `Failed to connect to bus`. Both streams are null now; the verdict was never in the output.
- **kern's diagnostics no longer land in a model's context.** `code_stderr`/`codeStderr` is stderr
  without kern's own lines, `runtime_notes`/`runtimeNotes` holds exactly what was removed, and
  `stderr` still holds every byte in order.
- **`kern_execution_policy` accepts `Sandbox`'s vocabulary**, `timeout_s` and `memory_mb` beside
  langchain's `command_timeout` and `memory_bytes`. Passing both halves of a pair is refused.
- **The OOM message never printed when kern runs as root or on a host with no systemd**, which is
  where the cap is most likely to be the only thing between a workload and the machine. The counter
  was read by walking kern's own cgroup ancestors, and on the direct-cap path the supervisor sat
  inside the cgroup `memory.oom.group` was about to kill. Verified on four hosts.
- **The registry recorded the supervisor's cgroup for every box**, and `kern stop` writes
  `cgroup.kill` into the path it records, so a stop would have killed the reporter.
- **A `-v` volume is mounted `nosuid`**, `/workspace` included. A `:ro` volume still fails hard.
- **`/dev/shm` reports the size the box actually has.** Unsized, `statvfs` reported half the host's
  RAM: a box held at 512 MiB told every workload it had 15.6 GB.
- **A warm interpreter could not import anything the image ships.** The driver ran `python3 -S`, so
  `import numpy` worked on a cold `run_code` and raised in a kernel cell. Dropped in both bindings.
- **`kern-sandbox` 0.1.36 on npm could not be installed**, its `package.json` depending on itself.
  Fixed in 0.1.37 and deprecated on npm.

### Changed

- **`deps_readonly` defaults to TRUE**, so a cell cannot change what the next cell imports. The route
  it closes is bytecode: a `.pyc` is validated on the source's timestamp and size, so a rewritten
  `.pyc` with the header re-pasted ran on the next import, invisible to `result.files`. A run-time
  write into `.deps` now gets `EROFS`; `deps_readonly=False` restores the old behaviour. It costs
  nothing at run time, the setup box compiling before the mount closes.
- **A timeout reports `exit_code = 137` in Python**, not `-9`, matching Node, the CLI and docker.
- **`integrations/pi` declares `engines: node >= 22`.** Measured: 20.18.1 fails at import, 22.11.0
  runs all 165 assertions.

### Added

- **`kern box --shm-size SIZE`**, for a workload needing `/dev/shm` sized differently from `--memory`.
- **`prewarm=N` in both bindings**: ~1.6 ms per call instead of ~37.8, measured over ssh, without
  giving up the fresh box, since a prewarmed box serves exactly one cell and is destroyed. A slot
  refills in ~70 ms, so N is a burst budget rather than throughput. Default `0` in the SDK, `1` in
  `kern-mcp`.
- **Every box gets a writable `/tmp`**, 64 MiB of tmpfs charged to the box's own memory cap. Nothing
  in it survives a call. `security_profile="untrusted"` gets none, deliberately.

**kern-sandbox 0.1.41** is documentation only, no code change from 0.1.40: the two package READMEs
moved their operational tail to `SANDBOX-NOTES.md` beside each binding. **0.1.40** answers an external
audit of the SDK, the pi extension and the LangChain integration.
