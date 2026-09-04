# Round 14 results: 39 of 40 run. 1 could not be run here, and it is the one you said so about

All four tiers, in your ranked order. Everything below is measured on this host. **17 confirmed,
8 refuted, 12 passed clean, 2 not established because our instrument was the problem, 1 impossible.**
Five findings changed the branch.

Suites after those changes: **python 395, node 75, pi 73 / 89 / 25**, seven gates bare at exit 0.

---

# TIER A

| | verdict | the measurement |
|---|---|---|
| A1 | **confirmed** | `HOME=/root` -> npm rc=1, no cache dir. `HOME=/tmp` + webpack/cli/typescript/eslint -> **ENOSPC errno -28**, the cache wants **81 MiB** against a 64 MiB default. `HOME=/workspace` -> rc=0. `express` alone is 8 MiB and passes either way: your false green, exactly |
| A2 | **refuted, then ANSWERED** | the setup box has **no tmpfs at all**. `pip install torch` under `memory_mb=256` succeeds and puts **886 MiB on the host disk**, no exit 137. Where the scratch went was left open and is now measured, by running the writable-path pin INSIDE the setup box: `writable = /dev/shm, /workspace`, root NOT writable, `TMPDIR` unset, cwd `/workspace`. Both guesses wrong. It is a strict SUBSET of the run box, missing exactly `/tmp`, and pip reaches the workspace through `tempfile`'s cwd fallback: the same mechanism that motivated the default. **Nothing describes a wider box because there is no wider box**, and a test now asserts the subset relation |
| A3 | **confirmed, and it falsified a sentence we shipped** | ten 10 MiB writes: `run_code` x10 all pass with 54 MiB always free; `kernel()` fails from cell 6 with `OSError: [Errno 28]`. Our unqualified "scratch does not survive a call" is true for one path and false for the other |
| A4 | **refuted** | the session opens lazily inside the tool call, so a construction refusal comes back as a **tools/call result** carrying the whole message, with stderr empty. A bad `KERN_MCP_IMAGE` likewise |
| A5 | **refuted, and the numbers redone** | first pass reported 46 ms cached against 34 ms uncached, which invites the reading that a cold image is faster. Two single samples separated by noise. Median of five per side: **30 ms and 30 ms** (29-31 both). The conclusion rests on the mechanism, not the timing: `_tools_view` names the image from the configured string and inspects nothing |
| A6 | **confirmed** | under `cpus=0.5`: `nproc` **28**, `nproc --all` **1**, `cpu.max` `50000 100000`, `pids.max` 64. `make -j$(nproc)` starts 28 jobs against half a core |
| A7 | **confirmed, sharpest of the forty** | 309 MB database on the workspace, `create index` -> `database or disk is full`, `/tmp` free **64 MiB**, `/workspace` free **202066 MiB**. And `/tmp` is empty by the time you look, because SQLite cleaned up its spill |
| A8 | **confirmed** | `false \| tee` -> **exit 0** under bash; with `pipefail` -> 1; `sh` on debian (dash) -> **2**, dash rejects `set -o pipefail`; `sh` on alpine (ash) -> 1, ash honours it |
| A9 | **refuted in mechanism, and it found an SDK gap** | postgres never reaches shared memory: `id -u` is 0 and `initdb: error: cannot be run as root`. kern has `--user`; **this binding does not expose it** |
| A10 | **see D4** | |

# TIER B

| | verdict | the measurement |
|---|---|---|
| B1 | **confirmed** | call 2: `python3: can't open file '/tmp/normalise.py'`. The documented cost as a job. The message names the path, so it is at least legible |
| B2 | **refuted, healthy** | restore applies the NEW options: snapshot from `memory_mb=1024` (tmpfs 64m) restored into `memory_mb=64` gives **tmpfs 32m** and `memory.max 67108864`. The recorded size is not replayed, because the tmpfs is not in the snapshot at all |
| B3 | **confirmed, and it was undocumented** | after `restore`: `/tmp` marker **False**, workspace marker **True**. Now in the README |
| B4 | **half confirmed** | `track_files` reports `['prodotto.txt']` and NOT `/tmp/invisibile.txt`: a job whose product lands in the scratch reports nothing changed. The `.kern-env` exclusion holds, in the third place it had to |
| B5 | **confirmed, and the false green is real** | the PNG is produced AND stderr carries `mkdir -p failed for path /root/.config/matplotlib: [Errno 30] Read-only file system`. `MPLCONFIGDIR` fell back to `/tmp/matplotlib-y691m8fv`. `exit_code == 0` is green for a run the user reports as broken |
| B6 | **confirmed** | `egress_allow=["pypi.org"]` -> rc 1, `HTTPSConnectionPool(host='files.pythonhosted.org', port=443): Max retries exceeded`. Both hosts -> rc 0. The message names the host it could not reach, and nothing says a policy refused it |
| B7 | **refuted** | `truncated=True`, and the FAIL line **survives**, because the caps are per-stream and it went to stderr. The in-band signal you asked about exists and is `truncated` |
| B8 | **passed clean** | `trap "" TERM` + `timeout_s=10` -> **10.0 s**, fault `timeout`, and the partial output survives |
| B9 | **refuted, with the discriminant you would want** | the cap does not kill the job: a marker file written AFTER the noisy part **exists**. `exit 0`, `fault None`, `truncated True`, `success True`. Output is discarded, the process is not stopped |
| B10 | **confirmed** | `deps_readonly=True` -> `pip install httpx` rc 1, the module is **not importable** after, `/workspace/.deps` not writable. Nothing in the message names `deps_readonly` |
| B11 | **confirmed** | `memory_mb=512` -> `MaxHeapSize = 134217728`, exactly 1/4 of the cgroup. The JVM knows nothing about the 64 MiB scratch or the unbounded `/dev/shm`. Nothing fails; the numbers just do not add up |
| B12 | **confirmed, with the floor measured** | `java -version` starts at `pids=16` and **fails at `pids=12`**: `Failed to start thread "Unknown thread"`. Your 64 is comfortably above it, as you suspected; the floor is 16 |
| B13 | **solved end to end, three blockers** | `open("/run/nginx.pid") failed (30: Read-only file system)` -> `tmpfs={"/run":"1m"}`, **not `/var/run`, which is a symlink to it**; then `chown(...) failed (1: Operation not permitted)` -> `cap_drop=()`, CAP_CHOWN is in the default drop; then it serves |
| B14 | **answered, and the answer is bigger than the cell** | git is in none of debian:12-slim, golang:1.23-alpine or alpine, and **`setup=` cannot add it**: `apk add git` answers `ERROR: Unable to lock database: Read-only file system`. A system package manager cannot run in a box at all. `setup=` installs Python packages into the workspace; a system tool is a choice of `image=` |

# TIER C

| | verdict | the measurement |
|---|---|---|
| C1 | **confirmed, and our probe was the confused instrument** | debian dash: `[[ ]]` -> exit 127 `[[: not found`, array -> syntax error. alpine ash: `[[ ]]` -> **exit 0 OK**, array -> syntax error. Our first probe ran both in one command, so the array masked the difference |
| C2 | **passed clean** | two concurrent `run_code` on one workspace: both complete, both files present, no collision |
| C3 | **confirmed, and the order is the one you asked for** | `go build -o /tmp/app` fails FIRST on `failed to initialize build cache at /root/.cache/go-build: mkdir /root/.cache: read-only file system`, and only then would `/tmp` have mattered. Call 2: `/tmp/app: not found` |
| C4 | **passed clean** | `'report.csv' is larger than max_bytes=1048576, so the read was REFUSED. max_bytes is a ceiling on what may be read at all, not a request for the first ...` |
| C5 | **passed clean** | `日本語 café` round-trips **byte-identical** |
| C6 | **already guarded** | `SandboxError: env var 'KEY' must not contain a newline or NUL`, at construction. The guard predates this round |
| C7 | **refuted, on the third instrument** | two attempts never reached pressure (1 MB, 89-byte rdb). With `redis-benchmark -r`: **75664 keys, 98.99 MB used** under `memory_mb=256`, `BGSAVE` -> `rdb_last_bgsave_status:ok`, **dump.rdb 92 MB**. The COW fork survives |
| C8 | **passed clean** | busybox gets the default scratch (`tmpfs 65536 /tmp`), and `language="python"` gives `exec_failed` naming `python3` and the image |
| C9 | **passed clean `[works-but]`** | bind at `/tmp` -> `_tmpfs_args` EMPTY, **one** mount on `/tmp`, the 70 MiB host file visible, 202 GiB free. The discriminant is the mount COUNT, not `lines[0]` |
| C10 | **impossible here** | no privileged kern, no second uid |

# TIER D

| | verdict | the measurement |
|---|---|---|
| D1 | **passed clean** | no kern on PATH -> `SandboxError: the `kern` binary was not found on PATH - install it (https://github.com/getkern/kern) or set $KERN_BIN` |
| D2 | **passed clean** | `kern-mcp` console script PRESENT in the venv, modules import, version 0.1.36 |
| D3 | **passed clean** | the sdist installs, and every submodule (`langchain`, `mcp`) imports from it |
| D4 | **found something, and our fix was worse** | `tsc` on the published tarball without `@types/node`: six `Cannot find name 'Buffer'` inside our `.d.ts`. We added `/// <reference types="node" />`, re-measured, and got **seven**: the reference adds `TS2688` and the six remain. TypeScript's own message already carries the remedy verbatim. Reverted, reason in the file, requirement in the README |
| D5 | **continuous** | the pi suites run against the unpacked published tarball, not the checkout. That is how they ran for this report |
| D6 | **passed clean** | `text/markdown`, 22158 chars, first line `# kern-sandbox` |

---

## What changed in the branch because of this round

1. **`kernel()` is the documented exception to the scratch lifetime** (A3), in both bindings, with the
   numbers, pinned by a test that compares the two execution paths.
2. **The `HOME`-on-scratch ceiling** (A1), the **`nproc`** and **SQLite** cases (A6, A7), and the
   **nginx recipe** (B13) are in the Python README with their measurements.
3. **Four more sharp edges documented** (B3, B4, B5, B14): nothing in `/tmp` survives a snapshot,
   `track_files` reports only the workspace, matplotlib succeeds while warning, and `setup=` cannot
   install system packages because the root is read-only.
4. **The `@types/node` requirement** is in the Node README, and the reason the obvious fix was
   rejected is in `index.d.ts` (D4).
5. **One SDK gap recorded and not fixed**: no `user=`, so an image that refuses root cannot run (A9).
   A new option on a delivery day needs its own validation surface; this is a decision, not an
   oversight.

## Round 15: the five things the reviewer took issue with

1. **A2 was not refuted, it was moved.** Answered above by running the pin in the setup box, which is
   the box it had never been run against. Pinned by a test asserting the writable set there is a
   strict subset of the run box's.
2. **The pin fixed paths and not capabilities**, and the nginx recipe is the first documented recipe
   in this cycle that widens a posture. The posture test now pins `CapEff` per profile, with the
   recipe as its own positive control: `cap_drop=()` moves it from `0000000000000000` to
   `00000110bd84efff`. It also found something neither of us asked for: **`untrusted` wins over
   `cap_drop=()`**, `CapEff` stays zero, so a server image and that bundle are mutually exclusive
   today. Both in the README beside the recipe.
3. **`apk_rc=0` is now mechanical, not mnemonic.** A test pins that a pipeline hides its failure
   without `set -o pipefail` and reports it with, so the rule fails loudly if it stops holding, and
   the rule is stated in `harness.ts` where the shell harnesses live. **Not** injected into the
   product's execution path: `language="bash"` runs bash, and bash without pipefail is what someone
   writing a pipeline expects. Injecting it would make our bash a different bash.
4. **A5's numbers are redone** as a median of five per side and the difference is gone.
5. **D4's third option is written down**: type the surface as `Uint8Array` rather than `Buffer`, which
   removes the `@types/node` requirement entirely because a `Buffer` is one. A change to the published
   surface, so a 0.2 decision rather than a delivery-day fix, and the README no longer implies the
   requirement is a law of the platform rather than a consequence of our type choice.

Plus the two short notes: **`max_output_bytes` limits what you receive, not what the job costs** (the
process runs to the end; a marker written after the noisy part exists), and **the JVM arithmetic works
by luck** (1/4 for the heap plus at most 1/2 for the scratch fits, and an `-Xmx` at 3/4 breaks it,
with `/dev/shm` in the same budget and unbounded).

## Where our own instrument was the problem, again

Three times in forty, and you predicted the shape each time.

- **C1**: one command tested `[[ ]]` and arrays together, so the array's syntax error masked that ash
  accepts the first. We nearly recorded "ash rejects bashisms too".
- **C7**: two attempts measured a 1 MB dataset and an 89-byte snapshot while claiming to test COW
  pressure under a memory cap. The third one reached 99 MB and answered the question.
- **B14**: two images without git before we asked why, and the answer (`apk` cannot write) was more
  interesting than the scenario.

And one in our own probe of A8's family: `apk add ... | head -3; echo $?` reported `apk_rc=0` for a
failed apk, which is the pipeline exit code you named in A8, biting the instrument measuring it.

## The one prediction of yours we could not test

**C10**, `--uid-range`, needs a privileged kern and a second uid. Stated as a gap, not faked. It is
also the condition under which `/workspace` having no `nosuid` stops being inert, which is why it
stays on the runtime findings list rather than here.
