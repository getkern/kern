# Virtual resources

kern is built around one idea, *virtual resources*, exposed as **two verbs**: `box` wraps a process in
a full isolated slice; `run` caps a resource on a process you launch yourself. A box gets *only* what
you slice for it; a bare `run` adds the same caps to a process that otherwise still sees the host.
Every shipping cap is a real cgroup v2 or kernel control, and devices are deny-by-default. The exact
`kern.toml` schema is in [CONFIG.md](CONFIG.md).

| Resource | Flag / profile | What the box gets | Enforcement |
|---|---|---|---|
| **CPU** | `--cpus` · `--cpuset-cpus` · `--nice` · `vcpu:` | Fractional CPU-time quota, core pinning, priority | cgroup `cpu.max` / `cpuset`: a hard quota where the controller is delegated, and NOT proven by `--require-limits`, which governs memory and pids (see below) |
| **Memory** | `--memory` · `--memory-swap-max` · `--shm-size` | Hard RAM ceiling, swap allowance, `/dev/shm` size | cgroup `memory.max`, hard¹ |
| **Disk** | `vdisk:` · `--size` (named volumes) | Size-capped scratch at `/vdisk/<name>` | rootless: a **RAM-backed tmpfs**, charged to the box's memory cap; privileged: ext4-on-loop quota |
| **Devices** | `vgpio:` | *Only* the named GPIO/I²C/SPI/LED nodes | fresh `/dev` + fd-pinned bind + capability deny-list |
| **PIDs** | `--pids-limit` | Fork-bomb ceiling | cgroup `pids.max`, hard |
| **Block I/O** | `--io-weight` | I/O bandwidth weight | cgroup `io` |
| **GPU** | `--gpus N\|device=N\|device=GPU-<uuid>\|all` · `--device nvidia.com/gpu=N` · `display` grant · compose `gpus:`, `deploy.resources.reservations.devices`, `devices:` | Whole cards, as devices | no per-box cap |

¹ Where the `memory` controller is not delegated to a non-root user's scope, kern warns and shows the
one-line `.wslconfig` fix; enforced natively on Linux.

## Checking a cap, and how not to

`free`, `top` and `htop` inside a box report the **host's** memory, because the kernel does not
namespace `/proc/meminfo`. That is true of every runtime without a `/proc` shim, and it makes an
enforced cap look absent. A runtime that sizes itself from the **cgroup** (a modern JVM, Go's memory
limit, most container-aware tooling) gets the right number. Read the cgroup, or hit the ceiling:

```sh
kern box check --image alpine --memory 256m -- cat /sys/fs/cgroup/memory.max   # 268435456
kern box oom   --image alpine --memory 256m -- \
  sh -c 'dd if=/dev/zero of=/dev/shm/x bs=1M count=512' ; echo "exit=$?"       # exit=137, OOM-killed
```

An over-allocation is OOM-killed (exit **137**, recorded for `kern wait` and `kern ps -a`). By
default the kernel kills the process it picks, as under Docker: an `exec` that runs out of memory dies
and the box goes on (measured: `kern exec` 137, the box still `running`). `--oom-group` makes the
whole box go as one: kern writes `memory.oom.group=1` on the box's own cgroup, so the kernel SIGKILLs
every task at once, which is what the Python and Node sandboxes ask for. That holds on both cap paths,
re-checked on four hosts and four systemd versions (**249, 252, 255, 257**).

⚠️ Exit **137** alone does not prove a cap fired: it is SIGKILL, which the system OOM killer delivers
identically. A kill by the box's own cap always carries kern's OOM message on stderr.

**Enforce, or refuse to start.** Where the controllers are not delegated, a `kern box` warns once and
runs uncapped; `--require-limits` (or `KERN_REQUIRE_LIMITS`) makes that fatal, reading the caps back
from the cgroup before starting. `--allow-uncapped` (`KERN_ALLOW_UNCAPPED`) is the explicit inverse;
the two are mutually exclusive. cpu and cpuset stay best-effort under both.

`cpu.max` reads directly: `50000 100000` is half a core, `200000 100000` is two.

`--pids-limit` counts **every task in the box**, not just the ones you fork, so your available forks are
the limit minus what is already there. That baseline depends on whether the command is a shell or an
exec'd binary and on whether the box is detached: measured at 2 on one box, so `--pids-limit 30` allowed
28 forks. It is a fork-bomb ceiling, not an exact budget.

## The model

A box (`kern run`, or `kern box` with the name first) isolates a workload and slices its resources:
its own namespaces, overlay or read-only fs, private process tree, seccomp, **plus** the caps below. It
follows Docker: with no `--memory` it is bounded by the machine, and `--memory M` alone allows as much
swap as memory.

Capping a program of this host WITHOUT a container is not something kern does since 0.57.0 (Docker
has no such verb either). systemd does it: `systemd-run --user --scope -p MemoryMax=1G -p CPUQuota=200% -- ./job`.

### What memory ceiling you get

| what you ran | ceiling and swap with no flag or key | why |
|---|---|---|
| `kern box`, `kern run`, `docker run` through kern's socket | **the host's RAM**, the host's swap; `--memory M` alone: M and M of swap | Docker parity: Docker does not cap a container, and its `--memory` alone allows an equal swap. `--memory-swap-max` sets the swap |
| a `kern compose` service with no `mem_limit:` | **the host's RAM**, the host's swap; `mem_limit` alone: an equal swap | compose parity, the same rule |
| a sandbox of the Python or Node SDK, or the Rust `Sandbox` builder | **512 MiB**, no swap | the sandbox's default; the cap is the whole budget, which is what its `oom` verdict reports |

Measured on a host with 33464963072 bytes of RAM and 25322409984 of swap: `kern run alpine` reads
`memory.max` `33464963072` and `memory.swap.max` `25322409984` (Docker reads `max` and `max`); with
`--memory 256m` both engines read `268435456` and `268435456`, and an SDK sandbox reads `536870912`
and `0`. The host's RAM is still a ceiling, not an absence of one: the box keeps a `memory.max` of its
own, so a failure stays attributable to its own cgroup. `[kern] compose_memory_max` puts a strict
ceiling back on compose services ([CONFIG.md](CONFIG.md), [DOCKER-COMPAT.md](DOCKER-COMPAT.md)).

**No mechanism at all.** A host with no systemd user manager, whose own cgroup cannot take
a capped child, has neither path, so NO cap is in force, default or asked-for. A `kern box` warns at
start, and `kern doctor` names the directories it probed. For a
running box it is a fact you can read:

```console
$ kern inspect web --json | grep memory
"memory_max":67108864,"memory_max_enforced":null
```

`memory_max` is what you asked for; `memory_max_enforced` is what the kernel will hold the box to,
walked up its cgroup chain and counting each level's swap (an ancestor with unlimited swap is not a
ceiling). `null` means nothing is enforcing it, and the human output says
`64M (requested, NOT enforced here)`.

**A limit above the box that throttles instead of killing.** A `memory.high` on a cgroup
above the box is not a kill limit: past it the kernel slows the box's allocations to a halt, so a box
that should be OOM-killed at its cap stalls until its timeout. Measured on a Jetson Orin with
`MemoryHigh=80M` on `kern.slice`: an OOM that takes 0.06 s took **317 s**. kern does not change that
limit, it reports it, in a `kern: note:` at start, a row in `kern doctor`, and in `kern inspect`:

```console
$ kern inspect web | grep mem-cap
mem-cap  512M; throttled above 80M by /user.slice/user-1000.slice/user@1000.service/kern.slice (memory.high)
```

`--json` carries it as `memory_high_outer` and `memory_high_outer_cgroup`, and `--require-limits`
refuses to start such a box.

Two ways to change the default ceiling, and they are not the same: `--memory <size>` raises or lowers
it, which is the one you want; `KERN_NO_SCOPE=1` removes the scope and with it every ceiling above,
leaving the command in your shell's cgroup.

From a session outside your systemd user subtree (an ssh login on a server, a `wsl.exe -u` shell),
a box cannot join kern's delegated cgroup, so it gets a scope of its own, which kern asks systemd for
over D-Bus from its own process. `KERN_SCOPE_VIA_SYSTEMD_RUN=1` asks through `systemd-run` instead.

## Profiles

Name a slice once, attach it by name, and stop repeating flags. Profiles live in
`~/.config/kern/kern.toml`.

```sh
kern config add vcpu:slim --cpus 0.5 --memory 256m       # or edit the file by hand
kern box app --image alpine vcpu:slim -- ./app           # no flag: the profile is just there
kern run vcpu:slim python:3.12-slim python train.py      # the same slice on `kern run`
```

That writes both the profile and the physical resource it slices:

```toml
[[cpu]]
id = "cpu:0"

[[vcpu]]
name    = "slim"
cpus    = 0.5
memory  = "256m"
backend = "cpu:0"    # the [[cpu]] above; `backend = "host"` slices the whole CPU with no [[cpu]] block
```

Profile tokens go BEFORE the `--`: `vcpu:` · `vdisk:` · `vgpio:`. Author them with `kern probe` (what
the host has to slice), `kern examples` and `kern validate`. Use `--config ./kern.toml` for a
per-project file, or `KERN_CONFIG` to make that the file every command reads. The full schema, the
7-layer precedence and `extends` are in **[CONFIG.md](CONFIG.md)**; a runnable walk-through is
[resource-profiles.sh](../examples/resources/resource-profiles.sh).

## Confining writes

`--landlock-rw <path>` confines a box's writes with the Landlock LSM: the root stays readable and
executable, and writes go only under the paths named (repeatable), plus the box's own `/dev`, `/tmp`,
`/run` and `/proc`. It refuses to start where the kernel has no Landlock, and implies `no_new_privs`,
which Landlock requires, so `sudo` inside the box stops working.

## Storage: volumes and vdisks

| I want | Use |
|---|---|
| Data that survives runs, or is shared between boxes | a **volume**, `-v name:/path` |
| A cap on how big that shared data can get | a **volume with `--size`** |
| One box with its own capped scratch disk | a **vdisk** profile, `vdisk:x` → `/vdisk/x` |
| Data on a remote server | a **network volume**, `-v nfs://…` |
| A persistent vdisk on a *specific* disk (advanced) | a `[[disk]]` plus the vdisk's `backend` |

A **volume** is shared, persistent data. A **vdisk** is one box's private capped disk. Both use the same
ext4-on-loop engine.

### Volumes

Attach with `-v NAME:/path-in-the-box`; kern creates it on first use.

```sh
kern box w --image alpine -v data:/out -- sh -c 'echo hello > /out/note.txt'
kern box r --image alpine -v data:/out -- cat /out/note.txt      # → hello
```

They live under `~/.local/share/kern/volumes/`, and `kern top` → Storage tab manages them.

`kern volume create cache --size 2g` gives one a quota. The quota is **enforced** only when a
**privileged, foreground** box mounts it, where kern backs the volume with a real ext4-on-loop image.
Rootless or detached, kern falls back to a bind-mount and **says the quota is not enforced** rather than
pretending. Your data is in the same place either way.

A `-v` source can also be a URL, mounted for the box's lifetime:

```sh
kern box app --image alpine -v nfs://server/export:/data   -- ./run.sh
kern box app --image alpine -v smb://server/share:/data    -- ./run.sh
kern box app --image alpine -v sshfs://user@host/srv:/data -- ./run.sh
```

### Vdisks

A vdisk is a reusable spec you name once and attach with the `vdisk:` prefix.

```toml
[[vdisk]]
name = "scratch"
size = "2g"            # hard cap
persistent = false     # true = survives box removal
backend = "ram"        # REQUIRED: "ram" is a RAM-backed tmpfs, or a [[disk]] id
# iops = 500           # optional I/O limit, ext4-loop backend only
```

```sh
kern box build --image alpine vdisk:scratch -- ./compile.sh    # → /vdisk/scratch, capped at 2g
```

`kern top` → Profiles tab edits them without touching the file, writing **surgically** so comments
survive. Like a quota'd volume, a vdisk uses the ext4-loop backend when the box is privileged and a
tmpfs otherwise; kern says which one you got and never silently drops the profile.

**`persistent` also decides who the disk belongs to.** It reads as a statement about time, and it is
also one about identity:

| | where the image lives | two boxes on the same profile |
|---|---|---|
| `persistent = false` (default) | the box's own scratch dir | **one disk each**, empty at start, gone at exit |
| `persistent = true` | the `[[disk]]` pool, or a per-user default | **one disk, shared by name** |

So a persistent vdisk is closer to a named volume than to an `emptyDir`: the name is the disk. Two boxes
cannot mount it at once, because an ext4 image mounted read-write twice corrupts, so kern takes an
exclusive lock. **The second box does not fail: it gets a tmpfs for that run and says so.**

```
kern: vdisk 'cache' is in use by another box - using a tmpfs backend this run
```

Its writes are discarded at exit, which is the one case where a profile named `persistent` does not
persist. Serialise the boxes, or give each its own profile.

### Advanced: pin a vdisk to a specific disk

By default kern picks where a vdisk's image lives. With multiple disks, name a `[[disk]]` pool and point
the vdisk's `backend` at it:

```toml
[[disk]]
name = "fast"
path = "/mnt/nvme"     # a writable dir on the disk you want

[[vdisk]]
name = "cache"
size = "10g"
backend = "fast"       # this vdisk's image lives under /mnt/nvme
```

`kern probe` lists your physical disks; `kern top`'s Overview and Storage tabs show them read-only.

```sh
$ kern probe
disks   nvme0n1  931.5G  SSD (Samsung 990 PRO)  ·  sda  1.8T  HDD (WDC WD20)
```

This is the one knob that stays in `kern.toml` rather than the TUI.
