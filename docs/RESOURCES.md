# Virtual resources

kern is built around one idea, *virtual resources*, exposed as **two verbs**: `box` wraps a process in
a full isolated slice; `run` caps a resource on a process you launch yourself. Isolation is the first
resource, not the only one. A box gets *only* what you slice for it; a bare `run` adds the same caps
to a process that otherwise still sees the host. Every shipping cap is a real cgroup v2 or kernel
control, and devices are deny-by-default. The exact `kern.toml` schema is in [CONFIG.md](CONFIG.md).

| Resource | Flag / profile | What the box gets | Enforcement |
|---|---|---|---|
| **CPU** | `--cpus` · `--cpuset-cpus` · `--nice` · `vcpu:` | Fractional CPU-time quota, core pinning, priority | cgroup `cpu.max` / `cpuset`, hard |
| **Memory** | `--memory` · `--memory-swap-max` · `--shm-size` | Hard RAM ceiling, swap allowance, `/dev/shm` size | cgroup `memory.max`, hard¹ |
| **Disk** | `vdisk:` · `--size` (named volumes) | Size-capped scratch at `/vdisk/<name>` | rootless: a **RAM-backed tmpfs**, charged to the box's memory cap; privileged: ext4-on-loop quota |
| **Devices** | `vgpio:` | *Only* the named GPIO/I²C/SPI/LED nodes | fresh `/dev` + fd-pinned bind + capability deny-list |
| **PIDs** | `--pids-limit` | Fork-bomb ceiling | cgroup `pids.max`, hard |
| **Block I/O** | `--io-weight` | I/O bandwidth weight | cgroup `io` |
| **GPU** | `display` device grant · compose `devices:` | The whole card, as a device | no per-box cap |

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

An over-allocation is OOM-killed as a WHOLE box (exit **137**, recorded for `kern wait` and
`kern ps -a`): kern writes `memory.oom.group=1` on the box's own cgroup, so the kernel SIGKILLs every
task at once instead of leaving the box half-dead. Measured: a sleeper child and the parent both
vanish, and `kern ps` shows no stale box.

That holds on both cap paths. Where a rootless box takes the `systemd-run --scope` path rather than
the direct `kern.slice` one, kern builds its own cgroup inside the scope: the workload capped at
exactly what you asked for, kern's supervisor outside the blast radius so the group-kill takes the
workload and not the process that has to report it. Re-checked in both layouts on four hosts and four
systemd versions (**249, 252, 255, 257**).

**Enforce, or refuse to start.** Where the controllers are not delegated, a `kern box` warns once and
runs uncapped by default; `--require-limits` (or `KERN_REQUIRE_LIMITS`) makes that fatal: the box
refuses to start unless the memory and pids caps are **read back** from the cgroup as in force.
`kern run --memory` does not wait to be asked. Since v0.31.0 it refuses on its own when no ceiling at
or below the one you named can be proven, because that verb governs resources and nothing else, and a
command that outgrows a cap nothing is holding takes the host with it.
`--allow-uncapped` (`KERN_ALLOW_UNCAPPED`) is the explicit inverse for a host with no delegation. The
two are mutually exclusive. cpu and cpuset stay best-effort under both, carrying no OOM or fork-bomb
role.

`cpu.max` reads directly: `50000 100000` is half a core, `200000 100000` is two.

`--pids-limit` counts **every task in the box**, not just the ones you fork, so your available forks
are the limit minus what is already there. That baseline is not fixed: it depends on whether the
command is a shell or an exec'd binary, and on whether the box is detached. On the box measured here
it was 2, so `--pids-limit 30` allowed 28 forks before `EAGAIN`. It is a fork-bomb ceiling, not an
exact budget.

## Profiles

Name a slice once, attach it by name, and stop repeating flags. Profiles live in
`~/.config/kern/kern.toml`.

```sh
kern config add vcpu:slim --cpus 0.5 --memory 256m       # or edit the file by hand
kern box app --image alpine vcpu:slim -- ./app           # no flag: the profile is just there
kern run vcpu:slim -- ./train.sh                         # the same slice, no sandbox
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

Profile tokens go BEFORE the `--`: `vcpu:` · `vdisk:` · `vgpio:`. Author them with `kern probe` (list
what the host has to slice), `kern examples` (print a sample) and `kern validate` (check one). Use
`--config ./kern.toml` for a per-project file, or `KERN_CONFIG` to make that the file every command
reads and writes. The full schema, every field, the 7-layer precedence and `extends` are in
**[CONFIG.md](CONFIG.md)**; a runnable walk-through is
[resource-profiles.sh](../examples/resources/resource-profiles.sh).

## The model, in two verbs

| Verb | Question it answers | What it does |
|------|--------------------|--------------|
| **`kern box`** | *"Isolate this workload, and slice its resources."* | Its own namespaces, overlay or read-only fs, private process tree, seccomp, **plus** the same resource slices |
| **`kern run`** | *"Just slice resources, no sandbox."* | The same caps with no namespaces, **plus** `--landlock-rw` to confine writes |

They compose: `run` inside `box`. Both ship today.

**Both carry a default memory cap of 512 MiB where the host can hold one**, plus no swap and a
ceiling of 512 tasks.

**`kern compose` answers the same question differently, and both answers are deliberate.** They are
in one table here because a reader who meets them one at a time concludes that one of them is a bug:

| what you ran | memory ceiling with no flag or key | why |
|---|---|---|
| `kern box` / `kern run` | **512 MiB** | kern's own default: a sandbox for something you are about to run is capped until you say otherwise |
| a `kern compose` service with no `mem_limit:` | **the host's RAM** | compose parity. Docker does not cap a service by default, and a file that behaves differently here than under Docker is the thing `kern compose` exists to avoid |

Measured, on a host with 33465040896 bytes of RAM: `kern box --image alpine -- cat
/sys/fs/cgroup/memory.max` prints `536870912`, and the same read inside a compose service with no
keys prints `33465040896`. The compose case is a ceiling, not an absence of one: the box still has a
`memory.max` and `oom.group = 1`, so a failure stays attributable to its own cgroup rather than the
host OOM killer picking a victim. `[kern] compose_memory_max` puts a strict ceiling back and caps a
larger `mem_limit:` too ([CONFIG.md](CONFIG.md), and [DOCKER-COMPAT.md](DOCKER-COMPAT.md) for the
parity argument). Where kern's delegated `kern.slice` is usable, both write those three caps
straight into a cgroup of their own; where it is not, they re-exec into a transient systemd scope that
carries the same three. A workload past the ceiling is OOM-killed and kern names `--memory` as the
fix. Two ways to change it, and they are not the same:
`--memory <size>` raises or lowers the ceiling, which is the one you want; `KERN_NO_SCOPE=1` removes
the scope and with it all three ceilings, leaving the command in the cgroup of whatever started it,
usually your shell's. With no `--memory` named, kern warns when that happens and
`KERN_ALLOW_UNCAPPED=1` silences the warning; with one named, it refuses to run instead, and that
same variable is what runs it anyway.

**And there is a third case, which this page used to promise its way past.** A host with no systemd
user manager whose own cgroup cannot take a capped child has neither of the two mechanisms above, so
NO cap is in force, default or asked-for. A `kern box` warns at start rather than pretending and a
`kern run --memory` refuses outright, `kern doctor`
names the directories it probed and what it found there, and for a running box the answer is a fact
you can read rather than a promise you have to trust:

```console
$ kern inspect web --json | grep memory
"memory_max":67108864,"memory_max_enforced":null
```

`memory_max` is what you asked for; `memory_max_enforced` is what the kernel will hold the box to,
walked from the box's own cgroup up its chain, counting each level's `memory.max` plus the swap that
level opens (an ancestor's ceiling bounds the box too, and one with unlimited swap is not a ceiling).
`null` means nothing is enforcing it, and the human output says
`64M (requested, NOT enforced here)`. Note that exit **137** alone does not tell you a cap bit: it is
SIGKILL, which the system OOM killer delivers identically. A kill by the box's own cap always carries
kern's own OOM message on stderr.

**A fourth case: a limit above the box that throttles instead of killing.** A `memory.high` on a
cgroup above the box (a slice or scope, typically set with `systemctl set-property ... MemoryHigh=`) is
not a kill limit: past it the kernel slows the box's allocations to a halt, so a box that should be
OOM-killed at its cap stalls until its timeout. Measured on a Jetson Orin with `MemoryHigh=80M` on
`kern.slice`: an OOM that takes 0.06 s took 317 s. kern does not change that limit. It reports it: a
`kern: note:` when a box starts under one, naming the cgroup and the command that lifts it, a row in
`kern doctor`, and in `kern inspect`:

```console
$ kern inspect web | grep mem-cap
mem-cap  512M; throttled above 80M by /user.slice/user-1000.slice/user@1000.service/kern.slice (memory.high)
```

`--json` carries the same as `memory_high_outer` (bytes) and `memory_high_outer_cgroup`, `null` when
there is none, and `--require-limits` refuses to start such a box.

**One boundary crosses the split.** `--landlock-rw <path>` works on `run` as well as on `box`, because
Landlock restricts the calling process rather than needing a mount namespace. So
`kern run --landlock-rw ~/project -- ./agent` runs a host binary with its writes confined by the
kernel to that directory. Two differences from the same flag on `box`, both consequences of there
being no namespace:

- It grants **only what you name**, plus `/dev/null` and the other character devices a program opens
  for writing. Inside a box, `/tmp`, `/run` and `/proc` are the box's own ephemeral ones and are
  granted automatically; on the host they are real and persistent, so they are not.
- It **refuses to run** where the kernel has no Landlock, rather than warning and continuing as a
  resource cap does. A cap that cannot be applied leaves the command running without a limit, which
  `run` says out loud; a confinement that cannot be applied would leave your files reachable while you
  believed otherwise.

It also implies `no_new_privs`, which Landlock requires, so `sudo` inside it stops working.

## Storage: volumes and vdisks

| I want | Use |
|---|---|
| Data that survives runs, or is shared between boxes | a **volume**, `-v name:/path` |
| A cap on how big that shared data can get | a **volume with `--size`** |
| One box with its own capped scratch disk | a **vdisk** profile, `vdisk:x` → `/vdisk/x` |
| Data on a remote server | a **network volume**, `-v nfs://…` |
| A persistent vdisk on a *specific* disk (advanced) | a `[[disk]]` plus the vdisk's `backend` |

A **volume** is shared, persistent data, the same relationship a `docker volume` has to a Kubernetes
`emptyDir`. A **vdisk** is one box's private capped disk. Both use the same ext4-on-loop engine.

### Volumes

Attach with `-v NAME:/path-in-the-box`; kern creates it on first use.

```sh
kern box w --image alpine -v data:/out -- sh -c 'echo hello > /out/note.txt'
kern box r --image alpine -v data:/out -- cat /out/note.txt      # → hello
```

They live under `~/.local/share/kern/volumes/` (or `$XDG_DATA_HOME/kern/volumes`), and
`kern top` → Storage tab manages them: `[n]ew`, `[⏎]inspect`, `[d]elete`, `[p]rune`.

`kern volume create cache --size 2g` gives one a quota. Honest note: the quota is **enforced** only
when a **privileged, foreground** box mounts it, where kern backs the volume with a real ext4-on-loop
image. Rootless or detached, kern falls back to a bind-mount and **says the quota is not enforced**
rather than pretending. Your data is in the same place either way; only the hard cap differs.

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

`kern top` → Profiles tab edits them without touching the file, writing **surgically** so comments and
other sections survive. Like a quota'd volume, a vdisk uses the ext4-loop backend when the box is
privileged and a tmpfs otherwise; kern says which one you got and never silently drops the profile.

**`persistent` also decides who the disk belongs to.** It reads as a statement about time, and it is
also one about identity:

| | where the image lives | two boxes on the same profile |
|---|---|---|
| `persistent = false` (default) | the box's own scratch dir | **one disk each**, empty at start, gone at exit |
| `persistent = true` | the `[[disk]]` pool, or a per-user default | **one disk, shared by name** |

So a persistent vdisk is closer to a named volume than to an `emptyDir`: the name is the disk. Two
boxes cannot mount it at once, because an ext4 image mounted read-write twice corrupts, so kern takes
an exclusive lock. **The second box does not fail: it gets a tmpfs for that run and says so.**

```
kern: vdisk 'cache' is in use by another box - using a tmpfs backend this run
```

Its writes to `/vdisk/cache` are discarded at exit, which is the one case where a profile named
`persistent` does not persist. Serialise the boxes, or give each its own profile.

### Advanced: pin a vdisk to a specific disk

By default kern picks where a vdisk's image lives, the way Docker does not ask which disk a volume
goes on. With multiple disks, name a `[[disk]]` pool and point the vdisk's `backend` at it:

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

This is the one knob that stays in `kern.toml` rather than the TUI, kept out of the beginner's way.
