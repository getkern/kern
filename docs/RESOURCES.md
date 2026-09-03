# Virtual resources

kern is built around one idea, *virtual resources*, exposed as **two verbs**: `box` wraps a process in
a full isolated slice; `run` caps a resource on a process you launch yourself. Isolation is the first
resource, not the only one. This page explains what each resource is and how to attach it; the exact
schema for a `kern.toml` is in [CONFIG.md](CONFIG.md).

One model: a box gets *only* what you slice for it; a bare `run` adds the same caps to a process that
otherwise still sees the host. Every shipping cap is a real cgroup v2 or kernel control; devices are
deny-by-default. GPU slices are on the [Roadmap](../ROADMAP.md).

| Resource | Flag / profile | What the box gets | Enforcement |
|---|---|---|---|
| **CPU** | `--cpus` · `--cpuset-cpus` · `--nice` · `vcpu:` | Fractional CPU-time quota, core pinning, priority | cgroup `cpu.max` / `cpuset`, hard |
| **Memory** | `--memory` · `--memory-swap-max` | Hard RAM ceiling (+ swap allowance) | cgroup `memory.max`, hard¹ |
| **Disk** | `vdisk:` · `--size` (named volumes) | Size-capped scratch at `/vdisk/<name>` | rootless: a **RAM-backed tmpfs** (counts against the box's memory cap); privileged: ext4-on-loop quota on real disk |
| **Devices** | `vgpio:` | *Only* the named GPIO/I²C/SPI/LED nodes, nothing else | fresh `/dev` + fd-pinned bind + capability deny-list (raw-mem/disk/kvm refused) |
| **PIDs** | `--pids-limit` | Fork-bomb ceiling | cgroup `pids.max`, hard |
| **Block I/O** | `--io-weight` | I/O bandwidth weight | cgroup `io` |
| **GPU** | *(roadmap)* | Not shipped | see [Roadmap](../ROADMAP.md) |

¹ Where the `memory` controller is not delegated to a non-root user's scope, kern warns and shows the one-line
`.wslconfig` fix; enforced natively on Linux.

**How to check a cap, and how not to.** `free`, `top` and `htop` inside a box report the **host's** memory,
not the box's, because the kernel does not namespace `/proc/meminfo`. That is true of every container
runtime without a `/proc` shim, and it makes a cap that *is* enforced look absent. The distinction that
matters in practice: a runtime that sizes itself from the **cgroup** (a modern JVM, Go's memory limit, most
container-aware tooling) gets the right number; one that reads `/proc/meminfo` gets the host's. Read the
cgroup, or hit the ceiling and watch the kernel do it:

```sh
kern box check --image alpine --memory 256m -- cat /sys/fs/cgroup/memory.max   # 268435456
kern box oom   --image alpine --memory 256m -- \
  sh -c 'dd if=/dev/zero of=/dev/shm/x bs=1M count=512' ; echo "exit=$?"       # exit=137, OOM-killed
```

The cap binds on every host tested, and an over-allocation is OOM-killed as a WHOLE box (exit **137**,
recorded for `kern wait` / `kern ps -a` too): kern writes `memory.oom.group=1` on the box's own cgroup,
so the kernel SIGKILLs every task at once rather than picking one victim and leaving the box half-dead
(measured: a sleeper child and the parent both vanish, no task survives, and `kern ps` shows no stale
box afterwards).

That holds on BOTH cap paths. On boards whose rootless boxes take the `systemd-run --scope` path rather
than the direct `kern.slice` one, kern builds its own cgroup inside that scope: the workload in a
`kern-box-*` child capped at exactly what you asked for, kern's supervisor in a `kern-sup` sibling, and
the scope itself 4 MiB above the box's cap so the kernel's group-kill takes the WORKLOAD and not the
process that has to report what it exited with. Your cap is what the box gets - kern's own ~1.3 MB is
no longer taken out of it. Measured identical on systemd **249, 252 and 257** (Jetson Orin Nano,
Raspberry Pi 5, Arduino UNO Q), foreground and detached, at a cost of ~2 ms of box start on that path.
Android's `lmkd` is **not running** on the UNO Q, so it is the cgroup doing the killing, not a
host-level low-memory killer.

**Enforce, or refuse to start.** Where the `memory`/`pids` controllers are not delegated (footnote ¹),
the default is to warn once and run uncapped. `--require-limits` (or `KERN_REQUIRE_LIMITS`) makes that
fatal: the box refuses to start, non-zero, unless the memory and pids caps are **read back** from the
cgroup as actually in force, so a fork-bomb / OOM-sensitive workload never runs believing it is capped
when it is not. `--allow-uncapped` (`KERN_ALLOW_UNCAPPED`) is the explicit inverse for a host with no
delegation (nested CI): accept uncapped operation silently. The two are mutually exclusive; drop one to
use the other. cpu/cpuset stay best-effort under both, as they carry no OOM/fork-bomb role.

`cpu.max` reads the same way: `50000 100000` is half a core, `200000 100000` is two.

`--pids-limit` counts **every task in the box**, not just the ones your workload forks, so the forks
available to you are the limit minus whatever is already there. That baseline is not a fixed number: it
depends on whether the command is a shell or an exec'd binary, and on whether the box is detached. On the
box measured here it was 2, so `--pids-limit 30` allowed 28 forks before the kernel returned `EAGAIN`
(`can't fork: Resource temporarily unavailable`). It is a fork-bomb ceiling, not an exact budget for your
own processes. Profiles (`vcpu:`/`vdisk:`/`vgpio:`) are reusable presets in
`~/.config/kern/kern.toml`, see [docs/CONFIG.md](CONFIG.md). Author them with `kern probe` (list the
host resources you can slice), `kern examples` (print a sample `kern.toml`), and `kern validate` (check one).

### Profiles

Name a slice once, attach it by name, and stop repeating flags. Profiles live in
`~/.config/kern/kern.toml`, so nothing has to be passed on the command line:

```sh
kern config add vcpu:slim --cpus 0.5 --memory 256m       # or edit the file by hand
kern box app --image alpine vcpu:slim -- ./app           # no flag: the profile is just there
kern run vcpu:slim -- ./train.sh                         # the same slice, no sandbox
```

What that wrote, and what a hand-written one looks like:

```toml
[[vcpu]]
name    = "slim"
backend = "host"     # the host resource being sliced: "host" is the whole CPU, so no [[cpu]] block
cpus    = 0.5
memory  = "256 MB"

[[vgpio]]
name    = "sensor"   # the interesting one: exactly one device node, everything else denied
backend = "host"
i2c     = ["/dev/i2c-1"]
```

Profile tokens go BEFORE the `--`: `vcpu:` · `vdisk:` · `vgpio:`. Use `--config ./kern.toml` only to
point at a per-project file instead of the default, or export `KERN_CONFIG` to make that the file every
command reads and writes. The full schema, every field, the 7-layer precedence and `extends` are in
**[docs/CONFIG.md](CONFIG.md)**; a runnable walk-through is
[resource-profiles.sh](../examples/resource-profiles.sh).

## The model, in two verbs


| Verb | Question it answers | What it does | Status |
|------|--------------------|--------------|--------|
| **`kern box`** | *"Isolate this workload, and slice its resources."* | Its own namespaces, overlay/read-only fs, private process tree, seccomp (**the container**), **plus** the same resource slices (`--memory`, `--cpus`, `vcpu:`, `vdisk:`, `vgpio:`). | ✅ works now |
| **`kern run`** | *"Just slice resources, no sandbox."* | Run a command against a CPU / memory quota with no namespaces: the lean governor on its own, **plus** `--landlock-rw` to confine its writes. (A **GPU slice** is on the roadmap.) | ✅ works now |

**Both take resource slices;** the difference is the sandbox. `box` = isolation **+** slices; `run` =
slices **without** the sandbox. They compose (`run` inside `box`). Both ship today.

**Both also carry a default memory cap of 512 MiB, whether or not you ask for one.** It is not the
absence of a limit that a command with no `--memory` gets: it is 512 MiB, plus no swap and a ceiling
of 512 tasks, applied by the transient systemd scope kern re-execs into. A workload that goes past it
is OOM-killed, and kern says so and names `--memory` as the fix. This is stated here because it was
not stated anywhere: `kern box --help` has always printed `default 512m` and `kern run --help` printed
only `e.g. 512m, 2g`, which reads as an example of the size format rather than as the value in force,
so a 700 MiB script exiting 137 under `kern run` had no document to look it up in.

Two ways to change it, and they are not the same:

- `--memory <size>` raises or lowers the ceiling. This is the one you want.
- `KERN_NO_SCOPE=1` removes the scope, and with it the default and the swap and task ceilings. The
  command then runs in the cgroup of whatever started it, which is usually your shell's and may be
  another application's entirely. kern warns when this happens; `KERN_ALLOW_UNCAPPED=1` says the
  uncapped run is intended and silences the warning.

**One boundary crosses the split.** `--landlock-rw <path>` works on `run` as well as on `box`, because
Landlock restricts the calling process rather than requiring a mount namespace: no image, no
`pivot_root`, nothing to build. So `kern run --landlock-rw ~/project -- ./agent` runs the binary you
already have on the host, with its writes confined by the kernel to that one directory and everything
else readable and executable.

Two differences from the same flag on `box`, both consequences of there being no namespace:

- It grants **only what you name**, plus `/dev/null` and the other character devices a program opens
  for writing. Inside a box `/tmp`, `/run` and `/proc` are the box's own ephemeral ones and are granted
  automatically; on the host they are real and persistent, so they are not.
- It **refuses to run** where the kernel has no Landlock, rather than warning and continuing as a
  resource cap does. A cap that cannot be applied leaves the command running without a limit, which
  `run` says out loud; a confinement that cannot be applied would leave it running with your files
  reachable while you believed otherwise.

It also implies `no_new_privs`, which Landlock requires: the confined command cannot gain privileges
through a setuid binary, so `sudo` inside it stops working.

## Storage: volumes and vdisks

kern models storage like the tools you already know: **Docker** for the simple 90%, **k8s/LXD** for the
power, layered so a beginner never meets the complexity.

**You almost always want just one thing: a volume.** A volume is a named folder that outlives the box
and can be shared, same as a Docker volume. Everything else is optional.

Where it lives in **`kern top`**:

- **Storage tab**: your **volumes** (create / inspect / delete / prune) + your physical disks shown
  read-only for context. This is the whole story for most people.
- **Profiles tab**: reusable box *specs* attached by prefix (`vcpu`, `vgpio`, `vdisk`). A **`vdisk`** is
  a private, size-capped disk for **one** box (like a Kubernetes `emptyDir` with a size limit), name +
  size, nothing more. Where it physically lives is a sensible default; power users can pin a `[[disk]]`
  in `kern.toml`.

Both are also editable from the **CLI** (`kern volume …`, `kern.toml`). Nothing needs you to hand-edit a
file.

> **volume vs vdisk?** A **volume** is *shared, persistent data* (`-v name:/path`), reach for this by
> default. A **vdisk** is *one box's private capped disk* (`vdisk:name` → `/vdisk/name`), reach for it
> only when a single box needs a hard-capped scratch/data disk. Same relationship as `docker volume` vs
> a Kubernetes `emptyDir`.

---

## Start here (the 90% case): a volume

A **volume** is a named folder that outlives the box and can be shared between boxes. Attach it with
`-v NAME:/path-in-the-box`. kern creates it on first use, no setup.

```sh
# write to it from one box…
kern box w --image alpine -v data:/out -- sh -c 'echo hello > /out/note.txt'
# …read it back from another. The volume persists; the boxes don't.
kern box r --image alpine -v data:/out -- cat /out/note.txt      # → hello
```

That's the whole model for most people: **`-v name:/path`, and your data is safe across runs.**

Manage them without touching the CLI:

```
kern top → Storage tab → [n]ew  [⏎]inspect  [d]elete  [p]rune
```

Volumes live under `~/.local/share/kern/volumes/` (or `$XDG_DATA_HOME/kern/volumes`).

### A volume with a size cap

Give a volume a **quota** at creation and it won't grow past it:

```sh
kern volume create cache --size 2g
kern box app --image alpine -v cache:/var/cache -- ./run.sh
```

Honest note: the quota is **enforced** only when a **privileged, foreground** box mounts it, then
kern backs the volume with a real **ext4-on-loop** image (a true filesystem-level cap). Rootless or
detached, kern falls back to a plain bind-mount and **tells you** the quota isn't enforced rather than
pretending. Either way your data is in the same place; only the *hard cap* differs.

### A volume from the network

A `-v` source can also be a URL, kern mounts it for the box's lifetime:

```sh
kern box app --image alpine -v nfs://server/export:/data   -- ./run.sh
kern box app --image alpine -v smb://server/share:/data    -- ./run.sh
kern box app --image alpine -v sshfs://user@host/srv:/data -- ./run.sh
```

---

### When you want a private, capped disk: a vdisk

A **vdisk** is a *profile* that hands one box its own size-capped disk mounted at `/vdisk/NAME`. Where a
volume is shared storage you attach ad-hoc, a vdisk is a **reusable spec** (size + IOPS + persistence)
you name once in `kern.toml` and attach with the `vdisk:` prefix.

```toml
# ~/.config/kern/kern.toml
[[vdisk]]
name = "scratch"
size = "2g"            # hard cap
persistent = false     # true = survives box removal
backend = "ram"        # REQUIRED: "ram" = a RAM-backed tmpfs, or a [[disk]] id (see below)
# iops = 500           # advanced: optional I/O limit (ext4-loop backend only)
```

```sh
kern box build --image alpine vdisk:scratch -- ./compile.sh    # → /vdisk/scratch, capped at 2g
```

Manage it interactively, **no file editing**:

```
kern top → Profiles tab → n → v   (new vdisk) / e (edit) / d (delete)
```

The form is just **name + size** (and an optional `persistent` toggle), like a Kubernetes `emptyDir`
with a size limit. Where the disk physically lives is a sensible default; it's written **surgically** to
`kern.toml`, preserving your comments and other sections.

Like a quota'd volume, a vdisk uses the ext4-loop backend when the box is privileged, and a RAM-backed
(`tmpfs`) fallback otherwise, kern says which one you got, and never silently drops the profile.

### `persistent` also decides WHO the disk belongs to

The toggle reads as a statement about time, "survives box removal", and it is also a statement about
identity:

| | where the image lives | two boxes on the same profile |
|---|---|---|
| `persistent = false` (default) | the box's own scratch dir | **one disk each**, empty at start, gone at exit |
| `persistent = true` | the `[[disk]]` pool, or a per-user default | **one disk, shared by name** |

So a persistent vdisk is closer to a named volume than to an `emptyDir`: the name is the disk. Two
boxes cannot mount it at once, because an ext4 image mounted read-write twice corrupts, so kern takes
an exclusive lock on it. **The second box does not fail: it gets a tmpfs for that run and says so.**

```
kern: vdisk 'cache' is in use by another box - using a tmpfs backend this run
```

That box runs normally and its writes to `/vdisk/cache` are discarded when it exits, which is the
one case where a profile named `persistent` does not persist. If that matters to your workload,
serialise the boxes or give each one its own profile.

---

### Advanced: pin a vdisk to a specific disk

By default kern picks where a vdisk's image lives, you don't choose, exactly like Docker doesn't ask
which disk a volume goes on, or Kubernetes uses a default StorageClass. If you have **multiple disks**
and want a `persistent` vdisk on a *specific* one (big scratch on the HDD, fast cache on the NVMe), name
a `[[disk]]` pool in `kern.toml` and point the vdisk's `backend` at it:

```toml
[[disk]]
name = "fast"
path = "/mnt/nvme"     # a writable dir on the disk you want

[[vdisk]]
name = "cache"
size = "10g"
backend = "fast"       # ← this vdisk's image lives under /mnt/nvme
```

`kern probe` lists your physical disks; `kern top`'s Overview and Storage tabs show them read-only.

```sh
$ kern probe
disks   nvme0n1  931.5G  SSD (Samsung 990 PRO)  ·  sda  1.8T  HDD (WDC WD20)
```

This is the one knob that stays in `kern.toml` (not the TUI), the deliberate "power-user escape hatch,"
kept out of the beginner's way.

---

### How they relate

```
volume  ── shared, persistent data          → -v name:/path        (kern volume · Storage tab)
vdisk   ── one box's private, capped disk    → /vdisk/name          (kern.toml · Profiles tab)
[[disk]]── (advanced) which physical disk a vdisk pins to           (kern.toml only)
```

- A **volume with a quota** and a **vdisk** use the *same* ext4-on-loop engine under the hood, a vdisk
  is essentially a one-box, size-capped volume you attach by prefix.
- The **physical disk** is a default you rarely set; it's a property of the data, not something you pick
  every time (like a k8s StorageClass).

### Which do I use?

| I want… | Use |
|---|---|
| Data that survives runs / shared between boxes | a **volume** (`-v name:/path`) |
| A cap on how big that shared data can get | a **volume with `--size`** |
| One box to have its own capped scratch/data disk | a **vdisk** profile (`vdisk:x` → `/vdisk/x`) |
| Data on a remote server | a **network volume** (`-v nfs://…`) |
| A persistent vdisk on a *specific* disk (advanced) | a `[[disk]]` + the vdisk's `backend` in `kern.toml` |

See also: [docs/CONFIG.md](CONFIG.md) for the full profile schema.
