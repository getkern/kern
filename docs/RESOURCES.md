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

The cap binds on every host tested. On the Arduino UNO Q - whose rootless boxes take the
`systemd-run --scope` path, not the direct `kern.slice` one - an over-allocation is OOM-killed as a
WHOLE box (exit **137**), the same as the direct path: the per-box scope is not `Delegate=yes`, so
kern writes `memory.oom.group=1` onto the scope's own cgroup and the kernel SIGKILLs every task at
once rather than one victim (measured: a sleeper child and the parent both vanish, no task survives,
and `kern ps` shows no stale box afterwards). Android's `lmkd` is **not running** on that board, so it
is the cgroup doing the killing, not a host-level low-memory killer. `memory.max` reads back 33554432
throughout.

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
| **`kern run`** | *"Just slice resources, no sandbox."* | Run a command against a CPU / memory quota with no isolation: the lean governor on its own. (A **GPU slice** is on the roadmap.) | ✅ works now |

**Both take resource slices;** the difference is the sandbox. `box` = isolation **+** slices; `run` =
slices **without** the sandbox. They compose (`run` inside `box`). Both ship today.
