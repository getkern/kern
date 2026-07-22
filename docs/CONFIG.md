# kern config & profile schema

kern reads TOML from `~/.config/kern/kern.toml` and from compose files. Two kinds of definition live
there, sharing **one schema philosophy** (every key mirrors a CLI flag):

- **Resource profiles**: reusable `[[vcpu]]` / `[[vgpio]]` / `[[vdisk]]` tables, attached to any
  `kern box` or `kern run` by **prefix**: `kern run vcpu:heavy vgpio:sensors vdisk:data -- ./job`.
  Managed with `kern config`, and edited live (guided, validated) in `kern top`.
- **Compose stacks**: `[box.NAME]` tables in a compose file, brought up by `kern compose` in
  `depends_on` order.

The parser is hand-rolled (no `serde`/`toml`) and **tolerant**: an unrecognized section or key, or a
line of TOML it doesn't model, is **ignored, not rejected**, so a `kern.toml` shared with another kern
edition still loads. A *malformed value* of a key it DOES implement is always an error, with its line.

---

## Resource profiles

Profiles are **resource-centric**: you declare a named slice once, then attach it to as many boxes as
you like by its prefix. This mirrors the private runtime's model (declare-then-carve, attach-by-prefix);
the CPU field names are spelled to match the CLI flags here, see the divergence note at the end. The
GPU family stays private, see [Roadmap](../README.md#roadmap).

### `[[vcpu]]`, a CPU + memory slice · attach with `vcpu:<name>`

```toml
[[vcpu]]
name     = "heavy"
cpus     = 4.0         # core QUOTA (cgroup cpu.max), like --cpus: 4.0 = four cores, 0.5 = half a core
memory   = "2 GB"      # RAM limit (cgroup memory.max), like --memory
cpuset   = "0-7"       # optional CPU PINNING (cpulist), like --cpuset-cpus; exclusive with `numa`
numa     = 0           # optional: pin to this NUMA node's CPUs
nice     = -5          # optional: scheduling priority, like --nice (-20 high … 19 low)
backend  = "cpu:0"     # optional: reference a [[cpu]] declaration to carve from; omit = standalone
extends  = "base"      # optional: inherit another [[vcpu]] by name
```

> Profile fields match the CLI flags **1:1**: `cpus` = `--cpus` (quota), `cpuset` = `--cpuset-cpus`
> (pinning), `memory` = `--memory`, `nice` = `--nice`. Know the flag, know the field.

### `[[vgpio]]`, device passthrough · attach with `vgpio:<name>`

Deny-by-default: **only** the peripherals you list cross into the box; every other `/dev` node is
refused. Each device is fd-pinned at bind time to close a check→mount race.

```toml
[[vgpio]]
name    = "sensors"
backend = "gpio:0"     # references a [[gpio]] controller (required)
pins    = [17, 27]     # GPIO lines
pwm     = [18]         # PWM channels
i2c     = ["1"]        # /dev/i2c-1
spi     = ["0.0"]      # /dev/spidev0.0
adc     = [0]
onewire = [4]
# also available: uart, can, camera, audio, leds, bluetooth, usb, input, midi, display, net, extra
# `extra` takes explicit /dev paths (validated); everything is refused unless a capability-based
# deny-list (raw memory, disks, VFIO/DMA, kvm, HID injection, the console, …) rejects it first.
```

### `[[vdisk]]`, a size-capped disk · attach with `vdisk:<name>`

```toml
[[vdisk]]
name       = "data"
size       = "2g"          # quota
backend    = "disk:pool"   # REQUIRED: a declared [[disk]] pool, or "ram" for a RAM-backed tmpfs
iops       = 1000          # optional I/O-ops limit
bandwidth  = "50m"         # optional throughput limit
persistent = true          # survive box removal (default: false → scratch, discarded)
```

A `vdisk:` appears in the box at `/vdisk/<name>`: a RAM tmpfs when rootless, or an ext4-on-loop image
with a real quota when privileged.

### Physical declarations, what a profile's `backend` points at

Declaring these is optional (a profile can use the reserved `host`/`ram` backend without them), but
every profile **must name a `backend`**: a declared block below, or `host` (vcpu/vgpio) / `ram` (vdisk).
Field shapes:

```toml
[[cpu]]   # a physical CPU budget a [[vcpu]] splits
id = "0"; cores = 16.0; memory = "32 GB"; cpuset = "0-15"; numa = 0

[[gpio]]  # a physical GPIO / peripheral controller a [[vgpio]] draws from
id = "0"; total_pins = 40; pins = [2, 3, 4, 17, 27]; i2c = ["1"]; leds = ["led0"]
# a specific USB port can be reserved on a controller:
[[gpio.usb_ports]]
bus = 1; port = 2; name = "sensor-hub"

[[disk]]  # a physical disk pool a [[vdisk]] places volumes on
name = "pool"; path = "/var/lib/kern/disks"; default = true; size = "100g"; iops = 5000
```

---

## Compose, `[box.NAME]` tables

`kern compose <file>` brings up a stack of `[box.NAME]` tables in `depends_on` order (it also reads a
`docker-compose.yml`). Every key maps to a `kern box` flag one-to-one, `compose` shells out to
`kern box`, so a value can never mean something different from its flag.

```toml
[box.api]
# source (one required)
image      = "alpine:3.19"        # --image
rootfs     = "/var/lib/rootfs"    # --rootfs   (mutually: image OR rootfs)

# command & ordering
command    = ["/bin/sh", "-c", "exec app"]   # -- <command...>
depends_on = ["db"]               # start after these boxes
# conditional dependencies, `up` WAITS for the condition before starting this box:
depends_healthy   = ["db"]        # wait until each named box's health_cmd reports healthy
depends_completed = ["migrate"]   # wait until each named box exits 0 (init-container / migration job)
# Docker long-syntax is accepted verbatim too, so a docker-compose.yml block pastes in as-is:
#   depends_on = { db = { condition = "service_healthy" }, migrate = { condition = "service_completed_successfully" } }
# Constraints (rejected at bring-up, not left to time out): a `depends_healthy` target must declare
# `health_cmd`; a `depends_completed` target must NOT set `restart = true` (it would never complete).
# `up` waits up to 120s per condition, and aborts early if a dependency dies or fails.

# filesystem / runtime
workdir    = "/srv"               # --workdir / -w
read_only  = true                 # --read-only
bind_rootfs = false               # --bind-rootfs   (rootfs only; mutually excl. read_only)
uid_range  = false                # --uid-range
hostname   = "api"                # --hostname
user       = "1000:1000"          # --user  (UID[:GID] inside the box)
tmpfs      = ["/tmp:64m"]         # --tmpfs  (repeatable; PATH[:size])

# resources
memory     = "512m"               # --memory / -m
cpus       = "1.5"                # --cpus                (quota)
cpuset     = "0-3"                # --cpuset-cpus         (pinning, via sched_setaffinity, rootless)
swap_max   = "1g"                 # --memory-swap-max
pids_limit = "512"                # --pids-limit
io_weight  = "200"                # --io-weight (cgroup v2 io.weight, 1-10000)
nice       = "5"                  # --nice (-20..19)
# (Resource profiles attach on the CLI, `kern run vcpu:heavy vgpio:sensors -- cmd`, not via a box
#  key yet. Docker's `profiles: [...]` service-gating key IS honored: a service with a non-empty
#  profile list stays inactive unless enabled via COMPOSE_PROFILES, exactly like Docker.)

# networking
net        = false                # --net   (share host net; no isolation)
tun        = false                # --tun   (expose /dev/net/tun)
ports      = ["127.0.0.1:8080:80"]  # --publish / -p  (repeatable)
ssh        = "2222"               # --ssh PORT  (in-box sshd on host PORT)
ssh_key    = "/keys/id.pub"       # --ssh-key   (authorize this pubkey instead of a throwaway)

# environment / secrets
env        = ["LOG=debug", "PORT=8080"]   # --env / -e  (repeatable)
env_file   = ["/etc/app.env"]     # --env-file  (repeatable; K=V lines)
secrets    = ["/host/db-pw:db"]   # --secret  (repeatable; src:name → /run/secrets/name)

# least privilege
cap_add    = ["NET_ADMIN"]        # --cap-add  (repeatable)
cap_drop   = ["ALL"]              # --cap-drop (repeatable)

# supervision (detached boxes)
restart              = true       # --restart
timeout              = "300"      # --timeout  (auto-stop after N seconds)
health_cmd           = "wget -qO- localhost/health"   # --health-cmd
health_interval      = 30         # --health-interval (integer seconds)
health_retries       = "3"        # --health-retries
health_start_period  = "10"       # --health-start-period
health_timeout       = "2"        # --health-timeout
health_action        = "restart"  # --health-action <restart|stop|none>

# host paths
volumes    = ["/data:/data:ro", "/etc/app:/app"]  # --volume / -v  (repeatable)
```

### Key → flag map (the non-obvious ones)

| TOML key   | CLI flag            |
|------------|---------------------|
| `cpuset`   | `--cpuset-cpus`     |
| `swap_max` | `--memory-swap-max` |
| `ssh`      | `--ssh`             |
| `user`     | `--user`            |
| `volumes`  | `--volume` / `-v`   |
| `env`      | `--env` / `-e`      |
| `secrets`  | `--secret`          |
| `ports`    | `--publish` / `-p`  |
| `net`      | `--net`             |

Everything else shares the flag's long name (`memory`, `cpus`, `workdir`, `read_only`, `uid_range`,
`bind_rootfs`, `restart`, `timeout`, `nice`, `tun`, `hostname`, `pids_limit`, `io_weight`, `tmpfs`,
`env_file`, `cap_add`, `cap_drop`, `ssh_key`, `image`, `rootfs`, and the
`health_cmd`/`health_interval`/`health_retries`/`health_start_period`/`health_timeout`/`health_action`
family).

---

## The one rule: TOML mirrors the CLI

Every key maps to a flag one-to-one, nothing to learn twice. If you know the flag, you know the key.

- **Scalar** → a **quoted string** carrying the exact CLI argument: `memory = "512m"`, `cpus = "1.5"`,
  `cpuset = "0-3"`. (Numeric profile fields like `cpus = 4.0` / `iops = 1000` / `nice = -5` are
  bare numbers, as shown above.)
- **Switch** → a **TOML bool**: `read_only = true`. A `false` (or absent) key emits no flag.
- **Repeatable flag** → an **array**: `volumes = ["src:dst:ro"]`, `pins = [17, 27]`.

## Types & tolerance

- Strings are double-quoted. An unquoted scalar (`memory = 512m`) for a key kern **implements** is a
  parse error, quote it. A *malformed value* of a recognized key is always caught, with its line.
- Bools are bare `true` / `false`. Integers/floats are bare (`health_interval = 30`, `cpus = 4.0`).
- Arrays are `["a", "b"]` / `[17, 27]`; a comma inside a quoted element does not split it.
- `#` starts a comment outside a string.
- **Unknown keys and sections are ignored, not rejected**: a `kern.toml` written for another kern
  edition still loads, so config is portable across editions. The trade-off is deliberate: a typo in a
  key name is silently skipped, so lean on `kern config` / `kern top` (which validate live) when authoring.

## Deliberate divergences from the private runtime

- **Profiles are resource-centric and identical in shape** to the private (`[[vcpu]]`/`[[vgpio]]`/`[[vdisk]]`
  attached by prefix), a profile file is portable between the two. Compose is the box-centric surface
  (`[box.NAME]`), a public addition.
- **CPU field names match the CLI everywhere**: `cpus` = quota, `cpuset` = pinning in both the flat
  compose keys AND the `[[vcpu]]` profile. This aligns the public schema with the flags 1:1, diverging
  from the private runtime's older `vcpus` = quota / `cpus` = pinning spelling. Chosen on purpose.
- **No `seccomp = "off"` / `no_seccomp` / `no_cgroup` key**: the seccomp filter and the cgroup caps
  are always on and cannot be disabled from config (hardening over blind parity, by design).
- **Not public:** the `[[vgpu]]` / `[[gpu]]` family (VRAM/compute/GPU slices), and the `intelligence`
  / `pool` sections, are on the [roadmap](../README.md#roadmap), not in the schema yet. A config that
  declares them still loads (the keys are ignored) so it stays portable.

## Fleet limits (environment)

Per-box caps (`--memory`, `--cpus`, `--pids-limit`) bound each box on its own. For a HOST that runs many
boxes (a serverless `box fn` pattern, an agent platform), three environment variables bound the fleet as
a whole. They are deployment-level, so they live in the environment kern runs under, not in a `kern.toml`
profile:

| Variable | Effect | Kind |
|---|---|---|
| `KERN_MAX_CONCURRENT=N` | Refuse to start a new box when `N` boxes are already running. | **Cooperative, best-effort.** First-party governor, NOT a security boundary (a caller can unset it). The count is crash-safe (a dead box's slot frees automatically). It is checked per box start, so a **concurrent burst** (`kern compose up`, `xargs -P kern box`) can race the count and overshoot `N` by the burst size. |
| `KERN_FLEET_MEMORY_MAX` | A `memory.max` on kern's shared `kern.slice`, bounding the SUM of all boxes' memory. Accepts `512m`, `4g`, or bare bytes. | **Kernel-enforced ONLY when boxes share `kern.slice`** (see below). |
| `KERN_FLEET_PIDS_MAX` | A `pids.max` on `kern.slice`, bounding total tasks across all boxes. | Same condition as above. |

**Important scope of the fleet caps.** The fleet SUM caps write `memory.max` / `pids.max` on kern's
`kern.slice` and only bound boxes that actually run INSIDE that slice, which happens on the **direct-cap
path** (kern as root, or a host where a delegated `kern.slice` is ensured). In the common ROOTLESS setup
kern puts each box in its OWN per-box systemd scope (under `app.slice`, NOT `kern.slice`), so the fleet
SUM is currently **not** enforced there. kern does not stay silent about it: when a fleet cap is set but
the direct-cap path is not taken, it prints a one-line warning at box start. The **per-box `--memory` /
`--pids` caps are the reliable knob and enforce everywhere the controller is delegated** (verified on
x86, the ARM boards, and the VPS: a box over its `--memory` is OOM-killed). For a guaranteed fleet bound
today, run kern as root, or cap each box with `--memory` / `--pids`. A rootless shared-slice fleet cap is
tracked as a post-launch improvement. Example:

```sh
export KERN_MAX_CONCURRENT=200        # at most 200 boxes at once
export KERN_FLEET_MEMORY_MAX=16g      # SUM cap, enforced only when boxes share kern.slice (see above)
export KERN_FLEET_PIDS_MAX=20000
```

**Cross-box OOM semantics.** `KERN_FLEET_MEMORY_MAX` caps the SUM of all boxes on the shared
`kern.slice`. When that shared ceiling is hit, the kernel's cgroup OOM killer acts at the slice level: it
picks a victim task by the usual heuristic (roughly the largest RSS) across ALL boxes, so one box's
memory spike can cause a task in a DIFFERENT box to be killed. This is the intended pooled-budget
behavior (the fleet shares one hard limit), but it means a fleet cap is not a per-box guarantee. For a
workload that must not be collateral, ALSO give it a per-box `--memory`: a box with its own `memory.max`
is OOM-scoped to itself first (its own cgroup limit is hit before it can push the slice over), so the
fleet cap becomes a backstop for the aggregate rather than the thing that kills your critical box.
