# kern config & profile schema

kern reads box definitions from TOML in two places today, and one more later — all sharing **one
schema**:

- **`kern compose <file>`** — a stack of `[box.NAME]` tables, brought up in `depends_on` order.
- **A future `--profile`** (0.5.x) — a single named box definition reusable by `kern box` and
  `kern run`. It will parse the *same* `[box.NAME]` table.

Because both consume the same table, the schema below is **frozen from 0.5.0**: once you write a
profile, the format won't shift under you. Changes follow the [deprecation
policy](../CHANGELOG.md) (a renamed key keeps working as a warned alias for ≥2 minors; a key whose
meaning changes is rejected with a pointer, never silently reinterpreted).

## The one rule: TOML mirrors the CLI

Every key maps to a `kern box` flag one-to-one. There is nothing to learn twice — if you know the
flag, you know the key.

- **Scalar** → a **quoted string** carrying the exact CLI argument: `memory = "512m"`,
  `cpus = "1.5"`, `cpuset = "0-3"`. (Sizes keep their unit; numbers stay quoted — the value is
  handed to the same parser the flag uses, so validation and error messages are identical.)
- **Switch** → a **TOML bool**: `read_only = true`. A `false` (or absent) key emits no flag.
- **Repeatable flag** → an **array of those same strings**: `volumes = ["src:dst:ro"]`.

`compose` shells out to `kern box`, so a value can never mean something different from its flag —
the two surfaces cannot drift.

## Box table — implemented in 0.5.0

```toml
[box.api]
# source (one required)
image      = "alpine:3.19"        # --image
rootfs     = "/var/lib/rootfs"    # --rootfs   (mutually: image OR rootfs)

# command & ordering
command    = ["/bin/sh", "-c", "exec app"]   # -- <command...>
depends_on = ["db"]               # compose-only: start after these boxes

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
cpus       = "1.5"                # --cpus
cpuset     = "0-3"                # --cpuset-cpus (CPU pinning via sched_setaffinity — works
                                  #   rootless, no cgroup cpuset delegation needed)
swap_max   = "1g"                 # --memory-swap-max
pids_limit = "512"                # --pids-limit
io_weight  = "200"                # --io-weight (cgroup v2 io.weight, 1–10000)
nice       = "5"                  # --nice (-20..19)

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

| TOML key      | CLI flag             |
|---------------|----------------------|
| `cpuset`      | `--cpuset-cpus`      |
| `swap_max`    | `--memory-swap-max`  |
| `ssh`         | `--ssh`              |
| `user`        | `--user`             |
| `volumes`     | `--volume` / `-v`    |
| `env`         | `--env` / `-e`       |
| `secrets`     | `--secret`           |
| `ports`       | `--publish` / `-p`   |
| `net`         | `--net`              |

Everything else shares the flag's long name (`memory`, `cpus`, `workdir`, `read_only`, `uid_range`,
`bind_rootfs`, `restart`, `timeout`, `nice`, `tun`, `hostname`, `pids_limit`, `io_weight`, `tmpfs`,
`env_file`, `cap_add`, `cap_drop`, `ssh_key`, `image`, `rootfs`, and the
`health_cmd`/`health_interval`/`health_retries`/`health_start_period`/`health_timeout`/`health_action`
family).

## Reserved keys — shape frozen now, parsing lands in a later 0.5.x slice

These are **decided but not yet accepted**. A key kern-public doesn't implement yet is **ignored,
not rejected** — the parser is deliberately tolerant, so a `kern.toml` shared with another kern
edition (or a newer slice) still loads; the keys below simply do nothing until their slice ships.
Their **names and array-vs-table shape are fixed now** so that when the owning slice lands, existing
profiles don't have to change.

Scalars (0.5.x):

```toml
network  = "backend"     # --network NAME (inter-box; may require a helper — see SECURITY.md)
```

Arrays of tables (structured resources, 0.5.x) — one table per device. **Field names mirror the
private runtime's `[[vgpio]]` / `[[vdisk]]` entries** (minus the GPU family), so a profile written
against one is readable by the other:

```toml
[[box.api.vgpio]]        # I/O passthrough — per-pin/LED/I2C/SPI/UART/cam/audio (0.5.6)
name    = "sensors"
backend = "gpio:0"       # references a host GPIO controller
pins    = [17, 27]       # plus: pwm, i2c, spi, uart, adc, onewire, can, camera,
i2c     = ["1"]          #       audio, leds, bluetooth, usb, input, midi, display, net

[[box.api.vdisk]]        # a named/quota disk volume (0.5.1)
name       = "data"
backend    = "disk:0"
size       = "2g"        # quota
iops       = 1000        # optional I/O limit
bandwidth  = "50m"       # optional throughput limit
persistent = true        # survive box removal
```

> **Deliberate divergences from the private (decided, not accidental):** the CPU/mem *flat* keys use
> Docker-standard names — `cpus` = quota, `cpuset` = pinning — whereas the private uses
> `vcpus` = quota, `cpus` = pinning. Public follows Docker here on purpose. There is **no
> `seccomp = "off"` / `no_seccomp` / `no_cgroup` key** — the seccomp filter and the cgroup caps are
> always on and cannot be disabled from a compose file (hardening over blind parity, by design). kern-public is also
> dependency-free (hand-rolled parser), so it does **not** import the private's `serde`/`toml`
> schema; and it is **box-centric** (`[box.NAME]` bundles a box) rather than the private's
> resource-centric model (named `[[vcpu]]`/`[[vgpu]]` profiles attached by `vcpu:`/`vgpu:` prefix).
>
> **Never public in 0.5:** the `[[vgpu]]`/`[[gpu]]` family (VRAM/compute/GPU access), the
> `intelligence`, `pool`, and physical-resource-declaration sections are out of the 0.5 schema
> entirely. See the roadmap.

## Types & tolerance

- Strings are double-quoted. An unquoted scalar (`memory = 512m`) for a key kern **implements** is a
  parse error — quote it. A *malformed value* of a recognized key is always caught, with its line.
- Bools are bare `true` / `false`. Integers are bare (`health_interval = 30`).
- Arrays are `["a", "b"]`; a comma inside a quoted element does not split it.
- `#` starts a comment outside a string.
- **Unknown keys and sections are ignored, not rejected** — a `kern.toml` written for another kern
  edition (with sections, keys, or TOML syntax this build doesn't model) still loads, so the config
  is portable across editions. The trade-off is deliberate: a typo in a key name is silently skipped
  rather than flagged, so lean on `kern validate` when authoring a profile.
