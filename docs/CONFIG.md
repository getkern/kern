# kern.toml

kern reads TOML from `~/.config/kern/kern.toml` and from compose files. Every key is spelled like its
CLI flag: if you know the flag, you know the key.

`KERN_CONFIG=<path>` picks another file for every command, `--config <path>` for one. `kern info` prints
the file in effect, `kern config setup` writes a starter for this host, and `kern validate <file>` checks
one.

## Profiles: declare once, attach by name

```toml
[[vcpu]]                 # CPU + memory  ->  vcpu:heavy
name    = "heavy"
backend = "host"         # the whole host CPU, or a [[cpu]] id
cpus    = 4.0            # like --cpus
memory  = "2 GB"         # like --memory

[[vdisk]]                # a size-capped disk  ->  vdisk:scratch
name    = "scratch"
backend = "ram"          # a RAM tmpfs, or a [[disk]] id
size    = "8g"

[[vgpio]]                # devices  ->  vgpio:sensors
name    = "sensors"
backend = "host"
i2c     = ["1"]                     # /dev/i2c-1
display = ["/dev/dri/renderD128"]   # the GPU, as a device
```

```sh
kern run vcpu:heavy vdisk:scratch -- ./job
kern box app --image alpine vgpio:sensors -- sh
```

- **One key per line**, and every profile names a `backend`.
- `[[vcpu]]` also takes `cpuset`, `numa`, `nice` and `extends`. `[[vdisk]]` also takes `iops`,
  `bandwidth` and `persistent`.
- `[[vgpio]]` grants only what you list: `pins`, `pwm`, `adc` and `onewire` (these need a `[[gpio]]`
  controller as `backend`), `i2c`, `spi`, `uart`, `can`, `camera`, `audio`, `midi`, `input`, `leds`,
  `bluetooth`, `net`, `display` (the GPU render node, the whole card), `usb` and `extra` (explicit
  `/dev` paths). Nodes that give control of the host (disks, raw memory, `kvm`, the console) are
  refused even when listed.
- `[[cpu]]`, `[[disk]]` and `[[gpio]]` declare the physical resource a profile's `backend` names. They
  are optional: `host` and `ram` need none.

## Compose stacks: `[box.NAME]`

`kern compose stack.toml up` starts the boxes in `depends_on` order; a `docker-compose.yml` works too.
Every service runs detached.

```toml
[box.db]
image = "redis:7-alpine"

[box.api]
image      = "alpine:3.19"
command    = ["/bin/sh", "-c", "exec sleep 60"]
depends_on = ["db"]
ports      = ["127.0.0.1:8080:80"]
env        = ["LOG=debug"]
memory     = "512m"
restart    = true
health_cmd = "wget -qO- localhost/health"
```

Every key is its flag's long name, with `_` for `-`. Where the flag differs, it is in brackets:

| | keys |
|---|---|
| source | `image`, `rootfs`, `bind_rootfs` |
| command and order | `command`, `depends_on`, `depends_healthy`, `depends_completed` |
| filesystem | `workdir`, `read_only`, `tmpfs`, `volumes` (`-v`), `volumes_from`, `user`, `uid_range`, `hostname` |
| resources | `memory`, `cpus`, `cpuset` (`--cpuset-cpus`), `swap_max` (`--memory-swap-max`), `pids_limit`, `cpu_weight`, `io_weight`, `nice`, `mem_reservation` or `memory_reservation`, `shm_size` |
| profiles | `config` (the file they are declared in), `vcpu`, `vdisk`, `vgpio` (become `vcpu:<name>` and so on) |
| network | `net`, `tun`, `ports` (`-p`), `networks`, `links`, `add_host`, `dns`, `dns_search`, `dns_opt` or `dns_options`, `ssh`, `ssh_key`, `port`, `expose` |
| security | `security_profile`, `cap_add`, `cap_drop`, `devices`, `init`, `labels`, `sysctls`, `ulimits` |
| environment | `env`, `env_file`, `secrets` |
| supervision | `restart`, `restart_max`, `stop_signal`, `stop_grace_period` (`--stop-timeout`), `timeout`, `health_cmd`, `health_interval`, `health_retries`, `health_timeout`, `health_start_period`, `health_start_interval`, `health_action` |
| images and logs | `pull` or `pull_policy`, `log_max_size`, `log_max_file` |

`port` and `expose` have no flag: they say what a service listens on inside the shared pod, so a port
collision is refused before anything starts. `kern compose stack.toml config` prints what each service
will get, without starting it.

## `[kern]` settings

```toml
[kern]
publish_bind        = "127.0.0.1"  # a port with no address binds here
compose_memory_max  = "512m"       # memory ceiling per compose service
allow_device_grants = true         # compose stacks may use device profiles
```

Without them, a port binds every interface, a compose service with no `mem_limit` gets the host's
RAM, and a stack that names a device profile is refused. They are read only from your own config,
never from a file a stack names, so a downloaded stack cannot grant itself anything. The first two are
ceilings: a stack cannot ask for more.

## Values

- A value that is a flag's argument is a quoted string: `memory = "512m"`. A switch is `true` or
  `false`. A repeatable flag is an array: `volumes = ["/data:/data:ro"]`.
- Numeric profile fields are bare numbers: `cpus = 4.0`, `nice = -5`.
- Unknown keys are ignored, so a typo is skipped too: check the file with `kern validate`.
- Seccomp and the cgroup caps cannot be turned off from a config file.

## Limits for many boxes

`KERN_MAX_CONCURRENT=N` refuses a new box while `N` are running. `KERN_FLEET_MEMORY_MAX` and
`KERN_FLEET_PIDS_MAX` cap all boxes together, but only where boxes share `kern.slice` (as root, or on a
delegated slice); kern warns when they do not apply. Per-box `--memory` and `--pids-limit` are the
caps that hold everywhere.
