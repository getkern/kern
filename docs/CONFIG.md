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
| images and logs | `pull` or `pull_policy`, `log_max_size`, `log_max_file`, `log_driver` (`none` keeps no log, as `--log-driver none`) |

`port` and `expose` have no flag: they say what a service listens on inside the shared pod, so a port
collision is refused before anything starts. `kern compose stack.toml config` says what each service
will get, without starting it, in the summary it prints on stderr.

## `[kern]` settings

```toml
[kern]
publish_bind        = "127.0.0.1"  # a port with no address binds here
compose_memory_max  = "512m"       # memory ceiling per compose service
allow_device_grants = true         # compose stacks may use device profiles
allow_gpu_grants    = true         # compose stacks may take GPUs, and no other device
sandbox_history     = "disk"       # keep the finished-sandbox lines across reboots
```

Every one can be set from the command line, which writes the same line and checks the value first:

```sh
kern config set log_max_size 10m    # write one key; a bad value is refused, nothing written
kern config get                     # every key, its value or -, and what it does (--json too)
kern config get log_max_size        # one value; exit 1 if it is not set, 3 if kern.toml does not parse
kern config unset log_max_size      # remove it: kern's default again
```

Without them, a port binds every interface, a compose service with no `mem_limit` gets the host's
RAM, and a stack that names a device profile or asks for a GPU is refused. `allow_gpu_grants` is the
narrow one: the GPU a stack asks for (`gpus:`, a `deploy` reservation, `runtime: nvidia`, an
`nvidia.com/gpu` CDI name) and no other device, where `allow_device_grants` opens every device.
They are read only from your own config, never from a file a stack names, so a downloaded stack
cannot grant itself anything. The first two are ceilings: a stack cannot ask for more.

`sandbox_history` is where kern keeps one line per finished box (time, name, image, run time, exit
code, outcome, GPU; never the output), which `kern sandbox history` and the Sandboxes tab of
`kern top` read:

| value | where | kept |
|---|---|---|
| `"memory"` (the default) | `$XDG_RUNTIME_DIR/kern/history/` | until reboot |
| `"disk"` | `$XDG_DATA_HOME/kern/history/` | across reboots |
| `"off"` | nothing new is written | |

`kern sandbox keep disk` (or `m` in the Sandboxes tab) writes this key and moves the lines already
kept to the new place; `kern sandbox keep` and `kern info` say where they are and how many there are,
and `kern sandbox clear` removes them. Each place holds about 33,000 lines, after which the oldest go.
Neither directory can be mounted into a box.

### Local names for compose services

```toml
[kern]
local_domains      = true  # compose up answers http://<service>.<project>.localhost (default true)
local_domains_port = 8780  # the port of those names (default 80 where allowed, else 8780)
```

When a compose service publishes a TCP port, `compose up` prints a name for it, e.g.
`web: http://web.shop.localhost:8780/`, and a router of your user answers it on the loopback
addresses, forwarding by the request's `Host` to the port the service published. `.localhost`
resolves to this machine with nothing to install (curl, browsers, systemd-resolved).

| name | goes to |
|---|---|
| `<service>.<project>.localhost` | the service's published port: container port 80, else 8080, 3000, 8000, 5000, else the first |
| `<port>.<service>.<project>.localhost` | the published port of that container port |
| `<service>-2.<project>.localhost` | replica 2 |
| `<box>.kern.localhost` | a box by its own name, with a published port: `kern box web -d -p ...`, or a service with `container_name` |
| `<service>.kern.localhost` | otherwise, the one running project that has that service; several are refused by name |

The router listens on port 80 where the system lets an ordinary user bind it
(`net.ipv4.ip_unprivileged_port_start` at 80 or below), otherwise on the first free port from 8780 to
8789, away from 8080, which many apps publish; `local_domains_port` fixes it. It reaches only ports your boxes already published, and leaves by
itself within a few seconds of the last box with a published port. `local_domains = false` starts no router.

On Windows, with kern in its WSL distro, the router is reached from Windows too, through WSL's
`localhost` forwarding: `curl.exe http://web.shop.localhost:8780/` answers. Windows' own name
resolver does not resolve `<name>.localhost` (`ping`, PowerShell's `Invoke-WebRequest`); there,
`http://localhost:8780/` with a `Host: web.shop.localhost` header reaches the same service.
`kern doctor` typed in Windows adds a row checked from the Windows side: a Windows program on the
same port takes the names from Windows while the distro sees nothing wrong, and the row says so,
as it says when Windows refuses to open that port, with the fix.

#### HTTPS for the local names: `kern proxy trust`

```
kern proxy trust     # once: https://<service>.<project>.localhost:8443/ answers, trusted by your browsers
kern proxy status
kern proxy untrust   # takes it out of every store it was put in, and deletes it
```

Without `kern proxy trust` nothing changes and nothing is made: the names answer `http://` as above.
`http://<name>.localhost` is already a secure context in Chrome and Firefox (service workers and the
APIs reserved to secure pages work over it; measured with Chrome 157 and Firefox 157), so HTTPS is
for what asks for it by name: an app configured with an `https://` URL, an OAuth provider that
requires one.

`trust` makes a certificate authority of your own, in `~/.local/share/kern/local-ca/` (the directory
0700, its key 0600), that can sign names under `localhost` only, and adds it to the certificate stores
of your user that Chrome (`~/.pki/nssdb`) and Firefox (each profile, the snap's and Flatpak's
included) read. The system's store is not touched. Then the router also answers HTTPS: on 443 where
an ordinary user may bind it, otherwise on the first free port from 8443 to 8452, and `kern box -d -p`,
`compose up` and `kern ps` print the `https://` URL. Each name gets its certificate when a browser
first asks for it, valid 30 days and replaced after 20; a name that is not a local name gets none.

Measured (2026-11-21) with an authority made the same way and a control authority without the
`localhost` limit: a certificate signed for another name is refused by OpenSSL 3.0.13, curl, Chrome
157 and Firefox 157 on Linux and by Windows' verifier, while the control's is accepted by each. On
Ubuntu 24.04 and in both WSL distros measured, an ordinary user cannot bind 443, so the port is 8443.

Writing those stores needs NSS's `certutil`, which a stock Ubuntu desktop does not have: without it
`kern proxy trust` says what to install (`libnss3-tools`, `nss-tools`, `nss`) and makes nothing.

On Windows, `kern proxy trust` in PowerShell also adds the authority to the certificate store of your
Windows user, which Windows asks you to confirm; in a session with no desktop (over ssh) Windows
refuses the add, and kern prints the `certutil -user -addstore Root` line to run on the desktop.
`curl.exe -k https://web.shop.localhost:8443/` and a .NET client trusting that authority were
measured to reach a box in the distro over HTTPS.

### Logs and retention

```toml
[kern]
log_max_size             = "10m"  # every box's log rotates at this size (default 16m)
log_max_file             = 2      # files each box keeps, the active one included (default 2)
log_keep_ended           = "24h"  # the log of a box that ended goes after this long
build_keep               = 200    # build records kept; older ones go when a build ends
sandbox_history_max_size = "1m"   # the history rotates at this size, two files kept (default 1m)
sandbox_transcripts      = true   # keep the code SDK sandboxes ran and its output (default true)
sandbox_transcripts_max_size = "16m"  # the most they occupy; the oldest go past it (default 16m)
```

A box's log holds at most `log_max_size` times `log_max_file`. A box's own `--log-max-size` and
`--log-max-file`, compose `logging: options: max-size` and `max-file`, and a stack's `log_max_size`
win over these two, as `--log-opt` wins over Docker's `daemon.json`; they apply to boxes started
after the change.

Without `log_keep_ended`, the log of a box that ended stays until `kern prune`, `kern gc` or a
reboot (the logs are in `$XDG_RUNTIME_DIR`, in memory). With it, kern removes those older than the
period each time a box starts with `-d`, the only moment a new log is made; a running box's log is
never touched. `30m`, `24h` and `7d` are periods.

Without `build_keep`, every build record and its log is kept (`kern build prune --keep N` removes
them by hand). With it, the records that ended longest ago go each time a build ends; a build still
running is never removed and does not count among the N.

Sandbox calls through the SDKs and MCP write no log file: their output goes back to the caller. What
they leave is the one-line history above, bounded at twice `sandbox_history_max_size`, and a
transcript per call: the code it ran and its output (`kern sandbox show`), up to 64 KiB of code and
256 KiB of each stream, in all at most `sandbox_transcripts_max_size`. Transcripts are kept where the
history is (`sandbox_history`: in memory by default, cleared at reboot; on disk only when chosen),
mode 0600; code and output can hold a secret, so `sandbox_transcripts = false` keeps none, and
`kern sandbox clear` removes them with the history.

`kern info` shows the values in force and where each comes from (`kern.toml` or the default), with
the number of build records kept.

## Values

- A value that is a flag's argument is a quoted string: `memory = "512m"`. A switch is `true` or
  `false`. A repeatable flag is an array: `volumes = ["/data:/data:ro"]`.
- Numeric profile fields are bare numbers: `cpus = 4.0`, `nice = -5`.
- Unknown keys are ignored with a warning, so a typo is skipped too: check the file with `kern
  validate`.
- The file must be valid TOML: a key twice in one table, `[kern]` twice, a header with no `]` or a
  stray line is refused by line, and a file refused that way is not applied at all (boxes start on
  the defaults, with published ports on loopback). A UTF-8 BOM at the start is fine, and so is a
  quoted key (`"log_max_size"` is `log_max_size`). `[[kern]]` is refused: the settings are one
  table, `[kern]`.
- Seccomp and the cgroup caps cannot be turned off from a config file.

## Limits for many boxes

`KERN_MAX_CONCURRENT=N` refuses a new box while `N` are running. `KERN_FLEET_MEMORY_MAX` and
`KERN_FLEET_PIDS_MAX` cap all boxes together, but only where boxes share `kern.slice` (as root, or on a
delegated slice); kern warns when they do not apply. Per-box `--memory` and `--pids-limit` are the
caps that hold everywhere.
