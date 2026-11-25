# `kern top --json`: the task manager for a program

```sh
kern version --json                          # {"version":"<version>","json_schema":1}
kern top --json                              # one frame, one line
kern top --json --stream                     # one frame a line, every second (NDJSON)
kern top --json --stream --interval 0.5      # every half second (0.2 to 3600)
kern top --json --tab images,sandboxes       # a frame with those tabs' records too
```

A frame is built by the same function the `kern top` screen draws from, so the two cannot disagree
about a box. A program keeps ONE `--stream` open per machine and runs single commands only for
actions (`kern stop`, `kern logs`); on Windows the same line runs through `kern.exe` or
`wsl.exe -d kern -- kern`.

## The version contract

Every frame opens with `"schema"`, and `kern version --json` reports the same number as
`json_schema`. A reader compares that number, never the version string. Under one schema a field is
never renamed or retyped; a field may be added, so a reader ignores keys it does not know.

## A frame

| key | what it holds |
|---|---|
| `schema`, `kern`, `ts_ms`, `tabs` | the schema, kern's version, the frame's time (Unix ms), the tabs it carries |
| `host` | `cpu_pct`, `cores`, `load1`, `mem_used`, `mem_total`, `disk_used`, `disk_total`, `disk_fill_pct`, `logs_used`, `logs_total`, `logs_fill_pct` (bytes) |
| `gpus` | one object per NVIDIA card: `index`, `name`, `bus`, `mem_used_mib`, `mem_total_mib`, `util_pct`, `temp_c`, `power_w` (`null` when the driver does not say) |
| `runs` | `kern limit` invocations: `total`, `per_sec`, `peak_per_sec`, `avg_setup_us` |
| `box_starts` | box starts: `total`, `per_sec`, `peak_per_sec` |
| `services` | `docker_api` and `https`: the Docker API socket and HTTPS, in `kern info`'s words |
| `boxes` | one object per running box, and per `--restart` box between two runs: `name`, `pid` (`null` between two runs, when no process runs), `restarting` (`true` for that row), `uptime_s`, `mem_bytes`, `cpu_pct`, `tasks`, `paused`, `orphaned`, `health`, `ports`, `pod`, `isolation` (`net:host`, `net:nat`, `root-mapped`, `caps:+`, `gpu:0,1`), `confinement` (`egress`, `landlock`), `oom_kills` and `oom_killed` (processes the OOM killer ended while the box runs on), `restarts` (Docker's `RestartCount`), `network` (`nat`, `pod`, `host`, `none`, or empty when the box's init could not be read) |
| `counts` | how many `boxes`, `images`, `builds`, `profiles`, `volumes`, `sandboxes` there are |

Rates and CPU% are deltas against the previous frame; the first frame is taken 120 ms after a
baseline, so it carries real numbers.

What a frame costs, measured on a host with 2 GPUs, 557 volumes and 8951 finished sandboxes: about
2 ms of kern's CPU. The GPUs are read from ONE `nvidia-smi` that kern starts and keeps running for
the whole stream (about 3 ms of CPU a reading, against about 44 ms for a fresh one); a single frame
takes about 150 ms, 120 of them the baseline its CPU% and rates are deltas against. `services` and
a `--restart always` box's `restarts` come from `systemctl` (about 4 ms a call), read again every
5 s while streaming.

## The tabs' records

`--tab` adds the records of those tabs. The expensive ones are read only when asked, as the screen
reads them only for the tab on view:

| `--tab` | adds |
|---|---|
| `images` | `images`, in the shape of `kern images --json`: `image`, `size_bytes`, `pulled`, `dangling` |
| `builds` | `builds`: the newest 512, in the shape of `kern builds --json`; `counts.builds` is the total |
| `profiles` | `profiles`: `section`, `name`, `summary` |
| `storage` | `volumes`: `name`, `size_bytes`, `quota_bytes`; a size is a walk of the volume, so a stream measures them at most every 30 s and a volume made since then reads `null` |
| `sandboxes` | `sandboxes`: the newest 512 finished SDK and MCP sandboxes, in the shape of `kern sandbox history --json`; `counts.sandboxes` is the total |

`overview`, `boxes` and `limits` add nothing: their data is in every frame (`limits` is the screen's tab for `kern limit`, whose figures are the `runs` key; `--tab runs`, its name before, is still taken). `--tab logs` is refused:
`kern logs --all -f` is that stream already, one line a box output line.
