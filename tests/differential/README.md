# Differential suite: the same compose files under Docker and kern

Every case here is a real-world use of Docker Compose written by someone other than kern's authors,
kept as it was written. `run-chaos.sh` runs each one twice on the same machine, once with
`COMPOSE="docker compose"` and once with `COMPOSE="kern compose"`, in a fresh copy of its directory,
and compares the check lines both runs print (`EXIT_*`, `*_OK`). A case passes when both engines print
the same set, or when the difference is one the script lists with its reason.

```sh
tests/differential/run-chaos.sh              # every case
tests/differential/run-chaos.sh set2/r2-6    # one case
```

The report is `work/report.txt`; the exit status is the number of cases that differ for a reason not
listed. What a case leaves running on either engine is counted before it is cleaned up.

## What a run needs

- Docker with Compose v2 or later, and kern, on the same Linux host.
- Two NVIDIA GPUs and the NVIDIA container toolkit for the GPU cases, and a local image
  `kern-torch:test` (PyTorch with CUDA, `python3` on PATH).
- `KERN_GPU_GRANT=flag` (the default) runs the GPU cases with `kern compose --allow-device-grants`;
  `KERN_GPU_GRANT=config` expects `allow_gpu_grants = true` in the operator's own `kern.toml`.
- Host ports 2222, 8080-8095, 18080-18099 and 18443 free.

## The sets

- `set1`: ten cases (GPU, a code sandbox, SSH, HTTPS, CI, per-branch projects, networks, failure
  paths, signals, day-2 operations). `case3fix` is `case3` with its package name corrected.
- `set2`: ten harder ones (TLS on an IP, volumes across `down`, two GPU stacks, IPv6, a loopback-only
  listener, selective recreate, `ps --format json`, resource boundaries, files, concurrency).
  `r2-9abs` is `r2-9` with an absolute bind path.
- `set3`: ten covering CI exit codes, GPU, a sandbox, networks, merged files and profiles, stop
  signals, `ulimits`/`sysctls`, restart policies, `cp`/`top`, long names.
- `set4`: four aimed at the kernel side: two UIDs on one bind mount, `--scale` with a host port range,
  shared IPC, and an out-of-memory kill. `x3b` is `x3` with `ipc: "service:producer"`, the form
  Docker accepts.

Several cases contain mistakes of their own (a certificate without the IP it is checked against, a
`$` that Compose interpolates, a check printed unconditionally). They are kept: a mistake that fails
the same way on both engines is still a 1:1 result, and the script compares engines, not intentions.
