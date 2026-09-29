# Roadmap and known gaps

What kern does not do. Nothing here is a commitment or a date. Shipped work is in
[CHANGELOG.md](CHANGELOG.md); the design is in [ARCHITECTURE.md](ARCHITECTURE.md).

## Under consideration

| | where it stands |
|---|---|
| **A VM tier** (in development) | A shared kernel is the wrong boundary for genuinely hostile, multi-tenant code, and [SECURITY.md](SECURITY.md) says so rather than arguing. A microVM tier is the honest answer to that case, and it is being built. Nothing ships yet, there is no date, and it will be its own command rather than a flag on a box |
| **Running kern in a Kubernetes pod** | It runs inside a container today, and CI holds it there on `main`, on the listed branches and on every pull request: `kern box --memory 64m` inside a privileged `docker run`, red if the cap does not bite, and red if `doctor` and the box disagree where the controller cannot be delegated. What is not measured is how much LESS privilege it needs, and that is the whole question: nobody signs off a `privileged: true` pod, so the lowest rung that still runs is the spec you would hand a security team. The rungs, in order: drop `--privileged`, then the default seccomp, then the default AppArmor, then a read-only cgroup, then without `SYS_ADMIN` |
| **More governed resources** | I/O bandwidth and IOPS ship and bind where the host delegates `io`. Widening that, plus network shaping |
| **Snapshot and warm start** | Rootless CRIU needs a capability and seccomp suspended, so it would be opt-in and same-host |
| **A `kern` command on the macOS side** | A Mac already runs the ordinary Linux kern inside a Linux VM, verified by hand on colima and the same shape on Lima, OrbStack and UTM ([platforms](docs/INSTALL.md#platforms)). What is under consideration is a shim, so `kern` can be typed in the Mac's own shell without entering the VM first. A NATIVE port is not: macOS has no namespaces and no cgroups, so there is nothing to port it to |

**Out by design:** the OCI runtime spec (reading OCI images is a format and is done; being podman's
`--runtime` or a CRI under a kubelet is not), network segmentation between services,
`deploy.replicas`, `docker.sock`, the compose `privileged:` key, an automatic fallback on a port
collision, and a per-box seccomp profile from a file. A stack is one pod, and an arbitrary OCI
profile is a parser whose bugs permit rather than crash.

## Known gaps, and what would settle them

| gap | what it costs you | what would settle it |
|---|---|---|
| The progress gate classifies by module, not by meaning | Three image-cache diagnostics were silenced under an SDK: a damaged entry was re-fetched without saying so, and a suite caught it rather than the gate | A rule that reads what a line says |
| `--egress-allow` cannot be validated on most hosts | Under policy routing the defective version passes exactly as the fix does, so `acceptance-matrix.sh` reports that it validated nothing | A board without policy routing |
| Landlock is absent on every ARM board tested | `--landlock-rw` REFUSES rather than running unconfined. Measured absent on Raspberry Pi OS 6.6, Jetson 5.15-tegra and Arduino UNO Q 6.16 | The kernel shipping the LSM |
| A host delegating `memory` but not `pids` | Would take the default `TasksMax=512` silently. Not observed anywhere tested | A predicate that stays quiet on healthy hosts |
| `kern ps` prints the mapping recorded at start | A forwarder killed while its box runs would still show. It dies with the supervisor, so the window is narrow | A live probe |
| Three legacy fallbacks in the pod store reason about a forgeable pid | Reachable only from a pod dir written by an older kern; how the forgery was verified is in `pod.rs` | One condition against the STORE FORMAT: when such a dir can no longer be produced, all three go together |
| Whether a survivable denial helps an attacker | Eleven denied syscalls return `ENOSYS` so probing software falls back. The errno leaks nothing; whether a cheaper map of the filter helps code already executing is not measured | `SECCOMP_RET_USER_NOTIF` hides the structure, but the listener must be the box's parent and fail closed |
