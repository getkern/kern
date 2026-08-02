# Roadmap


kern starts as a small, fast sandbox/OCI runtime and grows deliberately: the resources it governs are
driven by what proves useful. These are directions under consideration, **not commitments or dates**,
and some may never ship if they would change what kern is. Recently shipped work is under
[Project status](#project-status), not here.

- **GPU slices.** A workload gets a *slice* of a GPU, not the whole device. Not shipped, and this
  README will describe it when it is, not before. Nothing here touches a GPU today.
- **More governed resources.** The same profile model could extend to other cgroup or kernel-real
  resources (I/O bandwidth, network shaping) as they prove useful.
- **Snapshot / warm-start (CRIU).** Same-host checkpoint and restore of a *warm* box for subsecond
  restarts. Feasible but gated: rootless CRIU needs a capability and suspending the seccomp filter, so it
  would be an explicit opt-in mode, not the default, and only for same-host, non-GPU boxes. Not committed.
- **macOS.** No native port, and it is a non-goal: a daemonless kernel + cgroup sandbox has no macOS
  equivalent. The only path considered is a thin shim over a Linux VM, the same shape as WSL2.
- **1.0, freeze:** CLI + config under semver, threat model + architecture finalised.

**In progress**

- **Per-stack supervisor.** Today `up` catches a service that dies at startup; one that dies an hour
  later is not detected. Under measurement on a Pi before it gets built.

**Deliberately out, not missing**

- Network segmentation between services, `deploy.replicas`, `docker.sock` / Engine API,
  `--privileged`. These follow from rootless + daemonless + one pod as the unit of isolation, not
  from missing work.

> A stack is one pod. Within that model kern is complete: what is listed above as out is a
> consequence of the model, not a gap in it.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design.
