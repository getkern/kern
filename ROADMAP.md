# Roadmap


kern starts as a small, fast sandbox/OCI runtime and grows deliberately: the resources it governs are
driven by what proves useful. These are directions under consideration, **not commitments or dates**,
and some may never ship if they would change what kern is. Recently shipped work is under
[Status](README.md#status), not here.

- **GPU slices.** A workload gets a *slice* of a GPU, not the whole device. Not shipped, and the
  README will describe it when it is, not before.

  The judgement ships ahead of the capability, deliberately. `kern doctor` detects each GPU from
  sysfs and prints the tier a cap on it would have: `TIER-HW` where a MIG or SR-IOV partition is
  present, enforced by the device rather than by the tenant, with kern saying plainly that it read
  the partition's presence and has not measured the VRAM split; `TIER-SOFT` everywhere else. A cooperative quota on consumer hardware is
  bypassed by any tenant that talks to the device without going through the vendor library, so it is
  worth density and fairness and nothing else, and kern says so before it can cap anything. That
  detection is read-only: it reads, classifies and prints, and touches no driver.
- **More governed resources.** I/O bandwidth and IOPS caps already ship (`vdisk:` `--bandwidth` /
  `--iops`, box `--io-weight` → cgroup `io.max`/`io.weight`), and hold a box to the requested rate
  exactly where the host grants both: the `io` controller delegated to the box's cgroup (systemd
  often does not by default), and the ext4-on-loop vdisk backend (a real root, foreground box). A
  rootless box without those falls back and the caps are reported unapplied rather than pretended.
  Widening where they bind, and other kernel-real knobs like network shaping, as they prove useful.
- **Snapshot / warm-start (CRIU).** Same-host checkpoint and restore of a *warm* box for subsecond
  restarts. Feasible but gated: rootless CRIU needs a capability and suspending the seccomp filter, so it
  would be an explicit opt-in mode, not the default, and only for same-host, non-GPU boxes. Not committed.
- **macOS.** No native port, and it is a non-goal: a daemonless kernel + cgroup sandbox has no macOS
  equivalent. The only path considered is a thin shim over a Linux VM, the same shape as WSL2.

**In progress**

- **Stack-level watcher.** A service with a `restart:` policy is already restarted when it dies
  mid-run by its own per-service supervisor (`on-failure` on a non-zero exit, `always`/`unless-stopped`
  on any exit, for the stack's lifetime). What is not there yet is a watcher over the whole member
  *set* that survives an individual supervisor being killed and re-applies policy across the stack;
  lower priority now that the common case is covered.

**Deliberately out, not missing**

- Network segmentation between services, `deploy.replicas`, `docker.sock` / Engine API, and the compose
  `privileged:` service key. These follow from rootless + daemonless + one pod as the unit of isolation,
  not from missing work. (The CLI `kern box --privileged` exists, and relaxes exactly five syscalls for
  nesting; see [SECURITY.md](SECURITY.md).)

> A stack is one pod. Within that model kern is complete: what is listed above as out is a
> consequence of the model, not a gap in it.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design.
