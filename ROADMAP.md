# Roadmap

Nothing here is a commitment or a date. Shipped work is in
[CHANGELOG.md](CHANGELOG.md); the design is in [ARCHITECTURE.md](ARCHITECTURE.md).

## Under consideration

| | where it stands |
|---|---|
| **A VM tier** (in development) | A shared kernel is the wrong boundary for genuinely hostile, multi-tenant code, and [SECURITY.md](SECURITY.md) says so rather than arguing. A microVM tier is the honest answer to that case, and it is being built. Nothing ships yet, there is no date, and it will be its own command rather than a flag on a box |
| **Running kern in a Kubernetes pod** | It runs inside a container today, and CI holds it there on `main`, on the listed branches and on every pull request: `kern box --memory 64m` inside a privileged `docker run`, red if the cap does not bite, and red if `doctor` and the box disagree where the controller cannot be delegated. What is not measured is how much LESS privilege it needs, and that is the whole question: nobody signs off a `privileged: true` pod, so the lowest rung that still runs is the spec you would hand a security team. The rungs, in order: drop `--privileged`, then the default seccomp, then the default AppArmor, then a read-only cgroup, then without `SYS_ADMIN` |
| **Fuller GPU support** | A box is given the host's GPU whole, as a device, and kern does not split a GPU or cap it per box: that is what ships today ([docs/CONFIG.md](docs/CONFIG.md)). With more than one card you already give a different one to each box. Under consideration is a per-box limit, so two boxes can share a single card. Nothing ships, and there is no date |
| **Snapshot and warm start** | Rootless CRIU needs a capability and seccomp suspended, so it would be opt-in and same-host |
| **A `kern` command on the macOS side** | A Mac already runs the ordinary Linux kern inside a Linux VM, verified by hand on colima and the same shape on Lima, OrbStack and UTM ([platforms](docs/INSTALL.md#platforms)). What is under consideration is a shim, so `kern` can be typed in the Mac's own shell without entering the VM first. A NATIVE port is not: macOS has no namespaces and no cgroups, so there is nothing to port it to |
