# Architecture

This documents the structure and the deliberate design choices, so the repo reads as a
designed project, not a script.

## How it works

```text
   kern  ·  one static binary, no daemon        box · run · compose · exec · pull · top …
     │
     ▼
   runtime  (kern-isolation)
     ├─ namespaces   user · pid · net · mnt · uts · ipc
     ├─ rootfs       OCI overlay → pivot_root   (typestate: Mounted → OldRootReady → ReadOnly)
     ├─ devices      fresh /dev · vgpio passthrough · -v volumes (symlink-safe)
     ├─ cgroups v2   MemoryMax · CPUQuota · TasksMax
     ├─ seccomp      always-on deny-by-default allowlist (+ wrong-arch / x32)
     └─ supervisor   fork → PID 1 → reap → exec / stats / stop
     │
     ▼
   images  (kern-oci)   registry v2 · sha256 per blob · in-process tar vetting
```

A `kern box` is one short-lived process tree: no daemon, no shared state.

1. **Namespaces.** `unshare` into a fresh user + PID + UTS + IPC + net namespace. The net namespace
   gets Docker's default, a NAT of its own (pasta) with outbound and no reach into the host's loopback;
   `--network none` leaves it loopback only, as every SDK sandbox has it; `--net` shares the host's,
   opt-in, flagged in the status panel. A box on that default NAT usually ENTERS a user and net
   namespace kern prepared ahead, its NAT already up, instead of waiting for pasta at start: one is
   kept ready between boxes (an idle holder process and its pasta), serves exactly one box and goes
   with it, and the box keeps its own hostname, hosts and resolvers. `KERN_NET_POOL=0` turns it off. A single-uid map makes your uid root *inside* the box only; `--uid-range` opts into a full
   sub-id range.
2. **Root filesystem.** An **overlay** by default (image = read-only lower, a private upper takes
   writes); `--read-only` remounts it read-only *after* a self-pivot (`pivot_root(".", ".")`), which
   works even where a bind remount-RO is denied (some Android-kernel boards). Nothing is written into
   the rootfs, so many boxes share one read-only rootfs concurrently. (`--bind-rootfs` swaps the
   overlay for a direct bind: faster on a slow overlayfs, at the cost of a mutable shared source.)
3. **Devices, volumes & secrets.** A fresh `/dev` with the safe nodes (`+ /dev/net/tun` on `--tun`);
   `-v` volumes bound in with targets resolved **symlink-safely**, confined to the new root; secrets
   on a RAM `/run/secrets` (`0400`); `vdisk:`/`vgpio:` mounting exactly their declared disk/peripherals.
4. **Lockdown.** A clean env (no host secrets leak in), capabilities stripped to least-privilege, an
   optional `--user` drop, an always-on deny-by-default **seccomp allowlist** (moby's own default
   filter minus kern's 35 escape syscalls; incl. wrong-arch + x32 kills; the wider **denylist** is the
   opt-out via `KERN_SECCOMP=denylist`), and cgroup caps:

`kern box <name> --plan` prints the exact sequence for your invocation, without running it: that
output is generated from the code, so it cannot drift the way a description here would.
See **[SECURITY.md](SECURITY.md)** for where each boundary is real, cooperative, or opt-in.

## Peer relays, when a stack gives each service its own namespace

A stack is normally one pod. `kern compose --no-pod` gives each service its own network namespace
instead, and reaches peers over relays. Each service gets a stack-wide loopback alias; its own name
resolves to `127.0.0.1` where its listener is, and every peer resolves to that peer's alias.

- **A relay is two processes and a socketpair**, passing the accepted socket as `SCM_RIGHTS`, because
  descriptors are not namespaced and one process cannot do it: from inside box A,
  `open("/proc/<B>/ns/user")` fails `EACCES`, one step before `setns` is reached.
- **A shared container port costs only the wildcard side**, and which side that is comes from
  measurement, not from a compose file that never names an address. The holder reads
  `/proc/<pid1>/net/tcp` for the box that would host each relay, after the services have bound, which
  reports that pid's network namespace with no `setns` and no privilege. A specific listener leaves
  the alias free and is served; a wildcard listener owns every address on its port and that direction
  is reported by name with both remedies. A service that has not bound yet is a third answer,
  deferred and re-measured every pass, so a service that restarts bound differently changes the answer
  with no command run.
- **Both halves shed their privilege and refuse to serve if they cannot.** `setns` into a box's user
  namespace takes a process from `CapEff: 0` to `000001ffffffffff`, and the halves also keep the host
  mount namespace, so they are the only processes in a stack with a host filesystem view reachable
  from inside a box. The connector drops everything on entry; the listener narrows to
  `CAP_NET_BIND_SERVICE` before its bind and to zero after, because a service on port 80 puts that
  bind under it. Verified on x86_64 and a Raspberry Pi 5: `CapEff`, `CapPrm`, `CapBnd` and `CapAmb`
  all zero, `NoNewPrivs: 1`, `Seccomp: 2`, with port 80 still served.
- **The relay filter is a denylist where a box gets an allowlist**, and the asymmetry is the point. A
  box runs arbitrary tenant code, so only deny-by-default means anything there. A relay half runs this
  crate in a straight line and parses no tenant bytes, while an allowlist would have to be right on
  every architecture kern publishes, where musl picks spellings per target and one missing spelling is
  a `SIGSYS` on a board rather than a test failure. What is denied is the set that makes a host
  filesystem view worth anything: `execve`, the file-opening family, `mount`, `ptrace`,
  `process_vm_*`, `setns`, `unshare`, `bpf` and the module calls. A unit test asserts that `openat`
  kills with `SIGSYS` while a socketpair and a byte still pass.
- **A dead half takes its own edge down, and the edge is rebuilt** against the namespaces that exist
  now; a box whose PID 1 has moved has exactly the edges touching it rebuilt. Every rebuild is
  recorded, because an edge that dies twice a minute would otherwise look healthy, and one that keeps
  failing is named in a `degraded` file that `kern compose ps` prints as
  `peer edge DOWN: <a> -> <b> on <port>`. Retrying costs a registry read, so an edge whose service is
  merely restarting comes back on its own: measured, given up at attempt 12 and rebuilt at attempt 114
  when the box returned. Fail-closed applies at spawn and only at spawn: a plan that cannot be
  realised at all is a stack-level fact that `up` reports, while a half dying at hour three is
  repaired at service level. Because the holder heals itself, `compose start` no longer replaces it
  when the plan is unchanged.
- **Every pump arms `PR_SET_PDEATHSIG` against the connector.** It is not inherited across `fork`, so
  the per-connection pumps used to survive the holder while still bridging two boxes' namespaces,
  `compose down` included. An integration test asserts that killing the holder leaves nothing behind,
  with a live connection open as its positive control. A peer blocked in `read` through a relay sees a
  clean FIN and end-of-file when the holder is killed, not a reset, so the correct client response is
  to reconnect.
- **Published ports are one registry string read two ways**, by `ports::fmt` and its documented
  inverse `ports::parse_display`. Storing the structured value and formatting at display time is not
  available: `fmt`'s output is the only wire format there is, a second structured field would
  duplicate state, and re-encoding the existing one would make a running kern read nothing for boxes
  a previous kern started. So the drift is closed by exhausting the space instead of by deleting a
  reader: every bind-address shape `fmt` can emit, both ports at their boundaries, both protocols, in
  the single and the comma-joined forms. One asymmetry is deliberate, `parse_display` refusing port
  `0`, which means "any port" to `bind` and addresses nothing.

## Workspace

```
crates/
  kern-cli/        the `kern` binary (published as `getkern`); thin main + cli + commands/ + sandbox/
  kern-common/     shared newtypes (BoxName, …), units can't be mixed up
  kern-oci/        OCI pull / layer extraction / whiteout (security-critical path-safety)
  kern-isolation/  namespace / cgroup / mount primitives + the characterization seam
```

A GPU layer is **deferred to a later phase** and is additive: nothing in the core changes to accommodate
it. The only GPU code here is `kern-cli/src/gpu.rs`, a read-only classifier: it reads `/sys/class/drm`
and `/proc`, decides what a VRAM cap on each card would be worth, and hands its two readers a string
to print: `kern doctor`, a row per card, and `kern box … --plan`, which prints the full statement
when a profile grants a render node. It slices nothing and loads nothing, which is why it fits in a
single static binary while the
layer that would actually cap a GPU does not. This document will describe that layer when there is
something to describe.

## Design choices (and why)

- **Real `mod`s, no `include!()`.** The binary uses ordinary modules with `pub(crate)`
  boundaries and a command enum + `match` dispatch, a real module tree, not a concatenated
  script.
- **The sandbox is a sequence of steps against a seam.** Mount/pivot/remount operations go
  through the `kern_isolation::MountOps` trait. A `Recorder` impl captures the exact ordered
  call list so a test asserts it byte-identical before/after a refactor, the *refactor-safety*
  net for the setup sequence. This does **not** replace the real-syscall correctness tests that
  actually mount/pivot and assert escape-blocked.
- **Mount-ordering as a typestate.** `Rootfs<Mounted>` → `create_old_root()` →
  `Rootfs<OldRootReady>` → `into_readonly()` makes "remount read-only before `.old_root`
  exists" a *compile error*, not a runtime bug.
- **GPU backends as a closed enum (roadmap).** `enum Backend { Cuda, Hip, Vulkan }` with
  exhaustive `match`, the compiler forces every vendor to be handled; `Box<dyn>` only if/when
  third-party backends are allowed.
- **One driver proxy (roadmap).** `GovernedDriver<D: RealDriver>` checks the quota then
  forwards via the public API, a single, inspectable interception boundary (the auditability
  story).
- **Errors:** `Result`-based in libraries (the target is `thiserror` enums), mapped to an
  exit code in exactly one place in the binary. Post-fork, pre-exec child code stays
  `exit()`-based by necessity (you cannot unwind a `Result` across `fork`).
- **Zero-heap on hot paths, opt-in only.** Where it matters (per-syscall buffers), stack
  buffers; never as premature optimization elsewhere.

## Tests

Four layers (Rust-standard): unit (inline `#[cfg(test)]`), integration (`tests/`, black-box
binary), the characterization seam (deterministic, privilege-free), and real-syscall
correctness tests (skip-graceful where namespaces/HW are unavailable). CI x86 stays
always-green via skip-graceful gates on both x86 and a native aarch64 runner; the specific boards
(Pi, Jetson, UNO Q) are also validated by hand, and the real-GPU tests land with the GPU layer
(roadmap). See
`CONTRIBUTING.md`.
