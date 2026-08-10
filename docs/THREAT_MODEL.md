# Threat model

This is the structured view: who the attacker is, what they are after, where they get in, and which
boundaries hold against them. It is the map; [SECURITY.md](../SECURITY.md) is the per-mechanism
detail (every flag, syscall and check, with the bypasses named) and [OPEN_ITEMS.md](../OPEN_ITEMS.md)
is the register of what is not yet known or done. Where a number matters, ask the binary
(`kern box <name> --image <ref> --show-config`) rather than trusting a figure copied into prose.

The one rule this document keeps: **a boundary and a governor are named separately.** A boundary is
enforced by the kernel and holds against the workload itself; a governor shapes an honest workload
and a hostile first-party one steps around it. Conflating the two is the most expensive mistake a
sandbox document can make, so every row below says which it is.

## Assumptions

**Trusted.** The host kernel (reasonably current; kern's isolation is *built on* it, so a
kernel privilege-escalation bug is an escape). The operator who runs `kern` (their uid, their
credentials, their host paths). The `kern` binary itself (provenance is anchored with signed tags and
an independent timestamp).

**Untrusted.** Everything the workload or an image author controls: the in-box process, the OCI image
or `--rootfs`, the compose file, the bytes a registry returns, and any content reachable over the
box's network.

## Assets an attacker wants

1. **The host filesystem** outside the box's rootfs (read a host file, write or corrupt one).
2. **The host kernel, processes and mounts** (escape the namespaces; see or signal host or peer-box
   processes; reach the host mount tree).
3. **A peer box's secrets and posture.** kern's runtime registry holds other boxes' SSH host keys,
   `--secret` values, and the recorded capability/seccomp/AppArmor posture that `kern exec` reproduces.
   Reading it steals a peer's secrets; writing it forges a peer's posture to weaken that peer's `exec`.
4. **The operator's registry credentials** (lift them from argv, a world-readable file, or a token
   redirect).
5. **Host network reachability** the box's own netns should not grant (reach a host-loopback service,
   the LAN, or a host-side transport such as vsock on WSL2).

## Entry points (untrusted input)

- **The in-box workload** - arbitrary code with a shell, syscalls, and the box's namespace surface.
- **The OCI image / `--rootfs`** - a crafted tar (path traversal, symlink or hardlink escape,
  whiteout tricks, tar-parser desync) and hostile file modes.
- **The compose file** - dependency cycles, restart contradictions, override merges.
- **The registry** - a compromised or MITM'd host serving mismatched bytes, a downgraded transport,
  or a token realm on a foreign host.
- **Host-path flags** - `-v`, `--secret`, `--env-file`, `--rootfs`, the `kern build` context and `-f`
  Dockerfile, `kern cp`, `kern save -o`: every path where the box or the image can aim a read or write
  at a host location it should not reach, including kern's own registry.
- **The network** - egress destinations, published ports, network volumes.

## Trust boundaries: two levels, stated separately

### REAL - kernel-enforced, holds against the workload

| Boundary | Enforced by | Notes |
|---|---|---|
| Process / mount / UTS / IPC isolation | `unshare` + `pivot_root`, root remounted read-only **last** (compile-enforced by a typestate) | a box sees no host process, mount, or peer box |
| Rootless privilege | user namespace; box-root maps to an unprivileged host uid | no host uid 0 unless the caller is real root, where `--privileged` is refused |
| Dangerous syscalls | **always-on seccomp, allowlist by default** (moby's own default filter minus kern's 35): a syscall outside the allow set returns `ENOSYS` so honest software degrades instead of dying, while the mount/namespace/module/ptrace escape vectors hard-kill (`SIGSYS`); the wider denylist is the opt-out (`KERN_SECCOMP=denylist`) | the new **and** classic mount API is denied, so a box cannot remount its root writable or unmask the cgroup; `clone` is filtered on its namespace flags and `clone3` is refused wholesale (`ENOSYS`, since its flags sit behind a pointer BPF cannot read), so a nested-userns escape is closed either way; verified across platforms |
| Capabilities | bounding + effective/permitted/inheritable drop before exec, **verified by read-back** | a re-added cap is effective only over the box's own user namespace, never the host-owned cgroupfs or mounts |
| `/proc` and devices | sensitive `/proc` paths masked (`/proc/sys` read-only is fatal); `/dev` is a box-owned tmpfs with a deny-by-default node set; `MS_NODEV` + userns `SB_I_NODEV` make a fabricated node inert | core_pattern and the sysrq/kcore class stay closed for a root-mapped box |
| Fresh-fd hygiene | inherited descriptors shed before exec (CVE-2016-9962 class) | an SDK or CI fd cannot pass into the workload |
| Untrusted-image extraction | a tar-flavour-independent vetter (path/symlink/hardlink/whiteout/desync/bomb) + isolated staging + no-follow merge; every blob and every pinned manifest is sha256-verified before use | the cross-layer and host-inode escape classes are closed structurally, not by trusting `tar` |
| Registry integrity | TLS-pinned on every hop and redirect; realm pinning (CVE-2020-15157 class); credentials off argv | a hostile registry cannot downgrade the transport or steal the token |
| Optional LSM / write confinement | `--apparmor <profile>` (onexec, fail-closed) and `--landlock-rw` (opt-in, verified) | layered over namespaces + seccomp when requested; absent by default |
| Resource caps **where the controller is delegated** | cgroup v2 `memory.max` / `pids.max`, read back to confirm | REAL on a delegating host; see the governor row for the rest |

### COOPERATIVE - shapes an honest workload, not a boundary

| Governor | Why it is not a boundary | Honest handling |
|---|---|---|
| Resource caps on a **non-delegated** host | with no cgroup delegation kern cannot enforce a cap | best-effort with a once-per-host warning; `--require-limits` makes the uncapped fallback **fatal** (refuse to start unless the cap reads back in force) |
| Egress allowlist (`--egress-allow`) | a domain sharing a CDN IP and SNI with an allowed one is reachable | an application-layer allowlist for a semi-trusted workload, SSRF-guarded (a non-public resolve is refused), documented in [EGRESS.md](EGRESS.md) as not a hard exfiltration boundary |
| vGPIO pin list | GPIO is chip-granular: the character device exposes every line via ioctl, the kernel has no per-line mount boundary | `pins = [...]` is cooperative metadata; grant a `vgpio:` profile only to a workload you trust with that hardware |
| The `--ssh` subtree | sshd and its shells are forked before seccomp and the cap drop, and run the image's own binaries pre-filter | for interactive access, not a hardened bastion; the interactive-trust surface you opted into |
| `--net host` | shares the host netns | there is then no network isolation, by request |
| GPU limits | not shipped in this tree | when they land, expect a cooperative governor for honest workloads, with the bypasses named here |

## Attack surface, mitigation, residual

| Surface | Mitigation | Residual |
|---|---|---|
| Escape via a crafted image | in-process vetter + no-follow merge + digest verify | an exotic-but-safe image is refused rather than extracted (fail-closed) |
| Nested-namespace escape | `clone` flag filter + `clone3` refused wholesale (`ENOSYS`); mount API denied | the userns surface itself is kernel attack surface (below) |
| Remount root writable / unmask cgroup | seccomp kills the mount API; child-userns caps ineffective over host-owned mounts | `--privileged` re-gains the classic `mount` syscalls, but caps ineffective over host-owned mounts keep root/cgroup unchanged, the new mount API stays blocked, and seccomp itself cannot be turned off |
| Registry poisoning | sha256 on blobs and pinned manifests; TLS + realm pinning | trust in the host kernel's TLS stack via `curl` |
| Peer secret / posture theft | inverted-default registry guard at **every** host-path entry, by device+inode identity | the operator's own trusted source paths are trusted as such |
| Secret disclosure | `/run/secrets` tmpfs mode 0400, off argv, `O_EXCL\|O_NOFOLLOW` | inline `NAME=value` is visible in the host `ps`, and is warned about |
| Forged supervision signal | watchdogs forked before the pid namespace; target from `fork()` or the host-only registry; pidfd-pinned | a same-uid pid-reuse window on `--health-action restart`, sub-quantum and not attacker-targetable |
| Syscall-surface enumeration | a denied call is byte-identical to one the kernel lacks (`ENOSYS`) | whether a mapped filter helps an attacker who already has code execution is recorded open in [OPEN_ITEMS.md](../OPEN_ITEMS.md) |

## Non-goals and residual risk

- **Not a microVM.** kern shares the host kernel. A kernel privilege-escalation bug is an escape.
  For actively hostile, multi-tenant code from strangers on one host, reach for a hardware-virtualized
  boundary (Firecracker, Kata) or gVisor. That is not where kern competes.
- **An unprivileged user namespace is itself kernel attack surface.** Running untrusted code hands it
  the in-kernel namespace surface to probe. This is stated first, before any isolation claim.
- **Cooperative governors are bypassable by first-party code**, by construction. See the table above.
- **A malicious operator is out of scope.** kern runs with the operator's own privileges and paths.
- **Side channels, timing and hardware attacks are out of scope.**

## Verification

The claims are checked by asking the kernel what is true, not by asking kern to report on itself:

- Four adversarial suites in [pentest/](../pentest/) assert that a published port cannot tunnel into a
  host service, that `--ssh` does not hand out the host's shell, that `kern exec` does not escape,
  that a box cannot raise its own `memory.max` or see a cgroup above its own, that an ungranted device
  does not cross, and that a SIGKILLed supervisor holds no host port. They run against a loopback
  registry, so no account or network is needed; a host that cannot answer a question reports `SKIP`,
  never a false pass.
- The tar byte-parser is fuzzed. Production code is panic-free (no `unwrap`/`expect`/`panic!` on any
  reachable path). The boundaries have been exercised on x86_64, three ARM boards, WSL2, and a VPS.
- Three sequence/coverage properties are asserted by a test, not assumed: (1) the WHOLE mount API,
  classic and the fd-based family (`fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree`/`fspick`/
  `mount_setattr`), hard-kills with `SIGSYS` - not merely `ENOSYS`-by-allowlist - checked by
  arch-correct number (x86_64 + aarch64) in `mount_api_family_is_hard_killed`, so "safe by
  construction" never stands in for "killed". (2) The setup window carries no attacker code: the cap
  drop (bounding + effective, read-back verified), Landlock and the seccomp filter are all in force
  **before** the workload's `execvp`, and a source-level regression
  (`no_untrusted_exec_before_the_seccomp_filter`) fails the build if any process-launch or fork is
  introduced into `child_setup_and_exec` before the filter install - so the only untrusted binary
  forked before the filter stays `--ssh`'s sshd, declared cooperative above. (3) The shared overlay
  lower is isolating: `overlay_lower_is_shared_ro_across_boxes` builds a local image and asserts a
  marker + seed rewrite in one box is invisible to a fresh box from the same image, and the lower's
  host path is unreachable after the pivot.
- The discriminant is the standard: a claim is confirmed only when the same operation succeeds
  outside a box and is refused inside one, or the reverse, so a green result cannot come from the
  feature simply being absent.

To reproduce:

```sh
cargo build --release
sh pentest/run-with-local-registry.sh ./target/release/kern pentest/pentest-ports.sh
```
