# Threat model

Who the attacker is, what they are after, and which boundaries hold. This is the map;
[SECURITY.md](../SECURITY.md) is the per-mechanism detail. Where a number matters, ask the binary
(`kern box <name> --image <ref> --show-config`) rather than trusting prose.

The one rule this document keeps: **a boundary and a governor are named separately.** A boundary is
enforced by the kernel and holds against the workload itself; a governor shapes an honest workload, and
hostile first-party code steps around it. Conflating the two is the most expensive mistake a sandbox
document can make, so every row below says which it is.

## Assumptions

**Trusted.** The host kernel (kern's isolation is *built on* it, so a kernel privilege-escalation bug is
an escape). The operator who runs `kern`. The `kern` binary itself.

**Untrusted.** Everything the workload or an image author controls: the in-box process, the OCI image or
`--rootfs`, the compose file, the bytes a registry returns, and anything reachable over the box's
network.

## What an attacker wants

1. **The host filesystem** outside the box's rootfs.
2. **The host kernel, processes and mounts**: escape the namespaces, see or signal host processes, reach
   the host mount tree.
3. **A peer box's secrets and posture.** kern's runtime registry holds other boxes' SSH host keys,
   `--secret` values and the posture `kern exec` reproduces. Reading it steals a peer's secrets; writing
   it forges a peer's posture.
4. **The operator's registry credentials**, from argv, a readable file, or a token redirect.
5. **Host network reachability** the box's netns should not grant: a host-loopback service, or a
   host-side transport such as vsock on WSL2. The LAN and the internet are reachable from a box's
   default network, as from a Docker container; with `--network none` (every SDK sandbox) nothing is.

## Entry points

- **The in-box workload**: arbitrary code with a shell, syscalls and the box's namespace surface.
- **The OCI image / `--rootfs`**: a crafted tar (path traversal, symlink or hardlink escape, whiteout
  tricks, parser desync) and hostile file modes.
- **The compose file**: dependency cycles, restart contradictions, override merges.
- **The registry**: a compromised or MITM'd host serving mismatched bytes, a downgraded transport, or a
  token realm on a foreign host.
- **Host-path flags**: `-v`, `--secret`, `--env-file`, `--rootfs`, the build context, `kern cp`,
  `kern save -o`: every path where the box can aim a read or write at a host location, kern's own
  registry included.
- **The network**: egress destinations, published ports, network volumes.

## REAL boundaries: kernel-enforced, hold against the workload

| Boundary | Enforced by |
|---|---|
| Process / mount / UTS / IPC isolation | `unshare` + `pivot_root`, root remounted read-only **last** (compile-enforced by a typestate). A box sees no host process, mount or peer box |
| Rootless privilege | user namespace; box-root maps to an unprivileged host uid. No host uid 0 unless the caller is real root, where `--privileged` is refused |
| Dangerous syscalls | **always-on seccomp, allowlist by default**: a syscall outside the set returns `ENOSYS`, so honest software degrades instead of dying, while the mount, namespace, module and ptrace escape vectors are refused with `EPERM`, Docker's answer (a `SIGSYS` kill with `--security-opt seccomp-deny=kill` and in the SDKs' sandboxes, where the kill is the reported verdict). Both the classic and the new mount API are denied, so a box cannot remount its root writable or unmask the cgroup; `clone` is filtered on its namespace flags and `clone3` is refused wholesale, so a nested-userns escape is closed either way |
| Capabilities | bounding, effective, permitted and inheritable dropped before exec, **verified by read-back**. A re-added cap is effective only over the box's own user namespace |
| `/proc` and devices | sensitive `/proc` paths masked; `/dev` is a box-owned tmpfs with a deny-by-default node set; `MS_NODEV` plus userns `SB_I_NODEV` make a fabricated node inert |
| Fresh-fd hygiene | inherited descriptors shed before exec (CVE-2016-9962 class), so an SDK or CI fd cannot pass into the workload |
| Untrusted-image extraction | a tar-flavour-independent vetter (path, symlink, hardlink, whiteout, desync, bomb) plus isolated staging and a no-follow merge; every blob and pinned manifest is sha256-verified before use |
| Registry integrity | TLS-pinned on every hop and redirect; realm pinning (CVE-2020-15157 class); credentials off argv |
| Optional write confinement | `--apparmor <profile>` and `--landlock-rw`, both opt-in and fail-closed: no Landlock on this kernel refuses the box rather than running it unconfined |
| Resource caps **where the controller is delegated** | cgroup v2 `memory.max` / `pids.max`, read back to confirm |
| Host loopback from the default network | a NAT of the box's own (pasta with `--no-map-gw`): its gateway is not the host, and no address in it reaches a service the host binds to `127.0.0.1` (measured with a canary there: none of the gateway, the host's LAN address or `host-gateway` answered, while a service on every interface answered on the LAN address, as under Docker) |

## COOPERATIVE governors: shape an honest workload, not a boundary

| Governor | Why it is not a boundary | Honest handling |
|---|---|---|
| Resource caps on a **non-delegated** host | with no cgroup delegation kern cannot enforce a cap | `kern box` warns once and `--require-limits` makes it fatal; `kern limit --memory` refuses unless a ceiling at or below the one named can be proven |
| Egress allowlist (`--egress-allow`) | over HTTPS any domain on a SHARED CDN with an allowed one is reachable, chosen by the HTTP `Host` header inside TLS, where a matching SNI does not help. Over plain HTTP that header is visible and a head naming another host is refused | an application-layer allowlist for a semi-trusted workload, SSRF-guarded, documented in [EGRESS.md](EGRESS.md) as not a hard exfiltration boundary |
| vGPIO pin list | GPIO is chip-granular: the character device exposes every line via ioctl | `pins = [...]` is cooperative metadata; grant `vgpio:` only to a workload you trust with that hardware |
| The `--ssh` subtree | sshd and its shells fork before seccomp and the cap drop, running the image's own binaries pre-filter | for interactive access, not a hardened bastion |
| `--net host` | shares the host netns | no network isolation, by request |
| The GPU | a device grant gives the box one whole card | kern does not split or cap a GPU; a card with no node in the box cannot be initialised there, but the host's PCI bus still shows how many it has |

## Surface, mitigation, residual

| Surface | Mitigation | Residual |
|---|---|---|
| Escape via a crafted image | in-process vetter + no-follow merge + digest verify | an exotic-but-safe image is refused rather than extracted (fail-closed) |
| Nested-namespace escape | `clone` flag filter, `clone3` refused, mount API denied | the userns surface itself is kernel attack surface |
| Remount root writable | seccomp refuses the mount API; child-userns caps are ineffective over host-owned mounts | `--privileged` regains the classic `mount` syscalls, but root and cgroup stay unchanged and seccomp cannot be turned off |
| Registry poisoning | sha256 on blobs and pinned manifests; TLS + realm pinning | trust in the host kernel's TLS stack |
| Peer secret / posture theft | inverted-default registry guard at **every** host-path entry, by device+inode identity | the operator's own source paths are trusted as such |
| Secret disclosure | `/run/secrets` tmpfs mode 0400, off argv, `O_EXCL\|O_NOFOLLOW` | inline `NAME=value` is visible in the host `ps`, and is warned about |
| Forged supervision signal | watchdogs forked before the pid namespace, pidfd-pinned | a sub-quantum, non-targetable pid-reuse window on `--health-action restart` |
| Syscall-surface enumeration | a denied call is byte-identical to one the kernel lacks (`ENOSYS`) | whether that helps an attacker who already has code execution is not measured |
| A box escape on WSL2 reaching Windows | the distro's user is not root, interop is off (`wsl.conf`), `/proc/1/root` is denied, a mount by that user is refused (drvfs and 9p, in a user namespace too), and every process kern starts in the distro carries a seccomp filter, installed while kern is still root, that refuses `socket(AF_VSOCK)` (measured: refused through `kern run`, the filter on a detached box's supervisor; a box already refused it) | that user reaches all of `C:\` through the automount, and through Windows' own 9P file server: measured on Windows 10 (19045), a process of that user opened vsock connections to the host's ports 50000, 50001 and 50003, and 50003 answered the 9P version handshake. A process of that user that kern did not start (a `wsl -u kern` shell) still opens vsock. So mounting fewer folders would not narrow what an escape reaches, and kern does not offer it as a boundary. Opening and closing those connections also left WSL unable to start a new instance of the distro until `wsl --shutdown` |

## Non-goals

- **Not a microVM.** kern shares the host kernel, so a kernel privilege-escalation bug is an escape. For
  actively hostile, multi-tenant code from strangers, reach for Firecracker, Kata or gVisor.
- **An unprivileged user namespace is itself kernel attack surface.** Running untrusted code hands it
  that surface to probe. This is stated before any isolation claim.
- **Cooperative governors are bypassable by first-party code**, by construction.
- **A malicious operator is out of scope**: kern runs with the operator's own privileges and paths.
- **Side channels, timing and hardware attacks are out of scope.**

## Verification

The claims are checked by asking the kernel what is true, not by asking kern to report on itself.

- Five adversarial suites in [pentest/](../pentest/) assert that a published port cannot tunnel into a
  host service, that `--ssh` does not hand out the host's shell, that `kern exec` does not escape, that
  a box cannot raise its own `memory.max` or see a cgroup above its own, that an ungranted device does
  not cross, and that a SIGKILLed supervisor holds no host port. A host that cannot answer a question
  reports `SKIP`, never a false pass.
- The tar byte-parser is fuzzed, production code is panic-free, and the boundaries have been exercised
  on x86_64, aarch64, WSL2 and a VPS.
- Three properties are asserted by a test rather than assumed: the WHOLE mount API, classic and
  fd-based, is refused by arch-correct number (the helper sees `EPERM` and nothing runs), so "safe by
  construction" never stands in for "refused"; the cap drop, Landlock and the seccomp filter are all in force **before** the workload's
  `execvp`, with a source-level regression failing the build if any fork is introduced before the filter
  install; and the shared overlay lower is isolating, with a marker written in one box invisible to a
  fresh box from the same image.
- **The discriminant is the standard**: a claim is confirmed only when the same operation succeeds
  outside a box and is refused inside one, or the reverse, so a green result cannot come from the
  feature simply being absent.

```sh
cargo build --release
sh pentest/run-with-local-registry.sh ./target/release/kern pentest/pentest-ports.sh
```
