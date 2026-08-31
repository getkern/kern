#!/usr/bin/env python3
"""Generate crates/kern-isolation/src/seccomp_allow.rs from the pinned OCI seccomp profile.

WHY THIS EXISTS
    kern's seccomp filter is moving from a denylist (allow everything except 35 named syscalls) to an
    ALLOWLIST (deny everything except a vetted set). The vetted set is Docker/moby's default profile,
    which is validated by billions of container starts, MINUS the 35 kern denies for being rootless
    (mount, unshare, setns, ptrace, bpf, ...). So kern ends up STRICTER than Docker while gaining the
    allowlist property (a new kernel syscall is denied by default).

    The syscall NUMBERS differ per architecture and the Rust `libc` crate's `SYS_*` constants are
    INCOMPLETE on musl targets (measured: 140 of 392 names missing on x86_64-musl), so numbers cannot
    come from libc. They come from the kernel's own UAPI headers, resolved by the C preprocessor
    (which expands the asm-generic `__NR3264_*` indirection that a bare `-dM` dump does not). That is
    the authoritative ABI source, identical to what the running kernel uses.

INPUTS (all committed / on-disk, no network at generation time)
    crates/kern-isolation/seccomp/moby-default-v27.3.1.json   the pinned OCI allow set
    <asm/unistd.h> via `gcc` (x86_64) and `aarch64-linux-gnu-gcc` (aarch64)

OUTPUT
    crates/kern-isolation/src/seccomp_allow.rs   two sorted `&[u32]` arrays, one per target arch.

Usage:  python3 scripts/gen-seccomp-allowlist.py
Exit:   0 on success; non-zero if a compiler is missing or the profile cannot be read.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROFILE = REPO / "crates" / "kern-isolation" / "seccomp" / "moby-default-v27.3.1.json"
OUT = REPO / "crates" / "kern-isolation" / "src" / "seccomp_allow.rs"
# The arch-independent DECISION RECORD: the exact syscall NAMES the allowlist permits
# (`moby_allow ∖ KERN_DENIED`), one per line. Committed and diff-gated (`--check`) so a bump of the
# pinned profile that adds/removes a syscall surfaces HERE, for review, before it reaches the numbers.
NAMES = REPO / "crates" / "kern-isolation" / "seccomp" / "allow-names.txt"

# The 35 kern denies regardless of the OCI profile (kill / ENOSYS / nesting). They must NOT enter the
# allowlist: the filter keeps handling them explicitly. Kept in sync with seccomp.rs by the test
# `the_allowlist_excludes_every_denied_syscall`.
KERN_DENIED = {
    "bpf", "delete_module", "finit_module", "fsconfig", "fsmount", "fsopen", "fspick",
    "init_module", "kexec_file_load", "kexec_load", "mount_setattr", "move_mount", "open_tree",
    "process_vm_readv", "process_vm_writev", "ptrace", "reboot", "swapoff", "swapon",
    "unshare", "setns", "mount", "umount2", "pivot_root",
    "add_key", "clone3", "io_uring_enter", "io_uring_register", "io_uring_setup", "keyctl",
    "perf_event_open", "request_key", "syslog", "userfaultfd", "open_by_handle_at",
}

ARCHES = [
    ("x86_64", "gcc"),
    ("aarch64", "aarch64-linux-gnu-gcc"),
]

# Header sentinels that `#define __NR_*` to a number but are NOT syscalls: the total-count sentinel and
# the aarch64 reserved-range marker. Excluded from the coverage check below.
NON_SYSCALL_MARKERS = {"syscalls", "arch_specific_syscall"}

# Syscalls the kernel defines that are NEITHER in the moby allow set NOR in KERN_DENIED, so the DEFAULT
# denylist allows them silently. Each has been reviewed - either an obsolete/removed stub (the kernel
# answers ENOSYS, it does nothing) or a process/box-local call that cannot reach the host. `check_
# coverage` fails when the kernel gains a syscall NOT listed here, forcing a human to vet it (add here
# if benign, or to KERN_DENIED if it reaches the host) BEFORE it ships silently allowed - the standing
# weakness of ANY denylist. By NAME, so one list holds for every arch (numbers differ, names do not).
REVIEWED_UNCLASSIFIED = {
    # Obsolete / removed - the kernel returns ENOSYS for these, they execute nothing.
    "_sysctl", "afs_syscall", "create_module", "get_kernel_syms", "getpmsg", "nfsservctl",
    "putpmsg", "query_module", "security", "sysfs", "tuxcall", "uselib", "ustat", "vserver",
    # Process- or box-local, no host reach: NUMA page migration; mount enumeration, which reads the
    # CALLER's own mount namespace (a box sees only its own mounts); and LSM SELF attributes.
    "migrate_pages", "move_pages", "listmount", "statmount",
    "lsm_get_self_attr", "lsm_set_self_attr", "lsm_list_modules",
}


def kernel_syscall_names(cc: str) -> set[str] | None:
    """Every `__NR_<name>` the kernel headers define for `cc`'s architecture, minus the non-syscall
    sentinels. `None` when the compiler is absent, so the caller skips that arch rather than failing."""
    try:
        out = subprocess.run(
            [cc, "-E", "-dM", "-include", "asm/unistd.h", "-"],
            input="",
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    names = {m.group(1) for m in re.finditer(r"#define __NR_(\w+)\s+\d+", out.stdout)}
    return names - NON_SYSCALL_MARKERS


def check_coverage() -> int:
    """Fail if the kernel defines a syscall kern neither ALLOWS (moby set), DENIES (KERN_DENIED), nor
    has explicitly REVIEWED as benign. Closes the denylist's standing gap: a new kernel syscall is
    otherwise permitted by default with no human in the loop. Checks whichever arches have a cross-
    compiler; a runner with only `gcc` still gates x86_64."""
    classified = set(allow_names()) | set(KERN_DENIED) | REVIEWED_UNCLASSIFIED
    checked: list[str] = []
    skipped: list[str] = []
    for arch, cc in ARCHES:
        names = kernel_syscall_names(cc)
        if names is None:
            skipped.append(arch)
            continue
        unclassified = sorted(names - classified)
        if unclassified:
            print(
                f"UNCLASSIFIED syscalls on {arch} - the denylist would ALLOW these silently: "
                + " ".join(unclassified)
                + "\nVet each and add it to REVIEWED_UNCLASSIFIED (benign) or KERN_DENIED (reaches the "
                "host) in scripts/gen-seccomp-allowlist.py.",
                file=sys.stderr,
            )
            return 1
        checked.append(arch)
    msg = "syscall coverage complete: every kernel syscall is allowed, denied, or reviewed"
    if checked:
        msg += f" ({', '.join(checked)})"
    if skipped:
        msg += f"; skipped {', '.join(skipped)} (no cross-compiler)"
    print(msg + ".")
    return 0


def allow_names() -> list[str]:
    """The OCI allow set minus what kern denies, sorted for a stable diff."""
    try:
        prof = json.loads(PROFILE.read_text(encoding="utf-8"))
    except OSError as e:
        print(f"cannot read the pinned profile {PROFILE}: {e}", file=sys.stderr)
        raise SystemExit(1)
    allow: set[str] = set()
    for entry in prof.get("syscalls", []):
        if entry.get("action") == "SCMP_ACT_ALLOW":
            names = entry.get("names") or ([entry["name"]] if "name" in entry else [])
            allow.update(names)
    return sorted(allow - KERN_DENIED)


def resolve(compiler: str, names: list[str]) -> dict[str, int]:
    """name -> syscall number for this arch, via the C preprocessor EXPANDING each `__NR_name`.

    Expansion (not a `-dM` dump) is required: aarch64's asm-generic header defines several syscalls
    through the `__NR3264_*` macro indirection, so a raw definition dump shows `__NR_mmap` as a macro
    alias rather than the integer 222. `-E` runs the whole preprocessor, so every `__NR_name` on the
    marker lines below comes out as its final integer.
    """
    src_lines = ["#include <asm/unistd.h>"]
    for n in names:
        src_lines.append(f"MARK {n} __NR_{n}")
    src = "\n".join(src_lines) + "\n"
    try:
        out = subprocess.run(
            [compiler, "-E", "-P", "-"],
            input=src,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as e:
        print(f"cannot run {compiler}: {e}", file=sys.stderr)
        raise SystemExit(1)
    if out.returncode != 0:
        print(f"{compiler} failed to preprocess the syscall table:\n{out.stderr}", file=sys.stderr)
        raise SystemExit(1)
    resolved: dict[str, int] = {}
    for line in out.stdout.splitlines():
        parts = line.split()
        # `MARK <name> <expanded>`; keep only the ones that expanded to a bare integer (a name that
        # does not exist on this arch stays a macro token and is dropped, which is correct).
        if len(parts) == 3 and parts[0] == "MARK" and parts[2].isdigit():
            resolved[parts[1]] = int(parts[2])
    return resolved


def sidecar_text(names: list[str]) -> str:
    """The decision-record sidecar: the sorted allow NAMES, one per line, with a generated header."""
    header = (
        "# GENERATED by scripts/gen-seccomp-allowlist.py - DO NOT EDIT BY HAND.\n"
        "# The syscall NAMES kern's seccomp allowlist permits = the pinned OCI/moby default allow set\n"
        "# (moby-default-v27.3.1.json) MINUS the 35 syscalls kern denies for being rootless. The\n"
        "# per-architecture NUMBERS in src/seccomp_allow.rs are these names resolved via kernel headers.\n"
        "# A profile bump that changes this list is caught by `--check` in CI: regenerate and review.\n"
    )
    return header + "".join(f"{n}\n" for n in names)


def rust_text(names: list[str]) -> tuple[str, list[str]]:
    """Render seccomp_allow.rs (per-arch number arrays) and the counts. Needs the cross-compilers."""
    blocks: list[str] = []
    counts: list[str] = []
    for arch, compiler in ARCHES:
        m = resolve(compiler, names)
        nums = sorted(set(m.values()))
        counts.append(f"{arch}={len(nums)}")
        body = "\n".join(f"    {n}," for n in nums)
        blocks.append(
            f'#[cfg(target_arch = "{arch}")]\n'
            f"/// {len(nums)} allowed syscall numbers for {arch}, SORTED for the binary search in\n"
            f"/// `seccomp::build_allowlist_filter`. Generated; do not hand-edit.\n"
            f"pub const ALLOW: &[u32] = &[\n{body}\n];"
        )
    header = (
        "// GENERATED by scripts/gen-seccomp-allowlist.py - DO NOT EDIT BY HAND.\n"
        "//\n"
        "// Source: the pinned OCI/moby default seccomp allow set\n"
        "// (crates/kern-isolation/seccomp/moby-default-v27.3.1.json) MINUS the 35 syscalls kern denies\n"
        "// for being rootless, resolved to per-architecture numbers via the kernel UAPI headers.\n"
        "// Re-generate after bumping the pinned profile or a kernel headers update:\n"
        "//     python3 scripts/gen-seccomp-allowlist.py\n"
        f"// Counts: {', '.join(counts)}. NAMES: {len(names)} (see seccomp/allow-names.txt).\n\n"
    )
    return header + "\n\n".join(blocks) + "\n", counts


def read_sidecar_names() -> list[str]:
    """Parse the committed allow-names.txt, dropping blank and '#'-comment lines. Order preserved."""
    try:
        text = NAMES.read_text(encoding="utf-8")
    except OSError as e:
        print(f"cannot read {NAMES}: {e}", file=sys.stderr)
        raise SystemExit(1)
    return [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]


def extract_allow_numbers(rust_src: str) -> dict[str, set[int]]:
    """`{arch: {numbers}}` from a committed seccomp_allow.rs, INDEPENDENT of formatting (the file is
    `cargo fmt`-wrapped, so a byte compare would false-fail). The arch tokens (`#[cfg(target_arch=…)]`)
    and the `ALLOW` array bodies each appear exactly once per arch, in the same order, so they zip -
    matched separately because a doc comment between them contains a `;` that a single spanning regex
    would trip over."""
    archs = re.findall(r'target_arch = "(\w+)"', rust_src)
    bodies = re.findall(r"pub const ALLOW: &\[u32\] = &\[(.*?)\];", rust_src, re.S)
    if len(archs) != len(bodies):
        return {}  # unexpected shape → treat as drift, the caller fails the check
    return {
        arch: {int(x) for x in re.findall(r"\d+", body)}
        for arch, body in zip(archs, bodies)
    }


def generate() -> int:
    """Write both artifacts from the pinned profile. Needs gcc + aarch64-linux-gnu-gcc."""
    names = allow_names()
    NAMES.write_text(sidecar_text(names), encoding="utf-8")
    text, counts = rust_text(names)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT} and {NAMES} ({', '.join(counts)}, {len(names)} names)")
    return 0


def check() -> int:
    """The diff-gate. Two layers, so it stays useful on a runner without the cross-toolchains:

    1. NAME level (always, no compiler): the committed allow-names.txt MUST equal
       `moby_allow ∖ KERN_DENIED` recomputed from the pinned profile. This is what catches a profile
       bump silently pulling a new syscall into the allow set - it shows up here, named, for review.
    2. NUMBER level (only when BOTH cross-compilers are present): the number sets in seccomp_allow.rs
       MUST equal the names resolved per arch. Skipped-with-notice where a compiler is missing, because
       resolution needs that arch's kernel headers - the name layer still gates the actual risk.
    """
    expected = allow_names()
    committed = read_sidecar_names()
    if committed != expected:
        added = sorted(set(expected) - set(committed))
        removed = sorted(set(committed) - set(expected))
        print(
            "seccomp allow-list DRIFT: allow-names.txt does not match the pinned profile.",
            file=sys.stderr,
        )
        if added:
            print(f"  + would ENTER the allow set: {', '.join(added)}", file=sys.stderr)
        if removed:
            print(f"  - would LEAVE the allow set: {', '.join(removed)}", file=sys.stderr)
        print(
            "  Run `python3 scripts/gen-seccomp-allowlist.py` and review the diff before committing.",
            file=sys.stderr,
        )
        return 1

    # NUMBER level, PER ARCH: verify whichever arches have their cross-compiler available (so a runner
    # with only `gcc` still checks x86_64), and note the ones skipped for a missing toolchain.
    have = extract_allow_numbers(OUT.read_text(encoding="utf-8"))
    checked: list[str] = []
    skipped: list[str] = []
    for arch, cc in ARCHES:
        if shutil.which(cc) is None:
            skipped.append(arch)
            continue
        want = set(resolve(cc, expected).values())
        if want != have.get(arch, set()):
            print(
                f"seccomp_allow.rs is out of sync with allow-names.txt for {arch}: regenerate.",
                file=sys.stderr,
            )
            return 1
        checked.append(arch)
    msg = f"seccomp allow-list in sync: {len(expected)} names"
    if checked:
        msg += f", numbers verified for {', '.join(checked)}"
    if skipped:
        msg += f" (number check skipped for {', '.join(skipped)}: no cross-compiler)"
    print(msg + ".")
    return 0


def main(argv: list[str]) -> int:
    # CHECKING IS THE DEFAULT AND WRITING NEEDS TO BE ASKED FOR, which is the opposite of what this
    # file used to do. Every other script in `scripts/` is a gate that reads, so a sweep that runs
    # them all treated this one as a gate too and it REWROTE `seccomp_allow.rs` on the spot. The
    # rewrite is byte-equivalent in content and unformatted in shape, so the tree came back dirty on
    # a file whose own header says DO NOT EDIT BY HAND, and `cargo fmt --check` went red next.
    # Nothing was wrong with the allow-list; the generator was the only thing that had changed it.
    #
    # A generator that mutates unless told otherwise is a hazard in a directory of read-only checks,
    # so the safe mode is now the one you get by accident.
    if "--write" in argv[1:]:
        return generate()
    rc = check()
    if rc != 0:
        return rc
    # The allow-list is in sync; also gate the denylist's future-coverage (a new kernel syscall the
    # default filter would silently allow). Both run under the one `--check` the CI `docs` step calls.
    return check_coverage()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
