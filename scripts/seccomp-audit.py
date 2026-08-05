#!/usr/bin/env python3
"""Validate the seccomp allowlist against a REAL workload, before flipping it on by default.

WHY THIS EXISTS
    The allowlist (`KERN_SECCOMP=allowlist`) denies every syscall outside a vetted set with `ENOSYS`.
    A corpus that merely "does not crash" under it proves almost nothing: a program that probes a
    denied syscall and takes a fallback COMPLETES successfully while silently doing something else.
    The only way to know a flip to allowlist-default is safe for a workload is to observe the syscalls
    it ACTUALLY makes at runtime and diff them against the allow set.

    `KERN_SECCOMP=allowlist-audit` installs a filter identical to the allowlist EXCEPT that the
    would-be-denied branch is `SECCOMP_RET_LOG` instead of `ENOSYS`: the syscall is logged by the
    kernel and then RUNS. So the workload behaves exactly as under the (permissive) denylist, while
    every syscall a real allowlist would refuse is recorded. This harness runs a workload in that mode,
    collects those records, and reports the DELTA - the syscalls the workload used that the allowlist
    would deny. A non-empty delta is the answer to "is a flip safe for this workload": no.

HOW COLLECTION WORKS (and its one hard dependency)
    `SECCOMP_RET_LOG` writes an audit record (type 1326, AUDIT_SECCOMP) to the kernel audit subsystem,
    read here via, in order of preference: `ausearch` (auditd), `journalctl -k`, or `dmesg`. All three
    need privilege to read on a hardened host (`auditd` = root; `dmesg` = `CAP_SYSLOG` or
    `kernel.dmesg_restrict=0`). Also `log` must be in `/proc/sys/kernel/seccomp/actions_logged` (it is,
    by default). This is a DELIBERATELY-RUN validation tool for a controlled environment with that
    access - NOT a CI gate. When the log cannot be read it SKIPS with the exact reason, never a false
    "clean".

    Only processes running OUR audit filter emit `action=log` SECCOMP records, so a time-windowed
    collection is dominated by the workload's own boxes even on a not-idle host; unrelated `action=log`
    records (another seccomp policy logging) would only ADD to the delta and are called out.

USAGE
    scripts/seccomp-audit.py -- <command to run the workload>
    e.g.  scripts/seccomp-audit.py -- kern box t --image alpine -- python3 -c 'import ssl; ...'
          scripts/seccomp-audit.py --json -- kern compose up ...

    The command is run with KERN_SECCOMP=allowlist-audit injected into its environment. Everything
    after `--` is the command, run verbatim.

EXIT CODES
    0  collected, and the workload's syscalls are a SUBSET of the allow set (a flip looks safe for it)
    1  collected, and the delta is NON-EMPTY (a flip would deny syscalls this workload uses)
    2  could not collect (no readable audit log, or the workload did not run) - SKIP, not a verdict
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ALLOW_RS = REPO / "crates" / "kern-isolation" / "src" / "seccomp_allow.rs"

# uname -m -> the `#[cfg(target_arch = "…")]` token used in seccomp_allow.rs.
ARCH_TOKENS = {
    "x86_64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}


def host_arch_token() -> str | None:
    return ARCH_TOKENS.get(os.uname().machine)


def allow_numbers_for(arch_token: str) -> set[int] | None:
    """The allow-set NUMBERS for `arch_token`, parsed from the committed seccomp_allow.rs. Format
    independent (the file is `cargo fmt`-wrapped): grab the integers inside that arch's `ALLOW`
    array. Returns None if the file or the block can't be read."""
    try:
        src = ALLOW_RS.read_text(encoding="utf-8")
    except OSError as e:
        print(f"cannot read {ALLOW_RS}: {e}", file=sys.stderr)
        return None
    # Arch tokens and ALLOW bodies each appear once per arch, in the same order (a doc comment between
    # them carries a ';' that a single spanning regex would trip on), so match separately and zip.
    archs = re.findall(r'target_arch = "(\w+)"', src)
    bodies = re.findall(r"pub const ALLOW: &\[u32\] = &\[(.*?)\];", src, re.S)
    if len(archs) != len(bodies):
        return None
    for a, body in zip(archs, bodies):
        if a == arch_token:
            return {int(x) for x in re.findall(r"\d+", body)}
    return None


def syscall_name(nr: int) -> str:
    """Best-effort number -> name for the human report, via auditd's `ausyscall`. Falls back to the
    bare number when the tool is absent (the number is the authoritative datum for the diff anyway)."""
    ausyscall = shutil.which("ausyscall")
    if ausyscall is None:
        return f"#{nr}"
    try:
        out = subprocess.run(
            [ausyscall, str(nr)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return f"#{nr}"
    name = out.stdout.strip()
    return f"{name}(#{nr})" if name else f"#{nr}"


def log_action_enabled() -> bool:
    try:
        actions = Path("/proc/sys/kernel/seccomp/actions_logged").read_text(encoding="utf-8")
    except OSError:
        # Unreadable: don't block on it - the collectors below will simply find nothing if it's off.
        return True
    return "log" in actions.split()


def collect_seccomp_numbers(since_epoch: float) -> tuple[set[int], str] | None:
    """Syscall numbers from SECCOMP `action=log` audit records emitted since `since_epoch`. Tries the
    readable collectors in order and returns (numbers, source) for the first that WORKS (even if it
    finds zero records), or None if none is readable/available. `syscall=` is the arch-native number
    the audit filter saw, which is exactly what the allow-set numbers are compared against."""
    since_clock = time.strftime("%H:%M:%S", time.localtime(since_epoch))

    # 1. auditd: the precise, structured source. `-m SECCOMP` selects type 1326.
    ausearch = shutil.which("ausearch")
    if ausearch is not None:
        try:
            out = subprocess.run(
                [ausearch, "-m", "SECCOMP", "-ts", since_clock, "-i"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # ausearch exits 1 with "no matches" - that is a SUCCESSFUL empty collection, not an error.
            if out.returncode in (0, 1):
                return _parse_syscall_fields(out.stdout), "ausearch"
        except (OSError, subprocess.SubprocessError):
            pass

    # 2. journalctl kernel ring, since the run started.
    journalctl = shutil.which("journalctl")
    if journalctl is not None:
        try:
            out = subprocess.run(
                [journalctl, "-k", "--since", f"@{int(since_epoch)}", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if out.returncode == 0 and out.stdout:
                return _parse_syscall_fields(_only_seccomp(out.stdout)), "journalctl"
        except (OSError, subprocess.SubprocessError):
            pass

    # 3. dmesg: needs CAP_SYSLOG / dmesg_restrict=0. Time-filter is coarse (dmesg has no wall clock),
    #    so we take every SECCOMP line - acceptable because only our audit filter emits action=log.
    dmesg = shutil.which("dmesg")
    if dmesg is not None:
        try:
            out = subprocess.run(
                [dmesg], capture_output=True, text=True, timeout=30
            )
            if out.returncode == 0:
                return _parse_syscall_fields(_only_seccomp(out.stdout)), "dmesg"
        except (OSError, subprocess.SubprocessError):
            pass

    return None


def _only_seccomp(text: str) -> str:
    """Keep only lines that are SECCOMP audit records (type=1326 or the `audit(...): ... syscall=`
    shape), so a stray `syscall=` in some other log line can't pollute the set."""
    keep = []
    for line in text.splitlines():
        low = line.lower()
        if "type=1326" in low or ("seccomp" in low and "syscall=" in low):
            keep.append(line)
    return "\n".join(keep)


def _parse_syscall_fields(text: str) -> set[int]:
    """Every `syscall=<n>` in the given records. auditd's `-i` interpret mode can render the field as
    a NAME; we read the numeric form (default) so this stays arch-correct without a name table."""
    nums: set[int] = set()
    for m in re.finditer(r"\bsyscall=(\d+)\b", text):
        nums.add(int(m.group(1)))
    return nums


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="seccomp-audit.py",
        description="Run a workload under KERN_SECCOMP=allowlist-audit and report the syscalls the "
        "allowlist would deny.",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the result as one JSON object on stdout"
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="after `--`, the command that runs the workload (run with KERN_SECCOMP=allowlist-audit)",
    )
    args = parser.parse_args(argv[1:])

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("no workload command given (usage: seccomp-audit.py -- <cmd>)", file=sys.stderr)
        return 2

    arch_token = host_arch_token()
    if arch_token is None:
        print(f"unsupported host arch {os.uname().machine!r} for the allow-set diff", file=sys.stderr)
        return 2
    allow = allow_numbers_for(arch_token)
    if allow is None:
        print(f"could not read the allow set for {arch_token} from {ALLOW_RS}", file=sys.stderr)
        return 2

    if not log_action_enabled():
        print(
            "note: 'log' is not in /proc/sys/kernel/seccomp/actions_logged - RET_LOG records may not "
            "be emitted; enable it (root): echo 'log' > that file, or set it via sysctl.",
            file=sys.stderr,
        )

    env = dict(os.environ)
    env["KERN_SECCOMP"] = "allowlist-audit"
    started = time.time()
    try:
        proc = subprocess.run(command, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"failed to run the workload: {e}", file=sys.stderr)
        return 2
    # Give the kernel a moment to flush audit records for the just-exited processes.
    time.sleep(0.3)

    collected = collect_seccomp_numbers(started)
    if collected is None:
        print(
            "SKIP: no readable audit source (ausearch/journalctl -k/dmesg). SECCOMP_RET_LOG records "
            "need privilege to read (auditd=root, dmesg=CAP_SYSLOG or dmesg_restrict=0). Re-run this "
            "harness where one is readable; the workload's exit was "
            f"{proc.returncode}.",
            file=sys.stderr,
        )
        return 2

    logged, source = collected
    delta = sorted(logged - allow)
    in_allow = sorted(logged & allow)

    if args.json:
        import json

        print(
            json.dumps(
                {
                    "arch": arch_token,
                    "source": source,
                    "workload_exit": proc.returncode,
                    "logged_total": len(logged),
                    "in_allow": len(in_allow),
                    "would_be_denied": [{"nr": n, "name": syscall_name(n)} for n in delta],
                }
            )
        )
    else:
        print()
        print(f"seccomp-audit ({arch_token}, via {source}): workload exit {proc.returncode}")
        print(f"  syscalls logged (would-be-denied surface hit): {len(logged)}")
        print(f"  of those, already in the allow set:            {len(in_allow)}")
        if delta:
            print(f"  NOT in the allow set - a flip would DENY these {len(delta)}:")
            for n in delta:
                print(f"      {syscall_name(n)}")
            print(
                "  => a flip to allowlist-default would change this workload's behaviour. Vet each: "
                "add to the allow set (regenerate) or confirm the workload has a safe fallback."
            )
        else:
            print("  delta is EMPTY: every syscall this workload made is in the allow set.")

    return 1 if delta else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
