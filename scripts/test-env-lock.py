#!/usr/bin/env python3
"""The exemptions from the environment chokepoints are the declared ones, and no others.

WHO CHECKS WHAT, because this file used to try to do all of it and could not:

  * That a test holding no lock cannot read or write a process-global variable is enforced AT
    RUNTIME, by an assertion inside `crate::global_env`, `global_env_str`, `set_global_env` and
    `unset_global_env`. It found 35 tests. A static version of the same rule found 3.
  * That nobody reaches `std::env` around those chokepoints is enforced by CLIPPY, through
    `disallowed-methods` in `clippy.toml`. Clippy resolves the path, so `use std::env;` then
    `env::set_var(..)`, `use std::env::set_var as sv;`, a name held in a binding, and spaces around
    the `::` are all the same call to it. They were four separate holes in the regex that used to
    live here, found by an independent test in one sitting, on the second version of this gate.
  * THIS FILE checks the only thing left: that the list of crates and files exempted from that lint
    is the one written below. An exemption is a whole crate going unwatched, it is one line to add,
    and nothing else would notice.

⭐ The rule the three of them make, which is worth more than this gate: a check that has to PARSE the
language loses to someone who is trying; put the question where the code runs, or ask the compiler.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# ANY ATTRIBUTE THAT COULD SWITCH THE LINT OFF, not the one spelling we happen to use.
#
# 🪤 The first version of this matched `#![allow(clippy::disallowed_methods)]` exactly, and an
# independent test disarmed the lint three ways it could not see: `expect` instead of `allow`, a
# second lint in the same list, and `allow(clippy::all)`, which never names this lint at all and so
# defeats any regex keyed on its name. The question is not "is this the attribute we write", it is
# "could this attribute turn the lint off": `disallowed_methods` by name, the group that contains it,
# or `warnings` wholesale.
ALLOW = re.compile(
    r"^\s*#!?\[(?:allow|expect)\([^]]*"
    r"(?:disallowed_methods|clippy::all|clippy::style|\bwarnings\b)[^]]*\)\]"
)

# Every place that may reach `std::env` directly, and why. A path missing from here fails this gate.
DECLARED = {
    "crates/kern-cli/src/main.rs": "the chokepoints themselves",
    "crates/kern-cli/tests/sandbox_run.rs": "its own process: it SPAWNS kern rather than calling in",
    "crates/kern-common/build.rs": "a build script: cargo's own process, no sibling tests",
    "crates/kern-common/src/lib.rs": "not audited for the race yet",
    "crates/kern-compose/src/lib.rs": "not audited for the race yet",
    "crates/kern-isolation/src/lib.rs": "not audited for the race yet",
    "crates/kern-isolation/examples/sandbox_profile.rs": "an example binary, outside the crate attr",
    "crates/kern-oci/src/lib.rs": "not audited for the race yet",
}
CONFIG = ROOT / "clippy.toml"
REQUIRED_METHODS = (
    "std::env::set_var",
    "std::env::remove_var",
    "std::env::var",
    "std::env::var_os",
)

# EVERY `clippy.toml` THAT IS NOT THE ROOT ONE, and why it is allowed to exist.
#
# 🪤 THE HOLE THIS CLOSES. Clippy walks up from a crate root and uses the FIRST config it finds, with
# NO merging. So dropping a `clippy.toml` next to any crate replaces the root's `disallowed-methods`
# wholesale for that whole subtree - the same effect as `#![allow(clippy::disallowed_methods)]`,
# which this gate already refuses undeclared, except that it leaves no mark in any `.rs` file and so
# the attribute scan above cannot see it. A per-directory config was the quietest remaining way to
# switch the lint off for a subtree.
#
# A declaration is not approval, it is visibility: the reason has to be written here, where someone
# reviewing the environment rule will read it.
DECLARED_CONFIGS = {
    "windows/kern-win/clippy.toml": (
        "the Windows->WSL2 shim: a separate crate whose tests are pure functions in no shared "
        "process, where the prescribed remedy `crate::global_env` does not exist"
    ),
}

# 🪤 THE THIRD DOOR, and it was found by an outside reviewer after the first two were shut.
#
# Cargo's own lint tables switch a clippy lint off for a whole package or the whole workspace:
#
#     [lints.clippy]            # in any member's Cargo.toml
#     disallowed_methods = "allow"
#
#     [workspace.lints.clippy]  # in the root Cargo.toml
#     disallowed_methods = "allow"
#
# and `rustflags = ["-A", "clippy::disallowed_methods"]` in a `.cargo/config.toml` does the same for
# everything built under that directory. None of them leaves a mark in any `.rs` file, and none of
# them is a `clippy.toml`, so neither of the two checks above could see any of them.
#
# MEASURED, not reasoned: with that three-line block added to `crates/kern-cli/Cargo.toml`, this gate
# printed "the environment lint is armed ... and no undeclared ones of either kind" and exited 0,
# while `cargo clippy -p getkern` stopped flagging a planted `std::env::var` entirely. A green gate
# over a disarmed lint.
#
# The pattern deliberately does not try to parse TOML. It asks the only question that matters - does
# this file mention a lint table AND this lint, or blanket-allow the group that contains it - because
# a check that has to parse the language loses to someone who is trying, which is the rule written at
# the top of this file.
LINT_TABLE = re.compile(
    r"\[(?:workspace\.)?lints(?:\.clippy)?\]|lints\s*=|rustflags\s*=", re.I
)
# THE KEYS IN A CARGO LINT TABLE ARE BARE, and the first version of this pattern missed that.
#
# 🪤 Reported by the same outside review that found the table class at all, and MEASURED here, one
# form at a time, against a planted `std::env::var` with `RUSTFLAGS=-D warnings`:
#
#   [lints.clippy] disallowed_methods = "allow"   clippy stops flagging   gate RED    (was caught)
#   [lints.clippy] all   = "allow"                clippy stops flagging   gate GREEN  (the hole)
#   [lints.clippy] style = "allow"                clippy stops flagging   gate GREEN  (the hole)
#   [lints.clippy] style = "warn"                 still flagged           -
#   [lints.clippy] disallowed_methods = "warn"    still flagged           -
#   [lints.clippy] correctness = "allow"          still flagged           -
#
# So the groups that actually contain this lint are `style` and `all`, measured rather than recalled,
# and `warn` does not disarm it because `-D warnings` promotes it back. Inside a table the key is
# `all`, not `clippy::all`, which is why a pattern written for the attribute spelling could not see
# it. Both spellings are matched now: the bare key for tables, the `clippy::` one for attributes and
# for rustflags.
#
# ⛔ AND ONE PART OF THAT REPORT DID NOT HOLD, measured: `rustflags = ["-A", "clippy::all"]` in a
# `.cargo/config.toml` does NOT disarm the lint here. An env `RUSTFLAGS` REPLACES the config's
# rustflags rather than merging with them - the repository's own `.cargo/config.toml` says so in its
# header - and every path that runs this lint sets `RUSTFLAGS=-D warnings`. The rustflags spelling is
# still matched below, as a belt for anyone running clippy without that variable, but it is not the
# hole it was reported to be.
LINT_OFF = re.compile(
    # The lint itself, by either spelling. `warn` is kept for the bare key: it does not disarm under
    # `-D warnings`, but a tree that ever drops that flag should not also be carrying this.
    r"disallowed_methods\s*=\s*[\"']?(?:allow|warn)"
    r"|clippy::disallowed_methods"
    # The groups that contain it, bare (a Cargo lint table) or prefixed (an attribute, rustflags).
    r"|(?<![\w:])(?:all|style)\s*=\s*[\"']?allow"
    r"|clippy::(?:all|style)",
    re.I,
)
# Where a Cargo lint table or a cargo config may legitimately live, with the reason. Empty: nothing
# in this repository needs one, and that is the point - an entry appearing here is a decision.
DECLARED_LINT_TABLES: dict[str, str] = {}


def main():
    problems = []

    text = CONFIG.read_text() if CONFIG.exists() else ""
    for m in REQUIRED_METHODS:
        if f'"{m}"' not in text:
            problems.append(f"clippy.toml no longer disallows `{m}`, so nothing stops a direct call")

    # A `clippy.toml` anywhere but the root REPLACES the root's rules for its whole subtree, with no
    # merging and no trace in any `.rs` file. Same standard as the allow attributes below: declared
    # with a reason, or it fails. And a declaration for a file that is gone is removed, because a
    # stale entry reads as coverage that is not there.
    configs = {
        str(p.relative_to(ROOT))
        for p in ROOT.rglob("clippy.toml")
        if "target/" not in str(p) and "node_modules/" not in str(p) and p != CONFIG
    }
    for path in sorted(configs - set(DECLARED_CONFIGS)):
        problems.append(
            f"{path} replaces the root clippy.toml for its whole subtree and is not declared in "
            f"{pathlib.Path(__file__).name}. Clippy uses the FIRST config it finds walking up, with "
            f"no merging, so this switches `disallowed-methods` off for every crate under it and "
            f"leaves no mark in any .rs file: add it with its reason, or delete it"
        )
    for path in sorted(set(DECLARED_CONFIGS) - configs):
        problems.append(
            f"{path} is declared as a per-directory clippy config but no longer exists. Remove it "
            f"from the list: a stale declaration reads as coverage that is not there"
        )

    # Cargo lint tables and cargo configs: the third way to switch the lint off for a subtree, with
    # no `.rs` mark and no `clippy.toml`. Tracked files only, same reason as above.
    tables = set()
    for name in ("Cargo.toml", "config.toml"):
        for p in ROOT.rglob(name):
            rel = str(p.relative_to(ROOT))
            if "target/" in rel or "node_modules/" in rel:
                continue
            if name == "config.toml" and ".cargo/" not in rel:
                continue
            try:
                text = p.read_text()
            except OSError:
                continue
            if LINT_TABLE.search(text) and LINT_OFF.search(text):
                tables.add(rel)
    for path in sorted(tables - set(DECLARED_LINT_TABLES)):
        problems.append(
            f"{path} switches `disallowed_methods` off through a Cargo lint table or rustflags, for "
            f"its whole package or workspace, with no mark in any .rs file and no clippy.toml: "
            f"neither check above can see it. Declare it in "
            f"{pathlib.Path(__file__).name} with its reason, or route the calls through the "
            f"chokepoints"
        )
    for path in sorted(set(DECLARED_LINT_TABLES) - tables):
        problems.append(
            f"{path} is declared as carrying a lint exemption and no longer does. Remove it from "
            f"the list: a stale declaration reads as coverage that is not there"
        )

    found = {}
    for f in sorted(ROOT.rglob("*.rs")):
        if "target/" in str(f) or "/fuzz/" in str(f):
            continue
        for n, line in enumerate(f.read_text().split("\n"), 1):
            if ALLOW.match(line):
                found.setdefault(str(f.relative_to(ROOT)), []).append(n)

    for path, lines in found.items():
        if path not in DECLARED:
            problems.append(
                f"{path}:{lines[0]} exempts itself from the environment lint and is not declared "
                f"in {pathlib.Path(__file__).name}. An exemption is a crate nobody is watching: "
                f"add it with its reason, or route the calls through the chokepoints"
            )
    for path in DECLARED:
        if path not in found:
            problems.append(
                f"{path} is declared as exempt but carries no allow attribute any more. Remove it "
                f"from the list: a stale exemption reads as coverage that is not there"
            )

    if problems:
        print(f"{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  {p}")
        return 1

    # THE GATE SAYS WHAT IT CHECKED, including the count it would be easiest to forget. A summary
    # that omits the per-directory configs would read as full coverage of a rule it had not looked at.
    print(
        f"the environment lint is armed on {len(REQUIRED_METHODS)} methods, with "
        f"{len(DECLARED)} declared file exemptions, {len(DECLARED_CONFIGS)} declared "
        f"per-directory clippy config(s) and {len(DECLARED_LINT_TABLES)} declared Cargo lint "
        f"table(s), and no undeclared ones of any kind"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
