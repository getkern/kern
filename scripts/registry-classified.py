#!/usr/bin/env python3
"""Fail the build if a registry-root child is built without being CLASSIFIED.

WHY THIS EXISTS
    Every directory under `<runtime>/kern/` is either AUTHORITATIVE (kern reads it and ACTS ON it for
    another box, or it holds a cross-box secret; never bind-mountable) or BOX_DATA (opaque box bytes,
    mountable like `-v /home/other`). `waitexit/` shipped mountable because the protected-dirs list was
    hand-maintained parallel to the constructors, and nobody added the new child to it. The runtime
    chokepoint `registry::assert_registry_child(name)` now classifies every child, but it only fires
    when the constructor is EXERCISED. This is the COMPILE-TIME backstop: it reads the two const lists
    and refuses

      * a `runtime_subdir("X")` / `assert_registry_child("X")` call, or a `"kern/X"` path literal,
        whose child `X` is in neither class, and
      * a known non-`runtime_subdir` constructor (`pods_root`, `scratch_dir`) that stopped routing
        through the chokepoint.

    A new registry-child constructor that forgets `assert_registry_child` is caught the moment its
    child name appears unclassified here - the same "fail the build until a human decides" shape as the
    seccomp and stale-number gates.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "crates" / "kern-cli" / "src"
REGISTRY = SRC / "registry.rs"

# Constructors that MUST route their child through the classification chokepoint. `runtime_subdir`
# calls it directly; these two diverge on path resolution but must still classify.
CHOKEPOINT_CONSTRUCTORS = ["pods_root", "scratch_dir"]

# `kern/X` names that are NOT bind-mountable registry-root DIRECTORIES, each excluded for a stated
# reason. A new `kern/X` that is none of these AND not in the two dir classes fails the gate until a
# human decides which it is - the same "fail until classified" contract, extended to non-dir children.
#
#   * SIBLING TREES live under a DIFFERENT root ($XDG_CACHE_HOME / $XDG_DATA_HOME), not the runtime
#     registry root, so the `-v` guard on registry dirs does not apply to them.
#   * COSMETIC FILES are single kern-internal FILES under the runtime root that kern READS but never
#     ACTS ON (display only), so forging one skews a number, not a decision - not the identity/content
#     forgery that makes an authoritative dir dangerous, and a file is not dir-guardable anyway.
SIBLING_TREES = {"images", "volumes", "builds", "uncapped-notice"}  # under $XDG_DATA_HOME/$XDG_CACHE_HOME
COSMETIC_FILES = {"runstats", ".greeted"}  # runtime FILES kern only DISPLAYS: run counter, greet marker
NON_DIR_CHILDREN = SIBLING_TREES | COSMETIC_FILES


def const_names(text: str, const: str) -> set[str]:
    """The string entries of a `const NAME: [&str; N] = [ ... ];` array."""
    m = re.search(const + r"\s*:\s*\[&str;\s*\d+\]\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if not m:
        sys.exit(f"registry-classified: could not find `{const}` in registry.rs")
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def brace_body(text: str, start: int) -> tuple[str, int]:
    """The `{ ... }` block starting at/after `start`, brace-balanced, and the index after it."""
    i = text.find("{", start)
    if i < 0:
        return "", len(text)
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i : j + 1], j + 1
        j += 1
    return text[i:], len(text)


def strip_test_code(text: str) -> str:
    """Remove `#[cfg(test)] mod {...}` and `#[test] fn {...}` items (brace-balanced), so the bypass
    scan never flags a test that legitimately builds `<tmp>/kern/...` paths."""
    out, i = [], 0
    for m in re.finditer(r"#\[(?:cfg\(test\)|test)\]", text):
        if m.start() < i:
            continue
        out.append(text[i : m.start()])
        _, end = brace_body(text, m.end())
        i = end
    out.append(text[i:])
    return "".join(out)


def functions(text: str):
    """Yield `(name, body)` for every `fn NAME(...) { ... }`, brace-balanced."""
    for m in re.finditer(r"\bfn\s+(\w+)\s*\(", text):
        body, _ = brace_body(text, m.end())
        if body:
            yield m.group(1), body


def enclosing_fn_has_chokepoint(text: str, fn: str) -> bool:
    """True if `fn NAME(...) { ... }` calls `assert_registry_child` in its body (brace-balanced)."""
    m = re.search(r"\bfn\s+" + re.escape(fn) + r"\s*\(", text)
    if not m:
        return False  # the constructor was renamed/removed - report as missing
    i = text.find("{", m.end())
    if i < 0:
        return False
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return "assert_registry_child" in text[i : j + 1]


def main() -> int:
    reg = REGISTRY.read_text(encoding="utf-8")
    authoritative = const_names(reg, "AUTHORITATIVE_DIRS")
    box_data = const_names(reg, "BOX_DATA_DIRS")
    classified = authoritative | box_data

    overlap = authoritative & box_data
    if overlap:
        print(f"registry-classified: {sorted(overlap)} classified in BOTH lists")
        return 1

    errors: list[str] = []

    # 1. Every registry-child name referenced in the source must be classified.
    ref = re.compile(
        r'(?:runtime_subdir|assert_registry_child)\("([a-z_]+)"\)'
        r'|\.join\("kern/([a-z_]+)"\)'
        r'|/kern/\{leaf\}'  # runtime_subdir's own format! - matched but yields no name
    )
    for path in sorted(SRC.rglob("*.rs")):
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("//"):
                continue
            for m in ref.finditer(line):
                name = m.group(1) or m.group(2)
                if not name or name in NON_DIR_CHILDREN:
                    continue
                if name not in classified:
                    rel = path.relative_to(ROOT)
                    errors.append(
                        f"{rel}:{lineno}: registry child {name!r} is UNCLASSIFIED - add it to "
                        f"AUTHORITATIVE_DIRS or BOX_DATA_DIRS in registry.rs"
                    )

    # 2. The known non-runtime_subdir constructors must still route through the chokepoint.
    all_src = "\n".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.rs"))
    for fn in CHOKEPOINT_CONSTRUCTORS:
        if not enclosing_fn_has_chokepoint(all_src, fn):
            errors.append(
                f"{fn} builds a registry child but does not call assert_registry_child - route it "
                f"through the classification chokepoint"
            )

    # 3. SEARCH FOR THE BYPASS, not the name: any PRODUCTION function that builds a path under the
    # runtime registry root must route through the chokepoint. This catches a new constructor with a
    # NON-literal child name (`format!("{root}/kern/{leaf}")`) that rules 1-2 and the literal scan miss -
    # exactly the `runstats` shape, generalized. Cosmetic-file constructors are exempt (they build ONLY
    # a COSMETIC_FILES path and are not dir-classified); test code is stripped first.
    # RUNTIME root only (XDG_RUNTIME_DIR / /run/user); a function keyed on $XDG_DATA_HOME or
    # $XDG_CACHE_HOME builds a SIBLING tree (builds/, volumes/, images/, uncapped-notice), a different
    # root the registry `-v` guard does not cover, so it is not a bypass.
    runtime_kern = re.compile(r"XDG_RUNTIME_DIR|/run/user/")
    sibling_root = re.compile(r"XDG_DATA_HOME|XDG_CACHE_HOME|\.local/share|\.cache")
    # `.join("kern"` with the CLOSING QUOTE, not `.join("kern` as a prefix. The prefix form matched
    # any join whose argument merely STARTS with `kern`, so `<runtime>/kern-vgpu/`, which is a
    # SIBLING of the registry root and not a child of it, tripped a gate that exists to classify
    # children. That is a false positive, and this file records elsewhere what happens to a gate that
    # produces them: it gets switched off. `"kern/` still catches the embedded-path form
    # (`format!("{root}/kern/{leaf}")`), which is the shape rule 3 was written for.
    # THREE FORMS, and the third was missing while the comment above claimed it. `.join("kern"` with
    # the closing quote catches the joined form; `"kern/` catches a literal path that STARTS with it;
    # `}/kern/` catches the interpolated form, `format!("{root}/kern/{leaf}")`, which rule 3 was
    # written for and did not match, because in that string `/kern/` is preceded by `}` and never by
    # a quote. Verified by construction: the shape the comment names was added to a production
    # function and this gate passed, on the regex as it stood before this line was widened.
    #
    # The closing quote is load-bearing in the first alternative. Without it the pattern matched any
    # join whose argument merely BEGINS with `kern`, so `<runtime>/kern-vgpu/`, a SIBLING of the
    # registry root rather than a child of it, tripped a gate that exists to classify children. A
    # gate with false positives is a gate that gets switched off, which this repository records
    # happening twice.
    kern_join = re.compile(r'\.join\("kern"|"kern/|\}/kern/')
    child = re.compile(r'"kern/([.\w-]+)"|\.join\("kern"\)\s*\.join\("([.\w-]+)"\)')
    for path in sorted(SRC.rglob("*.rs")):
        prod = strip_test_code(path.read_text(encoding="utf-8"))
        for name, body in functions(prod):
            if sibling_root.search(body):
                continue
            if not (runtime_kern.search(body) and kern_join.search(body)):
                continue
            if "assert_registry_child" in body:
                continue
            built = {a or b for a, b in child.findall(body)}
            if built and built <= NON_DIR_CHILDREN:
                continue  # a cosmetic/sibling constructor (e.g. runstats::path) - not dir-classified
            errors.append(
                f"{path.relative_to(ROOT)}: fn {name!r} builds a runtime registry path but does not "
                f"call assert_registry_child (the chokepoint) - route it through, or if it is a "
                f"cosmetic file name it in COSMETIC_FILES"
            )

    if errors:
        print("registry-classified: FAIL")
        for e in errors:
            print("  " + e)
        return 1
    print(
        f"registry-classified: OK ({len(authoritative)} authoritative, {len(box_data)} box-data; "
        f"chokepoint enforced)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
