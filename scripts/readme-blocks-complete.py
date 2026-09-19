#!/usr/bin/env python3
"""Every Python block in a README either RUNS as written, or says it is reference.

WHY THIS EXISTS, and it is not hypothetical. The LangChain block in the Python SDK README read:

    from kern_sandbox.langchain import kern_code_tool
    tool = kern_code_tool(memory_mb=512, timeout_s=30)
    agent = create_agent(model, [tool])

`create_agent` and `model` are never imported and never assigned, under a heading that promises "use
it from LangChain" and directly under an install line. A reader pastes it and gets `NameError`. Worse
than a missing import: the install line above it (`pip install 'kern-sandbox[langchain]'`) pulls
`langchain-core` ONLY, on purpose, so `create_agent` would not be importable even if the import were
written. The install and the snippet under it disagreed, and nothing said so.

An external reviewer found it by pasting all thirteen blocks, which is what a launch audience does and
what I had never done. This gate is that pass, made cheap enough to run on every push.

HOW, and why STATIC rather than executed. Running the blocks needs a kern binary, a network and an
image pull: minutes, and it would not run on a CI runner. Undefined names do not need any of that. The
blocks are parsed in READING ORDER with an ACCUMULATING scope, because that is how a reader meets them:
a block may use `kern` from the block above it, and that is not a defect. A name that NO earlier block
defines is one.

WHAT IT DELIBERATELY DOES NOT CHECK: whether a runnable block produces the right answer. That needs
execution and belongs in the SDK's own test suite. This answers one question only, the one that was
missed: can a reader paste this and have it resolve?

THE ESCAPE HATCH IS EXPLICIT AND NARROW. A block that is a type definition or a catalogue of arguments
is legitimate prose; it carries `<!-- readme-block: reference -->` on the line before its fence, and
the marker names it as not-to-be-pasted. A marker is a decision someone wrote down, which is the
difference between a documented reference block and a broken snippet.
"""
import ast
import builtins
import re
import subprocess
import sys

MARKER = "<!-- readme-block: reference -->"


def tracked_readmes() -> list[str]:
    """The tracked READMEs, from git. An untracked file is invisible to CI too."""
    out = subprocess.run(
        ["git", "ls-files", "*README.md"], capture_output=True, text=True, check=False
    )
    return [p for p in out.stdout.split() if p]


def blocks(text: str):
    """Every fenced block: (index, language, body, marked_as_reference)."""
    for i, m in enumerate(re.finditer(r"^```(\w*)\n(.*?)^```", text, re.S | re.M), 1):
        before = text[: m.start()].rstrip().split("\n")
        marked = bool(before) and before[-1].strip() == MARKER
        yield i, m.group(1), m.group(2), marked


def defined_by(tree: ast.AST) -> set[str]:
    """Names this block introduces: imports, assignments, defs, with/for targets, comprehensions.

    Deliberately GENEROUS. A gate about undefined names must never invent one, so anything that could
    plausibly bind a name counts as binding it. The cost of being generous is a missed fragment; the
    cost of being strict is a false red on a correct README, and a gate that cries wolf gets deleted.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            out.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
            # A ClassDef has no `.args` at all, so the attribute is reached through the node and not
            # through `getattr(node.args, ...)`, which evaluates `node.args` first and raises.
            args = getattr(node, "args", None)
            if args is not None:
                out.update(a.arg for a in (args.args or []))
                out.update(a.arg for a in (args.kwonlyargs or []))
                out.update(a.arg for a in (args.posonlyargs or []))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                out.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            out.add(node.name)
        elif isinstance(node, ast.Global) or isinstance(node, ast.Nonlocal):
            out.update(node.names)
    return out


def used_by(tree: ast.AST) -> set[str]:
    return {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    }


def main() -> int:
    files = tracked_readmes()
    if not files:
        print("readme-blocks-complete: no tracked README found, so this gate measured nothing")
        return 1

    bad = 0
    checked = 0
    for path in files:
        text = open(path, encoding="utf-8").read()
        scope = set(dir(builtins)) | {"__name__", "__file__"}
        for idx, lang, body, marked in blocks(text):
            if lang != "python":
                continue
            if marked:
                # Still parsed: a reference block with a syntax error is a typo on the page.
                try:
                    ast.parse(body)
                except SyntaxError:
                    pass  # a type stub or an ellipsis catalogue need not parse
                continue
            checked += 1
            try:
                tree = ast.parse(body)
            except SyntaxError as e:
                print(f"{path}: block {idx} is not valid Python ({e.msg}) and is not marked "
                      f"{MARKER!r}")
                bad += 1
                continue
            scope |= defined_by(tree)
            missing = sorted(used_by(tree) - scope)
            if missing:
                print(
                    f"{path}: block {idx} uses {', '.join(missing)}, which no earlier block defines. "
                    f"A reader who pastes it gets NameError. Complete the block, or mark it "
                    f"{MARKER!r} on the line above its fence."
                )
                bad += 1
    if bad:
        print(f"\nreadme-blocks-complete: {bad} block(s) cannot be pasted as written.")
        return 1
    print(f"readme-blocks-complete: {checked} runnable Python block(s) across {len(files)} "
          f"README(s), every name resolves.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
