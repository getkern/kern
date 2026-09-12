#!/usr/bin/env python3
"""Run the documentation's shell blocks the way a reader runs them: in order, carrying state.

WHY THIS EXISTS, AND WHY IT IS NOT THE OTHER BATTERIES. The compose battery and the suites test the
RUNTIME. This tests the TEXT. A reader copies from a browser: they do not know about the AppArmor
profile, they do not know about the systemd scope, and they do not rewrite a command the paste broke.
The first thing anyone does with this project is copy a block, so a block that cannot work is the
most expensive defect there is, and nothing measured it.

IT FOUND ONE THE HOUR IT WAS WRITTEN. The README showed a `stack.toml` with `ports = ["8080:8080"]`
and then, in the very next block, `kern compose stack.toml port web 80` (wrong port, exits 1) and
`kern compose stack.toml watch` (the file has no `build:`, so there is nothing to watch, exits 1).
Two of three lines could not work with the file printed above them. Both errors were correct and
helpful; the text was wrong.

WHAT IT DOES NOT DO, DELIBERATELY:
  * it does not install anything, reach a registry over the network, or touch the machine: blocks
    with `install.sh`, `pip`, `apt`, `ssh`, `wsl`, `docker` and friends are SKIPPED and counted;
  * it does not run interactive blocks (`-it`): without a terminal they wait for one that is not
    there, and pretending to have tested them is worse than skipping them;
  * it does not overwrite a real file of yours. A non-executable block whose first line names a file
    (```toml starting `# stack.toml - …`) is materialised in the work dir, because that is what the
    reader does with it, but an absolute path that already exists is left alone.

State is carried per DOCUMENT, in one directory, because that is the order a reader meets it in: a
block that writes a file serves the block after it. Running each in a fresh directory measures a
reader who does not exist, and the first version of this file did exactly that and invented three
failures that were the measurer's.

    python3 scripts/readme-blocks.py [path/to/kern]
"""
import os
import pathlib
import re
import subprocess
import sys
import tempfile

KERN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/release/kern")
# Documents after the binary override the default set, which is what makes a POSITIVE CONTROL
# possible: point it at a file with a block that cannot work and it has to go red, or a green run
# here says nothing at all.
DOCS = sys.argv[2:] or ["README.md", "docs/INSTALL.md", "docs/MCP.md"]
SKIP_IF = re.compile(
    r"(install\.sh|install\.ps1|irm |brew |colima|apt |dnf |zypper|apk add|systemctl|sudo |"
    r"cargo install|pip install|npm i|npm install|uvx|ssh |wsl|docker |podman |git clone|curl -fsSL|"
    # imports a package this script refuses to install, so its failure would be about pip, not the doc
    r"import kern_sandbox|require\('kern-sandbox'|"
    # wants the cloned repository under its feet, which a reader in a clone has and this run does not
    r"\bpentest/|\bscripts/|\./target/|"
    # names a script the READER supplies (`./train.sh`, `/w/x.py`): running it here would be
    # inventing a file the documentation deliberately leaves to them
    r"\./\w[\w-]*\.(?:sh|py|js)\b|/w/)"
)
INTERACTIVE = re.compile(r"(^|\s)-(it|i|t)(\s|$)")
NAMES_A_FILE = re.compile(r"^[#/]{1,2}\s*([~\w./-]+\.(?:toml|yml|yaml|json))\b")
RUNNABLE = {"sh", "bash", "console", "shell", ""}


def blocks(path):
    """Every fenced block: (line number of its first content line, language, body)."""
    lines = pathlib.Path(path).read_text(encoding="utf-8").splitlines()
    fence, out, i = re.compile(r"^```(\w*)\s*$"), [], 0
    while i < len(lines):
        m = fence.match(lines[i])
        if m:
            lang, start, body = m.group(1), i + 1, []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                body.append(lines[i])
                i += 1
            out.append((start, lang, "\n".join(body)))
        i += 1
    return out


def main():
    if not os.access(KERN, os.X_OK):
        print(f"  readme-blocks: no kern at {KERN}; build it first")
        return 2
    total = ran = skipped = failed = 0
    problems, interactive, materialised = [], [], []
    env_base = dict(os.environ)
    env_base["PATH"] = os.path.dirname(KERN) + ":" + env_base.get("PATH", "")
    for doc in DOCS:
        if not os.path.exists(doc):
            continue
        workdir = tempfile.mkdtemp(prefix="kern-readme-")
        # HOME INSIDE THE WORK DIR. A block that writes `~/.config/kern/kern.toml` must not write
        # the machine's real one: this script reads documentation, it does not configure anybody's
        # computer. With HOME here, `~` resolves inside the temporary tree and nothing it does can
        # escape it, which also makes the absolute-path case safe to materialise instead of skipping.
        env = dict(env_base)
        env["HOME"] = workdir
        env["XDG_CONFIG_HOME"] = os.path.join(workdir, ".config")
        for line, lang, body in blocks(doc):
            total += 1
            if lang not in RUNNABLE:
                first = body.strip().splitlines()[0] if body.strip() else ""
                m = NAMES_A_FILE.match(first)
                if m:
                    raw = m.group(1)
                    rel = raw[2:] if raw.startswith("~/") else raw.lstrip("/")
                    path = os.path.join(workdir, rel)
                    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                    pathlib.Path(path).write_text(body + "\n", encoding="utf-8")
                    materialised.append((doc, line, raw))
                skipped += 1
                continue
            if not body.strip() or SKIP_IF.search(body):
                skipped += 1
                continue
            if INTERACTIVE.search(body):
                interactive.append((doc, line, body.splitlines()[0][:70]))
                skipped += 1
                continue
            cmd = "\n".join(l[2:] if l.startswith("$ ") else l for l in body.splitlines())
            ran += 1
            try:
                p = subprocess.run(
                    ["bash", "-c", cmd], cwd=workdir, env=env, stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=300,
                )
                rc, out = p.returncode, (p.stderr or p.stdout).strip().splitlines()
            except subprocess.TimeoutExpired:
                rc, out = 124, ["hung: 300s with stdin closed"]
            if rc != 0:
                failed += 1
                problems.append((doc, line, cmd.splitlines()[0][:70], rc,
                                 out[0][:110] if out else "(no output)"))
        # Take down whatever the blocks brought up, so the next document starts clean and the
        # machine is not left holding ports. A stack left running took port 8080 and made the NEXT
        # document's block fail, which read as a documentation defect and was this script's.
        subprocess.run(["bash", "-c", f'"{KERN}" ps -q | xargs -r "{KERN}" stop'],
                       cwd=workdir, env=env, capture_output=True)
    for doc, line, t in materialised:
        print(f"    saved as a reader would: {doc}:{line} -> {t}")
    for doc, line, c in interactive:
        print(f"    interactive, needs a TTY, not run here: {doc}:{line}  $ {c}")
    print(f"  blocks={total} ran={ran} skipped={skipped} FAILED={failed}")
    for doc, line, cmd, rc, err in problems:
        print(f"    {doc}:{line}  rc={rc}  $ {cmd}")
        print(f"        -> {err}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
