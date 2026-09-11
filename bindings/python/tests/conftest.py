"""Say which `kern` the integration tests are about to exercise, before any of them runs.

WHY THIS FILE EXISTS. The integration tests drive a real binary, and they find it the way the SDK
does: `$KERN_BIN` if set, else the first `kern` on `$PATH`. Nothing printed which one that was, so a
green run said nothing about WHAT was green.

MEASURED, and it is the reason this was written: the suite was passing against `kern 0.9.2`, the copy
installed in `~/.local/bin` months ago, while the working tree had moved on. One pinned assertion -
the set of writable mounts inside a box - had been true for 0.9.2 and false for the tree for as long
as the tree had mounted `/dev/mqueue`, and the pin stayed green the entire time. It went red the
first time anyone pointed `KERN_BIN` at the tree's own binary, which is not a thing the suite asked
anyone to do.

IT DOES NOT REFUSE, AND THAT IS DELIBERATE. Running the SDK against an installed kern is a legitimate
thing to do - it is what a user has - and a suite that refused it would be refusing the configuration
most people are in. What was missing is not a gate, it is a sentence: the version and the path, once,
at the top of the run, so a result can never be quoted about the wrong binary.

The same discipline the runtime's own rehearsal applies (`scripts/launch-dryrun.py` prints the
binary's path, its sha256 and whether it is the release shape), one layer up.
"""

import os
import shutil
import subprocess


def pytest_report_header(config):
    """One line in pytest's header: the kern these tests will drive, and where it came from."""
    del config  # the header does not depend on the invocation, only on the environment
    env = os.environ.get("KERN_BIN")
    if env:
        path, how = env, "$KERN_BIN"
    else:
        found = shutil.which("kern")
        if not found:
            return (
                "kern: NOT FOUND on $PATH and $KERN_BIN is unset. Every integration test will skip; "
                "a green run here proves only that the unit tests pass."
            )
        path, how = found, "$PATH"
    try:
        out = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=30
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as e:
        out = f"(could not run it: {e})"
    # The version string carries `git describe`, so it names the commit and whether the tree was
    # dirty. That is the fact that tells a reader whether this run was about their change.
    return f"kern: {out}  [{path}, from {how}]"
