"""A test double for the `kern` binary, for the unit tests that need a Sandbox and not a box.

WHY IT IS NOT `/bin/true` ANY MORE. The binding now REFUSES a binary that does not identify itself as
kern, and the reason is a defect an external reviewer found by running the positive control this project
had written for him: with `KERN_BIN=/bin/true` a call came back `success=True, exit_code=0, fault=None`
and an empty stdout. The code never ran and the caller was told it had.

So the double has to impersonate the one thing the binding checks, and only that: `--version` prints a
line beginning `kern `. Everything else stays what `/bin/true` was, an immediate clean exit, because that
is what the unit tests depend on (they assert the argv the binding BUILDS, never what a box does).

A double that cannot satisfy the contract under test would force an escape hatch into the product, and
an escape hatch in the product is a flag an agent framework can set. The double moves instead.
"""

import atexit
import os
import shutil
import tempfile

_SCRIPT = """#!/bin/sh
# A test double: it answers the identity question and does nothing else.
case "$1" in
  --version) echo "kern v0.0.0-test-double" ; exit 0 ;;
esac
exit 0
"""


def _build() -> str:
    d = tempfile.mkdtemp(prefix=f"kern-fake-{os.getpid()}-")
    p = os.path.join(d, "kern")
    with open(p, "w", encoding="utf-8") as f:
        f.write(_SCRIPT)
    os.chmod(p, 0o755)
    atexit.register(shutil.rmtree, d, True)
    return p


#: Absolute path to the double. Unique per process, so `_kern_runnable()` can still tell it from a real
#: kern by comparing paths.
FAKE_KERN = _build()
