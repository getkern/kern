#!/bin/sh
# Run a Python data task without Python or pip on your host.
#
# Two phases, deliberately split by network access:
#   1. INSTALL (--net):  pip install a pure-Python library into a bind-mounted /deps dir (kept on the
#                        host). The only step that touches the network.
#   2. PROCESS (no --net): a network-isolated box reads a bound-in data file, transforms it using the
#                        already-installed library (PYTHONPATH=/deps), and writes the result to an /out
#                        directory you keep. No outbound access while it crunches your data.
#
# The point: fetch the library once, then process untrusted/local data sealed off from the network. Your
# host never gets python, pip, or the library on its PATH.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/deps" "$work/data" "$work/out"

# A tiny CSV to process (bound in read-only).
cat > "$work/data/sales.csv" <<'EOF'
region,units,revenue
north,120,4800
south,90,3510
east,150,6000
west,60,2100
EOF

# The task: read the CSV and render it as a Markdown table using the installed `tabulate` library.
cat > "$work/data/process.py" <<'EOF'
import csv
from tabulate import tabulate  # provided via PYTHONPATH=/deps, installed in the network phase

with open('/data/sales.csv', newline='') as f:
    rows = list(csv.reader(f))

table = tabulate(rows[1:], headers=rows[0], tablefmt='github')
with open('/out/report.md', 'w') as f:
    f.write(table + '\n')
print(table)
EOF

echo "==> 1. INSTALL phase (--net on): pip install 'tabulate' into a host-side /deps dir:"
"$kern" box py_install --image python:alpine --net \
  -v "$work/deps:/deps" -- \
  sh -c 'pip install --quiet --target /deps tabulate && echo "   installed into /deps"'

echo
echo "==> 2. PROCESS phase (NO --net): transform the bound-in CSV, write /out/report.md:"
"$kern" box py_process --image python:alpine \
  -v "$work/deps:/deps:ro" -v "$work/data:/data:ro" -v "$work/out:/out" \
  -e PYTHONPATH=/deps -- \
  python3 /data/process.py

echo
echo "==> the result is on your host at \$out/report.md:"
sed 's/^/   /' "$work/out/report.md"

echo
echo "==> your host stayed clean:"
command -v python3 >/dev/null 2>&1 && echo "   (host has python3)" || echo "   host has NO python3 - it all lived in the boxes"
echo "done - deps, data and output removed on exit (trap)."
