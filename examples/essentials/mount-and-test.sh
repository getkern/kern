#!/bin/sh
# Run a command against your own files in a clean image.
# `-v` maps a folder in and out, `-w` sets the working dir; the host keeps the result.
set -eu
kern="${KERN:-kern}"
work="$(mktemp -d)"; printf 'one\ntwo\n' > "$work/data.txt"
echo '==> kern box job --image alpine -v "$work:/src" -w /src -- sh -c ...'
"$kern" box job --image alpine -v "$work:/src" -w /src -- \
  sh -c 'echo "cwd=$(pwd)"; echo "lines in data.txt: $(wc -l < data.txt)"; echo "appended by the box" >> data.txt'
echo
echo "==> the file on your host now carries the box's change:"
sed 's/^/    /' "$work/data.txt"
rm -rf "$work"
