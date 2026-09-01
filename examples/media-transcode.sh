#!/bin/sh
# Transcode media in an isolated box, capped to a couple of cores.
#
# ffmpeg runs inside a throwaway box (installed there, not on your host);
# `--cpus` caps the job so a long encode can't take over the machine. `-v` maps
# a folder in and out, so the result lands on your host - which needs no ffmpeg.
set -eu
kern="${KERN:-kern}"
# WHICH BINARY IS THIS. Printed to stderr on every run, because `${KERN:-kern}` silently
# resolves to whatever `kern` is on PATH: a validation that forgets to set KERN measures the
# INSTALLED release while believing it measured the build under test, and reports green for
# code that never ran. A wrong binary has to be visible in the output, not inferred from it.
printf '# using %s (%s)\n' "$(command -v "$kern" || echo "$kern")" "$("$kern" --version 2>&1 | head -1)" >&2


echo "==> transcoding a 3s test clip in a box, capped to 2 CPUs:"
"$kern" box transcode --image alpine --net --cpus 2 -v "$PWD:/work" -w /work -- sh -c '
  apk add --no-cache ffmpeg >/dev/null 2>&1
  ffmpeg -hide_banner -loglevel error \
         -f lavfi -i testsrc=duration=3:size=640x360:rate=25 \
         -c:v libx264 -y clip.mp4
  echo "  encoded clip.mp4 ($(wc -c < clip.mp4) bytes)"
'

echo
echo "==> the file is on your host:"
ls -la clip.mp4 2>/dev/null || echo "  (not found)"
echo
echo "done - the encode ran in a throwaway box; your host has no ffmpeg installed."
