#!/bin/sh
# Pull a real OCI image and run a command inside an isolated, writable box.
#
# The image is Alpine from Docker Hub. The box is writable by default (an overlay: the image is
# the read-only lower layer, your writes go to a private upper layer that's discarded on exit -
# the image itself never changes).
set -eu
kern="${KERN:-kern}"

"$kern" box demo --image alpine -- /bin/sh -c '
  echo "inside: $(cat /etc/os-release | sed -n "s/^PRETTY_NAME=//p")"
  echo "hostname: $(hostname)        # isolated UTS namespace"
  echo "uid: $(id -u)                 # mapped to root *inside* the namespace only"
  echo "pids visible: $(ls -d /proc/[0-9]* | wc -l)   # PID namespace: only this box"
  echo "writing /hello ...";  echo hi > /hello && cat /hello
'

# Re-running is instant: the image is cached locally.
echo "second run uses the cache:"
"$kern" box demo --image alpine -- /bin/echo "cached run, done."
