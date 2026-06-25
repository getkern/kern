#!/bin/sh
# Try a command on several Linux distros — instantly, throwaway, no VM, no install.
# Each box pulls the image once (cached after), runs in a writable overlay, and vanishes.
# Without kern this means either a daemon (Docker) or hand-built chroots/VMs.
set -eu
kern="${KERN:-kern}"

for img in alpine:3.19 debian:stable-slim ubuntu:24.04; do
  printf '%-22s ' "$img:"
  "$kern" box "try-$(echo "$img" | tr ':/' '--')" --image "$img" -- \
    sh -c '. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME"'
done

echo
echo "Nothing was installed on your host; every box was discarded on exit."
