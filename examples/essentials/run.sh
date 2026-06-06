#!/bin/sh
# Run a one-off command in a clean image, then throw the box away.
# The image is pulled once (cached after); nothing is installed on your host.
set -eu
kern="${KERN:-kern}"
echo '==> kern box demo --image alpine -- (print the distro)'
"$kern" box demo --image alpine -- sh -c '. /etc/os-release; echo "$PRETTY_NAME"'
echo "The box is gone; your host is untouched."
