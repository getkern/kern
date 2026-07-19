#!/bin/sh
# Docker-archive interop: `kern save` an image to a tar, `kern load` it back.
#
#   kern save <image> -o <file.tar>   write the image as a `docker save`-format tar
#   kern load -i <file.tar>           import an image from a kern OR docker tar (or stdin)
#
# The tar `kern save` writes is loadable by Docker (`docker load -i file.tar`) and vice-versa, so
# you can move images between kern and Docker, ship them to an air-gapped box, or check one into an
# artifact store - no registry needed. Every loaded tar is vetted + extracted through the SAME
# hardened path as `kern pull` (an archive is as untrusted as a registry image).
set -eu
kern="${KERN:-kern}"
img=alpine
tar="$(mktemp -d)/alpine.tar"

echo "==> make sure the image is present locally:"
"$kern" pull "$img"

echo
echo "==> save it to a docker-loadable tar:"
"$kern" save "$img" -o "$tar"
ls -lh "$tar" | awk '{print "   " $9 "   " $5}'
echo "   (this tar also loads into Docker with:  docker load -i $tar)"

echo
echo "==> drop the cached image, then re-import it FROM the tar:"
"$kern" rmi "$img" >/dev/null 2>&1 || true
"$kern" load -i "$tar"

echo
echo "==> it's back in the image list, and runnable:"
"$kern" images | sed -n '1,6p'
"$kern" box from-tar --image "$img" -- /bin/sh -c 'echo "   ran from the re-imported image ✓"'

echo
echo "==> cleanup:"
rm -rf "$(dirname "$tar")"
echo "done - images move as plain tars, interop with Docker both ways, no registry required."
