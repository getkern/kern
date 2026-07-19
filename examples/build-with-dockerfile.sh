#!/bin/sh
# Build a local image from a Dockerfile with `kern build`, then run it - no daemon, no root.
#
#   kern build -t <name[:tag]> [-f <Dockerfile>] [--build-arg K=V]... [<context>]
#     -t / --tag     name (and optional :tag) for the built image      (required)
#     -f / --file    Dockerfile path             (default: <context>/Dockerfile)
#     --build-arg    seed an ARG                                  (repeatable, K=V)
#     <context>      build-context directory                          (default: .)
#
# kern's builder understands the common instructions: FROM RUN COPY ADD ENV WORKDIR
# USER CMD ENTRYPOINT EXPOSE ARG LABEL. (VOLUME/HEALTHCHECK parse but have no build-time
# effect - HEALTHCHECK maps to the runtime `--health-cmd` instead.)
# The result is a normal cached image: `kern images` lists it and `--image <tag>` runs it.
set -eu
kern="${KERN:-kern}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat > "$work/Dockerfile" <<'EOF'
FROM alpine:3.19
ARG GREETING=hello
# ARG/ENV values substitute into later ${VAR}; --build-arg overrides the ARG default.
RUN echo "$GREETING from the build" > /greeting.txt
ENV APP_MSG="baked into the image config"
WORKDIR /app
CMD ["/bin/sh","-c","cat /greeting.txt; echo \"env: $APP_MSG\"; echo \"cwd: $(pwd)\""]
EOF

echo "==> building image 'dockerfile-demo:1' from the Dockerfile (context = $work):"
"$kern" build -t dockerfile-demo:1 --build-arg GREETING="hi there" "$work"

echo
echo "==> it's a cached image now:"
"$kern" images | sed -n '1p;/dockerfile-demo/p'

echo
echo "==> run it with NO command - the baked-in CMD/ENV/WORKDIR take effect:"
"$kern" box df-run --image dockerfile-demo:1

echo
echo "==> or override the command; the image's WORKDIR (/app) still applies:"
"$kern" box df-run2 --image dockerfile-demo:1 -- /bin/sh -c 'echo "pwd is $(pwd), file says: $(cat /greeting.txt)"'

echo
echo "==> cleanup: drop the built image, reclaim its layers:"
"$kern" rmi dockerfile-demo:1 >/dev/null 2>&1 || true
"$kern" gc >/dev/null 2>&1 || true
echo "done - image removed, temp Dockerfile gone, nothing left running."
