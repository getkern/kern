# The batteries-included sandbox image: what an agent reaches for, already inside.
#
# WHY IT EXISTS. The SDK default is `python:3.12-slim`, which has python, sh and bash and nothing
# else. An agent that wants a chart has no matplotlib, so the only way to get one is `setup=` (or
# `KERN_MCP_SETUP`), and that runs a box WITH THE NETWORK ON. The most common first request an agent
# makes therefore punches through the one promise the sandbox leads with. Baking the libraries in
# removes the reason to open the network at all.
#
# ⛔ NOT THE DEFAULT YET. `_DEFAULT_IMAGE` in both bindings still names `python:3.12-slim`, and it
# must keep naming a PUBLISHED image: pointing the default at something that exists only on the
# machine that built it would break every user on their next `pip install`. Build it, use it by name
# (`Sandbox(image="kern-sandbox:local")`), and flip the default only once it is published.
#
# Build it with kern itself:
#     kern build -t kern-sandbox:local -f images/sandbox/Dockerfile images/sandbox
#
# NODE COMES FROM A STAGE, NOT A PACKAGE MANAGER. `apt-get install nodejs` on a slim base pulls a
# dependency tree and a Debian-aged node; copying the official image's own tree gives the version
# that image ships and adds no apt lists to clean up. The three directories are all of it: the
# binary, the libraries it dlopens, and the bundled npm/corepack.
FROM node:22-slim AS node

FROM python:3.12-slim

# ONE layer for the python stack, and `--no-cache-dir` because a wheel cache in an image is bytes
# every puller downloads and nobody uses. Versions are NOT pinned here on purpose: this file is the
# recipe, and the published image's exact set is recorded by its own digest. Pin them the day this
# becomes the default, when reproducibility starts mattering more than staying current.
RUN pip install --no-cache-dir \
        numpy \
        pandas \
        matplotlib \
        && find /usr/local -name '__pycache__' -type d -prune -exec rm -rf {} + \
        && find /usr/local -name 'tests' -type d -prune -exec rm -rf {} +

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules

# npm and npx are symlinks INTO node_modules in the official image, and a COPY of a symlink whose
# target is copied separately would land as a dangling link. Re-made here so they point at what was
# actually copied.
RUN ln -sf /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
        && ln -sf /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# HEADLESS, OR THE FIRST PLOT FAILS. matplotlib picks an interactive backend when it can and a box
# has no display, so `plot()` would raise on the exact call this image exists to serve. Agg writes
# PNG/SVG to a file, which is what a sandbox can hand back anyway.
ENV MPLBACKEND=Agg

# THE FONT CACHE GOES IN /tmp, AND THE IMAGE DOES NOT SHIP ONE. Both halves were measured, because
# the obvious version of this is wrong:
#
#   * Baking the cache into the image and pointing `MPLCONFIGDIR` at it DOES NOT WORK. matplotlib
#     requires that directory to be WRITABLE and a box runs with a read-only root, so it refuses the
#     baked cache, prints "/usr/local/share/mplcache is not a writable directory" in every box, and
#     rebuilds the cache in a RANDOM directory next to the CWD - which is `/workspace`, so it litters
#     the user's own workspace with a `matplotlib-<random>` directory per box. Tried, measured, removed.
#   * It would buy ~50 ms anyway: measured in a box, the first import is 293-341 ms with the cache
#     being built and 258 ms with it already there.
#
# `/tmp` is writable in a sandbox box, so the cache is built once per box, silently, and nothing
# lands in the workspace. A bare `kern box --read-only` with no tmpfs at /tmp still gets matplotlib's
# warning, which is what it got before this image existed.
ENV MPLCONFIGDIR=/tmp/matplotlib

WORKDIR /workspace
