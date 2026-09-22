# The stock `python:3.12-slim` ships 567 `.py` files of standard library and no `.pyc`, and a box
# mounts its root read-only, so every box recompiles what it imports. This precompiles once, at
# build time, and the boxes stop paying for it.
FROM python:3.12-slim
RUN python3 -m compileall -q -j 0 /usr/local/lib/python3.12
