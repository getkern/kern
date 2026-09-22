# A precompiled Python image

Two lines that are worth about six times the call rate, and the reason is not kern.

`python:3.12-slim` ships **567 `.py` files** of standard library and **no `.pyc`**. A box mounts its
root read-only, so every box recompiles from source whatever it imports. That cost is paid at every
call, and it is also what limits the prewarm pool: refilling one slot was measured at 74 ms, of
which about 70 is the interpreter starting inside the box.

```sh
kern build -t kern-py-precompiled .
```

```python
import kern_sandbox as kern

with kern.Sandbox(image="kern-py-precompiled", prewarm=8) as s:
    print(s.run_code("import json; print(sum(range(100)))").stdout)
```

## What it is worth

Measured 2026-09-22 on an Intel i7-14700KF, Linux 7.0.0, with kern 0.20.0 and `kern-sandbox` 0.2.34.
Sixty calls of `import json; print(i)`, a **fresh container each time**, after letting the pool fill:

| image | `prewarm=0` | `prewarm=8` |
|---|---:|---:|
| `python:3.12-slim` | 45.33 ms | 22.83 ms |
| this one | 16.49 ms | **7.87 ms** |

The pool is worth twice as much here, and that is the point rather than a coincidence: a slot that
refills faster keeps up with a loop that the stock image could not.

**Why this is not the default.** An SDK that silently required an image you have to build would be
worse than one that costs the difference and says so. The default stays the stock tag, and this is
here so the choice is one command rather than a paragraph you have to act on yourself.
