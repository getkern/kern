#!/usr/bin/env python3
"""A GPU for the code an agent writes: one card per sandbox, chosen by whoever runs the agent.

`gpus=` takes kern's and docker's grammar as written: "all", "2" (how many), "device=0,1" (which), or
"device=GPU-<uuid>". The code in the box gets the card's device nodes, the driver's libraries bound
read-only and a loader cache that resolves `libcuda.so.1`; the network stays off and the RAM cap holds.

What it shows:
  1. One card each, at once : two sandboxes, each told a different card, report the card's UUID, and
                              the host's `nvidia-smi` is asked which card each process is on.
  2. State on the card      : a `kernel()` keeps a CUDA context and a device buffer between cells.
  3. A card that is not there comes back as a fault, not as a box that starts without it.

What a grant does NOT give, so a caller does not assume it:
  - a VRAM limit. `memory_mb` caps host RAM; the code can fill the card it was given. Separate cards
    are the separation between agents.
  - a boundary against that code. It reaches the NVIDIA driver through the device nodes, so grant a
    card to code you would trust with it. For an MCP client the same knob is `KERN_MCP_GPUS`, set by
    whoever starts the server and never by the model (docs/MCP.md).

The code is the CUDA driver API through ctypes, so `python:3.12-slim` is the whole image: no torch, no
download beyond it. A CUDA FRAMEWORK NEEDS MORE RAM THAN THE DEFAULT `memory_mb=512`: PyTorch 2.15 with
CUDA 13.2, training a small CNN, was OOM-killed at 1 GiB and trained at 1.5 GiB, under kern and docker
alike (measured on an RTX 5060 Ti); its resident size afterwards is about 350 MB, the peak is loading. On one card both sandboxes share it; with no NVIDIA card this says so and exits 0.

Run:  KERN_BIN=/path/to/kern python3 examples/agents/gpu-sandbox.py   (or have `kern` on PATH)
"""

import shutil
import subprocess
import sys
import threading
import time

import kern_sandbox as kern

IMAGE = "python:3.12-slim"

# The card's UUID and a pattern written on it and read back: real work on the GPU, nothing faked.
ON_THE_CARD = r"""
import ctypes, sys
c = ctypes.CDLL("libcuda.so.1")
assert c.cuInit(0) == 0, "cuInit"
n = ctypes.c_int(); c.cuDeviceGetCount(ctypes.byref(n))
d = ctypes.c_int(); c.cuDeviceGet(ctypes.byref(d), 0)
u = (ctypes.c_ubyte * 16)(); c.cuDeviceGetUuid(u, d); h = bytes(u).hex()
uuid = "GPU-%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])
ctx = ctypes.c_void_p(); assert c.cuCtxCreate_v2(ctypes.byref(ctx), 0, d) == 0
mb = int(sys.argv[1]) if len(sys.argv) > 1 else 256
p = ctypes.c_uint64(); assert c.cuMemAlloc_v2(ctypes.byref(p), ctypes.c_size_t(mb << 20)) == 0
c.cuMemsetD8_v2(p, ctypes.c_ubyte(0xAB), ctypes.c_size_t(mb << 20))
back = (ctypes.c_ubyte * 4096)(); c.cuMemcpyDtoH_v2(back, p, ctypes.c_size_t(4096))
import time; time.sleep(3)
print(uuid, "cards in box:", n.value, "pattern:", "ok" if all(b == 0xAB for b in back) else "BAD")
"""


def rule(t):
    print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


def host_cards():
    if not shutil.which("nvidia-smi"):
        return []
    out = subprocess.run(["nvidia-smi", "--query-gpu=uuid", "--format=csv,noheader"],
                         capture_output=True, text=True)
    return out.stdout.split() if out.returncode == 0 else []


cards = host_cards()
if not cards:
    print("no NVIDIA card on this host (nvidia-smi is absent or lists none): nothing to grant")
    sys.exit(0)
second = "1" if len(cards) > 1 else "0"
if len(cards) == 1:
    print("one card on this host: both sandboxes get card 0")

rule("1. one card per sandbox, both at once")
asked = [("0", 512), (second, 1024)]
results = [None] * len(asked)


def run_on(i, card, mb):
    with kern.Sandbox(image=IMAGE, gpus=f"device={card}", timeout_s=60) as sb:
        code = "import sys\nsys.argv = ['x', '%d']\n" % mb + ON_THE_CARD
        results[i] = sb.run_code(code)


threads = [threading.Thread(target=run_on, args=(i, card, mb)) for i, (card, mb) in enumerate(asked)]
for t in threads:
    t.start()
# While both hold their buffers, ask the driver from the host.
time.sleep(2)
seen = subprocess.run(["nvidia-smi", "--query-compute-apps=gpu_uuid,used_memory", "--format=csv,noheader"],
                      capture_output=True, text=True).stdout.strip()
for t in threads:
    t.join()
for (card, _), r in zip(asked, results):
    print(f"  device={card}: {r.stdout.strip() or r.fault}")
print("  the host's nvidia-smi, while they ran:")
for line in seen.splitlines():
    print("   ", line)

rule("2. a kernel() keeps a CUDA context and a buffer on the card between cells")
with kern.Sandbox(image=IMAGE, gpus=f"device={second}", timeout_s=60) as sb, sb.kernel() as k:
    k.run_code("import ctypes\nc = ctypes.CDLL('libcuda.so.1'); c.cuInit(0)\n"
               "d = ctypes.c_int(); c.cuDeviceGet(ctypes.byref(d), 0)\n"
               "ctx = ctypes.c_void_p(); c.cuCtxCreate_v2(ctypes.byref(ctx), 0, d)\n"
               "p = ctypes.c_uint64(); c.cuMemAlloc_v2(ctypes.byref(p), ctypes.c_size_t(64 << 20))\n"
               "c.cuMemsetD8_v2(p, ctypes.c_ubyte(7), ctypes.c_size_t(64 << 20))")
    r = k.run_code("h = (ctypes.c_ubyte * 4)(); c.cuMemcpyDtoH_v2(h, p, ctypes.c_size_t(4)); print(list(h))")
    print("  read back in the next cell:", r.stdout.strip(), " <- the buffer outlived the cell")

rule("3. a card this host does not have is a fault, not a box without it")
r = kern.run_code("print('this never runs')", image=IMAGE, gpus="device=99")
print(f"  fault: {r.fault.type if r.fault else None}")
print("  " + (r.fault.message if r.fault else r.stdout).splitlines()[0])
