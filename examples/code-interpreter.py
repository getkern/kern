#!/usr/bin/env python3
"""A stateful "code interpreter" session - like a notebook the agent drives turn by turn.

Many agents want a REPL-ish tool: turn 1 loads data, turn 2 transforms it, turn 3 plots it, each turn
building on the last. kern gives you that through a `Sandbox` context manager, with one honest twist you
MUST design around:

  * FILE state persists across turns. The workspace is a directory on disk, bind-mounted into every box,
    so anything the code WRITES (a CSV, a pickle, a model file) is there on the next `run_code`.
  * PROCESS/MEMORY state does NOT persist. There is no resident interpreter - each turn is a FRESH box.
    A variable `x = 40` living only in memory is GONE next turn. This is deliberate: it keeps the
    millisecond cold-start / high-density win instead of pinning a python process per session.

So the "notebook" rule is simple: if you need it next turn, WRITE IT TO DISK. Below we carry state the
right way (a file), and `setup=` installs a dependency ONCE (the only moment the network is on - a
separate setup box that dies), so later turns can `import` it network-off.

    KERN_BIN=./target/release/kern python3 examples/code-interpreter.py

Note: `setup="pip install ..."` reaches the network to fetch the package. If you're offline this line
will fail at __enter__ (raised as SandboxError - a setup/config failure, not a normal run outcome).

Honest threat model: a KERNEL-boundary sandbox for YOUR OWN or SEMI-TRUSTED code. seccomp is a
denylist, not a hard multi-tenant wall. See bindings/python/README.md.
"""
import kern_sandbox as kern

# `setup` runs ONCE, network-on, in a throwaway box; it installs into <workspace>/.deps, which every
# later network-off `run_code` gets on its PYTHONPATH. Install the dep here, import it for free later.
with kern.Sandbox(setup="pip install tabulate", memory_mb=512, cpus=1.0, timeout_s=30) as ipy:

    # Turn 1 - the agent "loads data". Persist it to the workspace so the next turn can see it.
    print("turn 1: write the dataset to the workspace (persists to disk)")
    ipy.write_file("sales.csv", "region,amount\nnorth,120\nsouth,80\nnorth,60\neast,200\n")
    r = ipy.run_code("print('rows:', sum(1 for _ in open('sales.csv')) - 1)")
    print("  ->", r.stdout.strip(), f"(success={r.success})")

    # Turn 2 - compute over the file from turn 1 and WRITE the intermediate result back to disk.
    #   In-memory `totals` would vanish; a JSON file on the workspace carries it to turn 3.
    print("\nturn 2: aggregate the CSV, save the intermediate result as JSON")
    r = ipy.run_code(
        "import csv, json, collections\n"
        "totals = collections.Counter()\n"
        "for row in csv.DictReader(open('sales.csv')):\n"
        "    totals[row['region']] += int(row['amount'])\n"
        "json.dump(dict(totals), open('totals.json', 'w'))\n"
        "print('wrote totals.json:', dict(totals))"
    )
    print("  ->", r.stdout.strip(), f"(success={r.success})")

    # Turn 3 - read the JSON turn 2 wrote AND use the dep installed once in `setup`, all network-off.
    print("\nturn 3: read the saved result + format it with the pre-installed 'tabulate' dep")
    r = ipy.run_code(
        "import json\n"
        "from tabulate import tabulate\n"
        "data = json.load(open('totals.json'))\n"
        "print(tabulate(sorted(data.items()), headers=['region', 'total']))"
    )
    print(r.stdout)

    # The host side can read any workspace file directly (files are host-owned) - e.g. to return an
    # artifact the agent produced to the user.
    print("host reads the artifact the session produced:")
    print("  totals.json =", ipy.read_file("totals.json").decode())

print("\ndone - file state carried each turn, one dep installed once; every turn a fresh, isolated box.")
