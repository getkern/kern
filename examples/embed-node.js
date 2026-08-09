#!/usr/bin/env node
/*
 * Embed kern in Node: run LLM/agent-generated code in a fresh kernel sandbox per call.
 *
 * This is the `kern-sandbox` npm package (install from source: `npm install ./bindings/node`) - a thin,
 * safe wrapper around the `kern` binary, a mirror of the Python `kern_sandbox` package. Each runCode()
 * spawns a FRESH, ephemeral box (user namespace + seccomp + cgroups); FILE state persists between steps
 * via a workspace directory on disk, but PROCESSES do not (no resident interpreter - write to disk if
 * you need continuity). A Node/TS agent backend that executes model-generated code is the intended use;
 * here it drives Python on the default python:3.12-slim image.
 *
 * Safe by default: no network, no host mounts, seccomp on, resource caps enforced. Sandbox events
 * (timeout / blocked-escape / OOM-kill) come back as DATA on `result.fault`, never as an exception -
 * so running untrusted code doesn't force a try/catch for normal outcomes.
 *
 *     KERN_BIN=./target/release/kern node examples/embed-node.js
 *
 * Honest threat model: this is a KERNEL-boundary sandbox for YOUR OWN or SEMI-TRUSTED code. seccomp is
 * a denylist - good for agent/CI code, NOT a hard boundary against deliberately hostile multi-tenant
 * code (for that use a microVM / gVisor). See bindings/node/README.md.
 */
"use strict";
// `kern-sandbox` once you `npm install ./bindings/node`; the fallback lets this run straight from a
// repo checkout with no install step.
let kern;
try {
  kern = require("kern-sandbox");
} catch {
  kern = require("../bindings/node");
}

async function main() {
  // 1) One-shot: a throwaway box, structured result. Network is OFF; the code cannot reach the host.
  console.log("1) one-shot runCode (fresh box, network off):");
  const r1 = await kern.runCode("import sys, platform; print(platform.python_version()); print(sum(range(100)))");
  console.log(`   success=${r1.success}  exit=${r1.exitCode}  ${r1.durationMs} ms`);
  console.log("   stdout:", r1.stdout.trim().replace(/\n/g, " | "));

  // 2) A session: FILE state persists across steps (a workspace on disk), each step is a fresh box.
  console.log("\n2) a session - write a file in one step, read it in the next:");
  await kern.withSandbox({ memoryMb: 256, cpus: 0.5, timeoutS: 15 }, async (sbx) => {
    await sbx.writeFile("data.csv", "a,b\n1,2\n3,4\n");
    const r = await sbx.runCode(
      "print(sum(int(l.split(',')[0]) for l in open('data.csv').read().splitlines()[1:]))"
    );
    console.log(`   computed from the CSV the previous step wrote: ${r.stdout.trim()}  (success=${r.success})`);
  });

  // 3) Untrusted code that misbehaves is reported as a FAULT (data), not an exception.
  console.log("\n3) untrusted code that runs away - reported as a fault, not a crash:");
  await kern.withSandbox({ timeoutS: 2 }, async (sbx) => {
    const r = await sbx.runCode("while True: pass"); // infinite loop
    if (r.fault) console.log(`   fault.type=${JSON.stringify(r.fault.type)}  -> ${r.fault.message}`);
    console.log(`   success=${r.success}   (the binding killed the box at its deadline)`);
  });

  // 4) The isolation is real: without `network: true`, the box cannot open a socket to the outside.
  console.log("\n4) network is off by default - an outbound connection fails:");
  await kern.withSandbox({ timeoutS: 10 }, async (sbx) => {
    const r = await sbx.runCode(
      "import socket\n" +
      "try:\n" +
      "    socket.create_connection(('1.1.1.1', 53), timeout=3); print('REACHED (unexpected)')\n" +
      "except OSError as e:\n" +
      "    print('no route out of the box:', e.__class__.__name__)"
    );
    console.log("   ", r.stdout.trim());
  });

  console.log("\ndone - a fresh, isolated box per call; file-state on disk; faults as data.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
