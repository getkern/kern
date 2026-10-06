"use strict";
// The test double for the `kern` binary, and how the suites find the real one: shared, so the two test
// files cannot drift into two definitions of "kern is here". The double IMPERSONATES kern's identity
// contract (the binding refuses a binary that does not) and otherwise exits 0, which is all the unit
// tests depend on: they assert the argv the binding BUILDS.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const FAKE_KERN = (() => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `kern-fake-${process.pid}-`));
  const p = path.join(d, "kern");
  fs.writeFileSync(p, '#!/bin/sh\ncase "$1" in\n  --version) echo "kern v0.0.0-test-double" ; exit 0 ;;\nesac\nexit 0\n');
  fs.chmodSync(p, 0o755);
  return p;
})();

/** The real kern: `$KERN_BIN` when it is set and not the double, else the first `kern` on `PATH`, else
 * null. */
function kernBin() {
  const k = process.env.KERN_BIN;
  if (k && k !== FAKE_KERN) return k;
  for (const d of (process.env.PATH || "").split(path.delimiter)) {
    const c = path.join(d, "kern");
    try {
      fs.accessSync(c, fs.constants.X_OK);
      return c;
    } catch {}
  }
  return null;
}

module.exports = { FAKE_KERN, kernBin };
