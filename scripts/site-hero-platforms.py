#!/usr/bin/env python3
"""Fail when getkern.dev's hero paragraph omits a platform the same page's metadata claims.

The site is deployed by hand and is not covered by `stale-numbers.py`, which reads only the repo's
`.md`. macOS was added to the platform list, the JSON-LD and the badge, and stayed out of the one
paragraph everybody reads, for a day. It was the third time in two days that a platform reached
everywhere except the front: an installer branch, a table in docs/INSTALL.md, and the hero. The
pattern is the same each time, that you add a platform where you are working rather than where a
reader looks first.

This compares the PAGE TO ITSELF rather than to the docs, deliberately. The JSON-LD
`operatingSystem` field is what search engines are told, the hero is what a person is told, and they
have no business disagreeing. Comparing against the repo instead would need a source of truth for
platform names that does not exist and would drift on its own.

Usage: curl the page to a file, then `python3 scripts/site-hero-platforms.py <file>`.
Exit 0 when they agree, 1 when the hero is missing one, and 1 with a different message when the
page's shape changed enough that the check cannot run, which is not a pass.
"""
import re, sys, pathlib

html = pathlib.Path(sys.argv[1]).read_text(errors="replace")

m = re.search(r'"operatingSystem":\s*"([^"]+)"', html)
if not m:
    sys.exit("no operatingSystem in the page's JSON-LD: the check cannot run")
declared = m.group(1)

h = re.search(r"Runs on(.{0,400}?)</p>", html, re.S)
if not h:
    sys.exit("no hero paragraph starting 'Runs on': the check cannot run")
hero = re.sub(r"<[^>]+>|&nbsp;", " ", h.group(1))

missing = [p for p in ("Linux", "Windows", "macOS", "ARM") if p in declared and p not in hero]
print("declared:", declared[:90])
print("hero    :", " ".join(hero.split())[:110])
if missing:
    sys.exit(f"the hero omits platforms the page's own metadata claims: {missing}")
print("hero and metadata agree")
