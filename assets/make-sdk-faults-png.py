#!/usr/bin/env python3
"""Render the SDK's verdict transcript as a PNG for the package README.

WHY A SECOND IMAGE GENERATOR. `make-demo-gif.py` draws ONE command and one output line, with the
rows at fixed pixel heights, because that is all the front page needs. The SDK's pitch is not one
command, it is that four different endings arrive as four different values on the result, so the
frame has to hold a session. Rather than bending the other generator into a multi-line renderer with
two callers and one shape, this one is its own file and owns its own layout.

⚠️ EVERY LINE OF THE TRANSCRIPT BELOW WAS CAPTURED BY RUNNING IT, on 2026-09-21, against the
PUBLISHED pair: `kern-sandbox` 0.2.31 from PyPI and the `kern` binary from the v0.10.0 release
tarball. Nothing here is typed from memory, and nothing is an approximation of what the API "would"
return:

    ordinary      stdout '4950\n'   exit 0    success True    fault None
    timeout       exit 137          fault timeout
    oom           exit 137          fault oom
    network off   exit 1            fault None   urllib.error.URLError

The last row is the one worth the space: the sandbox did nothing, the CODE failed, so `fault` is
None. An agent that branches on `fault` must not treat that as the sandbox stopping it, and a frame
that showed only the first three would teach the opposite.

Usage:  python3 assets/make-sdk-faults-png.py [out.png]
"""

from __future__ import annotations

import sys

from PIL import Image, ImageDraw, ImageFont

# Palette, identical to make-demo-gif.py so the two images are visibly the same product.
BG = (8, 12, 19)
BAR = (21, 26, 34)
DOTS = [(248, 79, 73), (226, 178, 65), (62, 183, 79)]
TEXT = (195, 241, 244)
ACCENT = (60, 200, 212)
PROMPT = (62, 183, 79)
META = (110, 140, 145)
FAULT = (226, 178, 65)

W = 980
BAR_H = 36
FONT_SIZE = 18
X0 = 26
LINE_H = 27
TOP = BAR_H + 20

# (kind, text). `in` is a typed line, `out` is what the REPL answered, `note` is a dim aside.
TRANSCRIPT: list[tuple[str, str]] = [
    ("in", 'r = kern.run_code("print(sum(range(100)))")'),
    ("in", "r.stdout, r.exit_code, r.fault"),
    ("out", "('4950\\n', 0, None)"),
    ("gap", ""),
    ("in", 'r = kern.run_code("while True: pass", timeout_s=3)'),
    ("in", "r.fault.type, r.exit_code"),
    ("fault", "('timeout', 137)"),
    ("gap", ""),
    ("in", 'r = kern.run_code("x = bytearray(400*1024*1024)", memory_mb=128)'),
    ("in", "r.fault.type, r.exit_code"),
    ("fault", "('oom', 137)"),
    ("gap", ""),
    ("in", 'r = kern.run_code("import urllib.request as u; u.urlopen(\'https://pypi.org\')")'),
    ("in", "r.fault, r.exit_code"),
    ("out", "(None, 1)"),
    ("note", "the network was off, so the CODE raised. The sandbox did nothing, so fault is None."),
]

FOOTER = "each call: its own box, no network, caps and a deadline from outside, destroyed on return"


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "assets/kern-sandbox-faults.png"
    font = load_font(FONT_SIZE)
    small = load_font(FONT_SIZE - 3)
    # A `gap` draws nothing and advances half a line, so counting every entry as a full line left a
    # band of dead pixels above the footer.
    height = TOP + sum(LINE_H // 2 if k == "gap" else LINE_H for k, _ in TRANSCRIPT) + 42

    im = Image.new("RGB", (W, height), BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, W, BAR_H], fill=BAR)
    for i, colour in enumerate(DOTS):
        cx = 22 + i * 22
        d.ellipse([cx - 6, BAR_H // 2 - 6, cx + 6, BAR_H // 2 + 6], fill=colour)
    d.text((110, BAR_H // 2 - 9), "python3", font=small, fill=META)

    cw = font.getbbox("M")[2] - font.getbbox("M")[0]
    y = TOP
    for kind, text in TRANSCRIPT:
        if kind == "gap":
            y += LINE_H // 2
            continue
        if kind == "in":
            d.text((X0, y), ">>>", font=font, fill=PROMPT)
            d.text((X0 + int(cw * 4), y), text, font=font, fill=TEXT)
        elif kind == "note":
            d.text((X0 + int(cw * 4), y), text, font=small, fill=META)
        else:
            d.text((X0 + int(cw * 4), y), text, font=font,
                   fill=FAULT if kind == "fault" else ACCENT)
        y += LINE_H

    d.text((X0, height - 32), FOOTER, font=small, fill=META)
    im.save(out)
    print(f"wrote {out} ({W}x{height})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
