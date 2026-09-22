#!/usr/bin/env python3
"""Render the SDK's pitch as an animated GIF for the package README.

WHY THIS REPLACED A STILL, which is worth writing down because the still looked fine to whoever
made it. `make-sdk-faults-png.py`, removed in the same commit as this file was added, drew this same
transcript as one frame: four exchanges stacked, each answering with a bare tuple, at a size that
survived neither a phone nor a narrow window. The owner read it and could not tell what it showed,
which is the only test an image has to pass. A still has to fit everything at once; an animation can
show one thing at a time and make it big.

So: three beats, three lines each, the screen cleared between them, at a font size that is legible
where a table would be. The fault value is the only coloured token on its line, because that is the
word the image exists to deliver.

⚠️ EVERY LINE WAS CAPTURED BY RUNNING IT, on 2026-09-22, against the PUBLISHED pair: `kern-sandbox`
0.2.33 from PyPI and `kern` 0.20.0 from the release tarball, installed into an empty HOME:

    print(sum(range(100)))                        fault None       exit 0
    while True: pass, timeout_s=3                 fault timeout    exit 137
    x = bytearray(400<<20), memory_mb=128         fault oom        exit 137

Nothing is typed from memory and nothing is an approximation of what the API "would" return.

Usage:  python3 assets/make-sdk-demo-gif.py [out.gif]
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# Palette, identical to the other two generators so the assets are visibly the same product.
BG = (8, 12, 19)
BAR = (21, 26, 34)
DOTS = [(248, 79, 73), (226, 178, 65), (62, 183, 79)]
TEXT = (195, 241, 244)
ACCENT = (60, 200, 212)
PROMPT = (62, 183, 79)
META = (110, 140, 145)
FAULT = (245, 158, 66)  # the one word the image exists to deliver

W, H = 900, 300
BAR_H = 36
FONT_SIZE = 22
X0 = 28
ROW0, ROW_H = 74, 40

FPS = 20
TYPE_EVERY = 2
HOLD_AFTER_ANSWER = 26
HOLD_END = 44

# (typed line, typed line, answer, the token in the answer to colour)
BEATS = [
    (
        'r = kern.run_code("print(sum(range(100)))")',
        "r.stdout, r.fault",
        "('4950\\n', None)",
        None,
    ),
    (
        'r = kern.run_code("while True: pass", timeout_s=3)',
        "r.fault.type, r.exit_code",
        "('timeout', 137)",
        "'timeout'",
    ),
    (
        'r = kern.run_code("x = bytearray(400<<20)", memory_mb=128)',
        "r.fault.type, r.exit_code",
        "('oom', 137)",
        "'oom'",
    ),
]

CLOSING = "one box per call. no network, caps, a deadline. then gone."


def load_font(size: int) -> ImageFont.FreeTypeFont:
    """A monospace face, or the bundled bitmap fallback so this never hard-fails on a host without
    fonts (the frame is uglier, the transcript is still right)."""
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ):
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def base_frame(font: ImageFont.FreeTypeFont) -> Image.Image:
    """The chrome: window bar, three dots, and the title that says which interpreter this is."""
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, W, BAR_H], fill=BAR)
    for i, colour in enumerate(DOTS):
        x = 26 + i * 20
        d.ellipse([x - 5, 13, x + 5, 23], fill=colour)
    d.text((110, 9), "python3", font=font, fill=META)
    return im


def draw_line(d: ImageDraw.ImageDraw, font, row: int, prompt: str, text: str, colour) -> None:
    cw = font.getlength("M")
    d.text((X0, row), prompt, font=font, fill=ACCENT if prompt == ">>>" else META)
    d.text((X0 + cw * 4, row), text, font=font, fill=colour)


def answer_line(d: ImageDraw.ImageDraw, font, row: int, answer: str, token: str | None) -> None:
    """The answer, with one token coloured. Drawn in three spans rather than one so the colour
    lands on the word and not on the punctuation around it."""
    cw = font.getlength("M")
    x = X0 + cw * 4
    if not token or token not in answer:
        d.text((x, row), answer, font=font, fill=TEXT)
        return
    head, _, tail = answer.partition(token)
    d.text((x, row), head, font=font, fill=TEXT)
    x += font.getlength(head)
    d.text((x, row), token, font=font, fill=FAULT)
    x += font.getlength(token)
    d.text((x, row), tail, font=font, fill=TEXT)


def render(font: ImageFont.FreeTypeFont) -> list[Image.Image]:
    frames: list[Image.Image] = []
    cw = font.getlength("M")

    def frame(call: str, query: str, answer: str, token, cursor_on: str | None) -> Image.Image:
        im = base_frame(font)
        d = ImageDraw.Draw(im)
        if call is not None:
            draw_line(d, font, ROW0, ">>>", call, TEXT)
            if cursor_on == "call":
                cx = X0 + cw * (4 + len(call))
                d.rectangle([cx, ROW0 + 2, cx + cw - 2, ROW0 + FONT_SIZE + 4], fill=ACCENT)
        if query is not None:
            draw_line(d, font, ROW0 + ROW_H, ">>>", query, TEXT)
            if cursor_on == "query":
                cx = X0 + cw * (4 + len(query))
                d.rectangle(
                    [cx, ROW0 + ROW_H + 2, cx + cw - 2, ROW0 + ROW_H + FONT_SIZE + 4], fill=ACCENT
                )
        if answer is not None:
            answer_line(d, font, ROW0 + ROW_H * 2, answer, token)
        return im

    for call, query, answer, token in BEATS:
        for i in range(1, len(call) + 1, TYPE_EVERY):
            frames.append(frame(call[:i], None, None, None, "call"))
        for i in range(1, len(query) + 1, TYPE_EVERY):
            frames.append(frame(call, query[:i], None, None, "query"))
        held = frame(call, query, answer, token, None)
        frames.extend([held] * HOLD_AFTER_ANSWER)

    last = frames[-1].copy()
    d = ImageDraw.Draw(last)
    d.text((X0, ROW0 + ROW_H * 3 + 8), CLOSING, font=font, fill=META)
    frames.extend([last] * HOLD_END)
    return frames


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "assets/kern-sandbox-demo.gif"
    font = load_font(FONT_SIZE)
    frames = render(font)
    frames[0].save(
        out,
        save_all=True,
        append_images=frames[1:],
        duration=int(1000 / FPS),
        loop=0,
        optimize=True,
    )
    total = len(frames) / FPS
    print(f"{out}: {len(frames)} frames, {total:.1f}s, {Path(out).stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
