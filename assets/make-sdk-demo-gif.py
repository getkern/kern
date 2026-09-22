#!/usr/bin/env python3
"""Render the SDK's pitch as an animated GIF for the package README.

WHY THIS REPLACED A STILL, which is worth writing down because the still looked fine to whoever
made it. `make-sdk-faults-png.py`, removed in the same commit as this file was added, drew this
transcript as one frame: four exchanges stacked, each answering with a bare tuple, at a size that
survived neither a phone nor a narrow window. The owner read it and could not tell what it showed,
which is the only test an image has to pass.

WHY IT SCROLLS NOW (2026-09-22, third cut). The first two cuts cleared the screen between beats,
so each answer had exactly its hold to be read in and then it was gone forever. That is why both
were judged too fast: holding longer only treats the symptom, and it makes the animation
interminable. A terminal scrolls, so this one scrolls. An exchange stays on screen while the next
one types, which buys every line several extra seconds of reading time for free, and a reader who
missed a line can still see it. Typing slowed down too, because the typed line is text a reader
has to read and not just decoration.

⚠️ EVERY LINE WAS CAPTURED BY RUNNING IT, on 2026-09-22, against `kern-sandbox` 0.2.34 and
`kern` 0.20.0. The seven beats are every fault the README names that a cell can actually produce:

    print(sum(range(100)))                    stdout '4950\\n'  fault None            exit 0
    while True: pass, timeout_s=3                             fault timeout         exit 137
    x = bytearray(400<<20), memory_mb=128                     fault oom             exit 137
    urlopen(...) with the network off                         fault None            exit 1
    os.remove('/root/.bashrc')                                fault None            exit 1
                          -> OSError: [Errno 30] Read-only file system: '/root/.bashrc'
    print(1) on alpine:3.19, which has no python3             fault exec_failed     exit 127
    print(1) on an image that does not exist                  fault startup_failed  exit 1

Nothing is typed from memory and nothing is an approximation of what the API "would" return.

⛔ `escape_blocked` and `killed` are deliberately absent: a cell cannot manufacture either, because
the pid 1 of a pid namespace does not take a fatal signal from inside it. Showing them would mean
staging them.

The beats carry an argument in this order: it works, the sandbox stops a hang, the sandbox stops a
leak, THE SANDBOX STOPPED NOTHING AND THE CODE RAISED (the row an agent loop gets wrong), a
hallucinated delete hits a read-only root, and the last two are the boring operational ones that
still come back as a value rather than as a stack trace.

Usage:  python3 assets/make-sdk-demo-gif.py [out.gif]
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# Palette, identical to the other generators so the assets are visibly the same product.
BG = (8, 12, 19)
BAR = (21, 26, 34)
DOTS = [(248, 79, 73), (226, 178, 65), (62, 183, 79)]
TEXT = (195, 241, 244)
ACCENT = (60, 200, 212)
META = (110, 140, 145)
FAULT = (245, 158, 66)  # the one word the image exists to deliver

W = 900
BAR_H = 36
FONT_SIZE = 22
X0 = 28
ROW0, ROW_H = 72, 38
VISIBLE_ROWS = 9
H = ROW0 + ROW_H * VISIBLE_ROWS + 18

# Milliseconds. The typing pace is the one the owner rejected twice, so it is deliberate: a typed
# line is text a reader reads, not an effect.
TYPE_MS = 62
TYPE_EVERY = 2  # characters per typing frame
BEFORE_ANSWER_MS = 420  # the beat between the last keystroke and the reply
ANSWER_MS = 2100  # shorter than the previous cut because the line does NOT disappear afterwards
CLOSING_MS = 4500

# (typed lines, answer, the token in the answer to colour)
BEATS = [
    (
        ['r = kern.run_code("print(sum(range(100)))")', "r.stdout, r.fault"],
        "('4950\\n', None)",
        None,
    ),
    (
        ['r = kern.run_code("while True: pass", timeout_s=3)', "r.fault.type, r.exit_code"],
        "('timeout', 137)",
        "'timeout'",
    ),
    (
        ['r = kern.run_code("x = bytearray(400<<20)", memory_mb=128)', "r.fault.type, r.exit_code"],
        "('oom', 137)",
        "'oom'",
    ),
    (
        [
            'src = "from urllib.request import urlopen"',
            "r = kern.run_code(src + \"; urlopen('https://pypi.org')\")",
            "r.fault, r.exit_code",
        ],
        "(None, 1)   # the code raised. the sandbox stopped nothing",
        "None",
    ),
    (
        ['r = kern.run_code("import os; os.remove(\'/root/.bashrc\')")', "r.stderr.splitlines()[-1]"],
        "\"OSError: [Errno 30] Read-only file system: '/root/.bashrc'\"",
        "Read-only file system",
    ),
    (
        ['r = kern.run_code("print(1)", image="alpine:3.19")', "r.fault.type, r.exit_code"],
        "('exec_failed', 127)   # alpine ships no python3",
        "'exec_failed'",
    ),
    (
        ['r = kern.run_code("print(1)", image="nosuchimage:1")', "r.fault.type, r.exit_code"],
        "('startup_failed', 1)",
        "'startup_failed'",
    ),
]

CLOSING = "a box per call. a hundred cost 1.4 s, and leave nothing."


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


def check_fits(font: ImageFont.FreeTypeFont) -> None:
    """Refuse to render a line that runs off the right edge.

    This exists because the tool-call chart shipped for weeks with its footer cut off at the frame
    edge, and nothing caught it because nobody measured a string against the canvas. A drawn line
    that overflows is invisible in exactly the way a truncated one is: it looks fine unless you go
    looking. So it is an assertion, not a comment."""
    cw = font.getlength("M")
    left = X0 + cw * 4  # the four columns the ">>> " prompt occupies
    for lines, answer, _token in BEATS:
        for text in [*lines, answer]:
            end = left + font.getlength(text)
            if end > W - 8:
                raise SystemExit(
                    f"make-sdk-demo-gif: line runs off the {W}px frame at {end:.0f}px, "
                    f"shorten it or widen W:\n    {text}"
                )
    if X0 + font.getlength(CLOSING) > W - 8:
        raise SystemExit("make-sdk-demo-gif: the closing line runs off the frame")


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


def draw_entry(d: ImageDraw.ImageDraw, font, row: int, kind: str, text: str, token) -> None:
    """One transcript line: an input carries the prompt, an answer carries the coloured token."""
    cw = font.getlength("M")
    x = X0 + cw * 4
    if kind == "in":
        d.text((X0, row), ">>>", font=font, fill=ACCENT)
        d.text((x, row), text, font=font, fill=TEXT)
        return
    if not token or token not in text:
        d.text((x, row), text, font=font, fill=TEXT)
        return
    head, _, tail = text.partition(token)
    d.text((x, row), head, font=font, fill=TEXT)
    x += font.getlength(head)
    d.text((x, row), token, font=font, fill=FAULT)
    x += font.getlength(token)
    d.text((x, row), tail, font=font, fill=TEXT)


def render(font: ImageFont.FreeTypeFont) -> tuple[list[Image.Image], list[int]]:
    """Frames and their individual delays, in milliseconds.

    The transcript is a flat list that only ever grows; a frame draws its last VISIBLE_ROWS
    entries, which is what makes the window scroll instead of clearing."""
    frames: list[Image.Image] = []
    delays: list[int] = []
    cw = font.getlength("M")
    transcript: list[tuple[str, str, str | None]] = []

    def frame(cursor: bool, closing: bool = False) -> Image.Image:
        im = base_frame(font)
        d = ImageDraw.Draw(im)
        # The closing line occupies a row, so it scrolls one more exchange off rather than being
        # drawn over the last answer, which is what the first scrolling cut did.
        rows = VISIBLE_ROWS - 1 if closing else VISIBLE_ROWS
        shown = transcript[-rows:]
        for i, (kind, text, token) in enumerate(shown):
            draw_entry(d, font, ROW0 + ROW_H * i, kind, text, token)
        if cursor and shown:
            row = ROW0 + ROW_H * (len(shown) - 1)
            cx = X0 + cw * (4 + len(shown[-1][1]))
            d.rectangle([cx, row + 2, cx + cw - 2, row + FONT_SIZE + 2], fill=ACCENT)
        if closing:
            d.text((X0, ROW0 + ROW_H * len(shown) + 6), CLOSING, font=font, fill=META)
        return im

    for lines, answer, token in BEATS:
        for line in lines:
            transcript.append(("in", "", None))
            for i in range(TYPE_EVERY, len(line) + TYPE_EVERY, TYPE_EVERY):
                transcript[-1] = ("in", line[:i], None)
                frames.append(frame(True))
                delays.append(TYPE_MS)
            transcript[-1] = ("in", line, None)
        frames.append(frame(False))
        delays.append(BEFORE_ANSWER_MS)
        transcript.append(("out", answer, token))
        frames.append(frame(False))
        delays.append(ANSWER_MS)

    frames.append(frame(False, closing=True))
    delays.append(CLOSING_MS)
    return frames, delays


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "assets/kern-sandbox-demo.gif"
    font = load_font(FONT_SIZE)
    check_fits(font)
    frames, delays = render(font)
    # ONE palette for every frame, derived from the last (it carries the closing line and a
    # coloured token, so it has every colour the animation uses). Quantising each frame on its own
    # gives each a local colour table AND defeats the inter-frame diffing, which took the first
    # scrolling cut to 1.6 MB; sharing the palette is most of the way back down.
    pal = frames[-1].convert("P", palette=Image.ADAPTIVE, colors=64)
    frames = [f.quantize(palette=pal, dither=Image.NONE) for f in frames]
    frames[0].save(
        out,
        save_all=True,
        append_images=frames[1:],
        duration=delays,
        loop=0,
        optimize=True,
    )
    total = sum(delays) / 1000
    print(
        f"{out}: {len(frames)} frames, {total:.1f}s, {Path(out).stat().st_size // 1024} KB, "
        f"{len(BEATS)} beats, {TYPE_MS / TYPE_EVERY:.0f} ms per character, {ANSWER_MS} ms per answer"
    )


if __name__ == "__main__":
    main()
