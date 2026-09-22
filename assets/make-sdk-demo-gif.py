#!/usr/bin/env python3
"""Render the SDK's pitch as an animated GIF for the package README.

WHY THIS REPLACED A STILL, which is worth writing down because the still looked fine to whoever
made it. `make-sdk-faults-png.py`, removed in the same commit as this file was added, drew this same
transcript as one frame: four exchanges stacked, each answering with a bare tuple, at a size that
survived neither a phone nor a narrow window. The owner read it and could not tell what it showed,
which is the only test an image has to pass. A still has to fit everything at once; an animation can
show one thing at a time and make it big.

WHY THE PACING CHANGED (2026-09-22). The first cut held each answer for 26 frames at 20 fps, which
is 1.3 s, and the owner's verdict was that it goes by too fast. The answer is the only thing the
image exists to deliver, so it was the wrong thing to rush. Two changes:

  - **Per-frame durations instead of repeated frames.** GIF carries a delay per frame, so a three
    second pause is ONE frame with a 3000 ms delay, not sixty identical ones. The animation is now
    twice as long as before and has FEWER frames than before.
  - **Typing got quicker, the answer got slower.** Watching characters appear is charm, not
    information. Typing runs at three characters a frame; the answer holds for 3 s.

⚠️ EVERY LINE WAS CAPTURED BY RUNNING IT, on 2026-09-22, against `kern-sandbox` 0.2.34 and
`kern` 0.20.0:

    print(sum(range(100)))                     stdout '4950\\n'  fault None      exit 0
    while True: pass, timeout_s=3                              fault timeout   exit 137
    x = bytearray(400<<20), memory_mb=128                      fault oom       exit 137
    urlopen(...) with the network off                          fault None      exit 1
    os.remove('/root/.bashrc')                                 fault None      exit 1
                              -> OSError: [Errno 30] Read-only file system: '/root/.bashrc'

Nothing is typed from memory and nothing is an approximation of what the API "would" return.

The last two beats are the ones that carry an argument rather than a feature. The network beat is
the row a loop gets WRONG: the fault is None, so the sandbox did not stop anything, the code itself
raised. The remove beat is the answer to "what if the model hallucinates a destructive command":
`~` resolves to the container's own `/root`, and that is mounted read-only, so the delete does not
fail to matter, it fails outright.

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
PROMPT = (62, 183, 79)
META = (110, 140, 145)
FAULT = (245, 158, 66)  # the one word the image exists to deliver

# H is the tallest beat plus the closing line and nothing more: four rows (the network beat types
# three lines before its answer) end at 216, the closing line at 228. Dead space below the text
# makes the type look smaller than it is once the README scales the image to 860.
W, H = 900, 252
BAR_H = 36
FONT_SIZE = 22
X0 = 28
ROW0, ROW_H = 74, 40

# Milliseconds, not frames. See the pacing note in the docstring.
TYPE_MS = 40  # one frame of typing
TYPE_EVERY = 3  # characters revealed per typing frame
BEFORE_ANSWER_MS = 300  # the beat between the last keystroke and the reply
ANSWER_MS = 3000  # how long the answer stays up, which is the whole point
CLOSING_MS = 4200

# (typed lines, answer, the token in the answer to colour)
BEATS = [
    (
        [
            'r = kern.run_code("print(sum(range(100)))")',
            "r.stdout, r.fault",
        ],
        "('4950\\n', None)",
        None,
    ),
    (
        [
            'r = kern.run_code("while True: pass", timeout_s=3)',
            "r.fault.type, r.exit_code",
        ],
        "('timeout', 137)",
        "'timeout'",
    ),
    (
        [
            'r = kern.run_code("x = bytearray(400<<20)", memory_mb=128)',
            "r.fault.type, r.exit_code",
        ],
        "('oom', 137)",
        "'oom'",
    ),
    (
        [
            'src = "from urllib.request import urlopen"',
            "r = kern.run_code(src + \"; urlopen('https://pypi.org')\")",
            "r.fault, r.exit_code",
        ],
        "(None, 1)",
        "None",
    ),
    (
        [
            'r = kern.run_code("import os; os.remove(\'/root/.bashrc\')")',
            "r.stderr.splitlines()[-1]",
        ],
        "\"OSError: [Errno 30] Read-only file system: '/root/.bashrc'\"",
        "Read-only file system",
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


def draw_line(d: ImageDraw.ImageDraw, font, row: int, text: str, colour) -> None:
    cw = font.getlength("M")
    d.text((X0, row), ">>>", font=font, fill=ACCENT)
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


def render(font: ImageFont.FreeTypeFont) -> tuple[list[Image.Image], list[int]]:
    """Frames and their individual delays, in milliseconds."""
    frames: list[Image.Image] = []
    delays: list[int] = []
    cw = font.getlength("M")

    def frame(shown: list[str], answer: str | None, token, cursor: bool) -> Image.Image:
        im = base_frame(font)
        d = ImageDraw.Draw(im)
        for i, text in enumerate(shown):
            row = ROW0 + ROW_H * i
            draw_line(d, font, row, text, TEXT)
        if cursor and shown:
            row = ROW0 + ROW_H * (len(shown) - 1)
            cx = X0 + cw * (4 + len(shown[-1]))
            d.rectangle([cx, row + 2, cx + cw - 2, row + FONT_SIZE + 4], fill=ACCENT)
        if answer is not None:
            answer_line(d, font, ROW0 + ROW_H * len(shown), answer, token)
        return im

    for lines, answer, token in BEATS:
        for n, line in enumerate(lines):
            done = lines[:n]
            for i in range(1, len(line) + 1, TYPE_EVERY):
                frames.append(frame([*done, line[:i]], None, None, True))
                delays.append(TYPE_MS)
            frames.append(frame([*done, line], None, None, True))
            delays.append(TYPE_MS)
        frames.append(frame(lines, None, None, False))
        delays.append(BEFORE_ANSWER_MS)
        frames.append(frame(lines, answer, token, False))
        delays.append(ANSWER_MS)

    last = frames[-1].copy()
    d = ImageDraw.Draw(last)
    lines = BEATS[-1][0]
    d.text((X0, ROW0 + ROW_H * (len(lines) + 1) + 8), CLOSING, font=font, fill=META)
    frames.append(last)
    delays.append(CLOSING_MS)
    return frames, delays


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else "assets/kern-sandbox-demo.gif"
    font = load_font(FONT_SIZE)
    check_fits(font)
    frames, delays = render(font)
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
        f"{len(BEATS)} beats, {ANSWER_MS} ms on each answer"
    )


if __name__ == "__main__":
    main()
