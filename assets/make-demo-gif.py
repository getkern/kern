#!/usr/bin/env python3
"""Render assets/kern-demo.gif, the terminal demo on the README's front page.

This script exists because the asset it replaces had its numbers baked into pixels with no source
next to them. When the binary grew and the image path got its uid-range map, the GIF kept claiming
~2 ms and 1.6 MB, and the README three lines below it said ~3.7 ms and ~1.8 MB. Nobody had lied:
there was simply nothing to edit when the facts moved.

Every claim the frame makes is a constant at the top of this file, so changing a number is a diff
rather than a re-recording.

That is necessary and it was not sufficient. On 2026-08-01 the constant below read `~3.3 ms` while
the COMMITTED GIF still showed `~3.6`: someone had edited the source and never re-run the script, so
the file that exists to keep the picture honest had itself gone stale. **Editing a constant here is
half the job; regenerate and commit the .gif in the same change.** Keep them measured:

    kern box app --image alpine -- true      # the image path, uid-range map included
    ls -l target/x86_64-unknown-linux-musl/release/kern

Usage:  python3 assets/make-demo-gif.py [-o assets/kern-demo.gif]
Needs:  Pillow.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# --- the claims, all measured ----------------------------------------------------------------
# `--image` costs more than a prepared rootfs (~2 ms) because kern maps a uid RANGE for it, which
# is what lets an official image drop privilege in its entrypoint. The command shown here is the
# image one, so the number shown here has to be the image one.
KERN_MS = "3.5 ms"
DOCKER_MS = "297 ms"
HOST = "Intel i7-14700KF, Linux 7.0"

COMMAND = 'kern box app --image alpine -- echo "hello from a real container"'
OUTPUT = "hello from a real container"

# --- palette, sampled from the asset this replaces ---------------------------------------------
BG = (8, 12, 19)
BAR = (21, 26, 34)
DOTS = [(248, 79, 73), (226, 178, 65), (62, 183, 79)]
TEXT = (195, 241, 244)
ACCENT = (60, 200, 212)
PROMPT = (62, 183, 79)
META = (110, 140, 145)
NOTE = (80, 96, 92)

W, H = 860, 280
BAR_H = 36
FONT_SIZE = 19
X0 = 30
ROWS = {"cmd": 62, "out": 104, "stat": 150, "meta": 182, "note": 228}

# --- timing, in frames at 20 fps ---------------------------------------------------------------
FPS = 20
TYPE_EVERY = 1  # frames per typed character
HOLD_AFTER_TYPE = 6
HOLD_AFTER_OUTPUT = 8
HOLD_END = 40


def load_font(size: int) -> ImageFont.FreeTypeFont:
    """A monospace face, or the bundled bitmap fallback so the script never hard-fails on a host
    without fonts (the frame is uglier, the numbers are still right)."""
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ):
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def base_frame(font: ImageFont.FreeTypeFont) -> Image.Image:
    """The chrome: window bar and three dots. Everything else is drawn on top per frame."""
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, W, BAR_H], fill=BAR)
    for i, colour in enumerate(DOTS):
        x = 26 + i * 20
        d.ellipse([x - 5, 13, x + 5, 23], fill=colour)
    return im


def render(font: ImageFont.FreeTypeFont) -> list[Image.Image]:
    cw = font.getbbox("M")[2] - font.getbbox("M")[0]  # monospace: one advance is enough
    frames: list[Image.Image] = []

    def frame(typed: int, show_output: bool, show_stats: bool, cursor: bool) -> Image.Image:
        im = base_frame(font)
        d = ImageDraw.Draw(im)
        d.text((X0, ROWS["cmd"]), "$", font=font, fill=PROMPT)
        shown = COMMAND[:typed]
        d.text((X0 + int(cw * 2), ROWS["cmd"]), shown, font=font, fill=TEXT)
        if cursor:
            cx = X0 + int(cw * (2 + len(shown)))
            d.rectangle([cx, ROWS["cmd"] + 2, cx + cw - 2, ROWS["cmd"] + FONT_SIZE + 4], fill=ACCENT)
        if show_output:
            d.text((X0 + int(cw * 2), ROWS["out"]), OUTPUT, font=font, fill=TEXT)
        if show_stats:
            left = f"kern started in {KERN_MS}"
            d.text((X0, ROWS["stat"]), left, font=font, fill=ACCENT)
            d.text(
                (X0 + int(cw * (len(left) + 6)), ROWS["stat"]),
                f"docker run: {DOCKER_MS}",
                font=font,
                fill=TEXT,
            )
            d.text(
                (X0, ROWS["meta"]),
                "real OCI image  .  rootless  .  static binary  .  no daemon",
                font=font,
                fill=META,
            )
            d.text(
                (X0, ROWS["note"]),
                f"* {HOST} . your hardware differs . measure your own",
                font=load_font(FONT_SIZE - 3),
                fill=NOTE,
            )
        return im

    # type the command, cursor blinking as it goes
    for i in range(1, len(COMMAND) + 1):
        for _ in range(TYPE_EVERY):
            frames.append(frame(i, False, False, cursor=(i // 4) % 2 == 0))
    for _ in range(HOLD_AFTER_TYPE):
        frames.append(frame(len(COMMAND), False, False, cursor=True))
    for _ in range(HOLD_AFTER_OUTPUT):
        frames.append(frame(len(COMMAND), True, False, cursor=False))
    for _ in range(HOLD_END):
        frames.append(frame(len(COMMAND), True, True, cursor=False))
    return frames


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", default="assets/kern-demo.gif")
    args = ap.parse_args()

    font = load_font(FONT_SIZE)
    frames = render(font)
    # Quantise to one shared adaptive palette: a per-frame palette triples the file for a demo whose
    # colours never change.
    pal = frames[-1].convert("P", palette=Image.ADAPTIVE, colors=64)
    frames = [f.quantize(palette=pal, dither=Image.NONE) for f in frames]
    frames[0].save(
        args.out,
        save_all=True,
        append_images=frames[1:],
        duration=int(1000 / FPS),
        loop=0,
        optimize=True,
    )
    size = Path(args.out).stat().st_size
    print(f"{args.out}: {len(frames)} frames, {size / 1024:.0f} KB")


if __name__ == "__main__":
    main()
