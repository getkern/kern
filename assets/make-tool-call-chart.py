#!/usr/bin/env python3
"""Render the one-tool-call comparison as a PNG for the package README.

THE JOB IS FIXED, and that is the only thing that makes the bars comparable: hand `print(1)` to an
isolated environment running `python:3.12-slim` and get its stdout back. Wall clock around the whole
call, because that is what the caller waits for. Same machine, same afternoon, p50 after a discarded
warm-up.

MEASURED 2026-09-21 on an Intel i7-14700KF, Linux 7.0.0, rootless. Every arm is a command a reader
can run:

    kern-sandbox, prewarm=8   0.70 ms   8 calls, all served by the pool (min 0.64, max 1.46)
    kern-sandbox, default    14.50 ms   n=15 (min 11.4, max 23.5)
    llm-sandbox              77.0  ms   n=10, session kept alive, docker backend (60.7 to 86.1)
    podman run --rm         286.0  ms   n=15
    docker run --rm         292.8  ms   n=15
    sbx exec                421    ms   7 calls into an ALREADY RUNNING sandbox (393 to 506)

THREE CATEGORIES, AND THE LABELS SAY WHICH, because the question "are docker and podman sandboxes?"
is the right one to ask of this chart. They are ENGINES: one `run` per tool-call is the
do-it-yourself baseline a reader is probably on today, not a product competing with this one. The
sandbox PRODUCTS here are `sbx` and `llm-sandbox`, and `llm-sandbox` drives docker underneath, which
is why keeping its session alive lands it between the engines and a box.

⚠️ THE sbx BAR IS THE ARM MOST FAVOURABLE TO IT, and that is deliberate. Docker Sandboxes is built
around a session: `sbx create` cost **5067 ms** here and is paid once, so charging it to every call
would be a comparison nobody would recognise. The bar is steady-state, and the create cost is named
in the footer rather than hidden.

⚠️ THE PREWARM BAR HAS A CONDITION, stated in the label: it is what a call gets while the pool keeps
up. A loop that outruns the refill falls back to the default bar, and the fall is a cliff. Eight
calls against a pool of eight is exactly the regime the bar claims, not a best-of.

Usage:  python3 assets/make-tool-call-chart.py [out.png]
"""

import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

BG = "#080c13"
TEXT = "#c3f1f4"
DIM = "#6e8c91"
OURS = "#3cc8d4"
THEIRS = "#3a4652"

# (label, p50 ms, is_ours)
BARS = [
    ("kern-sandbox, prewarm pool keeping up", 0.70, True),
    ("kern-sandbox", 14.5, True),
    ("llm-sandbox, session kept alive", 77.0, False),
    ("podman run --rm, one per call", 286.0, False),
    ("docker run --rm, one per call", 292.8, False),
    ("sbx exec, sandbox already running", 421.0, False),
]

FOOT = ("one tool-call: print(1) in python:3.12-slim, p50, wall clock around the whole call. "
        "Intel i7-14700KF, Linux 7.0.0, rootless, 2026-09-21.\n"
        "docker and podman are ENGINES, not sandbox products: one run per call is the "
        "do-it-yourself baseline. llm-sandbox drives docker underneath.\n"
        "The two session-based arms keep their session alive, which is the arm most favourable to "
        "them: sbx create is paid once and cost 5067 ms here.")


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "assets/kern-sandbox-vs.png"
    labels = [b[0] for b in BARS][::-1]
    values = [b[1] for b in BARS][::-1]
    colours = [OURS if b[2] else THEIRS for b in BARS][::-1]

    fig, ax = plt.subplots(figsize=(9.2, 4.0), dpi=150)
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.barh(labels, values, color=colours, height=0.62)
    ax.set_xscale("log")
    ax.set_xlim(0.3, 1400)
    ax.set_xlabel("milliseconds per call, log scale", color=DIM, fontsize=9)
    ax.tick_params(colors=DIM, labelsize=9)
    for s in ax.spines.values():
        s.set_color("#1d2731")
    ax.grid(axis="x", color="#141c25", zorder=0)
    ax.set_axisbelow(True)
    for y, (v, c) in enumerate(zip(values, colours)):
        ax.text(v * 1.15, y, f"{v:g} ms", va="center", color=TEXT if c == OURS else DIM,
                fontsize=10, fontweight="bold" if c == OURS else "normal")
    for lbl in ax.get_yticklabels():
        lbl.set_color(TEXT if "kern" in lbl.get_text() else DIM)
    # The footer sits INSIDE the canvas. Placed below it with `bbox_inches="tight"`, matplotlib grew
    # the figure to contain it and left a band of dead background between the axis and the text.
    fig.subplots_adjust(left=0.30, right=0.98, top=0.97, bottom=0.33)
    fig.text(0.012, 0.145, FOOT, color=DIM, fontsize=7.6, va="top")
    fig.savefig(out, facecolor=BG)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
