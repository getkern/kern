#!/usr/bin/env python3
"""Draw the README's top picture: kern as a container and as a sandbox, as the site draws code.

WHY AN IMAGE. getkern.dev draws every code block as a window (a bar with three dots and the
language, colours per token), and GitHub renders a README with no stylesheet and no script, so on
GitHub the only way to show the same thing is a picture of it. A picture cannot be copied, so the
README keeps every command as a real code block right under it: this is what the page looks like,
the block below is what you paste.

WHY A GENERATOR. A picture of code is a claim nobody re-reads: when a command changes, the text
gets fixed and the pixels do not. The lines below are the source; run this after changing them.
SVG rather than PNG, so it is sharp at any zoom and its text is searchable in the file itself.

The palette is the demo GIF's (`kern-sandbox-demo.gif`): bar #141a21, body #080c13, dots
#c58038 #e2b241 #3ab593, label #6e8c91, the same values `scripts/build-guide.py` uses on the site.

    python3 assets/make-readme-windows.py      # writes assets/readme-windows.svg and readme-basics.svg
"""
import html
import pathlib

try:
    from pygments import lex
    from pygments.lexers import get_lexer_by_name
    from pygments.token import Comment, Keyword, Name, Number, String
except ImportError:
    lex = None

HERE = pathlib.Path(__file__).resolve().parent
TERMINAL = ("#3ab593", "M3 4.5 6.5 8 3 11.5M8.5 12H13")
CODE = ("#e2b241", "M5.5 4.5 2 8l3.5 3.5M10.5 4.5 14 8l-3.5 3.5")

# Each figure: its file, its font (size, advance per character) and its windows, side by side.
FIGURES = [
    ("readme-windows.svg", 13.5, 8.1, [  # the top: the two things kern is, before any scrolling
        ("Container", TERMINAL, "bash", [
            "kern box dev --image alpine -it -- sh",
            "kern compose up -d      # your compose.yaml",
            "kern ps",
        ]),
        ("Sandbox", CODE, "python", [
            "import kern_sandbox as kern",
            'r = kern.run_code("print(6 * 7)")',
            "print(r.stdout)   # 42",
        ]),
    ]),
    ("readme-basics.svg", 13.0, 7.8, [  # three basics, cut to the lines that carry the idea; the
        ("files.py", CODE, "python", [   # README prints each one in full, runnable, right under it
            "with kern.Sandbox() as sb:",
            '  sb.write_file("in.csv", data)',
            "  sb.run_code(job)",
            '  sb.read_file("out.txt")',
        ]),
        ("state.py", CODE, "python", [
            "with kern.Sandbox() as sb:",
            "  with sb.kernel() as k:",
            '    k.run_code("x = 40")',
            '    k.run_code("print(x + 2)")',
        ]),
        ("package.py", CODE, "python", [
            "sb = kern.Sandbox(",
            '  setup="pip install numpy")',
            "with sb:",
            '  sb.run_code("import numpy")',
        ]),
    ]),
]

WIDTH, LINE = 880, 21
BAR, PAD_X, PAD_Y, GAP = 34, 20, 16, 16
TEXT = "#d4d4d4"
COLOURS = {  # VS Code Dark+, as on the site
    "kw": "#569cd6", "import": "#c586c0", "str": "#ce9178", "comment": "#6a9955",
    "num": "#b5cea8", "func": "#dcdcaa", "ns": "#4ec9b0", "var": "#9cdcfe",
}
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace"


def colour(token) -> str:
    if lex is None:
        return TEXT
    if token in Comment:
        return COLOURS["comment"]
    if token in Keyword.Namespace:
        return COLOURS["import"]
    if token in Keyword:
        return COLOURS["kw"]
    if token in String:
        return COLOURS["str"]
    if token in Number:
        return COLOURS["num"]
    if token in Name.Namespace:
        return COLOURS["ns"]
    if token in Name.Builtin or token in Name.Function:
        return COLOURS["func"]
    if token in Name.Variable:
        return COLOURS["var"]
    return TEXT


def spans(line: str, lang: str) -> str:
    if lex is None:
        return html.escape(line)
    out = []
    for token, value in lex(line, get_lexer_by_name(lang)):
        value = value.rstrip("\n")
        if value:
            out.append(f'<tspan fill="{colour(token)}">{html.escape(value)}</tspan>')
    return "".join(out)


def window(x: int, w: int, h: int, title: str, icon: tuple, lang: str, lines: list) -> str:
    icon_colour, icon_path = icon
    parts = [
        f'<g transform="translate({x} 0)">',
        f'<rect x="0.5" y="0.5" width="{w - 1}" height="{h - 1}" rx="10" fill="#080c13" stroke="#1f2933"/>',
        f'<path d="M0.5 {BAR}V10.5a10 10 0 0 1 10-10H{w - 10.5}a10 10 0 0 1 10 10V{BAR}Z" fill="#141a21"/>',
        f'<line x1="0.5" y1="{BAR}" x2="{w - 0.5}" y2="{BAR}" stroke="#1f2933"/>',
    ]
    for i, dot in enumerate(("#c58038", "#e2b241", "#3ab593")):
        parts.append(f'<circle cx="{20 + 18 * i}" cy="{BAR / 2}" r="5.6" fill="{dot}"/>')
    parts.append(
        f'<path transform="translate(80 {BAR / 2 - 7.5}) scale(0.94)" d="{icon_path}" fill="none" '
        f'stroke="{icon_colour}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>'
    )
    parts.append(f'<text x="101" y="{BAR / 2 + 4.5}" fill="#c9d1d9" font-size="13.5" font-weight="600">{title}</text>')
    for n, line in enumerate(lines):
        base = BAR + PAD_Y + LINE * n + 15
        parts.append(f'<text x="{PAD_X}" y="{base}" xml:space="preserve">{spans(line, lang)}</text>')
    parts.append("</g>")
    return "\n".join(parts)


def main() -> None:
    for name, font, char, windows in FIGURES:
        w = (WIDTH - GAP * (len(windows) - 1)) // len(windows)
        height = BAR + 2 * PAD_Y + LINE * max(len(lines) for _, _, _, lines in windows)
        body = []
        for i, (title, icon, lang, lines) in enumerate(windows):
            longest = max(len(line) for line in lines)
            assert PAD_X * 2 + longest * char <= w, f"{name} {title}: a line is wider than the window"
            body.append(window(i * (w + GAP), w, height, title, icon, lang, lines))
        alt = " ".join(line for _, _, _, lines in windows for line in lines if line)
        (HERE / name).write_text(
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
            f'viewBox="0 0 {WIDTH} {height}" font-family="{MONO}" font-size="{font}" role="img">\n'
            f"<title>{html.escape(alt)}</title>\n" + "\n".join(body) + "\n</svg>\n",
            encoding="utf-8",
        )
        print(f"{name}: {WIDTH}x{height}")


if __name__ == "__main__":
    main()
