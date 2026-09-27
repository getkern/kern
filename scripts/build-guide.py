#!/usr/bin/env python3
"""Render the `docs/` markdown into standalone HTML pages for getkern.dev.

WHY THIS EXISTS. Everything kern documents lives in this repository, and the site served exactly one
indexable page: `getkern.dev/docs` is a redirect to GitHub, so every search that reaches the project
lands on someone else's domain. Measured on 2026-09-09: the sitemap contained one URL.

WHAT IT IS NOT. Not a static site generator and not a theme. One file, no dependencies beyond
`python-markdown`, and the output is deliberately plain: the page's own stylesheet inlined, no
scripts, so it satisfies the site's Content-Security-Policy without an exception.

The pages go under `/guide/` rather than `/docs/`, because a Cloudflare rule redirects every
`/docs/*` to GitHub and it cannot be removed from the server side. If that rule is ever dropped,
change BASE below and regenerate; nothing else assumes the path.

Usage:
    python3 scripts/build-guide.py <out-dir> [analytics-token]
"""

import hashlib
import html
import pathlib
import re
import sys
import urllib.request

import markdown

BASE = "/guide"
SITE = "https://getkern.dev"
REPO = "https://github.com/getkern/kern"
ROOT = pathlib.Path(__file__).resolve().parent.parent

# GitHub's mark (Octicons `mark-github`, 16px), in `currentColor` so it follows the theme. The home's
# nav carries the same markup, because the two headers are meant to be identical.
GH_MARK = (
    '<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" '
    'd="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 '
    "0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 "
    "0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 "
    "1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61"
    ".55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 "
    '0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"></path></svg>'
)

# ONE SOURCE FOR THE SANDBOX PAGE, and it is the package README. Until 2026-09-23 the site rendered
# `docs/SANDBOX.md`, a condensed second copy of the same page, and the two had already drifted: the
# `rm -rf` correction and the fault table had to be made twice, and the table still stood at four rows
# on one and six on the other. A page that is rendered from the README cannot disagree with it.
SOURCE = {"SANDBOX.md": "bindings/python/README.md"}

# The README is written for GitHub, which shows one logo on both themes; the site has a pair.
README_LOGO = '<img src="https://raw.githubusercontent.com/getkern/kern/main/assets/brand/kern-logo.png" width="220" alt="kern">'
SITE_LOGOS = (
    '<img class="light" src="/img/kern-logo.png" width="220" alt="kern">'
    '<img class="dark" src="/img/kern-logo-dark.png" width="220" alt="kern">'
)

# The documents worth a page of their own, in the order a reader meets them. `title` is what goes in
# `<title>` and in the nav; the file's own H1 stays as the page heading.
PAGES = [
    ("INSTALL.md", "Install kern on Linux, WSL2, macOS and ARM boards"),
    ("SANDBOX.md", "Kern Sandbox: run a model's code from Python or Node"),
    ("RESOURCES.md", "Virtual resources: CPU, memory, disk and device profiles"),
    ("EGRESS.md", "Egress control: what a box can reach"),
    ("CONFIG.md", "kern.toml: configuration reference"),
    ("MCP.md", "kern-mcp: a code interpreter for any MCP client"),
    ("DOCKER-COMPAT.md", "Docker compatibility: what maps and what does not"),
    ("THREAT_MODEL.md", "Threat model: what the boundary is, and what it is not"),
    ("FAQ.md", "kern FAQ: the questions people ask"),
]

CSS = """
:root{--bg:#fff;--ink:#1f2328;--dim:#636c76;--line:#d1d9e0;--link:#0969da;--panel:#f6f8fa;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--ink:#e6edf3;--dim:#8b949e;--line:#30363d;
--link:#4493f8;--panel:#161b22}}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.6;margin:0;
padding:0 0 4rem}
.wrap{max-width:46rem;margin:0 auto;padding:0 1.5rem}
header{border-bottom:1px solid var(--line);margin-bottom:2rem}
header .wrap{display:flex;align-items:center;justify-content:space-between;gap:1rem;height:4rem}
main{max-width:46rem;margin:0 auto;padding:0 1.5rem}
nav{font-size:.9rem;display:flex;align-items:center;gap:1.1rem;flex-wrap:wrap}
nav a{white-space:nowrap;color:var(--dim)}
nav a:hover{color:var(--ink)}
nav a.here{color:var(--ink);font-weight:600}
nav a.gh{display:inline-flex;align-items:center;gap:.4rem;color:var(--ink);font-weight:600;border:1px solid var(--line);border-radius:6px;padding:.2rem .65rem}
nav a.gh:hover{border-color:var(--dim)}
main img{max-width:100%;height:auto}
main img.dark{display:none}
@media(prefers-color-scheme:dark){main img.light{display:none}main img.dark{display:inline}}
.logo img{height:26px;width:auto;display:block}
.logo img.dark{display:none}
@media(prefers-color-scheme:dark){.logo img.light{display:none}.logo img.dark{display:block}}
@media(max-width:46rem){header .wrap{height:auto;padding-top:1rem;padding-bottom:1rem;
flex-direction:column;align-items:flex-start}}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
h1{font-size:1.9rem;line-height:1.25;margin:.2rem 0 1rem}
h2{font-size:1.35rem;margin:2.2rem 0 .8rem;padding-bottom:.3rem;border-bottom:1px solid var(--line)}
h3{font-size:1.1rem;margin:1.6rem 0 .5rem}
code{font-family:var(--mono);font-size:.88em;background:var(--panel);padding:.15em .35em;
border-radius:4px}
pre{background:var(--panel);padding:1rem;border-radius:6px;overflow-x:auto;border:1px solid var(--line)}
pre code{background:none;padding:0}
.codewrap{position:relative}
.codewrap>button{position:absolute;top:.45rem;right:.45rem;font:inherit;font-size:.78rem;padding:.1rem .5rem;border:1px solid var(--line);border-radius:5px;background:var(--bg);color:var(--dim);cursor:pointer}
.codewrap>button:hover{color:var(--ink);border-color:var(--dim)}
table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.92rem;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:.5rem .7rem;text-align:left;vertical-align:top}
th{background:var(--panel)}
blockquote{margin:1rem 0;padding:.4rem 1rem;border-left:3px solid var(--line);color:var(--dim)}
footer{max-width:52rem;margin:3rem auto 0;padding-top:1rem;border-top:1px solid var(--line);
color:var(--dim);font-size:.85rem}
.win{margin:1rem 0;border-radius:10px;overflow:hidden;background:#080c13;border:1px solid #1f2933;
box-shadow:0 8px 24px rgba(1,4,9,.16)}
.win-bar{display:flex;align-items:center;gap:.8rem;height:2.25rem;padding:0 .8rem;background:#141a21;
border-bottom:1px solid #1f2933}
.win-dots{display:inline-flex;gap:.42rem}
.win-dots i{display:block;width:.7rem;height:.7rem;border-radius:50%}
.win-dots i:nth-child(1){background:#c58038}
.win-dots i:nth-child(2){background:#e2b241}
.win-dots i:nth-child(3){background:#3ab593}
.win-title{display:inline-flex;align-items:center;gap:.45rem;font-family:var(--mono);font-size:.8rem;
color:#6e8c91}
.win-title svg{width:15px;height:15px;color:#3ab593}
.win[data-lang=python] .win-title svg{color:#e2b241}
.win[data-lang=json] .win-title svg,.win[data-lang=toml] .win-title svg,
.win[data-lang=yaml] .win-title svg{color:#c58038}
.win-bar>button{margin-left:auto;font:inherit;font-family:var(--mono);font-size:.75rem;
padding:.05rem .55rem;border:1px solid #2a3642;border-radius:5px;background:transparent;color:#6e8c91;
cursor:pointer}
.win-bar>button:hover{color:#e6edf3;border-color:#6e8c91}
.win pre{margin:0;border:0;border-radius:0;background:transparent;color:#d4d4d4;padding:1rem 1.15rem;
line-height:1.55;scrollbar-color:#2a3642 #080c13}
.win pre::-webkit-scrollbar{height:8px}
.win pre::-webkit-scrollbar-track{background:#080c13}
.win pre::-webkit-scrollbar-thumb{background:#2a3642;border-radius:4px}
.win pre code{color:inherit}
.win .k,.win .kd,.win .kr,.win .kt,.win .kc{color:#569cd6}
.win .kn,.win .ow{color:#c586c0}
.win .s,.win .s1,.win .s2,.win .sa,.win .sb,.win .sd,.win .se,.win .sh,.win .si,.win .sx{color:#ce9178}
.win .c,.win .c1,.win .cm,.win .ch,.win .cs,.win .cp{color:#6a9955}
.win .m,.win .mi,.win .mf,.win .mh,.win .mo,.win .il{color:#b5cea8}
.win .nf,.win .fm,.win .nb,.win .bp{color:#dcdcaa}
.win .nc,.win .nn{color:#4ec9b0}
.win .nv,.win .na,.win .nt{color:#9cdcfe}
.win-tabs{display:flex;align-self:stretch;overflow-x:auto;scrollbar-width:none;min-width:0}
.win-tabs::-webkit-scrollbar{display:none}
.win-tab{font:inherit;font-family:var(--mono);font-size:.78rem;color:#6e8c91;background:transparent;
border:0;border-right:1px solid #1f2933;padding:0 .75rem;cursor:pointer;white-space:nowrap}
.win-tab:first-child{border-left:1px solid #1f2933}
.win-tab:hover{color:#e6edf3}
.win-tab[aria-selected=true]{background:#080c13;color:#e6edf3;box-shadow:inset 0 2px 0 #3ab593}
.win-tabbed.js .win-title{display:none}
.win-panel{padding-top:.9rem}
.win-panel+.win-panel{border-top:1px solid #1f2933}
.win-tabbed.js .win-panel+.win-panel{border-top:0}
.win-panel[hidden]{display:none}
.win-panel p{margin:0 1.15rem;color:#9aa7b0;font-size:.93rem;line-height:1.55}
.win-panel p strong{color:#e6edf3}
.win-panel p code{background:#141a21;color:#d4d4d4}
.win-panel pre{padding-top:.75rem}
"""

# Code blocks are drawn as windows, the way the demo GIF on the Sandbox page draws its terminal: a bar
# with three dots, an icon and the language, and colours from Pygments at BUILD time, so the page
# needs no highlighter script. Only a block that declares its language gets the frame: an undeclared
# one is a diagram or a transcript, and a label on it would be a guess. Without Pygments the frame
# still draws and the code stays plain.
try:
    from pygments import highlight as _highlight
    from pygments.formatters import HtmlFormatter as _HtmlFormatter
    from pygments.lexers import get_lexer_by_name as _get_lexer
    from pygments.util import ClassNotFound as _ClassNotFound
except ImportError:
    _highlight = None

_SVG = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="{}" fill="none" stroke="currentColor" ' \
    'stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>'
ICON_TERMINAL = _SVG.format("M3 4.5 6.5 8 3 11.5M8.5 12H13")
ICON_CODE = _SVG.format("M5.5 4.5 2 8l3.5 3.5M10.5 4.5 14 8l-3.5 3.5")
ICON_DATA = _SVG.format("M6 2.5C4.5 2.5 4 3.2 4 4.5V6c0 1-.6 1.5-1.5 2 .9.5 1.5 1 1.5 2v1.5c0 1.3.5 2 2 2"
                        "M10 2.5c1.5 0 2 .7 2 2V6c0 1 .6 1.5 1.5 2-.9.5-1.5 1-1.5 2v1.5c0 1.3-.5 2-2 2")
WINDOW_LANGS = {
    "bash": ("Terminal", ICON_TERMINAL), "sh": ("Terminal", ICON_TERMINAL),
    "shell": ("Terminal", ICON_TERMINAL), "console": ("Terminal", ICON_TERMINAL),
    "python": ("Python", ICON_CODE), "py": ("Python", ICON_CODE),
    "javascript": ("JavaScript", ICON_CODE), "js": ("JavaScript", ICON_CODE),
    "typescript": ("TypeScript", ICON_CODE), "ts": ("TypeScript", ICON_CODE),
    "rust": ("Rust", ICON_CODE), "go": ("Go", ICON_CODE),
    "json": ("JSON", ICON_DATA), "toml": ("TOML", ICON_DATA), "yaml": ("YAML", ICON_DATA),
    "yml": ("YAML", ICON_DATA),
}


def code_windows(body: str) -> str:
    def frame(m: "re.Match[str]") -> str:
        lang, code = m.group(1).lower(), m.group(2)
        known = WINDOW_LANGS.get(lang)
        if known is None:
            return m.group(0)
        if _highlight is not None:
            try:
                code = _highlight(html.unescape(code), _get_lexer(lang), _HtmlFormatter(nowrap=True))
            except _ClassNotFound:
                pass
        name, icon = known
        return (
            f'<div class="win" data-lang="{lang}"><div class="win-bar"><span class="win-dots">'
            f'<i></i><i></i><i></i></span><span class="win-title">{icon}{name}</span></div>'
            f'<pre><code class="language-{lang}">{code}</code></pre></div>'
        )

    return re.sub(r'<pre><code class="language-([\w+-]+)">(.*?)</code></pre>', frame, body, flags=re.S)


# A run of short examples reads as ONE window with a tab per example, the way an editor holds
# several files. The source marks it with HTML comments (`<!-- tabs -->`, `<!-- tab: name -->`,
# `<!-- /tabs -->`), which GitHub and PyPI do not render, so the README reads as a plain list there.
# Each tab keeps its paragraph and loses its own window frame. The page script turns the panels into
# tabs; without it every panel stays visible, one under the other, inside the one window.
def code_tabs(body: str) -> str:
    def group(m: "re.Match[str]") -> str:
        parts = re.split(r"<!-- tab: ([\w.-]+) -->", m.group(1))[1:]
        panels = []
        for name, content in zip(parts[0::2], parts[1::2]):
            content = re.sub(
                r'<div class="win" data-lang="[^"]+"><div class="win-bar">.*?</div>(<pre>.*?</pre>)</div>',
                r"\1", content.strip(), flags=re.S,
            )
            panels.append(f'<div class="win-panel" data-tab="{name}">{content}</div>')
        return (
            '<div class="win win-tabbed" data-lang="python"><div class="win-bar"><span class="win-dots">'
            f'<i></i><i></i><i></i></span><span class="win-title">{ICON_CODE}Python</span></div>'
            + "".join(panels) + "</div>"
        )

    return re.sub(r"<!-- tabs -->(.*?)<!-- /tabs -->", group, body, flags=re.S)


def out_name(md: str) -> str:
    return md.replace(".md", "").lower().replace("_", "-") + ".html"


def rewrite_links(body: str) -> str:
    """Point relative markdown links at the rendered page, or at the repo when there is none.

    A doc links to its siblings (`RESOURCES.md`), to repo files (`../SECURITY.md`) and to
    directories (`../pentest/`). Only the first has an HTML page here; the rest must reach GitHub,
    or the reader gets a 404 on a link that worked before.
    """
    have = {md for md, _ in PAGES}

    def fix(m):
        href = m.group(1)
        if href.startswith(("http", "#", "mailto:")):
            return m.group(0)
        target, _, frag = href.partition("#")
        base = target.split("/")[-1]
        if base in have and "/" not in target.strip("./"):
            return f'href="{out_name(base)}{"#" + frag if frag else ""}"'
        clean = target.lstrip("./")
        kind = "tree" if target.endswith("/") else "blob"
        return f'href="{REPO}/{kind}/main/{clean}{"#" + frag if frag else ""}"'

    return re.sub(r'href="([^"]+)"', fix, body)


RAW = "https://raw.githubusercontent.com/getkern/kern/main/"


def localize_images(page: str, out: pathlib.Path) -> str:
    """Serve every image from getkern.dev itself, because the site's policy allows nothing else.

    The Content-Security-Policy says `img-src 'self' data:`. The README the Sandbox page is built
    from loads its demo and its chart from raw.githubusercontent and its badges from shields.io,
    which GitHub shows and the site blocks: MEASURED 2026-09-23, the served page printed the demo's
    alt text where the animation should be. A local preview without that header showed everything,
    which is how it shipped. Repository images are copied from the checkout on every build, so this
    copy cannot go stale the way the home's hand-copied chart did; badges are fetched once per build,
    and one that cannot be fetched is replaced by its label rather than left as a broken image.
    """
    def fix(m):
        tag, raw = m.group(0), m.group(1)
        src = html.unescape(raw)
        if src.startswith(RAW):
            rel = src[len(RAW):]
            dst = out / "assets" / pathlib.Path(rel).name
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes((ROOT / rel).read_bytes())
            return tag.replace(raw, f"{BASE}/assets/{dst.name}")
        if src.startswith("https://img.shields.io/"):
            name = "badge-" + hashlib.sha1(src.encode()).hexdigest()[:10] + ".svg"
            try:
                req = urllib.request.Request(src, headers={"User-Agent": "curl/8"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = r.read()
            except OSError as e:
                print(f"badge not fetched, shown as text: {src} ({e})", file=sys.stderr)
                alt = re.search(r'alt="([^"]*)"', tag)
                return alt.group(1) if alt else ""
            (out / "assets").mkdir(parents=True, exist_ok=True)
            (out / "assets" / name).write_bytes(data)
            return tag.replace(raw, f"{BASE}/assets/{name}")
        return tag

    return re.sub(r'<img\b[^>]*\bsrc="([^"]+)"[^>]*>', fix, page)


def beacon(token: str) -> str:
    """The analytics snippet, inlined at build time so regenerating the pages cannot drop it.

    It went missing exactly that way once: the beacon was inserted into the published HTML by hand,
    and the next build would have overwritten every page with a copy that had none. The token is
    public, it ships in the HTML of every visitor, but it is passed in rather than written here so
    this file carries no value belonging to an account.
    """
    if not token:
        return ""
    return (
        "<!-- Cloudflare Web Analytics --><script type='module' "
        "src='https://static.cloudflareinsights.com/beacon.min.js' "
        f'data-cf-beacon=\'{{"token": "{token}"}}\'></script>'
        "<!-- End Cloudflare Web Analytics -->\n"
    )


def render(md_path: pathlib.Path, title: str, nav: str, token: str = "", page: str = "") -> str:
    text = md_path.read_text(encoding="utf-8")
    # The package README centres its header in a raw `<div align="center">`, which Markdown passes
    # through untouched, so its title, slogan and badges would print as literal `#` and `**`.
    # `md_in_html` renders inside a block marked `markdown="1"`, and no other page has one.
    text = text.replace('<div align="center">', '<div align="center" markdown="1">')
    text = text.replace(README_LOGO, SITE_LOGOS)
    body = markdown.markdown(
        text, extensions=["tables", "fenced_code", "toc", "attr_list", "md_in_html"]
    )
    body = code_tabs(code_windows(rewrite_links(body)))
    # The description is the first paragraph WITH TEXT, flattened. Better than a constant: it is what
    # the document itself opens with, so it cannot drift from the page. With text, because the
    # README's first paragraph is its logo, which flattens to nothing.
    paras = (re.sub(r"<[^>]+>", "", m) for m in re.findall(r"<p[^>]*>(.*?)</p>", body, re.S))
    desc = next((d for d in paras if d.strip()), title)
    # Cut on a WORD boundary. A flat [:157] took eight of the ten pages mid-word ("what is
    # supporte", "How m"), and that string is the search snippet and the social card, which is
    # exactly where a half word reads as a broken page.
    desc = " ".join(desc.split())
    if len(desc) > 157:
        desc = desc[:157].rsplit(" ", 1)[0].rstrip(",;:") + "…"
    desc = html.escape(desc, quote=True)
    page = page or out_name(md_path.name)
    # Where the page's source lives, for "this page on GitHub": the README for the Sandbox page,
    # `docs/` for the rest. The guide index is built from a temporary file, which keeps the old form.
    src = md_path.resolve()
    src_rel = src.relative_to(ROOT).as_posix() if src.is_relative_to(ROOT) else f"docs/{md_path.name}"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} | kern</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="{SITE}{BASE}/{page}">
<meta name="robots" content="index, follow, max-snippet:-1">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="/img/kern-icon.png">
<meta property="og:type" content="article">
<meta property="og:site_name" content="kern">
<meta property="og:url" content="{SITE}{BASE}/{page}">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{desc}">
<meta property="og:image" content="{SITE}/og-image-v5.png">
<style>{CSS}</style>
</head>
<body>
<header>
  <div class="wrap">
    <a class="logo" href="/" aria-label="kern">
      <img class="light" src="/img/kern-logo.png" alt="kern" width="876" height="342">
      <img class="dark"  src="/img/kern-logo-dark.png" alt="kern" width="876" height="342">
    </a>
    <nav>{nav}</nav>
  </div>
</header>
<main>
{body}
</main>
<footer>
<a href="{SITE}/">getkern.dev</a> &middot;
<a href="{REPO}/blob/main/{src_rel}">this page on GitHub</a> &middot;
<a href="{REPO}">source</a>
</footer>
<script>
// THE COMMAND IS THE FIRST THING A READER DOES WITH THIS PAGE, and until 2026-09-26 the only way to
// take it was to select it by hand: the home page had a copy button and the guide did not. The
// site's CSP is `script-src 'self' 'unsafe-inline'`, so this needs no exception, and it is the same
// handler the home page uses, bound to every block rather than to four hand-written ones. A block
// drawn as a window already has a bar, and the button goes in it. A tabbed window has ONE button,
// and it copies the tab that is open.
function copyButton(bar, source) {{
  var b = document.createElement('button');
  b.type = 'button';
  b.textContent = 'copy';
  b.addEventListener('click', function () {{
    navigator.clipboard.writeText(source().textContent).then(function () {{
      b.textContent = 'copied';
      setTimeout(function () {{ b.textContent = 'copy'; }}, 1500);
    }});
  }});
  bar.appendChild(b);
}}
document.querySelectorAll('main .win-tabbed').forEach(function (win) {{
  var bar = win.querySelector('.win-bar'), panels = win.querySelectorAll('.win-panel');
  var strip = document.createElement('div'), current = panels[0];
  strip.className = 'win-tabs';
  strip.setAttribute('role', 'tablist');
  panels.forEach(function (panel, i) {{
    var t = document.createElement('button');
    t.type = 'button';
    t.className = 'win-tab';
    t.setAttribute('role', 'tab');
    t.textContent = panel.dataset.tab;
    t.setAttribute('aria-selected', i === 0 ? 'true' : 'false');
    panel.setAttribute('role', 'tabpanel');
    panel.hidden = i !== 0;
    t.addEventListener('click', function () {{
      strip.querySelectorAll('.win-tab').forEach(function (o) {{ o.setAttribute('aria-selected', 'false'); }});
      t.setAttribute('aria-selected', 'true');
      panels.forEach(function (p) {{ p.hidden = p !== panel; }});
      current = panel;
    }});
    strip.appendChild(t);
  }});
  bar.appendChild(strip);
  win.classList.add('js');
  copyButton(bar, function () {{ return current.querySelector('pre'); }});
}});
document.querySelectorAll('main pre').forEach(function (pre) {{
  if (pre.closest('.win-tabbed')) return;
  var w = pre.parentNode.classList.contains('win') ? pre.parentNode.querySelector('.win-bar') : null;
  if (!w) {{
    w = document.createElement('div');
    w.className = 'codewrap';
    pre.parentNode.insertBefore(w, pre);
    w.appendChild(pre);
  }}
  copyButton(w, function () {{ return pre; }});
}});
</script>
{beacon(token)}</body>
</html>
"""


def main(argv: list[str]) -> int:
    usage = __doc__.strip().splitlines()[-1]
    if len(argv) not in (2, 3):
        print(usage, file=sys.stderr)
        return 2
    # `--help` USED TO BUILD A DIRECTORY CALLED `--help`. The out-dir is argv[1] and nothing looked
    # at it, so asking this script for its usage created `./--help/` with nine HTML pages in it,
    # which a later `git add -A` committed and pushed. A script whose first argument is a path it
    # will `mkdir` must refuse an argument that is obviously a flag, and must answer the one flag
    # every reader tries first.
    if argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[1].startswith("-"):
        print(f"refusing to treat {argv[1]!r} as an output directory\n{usage}", file=sys.stderr)
        return 2
    token = argv[2] if len(argv) > 2 else ""
    repo = pathlib.Path(__file__).resolve().parent.parent
    out = pathlib.Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)

    # THE LABEL IS NOT THE FILENAME. Title-casing `MCP.md` gave "Mcp" and `FAQ.md` gave "Faq",
    # which is a product's own name spelled wrong in its own navigation, on every page.
    LABELS = {
        "INSTALL.md": "Install",
        "SANDBOX.md": "Sandbox",
        "RESOURCES.md": "Resources",
        "EGRESS.md": "Egress",
        "CONFIG.md": "Config",
        "MCP.md": "MCP",
        "DOCKER-COMPAT.md": "Docker",
        "THREAT_MODEL.md": "Threat model",
        "FAQ.md": "FAQ",
    }
    # NOT EVERY PAGE BELONGS IN THE BAR. Nine links is a menu to read rather than a way to move,
    # and these three answer a question a reader arrives with rather than one they browse for: they
    # are reached from the sentence that raises them (SANDBOX links the threat model and the egress
    # page, FAQ links Docker compatibility) and from the guide index, which lists all of them.
    NAV_HIDDEN = {"EGRESS.md", "THREAT_MODEL.md", "DOCKER-COMPAT.md"}

    def build_nav(current: str | None = None) -> str:
        """The bar, with the page you are on marked. Built per page rather than once, because the
        only honest way to say "you are here" is to know which page is being written."""
        out_links = []
        for md, _ in PAGES:
            if md in NAV_HIDDEN:
                continue
            label = LABELS.get(md, md[:-3].title())
            here = ' class="here" aria-current="page"' if md == current else ""
            out_links.append(f'<a href="{out_name(md)}"{here}>{label}</a>')
        # THE WAY TO THE CODE, IN THE BAR. Until 2026-09-23 the only GitHub links on a guide page were
        # in the footer, so a reader landing on the Sandbox page from a post had nowhere visible to go
        # for the source or the star. The Sandbox page points at the SDK's README, which is what that
        # page is about; the others at the repository.
        gh = f"{REPO}/tree/main/bindings/python" if current == "SANDBOX.md" else REPO
        out_links.append(f'<a class="gh" href="{gh}">{GH_MARK}GitHub</a>')
        return " ".join(out_links)

    written = []
    for md, title in PAGES:
        src = repo / SOURCE.get(md, "docs/" + md)
        if not src.exists():
            print(f"MISSING: docs/{md}", file=sys.stderr)
            return 1
        (out / out_name(md)).write_text(
            localize_images(render(src, title, build_nav(md), token, out_name(md)), out),
            encoding="utf-8",
        )
        written.append(out_name(md))

    # AN INDEX, BECAUSE A DIRECTORY WITHOUT ONE IS A 403. Measured on 2026-09-22: the home links
    # straight to /guide/install.html, so nothing pointed at /guide/ itself and nobody noticed that
    # trimming the URL, which is what a reader does to look for the contents, hit nginx refusing to
    # list a directory. Built from PAGES through the same `render` as everything else, so a page
    # added there cannot go missing from here and the index cannot drift into its own style.
    body = "# kern guide\n\nInstalling, configuring and understanding kern.\n\n" + "\n".join(
        # The MARKDOWN name, not the html one: `rewrite_links` maps a sibling `.md` to its rendered
        # page and sends everything else to GitHub, so linking `install.html` here fell through to
        # the repo branch and the index pointed at eight files that do not exist there. Caught by
        # reading the SERVED page, not the generator.
        f"- [{title}]({md})" for md, title in PAGES
    ) + (
        "\n\nThese pages are rendered from `docs/` in the "
        "[repository](https://github.com/getkern/kern), which is where the same material lives.\n"
    )
    tmp = out / "_index.md"
    tmp.write_text(body, encoding="utf-8")
    (out / "index.html").write_text(
        render(tmp, "kern guide: installing and configuring kern", build_nav(), token),
        encoding="utf-8",
    )
    tmp.unlink()
    written.append("index.html")

    urls = "\n".join(
        f"  <url><loc>{SITE}{BASE}/{p}</loc></url>" for p in written
    )
    (out / "sitemap-guide.xml").write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n{urls}\n</urlset>\n',
        encoding="utf-8",
    )
    print(f"{len(written)} pages + sitemap-guide.xml in {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
