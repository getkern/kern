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

import html
import pathlib
import re
import sys

import markdown

BASE = "/guide"
SITE = "https://getkern.dev"
REPO = "https://github.com/getkern/kern"

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
nav a.gh{color:var(--ink);font-weight:600;border:1px solid var(--line);border-radius:6px;padding:.2rem .65rem}
nav a.gh:hover{border-color:var(--dim)}
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
table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.92rem;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:.5rem .7rem;text-align:left;vertical-align:top}
th{background:var(--panel)}
blockquote{margin:1rem 0;padding:.4rem 1rem;border-left:3px solid var(--line);color:var(--dim)}
footer{max-width:52rem;margin:3rem auto 0;padding-top:1rem;border-top:1px solid var(--line);
color:var(--dim);font-size:.85rem}
"""


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


def render(md_path: pathlib.Path, title: str, nav: str, token: str = "") -> str:
    text = md_path.read_text(encoding="utf-8")
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "toc", "attr_list"])
    body = rewrite_links(body)
    # The description is the first paragraph, flattened. Better than a constant: it is what the
    # document itself opens with, so it cannot drift from the page.
    first = re.search(r"<p>(.*?)</p>", body, re.S)
    desc = re.sub(r"<[^>]+>", "", first.group(1)) if first else title
    # Cut on a WORD boundary. A flat [:157] took eight of the ten pages mid-word ("what is
    # supporte", "How m"), and that string is the search snippet and the social card, which is
    # exactly where a half word reads as a broken page.
    desc = " ".join(desc.split())
    if len(desc) > 157:
        desc = desc[:157].rsplit(" ", 1)[0].rstrip(",;:") + "…"
    desc = html.escape(desc, quote=True)
    page = out_name(md_path.name)
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
<a href="{REPO}/blob/main/docs/{md_path.name}">this page on GitHub</a> &middot;
<a href="{REPO}">source</a>
</footer>
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
        out_links.append(f'<a class="gh" href="{gh}">&#9733; GitHub</a>')
        return " ".join(out_links)

    written = []
    for md, title in PAGES:
        src = repo / "docs" / md
        if not src.exists():
            print(f"MISSING: docs/{md}", file=sys.stderr)
            return 1
        (out / out_name(md)).write_text(
            render(src, title, build_nav(md), token), encoding="utf-8"
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
