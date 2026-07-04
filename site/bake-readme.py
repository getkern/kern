#!/usr/bin/env python3
"""Render README.md into the site template for SEO — crawlers and no-JS clients get the FULL content
server-side. Run by the VPS sync on every GitHub pull, so the baked copy is always current; the
client-side JS still live-replaces #readme in real browsers. Mirrors the JS link/image rewriting.

    bake-readme.py <template index.html> <README.md>  > index.html
"""
import sys, re, markdown

tmpl = open(sys.argv[1], encoding='utf-8').read()
md   = open(sys.argv[2], encoding='utf-8').read()

html = markdown.markdown(md, extensions=[
    'markdown.extensions.tables',        # GFM tables
    'markdown.extensions.fenced_code',   # ``` blocks
    'markdown.extensions.sane_lists',
    'markdown.extensions.toc',           # heading ids -> in-page #anchors resolve
    'markdown.extensions.attr_list',
    'markdown.extensions.md_in_html',    # markdown inside the README's <div align=center> header
])

BLOB = 'https://github.com/getkern/kern/blob/main/'
RAW  = 'https://raw.githubusercontent.com/getkern/kern/main/'
# repo-relative links -> GitHub blob; repo-relative images -> raw (same as the client-side JS does)
html = re.sub(r'href="(?!https?:|#|mailto:)\.?/?([^"]+)"', lambda m: 'href="%s%s"' % (BLOB, m.group(1)), html)
html = re.sub(r'src="(?!https?:|data:)\.?/?([^"]+)"',       lambda m: 'src="%s%s"'  % (RAW,  m.group(1)), html)

out = re.sub(r'<!--README_START-->.*?<!--README_END-->',
             lambda m: '<!--README_START-->\n' + html + '\n<!--README_END-->',
             tmpl, count=1, flags=re.S)
sys.stdout.write(out)
