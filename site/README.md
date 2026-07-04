# getkern.dev — the landing page

A single static page. It is a **thin shell**: the hero is evergreen, and the version + the full
project README are fetched **live from this GitHub repo** by client-side JS on every load — so the
site can never go stale.

`index.html` · `_headers` (content-type for `/install.sh`) · `vendor/` (marked + DOMPurify +
github-markdown-css, pinned, no build step).

## Deploy — the VPS PULLS from GitHub (no CI secret)

The origin (a small VPS behind Cloudflare) runs a systemd timer that `git pull`s this repo every few
minutes and syncs `site/` + the repo-root `install.sh`/`install.ps1` into its webroot. So a push to
`main` publishes automatically, with **no deploy key stored in CI** (which — for a site that serves
install scripts — avoids a supply-chain footgun). The install one-liners point at
`raw.githubusercontent.com` regardless, so installs never depend on the VPS being up.
