# Roadmap

Nothing here is a commitment or a date. Shipped work is in [CHANGELOG.md](CHANGELOG.md).

## In development

- **kern desktop**: a desktop app for kern. One-click install (on Windows it sets up the WSL
  distro), your boxes and stacks with their logs and ports, a tray icon, and `kern doctor`'s
  findings explained.
- **Live progress for `compose up` and `build`**: one line per service, redrawn in place (pull
  progress, the build step with its last output line, what a service is waiting for, elapsed time
  on a silent step), a summary of what failed and why at the end, and `--progress
  auto|tty|plain|json|quiet`, where `json` is the event stream the desktop app reads.

## Planned

- **VM tier**: a microVM boundary for hostile, multi-tenant code, as its own command
  ([SECURITY.md](SECURITY.md)).

## Under consideration

- **Desktop for computer use**: a virtual screen with Chromium, mouse, keyboard and screenshots,
  from Python, Node and MCP. For pages you trust; arbitrary browsing needs the VM tier.
- **Kubernetes pod**: kern runs in a privileged container today; next is the least privilege it
  needs.
- **Snapshot and warm start**: rootless CRIU, opt-in, same host.
