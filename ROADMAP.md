# Roadmap

Nothing here is a commitment or a date. Shipped work is in [CHANGELOG.md](CHANGELOG.md).

## In development

- **VM tier**: a microVM boundary for hostile, multi-tenant code, as its own command
  ([SECURITY.md](SECURITY.md)).
- **Full GPU support**.

## Under consideration

- **Desktop for computer use**: a virtual screen with Chromium, mouse, keyboard and screenshots,
  from Python, Node and MCP. For pages you trust; arbitrary browsing needs the VM tier.
- **Kubernetes pod**: kern runs in a privileged container today; next is the least privilege it
  needs.
- **Snapshot and warm start**: rootless CRIU, opt-in, same host.
- **`kern` on macOS**: a shim to type `kern` in the Mac's shell; it still runs in a Linux VM.
