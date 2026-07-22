# Give Claude Desktop / Cursor a local, network-off code interpreter (MCP)

`kern-mcp` is a dependency-free [Model Context Protocol](https://modelcontextprotocol.io) stdio server
that hands any MCP client (Claude Desktop, Cursor, Windsurf) a **local** code interpreter backed by kern:
the model can run Python / bash / Node, write and read files, and get charts back as image blocks, with
the **network hard-off on every run** and hard resource caps. No cloud, no account, no API key: the code
runs in a fresh isolated `kern box` on your machine.

## Install

```sh
pip install kern-sandbox          # ships the `kern-mcp` command
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh   # the kern binary
```

## Wire it into the client

Claude Desktop (`claude_desktop_config.json`) or any MCP client's server config:

```json
{
  "mcpServers": {
    "kern": {
      "command": "kern-mcp",
      "env": {
        "KERN_MCP_SETUP": "pip install numpy pandas matplotlib",
        "KERN_MCP_MEMORY_MB": "1024",
        "KERN_MCP_KERNEL": "1"
      }
    }
  }
}
```

Restart the client. It now exposes four tools: `run_code` (python / bash / node), `write_file`,
`read_file`, `list_files`. Ask the model to "plot the last column of data.csv" and the chart comes back
as an image; ask it to "check if this snippet is safe to run" and it runs in a throwaway box.

## The knobs (all optional)

| Env var | Default | What it does |
|---|---|---|
| `KERN_MCP_IMAGE` | `python:3.12-slim` | OCI image the boxes run in |
| `KERN_MCP_SETUP` | (none) | one-time `pip install ...`, the ONLY network-on moment; every `run_code` after is network-off |
| `KERN_MCP_MEMORY_MB` | `1024` | hard RAM cap per box (cgroup) |
| `KERN_MCP_TIMEOUT` | `60` | per-call wall-clock deadline |
| `KERN_MCP_WORKSPACE` | temp dir | persist file state at this path across calls instead of a temp dir |
| `KERN_MCP_PROFILES` | (none) | attach `kern.toml` profiles, e.g. `vcpu:heavy,vgpio:sensors` (the only way to grant a device: the edge/robotics angle) |
| `KERN_MCP_KERNEL` | off | `1` routes python `run_code` through a **warm kernel**: in-memory state persists across calls and each call is sub-millisecond instead of a ~10 ms interpreter boot. Still network-off; a runaway cell that times out respawns the kernel transparently, it never dooms the session |

## Why this and not a hosted code interpreter

A cloud code interpreter (E2B, Modal, Daytona) needs an account, an API key, and a network round-trip,
and your model's code runs on someone else's machine. `kern-mcp` runs it **on yours**: no account, no
egress, works air-gapped, and is the same shape (`run_code` + rich results). Because it is `kern box`
under the hood, the network is off by default, the box is memory/pids/CPU capped, and a blocked syscall
or an OOM comes back as data, not a crash. See [SECURITY.md](../SECURITY.md) for the honest threat model:
this is a kernel-boundary sandbox for your own or semi-trusted agent code, not a hostile-multi-tenant
microVM.
