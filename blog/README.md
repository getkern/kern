# kern blog

Notes on how kern is built and where its boundaries are — honest, technical, no marketing.

| Post | What it's about |
|---|---|
| [Introducing kern](introducing-kern.md) | What kern is and why: a daemonless, rootless container + resource runtime in ~1.5 MB — the two verbs, the embed SDK, the benchmarks, and where the security boundary actually is. |
| [What the type system buys you](what-the-type-system-buys-you.md) | How kern turns a class of sandbox-escape *ordering* bug into a compile error — the `Rootfs<S>` typestate, and an honest account of what it does and doesn't guarantee. |

Project: **[github.com/getkern/kern](https://github.com/getkern/kern)**
