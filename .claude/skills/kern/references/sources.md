# Sources and Docker skill selection

Research checked on 2026-09-08. Links follow upstream branches and can change; no immutable commit was captured. Consult the installed Kern release's documentation for executable decisions.

## Kern authorities

- [getkern/kern](https://github.com/getkern/kern): runtime model and basic commands.
- [Installation](https://github.com/getkern/kern/blob/main/docs/INSTALL.md): supported environment and setup.
- [Docker compatibility](https://github.com/getkern/kern/blob/main/docs/DOCKER-COMPAT.md): migration boundaries.
- [Changelog](https://github.com/getkern/kern/blob/main/CHANGELOG.md): released versus unreleased behavior.
- [Python bindings](https://github.com/getkern/kern/blob/main/bindings/python/README.md): sandbox API and lifecycle.

## Selected Docker reference

[ECC docker-patterns](https://github.com/affaan-m/ECC/blob/main/skills/docker-patterns/SKILL.md) was the Docker skill in the highest-starred repository among candidates checked. Its repository is MIT-licensed; the former `affaan-m/everything-claude-code` URL redirects to ECC.

GitHub's rounded **repository** star counts observed during the check:

| Repository | Stars | Evidence scope |
| --- | ---: | --- |
| [affaan-m/ECC](https://github.com/affaan-m/ECC) | 253.7k | Docker SKILL.md inspected |
| [sickn33/agentic-awesome-skills](https://github.com/sickn33/agentic-awesome-skills) | 46.1k | docker-expert SKILL.md inspected |
| [Jeffallan/claude-skills](https://github.com/Jeffallan/claude-skills) | 11.4k | Repository comparison only; Docker skill path not verified |
| [full-stack-skills/docker-skills](https://github.com/full-stack-skills/docker-skills) | 2 | README identifies 16 Docker skills |

These are not individual skill ratings or an exhaustive global ranking. Counts change.

This skill uses original guidance informed by the Docker reference's organization around lifecycle, configuration, persistence, networking, security, and diagnosis. Transferable practices include inspecting the environment first, distinguishing development and production needs, protecting persistent data, and collecting targeted evidence before changing state. Docker commands, Compose assumptions, and categorical deployment recommendations are not adopted as Kern facts.
