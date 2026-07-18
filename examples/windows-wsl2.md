# kern on Windows (via WSL2)

kern is a Linux runtime — it uses Linux user namespaces, seccomp and cgroup v2. On Windows it runs
**inside WSL2**, which is a real Linux kernel that Windows already ships. There is nothing to
emulate: kern in WSL2 is kern on Linux.

## Run it

```powershell
# 1. one-time: enable WSL2 and reboot (skip if you already use WSL2)
wsl --install

# 2. get a Linux userland (any distro works — Ubuntu, Alpine, Debian, …)
wsl --install -d Ubuntu           # or import a rootfs you already have

# 3. inside the distro, install kern and use it exactly as on Linux
wsl
  curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
  kern box demo --image alpine -- echo "hello from a kern box on Windows"
```

That's it — `kern box`, `kern run`, `kern compose`, `pull`, `ps`, ports, the SDKs: all the same
commands as on native Linux.

## What's real here (honest)

- **The resource caps are hard, kernel-enforced caps**, not best-effort. `--memory 128m` OOM-kills a
  workload that goes over (exit 137); `--cpus` throttles for real; published ports and
  network-off-by-default all behave as on native Linux — because it *is* a Linux kernel.
- **Namespaces + seccomp are a real kernel boundary**, the same one as on Linux. (Still a
  kernel-boundary sandbox, not a hardware/microVM boundary — see [../SECURITY.md](../SECURITY.md).)

## The one caveat worth stating

kern runs **inside the WSL2 kernel** — it does **not** spin up its own VM. So the isolation kern
gives you on Windows is exactly the Linux-namespace isolation described everywhere else in these
docs, layered on top of the single WSL2 VM that Windows manages. kern does not add a hypervisor
boundary of its own; if you want per-workload hardware isolation, that's a different tool.

## Performance note

Measure inside **one** WSL2 session (`N ≥ 100` boxes in a loop), not end-to-end from PowerShell: a
PowerShell → `wsl.exe` → kern round-trip is dominated by the `wsl.exe` process spawn (tens to
~hundreds of ms), which is a Windows cost, not kern's. A pure box in WSL2 starts in single-digit
milliseconds, the same class as native Linux.
