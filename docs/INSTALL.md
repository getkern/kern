# Installing kern

kern is one static binary, with no daemon and nothing running in the background. It needs a Linux
kernel with unprivileged user namespaces and cgroup v2.

## Linux

```sh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
kern doctor
kern box dev --image alpine -it -- sh
```

The script picks your architecture (`x86_64` or `aarch64`), checks the SHA256 and puts `kern` in
`~/.local/bin`. `kern doctor` tells you what your machine can and cannot do.

For Kern Sandbox from Python, `pip install kern-sandbox` is enough: on `x86_64` and `aarch64` it
brings the same binary, into the venv.

**Ubuntu 23.10 and newer need one root step before the first box:**

```sh
kern doctor --apparmor-profile | sudo tee /etc/apparmor.d/kern >/dev/null
sudo apparmor_parser -r /etc/apparmor.d/kern
```

**Without the script:**

```sh
f=kern-x86_64-unknown-linux-musl.tar.gz
u=https://github.com/getkern/kern/releases/latest/download
curl -fsSL -O $u/$f -O $u/$f.sha256
sha256sum -c $f.sha256
tar xzf $f && install -Dm755 kern ~/.local/bin/kern
```

To pin a release, run the script with `KERN_VERSION=vX.Y.Z`. To build from source:
`cargo install --git https://github.com/getkern/kern getkern --locked`.

## Windows

In PowerShell:

```powershell
irm https://raw.githubusercontent.com/getkern/kern/main/install.ps1 | iex
```

It sets up WSL2 (one reboot, if it was not there yet) and a small Linux distro with kern inside, and
puts `kern.exe` on your PATH. For more than a few commands, work inside the distro, where each box is
much faster:

```powershell
wsl -d kern
```

### Which WSL2 distro kern uses

`kern.exe` is a forwarder: it runs the real kern inside one WSL2 distro. If you have more than one,
`kern wsl` says which, and lets you change it.

```powershell
kern wsl list            # the distros, and which one is in use
kern wsl list --probe    # also kern's version inside each (this STARTS every stopped distro)
kern wsl status          # the distro in use, why it was chosen, and kern's version there
kern wsl use Ubuntu      # use this one from now on (refused if kern is not installed in it)
kern wsl reset           # forget the choice and detect again
```

The first command detects a distro and remembers it, preferring kern's own `kern` distro. Precedence
is: the `KERN_WSL_DISTRO` environment variable, then what `kern wsl use` stored, then detection.

`--probe` is the one that answers "why does my fix not show up": it prints the version in each distro,
so two installs disagreeing become visible. `kern doctor`, which runs inside a distro, cannot see
across the WSL boundary and says so.

## macOS

macOS has no containers of its own, so kern runs inside a Linux VM. With colima:

```sh
brew install colima
colima start
colima ssh
curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh
```

colima's default guest is Ubuntu, so run the Ubuntu step above once. In that guest, memory and
process limits are not enforced, and kern says so when a box starts. More in the
[FAQ](FAQ.md#does-it-run-on-macos).

**Kern Sandbox runs where kern runs, so your code goes in the VM too.** `pip install kern-sandbox`
on the Mac itself installs, and its first call stops with an error that says so. Inside the VM, in a
venv, it brings kern with it. An MCP client on the Mac needs the `ssh` line in
[docs/MCP.md](MCP.md).

## Uninstall

```sh
kern uninstall          # shows what it would remove
kern uninstall --yes    # removes it
```

On Windows, in PowerShell. It shows what it would remove, and the command that removes it:

```powershell
irm https://raw.githubusercontent.com/getkern/kern/main/uninstall.ps1 | iex
```

## Requirements and limitations

- A Linux kernel with unprivileged user namespaces and cgroup v2.
- `curl` and `tar`, to pull images.
- Memory and process limits need a systemd user session, or root. Without one the box still runs
  and kern warns; `--require-limits` refuses to start instead.
- `uidmap` (`newuidmap` and `/etc/subuid`) for images that switch to another user.
- It is not a microVM. For hostile, multi-tenant code, use one: see the
  [threat model](../SECURITY.md).

## Platforms

| Platform | Status |
|---|---|
| Linux x86_64 | automated CI |
| Linux aarch64 | automated CI |
| Windows 10 and 11 | through WSL2 |
| macOS | inside a Linux VM, tested on colima |
