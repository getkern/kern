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
