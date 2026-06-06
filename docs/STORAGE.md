# kern storage — volumes & vdisks

kern models storage like the tools you already know: **Docker** for the simple 90%, **k8s/LXD** for the
power — layered so a beginner never meets the complexity.

**You almost always want just one thing: a volume.** A volume is a named folder that outlives the box
and can be shared — same as a Docker volume. Everything else is optional.

Where it lives in **`kern top`**:

- **Storage tab** — your **volumes** (create / inspect / delete / prune) + your physical disks shown
  read-only for context. This is the whole story for most people.
- **Profiles tab** — reusable box *specs* attached by prefix (`vcpu`, `vgpio`, `vdisk`). A **`vdisk`** is
  a private, size-capped disk for **one** box (like a Kubernetes `emptyDir` with a size limit) — name +
  size, nothing more. Where it physically lives is a sensible default; power users can pin a `[[disk]]`
  in `kern.toml`.

Both are also editable from the **CLI** (`kern volume …`, `kern.toml`). Nothing needs you to hand-edit a
file.

> **volume vs vdisk?** A **volume** is *shared, persistent data* (`-v name:/path`) — reach for this by
> default. A **vdisk** is *one box's private capped disk* (`vdisk:name` → `/vdisk/name`) — reach for it
> only when a single box needs a hard-capped scratch/data disk. Same relationship as `docker volume` vs
> a Kubernetes `emptyDir`.

---

## Start here (the 90% case): a volume

A **volume** is a named folder that outlives the box and can be shared between boxes. Attach it with
`-v NAME:/path-in-the-box`. kern creates it on first use — no setup.

```sh
# write to it from one box…
kern box w --image alpine -v data:/out -- sh -c 'echo hello > /out/note.txt'
# …read it back from another. The volume persists; the boxes don't.
kern box r --image alpine -v data:/out -- cat /out/note.txt      # → hello
```

That's the whole model for most people: **`-v name:/path`, and your data is safe across runs.**

Manage them without touching the CLI:

```
kern top → Storage tab → [n]ew  [⏎]inspect  [d]elete  [p]rune
```

Volumes live under `~/.local/share/kern/volumes/` (or `$XDG_DATA_HOME/kern/volumes`).

### A volume with a size cap

Give a volume a **quota** at creation and it won't grow past it:

```sh
kern volume create cache --size 2g
kern box app --image alpine -v cache:/var/cache -- ./run.sh
```

Honest note: the quota is **enforced** only when a **privileged, foreground** box mounts it — then
kern backs the volume with a real **ext4-on-loop** image (a true filesystem-level cap). Rootless or
detached, kern falls back to a plain bind-mount and **tells you** the quota isn't enforced rather than
pretending. Either way your data is in the same place; only the *hard cap* differs.

### A volume from the network

A `-v` source can also be a URL — kern mounts it for the box's lifetime:

```sh
kern box app --image alpine -v nfs://server/export:/data   -- ./run.sh
kern box app --image alpine -v smb://server/share:/data    -- ./run.sh
kern box app --image alpine -v sshfs://user@host/srv:/data -- ./run.sh
```

---

## When you want a private, capped disk: a vdisk

A **vdisk** is a *profile* that hands one box its own size-capped disk mounted at `/vdisk/NAME`. Where a
volume is shared storage you attach ad-hoc, a vdisk is a **reusable spec** (size + IOPS + persistence)
you name once in `kern.toml` and attach with the `vdisk:` prefix.

```toml
# ~/.config/kern/kern.toml
[[vdisk]]
name = "scratch"
size = "2g"            # hard cap
persistent = false     # true = survives box removal
# backend = "disk:0"   # advanced: pin to a specific physical disk (see below); default is automatic
# iops = 500           # advanced: optional I/O limit (ext4-loop backend only)
```

```sh
kern box build --image alpine vdisk:scratch -- ./compile.sh    # → /vdisk/scratch, capped at 2g
```

Manage it interactively — **no file editing**:

```
kern top → Profiles tab → n → v   (new vdisk) / e (edit) / d (delete)
```

The form is just **name + size** (and an optional `persistent` toggle) — like a Kubernetes `emptyDir`
with a size limit. Where the disk physically lives is a sensible default; it's written **surgically** to
`kern.toml`, preserving your comments and other sections.

Like a quota'd volume, a vdisk uses the ext4-loop backend when the box is privileged, and a RAM-backed
(`tmpfs`) fallback otherwise — kern says which one you got, and never silently drops the profile.

---

## Advanced: pin a vdisk to a specific disk

By default kern picks where a vdisk's image lives — you don't choose, exactly like Docker doesn't ask
which disk a volume goes on, or Kubernetes uses a default StorageClass. If you have **multiple disks**
and want a `persistent` vdisk on a *specific* one (big scratch on the HDD, fast cache on the NVMe), name
a `[[disk]]` pool in `kern.toml` and point the vdisk's `backend` at it:

```toml
[[disk]]
name = "fast"
path = "/mnt/nvme"     # a writable dir on the disk you want

[[vdisk]]
name = "cache"
size = "10g"
backend = "fast"       # ← this vdisk's image lives under /mnt/nvme
```

`kern probe` lists your physical disks; `kern top`'s Overview and Storage tabs show them read-only.

```sh
$ kern probe
disks   nvme0n1  931.5G  SSD (Samsung 990 PRO)  ·  sda  1.8T  HDD (WDC WD20)
```

This is the one knob that stays in `kern.toml` (not the TUI) — the deliberate "power-user escape hatch,"
kept out of the beginner's way.

---

## How they relate

```
volume  ── shared, persistent data          → -v name:/path        (kern volume · Storage tab)
vdisk   ── one box's private, capped disk    → /vdisk/name          (kern.toml · Profiles tab)
[[disk]]── (advanced) which physical disk a vdisk pins to           (kern.toml only)
```

- A **volume with a quota** and a **vdisk** use the *same* ext4-on-loop engine under the hood — a vdisk
  is essentially a one-box, size-capped volume you attach by prefix.
- The **physical disk** is a default you rarely set; it's a property of the data, not something you pick
  every time (like a k8s StorageClass).

### Which do I use?

| I want… | Use |
|---|---|
| Data that survives runs / shared between boxes | a **volume** (`-v name:/path`) |
| A cap on how big that shared data can get | a **volume with `--size`** |
| One box to have its own capped scratch/data disk | a **vdisk** profile (`vdisk:x` → `/vdisk/x`) |
| Data on a remote server | a **network volume** (`-v nfs://…`) |
| A persistent vdisk on a *specific* disk (advanced) | a `[[disk]]` + the vdisk's `backend` in `kern.toml` |

See also: [docs/CONFIG.md](CONFIG.md) for the full profile schema.
