//! Named volumes + the `kern volume` CLI.
//!
//! A *named* volume is persistent storage referenced by name instead of a host path: `-v
//! data:/work` mounts the volume `data` at `/work` in the box, and (like Docker) auto-creates it on
//! first use. Volumes live under `$XDG_DATA_HOME/kern/volumes/<name>/data/` (or
//! `~/.local/share/kern/volumes`), with a small `meta.json` sidecar. Fully rootless — a volume is a
//! directory that gets bind-mounted, so it needs no privilege.
//!
//! Network volumes (`nfs://` / `smb://` / `sshfs://`) and per-volume quota are separate slices.

use crate::error::Error;
use std::path::PathBuf;

/// Root directory holding all named volumes.
pub fn volumes_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(x).join("kern").join("volumes");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".local/share/kern/volumes");
    }
    PathBuf::from(format!("/tmp/kern-volumes-{}", unsafe { libc::getuid() }))
}

/// Is this `-v` source a *named* volume (a bare name) rather than a host path or a `scheme://` URL?
pub fn is_named(source: &str) -> bool {
    !source.is_empty() && !source.starts_with('/') && !source.contains("://")
}

/// A valid volume name: non-empty, `[A-Za-z0-9_.-]` only, no leading `-`/`.`, not `.`/`..`, ≤ 64.
/// Guarantees the name is a single path component that can't climb out of the volumes dir.
fn validate(name: &str) -> Result<(), Error> {
    if kern_common::valid_resource_name(name) {
        Ok(())
    } else {
        Err(Error::Volume(format!(
            "invalid volume name '{name}' (letters/digits/_/./- only, no leading '-' or '.', ≤64)"
        )))
    }
}

/// Resolve a named volume to its `data` directory, **auto-creating** it (with a `meta.json`) on
/// first use — Docker's behaviour. Returns the absolute data path for the caller to bind-mount.
pub fn resolve_named(name: &str) -> Result<String, Error> {
    validate(name)?;
    let base_dir = volumes_dir();
    let vol = base_dir.join(name);
    let data = vol.join("data");
    if !data.exists() {
        std::fs::create_dir_all(&data)
            .map_err(|e| Error::Volume(format!("cannot create volume '{name}': {e}")))?;
        let _ = std::fs::write(
            vol.join("meta.json"),
            format!("{{\"created\":{}}}", crate::registry::now_unix()),
        );
    }
    // Return a canonical, symlink-free source (parity with the host-path `-v` branch) AND confine it:
    // if `<name>` was pre-planted as a symlink pointing outside the volumes dir, the real path won't
    // stay under the (canonical) base — refuse it rather than bind an attacker-chosen host dir.
    let base =
        std::fs::canonicalize(&base_dir).map_err(|e| Error::Volume(format!("volumes dir: {e}")))?;
    let real =
        std::fs::canonicalize(&data).map_err(|e| Error::Volume(format!("volume '{name}': {e}")))?;
    if !real.starts_with(&base) {
        return Err(Error::Volume(format!(
            "volume '{name}' resolves outside the volumes directory (symlink?)"
        )));
    }
    Ok(real.to_string_lossy().into_owned())
}

// ─────────────────────────── network volumes (nfs/smb/sshfs) ───────────────────────────

/// A network filesystem scheme.
#[derive(Clone, Copy, PartialEq)]
enum NetScheme {
    Nfs,
    Smb,
    Sshfs,
}

/// Is this `-v` source a network URL (`nfs://` / `smb://` / `sshfs://`)?
pub fn is_network(source: &str) -> bool {
    source.starts_with("nfs://") || source.starts_with("smb://") || source.starts_with("sshfs://")
}

/// A mounted network volume, unmounted on drop/`teardown`.
pub struct NetVolume {
    staging: String,
    /// `Some(url)` for a GVFS (`gio`) mount that is unmounted by URL; `None` for a FUSE mount
    /// (sshfs / mount.nfs) unmounted by path.
    gio_url: Option<String>,
}

/// Split a network `-v` spec `scheme://…:/container[:ro|:rw]` into (url, container, read_only).
/// The container mount point is the final `:`-segment (an absolute path); the URL keeps its own
/// internal colons (e.g. `sshfs://user@host:/remote`).
fn split_net_spec(spec: &str) -> Result<(&str, &str, bool), Error> {
    let (body, ro) = match spec.strip_suffix(":ro") {
        Some(b) => (b, true),
        None => (spec.strip_suffix(":rw").unwrap_or(spec), false),
    };
    let (url, container) = body
        .rsplit_once(':')
        .ok_or_else(|| Error::Sandbox(format!("-v '{spec}': network volume needs :/container")))?;
    // The container is the bind TARGET inside the box: absolute, no `.`/`..`/NUL — same rules the
    // local `-v` path enforces (the in-box `open_in_root` re-checks per-component; this is fail-fast).
    if !container.starts_with('/') {
        return Err(Error::Sandbox(format!(
            "-v '{spec}': container mount point must be an absolute path"
        )));
    }
    if container.contains('\0') || container.split('/').any(|c| c == "." || c == "..") {
        return Err(Error::Sandbox(format!(
            "-v '{spec}': container path must not contain '.', '..' or NUL"
        )));
    }
    Ok((url, container, ro))
}

/// Parse a network URL into (scheme, host, path). `sshfs://user@host:/path` keeps `user@host`.
fn parse_network_url(url: &str) -> Option<(NetScheme, &str, &str)> {
    let (scheme_str, rest) = url.split_once("://")?;
    let scheme = match scheme_str {
        "nfs" => NetScheme::Nfs,
        "smb" => NetScheme::Smb,
        "sshfs" => NetScheme::Sshfs,
        _ => return None,
    };
    let (host, path) = if scheme == NetScheme::Sshfs {
        if let Some(c) = rest.find(":/") {
            (&rest[..c], &rest[c + 1..])
        } else if let Some(s) = rest.find('/') {
            (&rest[..s], &rest[s..])
        } else {
            (rest, "/")
        }
    } else if let Some(s) = rest.find('/') {
        (&rest[..s], &rest[s..])
    } else {
        (rest, "/")
    };
    Some((scheme, host, path))
}

/// Reject control chars, whitespace and shell metacharacters in the host/path — these strings become
/// subprocess arguments (`sshfs`/`mount.nfs` via argv, no shell, but stay strict as defense-in-depth
/// and to keep a hostile URL out of a GVFS scan). Mirrors the private runtime.
fn validate_net(host: &str, path: &str) -> Result<(), Error> {
    for (label, val) in [("host", host), ("path", path)] {
        if val.is_empty() {
            return Err(Error::Sandbox(format!("network volume {label} is empty")));
        }
        // A leading `-` would be parsed by `sshfs`/`mount.nfs` as an OPTION, not a positional arg —
        // e.g. host `-oProxyCommand=…` = command injection. Refuse it (the path always starts `/`).
        if val.starts_with('-') {
            return Err(Error::Sandbox(format!(
                "network volume {label} must not start with '-'"
            )));
        }
        for &b in val.as_bytes() {
            let forbidden = b < 0x20 || b == 0x7f || b" `;|&$(){}[]'\"\\!*?<>\n\t".contains(&b);
            if forbidden {
                return Err(Error::Sandbox(format!(
                    "network volume {label} has a forbidden character 0x{b:02x}"
                )));
            }
        }
    }
    if !path.starts_with('/') {
        return Err(Error::Sandbox(
            "network volume path must start with '/'".into(),
        ));
    }
    Ok(())
}

fn net_staging(idx: usize) -> String {
    let uid = unsafe { libc::getuid() };
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("/run/user/{uid}"));
    format!("{base}/kern/mounts/net-{}-{idx}", std::process::id())
}

/// How long to wait for a network mount before giving up. `gio`/`sshfs` can hang indefinitely on an
/// unreachable server, so a mount that hasn't completed by now is killed and reported as failed.
const MOUNT_TIMEOUT_SECS: u64 = 25;

/// Run a mount command with a timeout: spawn, poll, and `kill` it if it hasn't finished in
/// `MOUNT_TIMEOUT_SECS` (so an unreachable server can't hang the box launch forever). Returns
/// whether it exited successfully in time.
fn run_mount(cmd: &mut std::process::Command) -> bool {
    // Silence the helper's own stdout/stderr: on failure kern prints one clean, actionable error
    // (e.g. "install gvfs-backends …"), so a raw `mount.nfs: failed to apply fstab options` leaking
    // to the terminal in front of it is just noise. kern owns the messaging.
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(MOUNT_TIMEOUT_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => return false,
        }
    }
}

/// Is `tool` on `PATH` and executable? `access(X_OK)`, no subprocess.
fn tool_exists(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p).any(|d| {
                let f = d.join(tool);
                std::ffi::CString::new(f.as_os_str().as_encoded_bytes())
                    .map(|c| unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0)
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Mount a network `-v` spec to a staging dir and return (source, container, read_only, handle) so
/// the caller can bind it into the box and tear it down after. Rootless via FUSE (sshfs) / GVFS
/// (gio); `mount.nfs` is a root fallback for NFS. Honest errors when the required tool is absent.
pub fn setup_network(spec: &str, idx: usize) -> Result<(String, String, bool, NetVolume), Error> {
    let (url, container, ro) = split_net_spec(spec)?;
    let (scheme, host, path) =
        parse_network_url(url).ok_or_else(|| Error::Sandbox(format!("-v '{spec}': bad URL")))?;
    validate_net(host, path)?;
    let staging = net_staging(idx);
    std::fs::create_dir_all(&staging)
        .map_err(|e| Error::Sandbox(format!("network staging dir: {e}")))?;

    let cleanup = |s: &str| {
        let _ = std::fs::remove_dir(s);
    };
    match scheme {
        NetScheme::Sshfs => {
            if !tool_exists("sshfs") {
                cleanup(&staging);
                return Err(Error::Sandbox(
                    "sshfs not installed (apt install sshfs / dnf install fuse-sshfs)".into(),
                ));
            }
            let ok = run_mount(
                std::process::Command::new("sshfs")
                    .args([
                        "-o",
                        "StrictHostKeyChecking=accept-new,reconnect,ServerAliveInterval=15",
                    ])
                    .arg(format!("{host}:{path}"))
                    .arg(&staging),
            );
            if !ok {
                cleanup(&staging);
                return Err(Error::Sandbox(format!("sshfs mount of {url} failed")));
            }
            Ok((
                staging.clone(),
                container.to_string(),
                ro,
                NetVolume {
                    staging,
                    gio_url: None,
                },
            ))
        }
        NetScheme::Nfs | NetScheme::Smb => {
            // Rootless via GVFS: `gio mount` then find the mount under $XDG_RUNTIME_DIR/gvfs.
            if tool_exists("gio")
                && run_mount(std::process::Command::new("gio").args(["mount", url]))
            {
                if let Some(gvfs) = find_gvfs_mount(scheme, host) {
                    cleanup(&staging);
                    return Ok((
                        gvfs,
                        container.to_string(),
                        ro,
                        NetVolume {
                            staging: String::new(),
                            gio_url: Some(url.to_string()),
                        },
                    ));
                }
                let _ = std::process::Command::new("gio")
                    .args(["mount", "-u", url])
                    .status();
            }
            // NFS root fallback: mount.nfs (needs privilege).
            if scheme == NetScheme::Nfs
                && tool_exists("mount.nfs")
                && run_mount(std::process::Command::new("mount.nfs").args([
                    &format!("{host}:{path}"),
                    &staging,
                    "-o",
                    "vers=4.2,tcp,nolock",
                ]))
            {
                return Ok((
                    staging.clone(),
                    container.to_string(),
                    ro,
                    NetVolume {
                        staging,
                        gio_url: None,
                    },
                ));
            }
            cleanup(&staging);
            Err(Error::Sandbox(format!(
                "{} mount of {url} failed — install gvfs-backends (gio){}",
                if scheme == NetScheme::Nfs {
                    "NFS"
                } else {
                    "SMB"
                },
                if scheme == NetScheme::Nfs {
                    " or ensure mount.nfs works"
                } else {
                    ""
                }
            )))
        }
    }
}

/// Locate a just-created GVFS mount for (scheme, host) under `$XDG_RUNTIME_DIR/gvfs`.
fn find_gvfs_mount(scheme: NetScheme, host: &str) -> Option<String> {
    let uid = unsafe { libc::getuid() };
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("/run/user/{uid}"));
    let (prefix, key) = match scheme {
        NetScheme::Nfs => ("nfs:", format!("host={host}")),
        NetScheme::Smb => ("smb-share:", format!("server={host}")),
        NetScheme::Sshfs => return None,
    };
    std::fs::read_dir(format!("{base}/gvfs"))
        .ok()?
        .flatten()
        .find_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            // GVFS names are `nfs:host=X,export=Y` — match `host=X` as a whole comma-delimited field
            // so `host=server` can't spuriously match `host=server.example`.
            let hit = n
                .strip_prefix(prefix)
                .is_some_and(|fields| fields.split(',').any(|f| f == key));
            hit.then(|| e.path().to_string_lossy().into_owned())
        })
}

/// Safety net for an error path (a `?` after the mount) that doesn't `exit` — the success path
/// unmounts explicitly before `std::process::exit` (which skips destructors), and `teardown` is
/// idempotent, so both are needed and safe together.
impl Drop for NetVolume {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl NetVolume {
    /// Unmount the network volume and remove its staging dir. Idempotent, best-effort.
    pub fn teardown(&self) {
        if let Some(url) = &self.gio_url {
            let _ = std::process::Command::new("gio")
                .args(["mount", "-u", url])
                .status();
        } else if !self.staging.is_empty() {
            // FUSE (sshfs) → fusermount3 -u; falls back to fusermount.
            let unmounted = std::process::Command::new("fusermount3")
                .args(["-u", &self.staging])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !unmounted {
                let _ = std::process::Command::new("fusermount")
                    .args(["-u", &self.staging])
                    .status();
            }
            let _ = std::fs::remove_dir(&self.staging);
        }
    }
}

/// `kern volume <create|ls|rm|inspect|prune> …`.
pub fn run(args: &[String]) -> Result<(), Error> {
    match args.first().map(String::as_str) {
        Some("create" | "c") => create(&args[1..]),
        Some("ls" | "list") => list(),
        Some("rm" | "remove" | "delete") => remove(&args[1..]),
        Some("inspect" | "show") => inspect(args.get(1)),
        Some("edit") => edit_cmd(&args[1..]),
        Some("prune") => prune(),
        None | Some("-h" | "--help" | "help") => {
            usage();
            Ok(())
        }
        Some(other) => Err(Error::Volume(format!(
            "unknown `volume` subcommand '{other}' (create/ls/rm/inspect/edit/prune)"
        ))),
    }
}

fn create(args: &[String]) -> Result<(), Error> {
    let (mut name, mut size): (Option<&str>, Option<u64>) = (None, None);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--size" | "-s" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or(Error::Usage("volume create <name> --size <N>"))?;
                size = Some(parse_size(v)?);
            }
            s if !s.starts_with('-') && name.is_none() => name = Some(s),
            _ => return Err(Error::Usage("volume create <name> [--size <N>]")),
        }
        i += 1;
    }
    let name = name.ok_or(Error::Usage("volume create <name> [--size <N>]"))?;
    validate(name)?;
    let vol = volumes_dir().join(name);
    std::fs::create_dir_all(vol.join("data"))
        .map_err(|e| Error::Volume(format!("cannot create volume '{name}': {e}")))?;
    let created = crate::registry::now_unix();
    let meta = match size {
        Some(n) => format!("{{\"created\":{created},\"size_limit\":{n}}}"),
        None => format!("{{\"created\":{created}}}"),
    };
    let _ = std::fs::write(vol.join("meta.json"), meta);
    println!("{name}");
    Ok(())
}

/// Rename and/or re-quota an existing volume. `new_name == orig` keeps the name; `size = None` clears
/// the quota, `Some(0)` is rejected upstream (a 0-byte quota is meaningless). Shared by the TUI's
/// Storage-tab edit and `kern volume edit`. A rename refuses an in-use volume (its bind mount would
/// break) and won't clobber an existing name; the data dir is preserved (only the folder is moved and
/// `meta.json` rewritten). Race-free vs. a starting box the same way `remove` is (register-before-mount).
pub fn edit(orig: &str, new_name: &str, size: Option<u64>) -> Result<(), Error> {
    validate(orig)?;
    validate(new_name)?;
    let dir = volumes_dir();
    if !dir.join(orig).join("data").is_dir() {
        return Err(Error::Volume(format!("no volume named '{orig}'")));
    }
    if new_name != orig {
        if let Some(b) = crate::registry::list()
            .iter()
            .find(|b| b.volume_names().any(|v| v == orig))
        {
            return Err(Error::AlreadyRunning(format!(
                "volume '{orig}' is in use by box '{}' — stop it first",
                b.name
            )));
        }
        if dir.join(new_name).join("data").is_dir() {
            return Err(Error::Volume(format!(
                "a volume named '{new_name}' already exists"
            )));
        }
        std::fs::rename(dir.join(orig), dir.join(new_name))
            .map_err(|e| Error::Volume(format!("cannot rename volume '{orig}': {e}")))?;
    }
    // Rewrite meta.json, preserving `created`; set/clear the quota.
    let vol = dir.join(new_name);
    let created = std::fs::read_to_string(vol.join("meta.json"))
        .ok()
        .and_then(|m| json_u64(&m, "created"))
        .unwrap_or_else(crate::registry::now_unix);
    let meta = match size {
        Some(n) => format!("{{\"created\":{created},\"size_limit\":{n}}}"),
        None => format!("{{\"created\":{created}}}"),
    };
    std::fs::write(vol.join("meta.json"), meta)
        .map_err(|e| Error::Volume(format!("cannot write volume metadata: {e}")))?;
    Ok(())
}

/// `kern volume edit <name> [--name NEW] [--size SIZE|--size 0=clear]` — CLI twin of the TUI edit.
fn edit_cmd(args: &[String]) -> Result<(), Error> {
    const U: &str = "volume edit <name> [--name NEW] [--size N|0=clear]";
    let orig = args
        .first()
        .filter(|s| !s.starts_with('-'))
        .ok_or(Error::Usage(U))?;
    let (mut new_name, mut size, mut size_set) = (orig.clone(), None, false);
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--name" | "-n" => {
                i += 1;
                new_name = args.get(i).ok_or(Error::Usage(U))?.clone();
            }
            "--size" | "-s" => {
                i += 1;
                let v = args.get(i).ok_or(Error::Usage(U))?;
                size_set = true;
                // `--size 0` clears the quota; anything else parses as a size.
                size = if v == "0" { None } else { Some(parse_size(v)?) };
            }
            _ => return Err(Error::Usage(U)),
        }
        i += 1;
    }
    if new_name == *orig && !size_set {
        return Err(Error::Volume(
            "nothing to change (pass --name and/or --size)".into(),
        ));
    }
    // If `--size` wasn't given, KEEP the current quota — a rename must never silently drop it.
    let final_size = if size_set { size } else { size_limit(orig) };
    edit(orig, &new_name, final_size)?;
    let p = crate::ui::Palette::detect();
    println!("{}updated{} {new_name}", p.g, p.z);
    Ok(())
}

/// Parse a named-volume `-v` spec `name:/dest[:ro|:rw]` → (name, dest, read_only). The dest is an
/// absolute, `.`/`..`-free path (the in-box `open_in_root` re-checks; this is fail-fast).
pub fn parse_named_spec(spec: &str) -> Result<(&str, String, bool), Error> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (name, dest, ro) = match parts.as_slice() {
        [n, d] => (*n, *d, false),
        [n, d, "ro"] => (*n, *d, true),
        [n, d, "rw"] => (*n, *d, false),
        _ => {
            return Err(Error::Sandbox(format!(
                "bad -v '{spec}' (expected name:/dest[:ro])"
            )))
        }
    };
    validate(name)?;
    if !dest.starts_with('/')
        || dest.split('/').any(|c| c == "." || c == "..")
        || dest.contains('\0')
    {
        return Err(Error::Sandbox(format!(
            "-v '{spec}': target must be an absolute path without '.'/'..'/NUL"
        )));
    }
    Ok((name, dest.to_string(), ro))
}

/// Upper bound on a vdisk/quota image, to reject an absurd (or hand-edited) size before it reaches
/// `File::set_len` + `mkfs.ext4` — a multi-EB sparse image would churn `mkfs` writing fs metadata.
/// 64 TiB is far above any legitimate rootless volume yet fences off the pathological values.
pub const MAX_VDISK_BYTES: u64 = 64 << 40;

/// The `size_limit` (bytes) recorded for a named volume, or `None` if unset. A quota'd volume is
/// backed by an ext4-loop image (real disk quota) when mounted privileged; otherwise the plain data
/// dir is used and the quota is not enforced (kern says so). The name is validated first (so this
/// can't probe outside the volumes dir), and the recorded value is re-clamped to `MAX_VDISK_BYTES`
/// in case `meta.json` was hand-edited past the `create`-time check.
pub fn size_limit(name: &str) -> Option<u64> {
    validate(name).ok()?;
    let meta = std::fs::read_to_string(volumes_dir().join(name).join("meta.json")).ok()?;
    let n = json_u64(&meta, "size_limit")?;
    (n > 0 && n <= MAX_VDISK_BYTES).then_some(n)
}

/// Read an unsigned-integer value for `key` out of our small hand-written `meta.json`. Matches the
/// key only at a JSON structural boundary (`{`/`,`/whitespace before the opening quote), so a stray
/// `"size_limit":…` sitting inside some *other* string value can't be misread as the quota.
fn json_u64(s: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let bytes = s.as_bytes();
    let mut from = 0;
    while let Some(rel) = s[from..].find(&needle) {
        let at = from + rel;
        let boundary =
            at == 0 || matches!(bytes[at - 1], b'{' | b',' | b' ' | b'\t' | b'\n' | b'\r');
        if boundary {
            let digits: String = s[at + needle.len()..]
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                return digits.parse().ok();
            }
        }
        from = at + needle.len();
    }
    None
}

/// Parse a binary size (`512m`, `2g`, `1048576`) into bytes, capped at [`MAX_VDISK_BYTES`]. Shares
/// the parse with the rest of kern ([`kern_common::parse_binary_size`]); this layers the volume cap
/// and the `--size` usage error on top.
fn parse_size(s: &str) -> Result<u64, Error> {
    kern_common::parse_binary_size(s)
        .filter(|b| *b <= MAX_VDISK_BYTES)
        .ok_or(Error::Usage(
            "--size <N>[k|m|g|t] (e.g. 512m, 2g), up to 64t",
        ))
}

/// A named volume for the `kern top` Volumes tab.
pub(crate) struct VolInfo {
    pub name: String,
    /// Bytes used by the volume's `data/` dir.
    pub size: u64,
    /// Quota (bytes) from `meta.json`, if one was set at create time.
    pub quota: Option<u64>,
}

/// The named volumes on disk, sorted by name — same `meta.json`-sidecar detection as `volume ls`.
/// Used by the TUI, which needs the data structured rather than printed.
pub(crate) fn entries() -> Vec<VolInfo> {
    let dir = volumes_dir();
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            let p = e.path();
            // A single read of meta.json both identifies a real volume (its presence) AND yields the
            // quota — no separate `is_file()` stat before the read.
            let Ok(meta) = std::fs::read_to_string(p.join("meta.json")) else {
                continue;
            };
            let Some(name) = e.file_name().to_str().map(crate::ui::scrub) else {
                continue;
            };
            let quota = json_u64(&meta, "size_limit").filter(|n| *n > 0 && *n <= MAX_VDISK_BYTES);
            out.push(VolInfo {
                name,
                size: dir_size(&p.join("data")),
                quota,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn list() -> Result<(), Error> {
    let p = crate::ui::Palette::detect();
    // Same `meta.json`-sidecar detection, scrubbing and sort as the TUI — one scanner, `entries()`.
    // SIZE is the data actually stored; QUOTA is the cap set at create (`--size`), shown so an empty
    // volume with a quota reads as `0 B / 2.0G` instead of a bare, confusing `0 B`.
    println!(
        "{d}{:<28} {:>10} {:>10}{z}",
        "NAME",
        "SIZE",
        "QUOTA",
        d = p.d,
        z = p.z
    );
    for v in entries() {
        let quota = v.quota.map_or_else(|| "-".to_string(), human_bytes);
        println!(
            "{b}{c}{:<28}{z} {:>10} {d}{:>10}{z}",
            v.name,
            human_bytes(v.size),
            quota,
            b = p.b,
            c = p.c,
            d = p.d,
            z = p.z
        );
    }
    Ok(())
}

fn remove(names: &[String]) -> Result<(), Error> {
    if names.is_empty() {
        return Err(Error::Usage("volume rm <name>..."));
    }
    // Snapshot the running boxes once. Each box records the named volumes it mounts in the registry
    // BEFORE mounting them, so this in-use scan is race-free. Refusing an in-use volume is Docker's
    // behaviour — deleting it would pull the box's bind mount out from under it.
    let running = crate::registry::list();
    let user_of = |name: &str| {
        running
            .iter()
            .find(|b| b.volume_names().any(|v| v == name))
            .map(|b| b.name.clone())
    };
    let dir = volumes_dir();
    // Process every requested name independently (like `docker volume rm a b c`): remove what we can,
    // collect the rest, and exit non-zero if any failed — never stop at the first problem. Removed
    // names go to stdout; the failures become one error (a single clean line for a single volume, a
    // bulleted list for several), with a hint chosen by cause — boxes only when something is in use.
    let mut fails: Vec<String> = Vec::new();
    let mut any_in_use = false;
    for name in names {
        if let Err(e) = validate(name) {
            fails.push(e.to_string()); // reuse validate's exact wording (parity with create/inspect)
        } else if !dir.join(name).join("data").is_dir() {
            fails.push(format!("no volume named '{name}'"));
        } else if let Some(box_name) = user_of(name) {
            any_in_use = true;
            fails.push(format!(
                "volume '{name}' is in use by box '{box_name}' — stop it first"
            ));
        } else if let Err(e) = std::fs::remove_dir_all(dir.join(name)) {
            fails.push(format!("cannot remove volume '{name}': {e}"));
        } else {
            println!("{name}");
        }
    }
    match fails.len() {
        0 => Ok(()),
        1 if any_in_use => Err(Error::AlreadyRunning(fails.remove(0))),
        1 => Err(Error::Volume(fails.remove(0))),
        n => {
            let msg = format!("{n} volume(s) not removed:\n  {}", fails.join("\n  "));
            Err(if any_in_use {
                Error::AlreadyRunning(msg)
            } else {
                Error::Volume(msg)
            })
        }
    }
}

fn inspect(name: Option<&String>) -> Result<(), Error> {
    let name = name.ok_or(Error::Usage("volume inspect <name>"))?;
    validate(name)?;
    let vol = volumes_dir().join(name);
    let data = vol.join("data");
    if !data.is_dir() {
        return Err(Error::Volume(format!("no volume named '{name}'")));
    }
    let p = crate::ui::Palette::detect();
    let row = |k: &str, v: &str| println!("{d}{k:<8}{z} {v}", d = p.d, z = p.z);
    println!("{}{}{}{}", p.b, p.c, name, p.z);
    row("path", &data.to_string_lossy());
    row("size", &human_bytes(dir_size(&data)));
    match size_limit(name) {
        Some(n) => row(
            "quota",
            &format!("{} (ext4-loop when mounted as root)", human_bytes(n)),
        ),
        None => row("quota", "none"),
    }
    Ok(())
}

fn prune() -> Result<(), Error> {
    // Remove EMPTY volumes only (nothing written) — conservative; a non-empty volume is never
    // deleted implicitly.
    let dir = volumes_dir();
    // Named volumes a running box still mounts — never prune these out from under a box.
    let in_use = crate::registry::volumes_in_use();
    let mut removed = 0usize;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let data = e.path().join("data");
            if data.is_dir()
                && dir_size(&data) == 0
                && !in_use.contains(&name)
                && std::fs::remove_dir_all(e.path()).is_ok()
            {
                removed += 1;
            }
        }
    }
    let p = crate::ui::Palette::detect();
    if removed == 0 {
        println!("{}no empty volumes to prune{}", p.d, p.z);
    } else {
        let s = if removed == 1 { "volume" } else { "volumes" };
        println!("{}pruned{} {removed} empty {s}", p.g, p.z);
    }
    Ok(())
}

fn usage() {
    let p = crate::ui::Palette::detect();
    let c = p.c;
    let z = p.z;
    println!(
        "\
{b}kern volume{z} — named persistent volumes

    {c}create{z} <name>       Create a volume (also auto-created by `-v name:/dest`)
    {c}ls{z}                  List volumes with sizes
    {c}inspect{z} <name>      Show a volume's path, size and metadata
    {c}edit{z} <name> [--name NEW] [--size N|0]   Rename and/or re-quota a volume
    {c}rm{z} <name>...        Remove volume(s)
    {c}prune{z}               Remove empty volumes

Use a volume:  kern box web --image alpine -v data:/var/lib/app",
        b = p.b,
        c = c,
        z = z
    );
}

/// Recursive on-disk size of a directory (bytes), symlink-safe (never follows out).
fn dir_size(path: &std::path::Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(md) = e.metadata() else { continue }; // metadata() does not follow symlinks here
            if md.is_dir() {
                stack.push(e.path());
            } else {
                total += md.len();
            }
        }
    }
    total
}

/// Human-readable byte size — the shared [`kern_common::fmt_bytes`] convention (one for the whole CLI).
fn human_bytes(b: u64) -> String {
    kern_common::fmt_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    // `XDG_DATA_HOME` is process-global; serialize the tests that mutate it so parallel runs don't
    // clobber each other's value.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn is_named_distinguishes_names_from_paths_and_urls() {
        assert!(is_named("data"));
        assert!(is_named("my-vol_1"));
        assert!(!is_named("/host/path")); // absolute path
        assert!(!is_named("sshfs://h/p")); // network URL
        assert!(!is_named("nfs://h/x"));
        assert!(!is_named("")); // empty
    }

    #[test]
    fn validate_rejects_traversal_and_bad_names() {
        assert!(validate("data").is_ok());
        assert!(validate("a.b-c_1").is_ok());
        for bad in [
            "", ".", "..", "-x", ".hidden", "a/b", "a/../b", "a b", "a\0b",
        ] {
            assert!(validate(bad).is_err(), "'{bad}' must be rejected");
        }
        // a 65-char name is too long.
        assert!(validate(&"a".repeat(65)).is_err());
    }

    #[test]
    fn resolve_named_auto_creates_under_the_data_home() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("kern-voltest-{}", std::process::id()));
        std::env::set_var("XDG_DATA_HOME", &tmp);
        let path = resolve_named("unit_vol").unwrap();
        assert!(path.ends_with("kern/volumes/unit_vol/data"));
        assert!(
            std::path::Path::new(&path).is_dir(),
            "data dir auto-created"
        );
        assert!(tmp.join("kern/volumes/unit_vol/meta.json").exists());
        // a traversal name never resolves.
        assert!(resolve_named("../evil").is_err());
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::remove_var("XDG_DATA_HOME");
    }

    #[test]
    fn is_network_detects_schemes() {
        assert!(is_network("nfs://h/x"));
        assert!(is_network("smb://h/s"));
        assert!(is_network("sshfs://u@h:/p"));
        assert!(!is_network("data")); // named
        assert!(!is_network("/host/path")); // host path
    }

    #[test]
    fn parse_and_split_network_specs() {
        // nfs://host/export:/container
        let (url, cont, ro) = split_net_spec("nfs://server/export:/data").unwrap();
        assert_eq!((url, cont, ro), ("nfs://server/export", "/data", false));
        let (s, h, p) = parse_network_url(url).unwrap();
        assert!(s == NetScheme::Nfs && h == "server" && p == "/export");

        // sshfs keeps its internal `user@host:/remote`, container is the final segment.
        let (url, cont, ro) = split_net_spec("sshfs://me@host:/remote:/mnt:ro").unwrap();
        assert_eq!((url, cont, ro), ("sshfs://me@host:/remote", "/mnt", true));
        let (s, h, p) = parse_network_url(url).unwrap();
        assert!(s == NetScheme::Sshfs && h == "me@host" && p == "/remote");

        // a non-absolute or traversal container is refused (fail-fast; box re-checks too).
        assert!(split_net_spec("nfs://h/x:relative").is_err());
        assert!(split_net_spec("nfs://h/x:/../etc").is_err());
    }

    #[test]
    fn validate_net_blocks_injection() {
        assert!(validate_net("host.example", "/export").is_ok());
        assert!(validate_net("user@host", "/p").is_ok());
        for bad in [
            "h;rm",
            "h|x",
            "h`x`",
            "h$(x)",
            "h&x",
            "h x",
            "h\nx",
            "h'x",
            "-oProxyCommand=evil",
        ] {
            assert!(
                validate_net(bad, "/p").is_err(),
                "host '{bad}' must be rejected"
            );
        }
        assert!(validate_net("h", "relative").is_err()); // path must be absolute
        assert!(validate_net("", "/p").is_err()); // empty host
    }

    #[test]
    fn parse_size_binary_units() {
        assert_eq!(parse_size("512m").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("2g").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1048576").unwrap(), 1048576);
        assert!(parse_size("huge").is_err());
        assert!(parse_size("0").is_err());
        // Upper bound (F2): the max is accepted, one past it and an absurd EB value are rejected.
        assert_eq!(parse_size("64t").unwrap(), MAX_VDISK_BYTES);
        assert!(parse_size("65t").is_err());
        assert!(parse_size("18000000000000000000").is_err());
    }

    #[test]
    fn json_u64_matches_key_only_at_a_boundary() {
        // Real top-level key.
        assert_eq!(
            json_u64("{\"created\":1,\"size_limit\":2048}", "size_limit"),
            Some(2048)
        );
        // Absent key.
        assert_eq!(json_u64("{\"created\":1}", "size_limit"), None);
        // The literal sitting inside another string value must NOT be picked up (no leading delimiter).
        assert_eq!(
            json_u64("{\"note\":\"x\\\"size_limit\\\":999\"}", "size_limit"),
            None
        );
    }

    #[test]
    fn size_limit_rejects_bad_name_and_out_of_range() {
        // A traversing name never reaches the filesystem read.
        assert_eq!(size_limit("../etc"), None);
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("kern-qclamp-{}", std::process::id()));
        std::env::set_var("XDG_DATA_HOME", &tmp);
        // A hand-edited meta.json past the ceiling is re-clamped away (treated as unset).
        let vol = volumes_dir().join("huge");
        std::fs::create_dir_all(vol.join("data")).unwrap();
        std::fs::write(
            vol.join("meta.json"),
            "{\"created\":1,\"size_limit\":99999999999999999}",
        )
        .unwrap();
        assert_eq!(size_limit("huge"), None);
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::remove_var("XDG_DATA_HOME");
    }

    #[test]
    fn edit_renames_requotas_and_guards() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("kern-edittest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::set_var("XDG_DATA_HOME", &tmp);
        let g2 = 2 * 1024 * 1024 * 1024;
        resolve_named("v1").unwrap();
        // Set a quota (no rename).
        edit("v1", "v1", Some(g2)).unwrap();
        assert_eq!(size_limit("v1"), Some(g2));
        // Rename v1 → v2, keeping the quota; old name gone, data preserved.
        edit("v1", "v2", Some(g2)).unwrap();
        assert!(volumes_dir().join("v2").join("data").is_dir());
        assert!(
            !volumes_dir().join("v1").exists(),
            "old name gone after rename"
        );
        assert_eq!(size_limit("v2"), Some(g2));
        // Clear the quota.
        edit("v2", "v2", None).unwrap();
        assert_eq!(size_limit("v2"), None);
        // Rename onto an existing name is refused; editing a nonexistent volume errors.
        resolve_named("taken").unwrap();
        assert!(edit("v2", "taken", None).is_err());
        assert!(edit("ghost", "ghost", None).is_err());
        // Regression: a CLI rename WITHOUT --size must KEEP the quota (not silently drop it).
        resolve_named("q").unwrap();
        edit("q", "q", Some(g2)).unwrap();
        run(&["edit".into(), "q".into(), "--name".into(), "qq".into()]).unwrap();
        assert_eq!(size_limit("qq"), Some(g2), "rename-only kept the quota");
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::remove_var("XDG_DATA_HOME");
    }

    #[test]
    fn parse_named_spec_and_size_limit_roundtrip() {
        assert_eq!(
            parse_named_spec("data:/work").unwrap(),
            ("data", "/work".to_string(), false)
        );
        assert_eq!(
            parse_named_spec("data:/work:ro").unwrap(),
            ("data", "/work".to_string(), true)
        );
        assert!(parse_named_spec("data:relative").is_err());
        assert!(parse_named_spec("data:/a/../b").is_err());
        assert!(parse_named_spec("../evil:/w").is_err());

        // create --size records a quota that size_limit reads back.
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("kern-qtest-{}", std::process::id()));
        std::env::set_var("XDG_DATA_HOME", &tmp);
        create(&[
            "quotavol".to_string(),
            "--size".to_string(),
            "2g".to_string(),
        ])
        .unwrap();
        assert_eq!(size_limit("quotavol"), Some(2 * 1024 * 1024 * 1024));
        create(&["plainvol".to_string()]).unwrap();
        assert_eq!(size_limit("plainvol"), None);
        let _ = std::fs::remove_dir_all(&tmp);
        std::env::remove_var("XDG_DATA_HOME");
    }
}
