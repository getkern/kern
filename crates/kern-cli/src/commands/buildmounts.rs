//! What a `RUN --mount=...` needs that the Dockerfile cannot carry: the build's secrets and SSH
//! agents, the persistent cache directories, and the per-step plumbing that hands each to the one
//! RUN that asked for it.
//!
//! EVERY MOUNT REACHES THE STEP'S BOX AS A BIND (or a tmpfs), so the one code path that already
//! confines and cleans up a `type=bind` mount carries the other four as well: `drop_mountpoints`
//! removes their stand-ins from the layer, and nothing here writes into the image.
//!
//! BuildKit's semantics, MEASURED with buildx v0.39.0 before this was written (busybox, alpine):
//! a secret is `/run/secrets/<id>`, mode 0400, owner 0:0; `env=` alone gives the variable and no
//! file; `uid=`/`mode=` are honoured; a missing secret is no mount at all unless `required=true`,
//! which fails with "secret <id>: not found". An SSH agent is a socket at
//! `/run/buildkit/ssh_agent.<n>`, mode 0600, owner 0:0, with `SSH_AUTH_SOCK` set to it; a non-root
//! `USER` gets "Permission denied" from it unless `uid=` says otherwise. A cache directory is mode
//! 0755, owner 0:0, kept between builds (1, 2, 3 lines across three builds), and `--no-cache` starts
//! it empty. A tmpfs is a real tmpfs. None of them leaves anything in the image.

use crate::dockerfile::{CacheSharing, MountKind, RunMount};
use crate::error::Error;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Where one build secret comes from (`kern build --secret id=...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SecretSource {
    /// `src=<file>`: read when a step mounts it.
    File(PathBuf),
    /// `env=<VAR>`: the caller's variable, read when a step mounts it.
    Env(String),
}

/// Where one build SSH agent comes from (`kern build --ssh id[=...]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SshSource {
    /// A running agent's socket (`default` is `$SSH_AUTH_SOCK`).
    Socket(PathBuf),
    /// Private key files, loaded into an agent kern starts for this build.
    Keys(Vec<PathBuf>),
}

/// The inputs of this build process, set once by `kern build` before the first step.
#[derive(Debug, Default)]
pub(crate) struct BuildInputs {
    secrets: HashMap<String, SecretSource>,
    ssh: HashMap<String, SshSource>,
    no_cache: bool,
}

static INPUTS: std::sync::OnceLock<BuildInputs> = std::sync::OnceLock::new();

/// Agents kern started for `--ssh id=<key>`, by id: (process, socket). Stopped by [`finish_build`].
static AGENTS: std::sync::Mutex<Vec<(String, std::process::Child, PathBuf)>> =
    std::sync::Mutex::new(Vec::new());

/// Cache ids this build has already started empty under `--no-cache`, so a second RUN using the same
/// cache sees the first one's work, as BuildKit's does.
static RESET_CACHES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn inputs() -> &'static BuildInputs {
    INPUTS.get_or_init(BuildInputs::default)
}

/// Record this build's `--secret`, `--ssh` and `--no-cache`. Once per process: a `kern build` is one
/// build, and every stage of a multi-stage build runs in it.
pub(crate) fn set_build_inputs(
    secrets: &[String],
    ssh: &[String],
    no_cache: bool,
) -> Result<(), Error> {
    let mut b = BuildInputs {
        no_cache,
        ..Default::default()
    };
    for s in secrets {
        let (id, src) = parse_secret_spec(s)?;
        b.secrets.insert(id, src);
    }
    for s in ssh {
        let (id, src) = parse_ssh_spec(s)?;
        b.ssh.insert(id, src);
    }
    let _ = INPUTS.set(b);
    Ok(())
}

/// Whether this build was asked not to reuse anything (`--no-cache`).
pub(crate) fn no_cache() -> bool {
    inputs().no_cache
}

/// `--secret id=<id>[,src=<file>|,env=<VAR>][,type=file|env]`, docker's grammar.
///
/// With neither `src=` nor `env=` the id names both, and the VARIABLE wins when it is set: MEASURED
/// with buildx v0.39.0, `--secret id=MYTOK` read `$MYTOK` when it was set and the file `./MYTOK`
/// when it was not.
pub(crate) fn parse_secret_spec(spec: &str) -> Result<(String, SecretSource), Error> {
    let mut id = None;
    let mut src = None;
    let mut env = None;
    let mut typ = None;
    // CSV, as docker reads `--secret` and as `--mount` is read here: a quoted field carries a comma,
    // so a path holding one is one field and can never open a second `src=`.
    for f in crate::cli::csv_fields(spec)?
        .iter()
        .map(|f| f.trim())
        .filter(|f| !f.is_empty())
    {
        let (k, v) = f.split_once('=').ok_or(Error::Usage(
            "--secret id=<id>[,src=<file>|,env=<VAR>][,type=file|env]",
        ))?;
        match k {
            "id" => id = Some(v.to_string()),
            "src" | "source" => src = Some(v.to_string()),
            "env" => env = Some(v.to_string()),
            "type" => typ = Some(v.to_string()),
            other => {
                return Err(Error::Build(format!(
                    "--secret {spec}: unknown field `{other}` (id, src, env, type)"
                )))
            }
        }
    }
    let id = id
        .filter(|i| !i.is_empty())
        .ok_or_else(|| Error::Build(format!("--secret {spec}: needs an `id=`")))?;
    if id.contains('/') {
        return Err(Error::Build(format!(
            "--secret {spec}: an id is a name, not a path"
        )));
    }
    let source = match (src, env, typ.as_deref()) {
        (Some(_), Some(_), _) => {
            return Err(Error::Build(format!(
                "--secret {spec}: `src=` and `env=` name two sources; give one"
            )))
        }
        (Some(s), None, None | Some("file")) => SecretSource::File(PathBuf::from(s)),
        (None, Some(e), None | Some("env")) => SecretSource::Env(e),
        (None, None, Some("env")) => SecretSource::Env(id.clone()),
        (None, None, Some("file")) => SecretSource::File(PathBuf::from(&id)),
        (None, None, None) => {
            if crate::global_env_str(&id).is_ok() {
                SecretSource::Env(id.clone())
            } else {
                SecretSource::File(PathBuf::from(&id))
            }
        }
        (_, _, Some(t)) => {
            return Err(Error::Build(format!(
                "--secret {spec}: `type={t}` does not match the source given (file or env)"
            )))
        }
    };
    Ok((id, source))
}

/// `--ssh default|<id>[=<socket>|<key>[,<key>...]]`, docker's grammar. An id with no value is the
/// caller's own agent, `$SSH_AUTH_SOCK`.
pub(crate) fn parse_ssh_spec(spec: &str) -> Result<(String, SshSource), Error> {
    let (id, paths) = match spec.split_once('=') {
        Some((id, rest)) => (id.trim().to_string(), rest),
        None => (spec.trim().to_string(), ""),
    };
    if id.is_empty() {
        return Err(Error::Usage("--ssh default|<id>[=<socket>|<key>[,<key>]]"));
    }
    if paths.trim().is_empty() {
        let sock = crate::global_env_str("SSH_AUTH_SOCK").map_err(|_| {
            Error::Build(format!(
                "--ssh {spec}: no agent to forward - SSH_AUTH_SOCK is not set. Start one \
                 (`eval $(ssh-agent)` and `ssh-add`) or name a key: --ssh {id}=~/.ssh/id_ed25519"
            ))
        })?;
        return Ok((id, SshSource::Socket(PathBuf::from(sock))));
    }
    let paths: Vec<PathBuf> = paths
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect();
    let is_socket = |p: &Path| {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
    };
    match paths.as_slice() {
        [one] if is_socket(one) => Ok((id, SshSource::Socket(one.clone()))),
        _ => {
            for p in &paths {
                if !p.is_file() {
                    return Err(Error::Build(format!(
                        "--ssh {spec}: {} is neither an agent socket nor a key file",
                        p.display()
                    )));
                }
            }
            Ok((id, SshSource::Keys(paths)))
        }
    }
}

/// Stop what this build started (the key agents). Called once when `kern build` ends, whatever the
/// outcome.
pub(crate) fn finish_build() {
    if let Ok(mut agents) = AGENTS.lock() {
        for (_, child, sock) in agents.iter_mut() {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(dir) = sock.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
        agents.clear();
    }
}

/// What one RUN step receives from its mounts, and what must be released when it ends.
#[derive(Default)]
pub(crate) struct StepMounts {
    /// `(host source, box target, read-only)`: bind mounts, secrets and caches among them.
    pub binds: Vec<(String, String, bool)>,
    /// Box targets that get an empty tmpfs.
    pub tmpfs: Vec<String>,
    /// `(host socket, box target)`: SSH agent sockets.
    pub sockets: Vec<(String, String)>,
    /// Variables the command runs with: secrets asked for with `env=`, and `SSH_AUTH_SOCK`.
    pub env: Vec<(String, String)>,
    holds: Vec<Hold>,
}

/// Something a step holds until it ends.
enum Hold {
    /// A cache's lock, released by dropping the file.
    Lock(#[allow(dead_code)] std::fs::File),
    /// A private directory of this step (secret files, proxy sockets), removed when it ends.
    Dir(PathBuf),
    /// An SSH agent proxy, stopped when the step ends.
    Proxy(std::process::Child),
}

impl StepMounts {
    /// Every box path this step's mounts occupy, for `drop_mountpoints`.
    pub(crate) fn targets(&self) -> Vec<(String, String, bool)> {
        let mut all = self.binds.clone();
        all.extend(self.tmpfs.iter().map(|t| (String::new(), t.clone(), false)));
        all.extend(
            self.sockets
                .iter()
                .map(|(s, t)| (s.clone(), t.clone(), false)),
        );
        all
    }
}

impl Drop for StepMounts {
    fn drop(&mut self) {
        // Proxies first: they hold sockets inside the directories removed after them.
        for h in self.holds.iter_mut() {
            if let Hold::Proxy(child) = h {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        for h in &self.holds {
            if let Hold::Dir(d) = h {
                if std::fs::remove_dir_all(d).is_err() {
                    // A secret given to a non-root uid is owned by a subordinate uid.
                    let _ = crate::commands::remove_tree_mapped(d);
                }
            }
        }
    }
}

/// The absolute box path of a mount target, relative ones taken from the `WORKDIR` as BuildKit does.
fn box_target(target: &str, config: &kern_oci::ImageConfig) -> String {
    if target.starts_with('/') {
        target.to_string()
    } else {
        format!(
            "{}/{}",
            config
                .workdir
                .as_deref()
                .unwrap_or("/")
                .trim_end_matches('/'),
            target
        )
    }
}

/// Give `path` an owner and mode IN THE BOX'S ID MAP (uid N there is a subordinate id here), the
/// way `own_created_dirs` gives a WORKDIR its user. With 0:0 there is nothing to map: the caller is
/// the box's root.
fn own_in_box(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::Build(format!("{}: a path with a NUL byte", path.display())))?;
    if uid == 0 && gid == 0 {
        // SAFETY: a NUL-terminated path for the duration of the call.
        if unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) } != 0 {
            return Err(Error::Build(format!(
                "{}: chmod {mode:o}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        return Ok(());
    }
    let status = kern_isolation::with_id_mapped_userns(|ranged| {
        if !ranged {
            return 3;
        }
        // SAFETY: as above, inside the mapped namespace's child.
        unsafe {
            if libc::lchown(c.as_ptr(), uid, gid) != 0 {
                return 1;
            }
            if libc::chmod(c.as_ptr(), mode as libc::mode_t) != 0 {
                return 2;
            }
        }
        0
    })
    .map_err(|e| Error::Build(format!("{}: owner {uid}:{gid}: {e}", path.display())))?;
    match status {
        0 => Ok(()),
        3 => Err(Error::Build(format!(
            "{}: owner {uid}:{gid} needs a subordinate uid range (newuidmap and an /etc/subuid entry), \
             which this host does not give kern",
            path.display()
        ))),
        _ => Err(Error::Build(format!(
            "{}: could not give it owner {uid}:{gid} and mode {mode:o}",
            path.display()
        ))),
    }
}

/// A private directory for this step's secret files and agent sockets: under kern's scratch area
/// (RAM-backed where the runtime directory is, and the one runtime place a box bind may come from),
/// mode 0700, unique to this process and step.
fn step_private_dir(step: usize) -> Result<PathBuf, Error> {
    use std::os::unix::fs::DirBuilderExt;
    let base = crate::commands::scratch_dir();
    std::fs::create_dir_all(&base)
        .map_err(|e| Error::Build(format!("build scratch {}: {e}", base.display())))?;
    let dir = base.join(format!("build-{}-{step}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| Error::Build(format!("build scratch {}: {e}", dir.display())))?;
    Ok(dir)
}

/// A stable name for a cache id: FNV-1a over the id (the same name in every kern version, which a
/// std hasher does not promise) plus a readable tail.
fn cache_dir_name(id: &str) -> String {
    let h = crate::commands::imagecache::fnv1a(id);
    let tail: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let tail = tail.trim_matches('_');
    let tail: String = tail.chars().take(40).collect();
    format!("{h:016x}-{tail}")
}

/// Where the persistent cache mounts live.
pub(crate) fn build_cache_root() -> PathBuf {
    crate::commands::cache_dir().join("build-cache")
}

/// The cache directory for `id`, created with BuildKit's owner and mode the first time (or seeded
/// from `from`), locked as `sharing` says. Returns the directory and the lock to hold.
#[allow(clippy::too_many_arguments)]
fn cache_mount(
    m: &RunMount,
    id: &str,
    sharing: CacheSharing,
    mode: u32,
    uid: u32,
    gid: u32,
    work: &Path,
    step: usize,
    n: usize,
) -> Result<(PathBuf, Option<std::fs::File>), Error> {
    use std::os::unix::io::AsRawFd;
    let root = build_cache_root();
    std::fs::create_dir_all(&root)
        .map_err(|e| Error::Build(format!("build cache {}: {e}", root.display())))?;
    let name = cache_dir_name(id);
    let lock_path = root.join(format!("{name}.lock"));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| Error::Build(format!("build cache lock {}: {e}", lock_path.display())))?;
    let fd = lock.as_raw_fd();
    let flock = |op: libc::c_int| loop {
        // SAFETY: flock on an fd this function owns.
        let r = unsafe { libc::flock(fd, op) };
        if r == 0 {
            break true;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            break false;
        }
    };
    let mut dir = root.join(&name);
    match sharing {
        CacheSharing::Shared => {
            flock(libc::LOCK_SH);
        }
        CacheSharing::Locked => {
            if !flock(libc::LOCK_EX) {
                return Err(Error::Build(format!(
                    "RUN --mount=type=cache,id={id},sharing=locked: could not take the lock"
                )));
            }
        }
        CacheSharing::Private => {
            // Busy: a fresh one for this step alone, as BuildKit gives.
            if !flock(libc::LOCK_EX | libc::LOCK_NB) {
                dir = work.join(format!("cache-private-{step}-{n}"));
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
    // `--no-cache` STARTS EACH CACHE EMPTY, once per build (measured: 4 lines, then 1).
    if no_cache() && dir.starts_with(&root) {
        let first = RESET_CACHES
            .lock()
            .map(|mut r| {
                if r.iter().any(|x| x == id) {
                    false
                } else {
                    r.push(id.to_string());
                    true
                }
            })
            .unwrap_or(true);
        if first && dir.exists() && std::fs::remove_dir_all(&dir).is_err() {
            let _ = crate::commands::remove_tree_mapped(&dir);
        }
    }
    // A CACHE ENTRY IS A REAL DIRECTORY OR IT IS NOT USED. The host follows a mount source, so a link
    // standing here would mount whatever host path it names; an earlier builder could leave one (see
    // `copy_out_of_image`). The link itself is removed, never its target, and the cache starts empty.
    if std::fs::symlink_metadata(&dir).is_ok_and(|md| !md.is_dir()) {
        std::fs::remove_file(&dir).map_err(|e| {
            Error::Build(format!(
                "build cache {} is not a directory and could not be removed: {e}",
                dir.display()
            ))
        })?;
    }
    if !dir.exists() {
        match &m.from {
            // SEEDED FROM A STAGE OR AN IMAGE: that directory, with its own owner and mode.
            Some(from) => {
                let source = m.source.trim_start_matches('/');
                if source.is_empty() || source == "." {
                    return Err(Error::Build(format!(
                        "RUN --mount=type=cache,from={from} needs a `source=` directory to seed from"
                    )));
                }
                let seed = work.join(format!("cache-seed-{step}-{n}"));
                let copied = copy_out_of_image(from, source, &seed)?;
                std::fs::rename(&copied, &dir)
                    .map_err(|e| Error::Build(format!("cache seed from {from}:{source}: {e}")))?;
                let _ = std::fs::remove_dir_all(&seed);
            }
            None => {
                std::fs::create_dir_all(&dir)
                    .map_err(|e| Error::Build(format!("build cache {}: {e}", dir.display())))?;
                own_in_box(&dir, uid, gid, mode)?;
            }
        }
    }
    Ok((dir, Some(lock)))
}

/// Copy `source` out of the image or stage `from` into a fresh `scratch` directory, and return the
/// copy's path, which a bind or cache mount then uses as its HOST source.
///
/// THE SOURCE IS RESOLVED INSIDE THE IMAGE, as BuildKit does: every symlink along it, the last
/// component included, is followed within the image's own root. What lands in `scratch` is then
/// refused if it is still a link, because the host follows a mount source: a link copied as a link
/// would mount the host path it names. MEASURED (audit, rootless): a stage with `ln -s <host dir> /c`
/// and `RUN --mount=type=bind,from=s,source=/c` listed and read that host directory; as a cache
/// mount the step wrote into it, and the poisoned entry served every later build of that id.
fn copy_out_of_image(from: &str, source: &str, scratch: &Path) -> Result<PathBuf, Error> {
    let (lower, _) = crate::commands::resolve_image(from)?;
    let _ = std::fs::remove_dir_all(scratch);
    std::fs::create_dir_all(scratch)
        .map_err(|e| Error::Build(format!("RUN --mount from={from} scratch: {e}")))?;
    // `chain_resolve` reads its chain BOTTOM first; an image's layers come TOP first.
    let bottom_first: Vec<String> = lower.iter().rev().cloned().collect();
    let resolved = crate::commands::imagecache::chain_resolve(&bottom_first, source);
    let name = Path::new(&resolved).file_name().ok_or_else(|| {
        Error::Build(format!(
            "RUN --mount from={from},source={source} resolves to the image's root, which kern's \
             builder does not mount: name a path under it"
        ))
    })?;
    let copied = scratch.join(name);
    crate::commands::copy_from_stage_chain(&lower, &resolved, scratch, &format!("'{from}'"))?;
    match std::fs::symlink_metadata(&copied) {
        Ok(md) if md.file_type().is_symlink() => Err(Error::Build(format!(
            "RUN --mount from={from},source={source} is a symbolic link that does not resolve \
             inside the image (refused: the host would follow it)"
        ))),
        Ok(_) => Ok(copied),
        Err(e) => Err(Error::Build(format!(
            "RUN --mount from={from},source={source}: {e}"
        ))),
    }
}

/// Start (once per build) the agent that holds `--ssh id=<key>`'s keys, and return its socket.
fn agent_for_keys(id: &str, keys: &[PathBuf]) -> Result<PathBuf, Error> {
    let mut agents = AGENTS
        .lock()
        .map_err(|_| Error::Build("ssh agent table poisoned".into()))?;
    if let Some((_, _, sock)) = agents.iter().find(|(i, _, _)| i == id) {
        return Ok(sock.clone());
    }
    let dir = step_private_dir(usize::MAX - agents.len())?;
    let sock = dir.join("agent.sock");
    let child = std::process::Command::new("ssh-agent")
        .arg("-D")
        .arg("-a")
        .arg(&sock)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            Error::Build(format!(
                "--ssh {id}=<key>: starting ssh-agent ({e}); install openssh-client, or forward a \
                 running agent with --ssh {id}"
            ))
        })?;
    agents.push((id.to_string(), child, sock.clone()));
    wait_for_socket(&sock)?;
    let added = std::process::Command::new("ssh-add")
        .args(keys)
        .env("SSH_AUTH_SOCK", &sock)
        .status()
        .map_err(|e| Error::Build(format!("--ssh {id}: ssh-add: {e}")))?;
    if !added.success() {
        return Err(Error::Build(format!(
            "--ssh {id}: ssh-add could not load {}",
            keys.iter()
                .map(|k| k.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(sock)
}

/// Wait until a socket a child process is creating exists.
fn wait_for_socket(sock: &Path) -> Result<(), Error> {
    for _ in 0..600 {
        if std::fs::symlink_metadata(sock).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    Err(Error::Build(format!(
        "{} did not appear within 3 s",
        sock.display()
    )))
}

/// The bytes of a build secret, or `None` when the build was not given it.
fn secret_bytes(id: &str) -> Result<Option<Vec<u8>>, Error> {
    match inputs().secrets.get(id) {
        None => Ok(None),
        Some(SecretSource::File(p)) => {
            crate::secret::read_host_file_for_box(&p.to_string_lossy(), "--secret").map(Some)
        }
        Some(SecretSource::Env(v)) => Ok(crate::global_env_str(v).ok().map(String::into_bytes)),
    }
}

/// Resolve one RUN's mounts for its box. `ctx` is the build context, `config` the image config the
/// step runs with, `work` the build's private tree, `self_exe` this binary (the agent proxy).
pub(crate) fn resolve_step_mounts(
    ctx: &Path,
    mounts: &[RunMount],
    config: &kern_oci::ImageConfig,
    work: &Path,
    step: usize,
    self_exe: &Path,
) -> Result<StepMounts, Error> {
    let ctx_root = std::fs::canonicalize(ctx)
        .map_err(|e| Error::Build(format!("build context {}: {e}", ctx.display())))?;
    let mut out = StepMounts::default();
    let mut private: Option<PathBuf> = None;
    let mut private_dir = |out: &mut StepMounts| -> Result<PathBuf, Error> {
        if let Some(d) = &private {
            return Ok(d.clone());
        }
        let d = step_private_dir(step)?;
        out.holds.push(Hold::Dir(d.clone()));
        private = Some(d.clone());
        Ok(d)
    };
    for (n, m) in mounts.iter().enumerate() {
        let target = box_target(&m.target, config);
        match &m.kind {
            MountKind::Bind => {
                out.binds
                    .push(bind_mount(m, &ctx_root, ctx, work, step, n, &target)?);
            }
            MountKind::Tmpfs => out.tmpfs.push(target),
            MountKind::Cache {
                id,
                sharing,
                mode,
                uid,
                gid,
            } => {
                let (dir, lock) = cache_mount(m, id, *sharing, *mode, *uid, *gid, work, step, n)?;
                if let Some(l) = lock {
                    out.holds.push(Hold::Lock(l));
                }
                out.binds
                    .push((dir.to_string_lossy().into_owned(), target, !m.rw));
            }
            MountKind::Secret {
                id,
                env,
                required,
                mode,
                uid,
                gid,
            } => {
                let Some(bytes) = secret_bytes(id)? else {
                    if *required {
                        return Err(Error::Build(format!(
                            "secret {id}: not found (give it with kern build --secret id={id},src=<file>)"
                        )));
                    }
                    continue;
                };
                if let Some(var) = env {
                    let value = String::from_utf8(bytes.clone()).map_err(|_| {
                        Error::Build(format!(
                            "secret {id}: env={var} needs text, and the secret is not valid UTF-8"
                        ))
                    })?;
                    out.env.push((var.clone(), value));
                }
                if !m.target.is_empty() {
                    let dir = private_dir(&mut out)?;
                    let file = dir.join(format!("secret-{n}"));
                    write_private(&file, &bytes)?;
                    own_in_box(&file, *uid, *gid, *mode)?;
                    out.binds
                        .push((file.to_string_lossy().into_owned(), target, true));
                }
            }
            MountKind::Ssh {
                id,
                required,
                mode,
                uid,
                gid,
            } => {
                let upstream = match inputs().ssh.get(id) {
                    Some(SshSource::Socket(s)) => s.clone(),
                    Some(SshSource::Keys(keys)) => agent_for_keys(id, keys)?,
                    None if *required => {
                        return Err(Error::Build(format!(
                            "ssh {id}: not found (give it with kern build --ssh {id})"
                        )))
                    }
                    None => continue,
                };
                let dir = private_dir(&mut out)?;
                let sock = dir.join(format!("agent-{n}.sock"));
                let child = std::process::Command::new(self_exe)
                    .arg("__build-ssh-proxy")
                    .arg(&sock)
                    .arg(&upstream)
                    // ALL THREE STREAMS CLOSED: a proxy holding the build's stderr would keep the
                    // pipe of whoever reads `kern build` open, and a caller collecting its output
                    // would wait for ever (found by a sabotage that left the proxy running).
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .map_err(|e| Error::Build(format!("ssh {id}: agent proxy: {e}")))?;
                out.holds.push(Hold::Proxy(child));
                wait_for_socket(&sock)?;
                own_in_box(&sock, *uid, *gid, *mode)?;
                if !out.env.iter().any(|(k, _)| k == "SSH_AUTH_SOCK") {
                    out.env.push(("SSH_AUTH_SOCK".to_string(), target.clone()));
                }
                out.sockets
                    .push((sock.to_string_lossy().into_owned(), target));
            }
        }
    }
    Ok(out)
}

/// Write a secret's bytes to a new file only this user can read, before its final mode is set.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::Build(format!("build secret {}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| Error::Build(format!("build secret {}: {e}", path.display())))
}

/// One `type=bind` mount: from the context (confined to it), a stage or an image.
fn bind_mount(
    m: &RunMount,
    ctx_root: &Path,
    ctx: &Path,
    work: &Path,
    step: usize,
    n: usize,
    target: &str,
) -> Result<(String, String, bool), Error> {
    // FROM AN IMAGE OR A STAGE (already rewritten to its local tag): the source is taken out of
    // that image's merged view into a scratch directory, by the same code `COPY --from` uses, and
    // that copy is what the command sees.
    if let Some(from) = &m.from {
        let source = m.source.trim_start_matches('/');
        if source.is_empty() || source == "." {
            return Err(Error::Build(format!(
                "RUN --mount from={from} without a `source=` mounts the whole image, which kern's \
                 builder does not do: name the path to mount (source=/path)"
            )));
        }
        let scratch = work.join(format!("run-from-{step}-{n}"));
        let copied = copy_out_of_image(from, source, &scratch)?;
        return Ok((
            copied.to_string_lossy().into_owned(),
            target.to_string(),
            !m.rw,
        ));
    }
    let host = std::fs::canonicalize(ctx.join(&m.source))
        .map_err(|e| Error::Build(format!("RUN --mount source={}: {e}", m.source)))?;
    if !host.starts_with(ctx_root) {
        return Err(Error::Build(format!(
            "RUN --mount source={} leaves the build context (refused)",
            m.source
        )));
    }
    let host = if m.rw {
        let scratch = work.join(format!("rw-mount-{step}-{n}"));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch)
            .map_err(|e| Error::Build(format!("RUN --mount rw scratch: {e}")))?;
        let copy = scratch.join("m");
        let ok = std::process::Command::new("cp")
            .arg("-a")
            .arg("--")
            .arg(&host)
            .arg(&copy)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return Err(Error::Build(format!(
                "RUN --mount source={},rw: the throwaway copy failed",
                m.source
            )));
        }
        copy
    } else {
        host
    };
    Ok((
        host.to_string_lossy().into_owned(),
        target.to_string(),
        !m.rw,
    ))
}

/// What a mount contributes to its layer's cache key. A bind contributes its CONTENT (a changed
/// `uv.lock` must rebuild); a cache, a secret, an SSH agent and a tmpfs contribute what they are and
/// where, never their content, as BuildKit keys them: a rotated token must not rebuild every layer,
/// and must never be readable in a key.
pub(crate) fn mount_cache_key(m: &RunMount, bind_content: impl FnOnce() -> String) -> String {
    match &m.kind {
        MountKind::Bind => format!("{}\u{2}{}\u{2}{}", m.target, m.rw, bind_content()),
        MountKind::Cache { id, sharing, .. } => {
            format!(
                "cache\u{2}{}\u{2}{id}\u{2}{sharing:?}\u{2}{}",
                m.target, m.rw
            )
        }
        MountKind::Secret { id, env, .. } => format!(
            "secret\u{2}{}\u{2}{id}\u{2}{}",
            m.target,
            env.as_deref().unwrap_or("")
        ),
        MountKind::Ssh { id, .. } => format!("ssh\u{2}{}\u{2}{id}", m.target),
        MountKind::Tmpfs => format!("tmpfs\u{2}{}", m.target),
    }
}

/// `kern __build-ssh-proxy <listen> <upstream>`: forward every connection on `listen` to the agent at
/// `upstream`. A socket of kern's own, so its owner and mode are the step's (`uid=`, `mode=`) and the
/// caller's agent never is.
pub(crate) fn ssh_agent_proxy(listen: &str, upstream: &str) -> Result<(), Error> {
    use std::os::unix::net::{UnixListener, UnixStream};
    let _ = std::fs::remove_file(listen);
    let l = UnixListener::bind(listen)
        .map_err(|e| Error::Build(format!("ssh agent proxy {listen}: {e}")))?;
    for conn in l.incoming() {
        let Ok(client) = conn else { continue };
        let up = upstream.to_string();
        std::thread::spawn(move || {
            let Ok(agent) = UnixStream::connect(&up) else {
                return;
            };
            let (Ok(mut c_read), Ok(mut a_write)) = (client.try_clone(), agent.try_clone()) else {
                return;
            };
            let forward = std::thread::spawn(move || {
                let _ = std::io::copy(&mut c_read, &mut a_write);
                let _ = a_write.shutdown(std::net::Shutdown::Write);
            });
            let (mut a_read, mut c_write) = (agent, client);
            let _ = std::io::copy(&mut a_read, &mut c_write);
            let _ = c_write.shutdown(std::net::Shutdown::Write);
            let _ = forward.join();
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docker's `--secret` grammar, including the measured rule for an id alone.
    #[test]
    fn a_secret_spec_reads_like_dockers() {
        let _g = crate::env_guard();
        // CSV, as docker reads it: a quoted field keeps its comma, so a path holding `,src=` is one
        // path and never a second source (compose passes its secrets this way).
        assert_eq!(
            parse_secret_spec(r#""id=t","src=/p/a,src=/etc/shadow""#).ok(),
            Some((
                "t".to_string(),
                SecretSource::File(PathBuf::from("/p/a,src=/etc/shadow"))
            ))
        );
        assert_eq!(
            parse_secret_spec("id=npm,src=/tmp/npmrc").ok(),
            Some((
                "npm".to_string(),
                SecretSource::File(PathBuf::from("/tmp/npmrc"))
            ))
        );
        assert_eq!(
            parse_secret_spec("id=tok,env=GH_TOKEN").ok(),
            Some(("tok".to_string(), SecretSource::Env("GH_TOKEN".into())))
        );
        assert_eq!(
            parse_secret_spec("id=K,type=env").ok(),
            Some(("K".to_string(), SecretSource::Env("K".into())))
        );
        // An id alone: the variable when it is set, else the file of that name.
        crate::set_global_env("KERN_TEST_SECRET_ID", "x");
        assert_eq!(
            parse_secret_spec("id=KERN_TEST_SECRET_ID").ok(),
            Some((
                "KERN_TEST_SECRET_ID".to_string(),
                SecretSource::Env("KERN_TEST_SECRET_ID".into())
            ))
        );
        crate::unset_global_env("KERN_TEST_SECRET_ID");
        assert_eq!(
            parse_secret_spec("id=KERN_TEST_SECRET_ID").ok(),
            Some((
                "KERN_TEST_SECRET_ID".to_string(),
                SecretSource::File(PathBuf::from("KERN_TEST_SECRET_ID"))
            ))
        );
        for bad in [
            "src=/x",
            "id=a,src=/x,env=Y",
            "id=a/b,src=/x",
            "id=a,bogus=1",
            "id=a,type=env,src=/x",
        ] {
            assert!(parse_secret_spec(bad).is_err(), "{bad}");
        }
    }

    /// The cache directory name is the same in every kern version and readable.
    #[test]
    fn a_cache_dir_name_is_stable_and_readable() {
        assert_eq!(
            cache_dir_name("/root/.cache/pip"),
            format!("{:016x}-root__cache_pip", {
                let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                for b in b"/root/.cache/pip" {
                    h ^= u64::from(*b);
                    h = h.wrapping_mul(0x0100_0000_01b3);
                }
                h
            })
        );
        assert_ne!(cache_dir_name("a"), cache_dir_name("b"));
        assert!(cache_dir_name(&"x".repeat(200)).len() <= 16 + 1 + 40);
    }

    /// A secret's VALUE never reaches a cache key; a bind's content does.
    #[test]
    fn a_secret_value_is_never_part_of_a_cache_key() {
        let secret = RunMount {
            source: String::new(),
            target: "/run/secrets/tok".into(),
            rw: false,
            from: None,
            kind: MountKind::Secret {
                id: "tok".into(),
                env: None,
                required: false,
                mode: 0o400,
                uid: 0,
                gid: 0,
            },
        };
        let key = mount_cache_key(&secret, || "SHOULD-NOT-APPEAR".into());
        assert!(!key.contains("SHOULD-NOT-APPEAR"), "{key}");
        let bind = RunMount {
            kind: MountKind::Bind,
            ..secret
        };
        assert!(mount_cache_key(&bind, || "content-hash".into()).contains("content-hash"));
    }
}
