//! `kern self-update`: replace this kern with a newer SIGNED release, or put the previous one back.
//!
//! WHAT IS TRUSTED, AND WHERE IT COMES FROM. Two minisign public keys are compiled into this binary
//! ([`RELEASE_KEYS`]): the release key and a spare kept offline for the day the first one is lost
//! or stolen. Nothing downloaded is believed until a signature by one of them checks out over the
//! WHOLE tarball, before it is unpacked. The network, the mirror, GitHub itself are transport.
//!
//! WHAT THE SIGNATURE SAYS, NOT ONLY THAT IT IS VALID. A valid signature on an OLD release is still
//! a valid signature, so a bare check would let anyone able to answer the download serve kern
//! 0.40 to a 0.51 and call it an update. The signed (trusted) comment carries the version, the
//! target and the file name ([`parse_statement`]), and the update goes through only when that
//! version is NEWER than this one, the target is this machine's and the file is the one asked for.
//! What a signature cannot stop is a FREEZE: someone who can answer the download can keep serving
//! the current release forever. That shows as "no newer release", never as a wrong binary.
//!
//! THE SWAP IS ONE RENAME. The new binary is unpacked into a private directory NEXT TO the current
//! one (same filesystem, so `rename` is atomic), run once with `--version` to prove it starts on
//! this machine and is the version the signature names, and only then renamed over the old path.
//! The old binary is kept as `<name>.previous` first, so `kern self-update --rollback` puts it
//! back. A box already running keeps the inode it started from; the next `kern` started is the new
//! one.
//!
//! WHAT IT REFUSES TO TOUCH. A kern that pip, npm, cargo, Homebrew, Nix or a system package manager
//! put in place belongs to that tool: replacing it behind the tool's back breaks the tool's own
//! upgrade and uninstall. Those are refused with the command to use ([`owner_of`]). A build from
//! source has no release version to compare and is refused too.

use crate::error::Error;
use minisign_verify::{PublicKey, Signature};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The release keys, as `minisign -G` printed them on 2026-11-18: (key id, public key).
///
/// The first signs every release. The second is the spare, kept offline: if the first is lost or
/// stolen, a release signed with the spare can still reach every kern installed before that day,
/// and that release drops the first key from this list.
pub(crate) const RELEASE_KEYS: [(&str, &str); 2] = [
    (
        "57003FB4EA6F60AE",
        "RWSuYG/qtD8AV5p5IzIqfRuCwh5eJlT7ed5+7lVKrgILE1qvIpPGv+Ej",
    ),
    (
        "B0D7F514A5DD424B",
        "RWRLQt2lFPXXsC0g2+1SPfSmOdjpxJ/f+t5DU+xPOaRNjElnisOR0Uo3",
    ),
];

/// Where the newest release's assets are, and where a tagged one's are (`<TAGGED>/v<version>`).
const LATEST: &str = "https://github.com/getkern/kern/releases/latest/download";
const TAGGED: &str = "https://github.com/getkern/kern/releases/download";

/// The first two words of a release statement. The second is the format, so a later change of
/// the fields is a new word and an old kern refuses it rather than misreading it.
const STATEMENT_TAG: &str = "kern-release";
const STATEMENT_FORMAT: &str = "v1";

/// Download bounds. The tarball holds one static binary; the signature is four short lines.
const MAX_TARBALL_BYTES: u64 = 256 << 20;
const MAX_SIG_BYTES: u64 = 4096;
const TARBALL_MAX_SECONDS: &str = "900";
const SIG_MAX_SECONDS: &str = "60";

/// How long a binary gets to answer `--version` before it is called broken.
const PROBE_LIMIT: Duration = Duration::from_secs(10);

/// What `kern self-update` was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    /// Install the newest release, or the one named by `to`.
    Install { to: Option<Version> },
    /// Say whether a newer release exists, without replacing anything.
    Check { json: bool },
    /// Swap this binary with `<name>.previous`.
    Rollback,
}

/// A release version: exactly `MAJOR.MINOR.PATCH`, decimal, no leading zeros, an optional `v`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Version(u32, u32, u32);

impl Version {
    pub(crate) fn parse(s: &str) -> Option<Version> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let mut parts = s.split('.');
        let major = number(parts.next()?)?;
        let minor = number(parts.next()?)?;
        let patch = number(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Version(major, minor, patch))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// One version component. Nine digits at most, so it always fits a `u32`.
fn number(p: &str) -> Option<u32> {
    let digits = !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit());
    if !digits || (p.len() > 1 && p.starts_with('0')) {
        return None;
    }
    p.parse().ok()
}

/// The signed statement of one release asset.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Statement<'a> {
    pub(crate) version: Version,
    pub(crate) target: &'a str,
    pub(crate) file: &'a str,
}

/// Read a trusted comment as a release statement:
/// `kern-release v1 version=0.52.0 target=x86_64-unknown-linux-musl file=kern-x86_64-unknown-linux-musl.tar.gz`.
///
/// Strict on purpose: single spaces, each key exactly once, no key this format does not define.
/// Anything else is refused, because a statement read loosely is a statement someone else can
/// write for you.
pub(crate) fn parse_statement(comment: &str) -> Result<Statement<'_>, String> {
    let shown: String = comment.chars().take(200).collect();
    let not_ours = || format!("the signed comment is not a kern release statement: {shown:?}");
    let mut words = comment.split(' ');
    if words.next() != Some(STATEMENT_TAG) || words.next() != Some(STATEMENT_FORMAT) {
        return Err(not_ours());
    }
    let (mut version, mut target, mut file) = (None, None, None);
    for word in words {
        let Some((key, value)) = word.split_once('=') else {
            return Err(not_ours());
        };
        let slot = match key {
            "version" => &mut version,
            "target" => &mut target,
            "file" => &mut file,
            _ => return Err(not_ours()),
        };
        if slot.is_some() || value.is_empty() {
            return Err(not_ours());
        }
        *slot = Some(value);
    }
    let (Some(version), Some(target), Some(file)) = (version, target, file) else {
        return Err(not_ours());
    };
    let Some(version) = Version::parse(version) else {
        return Err(not_ours());
    };
    Ok(Statement {
        version,
        target,
        file,
    })
}

/// What a verified statement means for this binary.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The release is newer: install it.
    Newer,
    /// The release is this version.
    Current,
}

/// Judge a VERIFIED statement against this binary: right asset, right machine, and never older.
pub(crate) fn judge(
    statement: &Statement<'_>,
    current: Version,
    target: &str,
    file: &str,
    to: Option<Version>,
) -> Result<Verdict, String> {
    if statement.target != target {
        return Err(format!(
            "the signed release is for {}, this machine needs {target}: nothing replaced",
            statement.target
        ));
    }
    if statement.file != file {
        return Err(format!(
            "the signature is for {}, not for {file}: nothing replaced",
            statement.file
        ));
    }
    if let Some(want) = to {
        if statement.version != want {
            return Err(format!(
                "asked for {want}, the signed release says {}: nothing replaced",
                statement.version
            ));
        }
    }
    match statement.version.cmp(&current) {
        std::cmp::Ordering::Greater => Ok(Verdict::Newer),
        std::cmp::Ordering::Equal => Ok(Verdict::Current),
        std::cmp::Ordering::Less => Err(format!(
            "the signed release is {}, older than this kern ({current}): self-update never goes back \
             a version. `kern self-update --rollback` restores the binary this one replaced",
            statement.version
        )),
    }
}

/// Who put the binary at `exe` in place, read from its path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Owner {
    /// `install.sh` (or a copy by hand): self-update may replace it.
    Standalone,
    Pip,
    Npm,
    Cargo,
    Homebrew,
    Nix,
    /// A directory a system package manager owns (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`).
    System,
    /// A `target/` directory of a source tree.
    SourceTree,
}

pub(crate) fn owner_of(exe: &Path) -> Owner {
    let has = |part: &str| exe.components().any(|c| c.as_os_str() == part);
    let dir = exe.parent().unwrap_or(Path::new("/"));
    if has("site-packages") || has("dist-packages") {
        Owner::Pip
    } else if has("node_modules") {
        Owner::Npm
    } else if exe.starts_with("/nix/store") {
        Owner::Nix
    } else if has("Cellar") || has(".linuxbrew") || exe.starts_with("/opt/homebrew") {
        Owner::Homebrew
    } else if has(".cargo") {
        Owner::Cargo
    } else if ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .iter()
        .any(|d| dir == Path::new(d))
    {
        Owner::System
    } else if exe.ancestors().any(|a| {
        a.file_name().is_some_and(|n| n == "target")
            && a.parent().is_some_and(|p| p.join("Cargo.toml").is_file())
    }) {
        Owner::SourceTree
    } else {
        Owner::Standalone
    }
}

/// The refusal for a binary another tool owns, naming that tool's own command.
fn owned_elsewhere(owner: &Owner, exe: &Path) -> Option<String> {
    let what = match owner {
        Owner::Standalone => return None,
        Owner::Pip => "pip installed it: run `pip install -U kern-sandbox`",
        Owner::Npm => "npm installed it: run `npm install kern-sandbox@latest`",
        Owner::Cargo => "cargo installed it: run `cargo install getkern --force`",
        Owner::Homebrew => "Homebrew installed it: run `brew upgrade kern`",
        Owner::Nix => "it is in the Nix store: update it through Nix",
        Owner::System => {
            "it is in a directory a package manager owns: update it with that package manager"
        }
        Owner::SourceTree => "it was built in a source tree: rebuild it there",
    };
    Some(format!("{} is not replaced: {what}", exe.display()))
}

/// This machine's release target, or `None` where no release is published.
pub(crate) fn release_target() -> Option<&'static str> {
    if cfg!(target_arch = "x86_64") {
        Some("x86_64-unknown-linux-musl")
    } else if cfg!(target_arch = "aarch64") {
        Some("aarch64-unknown-linux-musl")
    } else {
        None
    }
}

/// A variable only the tests set, read only by a DEBUG build. A release build compiles the other
/// body, so no environment can change which keys a shipped kern trusts or what version it is.
#[cfg(debug_assertions)]
fn test_override(name: &str) -> Option<String> {
    crate::global_env_str(name).ok()
}

#[cfg(not(debug_assertions))]
fn test_override(_name: &str) -> Option<String> {
    None
}

/// This binary's version, when it is a release.
fn current_version() -> Result<Version, Error> {
    // A test pretends to be a release: the debug binary's own version is `vX-N-gHASH-dirty`.
    if let Some(v) = test_override("KERN_SELF_UPDATE_TEST_VERSION") {
        return Version::parse(&v).ok_or_else(|| {
            Error::SelfUpdate(format!("KERN_SELF_UPDATE_TEST_VERSION={v:?} is not X.Y.Z"))
        });
    }
    match Version::parse(kern_common::VERSION) {
        Some(v) if v != Version(0, 0, 0) => Ok(v),
        _ => Err(Error::SelfUpdate(format!(
            "this kern ({}) was built from source, not cut from a release, so there is no release \
             version to compare: rebuild it, or install a release with `curl -fsSL \
             https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh`",
            kern_common::VERSION
        ))),
    }
}

/// The keys a signature may be made with: [`RELEASE_KEYS`], and in a debug build a test key.
fn trusted_keys() -> Result<Vec<PublicKey>, Error> {
    let mut keys = Vec::with_capacity(RELEASE_KEYS.len() + 1);
    for (id, b64) in RELEASE_KEYS {
        keys.push(PublicKey::from_base64(b64).map_err(|e| {
            Error::SelfUpdate(format!(
                "the built-in release key {id} does not decode: {e}"
            ))
        })?);
    }
    if let Some(b64) = test_override("KERN_SELF_UPDATE_TEST_PUBKEY") {
        keys.push(PublicKey::from_base64(&b64).map_err(|e| {
            Error::SelfUpdate(format!("KERN_SELF_UPDATE_TEST_PUBKEY does not decode: {e}"))
        })?);
    }
    Ok(keys)
}

/// Check `sig` over the file at `path` with whichever trusted key made it, reading the file in
/// fixed chunks (no copy of the tarball in memory).
fn verify_file(path: &Path, sig: &Signature, keys: &[PublicKey]) -> Result<(), String> {
    for key in keys {
        let mut verifier = match key.verify_stream(sig) {
            Ok(v) => v,
            Err(minisign_verify::Error::UnexpectedKeyId) => continue,
            Err(e) => return Err(format!("the signature cannot be checked: {e}")),
        };
        let mut file = std::fs::File::open(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
            };
            verifier.update(&buf[..n]);
        }
        return verifier.finalize().map_err(|_| {
            "the signature does not match the download (altered or truncated): nothing replaced"
                .to_string()
        });
    }
    Err("the release is signed with a key this kern does not trust: nothing replaced".to_string())
}

/// `kern __verify-release <file> <file.minisig> <target> <asset> [<version>]` (hidden): check a
/// release file the way `self-update` checks its own download, with the keys built into this binary.
///
/// FOR INSTALL.PS1'S UPDATES. Windows has no minisign and PowerShell 5.1 no Ed25519, so a first install
/// there is checked by SHA256 only; but on an UPDATE the kern already in the distro is a binary this
/// user trusts, and it can check the next `kern.exe`, distro and tarball before anything is replaced.
///
/// Prints `verified <version>` and exits 0 when the signature checks out and its statement names this
/// target, this file and (when given) this version; exits 3 with the reason otherwise. 3 and not 1,
/// because an older kern answers 1 to a command it does not know, and the caller must tell "refused"
/// from "this kern cannot check".
pub(crate) fn verify_release_verb(args: &[String]) -> i32 {
    let (file, sig, target, asset, want) = match args {
        [f, s, t, a] => (f, s, t, a, None),
        [f, s, t, a, v] => match Version::parse(v.trim_start_matches('v')) {
            Some(v) => (f, s, t, a, Some(v)),
            None => {
                eprintln!("kern: __verify-release: {v:?} is not a version");
                return 2;
            }
        },
        _ => {
            eprintln!(
                "usage: kern __verify-release <file> <file.minisig> <target> <asset> [<version>]"
            );
            return 2;
        }
    };
    match verify_release(Path::new(file), Path::new(sig), target, asset, want) {
        Ok(v) => {
            println!("verified {v}");
            0
        }
        Err(m) => {
            eprintln!("kern: {m}");
            3
        }
    }
}

fn verify_release(
    file: &Path,
    sigpath: &Path,
    target: &str,
    asset: &str,
    want: Option<Version>,
) -> Result<Version, String> {
    let keys = trusted_keys().map_err(|e| e.to_string())?;
    let text = std::fs::read_to_string(sigpath)
        .map_err(|e| format!("the signature {} cannot be read: {e}", sigpath.display()))?;
    let sig = Signature::decode(&text).map_err(|e| format!("the signature does not parse: {e}"))?;
    verify_file(file, &sig, &keys)?;
    let st = parse_statement(sig.trusted_comment())?;
    if st.target != target {
        return Err(format!("the signature is for {}, not {target}", st.target));
    }
    if st.file != asset {
        return Err(format!("the signature is for {}, not {asset}", st.file));
    }
    if let Some(w) = want {
        if st.version != w {
            return Err(format!("asked for {w}, the signature says {}", st.version));
        }
    }
    Ok(st.version)
}

/// Download `url` to `out` with curl, bounded in size and time.
///
/// `https://` only, redirects included. A debug build also takes `file://`, which is how the tests
/// serve a release without a network.
fn fetch(url: &str, out: &Path, cap: u64, max_seconds: &str) -> Result<(), Error> {
    fetch_as(url, out, cap, max_seconds).map_err(|f| match f {
        Fetched::Missing(e) | Fetched::Failed(e) => e,
    })
}

/// Why a download failed: the server ANSWERED that the file is not there (HTTP error, or a missing
/// `file://` in the tests), or the download never completed (no DNS, no route, a timeout, TLS).
/// Only the first may be read as "this release is not signed yet". MEASURED 2026-11-18 on a WSL
/// distro whose resolver failed: "could not resolve host" was followed by "no signature was found
/// for this release", and the release was signed.
enum Fetched {
    Missing(Error),
    Failed(Error),
}

/// curl's exit for "the server answered with an error" under `--fail` (22), and for a `file://`
/// that is not there (37).
const CURL_MISSING: [i32; 2] = [22, 37];

/// curl's exit for "could not resolve host".
const CURL_RESOLVE: i32 = 6;

/// curl's exit for "operation timed out", which covers a name lookup that never answered.
const CURL_TIMEOUT: i32 = 28;

fn fetch_as(url: &str, out: &Path, cap: u64, max_seconds: &str) -> Result<(), Fetched> {
    let local = cfg!(debug_assertions) && url.starts_with("file://");
    if !local && !url.starts_with("https://") {
        return Err(Fetched::Failed(Error::SelfUpdate(format!(
            "refusing to download over anything but https: {url}"
        ))));
    }
    let proto = if local { "=file" } else { "=https" };
    let cap_arg = cap.to_string();
    let run = |ipv4: bool| {
        let mut cmd = Command::new("curl");
        cmd.args(["--no-progress-meter", "-S", "-L", "--fail"])
            .args(["--proto", proto, "--proto-redir", proto])
            .args(["--max-redirs", "10", "--connect-timeout", "10"])
            .args(["--max-time", max_seconds, "--max-filesize", &cap_arg])
            .args(["--speed-limit", "1024", "--speed-time", "30"]);
        if !local {
            cmd.arg("--tlsv1.2");
        }
        if ipv4 {
            cmd.arg("--ipv4");
        }
        cmd.arg("-o")
            .arg(out)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| {
                Fetched::Failed(if e.kind() == std::io::ErrorKind::NotFound {
                    Error::SelfUpdate(
                        "self-update downloads with curl, and curl is not installed".into(),
                    )
                } else {
                    Error::SelfUpdate(format!("cannot run curl: {e}"))
                })
            })
    };
    let mut done = run(false)?;
    // A NAME THAT DOES NOT RESOLVE (curl 6) IS TRIED AGAIN OVER IPv4. MEASURED 2026-11-18 in kern's
    // WSL distro (Alpine curl with c-ares, WSL's DNS proxy): following the redirect from github.com
    // to release-assets.githubusercontent.com failed 5 of 5 times with "Could not resolve host",
    // and 5 of 5 succeeded with `--ipv4`; so every `kern self-update` there failed.
    // The same resolver can also time out instead (curl 28, "Resolving timed out", MEASURED on the
    // same distro): a timeout that happened while resolving is the same failure.
    let resolving = done.status.code() == Some(CURL_RESOLVE)
        || (done.status.code() == Some(CURL_TIMEOUT)
            && String::from_utf8_lossy(&done.stderr).contains("Resolving timed out"));
    if resolving {
        done = run(true)?;
    }
    if !done.status.success() {
        let said = String::from_utf8_lossy(&done.stderr);
        let said = said.lines().last().unwrap_or("").trim();
        let e = Error::SelfUpdate(format!("could not download {url}: {said}"));
        return Err(match done.status.code() {
            Some(c) if CURL_MISSING.contains(&c) => Fetched::Missing(e),
            _ => Fetched::Failed(Error::SelfUpdate(format!(
                "could not download {url}: {said}\nthe download did not complete, so nothing \
                 was replaced: check the network (DNS, a proxy) and run it again"
            ))),
        });
    }
    // `--max-filesize` cannot stop a body whose size the server did not announce, so look.
    let size = std::fs::metadata(out)
        .map_err(|e| {
            Fetched::Failed(Error::SelfUpdate(format!(
                "the download of {url} left no file: {e}"
            )))
        })?
        .len();
    if size > cap {
        return Err(Fetched::Failed(Error::SelfUpdate(format!(
            "{url} is {size} bytes, over the {cap} a release asset may be: nothing replaced"
        ))));
    }
    Ok(())
}

/// A private directory next to the binary, removed on every way out.
struct WorkDir(PathBuf);

impl WorkDir {
    fn create(bindir: &Path) -> Result<WorkDir, Error> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = bindir.join(format!(".kern-self-update-{}-{nanos}", std::process::id()));
        // `create`, not `create_all`: an existing path is refused, so the directory removed on
        // drop is always one this process made.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    Error::SelfUpdate(format!(
                        "cannot write {}: this kern was installed by another user (root?): run \
                         the update as that user, e.g. `sudo kern self-update`",
                        bindir.display()
                    ))
                } else {
                    Error::SelfUpdate(format!(
                        "cannot create a work directory in {}: {e}",
                        bindir.display()
                    ))
                }
            })?;
        Ok(WorkDir(path))
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An exclusive lock on the binary's directory, held for the whole update: two self-updates in one
/// directory would each keep the other's binary as `.previous`. Released when the file closes.
struct DirLock(#[allow(dead_code)] std::fs::File);

fn lock_dir(dir: &Path) -> Result<DirLock, Error> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|e| Error::SelfUpdate(format!("cannot open {}: {e}", dir.display())))?;
    // SAFETY: `f` is an open descriptor owned by this frame; flock does not touch memory.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(Error::SelfUpdate(
            if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                format!("another self-update is running in {}", dir.display())
            } else {
                format!("cannot lock {}: {e}", dir.display())
            },
        ));
    }
    Ok(DirLock(f))
}

/// Run `bin --version` and return what it printed, or why it is not a kern that runs here.
fn probe(bin: &Path) -> Result<String, String> {
    // ROOT STAYS ROOT FOR THIS ONE QUESTION. MEASURED 2026-11-18 in kern's WSL distro: started as
    // root there, the new binary gives root up and starts again as the user from the staging
    // directory, which the user cannot enter, so `--version` exited 125 and every update was
    // refused. The probe asks for a version string and starts no box.
    let mut child = Command::new(bin)
        .env("KERN_WSL_AS_ROOT", "1")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("it does not start here: {e}"))?;
    let deadline = Instant::now() + PROBE_LIMIT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "`--version` did not answer in {} s",
                    PROBE_LIMIT.as_secs()
                ));
            }
            Err(e) => return Err(format!("cannot wait for it: {e}")),
        }
    };
    let mut said = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.by_ref().take(4096).read_to_string(&mut said);
    }
    if !status.success() {
        return Err(format!("`--version` failed ({status})"));
    }
    Ok(said.trim().to_string())
}

/// The running binary's real path.
pub(crate) fn this_exe() -> Result<PathBuf, Error> {
    let exe = std::fs::read_link("/proc/self/exe")
        .map_err(|e| Error::SelfUpdate(format!("cannot find this binary: {e}")))?;
    if exe.as_os_str().as_encoded_bytes().ends_with(b" (deleted)") {
        return Err(Error::SelfUpdate(format!(
            "this binary was replaced or removed while running ({}): start the new one",
            exe.display()
        )));
    }
    Ok(exe)
}

/// The binary, its directory and its `.previous`, after refusing a binary another tool owns.
struct Place {
    exe: PathBuf,
    dir: PathBuf,
    previous: PathBuf,
}

fn place() -> Result<Place, Error> {
    let exe = this_exe()?;
    if let Some(why) = owned_elsewhere(&owner_of(&exe), &exe) {
        return Err(Error::SelfUpdate(why));
    }
    let (Some(dir), Some(name)) = (exe.parent(), exe.file_name()) else {
        return Err(Error::SelfUpdate(format!(
            "{} has no directory",
            exe.display()
        )));
    };
    let mut prev = name.to_os_string();
    prev.push(".previous");
    Ok(Place {
        previous: dir.join(prev),
        dir: dir.to_path_buf(),
        exe,
    })
}

/// Flush a file or directory to disk.
fn sync(path: &Path) -> Result<(), Error> {
    std::fs::File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|e| Error::SelfUpdate(format!("cannot flush {}: {e}", path.display())))
}

pub(crate) fn run(req: &Request) -> Result<(), Error> {
    match req {
        Request::Rollback => rollback(),
        Request::Check { json } => install(None, Some(*json)),
        Request::Install { to } => install(*to, None),
    }
}

/// Download, verify and judge the release; with `check` set, report and stop there.
fn install(to: Option<Version>, check: Option<bool>) -> Result<(), Error> {
    let place = place()?;
    let current = current_version()?;
    let Some(target) = release_target() else {
        return Err(Error::SelfUpdate(
            "no release is published for this architecture (x86_64 and aarch64 are)".into(),
        ));
    };
    let file = format!("kern-{target}.tar.gz");
    let base =
        match (crate::global_env_str("KERN_SELF_UPDATE_URL").ok(), to) {
            (Some(_), Some(_)) => return Err(Error::SelfUpdate(
                "--to and KERN_SELF_UPDATE_URL do not combine: point KERN_SELF_UPDATE_URL at the \
                 directory of the release you want"
                    .into(),
            )),
            (Some(url), None) => url.trim_end_matches('/').to_string(),
            (None, Some(v)) => format!("{TAGGED}/v{v}"),
            (None, None) => LATEST.to_string(),
        };
    let keys = trusted_keys()?;
    let _lock = lock_dir(&place.dir)?;
    let work = WorkDir::create(&place.dir)?;
    let tarball = work.0.join(&file);
    let sigfile = work.0.join(format!("{file}.minisig"));
    fetch_as(
        &format!("{base}/{file}.minisig"),
        &sigfile,
        MAX_SIG_BYTES,
        SIG_MAX_SECONDS,
    )
    .map_err(|f| match f {
        Fetched::Missing(Error::SelfUpdate(m)) => Error::SelfUpdate(format!(
            "{m}\nno signature was found for this release: a release is installable once \
                 it is signed, try again later"
        )),
        Fetched::Missing(other) | Fetched::Failed(other) => other,
    })?;
    let sig_text = std::fs::read_to_string(&sigfile)
        .map_err(|e| Error::SelfUpdate(format!("the signature is not text: {e}")))?;
    let sig = Signature::decode(&sig_text)
        .map_err(|e| Error::SelfUpdate(format!("the signature does not parse: {e}")))?;
    fetch(
        &format!("{base}/{file}"),
        &tarball,
        MAX_TARBALL_BYTES,
        TARBALL_MAX_SECONDS,
    )?;
    verify_file(&tarball, &sig, &keys).map_err(Error::SelfUpdate)?;
    // Only now is the comment worth reading: the check above covered it too.
    let statement = parse_statement(sig.trusted_comment()).map_err(Error::SelfUpdate)?;
    let verdict = judge(&statement, current, target, &file, to).map_err(Error::SelfUpdate)?;
    if let Some(json) = check {
        let newer = verdict == Verdict::Newer;
        if json {
            println!(
                "{{\"schema\":1,\"current\":\"{current}\",\"latest\":\"{}\",\"update_available\":{newer}}}",
                statement.version
            );
        } else if newer {
            println!(
                "kern {} is available (this is {current}): run `kern self-update`",
                statement.version
            );
        } else {
            println!("kern {current} is the latest release");
        }
        return Ok(());
    }
    if verdict == Verdict::Current {
        println!("kern {current} is the latest release: nothing to do");
        return Ok(());
    }
    let unpacked = work.0.join("unpacked");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&unpacked)
        .map_err(|e| Error::SelfUpdate(format!("cannot create {}: {e}", unpacked.display())))?;
    let tar = Command::new("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&unpacked)
        .args(["--no-same-owner", "kern"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::SelfUpdate(format!("cannot run tar: {e}")))?;
    if !tar.status.success() {
        return Err(Error::SelfUpdate(format!(
            "the release tarball does not unpack: {}",
            String::from_utf8_lossy(&tar.stderr).trim()
        )));
    }
    let new = unpacked.join("kern");
    let meta = std::fs::symlink_metadata(&new)
        .map_err(|e| Error::SelfUpdate(format!("the tarball holds no `kern`: {e}")))?;
    if !meta.file_type().is_file() || meta.len() == 0 {
        return Err(Error::SelfUpdate(
            "the tarball's `kern` is not a regular file".into(),
        ));
    }
    std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| Error::SelfUpdate(format!("cannot make the new binary executable: {e}")))?;
    let want = format!("kern {}", statement.version);
    match probe(&new) {
        Ok(said) if said == want => {}
        Ok(said) => {
            return Err(Error::SelfUpdate(format!(
                "the new binary says {said:?}, its signature says {want:?}: nothing replaced"
            )))
        }
        Err(why) => {
            return Err(Error::SelfUpdate(format!(
                "the new binary does not run on this machine ({why}): nothing replaced"
            )))
        }
    }
    sync(&new)?;
    // KEEP THE OLD ONE FIRST. A hard link is instant and needs no space; where the filesystem
    // refuses links, a copy. Built in the work directory and renamed into place, so an older
    // `.previous` is replaced in one step and never half-written.
    let kept = work.0.join("previous");
    if std::fs::hard_link(&place.exe, &kept).is_err() {
        std::fs::copy(&place.exe, &kept).map_err(|e| {
            Error::SelfUpdate(format!(
                "cannot keep a copy of {}: {e}",
                place.exe.display()
            ))
        })?;
        sync(&kept)?;
    }
    std::fs::rename(&kept, &place.previous).map_err(|e| {
        Error::SelfUpdate(format!("cannot write {}: {e}", place.previous.display()))
    })?;
    std::fs::rename(&new, &place.exe)
        .map_err(|e| Error::SelfUpdate(format!("cannot replace {}: {e}", place.exe.display())))?;
    sync(&place.dir)?;
    println!(
        "kern {} installed at {} (was {current}); the previous binary is kept as {}: `kern \
         self-update --rollback` puts it back",
        statement.version,
        place.exe.display(),
        place.previous.display()
    );
    Ok(())
}

/// Swap the binary with `<name>.previous`, so a second rollback undoes the first.
fn rollback() -> Result<(), Error> {
    let place = place()?;
    let _lock = lock_dir(&place.dir)?;
    let meta = std::fs::symlink_metadata(&place.previous).map_err(|_| {
        Error::SelfUpdate(format!(
            "there is no {} to go back to: only a binary installed by `kern self-update` keeps one",
            place.previous.display()
        ))
    })?;
    if !meta.file_type().is_file() {
        return Err(Error::SelfUpdate(format!(
            "{} is not a regular file: not used",
            place.previous.display()
        )));
    }
    let said = match probe(&place.previous) {
        Ok(said) if said.starts_with("kern ") => said,
        Ok(said) => {
            return Err(Error::SelfUpdate(format!(
                "{} does not answer as kern ({said:?}): not used",
                place.previous.display()
            )))
        }
        Err(why) => {
            return Err(Error::SelfUpdate(format!(
                "{} does not run on this machine ({why}): not used",
                place.previous.display()
            )))
        }
    };
    exchange(&place.previous, &place.exe, &place.dir)?;
    sync(&place.dir)?;
    println!(
        "{said} is back at {}; the binary it replaced is kept as {}: a second `kern self-update \
         --rollback` swaps them again",
        place.exe.display(),
        place.previous.display()
    );
    Ok(())
}

/// Swap two paths in one step (`renameat2(RENAME_EXCHANGE)`), or, where the filesystem does not
/// offer it, in three renames through a link in the same directory.
fn exchange(a: &Path, b: &Path, dir: &Path) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    let c = |p: &Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .map_err(|_| Error::SelfUpdate(format!("{} holds a NUL byte", p.display())))
    };
    let (ca, cb) = (c(a)?, c(b)?);
    // SAFETY: both paths are NUL-terminated C strings that outlive the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            ca.as_ptr(),
            libc::AT_FDCWD,
            cb.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if !matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOSYS)) {
        return Err(Error::SelfUpdate(format!(
            "cannot swap {} and {}: {e}",
            a.display(),
            b.display()
        )));
    }
    let work = WorkDir::create(dir)?;
    let held = work.0.join("held");
    std::fs::hard_link(b, &held)
        .and_then(|()| std::fs::rename(a, b))
        .and_then(|()| std::fs::rename(&held, a))
        .map_err(|e| {
            Error::SelfUpdate(format!(
                "cannot swap {} and {}: {e}",
                a.display(),
                b.display()
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard base64, decode only: enough to read a key's id out of its text.
    fn b64_decode(s: &str) -> Option<Vec<u8>> {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for c in s.bytes().filter(|c| *c != b'=') {
            let v = A.iter().position(|a| *a == c)? as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        Some(out)
    }

    #[test]
    fn the_built_in_keys_decode_and_carry_the_ids_minisign_printed() {
        // A key pasted with one character wrong still decodes as SOME key, and every release would
        // then be refused in the field. minisign prints the id as the 8 key-id bytes read as a
        // little-endian u64; the id is copied from its output on 2026-11-18.
        for (id, b64) in RELEASE_KEYS {
            assert!(PublicKey::from_base64(b64).is_ok(), "{id} does not decode");
            let raw = b64_decode(b64).unwrap_or_default();
            assert_eq!(raw.len(), 42, "{id}");
            assert_eq!(&raw[..2], b"Ed", "{id}");
            let mut kid = [0u8; 8];
            kid.copy_from_slice(&raw[2..10]);
            assert_eq!(format!("{:016X}", u64::from_le_bytes(kid)), id);
        }
        assert_ne!(RELEASE_KEYS[0].1, RELEASE_KEYS[1].1);
    }

    #[test]
    fn the_installer_and_the_signing_script_carry_the_same_keys() {
        // Four copies of one fact: this file, install.sh (checks a fresh install), install.ps1 (the
        // Windows assets) and
        // scripts/sign-release.sh (checks the owner's signature before uploading it). A rotation
        // that missed one would leave an installer refusing every release, or a signing script
        // approving a key no kern trusts.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for file in ["install.sh", "scripts/sign-release.sh"] {
            let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
            let line = text
                .lines()
                .find(|l| l.starts_with("KERN_RELEASE_KEYS="))
                .unwrap_or_default();
            let want = format!(
                "KERN_RELEASE_KEYS=\"{} {}\"",
                RELEASE_KEYS[0].1, RELEASE_KEYS[1].1
            );
            assert_eq!(line, want, "{file}");
        }
        // install.ps1 checks the Windows assets with the same two, in PowerShell's spelling.
        let ps = std::fs::read_to_string(root.join("install.ps1")).unwrap_or_default();
        let line = ps
            .lines()
            .find(|l| l.starts_with("$KernReleaseKeys ="))
            .unwrap_or_default();
        assert_eq!(
            line,
            format!(
                "$KernReleaseKeys = @('{}', '{}')",
                RELEASE_KEYS[0].1, RELEASE_KEYS[1].1
            ),
            "install.ps1"
        );
        // kern.exe checks its own update with the same two, and with nothing else: the code before
        // its tests carries exactly these two public keys.
        let win = std::fs::read_to_string(root.join("windows/kern-win/src/selfupdate.rs"))
            .unwrap_or_default();
        let code = win.split("#[cfg(test)]").next().unwrap_or_default();
        for (id, key) in RELEASE_KEYS {
            assert!(
                code.contains(&format!("\"{id}\"")) && code.contains(&format!("\"{key}\"")),
                "kern.exe lacks key {id}"
            );
        }
        assert_eq!(
            code.matches("\"RW").count(),
            2,
            "kern.exe carries a key kern does not"
        );
        // And docs/INSTALL.md, which shows the reader how to check a file by hand with them.
        let doc = std::fs::read_to_string(root.join("docs/INSTALL.md")).unwrap_or_default();
        for (id, key) in RELEASE_KEYS {
            assert!(
                doc.contains(&format!("-P {key}")),
                "docs/INSTALL.md lacks key {id}"
            );
        }
    }

    /// install.ps1 checks downloads with the kern that was installed BEFORE the run: saved first, used
    /// from the saved copy, and the new rootfs fetched while the old distro still exists to run it.
    /// Taken at check time, the verifier could already be the new binary (the in-place update swaps it
    /// before kern.exe is fetched), vouching for the files it came with.
    #[test]
    fn install_ps1_checks_with_the_kern_installed_before_the_run() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let ps = std::fs::read_to_string(root.join("install.ps1")).unwrap_or_default();
        let at = |needle: &str| ps.find(needle).unwrap_or(usize::MAX);
        // The run block: the verifier is saved before anything that replaces a file.
        let run = at("if (Ensure-WslEngine) {");
        let tail = &ps[run.min(ps.len())..];
        let pos = |needle: &str| tail.find(needle).unwrap_or(usize::MAX);
        assert!(
            pos("Save-Verifier") < pos("Import-Distro"),
            "Save-Verifier must run first"
        );
        assert!(pos("Import-Distro") < pos("Install-Shim"));
        // The check runs the SAVED copy, never whatever `kern` the distro holds at that moment.
        let body_start = at("function Verify-InDistro");
        let body = &ps[body_start.min(ps.len())..];
        let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
        assert!(body.contains("$script:VerifierPath"), "{body}");
        assert!(
            !body.contains("'kern'") && !body.contains("--exec kern"),
            "{body}"
        );
        // A re-import fetches (and so checks) the new rootfs BEFORE the old distro is unregistered.
        let reimport = at("in-place update unavailable");
        let after = &ps[reimport.min(ps.len())..];
        let fetch = after.find("Fetch $RootfsUrl").unwrap_or(usize::MAX);
        let unreg = after.find("--unregister $DistroName").unwrap_or(usize::MAX);
        assert!(
            fetch < unreg,
            "the rootfs must be fetched before the old distro goes"
        );
    }

    #[test]
    fn a_version_is_exactly_three_decimal_numbers() {
        assert_eq!(Version::parse("0.51.1"), Some(Version(0, 51, 1)));
        assert_eq!(Version::parse("v10.0.12"), Some(Version(10, 0, 12)));
        for bad in [
            "",
            "0.51",
            "0.51.1.2",
            "0.51.1-rc1",
            "v0.51.1-3-gabc-dirty",
            "01.2.3",
            "1..2",
            "a.b.c",
            "1.2.3 ",
            "1234567890.0.0",
            "vv1.2.3",
            "+1.2.3",
        ] {
            assert_eq!(Version::parse(bad), None, "{bad:?}");
        }
        assert!(Version(0, 52, 0) > Version(0, 51, 9));
        assert!(Version(1, 0, 0) > Version(0, 99, 99));
        assert!(Version(0, 51, 10) > Version(0, 51, 9));
        assert_eq!(Version(0, 51, 1).to_string(), "0.51.1");
    }

    const T: &str = "x86_64-unknown-linux-musl";
    const F: &str = "kern-x86_64-unknown-linux-musl.tar.gz";

    #[test]
    fn a_statement_is_read_strictly() {
        let ok = format!("kern-release v1 version=0.52.0 target={T} file={F}");
        assert_eq!(
            parse_statement(&ok),
            Ok(Statement {
                version: Version(0, 52, 0),
                target: T,
                file: F
            })
        );
        // Order is free; everything else is not.
        assert!(parse_statement(&format!(
            "kern-release v1 file={F} target={T} version=0.52.0"
        ))
        .is_ok());
        for bad in [
            format!("timestamp:1795000326\tfile:{F}\thashed"),
            format!("kern-release v2 version=0.52.0 target={T} file={F}"),
            format!("kern-release v1 version=0.52.0 target={T}"),
            format!("kern-release v1 version=0.52.0 version=0.53.0 target={T} file={F}"),
            format!("kern-release v1 version=0.52.0 target={T} file={F} extra=1"),
            format!("kern-release v1 version=0.52 target={T} file={F}"),
            format!("kern-release v1 version= target={T} file={F}"),
            format!("kern-release v1  version=0.52.0 target={T} file={F}"),
            format!("kern-release v1 version=0.52.0 target={T} file={F} "),
            format!("kern-release v1 version=0.52.0 target={T} {F}"),
            "kern-release".to_string(),
            String::new(),
        ] {
            assert!(parse_statement(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_a_newer_release_for_this_machine_and_this_file_is_installed() {
        let s = |v: Version, t: &'static str, f: &'static str| Statement {
            version: v,
            target: t,
            file: f,
        };
        let cur = Version(0, 51, 1);
        assert_eq!(
            judge(&s(Version(0, 52, 0), T, F), cur, T, F, None),
            Ok(Verdict::Newer)
        );
        assert_eq!(judge(&s(cur, T, F), cur, T, F, None), Ok(Verdict::Current));
        let down = judge(&s(Version(0, 50, 0), T, F), cur, T, F, None);
        assert!(
            down.as_ref().is_err_and(|m| m.contains("never goes back")),
            "{down:?}"
        );
        let other_arch = "aarch64-unknown-linux-musl";
        assert!(judge(&s(Version(0, 52, 0), other_arch, F), cur, T, F, None).is_err());
        assert!(judge(
            &s(
                Version(0, 52, 0),
                T,
                "kern-aarch64-unknown-linux-musl.tar.gz"
            ),
            cur,
            T,
            F,
            None
        )
        .is_err());
        // `--to` names the version; a statement for another one is refused, and `--to` an older
        // version is still a downgrade.
        let to = Some(Version(0, 52, 0));
        assert_eq!(
            judge(&s(Version(0, 52, 0), T, F), cur, T, F, to),
            Ok(Verdict::Newer)
        );
        assert!(judge(&s(Version(0, 53, 0), T, F), cur, T, F, to).is_err());
        assert!(judge(
            &s(Version(0, 50, 0), T, F),
            cur,
            T,
            F,
            Some(Version(0, 50, 0))
        )
        .is_err());
    }

    #[test]
    fn a_binary_another_tool_installed_is_left_to_that_tool() {
        let cases = [
            ("/home/u/.local/bin/kern", Owner::Standalone),
            ("/usr/local/bin/kern", Owner::Standalone),
            ("/opt/kern/kern", Owner::Standalone),
            (
                "/home/u/.venv/lib/python3.12/site-packages/kern_sandbox/bin/kern",
                Owner::Pip,
            ),
            (
                "/usr/lib/python3/dist-packages/kern_sandbox/bin/kern",
                Owner::Pip,
            ),
            ("/home/u/app/node_modules/kern-sandbox/bin/kern", Owner::Npm),
            ("/home/u/.cargo/bin/getkern", Owner::Cargo),
            ("/nix/store/abc-kern/bin/kern", Owner::Nix),
            (
                "/home/linuxbrew/.linuxbrew/Cellar/kern/0.51.1/bin/kern",
                Owner::Homebrew,
            ),
            ("/opt/homebrew/bin/kern", Owner::Homebrew),
            ("/usr/bin/kern", Owner::System),
            ("/bin/kern", Owner::System),
            ("/usr/sbin/kern", Owner::System),
        ];
        for (p, want) in cases {
            assert_eq!(owner_of(Path::new(p)), want, "{p}");
        }
        // A `target` directory is a source tree only when a Cargo.toml sits beside it.
        let tree = std::env::temp_dir().join(format!("kern-su-tree-{}", std::process::id()));
        let bin = tree.join("target/release");
        assert!(std::fs::create_dir_all(&bin).is_ok());
        assert_eq!(owner_of(&bin.join("kern")), Owner::Standalone);
        assert!(std::fs::write(tree.join("Cargo.toml"), "").is_ok());
        assert_eq!(owner_of(&bin.join("kern")), Owner::SourceTree);
        let _ = std::fs::remove_dir_all(&tree);
        // Every owner but the installer's gets a refusal naming the command to use.
        for owner in [
            Owner::Pip,
            Owner::Npm,
            Owner::Cargo,
            Owner::Homebrew,
            Owner::Nix,
            Owner::System,
            Owner::SourceTree,
        ] {
            assert!(
                owned_elsewhere(&owner, Path::new("/x/kern")).is_some(),
                "{owner:?}"
            );
        }
        assert!(owned_elsewhere(&Owner::Standalone, Path::new("/x/kern")).is_none());
    }

    #[test]
    fn the_release_target_is_a_published_one() {
        let t = release_target();
        assert!(
            matches!(
                t,
                Some("x86_64-unknown-linux-musl") | Some("aarch64-unknown-linux-musl")
            ),
            "{t:?}"
        );
    }
}
