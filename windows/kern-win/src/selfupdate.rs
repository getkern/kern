//! `kern self-update` typed in Windows: the distro's kern first, then THIS bridge, each verified.
//!
//! ORDER. The kern inside the distro updates itself first (its own `self-update`, which checks its
//! own download). Only when that succeeded does this bridge fetch the `kern-windows-x86_64.exe` of
//! the release the distro now runs, check its signature HERE, with the release keys built into this
//! binary, and replace itself. A bridge that does not match the distro's release is the drift this
//! exists to end: `kern.exe` had no way to update but re-running the installer.
//!
//! THE CHECK IS THIS BINARY'S OWN. minisign's verifier (`minisign-verify`, by minisign's author,
//! with no dependencies of its own, pinned exactly as `kern` pins it), the same two keys as `kern`,
//! `install.sh`, `install.ps1` and `sign-release.sh` (a test in `kern` reads this file to keep them
//! equal), and the same strict release statement: `kern-release v1 version=X
//! target=x86_64-pc-windows-gnu file=kern-windows-x86_64.exe`, where X must be the distro's version.
//!
//! THE SWAP. Windows will not overwrite a running executable but will rename it: the running file
//! becomes `<name>.previous` and the verified download takes its name, so the next `kern` is the new
//! one. `kern self-update --rollback` swaps the two back after the distro's own rollback.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use minisign_verify::{PublicKey, Signature};

/// The release keys, as `minisign -G` printed them on 2026-11-18: (key id, public key). The same
/// two `kern` carries; the first signs every release, the second is the offline spare.
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

/// This bridge's release target and asset name, as the release statement names them.
const TARGET: &str = "x86_64-pc-windows-gnu";
const ASSET: &str = "kern-windows-x86_64.exe";

/// Where a tagged release's assets are (`<TAGGED>/v<version>/<asset>`).
const TAGGED: &str = "https://github.com/getkern/kern/releases/download";

/// Download bounds: the bridge is a few hundred KiB, a signature four short lines.
const MAX_EXE_BYTES: u64 = 64 << 20;
const MAX_SIG_BYTES: u64 = 4096;

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

/// Read a trusted comment as a release statement, strictly: single spaces, each key once, no key
/// the format does not define. Read loosely, a statement is one someone else can write for you.
pub(crate) fn parse_statement(comment: &str) -> Result<Statement<'_>, String> {
    let shown: String = comment.chars().take(200).collect();
    let not_ours = || format!("the signed comment is not a kern release statement: {shown:?}");
    let mut words = comment.split(' ');
    if words.next() != Some("kern-release") || words.next() != Some("v1") {
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

/// The built-in keys, decoded.
fn trusted_keys() -> Result<Vec<PublicKey>, String> {
    RELEASE_KEYS
        .iter()
        .map(|(id, b64)| {
            PublicKey::from_base64(b64)
                .map_err(|e| format!("the built-in release key {id} does not decode: {e}"))
        })
        .collect()
}

/// Check `sig_text` over `bytes` with whichever of `keys` made it, then read the statement it signs:
/// this target, this asset, and exactly `want`. Every refusal says why and replaces nothing.
pub(crate) fn verify(
    bytes: &[u8],
    sig_text: &str,
    keys: &[PublicKey],
    want: Version,
) -> Result<(), String> {
    let sig =
        Signature::decode(sig_text).map_err(|e| format!("the signature does not parse: {e}"))?;
    let mut checked = false;
    for key in keys {
        match key.verify(bytes, &sig, false) {
            Ok(()) => {
                checked = true;
                break;
            }
            Err(minisign_verify::Error::UnexpectedKeyId) => continue,
            Err(_) => {
                return Err(
                    "the signature does not match the download (altered or truncated): \
                     nothing replaced"
                        .to_string(),
                )
            }
        }
    }
    if !checked {
        return Err(
            "the download is signed with a key kern.exe does not trust: nothing replaced"
                .to_string(),
        );
    }
    // Only now is the comment worth reading: the signature covered it too.
    let st = parse_statement(sig.trusted_comment())?;
    if st.target != TARGET {
        return Err(format!(
            "the signature is for {}, this bridge is {TARGET}: nothing replaced",
            st.target
        ));
    }
    if st.file != ASSET {
        return Err(format!(
            "the signature is for {}, not {ASSET}: nothing replaced",
            st.file
        ));
    }
    if st.version != want {
        return Err(format!(
            "the distro runs kern {want}, the signed bridge is {}: nothing replaced",
            st.version
        ));
    }
    Ok(())
}

/// Download `url` to `out` with Windows' own `curl.exe`, bounded in size and time. `https` only, as
/// `kern`'s own self-update: a DEBUG build also takes an `http` mirror, which is how a test serves a
/// release on a LAN (the signature is checked either way).
fn fetch(url: &str, out: &Path, cap: u64, mirror: bool) -> Result<(), String> {
    let plain = cfg!(debug_assertions) && mirror && url.starts_with("http://");
    if !plain && !url.starts_with("https://") {
        return Err(format!(
            "refusing to download over anything but https: {url}"
        ));
    }
    let proto = if plain { "=http" } else { "=https" };
    let st = Command::new("curl.exe")
        .args([
            "-fsSL",
            "--proto",
            proto,
            "--proto-redir",
            proto,
            "--max-time",
            "600",
        ])
        .args(["--max-filesize", &cap.to_string(), "-o"])
        .arg(out)
        .arg(url)
        .stdin(Stdio::null())
        .status();
    match st {
        Ok(s) if s.success() => {}
        Ok(s) => {
            return Err(format!(
                "{url}: curl.exe exited {} (no such release, or no network)",
                s.code().unwrap_or(-1)
            ))
        }
        Err(e) => {
            return Err(format!(
                "curl.exe cannot run ({e}); Windows 10 1803 and later ship it in System32"
            ))
        }
    }
    // A stream of unknown length is not bounded by --max-filesize: the size is checked here too.
    let len = fs::metadata(out).map(|m| m.len()).unwrap_or(u64::MAX);
    if len > cap {
        let _ = fs::remove_file(out);
        return Err(format!("{url}: larger than {cap} bytes"));
    }
    Ok(())
}

/// The version the distro's kern reports, as a release version.
fn distro_version() -> Result<Version, String> {
    let t = crate::resolve_target().map_err(|_| "no WSL distro with kern was found".to_string())?;
    let out = match &t.kern_path {
        Some(p) => crate::wsl_query(&["-d", &t.distro, "--exec", p, "--version"]),
        None => crate::wsl_query(&[
            "-d",
            &t.distro,
            "--exec",
            "sh",
            "-lc",
            "exec kern --version",
        ]),
    };
    let text = out.ok_or("the distro's kern did not answer --version")?;
    let text = text.trim();
    text.split_whitespace()
        .nth(1)
        .and_then(Version::parse)
        .ok_or_else(|| {
            format!(
                "the distro's kern says {:?}, which is not a release version: kern.exe is left as \
                 it is",
                crate::short(text)
            )
        })
}

/// `KERN_SELF_UPDATE_URL` (a mirror holding a release's assets) reaches the distro's kern too, so
/// both halves read the same release: WSL passes a Windows variable only when `WSLENV` names it.
fn pass_into_wsl(name: &str) {
    if env::var_os(name).is_none() {
        return;
    }
    let cur = env::var("WSLENV").unwrap_or_default();
    if cur.split(':').any(|e| e.split('/').next() == Some(name)) {
        return;
    }
    let next = if cur.is_empty() {
        name.to_string()
    } else {
        format!("{cur}:{name}")
    };
    // Single-threaded: nothing else reads the environment while it is set.
    env::set_var("WSLENV", next);
}

/// The paths of the swap, beside this executable.
struct Paths {
    exe: PathBuf,
    previous: PathBuf,
    download: PathBuf,
    signature: PathBuf,
}

fn paths() -> Result<Paths, String> {
    let exe = env::current_exe().map_err(|e| format!("cannot find this binary: {e}"))?;
    let name = exe
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("this binary's name is not text")?
        .to_string();
    let dir = exe
        .parent()
        .ok_or("this binary has no folder")?
        .to_path_buf();
    Ok(Paths {
        previous: dir.join(format!("{name}.previous")),
        download: dir.join(format!("{name}.download")),
        signature: dir.join(format!("{name}.download.minisig")),
        exe,
    })
}

fn update_exe() -> Result<String, String> {
    let want = distro_version()?;
    let p = paths()?;
    let mirror = env::var("KERN_SELF_UPDATE_URL")
        .ok()
        .filter(|u| !u.trim().is_empty());
    let base = match &mirror {
        Some(u) => u.trim().trim_end_matches('/').to_string(),
        None => format!("{TAGGED}/v{want}"),
    };
    let cleanup = |p: &Paths| {
        let _ = fs::remove_file(&p.download);
        let _ = fs::remove_file(&p.signature);
    };
    let fetched = fetch(
        &format!("{base}/{ASSET}.minisig"),
        &p.signature,
        MAX_SIG_BYTES,
        mirror.is_some(),
    )
    .and_then(|()| {
        fetch(
            &format!("{base}/{ASSET}"),
            &p.download,
            MAX_EXE_BYTES,
            mirror.is_some(),
        )
    });
    if let Err(e) = fetched {
        cleanup(&p);
        return Err(e);
    }
    let checked = (|| -> Result<Vec<u8>, String> {
        let bytes = fs::read(&p.download).map_err(|e| format!("cannot read the download: {e}"))?;
        let sig = fs::read_to_string(&p.signature)
            .map_err(|e| format!("the signature is not text: {e}"))?;
        verify(&bytes, &sig, &trusted_keys()?, want)?;
        Ok(bytes)
    })();
    let bytes = match checked {
        Ok(b) => b,
        Err(e) => {
            cleanup(&p);
            return Err(e);
        }
    };
    let _ = fs::remove_file(&p.signature);
    if !swap_in(&p, &bytes)? {
        return Ok(format!(
            "kern.exe is the one released with kern {want} already"
        ));
    }
    Ok(format!(
        "kern.exe replaced with the one released with kern {want} (signature checked); the one \
         it replaced is {}, and `kern self-update --rollback` puts it back",
        p.previous.display()
    ))
}

/// Put the VERIFIED download (`bytes`, already at `p.download`) in place of `p.exe`, keeping the
/// replaced one as `p.previous`. `false` when the two are the same file already.
fn swap_in(p: &Paths, bytes: &[u8]) -> Result<bool, String> {
    if fs::read(&p.exe).is_ok_and(|cur| cur == bytes) {
        let _ = fs::remove_file(&p.download);
        return Ok(false);
    }
    let _ = fs::remove_file(&p.previous);
    if let Err(e) = fs::rename(&p.exe, &p.previous) {
        let _ = fs::remove_file(&p.download);
        return Err(format!("cannot move the running kern.exe aside: {e}"));
    }
    if let Err(e) = fs::rename(&p.download, &p.exe) {
        // Put the running one back under its name: never leave the folder without a kern.exe.
        let _ = fs::rename(&p.previous, &p.exe);
        let _ = fs::remove_file(&p.download);
        return Err(format!("cannot put the new kern.exe in place: {e}"));
    }
    Ok(true)
}

fn rollback_exe() -> Result<String, String> {
    rollback_in(&paths()?)
}

/// Swap `p.exe` and `p.previous`; a second rollback undoes the first.
fn rollback_in(p: &Paths) -> Result<String, String> {
    if fs::symlink_metadata(&p.previous).is_err() {
        return Ok("no previous kern.exe is kept, so the bridge stays as it is".to_string());
    }
    let tmp = p.exe.with_extension("exe.rollback");
    fs::rename(&p.exe, &tmp).map_err(|e| format!("cannot move the running kern.exe aside: {e}"))?;
    if let Err(e) = fs::rename(&p.previous, &p.exe) {
        let _ = fs::rename(&tmp, &p.exe);
        return Err(format!("cannot put the previous kern.exe back: {e}"));
    }
    if let Err(e) = fs::rename(&tmp, &p.previous) {
        return Err(format!(
            "the previous kern.exe is back; the one it replaced stays as {} ({e})",
            tmp.display()
        ));
    }
    Ok(format!(
        "kern.exe rolled back; the one it replaced is {}",
        p.previous.display()
    ))
}

/// `kern self-update [--check [--json]] [--to X.Y.Z] [--rollback]` in Windows.
pub(crate) fn run(args: &[String]) -> i32 {
    let rest = args.get(1..).unwrap_or_default();
    let check = rest.iter().any(|a| a == "--check");
    let rollback = rest.iter().any(|a| a == "--rollback");
    pass_into_wsl("KERN_SELF_UPDATE_URL");
    // A DEBUG build can be told to leave the distro alone and test this bridge's half by itself.
    let exe_only = cfg!(debug_assertions) && env::var("KERN_TEST_EXE_ONLY").as_deref() == Ok("1");
    let code = if exe_only {
        0
    } else {
        crate::forward_to_kern(args, false)
    };
    if code != 0 || check {
        return code;
    }
    let done = if rollback {
        rollback_exe()
    } else {
        update_exe()
    };
    match done {
        Ok(msg) => {
            eprintln!("kern: {msg}");
            0
        }
        Err(e) => {
            eprintln!("kern: kern.exe: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway key made for these tests (`minisign -G -W`), never a release key.
    const TEST_PUB: &str = "RWR0282jiWxtdPpvefC8kX1Pw5VlRdvKYSvRqZG+51ylTEjt8T/8aA5z";
    const FILE: &[u8] = b"kern.exe bytes for the test\n";
    const GOOD: &str = "untrusted comment: signature from minisign secret key\nRUR0282jiWxtdPHfjXGFU7KjZJGR9vZwyr+6AZuUhhYlnVh6XX0IP91V9v3cARtc5m9TwzjodeCmchj9rC/qIm7Qfw0r0AiPhAE=\ntrusted comment: kern-release v1 version=0.57.0 target=x86_64-pc-windows-gnu file=kern-windows-x86_64.exe\nvCy9dDENdQVoezOOa5Az34KqEP+BRk0yim7lq10vFa9yHp6VBtTWFXxdV9fe2dy0njhZAilfATR13wUy8GxQBg==\n";
    const LINUX: &str = "untrusted comment: signature from minisign secret key\nRUR0282jiWxtdPHfjXGFU7KjZJGR9vZwyr+6AZuUhhYlnVh6XX0IP91V9v3cARtc5m9TwzjodeCmchj9rC/qIm7Qfw0r0AiPhAE=\ntrusted comment: kern-release v1 version=0.57.0 target=x86_64-unknown-linux-musl file=kern-windows-x86_64.exe\nTQRNcsFapfijXPcvgPnaYjT5k8en4MMEcvUxXuSPH1fnr3gMP8qcIA7j+RFiZTrU10VTwBS6LXJGzNlvKGegCQ==\n";
    const OTHER_FILE: &str = "untrusted comment: signature from minisign secret key\nRUR0282jiWxtdPHfjXGFU7KjZJGR9vZwyr+6AZuUhhYlnVh6XX0IP91V9v3cARtc5m9TwzjodeCmchj9rC/qIm7Qfw0r0AiPhAE=\ntrusted comment: kern-release v1 version=0.57.0 target=x86_64-pc-windows-gnu file=kern-x86_64-unknown-linux-musl.tar.gz\n1YIKaEdJbB4Gto2hO8AYZTsYkJN2zmTynNEiRBWqSwPvb1nwXJATd4YyS591Mkt/p2s/dl5mXMZUuFBcwRv5DQ==\n";

    fn keys() -> Vec<PublicKey> {
        PublicKey::from_base64(TEST_PUB)
            .map(|k| vec![k])
            .unwrap_or_default()
    }

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or(Version(0, 0, 0))
    }

    #[test]
    fn a_good_signature_for_this_bridge_and_this_version_is_accepted() {
        assert_eq!(keys().len(), 1);
        assert_eq!(verify(FILE, GOOD, &keys(), v("0.57.0")), Ok(()));
    }

    #[test]
    fn an_altered_file_a_wrong_key_or_a_wrong_statement_is_refused() {
        let mut altered = FILE.to_vec();
        altered[0] ^= 1;
        let e = verify(&altered, GOOD, &keys(), v("0.57.0"));
        assert!(
            matches!(&e, Err(m) if m.contains("altered or truncated")),
            "{e:?}"
        );
        // The release keys did not make the test signature.
        let release = trusted_keys().unwrap_or_default();
        assert_eq!(release.len(), 2);
        let e = verify(FILE, GOOD, &release, v("0.57.0"));
        assert!(
            matches!(&e, Err(m) if m.contains("does not trust")),
            "{e:?}"
        );
        let e = verify(FILE, LINUX, &keys(), v("0.57.0"));
        assert!(
            matches!(&e, Err(m) if m.contains("x86_64-unknown-linux-musl")),
            "{e:?}"
        );
        let e = verify(FILE, OTHER_FILE, &keys(), v("0.57.0"));
        assert!(
            matches!(&e, Err(m) if m.contains("not kern-windows-x86_64.exe")),
            "{e:?}"
        );
        let e = verify(FILE, GOOD, &keys(), v("0.58.0"));
        assert!(
            matches!(&e, Err(m) if m.contains("the distro runs kern 0.58.0")),
            "{e:?}"
        );
        let e = verify(FILE, "not a signature", &keys(), v("0.57.0"));
        assert!(
            matches!(&e, Err(m) if m.contains("does not parse")),
            "{e:?}"
        );
    }

    #[test]
    fn the_statement_is_read_strictly() {
        let ok = parse_statement(
            "kern-release v1 version=0.57.0 target=x86_64-pc-windows-gnu file=kern-windows-x86_64.exe",
        );
        assert_eq!(ok.map(|s| s.version), Ok(v("0.57.0")));
        for bad in [
            "kern-release v2 version=0.57.0 target=t file=f",
            "kern-release v1 version=0.57.0 target=t",
            "kern-release v1 version=0.57.0 version=0.58.0 target=t file=f",
            "kern-release v1 version=0.57.0 target=t file=f extra=1",
            "kern-release v1 version=0.057.0 target=t file=f",
            "kern-release  v1 version=0.57.0 target=t file=f",
        ] {
            assert!(parse_statement(bad).is_err(), "{bad}");
        }
    }

    fn temp_paths(tag: &str) -> (PathBuf, Paths) {
        let dir = std::env::temp_dir().join(format!("kern-exe-swap-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let p = Paths {
            exe: dir.join("kern.exe"),
            previous: dir.join("kern.exe.previous"),
            download: dir.join("kern.exe.download"),
            signature: dir.join("kern.exe.download.minisig"),
        };
        (dir, p)
    }

    #[test]
    fn the_swap_keeps_the_replaced_bridge_and_rollback_toggles_it() {
        let (dir, p) = temp_paths("swap");
        let _ = fs::write(&p.exe, b"old");
        let _ = fs::write(&p.download, b"new");
        assert_eq!(swap_in(&p, b"new"), Ok(true));
        assert_eq!(fs::read(&p.exe).unwrap_or_default(), b"new");
        assert_eq!(fs::read(&p.previous).unwrap_or_default(), b"old");
        assert!(!p.download.exists());
        assert!(rollback_in(&p).is_ok());
        assert_eq!(fs::read(&p.exe).unwrap_or_default(), b"old");
        assert_eq!(fs::read(&p.previous).unwrap_or_default(), b"new");
        assert!(rollback_in(&p).is_ok());
        assert_eq!(fs::read(&p.exe).unwrap_or_default(), b"new");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_same_bridge_is_not_swapped_and_no_previous_means_nothing_to_roll_back() {
        let (dir, p) = temp_paths("same");
        let _ = fs::write(&p.exe, b"same");
        let _ = fs::write(&p.download, b"same");
        assert_eq!(swap_in(&p, b"same"), Ok(false));
        assert!(!p.download.exists() && !p.previous.exists());
        let r = rollback_in(&p);
        assert!(matches!(&r, Ok(m) if m.contains("no previous")), "{r:?}");
        assert_eq!(fs::read(&p.exe).unwrap_or_default(), b"same");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_version_is_three_plain_numbers() {
        assert_eq!(Version::parse("v0.56.0"), Some(Version(0, 56, 0)));
        assert_eq!(Version::parse("0.56"), None);
        assert_eq!(Version::parse("0.56.0-dirty"), None);
        assert_eq!(Version::parse("01.2.3"), None);
        assert_eq!(v("0.56.0").to_string(), "0.56.0");
    }
}
