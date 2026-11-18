//! `kern self-update` end to end, against releases signed HERE with a throwaway key.
//!
//! A debug kern trusts one extra key, named by `KERN_SELF_UPDATE_TEST_PUBKEY`, and takes `file://`
//! as a release directory; a release build compiles both out. Each test copies the built kern into
//! its own directory and updates THAT copy, so the binary cargo built is never touched.
//!
//! The refusals are the point: each one must leave the installed binary byte for byte as it was,
//! with no `.previous` and no work directory left behind.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TARGET: &str = if cfg!(target_arch = "x86_64") {
    "x86_64-unknown-linux-musl"
} else {
    "aarch64-unknown-linux-musl"
};

fn asset() -> String {
    format!("kern-{TARGET}.tar.gz")
}

/// Standard base64 with padding.
fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A minisign key pair, writing the formats minisign writes.
struct Signer {
    key: ed25519_dalek::SigningKey,
    id: [u8; 8],
}

impl Signer {
    fn new(seed: u8) -> Signer {
        Signer {
            key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            id: [seed, 1, 2, 3, 4, 5, 6, 7],
        }
    }

    /// `Ed` + key id + public key, as the second line of a minisign `.pub`.
    fn public(&self) -> String {
        let mut raw = b"Ed".to_vec();
        raw.extend_from_slice(&self.id);
        raw.extend_from_slice(self.key.verifying_key().as_bytes());
        b64(&raw)
    }

    /// A prehashed (`ED`) signature over `data` with `comment` as the trusted comment.
    fn sign(&self, data: &[u8], comment: &str) -> String {
        use blake2::Digest;
        use ed25519_dalek::Signer as _;
        let hash = blake2::Blake2b512::digest(data);
        let sig = self.key.sign(&hash).to_bytes();
        let mut line = b"ED".to_vec();
        line.extend_from_slice(&self.id);
        line.extend_from_slice(&sig);
        let mut global = sig.to_vec();
        global.extend_from_slice(comment.as_bytes());
        let global = self.key.sign(&global).to_bytes();
        format!(
            "untrusted comment: signature from minisign secret key\n{}\ntrusted comment: {comment}\n{}\n",
            b64(&line),
            b64(&global)
        )
    }
}

fn statement(version: &str) -> String {
    format!(
        "kern-release v1 version={version} target={TARGET} file={}",
        asset()
    )
}

/// One test's world: `bin/kern` (a copy of the built kern) and `rel/` (the release directory).
struct World {
    root: PathBuf,
}

impl World {
    fn new(tag: &str) -> World {
        let root = std::env::temp_dir().join(format!("kern-su-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["bin", "rel", "pack"] {
            std::fs::create_dir_all(root.join(d)).expect("world dir");
        }
        std::fs::copy(env!("CARGO_BIN_EXE_kern"), root.join("bin/kern")).expect("copy kern");
        World { root }
    }

    fn bin(&self) -> PathBuf {
        self.root.join("bin/kern")
    }

    fn previous(&self) -> PathBuf {
        self.root.join("bin/kern.previous")
    }

    /// Publish a release whose `kern` is a script answering `--version` with `says`.
    fn publish(&self, says: &str) -> Vec<u8> {
        let pack = self.root.join("pack");
        let script = format!("#!/bin/sh\necho '{says}'\n");
        std::fs::write(pack.join("kern"), script).expect("write the fake kern");
        let tarball = self.root.join("rel").join(asset());
        let ok = Command::new("tar")
            .arg("-C")
            .arg(&pack)
            .arg("-czf")
            .arg(&tarball)
            .arg("kern")
            .status()
            .expect("run tar");
        assert!(ok.success());
        std::fs::read(&tarball).expect("read the tarball")
    }

    fn put_signature(&self, minisig: &str) {
        let p = self.root.join("rel").join(format!("{}.minisig", asset()));
        std::fs::write(p, minisig).expect("write the signature");
    }

    fn self_update(&self, trusted: &Signer, args: &[&str]) -> Output {
        Command::new(self.bin())
            .arg("self-update")
            .args(args)
            .env(
                "KERN_SELF_UPDATE_URL",
                format!("file://{}", self.root.join("rel").display()),
            )
            .env("KERN_SELF_UPDATE_TEST_PUBKEY", trusted.public())
            .env("KERN_SELF_UPDATE_TEST_VERSION", "0.51.1")
            .output()
            .expect("run kern self-update")
    }

    /// Nothing but `kern` (and `kern.previous` when `kept`) in `bin/`: no work directory left.
    fn assert_bin_holds_only(&self, kept: bool) {
        let mut names: Vec<String> = std::fs::read_dir(self.root.join("bin"))
            .expect("list bin")
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort();
        let want: Vec<&str> = if kept {
            vec!["kern", "kern.previous"]
        } else {
            vec!["kern"]
        };
        assert_eq!(names, want);
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn said(out: &Output) -> String {
    format!(
        "rc={:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn version_of(bin: &Path) -> String {
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .expect("run --version");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn a_newer_signed_release_replaces_kern_and_keeps_the_old_one() {
    let w = World::new("newer");
    let key = Signer::new(7);
    let original = std::fs::read(w.bin()).expect("read kern");
    let tarball = w.publish("kern 99.0.0");
    w.put_signature(&key.sign(&tarball, &statement("99.0.0")));

    let check = w.self_update(&key, &["--check", "--json"]);
    assert!(check.status.success(), "{}", said(&check));
    assert_eq!(
        String::from_utf8_lossy(&check.stdout).trim(),
        r#"{"schema":1,"current":"0.51.1","latest":"99.0.0","update_available":true}"#
    );
    assert_eq!(
        std::fs::read(w.bin()).expect("read kern"),
        original,
        "--check replaced the binary"
    );
    w.assert_bin_holds_only(false);

    let out = w.self_update(&key, &[]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("kern 99.0.0 installed"),
        "{}",
        said(&out)
    );
    assert_eq!(version_of(&w.bin()), "kern 99.0.0");
    assert_eq!(
        std::fs::read(w.previous()).expect("read previous"),
        original
    );
    w.assert_bin_holds_only(true);
}

#[test]
fn rollback_swaps_kern_with_the_previous_binary() {
    let w = World::new("rollback");
    let key = Signer::new(7);
    let original = std::fs::read(w.bin()).expect("read kern");
    let none = w.self_update(&key, &["--rollback"]);
    assert!(
        !none.status.success() && said(&none).contains("no "),
        "{}",
        said(&none)
    );

    std::fs::write(w.previous(), "#!/bin/sh\necho 'kern 0.51.0'\n").expect("write previous");
    let mut perm = std::fs::metadata(w.previous()).expect("stat").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o755);
    std::fs::set_permissions(w.previous(), perm).expect("chmod");

    let out = w.self_update(&key, &["--rollback"]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(version_of(&w.bin()), "kern 0.51.0");
    assert_eq!(
        std::fs::read(w.previous()).expect("read previous"),
        original
    );
    w.assert_bin_holds_only(true);
}

/// Publish `tarball` with `minisig`, run an update, and require a refusal mentioning `why` that
/// left the installed kern exactly as it was.
fn assert_refused(w: &World, key: &Signer, why: &str) {
    let original = std::fs::read(w.bin()).expect("read kern");
    let out = w.self_update(key, &[]);
    assert!(!out.status.success(), "accepted:\n{}", said(&out));
    assert!(
        said(&out).contains(why),
        "refused for another reason than {why:?}:\n{}",
        said(&out)
    );
    assert_eq!(
        std::fs::read(w.bin()).expect("read kern"),
        original,
        "the binary changed"
    );
    w.assert_bin_holds_only(false);
}

#[test]
fn an_altered_tarball_is_refused() {
    let w = World::new("altered");
    let key = Signer::new(7);
    let mut tarball = w.publish("kern 99.0.0");
    w.put_signature(&key.sign(&tarball, &statement("99.0.0")));
    tarball.push(0);
    std::fs::write(w.root.join("rel").join(asset()), &tarball).expect("alter");
    assert_refused(&w, &key, "does not match the download");
}

#[test]
fn a_truncated_tarball_is_refused() {
    let w = World::new("truncated");
    let key = Signer::new(7);
    let tarball = w.publish("kern 99.0.0");
    w.put_signature(&key.sign(&tarball, &statement("99.0.0")));
    std::fs::write(
        w.root.join("rel").join(asset()),
        &tarball[..tarball.len() / 2],
    )
    .expect("cut");
    assert_refused(&w, &key, "does not match the download");
}

#[test]
fn a_release_signed_by_an_untrusted_key_is_refused() {
    let w = World::new("untrusted");
    let trusted = Signer::new(7);
    let stranger = Signer::new(9);
    let tarball = w.publish("kern 99.0.0");
    w.put_signature(&stranger.sign(&tarball, &statement("99.0.0")));
    assert_refused(&w, &trusted, "does not trust");
}

#[test]
fn an_edited_trusted_comment_is_refused() {
    // The version lives in the trusted comment; the global signature is what binds it. Sign 0.50.0
    // (a downgrade), then rewrite the comment to 99.0.0 as an attacker would.
    let w = World::new("comment");
    let key = Signer::new(7);
    let tarball = w.publish("kern 99.0.0");
    let sig = key.sign(&tarball, &statement("0.50.0"));
    w.put_signature(&sig.replace("version=0.50.0", "version=99.0.0"));
    assert_refused(&w, &key, "does not match the download");
}

#[test]
fn an_older_signed_release_is_refused() {
    let w = World::new("older");
    let key = Signer::new(7);
    let tarball = w.publish("kern 0.50.0");
    w.put_signature(&key.sign(&tarball, &statement("0.50.0")));
    assert_refused(&w, &key, "never goes back");
}

#[test]
fn a_release_for_another_machine_is_refused() {
    let w = World::new("arch");
    let key = Signer::new(7);
    let tarball = w.publish("kern 99.0.0");
    let other = if TARGET.starts_with("x86_64") {
        "aarch64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-musl"
    };
    let comment = format!(
        "kern-release v1 version=99.0.0 target={other} file={}",
        asset()
    );
    w.put_signature(&key.sign(&tarball, &comment));
    assert_refused(&w, &key, "this machine needs");
}

#[test]
fn a_signature_without_a_release_statement_is_refused() {
    // What `minisign -S` writes when nobody passes `-t`: valid, signed, and says nothing about
    // which version it is.
    let w = World::new("nostatement");
    let key = Signer::new(7);
    let tarball = w.publish("kern 99.0.0");
    w.put_signature(&key.sign(
        &tarball,
        &format!("timestamp:1795000326\tfile:{}\thashed", asset()),
    ));
    assert_refused(&w, &key, "not a kern release statement");
}

#[test]
fn a_binary_that_is_not_the_signed_version_is_refused() {
    let w = World::new("mismatch");
    let key = Signer::new(7);
    let tarball = w.publish("kern 98.0.0");
    w.put_signature(&key.sign(&tarball, &statement("99.0.0")));
    assert_refused(&w, &key, "its signature says");
}

#[test]
fn a_release_with_no_signature_is_refused() {
    let w = World::new("unsigned");
    let key = Signer::new(7);
    w.publish("kern 99.0.0");
    assert_refused(&w, &key, "no signature was found");
}

/// A download that never completes is a network failure, not an unsigned release. MEASURED
/// 2026-11-18 on a WSL distro whose resolver failed: "could not resolve host" was followed by "no
/// signature was found for this release", and the release was signed.
#[test]
fn a_network_failure_is_not_called_a_missing_signature() {
    let w = World::new("offline");
    let key = Signer::new(7);
    let original = std::fs::read(w.bin()).expect("read kern");
    let out = Command::new(w.bin())
        .arg("self-update")
        .env("KERN_SELF_UPDATE_URL", "https://127.0.0.1:1/rel")
        .env("KERN_SELF_UPDATE_TEST_PUBKEY", key.public())
        .env("KERN_SELF_UPDATE_TEST_VERSION", "0.51.1")
        .output()
        .expect("run kern self-update");
    let text = said(&out);
    assert!(!out.status.success(), "accepted:\n{text}");
    assert!(
        !text.contains("no signature was found"),
        "a failed download was called a missing signature:\n{text}"
    );
    assert!(
        text.contains("check the network"),
        "no network hint:\n{text}"
    );
    assert_eq!(
        std::fs::read(w.bin()).expect("read kern"),
        original,
        "the binary changed"
    );
}

#[test]
fn the_current_release_is_nothing_to_do() {
    let w = World::new("current");
    let key = Signer::new(7);
    let original = std::fs::read(w.bin()).expect("read kern");
    let tarball = w.publish("kern 0.51.1");
    w.put_signature(&key.sign(&tarball, &statement("0.51.1")));
    let out = w.self_update(&key, &[]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("is the latest release"),
        "{}",
        said(&out)
    );
    assert_eq!(std::fs::read(w.bin()).expect("read kern"), original);
    w.assert_bin_holds_only(false);
}
