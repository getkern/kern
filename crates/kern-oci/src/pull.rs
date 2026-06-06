//! OCI image pull (registry v2) via `curl` + `tar`.
//!
//! Resolves an image reference, fetches a manifest (selecting this host's arch from a manifest
//! list / image index), downloads each layer blob, extracts it into a rootfs directory, and
//! applies OCI whiteouts — with the symlink-escape guard from [`crate::whiteout_dir_symlink_free`].
//!
//! Tooling: `curl` (TLS, auth, redirects) and GNU `tar` (gzip + traversal-safe extraction, no
//! `-P`). Anonymous Docker Hub auth is supported out of the box.
//!
//! Hardening (adversarial images): every blob is verified to hash to its `sha256:` digest
//! ([`verify_digest`]) before use. Each layer is then vetted ([`check_layer_safe`]: no
//! absolute/`..` paths, no device nodes, no escaping hardlink target, a 2 GiB decompression-bomb
//! cap), extracted into an ISOLATED staging dir, and merged into the rootfs with **no-follow**
//! semantics ([`merge_layer`]) — a symlink planted by an earlier layer can never be traversed by
//! a later layer's writes, so the cross-layer escape class is closed structurally, not by
//! trusting tar.

use crate::json::{all_str_values, array_after, first_str, split_objects};
use crate::net::curl;
use crate::whiteout_dir_symlink_free;
use std::path::Path;
use std::process::{Command, Stdio};

const DEFAULT_REGISTRY: &str = "registry-1.docker.io";

/// An OCI pull failure.
#[derive(Debug)]
pub enum OciError {
    /// The image reference could not be parsed.
    Ref(String),
    /// An external tool (`curl`/`tar`) failed.
    Tool(&'static str, String),
    /// The registry returned something unexpected.
    Registry(String),
    /// Extraction / filesystem error.
    Extract(String),
}

impl std::fmt::Display for OciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OciError::Ref(s) => write!(f, "bad image reference: {s}"),
            OciError::Tool(t, e) => write!(f, "{t} failed: {e}"),
            OciError::Registry(s) => write!(f, "registry: {s}"),
            OciError::Extract(s) => write!(f, "extract: {s}"),
        }
    }
}

impl std::error::Error for OciError {}

/// Pull `image` into `dest` (created if needed), producing a usable rootfs. Progress is reported
/// to **stderr** (so stdout stays clean) — the user always sees what's happening, never a silent
/// hang.
pub fn pull(image: &str, dest: &Path) -> Result<(), OciError> {
    eprintln!("→ resolving {image} ({})", current_arch());
    let (registry, repo, reference) = parse_ref(image)?;
    let token = auth_token(&registry, &repo)?;

    let manifest = fetch_manifest(&registry, &repo, &reference, &token)?;
    let manifest = if is_manifest_list(&manifest) {
        let digest = select_arch_digest(&manifest)
            .ok_or_else(|| OciError::Registry(format!("no manifest for {}", current_arch())))?;
        fetch_manifest(&registry, &repo, &digest, &token)?
    } else {
        manifest
    };

    let layers = layer_digests(&manifest);
    if layers.is_empty() {
        return Err(OciError::Registry("no layers in manifest".into()));
    }
    let total = layers.len();
    eprintln!(
        "→ {total} layer{} to download + extract",
        if total == 1 { "" } else { "s" }
    );
    std::fs::create_dir_all(dest).map_err(|e| OciError::Extract(e.to_string()))?;
    for (i, digest) in layers.iter().enumerate() {
        extract_layer(&registry, &repo, digest, &token, dest, i + 1, total)?;
    }
    eprintln!("✓ pulled {image} → {} ({total} layers)", dest.display());
    Ok(())
}

/// `[registry/]repo[:tag]` → `(registry, repo, reference)`. Bare names get `library/` +
/// `registry-1.docker.io`; the first path segment is a registry only if it looks like a host.
fn parse_ref(image: &str) -> Result<(String, String, String), OciError> {
    if image.is_empty() {
        return Err(OciError::Ref("empty".into()));
    }
    // A trailing `:tag` only counts if the part after `:` has no `/` (else it's a host:port).
    let (name, reference) = match image.rsplit_once(':') {
        Some((n, t)) if !t.contains('/') && !n.is_empty() => (n.to_string(), t.to_string()),
        _ => (image.to_string(), "latest".to_string()),
    };
    let (registry, repo) = match name.split_once('/') {
        Some((host, rest)) if host.contains('.') || host.contains(':') || host == "localhost" => {
            (host.to_string(), rest.to_string())
        }
        _ if name.contains('/') => (DEFAULT_REGISTRY.to_string(), name.clone()),
        _ => (DEFAULT_REGISTRY.to_string(), format!("library/{name}")),
    };
    Ok((registry, repo, reference))
}

fn current_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

/// Download a blob to `tmp` showing curl's live progress bar (`-#`, stderr inherited) so a big
/// layer never looks frozen. `-S` still surfaces errors; `-L` follows redirects.
fn curl_download(url: &str, tmp: &str, token: &str) -> Result<(), OciError> {
    let auth = format!("Authorization: Bearer {token}");
    let mut cmd = Command::new("curl");
    cmd.args([
        "-#",
        "-S",
        "-L",
        "--connect-timeout",
        "10",
        "--max-time",
        "600",
        "-o",
        tmp,
    ]);
    if !token.is_empty() {
        cmd.args(["-H", &auth]);
    }
    cmd.arg(url).stderr(Stdio::inherit()); // live progress bar to the terminal
    let status = cmd
        .status()
        .map_err(|e| OciError::Tool("curl", e.to_string()))?;
    if !status.success() {
        return Err(OciError::Tool(
            "curl",
            format!("download failed (exit {:?})", status.code()),
        ));
    }
    Ok(())
}

/// Anonymous Docker Hub pull token. (Other registries' auth flows land later.)
fn auth_token(registry: &str, repo: &str) -> Result<String, OciError> {
    if registry != DEFAULT_REGISTRY {
        // No token: many registries serve public manifests unauthenticated; if not, the
        // manifest fetch will fail clearly.
        return Ok(String::new());
    }
    let url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    );
    let body = curl(&["-sSL", "--connect-timeout", "10", "--max-time", "60", &url])?;
    let s = String::from_utf8_lossy(&body);
    first_str(&s, "token").ok_or_else(|| OciError::Registry("no auth token in response".into()))
}

fn fetch_manifest(
    registry: &str,
    repo: &str,
    reference: &str,
    token: &str,
) -> Result<String, OciError> {
    let url = format!("https://{registry}/v2/{repo}/manifests/{reference}");
    let accept = "Accept: application/vnd.oci.image.index.v1+json,\
        application/vnd.oci.image.manifest.v1+json,\
        application/vnd.docker.distribution.manifest.list.v2+json,\
        application/vnd.docker.distribution.manifest.v2+json";
    let auth = format!("Authorization: Bearer {token}");
    let mut args = vec![
        "-sSL",
        "--connect-timeout",
        "10",
        "--max-time",
        "60",
        "-H",
        accept,
    ];
    if !token.is_empty() {
        args.push("-H");
        args.push(&auth);
    }
    args.push(&url);
    let body = curl(&args)?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn extract_layer(
    registry: &str,
    repo: &str,
    digest: &str,
    token: &str,
    dest: &Path,
    idx: usize,
    total: usize,
) -> Result<(), OciError> {
    let short = digest
        .strip_prefix("sha256:")
        .map(|h| &h[..h.len().min(12)])
        .unwrap_or(digest);
    eprintln!("→ layer {idx}/{total}  {short}  downloading…");
    let url = format!("https://{registry}/v2/{repo}/blobs/{digest}");
    let tmp = dest.join(format!(
        ".kern-layer-{}.tar.gz",
        digest.replace([':', '/'], "_")
    ));
    let tmp_s = tmp.to_string_lossy().into_owned();
    curl_download(&url, &tmp_s, token)?;

    // INTEGRITY: the blob's content must hash to its digest — defends against a compromised or
    // MITM'd registry (TLS only protects the transport), and against a corrupt download.
    eprintln!("  layer {idx}/{total}  {short}  verifying + extracting…");
    if let Err(e) = verify_digest(&tmp, digest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // HARDENING: vet the layer BEFORE writing anything to disk — reject path traversal, absolute
    // members, device nodes, and oversized (decompression-bomb) layers.
    if let Err(e) = check_layer_safe(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // ISOLATED STAGING: extract this layer into a FRESH empty sibling dir, never directly into
    // `dest`. Then merge it into `dest` ourselves with no-follow semantics (see `merge_layer`),
    // so a symlink planted by a previous layer cannot be traversed by this layer's writes — the
    // cross-layer symlink-escape class is closed structurally, not by trusting tar.
    let staging = dest.with_file_name(format!(".kern-stg-{}", digest.replace([':', '/'], "_")));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| OciError::Extract(e.to_string()))?;
    let staging_s = staging.to_string_lossy().into_owned();
    let status = Command::new("tar")
        .args(["-xzf", &tmp_s, "-C", &staging_s, "--no-same-owner"])
        .status()
        .map_err(|e| OciError::Tool("tar", e.to_string()))?;
    let _ = std::fs::remove_file(&tmp);
    if !status.success() {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(OciError::Extract(format!("tar exit {:?}", status.code())));
    }
    let merged = merge_layer(&staging, dest);
    let _ = std::fs::remove_dir_all(&staging);
    merged
}

/// Verify `file` hashes to `digest` (`sha256:HEX`). Uses `sha256sum` (coreutils). An unknown
/// algorithm is skipped (not failed); a mismatch is a hard error.
fn verify_digest(file: &Path, digest: &str) -> Result<(), OciError> {
    let Some(expected) = digest.strip_prefix("sha256:") else {
        // Refuse any digest we can't verify — a non-sha256 algorithm must not be a free pass for
        // a compromised registry to serve unverified bytes.
        return Err(OciError::Registry(format!(
            "unsupported digest algorithm (only sha256 is verified): {digest}"
        )));
    };
    let out = Command::new("sha256sum")
        .arg(file)
        .output()
        .map_err(|e| OciError::Tool("sha256sum", e.to_string()))?;
    if !out.status.success() {
        return Err(OciError::Tool("sha256sum", "hashing failed".into()));
    }
    let got = String::from_utf8_lossy(&out.stdout);
    let got = got.split_whitespace().next().unwrap_or("");
    if !got.eq_ignore_ascii_case(expected) {
        return Err(OciError::Registry(format!(
            "blob digest mismatch (expected {expected}, got {got}) — refusing"
        )));
    }
    Ok(())
}

/// A tar member path that would escape the rootfs: absolute, `..`-traversing, or NUL-bearing.
fn unsafe_member_path(p: &str) -> bool {
    p.starts_with('/') || p.split('/').any(|c| c == "..") || p.contains('\0')
}

/// Max uncompressed bytes per layer — a decompression-bomb ceiling (2 GiB).
const MAX_LAYER_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Vet a downloaded layer tarball before extraction. Lists entries with `tar -tzv` and rejects:
/// absolute paths, `..` traversal, device/special nodes, and a total uncompressed size over the
/// bomb cap. (Cross-layer symlink escapes are handled structurally by isolated staging +
/// no-follow merge in [`merge_layer`].)
fn check_layer_safe(tar_path: &Path) -> Result<(), OciError> {
    let out = Command::new("tar")
        .args(["-tzvf", &tar_path.to_string_lossy()])
        .output()
        .map_err(|e| OciError::Tool("tar", e.to_string()))?;
    if !out.status.success() {
        return Err(OciError::Extract(format!(
            "could not list layer: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    let mut total: u64 = 0;
    for line in listing.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue; // not an entry line
        }
        let typ = cols[0].as_bytes().first().copied().unwrap_or(b'-');
        let size: u64 = cols[2].parse().unwrap_or(0);
        // The name (cols[5..]) may be `path -> target` (symlink or hardlink).
        let name = cols[5..].join(" ");
        let mut halves = name.split(" -> ");
        let path = halves.next().unwrap_or(&name);
        let link_target = halves.next();

        if typ == b'c' || typ == b'b' {
            return Err(OciError::Extract(format!(
                "layer has a device node: {path}"
            )));
        }
        if unsafe_member_path(path) {
            return Err(OciError::Extract(format!("unsafe path in layer: {path}")));
        }
        // A HARDLINK's target is a real path into the rootfs — it must stay inside it (an
        // absolute or `..` target could hardlink a host inode into the image). Symlink targets
        // are fine: the no-follow merge never traverses them.
        if typ == b'h' {
            if let Some(t) = link_target {
                if unsafe_member_path(t) {
                    return Err(OciError::Extract(format!(
                        "layer hardlink escapes the rootfs: {path} -> {t}"
                    )));
                }
            }
        }
        total = total.saturating_add(size);
        if total > MAX_LAYER_BYTES {
            return Err(OciError::Extract(
                "layer exceeds the size cap (possible decompression bomb)".into(),
            ));
        }
    }
    Ok(())
}

/// Merge an isolated layer staging tree into `dest` with **no-follow** semantics. Before writing
/// any entry, the destination parent must be symlink-free (else a previous layer planted a
/// symlink to escape through — refuse). `.wh.<name>` deletes `<name>`; `.wh..wh..opq` drops the
/// directory's lower-layer contents. Targets are removed without following symlinks, so the
/// merge can never write through one.
fn merge_layer(staging: &Path, dest: &Path) -> Result<(), OciError> {
    let dest_s = dest
        .to_str()
        .ok_or_else(|| OciError::Extract("non-utf8 rootfs path".into()))?;
    merge_dir(staging, staging, dest, dest_s)
}

fn merge_dir(base: &Path, dir: &Path, dest: &Path, dest_s: &str) -> Result<(), OciError> {
    // Opaque marker: clear the dir's lower-layer contents BEFORE merging this layer's entries.
    let dir_rel = dir.strip_prefix(base).unwrap_or(Path::new(""));
    if dir.join(".wh..wh..opq").exists()
        && whiteout_dir_symlink_free(dest_s, &dir_rel.to_string_lossy())
    {
        clear_dir(&dest.join(dir_rel));
    }

    for entry in std::fs::read_dir(dir).map_err(|e| OciError::Extract(e.to_string()))? {
        let entry = entry.map_err(|e| OciError::Extract(e.to_string()))?;
        let src = entry.path();
        let rel = src.strip_prefix(base).unwrap_or(&src);
        let parent_rel = rel
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        // No-follow guard: never write through a symlink a previous layer planted in `dest`.
        if !whiteout_dir_symlink_free(dest_s, &parent_rel) {
            return Err(OciError::Extract(format!(
                "layer writes through a symlink: {}",
                rel.display()
            )));
        }
        let fname = entry.file_name();
        let fname = fname.to_string_lossy();
        let target = dest.join(rel);

        if let Some(victim_name) = fname.strip_prefix(".wh.") {
            if fname.as_ref() != ".wh..wh..opq" {
                remove_no_follow(&target.with_file_name(victim_name));
            }
            continue; // never materialise a whiteout marker
        }

        let ft = entry
            .file_type()
            .map_err(|e| OciError::Extract(e.to_string()))?;
        if ft.is_dir() {
            match std::fs::symlink_metadata(&target) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => {
                    remove_no_follow(&target);
                    std::fs::create_dir(&target).map_err(|e| OciError::Extract(e.to_string()))?;
                }
                Err(_) => {
                    std::fs::create_dir(&target).map_err(|e| OciError::Extract(e.to_string()))?;
                }
            }
            merge_dir(base, &src, dest, dest_s)?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(&src).map_err(|e| OciError::Extract(e.to_string()))?;
            remove_no_follow(&target);
            std::os::unix::fs::symlink(&link, &target)
                .map_err(|e| OciError::Extract(e.to_string()))?;
        } else {
            // Regular file (device/special nodes were rejected by check_layer_safe).
            remove_no_follow(&target);
            if std::fs::rename(&src, &target).is_err() {
                std::fs::copy(&src, &target).map_err(|e| OciError::Extract(e.to_string()))?;
            }
        }
    }
    Ok(())
}

/// Remove a path without following symlinks (a symlink is unlinked, never traversed).
fn remove_no_follow(p: &Path) {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => {
            let _ = std::fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(p);
        }
        Err(_) => {}
    }
}

/// Remove every direct child of `d` (no-follow). Used for opaque-dir whiteouts.
fn clear_dir(d: &Path) {
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            remove_no_follow(&e.path());
        }
    }
}

fn is_manifest_list(m: &str) -> bool {
    m.contains("\"manifests\"") || m.contains("manifest.list") || m.contains("image.index")
}

/// Pick the layer-bearing manifest digest for this host's arch from a manifest list / index.
fn select_arch_digest(m: &str) -> Option<String> {
    let arch = current_arch();
    let manifests = array_after(m, "manifests")?;
    let mut fallback = None;
    for obj in split_objects(manifests) {
        // Match on a whitespace-stripped copy so a pretty-printed index (`"architecture": "amd64"`)
        // works as well as Docker Hub's compact form. Digest extraction uses the original `obj`.
        let compact: String = obj.split_whitespace().collect();
        if compact.contains("\"unknown\"") {
            continue; // attestation / provenance entries
        }
        let is_arch = compact.contains(&format!("\"architecture\":\"{arch}\""));
        if is_arch && compact.contains("\"os\":\"linux\"") {
            return first_str(obj, "digest");
        }
        if is_arch && fallback.is_none() {
            fallback = first_str(obj, "digest");
        }
    }
    fallback
}

fn layer_digests(m: &str) -> Vec<String> {
    match array_after(m, "layers") {
        Some(layers) => all_str_values(layers, "digest"),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ref_defaults_and_registries() {
        assert_eq!(
            parse_ref("alpine").unwrap(),
            (
                DEFAULT_REGISTRY.into(),
                "library/alpine".into(),
                "latest".into()
            )
        );
        assert_eq!(
            parse_ref("alpine:3.19").unwrap(),
            (
                DEFAULT_REGISTRY.into(),
                "library/alpine".into(),
                "3.19".into()
            )
        );
        assert_eq!(
            parse_ref("user/repo:tag").unwrap(),
            (DEFAULT_REGISTRY.into(), "user/repo".into(), "tag".into())
        );
        assert_eq!(
            parse_ref("ghcr.io/org/app:v1").unwrap(),
            ("ghcr.io".into(), "org/app".into(), "v1".into())
        );
    }

    #[test]
    fn selects_arch_from_manifest_list() {
        let list = r#"{"manifests":[
            {"digest":"sha256:aaa","platform":{"architecture":"amd64","os":"linux"}},
            {"digest":"sha256:bbb","platform":{"architecture":"arm64","os":"linux"}},
            {"digest":"sha256:ccc","platform":{"architecture":"unknown","os":"unknown"}}
        ]}"#;
        let want = if current_arch() == "arm64" {
            "sha256:bbb"
        } else {
            "sha256:aaa"
        };
        assert_eq!(select_arch_digest(list).as_deref(), Some(want));
    }

    #[test]
    fn extracts_all_layer_digests_only() {
        let manifest = r#"{"config":{"digest":"sha256:config"},
            "layers":[{"digest":"sha256:l1"},{"digest":"sha256:l2"}]}"#;
        assert_eq!(layer_digests(manifest), vec!["sha256:l1", "sha256:l2"]);
    }

    fn have_tar() -> bool {
        Command::new("tar").arg("--version").output().is_ok()
    }

    /// A layer whose member path is absolute (traversal class) must be rejected before extraction.
    #[test]
    fn rejects_absolute_path_layer() {
        if !have_tar() {
            eprintln!("skip: no tar");
            return;
        }
        let dir = std::env::temp_dir().join(format!("kern-oci-evil-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let victim = dir.join("victimfile");
        std::fs::write(&victim, b"x").unwrap();
        let evil = dir.join("evil.tar.gz");
        // `-P` keeps the leading '/', so the stored member name is absolute.
        let ok = Command::new("tar")
            .args(["-czPf", evil.to_str().unwrap(), victim.to_str().unwrap()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            assert!(
                check_layer_safe(&evil).is_err(),
                "an absolute-path layer must be rejected"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SECURITY: merging a layer must never write THROUGH a symlink an earlier layer planted in
    /// the rootfs — the target outside the rootfs must stay untouched.
    #[test]
    fn merge_never_writes_through_a_planted_symlink() {
        let base = std::env::temp_dir().join(format!("kern-oci-merge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let victim = base.join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        let dest = base.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        // An "earlier layer" planted `dest/link -> victim` (an escape symlink).
        std::os::unix::fs::symlink(&victim, dest.join("link")).unwrap();
        // The new layer (staging) tries to drop a file under `link/`.
        let staging = base.join("stg");
        std::fs::create_dir_all(staging.join("link")).unwrap();
        std::fs::write(staging.join("link/evil"), b"pwned").unwrap();

        let _ = merge_layer(&staging, &dest); // may replace or refuse — either way must be safe

        assert!(
            !victim.join("evil").exists(),
            "must NOT write through the symlink into its target"
        );
        // The escape symlink was replaced by a real directory (no longer points at the victim).
        let md = std::fs::symlink_metadata(dest.join("link")).unwrap();
        assert!(
            !md.file_type().is_symlink(),
            "the planted symlink must be gone"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A normal, well-formed layer passes the check.
    #[test]
    fn accepts_a_normal_layer() {
        if !have_tar() {
            eprintln!("skip: no tar");
            return;
        }
        let dir = std::env::temp_dir().join(format!("kern-oci-ok-{}", std::process::id()));
        let payload = dir.join("payload/sub");
        std::fs::create_dir_all(&payload).unwrap();
        std::fs::write(payload.join("file"), b"hello").unwrap();
        let good = dir.join("good.tar.gz");
        let ok = Command::new("tar")
            .args([
                "-czf",
                good.to_str().unwrap(),
                "-C",
                dir.join("payload").to_str().unwrap(),
                ".",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            assert!(
                check_layer_safe(&good).is_ok(),
                "a normal layer should pass"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
