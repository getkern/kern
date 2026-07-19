//! OCI image push (registry v2) - the dual of [`crate::pull`]. Takes a local rootfs directory + its
//! image config and publishes it to a registry as a single-layer OCI image.
//!
//! The flow (standard registry-v2 blob upload + manifest PUT):
//!  1. `tar` the rootfs → gzip → the layer blob; sha256 of the compressed blob = its digest, sha256 of
//!     the uncompressed tar = the `diff_id` for the config's `rootfs.diff_ids`.
//!  2. Build the OCI image config JSON (entrypoint/cmd/env/… from the local `.image` sidecar) → its
//!     sha256 is the config digest.
//!  3. For each blob: `POST /v2/<repo>/blobs/uploads/` → follow the `Location` → `PUT ?digest=…` the
//!     bytes. Skip the upload if the registry already has the blob (`HEAD /blobs/<digest>` = 200).
//!  4. `PUT /v2/<repo>/manifests/<tag>` with the manifest JSON.
//!
//! Auth is the same challenge dance as pull but with a WRITE scope
//! (`repository:<repo>:push,pull`) - see [`crate::pull::discover_auth_scoped`]. Credentials travel
//! off-argv (via curl `-K` STDIN) exactly as on the pull path; a push to a private repo needs `kern
//! login` first. All requests are HTTPS-pinned (`TLS_PIN`).

use crate::pull::{
    curl_authed, discover_auth_scoped, is_loopback_registry, parse_ref, reg_base, Auth, TLS_PIN,
};
use crate::OciError;
use std::path::Path;
use std::process::Command;

/// The gzip'd-tar media type for an OCI/Docker layer, and the config media type. We publish a v2
/// schema-2 (Docker) manifest - the format every registry accepts and `docker pull` understands.
const LAYER_MT: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
const CONFIG_MT: &str = "application/vnd.docker.container.image.v1+json";
const MANIFEST_MT: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// Publish the rootfs at `rootfs` (with runtime `config`) to `image` (`[registry/]repo[:tag]`).
/// `work` is a scratch dir for the layer blob (caller creates + cleans it).
pub fn push(
    image: &str,
    rootfs: &Path,
    config: &ImageConfigOut,
    work: &Path,
) -> Result<(), OciError> {
    let (registry, repo, reference) = parse_ref(image)?;
    // Loopback registries (localhost / 127.* / ::1) speak plain HTTP and are the common local-dev /
    // `registry:2` case - Docker treats loopback as insecure-OK by default, and so do we: over the
    // loopback interface there's no MITM to pin against. Everything else stays HTTPS-pinned.
    let ep = Endpoint::for_registry(&registry);
    // WRITE-scoped auth. A push to a private repo needs `kern login`; anonymous push is refused by the
    // registry with a clear 401/403 that we surface. (Loopback dev registries are usually open.)
    let auth = discover_auth_scoped(&registry, &repo, "push,pull")?;

    eprintln!("→ packing rootfs into a layer…");
    let (layer_path, layer_digest, diff_id, layer_size) = pack_layer(rootfs, work)?;

    // Build the config JSON and its digest.
    let config_json = build_config_json(config, &diff_id);
    let config_path = work.join("config.json");
    std::fs::write(&config_path, &config_json)
        .map_err(|e| OciError::Extract(format!("write config: {e}")))?;
    let config_digest = sha256_file(&config_path)?;
    let config_size = config_json.len() as u64;

    // Upload the two blobs (layer, config) - skip any the registry already has.
    eprintln!(
        "→ uploading layer ({})…",
        kern_common::fmt_bytes(layer_size)
    );
    upload_blob(&ep, &repo, &layer_digest, &layer_path, &auth)?;
    eprintln!("→ uploading config…");
    upload_blob(&ep, &repo, &config_digest, &config_path, &auth)?;

    // Build + PUT the manifest.
    let manifest = build_manifest(&config_digest, config_size, &layer_digest, layer_size);
    eprintln!("→ pushing manifest {reference}…");
    put_manifest(&ep, &repo, &reference, &manifest, &auth)?;

    eprintln!("✓ pushed {image}");
    Ok(())
}

/// A registry endpoint: its base URL scheme and whether to HTTPS-pin. Loopback → `http://` + no pin
/// (local-dev registries; safe over loopback). Everything else → `https://` + `TLS_PIN`.
struct Endpoint {
    base: String, // e.g. "https://ghcr.io" or "http://localhost:5000"
    pin: bool,
}

impl Endpoint {
    fn for_registry(registry: &str) -> Self {
        // Shared loopback rule with the pull path (`is_loopback_registry`/`reg_base`) - one source of
        // truth so push and pull can't disagree on which registries are insecure-OK.
        Endpoint {
            base: reg_base(registry),
            pin: !is_loopback_registry(registry),
        }
    }
    /// The TLS-pin curl args for this endpoint (empty when talking plain HTTP to loopback).
    fn pin_args(&self) -> &'static [&'static str] {
        if self.pin {
            TLS_PIN
        } else {
            &[]
        }
    }

    /// This endpoint's authority as curl would dial it - host **and port** (no scheme/userinfo),
    /// lowercased. We compare host+port (not host alone) so a compromised registry can't bounce the
    /// upload to a DIFFERENT PORT on the same host (a distinct service, e.g. an internal admin port).
    fn authority(&self) -> String {
        authority_no_userinfo(authority_of(&self.base))
    }

    /// Vet a registry-supplied upload `Location` before we PUT the blob (with credentials) to it.
    ///
    /// SECURITY (CVE-2020-15157 class): the registry is untrusted and may answer the upload POST with
    /// an ABSOLUTE `Location: https://evil.com/…`. `curl_authed` unconditionally attaches the bearer
    /// token (or the long-lived `kern login` basic creds) - so following a cross-host Location would
    /// exfiltrate the credentials AND the private layer bytes to an attacker-chosen host. We therefore
    /// require an absolute Location to have the SAME host as the registry (a cross-host CDN upload is
    /// not worth leaking creds for); a relative Location is resolved against our own base and is always
    /// same-host. On a plain-HTTP loopback endpoint we additionally reject an absolute `http://` host
    /// that isn't the loopback base itself (blocks a `http://169.254.169.254/…` SSRF from a local reg).
    fn resolve_upload_location(&self, location: &str) -> Result<String, OciError> {
        if !location.starts_with("http://") && !location.starts_with("https://") {
            // Relative → same host by construction.
            return Ok(format!("{}{location}", self.base));
        }
        let loc_auth = authority_no_userinfo(authority_of(location));
        if loc_auth != self.authority() || loc_auth.is_empty() {
            return Err(OciError::Registry(format!(
                "registry redirected the blob upload to a different host ('{loc_auth}' != '{}') - \
                 refusing to send credentials off-registry",
                self.authority()
            )));
        }
        // Same host, but a pinned (HTTPS) endpoint must not be downgraded to http:// by the Location.
        if self.pin && location.starts_with("http://") {
            return Err(OciError::Registry(
                "registry redirected an HTTPS upload to plain http:// - refusing".into(),
            ));
        }
        Ok(location.to_string())
    }
}

/// A URL authority with any `userinfo@` dropped and lowercased, KEEPING the `:port` (curl dials the
/// host after the LAST `@`, so `trusted@evil.com` connects to `evil.com`). Used to compare a
/// registry-supplied Location against our endpoint by host+port.
fn authority_no_userinfo(authority: &str) -> String {
    authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .to_ascii_lowercase()
}

/// The bare authority of a URL: drop a leading `scheme://`, then keep only the part before the first
/// `/`, `?` or `#` (so the caller sees `host[:port]`, not the path). Feeding the path in would make
/// `https://ghcr.io/upload` look like the host `ghcr.io/upload` and never match.
fn authority_of(url: &str) -> &str {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
}

/// The subset of image config we serialize into the pushed config JSON. Mirror of the fields kern
/// stores in an image's `.image` sidecar.
#[derive(Default)]
pub struct ImageConfigOut {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub workdir: Option<String>,
    pub user: Option<String>,
}

/// `tar` the rootfs and gzip it into `work/layer.tar.gz`. Returns `(path, "sha256:<compressed>",
/// "sha256:<uncompressed diff_id>", compressed_size)`. Uses the system `tar`/`gzip` (like the pull
/// path) - no in-process tar dependency.
fn pack_layer(
    rootfs: &Path,
    work: &Path,
) -> Result<(std::path::PathBuf, String, String, u64), OciError> {
    let tar_path = work.join("layer.tar");
    // SECURITY (privilege-escalation via ownership normalization): the layer is tarred root-owned
    // (Docker layers are root-owned), but forcing owner 0 on a NON-root-owned `-rwsr-xr-x` binary would
    // turn it into **setuid-ROOT** in the pushed image - an escalation the original never had. So the
    // shared packer strips setuid/setgid BEFORE tarring (kern treats in-image setuid as inert anyway -
    // the box root mount is MS_NOSUID and pull uses `--no-same-owner`; file-capabilities are closed the
    // same way, the build copier never propagates `security.capability`). It also handles the tar-flavour
    // split: GNU `--owner=0 --group=0`, or BusyBox `--numeric-owner` (which is already 0:0 for a
    // root-run build) - the fix for `save`/`push` erroring on Alpine/WSL's BusyBox tar.
    crate::archive::tar_rootfs_root_owned(rootfs, &tar_path)?;
    let diff_id = sha256_file(&tar_path)?; // uncompressed digest = diff_id

    // gzip the tar → layer.tar.gz.
    let gz_path = work.join("layer.tar.gz");
    let ok = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "gzip -n -c -- {} > {}",
            shell_quote(&tar_path.to_string_lossy()),
            shell_quote(&gz_path.to_string_lossy())
        ))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return Err(OciError::Extract("gzip of layer failed".into()));
    }
    let _ = std::fs::remove_file(&tar_path); // the compressed blob is what we upload
    let digest = sha256_file(&gz_path)?;
    let size = std::fs::metadata(&gz_path).map(|m| m.len()).unwrap_or(0);
    Ok((gz_path, digest, diff_id, size))
}

/// `sha256:<hex>` of a file, via `sha256sum` (coreutils). Errs if the tool is missing or fails.
pub(crate) fn sha256_file(path: &Path) -> Result<String, OciError> {
    let out = Command::new("sha256sum")
        .arg("--")
        .arg(path)
        .output()
        .map_err(|e| OciError::Extract(format!("sha256sum: {e}")))?;
    if !out.status.success() {
        return Err(OciError::Extract("sha256sum failed".into()));
    }
    let hex = String::from_utf8_lossy(&out.stdout);
    let hex = hex.split_whitespace().next().unwrap_or("");
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OciError::Extract(
            "sha256sum gave an unexpected digest".into(),
        ));
    }
    Ok(format!("sha256:{hex}"))
}

/// Build the OCI/Docker image config JSON. Minimal but valid: `rootfs.diff_ids` (the one layer's
/// uncompressed digest) plus a `config` with the runtime fields. JSON is emitted by hand (no serde) -
/// the fields are simple string arrays, matching the dependency-free posture of the rest of kern-oci.
pub(crate) fn build_config_json(cfg: &ImageConfigOut, diff_id: &str) -> String {
    let arr = |xs: &[String]| {
        let items: Vec<String> = xs.iter().map(|s| json_str(s)).collect();
        format!("[{}]", items.join(","))
    };
    let mut config_fields = Vec::new();
    if !cfg.env.is_empty() {
        config_fields.push(format!("\"Env\":{}", arr(&cfg.env)));
    }
    if !cfg.entrypoint.is_empty() {
        config_fields.push(format!("\"Entrypoint\":{}", arr(&cfg.entrypoint)));
    }
    if !cfg.cmd.is_empty() {
        config_fields.push(format!("\"Cmd\":{}", arr(&cfg.cmd)));
    }
    if let Some(w) = &cfg.workdir {
        config_fields.push(format!("\"WorkingDir\":{}", json_str(w)));
    }
    if let Some(u) = &cfg.user {
        config_fields.push(format!("\"User\":{}", json_str(u)));
    }
    format!(
        "{{\"architecture\":{},\"os\":\"linux\",\"config\":{{{}}},\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[{}]}}}}",
        json_str(crate::Platform::host().as_oci_arch()),
        config_fields.join(","),
        json_str(diff_id)
    )
}

/// Build the schema-2 manifest referencing the config + the single layer.
fn build_manifest(
    config_digest: &str,
    config_size: u64,
    layer_digest: &str,
    layer_size: u64,
) -> String {
    format!(
        "{{\"schemaVersion\":2,\"mediaType\":{mm},\
         \"config\":{{\"mediaType\":{cm},\"size\":{cs},\"digest\":{cd}}},\
         \"layers\":[{{\"mediaType\":{lm},\"size\":{ls},\"digest\":{ld}}}]}}",
        mm = json_str(MANIFEST_MT),
        cm = json_str(CONFIG_MT),
        cs = config_size,
        cd = json_str(config_digest),
        lm = json_str(LAYER_MT),
        ls = layer_size,
        ld = json_str(layer_digest),
    )
}

/// Upload one blob unless the registry already has it. Registry-v2 monolithic upload:
///   HEAD /blobs/<digest> - 200 → skip.
///   POST /blobs/uploads/ - 202 with a `Location` upload URL.
///   PUT  <location>?digest=<digest> - the bytes.
fn upload_blob(
    ep: &Endpoint,
    repo: &str,
    digest: &str,
    file: &Path,
    auth: &Auth,
) -> Result<(), OciError> {
    // Already present?
    let head_url = format!("{}/v2/{repo}/blobs/{digest}", ep.base);
    let mut head = vec!["-sS", "-o", "/dev/null", "-w", "%{http_code}", "-I"];
    head.extend_from_slice(ep.pin_args());
    head.extend_from_slice(&["--connect-timeout", "10", "--max-time", "60"]);
    if let Ok(code) = curl_authed(&head, &head_url, auth) {
        if String::from_utf8_lossy(&code).trim() == "200" {
            eprintln!("  blob {} already present - skipped", short(digest));
            return Ok(());
        }
    }

    // Start an upload session → capture the Location.
    let start_url = format!("{}/v2/{repo}/blobs/uploads/", ep.base);
    let mut start = vec!["-sS", "-o", "/dev/null", "-D", "-", "-X", "POST"];
    start.extend_from_slice(ep.pin_args());
    start.extend_from_slice(&["--connect-timeout", "10", "--max-time", "120"]);
    let headers = curl_authed(&start, &start_url, auth)?;
    let location = location_header(&String::from_utf8_lossy(&headers)).ok_or_else(|| {
        OciError::Registry(format!(
            "registry did not return an upload location for {repo} (push denied? try `kern login`)"
        ))
    })?;
    // The Location may be relative to the registry host, or an absolute URL. Vet it before we PUT the
    // blob WITH CREDENTIALS: an absolute cross-host Location would leak the token/password (and the
    // layer) to an attacker-chosen host (CVE-2020-15157 class). See `resolve_upload_location`.
    let location = ep.resolve_upload_location(&location)?;
    let sep = if location.contains('?') { '&' } else { '?' };
    let put_url = format!("{location}{sep}digest={digest}");

    // PUT the bytes with the digest - the monolithic completion.
    let mut put = vec![
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-X",
        "PUT",
        "-H",
        "Content-Type: application/octet-stream",
        "--data-binary",
    ];
    let at = format!("@{}", file.to_string_lossy());
    put.push(&at);
    put.extend_from_slice(ep.pin_args());
    put.extend_from_slice(&["--connect-timeout", "10", "--max-time", "600"]);
    let code = curl_authed(&put, &put_url, auth)?;
    let code = String::from_utf8_lossy(&code);
    let code = code.trim();
    if code != "201" && code != "202" {
        return Err(OciError::Registry(format!(
            "blob upload for {} failed (HTTP {code})",
            short(digest)
        )));
    }
    Ok(())
}

/// PUT the manifest under `reference` (a tag). 201 = created.
fn put_manifest(
    ep: &Endpoint,
    repo: &str,
    reference: &str,
    manifest: &str,
    auth: &Auth,
) -> Result<(), OciError> {
    let url = format!("{}/v2/{repo}/manifests/{reference}", ep.base);
    let ct = format!("Content-Type: {MANIFEST_MT}");
    let mut put = vec![
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-X",
        "PUT",
        "-H",
        &ct,
        "--data-binary",
        manifest,
    ];
    put.extend_from_slice(ep.pin_args());
    put.extend_from_slice(&["--connect-timeout", "10", "--max-time", "120"]);
    let code = curl_authed(&put, &url, auth)?;
    let code = String::from_utf8_lossy(&code);
    let code = code.trim();
    if code != "201" && code != "202" {
        return Err(OciError::Registry(format!(
            "manifest push failed (HTTP {code}) - is the repo writable, and are you logged in?"
        )));
    }
    Ok(())
}

/// First `Location:` header value (case-insensitive) from a raw header block.
fn location_header(headers: &str) -> Option<String> {
    headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("location:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Minimal JSON string encoder (escapes `"`, `\`, control chars) - the values here are image refs,
/// env vars, and paths; no need for a serde dependency.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Shell-quote a path for the one `sh -c` we use (gzip redirection). Single-quote and escape any
/// embedded single quote - a cache path never contains one in practice, but be correct anyway.
pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The short 12-hex form of a `sha256:<hex>` digest, for messages.
fn short(digest: &str) -> String {
    digest
        .strip_prefix("sha256:")
        .map(|h| h[..h.len().min(12)].to_string())
        .unwrap_or_else(|| digest.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_str_escapes() {
        assert_eq!(json_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_str("x\ny"), "\"x\\ny\"");
    }

    #[test]
    fn manifest_shape_is_valid_schema2() {
        let m = build_manifest("sha256:cc", 12, "sha256:ll", 34);
        assert!(m.contains("\"schemaVersion\":2"));
        assert!(m.contains("\"digest\":\"sha256:cc\""));
        assert!(m.contains("\"digest\":\"sha256:ll\""));
        assert!(m.contains("\"size\":12"));
        assert!(m.contains("\"size\":34"));
    }

    #[test]
    fn config_json_has_diff_id_and_fields() {
        let cfg = ImageConfigOut {
            entrypoint: vec!["/bin/app".into()],
            cmd: vec!["--serve".into()],
            env: vec!["K=v".into()],
            workdir: Some("/srv".into()),
            user: None,
        };
        let j = build_config_json(&cfg, "sha256:dd");
        assert!(j.contains("\"diff_ids\":[\"sha256:dd\"]"));
        assert!(j.contains("\"Entrypoint\":[\"/bin/app\"]"));
        assert!(j.contains("\"WorkingDir\":\"/srv\""));
        assert!(!j.contains("\"User\"")); // None → omitted
    }

    #[test]
    fn location_header_case_insensitive() {
        let h = "HTTP/1.1 202\r\nLocation: /v2/x/blobs/uploads/abc\r\n\r\n";
        assert_eq!(
            location_header(h).as_deref(),
            Some("/v2/x/blobs/uploads/abc")
        );
        assert_eq!(location_header("no header here"), None);
    }

    #[test]
    fn short_digest() {
        assert_eq!(short("sha256:0123456789abcdef00"), "0123456789ab");
    }

    #[test]
    fn upload_location_rejects_cross_host_redirect() {
        // CVE-2020-15157 class: a compromised registry returns an absolute Location on another host.
        // Following it would send the bearer token / basic creds + the layer to the attacker.
        let ep = Endpoint {
            base: "https://ghcr.io".into(),
            pin: true,
        };
        // Same host (relative) → resolved against our base.
        assert_eq!(
            ep.resolve_upload_location("/v2/x/blobs/uploads/abc")
                .unwrap(),
            "https://ghcr.io/v2/x/blobs/uploads/abc"
        );
        // Same host (absolute) → allowed verbatim.
        assert_eq!(
            ep.resolve_upload_location("https://ghcr.io/upload/abc")
                .unwrap(),
            "https://ghcr.io/upload/abc"
        );
        // Cross host → refused.
        assert!(ep
            .resolve_upload_location("https://evil.com/collect")
            .is_err());
        // Userinfo trick: curl dials the host after the LAST '@' → evil.com → refused.
        assert!(ep
            .resolve_upload_location("https://ghcr.io@evil.com/collect")
            .is_err());
        // HTTPS→http downgrade on the same host → refused (don't drop TLS mid-upload).
        assert!(ep.resolve_upload_location("http://ghcr.io/upload").is_err());
        // Uppercase host → allowed (DNS is case-insensitive; curl dials the same host).
        assert!(ep.resolve_upload_location("https://GHCR.IO/up").is_ok());
    }

    #[test]
    fn upload_location_is_port_aware() {
        // A compromised registry must not be able to bounce the upload to a DIFFERENT PORT on the same
        // host - that's a distinct service (e.g. an internal admin API) and the creds would still leak.
        let ep = Endpoint {
            base: "https://reg.example.com:5000".into(),
            pin: true,
        };
        // Same host:port → ok.
        assert!(ep
            .resolve_upload_location("https://reg.example.com:5000/up")
            .is_ok());
        // Same host, DIFFERENT port → refused.
        assert!(ep
            .resolve_upload_location("https://reg.example.com:9999/up")
            .is_err());
        // Same host, no port on the Location while the base has one → refused (5000 != <none>).
        assert!(ep
            .resolve_upload_location("https://reg.example.com/up")
            .is_err());
    }

    #[test]
    fn upload_location_loopback_blocks_ssrf() {
        // A plain-HTTP loopback dev registry must not be able to bounce the upload to an internal
        // metadata endpoint via an absolute http:// Location.
        let ep = Endpoint {
            base: "http://localhost:5000".into(),
            pin: false,
        };
        assert_eq!(
            ep.resolve_upload_location("/v2/x/uploads/abc").unwrap(),
            "http://localhost:5000/v2/x/uploads/abc"
        );
        // 169.254.169.254 (cloud metadata) is a different host → refused.
        assert!(ep
            .resolve_upload_location("http://169.254.169.254/latest/meta-data/")
            .is_err());
    }
}
