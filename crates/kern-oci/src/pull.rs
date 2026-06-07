//! OCI image pull (registry v2) via `curl` + `tar`.
//!
//! Resolves an image reference, fetches a manifest (selecting this host's arch from a manifest
//! list / image index), downloads each layer blob, extracts it into a rootfs directory, and
//! applies OCI whiteouts — with the symlink-escape guard from [`crate::whiteout_dir_symlink_free`].
//!
//! Tooling: `curl` (TLS, auth, redirects) and GNU `tar` (gzip + traversal-safe extraction, no
//! `-P`). Authentication follows the standard registry-v2 `WWW-Authenticate` challenge, so any
//! compliant registry works (Docker Hub, GHCR, GitLab, quay, Harbor, self-hosted) — anonymously, or
//! with `kern login` credentials (sent off-argv). All requests are https-pinned.
//!
//! Hardening (adversarial images): every blob is verified to hash to its `sha256:` digest
//! ([`verify_digest`]) before use. Each layer is then vetted ([`check_layer_safe`]: no
//! absolute/`..` paths, no device nodes, no escaping hardlink target, a 2 GiB decompression-bomb
//! cap), extracted into an ISOLATED staging dir, and merged into the rootfs with **no-follow**
//! semantics ([`merge_layer`]) — a symlink planted by an earlier layer can never be traversed by
//! a later layer's writes, so the cross-layer escape class is closed structurally, not by
//! trusting tar.

use crate::json::{
    all_str_values, array_after, first_str, object_after, split_objects, str_array_after,
};
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

/// An image's runtime configuration, read from its OCI config blob — the defaults `kern box --image`
/// applies (explicit CLI flags win) so an official image runs like `docker run`, not a bare shell.
#[derive(Debug, Default, Clone)]
pub struct ImageConfig {
    /// `config.Entrypoint` — prepended to the command.
    pub entrypoint: Vec<String>,
    /// `config.Cmd` — the default command (used when the user gives none).
    pub cmd: Vec<String>,
    /// `config.Env` — `KEY=VALUE` strings, applied UNDER the user's `--env` (user wins).
    pub env: Vec<String>,
    /// `config.WorkingDir` — default working directory.
    pub workdir: Option<String>,
    /// `config.User` — default `uid[:gid]` / name.
    pub user: Option<String>,
}

/// Pull `image` into `dest` (created if needed), producing a usable rootfs, and return its OCI
/// runtime config (entrypoint/cmd/env/workdir/user). Progress is reported to **stderr** (so stdout
/// stays clean) — the user always sees what's happening, never a silent hang.
pub fn pull(image: &str, dest: &Path) -> Result<ImageConfig, OciError> {
    eprintln!("→ resolving {image} ({})", current_arch());
    let (registry, repo, reference) = parse_ref(image)?;
    let auth = discover_auth(&registry, &repo)?;

    let manifest = fetch_manifest(&registry, &repo, &reference, &auth)?;
    let manifest = if is_manifest_list(&manifest) {
        let digest = select_arch_digest(&manifest)
            .ok_or_else(|| OciError::Registry(format!("no manifest for {}", current_arch())))?;
        fetch_manifest(&registry, &repo, &digest, &auth)?
    } else {
        manifest
    };

    // The image's runtime config (entrypoint/env/…) lives in a small blob the manifest points at.
    // Best-effort: a missing/odd config just yields defaults, never fails the pull.
    let config = fetch_config(&registry, &repo, &manifest, &auth, dest);

    let layers = layer_digests(&manifest);
    if layers.is_empty() {
        return Err(manifest_error(&manifest, &registry, &repo));
    }
    let total = layers.len();
    eprintln!(
        "→ {total} layer{} to download + extract",
        if total == 1 { "" } else { "s" }
    );
    std::fs::create_dir_all(dest).map_err(|e| OciError::Extract(e.to_string()))?;
    for (i, digest) in layers.iter().enumerate() {
        extract_layer(&registry, &repo, digest, &auth, dest, i + 1, total)?;
    }
    eprintln!("✓ pulled {image} → {} ({total} layers)", dest.display());
    Ok(config)
}

/// Fetch and parse the image's OCI config blob (the descriptor is in `manifest.config`). Best-effort:
/// any failure (missing descriptor, network, digest mismatch) returns the default config rather than
/// failing the pull — the box just falls back to a shell / the user's flags. The blob is
/// sha256-verified against its digest before use, like every other blob.
fn fetch_config(
    registry: &str,
    repo: &str,
    manifest: &str,
    auth: &Auth,
    dest: &Path,
) -> ImageConfig {
    let Some(digest) = object_after(manifest, "config").and_then(|d| first_str(d, "digest")) else {
        return ImageConfig::default();
    };
    let tmp = dest.join(".kern-image-config.json");
    let tmp_s = tmp.to_string_lossy().into_owned();
    let url = format!("https://{registry}/v2/{repo}/blobs/{digest}");
    // Independent size guard checked AFTER the download, BEFORE we read the blob into memory: curl's
    // `--max-filesize` only aborts a transfer whose length is known in advance, so a hostile registry
    // could stream a huge Content-Length-less body. A real config blob is a few KB; refuse over 4 MB.
    const MAX_CONFIG_BYTES: u64 = 4_000_000;
    let within_cap = || {
        std::fs::metadata(&tmp)
            .map(|m| m.len() <= MAX_CONFIG_BYTES)
            .unwrap_or(false)
    };
    let parsed = if download_blob_quiet(&url, &tmp_s, auth).is_ok()
        && within_cap()
        && verify_digest(&tmp, &digest).is_ok()
    {
        parse_image_config(&std::fs::read_to_string(&tmp).unwrap_or_default())
    } else {
        ImageConfig::default()
    };
    let _ = std::fs::remove_file(&tmp);
    parsed
}

/// Run `curl <base> [Authorization: Bearer …] -- <url>`, routing Basic credentials off-argv (`-K`
/// STDIN config) exactly like every other request — the ONE place the "Basic creds never in argv"
/// decision is made for GET-style fetches (manifest + config blob). Returns curl's stdout (empty
/// when `base` already redirects the body to a file with `-o`).
fn curl_authed(base: &[&str], url: &str, auth: &Auth) -> Result<Vec<u8>, OciError> {
    let bearer = auth.bearer_header();
    let mut args: Vec<&str> = base.to_vec();
    if let Some(b) = &bearer {
        args.push("-H");
        args.push(b);
    }
    args.push("--");
    args.push(url);
    match auth.basic_config() {
        Some(cfg) => crate::net::curl_with_config(&args, &cfg),
        None => crate::net::curl(&args),
    }
}

/// Quietly download a small blob (the config JSON) to `tmp` — no progress bar (unlike a layer), size-
/// and time-capped, https-pinned, with the same off-argv auth as every other request.
fn download_blob_quiet(url: &str, tmp: &str, auth: &Auth) -> Result<(), OciError> {
    let mut args = vec!["-sS", "-L"];
    args.extend_from_slice(TLS_PIN);
    args.extend_from_slice(&[
        "--max-redirs",
        "10",
        "--max-filesize",
        "4000000",
        "--connect-timeout",
        "10",
        "--max-time",
        "120",
        "-o",
        tmp,
    ]);
    curl_authed(&args, url, auth)?;
    Ok(())
}

/// Parse the OCI image config blob's `config.{Entrypoint,Cmd,Env,WorkingDir,User}` into [`ImageConfig`].
fn parse_image_config(blob: &str) -> ImageConfig {
    // No `"config"` object (malformed/unexpected) → scan the whole blob defensively; a real OCI
    // config always carries it, so this fallback is belt-and-braces, not the normal path.
    let cfg = object_after(blob, "config").unwrap_or(blob);
    let nonempty = |s: String| (!s.is_empty()).then_some(s);
    ImageConfig {
        entrypoint: str_array_after(cfg, "Entrypoint"),
        cmd: str_array_after(cfg, "Cmd"),
        env: str_array_after(cfg, "Env"),
        workdir: first_str(cfg, "WorkingDir").and_then(nonempty),
        user: first_str(cfg, "User").and_then(nonempty),
    }
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

/// Explain a manifest that yielded no layers. A registry error body (`UNAUTHORIZED`/`denied`) or an
/// empty body (a bare `401`) almost always means a **private repo you're not logged into**, so point
/// at `kern login` rather than the opaque "no layers"; otherwise the tag is malformed or absent.
fn manifest_error(manifest: &str, registry: &str, repo: &str) -> OciError {
    let low = manifest.to_ascii_lowercase();
    let auth_ish = manifest.trim().is_empty()
        || low.contains("unauthorized")
        || low.contains("denied")
        || low.contains("authentication");
    if auth_ish {
        OciError::Registry(format!(
            "cannot access '{repo}' on {registry} — it may be private (run `kern login {registry}`) \
             or the tag may not exist"
        ))
    } else {
        OciError::Registry("no layers in manifest".into())
    }
}

fn current_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    }
}

/// Download a blob to `tmp` showing curl's live progress bar (`-#`, stderr inherited) so a big
/// layer never looks frozen. `-S` surfaces errors; `-L` follows redirects (registries hand blobs off
/// to a CDN) but `--proto-redir =https` keeps every hop on TLS — a hostile registry can't redirect a
/// blob to `http://`/`file://`. Bearer creds go in a header; Basic creds go via `-K` STDIN (off-argv).
fn curl_download(url: &str, tmp: &str, auth: &Auth) -> Result<(), OciError> {
    let mut cmd = Command::new("curl");
    cmd.args(["-#", "-S", "-L"]).args(TLS_PIN).args([
        "--max-redirs",
        "10",
        "--connect-timeout",
        "10",
        "--max-time",
        "600",
        // Bound the download itself: a hostile registry could otherwise stream an arbitrarily large
        // body for the whole `--max-time` window and fill the disk before any size check runs. The
        // uncompressed layer is separately capped in `check_layer_safe`; this bounds the compressed
        // fetch. Generous enough for any realistic layer.
        "--max-filesize",
        MAX_LAYER_DOWNLOAD_BYTES,
        "-o",
        tmp,
    ]);
    if let Some(h) = auth.bearer_header() {
        cmd.args(["-H", &h]);
    }
    // This re-hand-rolls the `-K -` STDIN plumbing that `net::curl_with_config` owns because it needs
    // a different I/O shape: stream to `-o tmp` and INHERIT stderr for the live progress bar, rather
    // than capturing stdout — so it can't reuse that helper.
    let basic_cfg = auth.basic_config();
    if basic_cfg.is_some() {
        cmd.args(["-K", "-"]).stdin(Stdio::piped());
    }
    cmd.arg("--").arg(url).stderr(Stdio::inherit()); // live progress bar to the terminal
    let mut child = cmd
        .spawn()
        .map_err(|e| OciError::Tool("curl", e.to_string()))?;
    if let (Some(cfg), Some(mut sin)) = (basic_cfg, child.stdin.take()) {
        use std::io::Write;
        let _ = sin.write_all(cfg.as_bytes()); // drop closes stdin → curl proceeds
    }
    let status = child
        .wait()
        .map_err(|e| OciError::Tool("curl", e.to_string()))?;
    if !status.success() {
        return Err(OciError::Tool(
            "curl",
            format!("download failed (exit {:?})", status.code()),
        ));
    }
    Ok(())
}

/// Escape a value for curl's `-K` config double-quoted string: backslash-escape `\` and `"`, and
/// DROP control characters (`\n`/`\r`/…). A newline would otherwise close the `user = "…"` line and
/// let a crafted credential inject an arbitrary curl directive; control chars can't appear in a valid
/// HTTP Basic credential anyway. (`kern login` already reads a single line, so this is defence in
/// depth against a hand-edited credentials file.)
fn curl_cfg_escape(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// How to authenticate requests to a registry, discovered from its `WWW-Authenticate` challenge.
enum Auth {
    /// Open (or already-satisfied) — no `Authorization` header.
    None,
    /// A short-lived Bearer token from the registry's token endpoint (Docker Hub, GHCR, GitLab,
    /// Harbor, quay, …). Sent as a header (tokens are not the long-lived secret).
    Bearer(String),
    /// HTTP Basic — the `kern login` credentials, sent to curl **off-argv** via a `-K` STDIN config.
    Basic { user: String, pass: String },
}

impl Auth {
    /// The `Authorization: Bearer …` header, if this is a Bearer auth.
    fn bearer_header(&self) -> Option<String> {
        match self {
            Auth::Bearer(t) => Some(format!("Authorization: Bearer {t}")),
            _ => None,
        }
    }
    /// A curl `-K` config line carrying the Basic credentials off-argv, if this is Basic auth.
    fn basic_config(&self) -> Option<String> {
        match self {
            Auth::Basic { user, pass } => Some(curl_user_config(user, pass)),
            _ => None,
        }
    }
}

/// The single place that renders stored credentials into curl's `-K` config `user = "u:p"` line,
/// with the control-char/quote escaping ([`curl_cfg_escape`]) that stops a crafted credential from
/// injecting a curl directive. Every credential-bearing request goes through here.
fn curl_user_config(user: &str, pass: &str) -> String {
    format!(
        "user = \"{}:{}\"\n",
        curl_cfg_escape(user),
        curl_cfg_escape(pass)
    )
}

/// Discover how to authenticate to `registry` for pulling `repo`, via the standard registry-v2
/// `WWW-Authenticate` challenge — so ANY compliant registry works (Docker Hub, GHCR, GitLab, Harbor,
/// quay, self-hosted `distribution`), not just Docker Hub. Pings `/v2/`: a `200` means no auth is
/// needed; a `401` carries the challenge. For a `Bearer` challenge we fetch a pull-scoped token from
/// the advertised realm (anonymously, or upgraded with `kern login` credentials for private repos);
/// for a `Basic` challenge we carry the credentials directly. Credentials always travel to curl via a
/// `-K` STDIN config, never argv, so another same-uid process can't read them from `/proc/<pid>/cmdline`.
fn discover_auth(registry: &str, repo: &str) -> Result<Auth, OciError> {
    let headers = match crate::net::head_headers(&format!("https://{registry}/v2/")) {
        Ok(h) => h,
        // A registry that won't answer the ping (older/odd) — fall back to anonymous and let the
        // manifest fetch surface a clear error if auth turns out to be required.
        Err(_) => return Ok(Auth::None),
    };
    if http_status(&headers) != 401 {
        return Ok(Auth::None); // open registry, or already authorized
    }
    let creds = kern_common::registry_auth::lookup(registry);
    match parse_www_authenticate(&headers) {
        Some(Challenge::Bearer { realm, service }) => {
            // Ask the token endpoint for a pull-scoped token for this repo. The realm/service come
            // from the (TLS-authenticated) challenge; the scope we request ourselves.
            let scope = format!("repository:{repo}:pull");
            let sep = if realm.contains('?') { '&' } else { '?' };
            let url = format!("{realm}{sep}service={service}&scope={scope}");
            let mut base = vec!["-sSL"];
            base.extend_from_slice(TLS_PIN);
            base.extend_from_slice(&[
                "--max-redirs",
                "5",
                "--max-filesize",
                "8000000", // a token response is tiny — cap it so a hostile realm can't OOM us
                "--connect-timeout",
                "10",
                "--max-time",
                "60",
                "--",
                url.as_str(),
            ]);
            // CREDENTIAL SAFETY (CVE-2020-15157 class): only send the stored credentials to the token
            // endpoint if its host belongs to the SAME registry (same host, or a subdomain of the
            // registry's parent domain — e.g. Docker Hub's registry-1.docker.io ↔ auth.docker.io). A
            // hostile/compromised registry could otherwise advertise `realm="https://evil/token"` and
            // harvest the creds the user stored for it. If the realm is foreign we withhold the creds
            // and fetch an ANONYMOUS token instead (fine for public repos; a private one then fails
            // with a clear 401), warning so it's never a silent behaviour change.
            let send_creds = creds
                .as_ref()
                .filter(|_| realm_host_trusted(&realm, registry));
            if creds.is_some() && send_creds.is_none() {
                eprintln!(
                    "kern: withholding credentials — {registry} pointed its auth to a different host \
                     ({realm}); fetching an anonymous token instead"
                );
            }
            let body = match send_creds {
                Some((user, pass)) => {
                    crate::net::curl_with_config(&base, &curl_user_config(user, pass))?
                }
                None => curl(&base)?,
            };
            let s = String::from_utf8_lossy(&body);
            // Docker uses `token`; GHCR/others use `access_token` (both per the OAuth2 token spec).
            let tok = first_str(&s, "token")
                .or_else(|| first_str(&s, "access_token"))
                .ok_or_else(|| OciError::Registry("no auth token in token response".into()))?;
            Ok(Auth::Bearer(tok))
        }
        Some(Challenge::Basic) => {
            let (user, pass) = creds.ok_or_else(|| {
                OciError::Registry(format!(
                    "{registry} requires authentication — run `kern login {registry}`"
                ))
            })?;
            Ok(Auth::Basic { user, pass })
        }
        // A 401 with no recognizable scheme: nothing we can do but try anonymously.
        None => Ok(Auth::None),
    }
}

/// Whether it's safe to send the registry's stored credentials to a Bearer `realm` (token endpoint).
/// True only when the realm host is the registry host, or a subdomain of the registry's parent domain
/// (so Docker Hub's `registry-1.docker.io` trusts `auth.docker.io`, but no registry can point auth at
/// an unrelated host to harvest creds — the CVE-2020-15157 credential-leak class). The realm must be
/// `https://`. Both hosts are parsed the SAME way curl resolves them (userinfo + port stripped, see
/// [`host_from_authority`]) — a parser differential here would itself be an allowlist bypass.
fn realm_host_trusted(realm: &str, registry: &str) -> bool {
    let reg_host = host_from_authority(registry.split('/').next().unwrap_or(registry));
    let Some(after) = realm.strip_prefix("https://") else {
        return false; // non-TLS realm → never trust creds to it
    };
    let realm_host = host_from_authority(after.split(['/', '?', '#']).next().unwrap_or(after));
    if realm_host.is_empty() {
        return false;
    }
    if realm_host == reg_host {
        return true;
    }
    // Parent domain = registry host minus its first label (registry-1.docker.io → docker.io). Guards:
    // it must have a dot and >3 chars (so a single-label TLD `io`/`com` is never a trusted parent),
    // and must not be a known multi-label public suffix (so two unrelated `*.co.uk` registries can't
    // cross-trust).
    match reg_host.split_once('.') {
        Some((_, parent))
            if parent.len() > 3 && parent.contains('.') && !is_public_suffix(parent) =>
        {
            realm_host == parent || realm_host.ends_with(&format!(".{parent}"))
        }
        _ => false,
    }
}

/// The host of a URL authority as curl would dial it: drop any `userinfo@` (curl uses the part after
/// the LAST `@` as the host — a `realm="https://trusted:0@evil.com/…"` connects to `evil.com`, NOT
/// `trusted`) and any `:port`, lowercased (DNS is case-insensitive). Parsing the host the same way
/// curl resolves it is what keeps [`realm_host_trusted`] sound.
fn host_from_authority(authority: &str) -> String {
    let host = authority.rsplit('@').next().unwrap_or(authority);
    host.split(':').next().unwrap_or(host).to_ascii_lowercase()
}

/// A registrable-domain check without a full public-suffix list (out of scope for a dependency-free
/// build): the common multi-label public suffixes that must never count as a trustable parent domain
/// in [`realm_host_trusted`]. Not exhaustive — it closes the realistic ccTLD second-levels; a full
/// PSL would be the complete fix.
fn is_public_suffix(d: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "co.jp", "ne.jp", "or.jp", "com.au",
        "net.au", "org.au", "co.nz", "co.in", "co.za", "com.br", "com.cn", "com.mx", "com.tr",
        "com.sg", "com.hk", "co.kr", "com.ar", "com.pl", "co.il",
    ];
    SUFFIXES.contains(&d)
}

/// The auth scheme advertised in a registry's `WWW-Authenticate` challenge header.
enum Challenge {
    Bearer { realm: String, service: String },
    Basic,
}

/// Parse the `WWW-Authenticate` header from a raw HTTP response-header block.
fn parse_www_authenticate(headers: &str) -> Option<Challenge> {
    let line = headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("www-authenticate:"))?;
    let val = line.split_once(':')?.1.trim();
    let scheme = val.split_whitespace().next()?.to_ascii_lowercase();
    match scheme.as_str() {
        "bearer" => Some(Challenge::Bearer {
            realm: auth_param(val, "realm")?,
            service: auth_param(val, "service").unwrap_or_default(),
        }),
        "basic" => Some(Challenge::Basic),
        _ => None,
    }
}

/// Pull `key="value"` out of a `WWW-Authenticate` parameter list (`realm="…",service="…"`).
fn auth_param(s: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=\"");
    let start = s.find(&pat)? + pat.len();
    let rest = &s[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The numeric status from an HTTP response's first line (`HTTP/1.1 401 …` → `401`).
fn http_status(headers: &str) -> u16 {
    headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

fn fetch_manifest(
    registry: &str,
    repo: &str,
    reference: &str,
    auth: &Auth,
) -> Result<String, OciError> {
    let url = format!("https://{registry}/v2/{repo}/manifests/{reference}");
    let accept = "Accept: application/vnd.oci.image.index.v1+json,\
        application/vnd.oci.image.manifest.v1+json,\
        application/vnd.docker.distribution.manifest.list.v2+json,\
        application/vnd.docker.distribution.manifest.v2+json";
    let mut args = vec!["-sSL"];
    args.extend_from_slice(TLS_PIN);
    args.extend_from_slice(&[
        "--max-redirs",
        "5",
        // A manifest is small (KBs); cap the body so a hostile registry can't stream GBs into memory
        // (unlike blobs, the manifest is buffered in RAM).
        "--max-filesize",
        "8000000",
        "--connect-timeout",
        "10",
        "--max-time",
        "60",
        "-H",
        accept,
    ]);
    let body = curl_authed(&args, &url, auth)?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn extract_layer(
    registry: &str,
    repo: &str,
    digest: &str,
    auth: &Auth,
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
    curl_download(&url, &tmp_s, auth)?;

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
pub(crate) fn unsafe_member_path(p: &str) -> bool {
    p.starts_with('/') || p.split('/').any(|c| c == "..") || p.contains('\0')
}

/// Max uncompressed bytes per layer — a decompression-bomb ceiling (2 GiB).
const MAX_LAYER_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Max entries per layer — a dir/empty-file *inode* bomb has ~0 byte total but still exhausts the fs.
const MAX_LAYER_ENTRIES: u64 = 2_000_000;
/// Max COMPRESSED bytes for a single layer download (curl `--max-filesize`), as a string for the argv.
/// Bounds a disk-fill DoS from a hostile registry; generous enough for any realistic layer (8 GB).
const MAX_LAYER_DOWNLOAD_BYTES: &str = "8000000000";

/// The TLS-pinning flags EVERY registry fetch must carry: HTTPS-only on the initial request AND on
/// every redirect hop (registries hand blobs to a CDN), with a bounded redirect count. Single-sourced
/// so a copy can't silently drop `--proto-redir =https` and let a hostile registry downgrade a hop to
/// `http://` or `file://`. (`--max-redirs` stays per-call — the count legitimately differs.)
const TLS_PIN: &[&str] = &["--proto", "=https", "--proto-redir", "=https"];

/// Is the system `tar` GNU tar? GNU tar refuses to extract THROUGH a planted symlink (the secure
/// default); BusyBox tar historically follows it, so on a non-GNU tar we must reject escaping symlink
/// targets in a layer ourselves. Probed once.
fn tar_is_gnu() -> bool {
    use std::sync::OnceLock;
    static GNU: OnceLock<bool> = OnceLock::new();
    *GNU.get_or_init(|| {
        Command::new("tar")
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("GNU tar"))
            .unwrap_or(false)
    })
}

/// Vet a downloaded layer tarball before extraction. Lists entries with `tar -tzv` and rejects:
/// absolute paths, `..` traversal, device/special nodes, and a total uncompressed size over the
/// bomb cap. (Cross-layer symlink escapes are handled structurally by isolated staging +
/// no-follow merge in [`merge_layer`].)
fn check_layer_safe(tar_path: &Path) -> Result<(), OciError> {
    use std::io::BufRead;
    // `LC_ALL=C` pins tar's `-v` output to the stable English form we parse — `x -> y` for a symlink,
    // `x link to y` for a HARDLINK. A localized listing (`collegamento a`, …) would otherwise hide a
    // hardlink target from the escape check below. STREAM stdout line-by-line so the entry/size caps
    // abort EARLY with bounded memory instead of buffering the whole (attacker-sized) listing in RAM.
    let mut child = Command::new("tar")
        .args(["-tzvf", &tar_path.to_string_lossy()])
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| OciError::Tool("tar", e.to_string()))?;
    let stdout = child.stdout.take().expect("stdout piped");
    let gnu_tar = tar_is_gnu();
    let mut total: u64 = 0;
    let mut entries: u64 = 0;

    let scan = || -> Result<(), OciError> {
        for line in std::io::BufReader::new(stdout).lines() {
            let line = line.map_err(|e| OciError::Tool("tar", e.to_string()))?;
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 6 {
                continue; // not an entry line
            }
            // Cap the entry COUNT, not just the byte total: a layer of millions of empty files/dirs
            // sums to ~0 bytes yet exhausts inodes/disk on extraction.
            entries += 1;
            if entries > MAX_LAYER_ENTRIES {
                return Err(OciError::Extract(
                    "layer has too many entries (possible inode bomb)".into(),
                ));
            }
            let typ = cols[0].as_bytes().first().copied().unwrap_or(b'-');
            // The size column is always numeric; an unparseable value means the columns are desynced
            // (e.g. a crafted uname with spaces) — refuse rather than silently count it as 0, which
            // would let a decompression bomb slip under the size cap.
            let Ok(size) = cols[2].parse::<u64>() else {
                return Err(OciError::Extract(format!(
                    "unparseable layer listing (bad size column): {line}"
                )));
            };
            // Split the entry name from its optional link target: `-> ` for a symlink, `link to ` for
            // a hardlink (both in the C locale forced above).
            let name = cols[5..].join(" ");
            let (path, link_target) = match typ {
                b'l' => name
                    .split_once(" -> ")
                    .map_or((name.as_str(), None), |(p, t)| (p, Some(t))),
                b'h' => name
                    .split_once(" link to ")
                    .map_or((name.as_str(), None), |(p, t)| (p, Some(t))),
                _ => (name.as_str(), None),
            };

            if typ == b'c' || typ == b'b' {
                return Err(OciError::Extract(format!(
                    "layer has a device node: {path}"
                )));
            }
            if unsafe_member_path(path) {
                return Err(OciError::Extract(format!("unsafe path in layer: {path}")));
            }
            // A HARDLINK target is a real path into the rootfs and must stay inside it (an absolute/
            // `..` target hardlinks a HOST inode into the image — a confidentiality escape). A SYMLINK
            // target is normally fine — the no-follow merge never traverses it, and legit images carry
            // absolute symlinks (`/usr/lib/x -> /lib/x`) — UNLESS `tar -xzf` itself follows a planted
            // symlink within one layer's extraction: GNU tar doesn't, BusyBox tar historically does.
            // So reject an escaping hardlink target always, and an escaping symlink target on non-GNU tar.
            if let Some(t) = link_target {
                let escapes = unsafe_member_path(t);
                if (typ == b'h' && escapes) || (typ == b'l' && escapes && !gnu_tar) {
                    return Err(OciError::Extract(format!(
                        "layer {} target escapes the rootfs: {path} -> {t}",
                        if typ == b'h' { "hardlink" } else { "symlink" }
                    )));
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
    };
    let scanned = scan();

    // A scan error (cap tripped / unsafe entry) means we bailed early — kill tar so it can't keep
    // decompressing; otherwise wait and require a clean exit (a corrupt gzip fails here).
    if scanned.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return scanned;
    }
    match child.wait() {
        Ok(s) if s.success() => Ok(()),
        _ => Err(OciError::Extract(
            "could not list layer (corrupt or unsupported archive)".into(),
        )),
    }
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
            // A whiteout deletes a sibling in THIS directory, so the victim must be a plain file
            // name. Reject `.`/`..`/empty/`<sep>`: a crafted `.wh...` strips to `..`, and
            // `with_file_name("..")` then points at the rootfs's PARENT — `remove_no_follow` would
            // `remove_dir_all` files OUTSIDE the image (other pulled images / the store). `..` is a
            // real dir, so the no-follow symlink guard does not stop it. (Opaque marker handled above.)
            let plain_victim = !victim_name.is_empty()
                && victim_name != "."
                && victim_name != ".."
                && !victim_name.contains('/');
            if fname.as_ref() != ".wh..wh..opq" && plain_victim {
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
    fn parses_bearer_challenge() {
        let h = "HTTP/1.1 401 Unauthorized\r\n\
            Www-Authenticate: Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/alpine:pull\"\r\n\
            Content-Type: application/json\r\n";
        assert_eq!(http_status(h), 401);
        match parse_www_authenticate(h) {
            Some(Challenge::Bearer { realm, service }) => {
                assert_eq!(realm, "https://auth.docker.io/token");
                assert_eq!(service, "registry.docker.io");
            }
            _ => panic!("expected a Bearer challenge"),
        }
    }

    #[test]
    fn parses_basic_challenge_and_status() {
        let h = "HTTP/2 401\r\nwww-authenticate: Basic realm=\"Registry\"\r\n";
        assert_eq!(http_status(h), 401);
        assert!(matches!(parse_www_authenticate(h), Some(Challenge::Basic)));
    }

    #[test]
    fn open_registry_and_unknown_scheme() {
        // A 200 ping → no challenge line at all.
        assert_eq!(http_status("HTTP/1.1 200 OK\r\n\r\n"), 200);
        assert!(parse_www_authenticate("HTTP/1.1 200 OK\r\n").is_none());
        // A 401 with an unrecognized scheme → None (fall back to anonymous).
        assert!(parse_www_authenticate("HTTP/1.1 401\r\nWWW-Authenticate: Digest x\r\n").is_none());
    }

    #[test]
    fn realm_trust_pins_creds_to_the_registry() {
        // Docker Hub: registry-1.docker.io must trust auth.docker.io (shared parent docker.io).
        assert!(realm_host_trusted(
            "https://auth.docker.io/token",
            "registry-1.docker.io"
        ));
        // Same-host token endpoints (GHCR, quay, GitLab).
        assert!(realm_host_trusted("https://ghcr.io/token", "ghcr.io"));
        assert!(realm_host_trusted("https://quay.io/v2/auth", "quay.io"));
        assert!(realm_host_trusted(
            "https://registry.gitlab.com/jwt/auth",
            "registry.gitlab.com"
        ));
        // CVE-2020-15157: a registry pointing auth at a foreign host must NOT get the creds.
        assert!(!realm_host_trusted(
            "https://collector.evil.com/token",
            "registry-1.docker.io"
        ));
        assert!(!realm_host_trusted("https://evil.com/token", "ghcr.io"));
        // CRITICAL bypass class — userinfo (`user@host`) with/without a port: curl connects to the
        // host AFTER the last `@`, so the check must too. Every one of these dials `evil.com`.
        assert!(!realm_host_trusted(
            "https://ghcr.io@evil.com/token",
            "ghcr.io"
        ));
        assert!(!realm_host_trusted(
            "https://ghcr.io:0@evil.com/token",
            "ghcr.io"
        ));
        assert!(!realm_host_trusted(
            "https://auth.docker.io:0@evil.com/token",
            "registry-1.docker.io"
        ));
        assert!(!realm_host_trusted(
            "https://registry.gitlab.com@evil.com/token",
            "registry.gitlab.com"
        ));
        // `#` ends the authority (curl treats it as a fragment) — must not smuggle a foreign host.
        assert!(!realm_host_trusted(
            "https://ghcr.io:0@evil.com#x",
            "ghcr.io"
        ));
        // Public-suffix parent: a `label.co.uk` registry must NOT cross-trust another `*.co.uk`.
        assert!(!realm_host_trusted(
            "https://attacker.co.uk/token",
            "myreg.co.uk"
        ));
        // …but a real registrable domain under a ccTLD still trusts its own subdomains.
        assert!(realm_host_trusted(
            "https://auth.company.co.uk/token",
            "registry.company.co.uk"
        ));
        // Case-insensitive host comparison (DNS is case-insensitive).
        assert!(realm_host_trusted(
            "https://AUTH.DOCKER.IO/token",
            "registry-1.docker.io"
        ));
        // A bare public suffix parent (`io`) must never count as trusted across registries.
        assert!(!realm_host_trusted("https://evil.io/token", "ghcr.io"));
        // Non-https realm is never trusted with creds.
        assert!(!realm_host_trusted(
            "http://auth.docker.io/token",
            "registry-1.docker.io"
        ));
        // A registry carrying a :port compares on host only.
        assert!(realm_host_trusted(
            "https://localhost/token",
            "localhost:5000"
        ));
    }

    #[test]
    fn manifest_error_points_at_login_for_auth_failures() {
        // An empty body (a bare 401) or a registry auth-error body → the `kern login` hint.
        for body in [
            "",
            "{\"errors\":[{\"code\":\"UNAUTHORIZED\"}]}",
            "{\"errors\":[{\"code\":\"DENIED\"}]}",
        ] {
            let e = manifest_error(body, "ghcr.io", "org/app").to_string();
            assert!(e.contains("kern login ghcr.io"), "got: {e}");
        }
        // A genuinely layerless-but-valid manifest keeps the plain message.
        let e =
            manifest_error("{\"schemaVersion\":2,\"config\":{}}", "ghcr.io", "org/app").to_string();
        assert!(e.contains("no layers"), "got: {e}");
    }

    #[test]
    fn auth_param_extracts_quoted_values() {
        let v = "Bearer realm=\"https://a/b?c=d\",service=\"svc\"";
        assert_eq!(auth_param(v, "realm").as_deref(), Some("https://a/b?c=d"));
        assert_eq!(auth_param(v, "service").as_deref(), Some("svc"));
        assert_eq!(auth_param(v, "scope"), None);
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

    /// SECURITY (regression): an OCI whiteout whose victim strips to `..` (member name `.wh...`) must
    /// NOT delete the rootfs's PARENT. Without the guard, `with_file_name("..")` → `<dest>/..` and
    /// `remove_no_follow` would `remove_dir_all` files OUTSIDE the image (other pulled images / store).
    #[test]
    fn whiteout_dotdot_cannot_escape_the_rootfs() {
        let base = std::env::temp_dir().join(format!("kern-oci-wh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dest = base.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        // A sibling of `dest` — i.e. living under `dest/..` (== base) — that an escape would wipe.
        let outside = base.join("outside_sibling.txt");
        std::fs::write(&outside, b"keep me").unwrap();
        // A layer (staging) carrying a single member `.wh...`: `.wh.` + `..` → victim name "..".
        let staging = base.join("stg");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join(".wh..."), b"").unwrap();

        let _ = merge_layer(&staging, &dest);

        assert!(
            outside.exists(),
            "a `.wh...` whiteout must not delete the rootfs's parent (escape)"
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
