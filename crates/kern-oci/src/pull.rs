//! OCI image pull (registry v2) via `curl` + `tar`.
//!
//! Resolves an image reference, fetches a manifest (selecting this host's arch from a manifest
//! list / image index), downloads each layer blob, extracts it into a rootfs directory, and
//! applies OCI whiteouts - with the symlink-escape guard from [`crate::whiteout_dir_symlink_free`].
//!
//! Tooling: `curl` (TLS, auth, redirects) and GNU `tar` (gzip + traversal-safe extraction, no
//! `-P`). Authentication follows the standard registry-v2 `WWW-Authenticate` challenge, so any
//! compliant registry works (Docker Hub, GHCR, GitLab, quay, Harbor, self-hosted) - anonymously, or
//! with `kern login` credentials (sent off-argv). All requests are https-pinned.
//!
//! Hardening (adversarial images): every blob is verified to hash to its `sha256:` digest
//! ([`verify_digest`]) before use. Each layer is then vetted ([`check_layer_safe`]) by reading the
//! RAW tar headers IN-PROCESS (`gzip -dc` only decompresses) - name/prefix/linkname/typeflag at fixed
//! offsets, resolving GNU long-name/link and PAX overrides - so the escape decision (no absolute/`..`
//! path, no device node, no escaping hardlink target, a 2 GiB bomb cap, an entry-count cap) never
//! depends on parsing `tar -tv`'s locale-dependent, delimiter-desyncable text. The layer is then
//! extracted into an ISOLATED staging dir and merged into the rootfs with **no-follow** semantics
//! ([`merge_layer`]) - a symlink planted by an earlier layer can never be traversed by a later
//! layer's writes, so the cross-layer escape class is closed structurally, not by trusting tar.

use crate::json::{
    all_str_values, array_after, first_str, object_after, split_objects, str_array_after,
};
use crate::net::curl;
use crate::whiteout_dir_symlink_free;
use std::path::Path;
use std::process::{Command, Stdio};

const DEFAULT_REGISTRY: &str = "registry-1.docker.io";

/// Warn if the pull destination sits on a Windows-mounted filesystem. WSL2 exposes the Windows drives
/// (`/mnt/c`, `\\wsl$`) as a **9p** (`drvfs`) mount that can't represent Linux ownership, permissions,
/// or special files - so extracting an image there is slow and, for images that carry those (e.g.
/// `debian`), fails outright with an opaque "layer extraction failed". Turn that into an actionable
/// hint BEFORE the failure: pull into a real Linux filesystem instead (the WSL home / a Linux-side
/// cache). Simple images (alpine/busybox) still extract on 9p, so this warns rather than refuses.
/// Linux-only and a no-op on every native filesystem (9p never matches there).
fn warn_if_windows_mount(dest: &Path) {
    use std::os::unix::ffi::OsStrExt;
    const V9FS_MAGIC: i64 = 0x0102_1997; // WSL2 drvfs / `\\wsl$` is a 9p mount
    let Ok(c) = std::ffi::CString::new(dest.as_os_str().as_bytes()) else {
        return;
    };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0 && st.f_type as i64 == V9FS_MAGIC {
        eprintln!(
            "kern: warning: pulling into a Windows-mounted path (WSL2 9p/drvfs) - slow, and it fails \
             for images carrying Linux ownership/permissions (e.g. debian). Pull into a Linux \
             filesystem instead: run from your WSL home directory, not a /mnt/<drive> path."
        );
    }
}

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

/// An image's runtime configuration, read from its OCI config blob - the defaults `kern box --image`
/// applies (explicit CLI flags win) so an official image runs like `docker run`, not a bare shell.
#[derive(Debug, Default, Clone)]
pub struct ImageConfig {
    /// `config.Entrypoint` - prepended to the command.
    pub entrypoint: Vec<String>,
    /// `config.Cmd` - the default command (used when the user gives none).
    pub cmd: Vec<String>,
    /// `config.Env` - `KEY=VALUE` strings, applied UNDER the user's `--env` (user wins).
    pub env: Vec<String>,
    /// `config.WorkingDir` - default working directory.
    pub workdir: Option<String>,
    /// `config.User` - default `uid[:gid]` / name.
    pub user: Option<String>,
    /// `config.ExposedPorts` keys, as `(port, is_udp)`. The image's IMPLICIT EXPOSE (nginx's `80`,
    /// postgres's `5432`), which the compose file need not restate. Lets a stack preflight warn when
    /// two pod services would bind the same container port even though neither DECLARES it. Empty
    /// when the image config omits it.
    pub exposed_ports: Vec<(u16, bool)>,
}

/// Pull `image` into `dest` (created if needed), producing a usable rootfs, and return its OCI
/// runtime config (entrypoint/cmd/env/workdir/user). Progress is reported to **stderr** (so stdout
/// stays clean) - the user always sees what's happening, never a silent hang.
pub fn pull(
    image: &str,
    dest: &Path,
    platform: Option<&Platform>,
) -> Result<ImageConfig, OciError> {
    let host = Platform::host();
    let want = platform.unwrap_or(&host);
    eprintln!("→ resolving {image} ({}/{})", want.os, want.arch);
    let (registry, repo, reference) = parse_ref(image)?;
    let auth = discover_auth(&registry, &repo)?;

    let manifest = fetch_manifest(&registry, &repo, &reference, &auth)?;
    // A digest PIN is a content-address: verify the bytes hash to it, so a compromised registry cannot
    // serve a DIFFERENT manifest under a pinned reference (TLS protects the transport, not a malicious
    // or backdoored registry). Only sha256 references reach here as digests; a tag skips this.
    if reference.starts_with("sha256:") {
        verify_digest_bytes(manifest.as_bytes(), &reference)?;
    }
    let manifest = if is_manifest_list(&manifest) {
        // Select the requested arch EXACTLY - no wrong-arch fallback. Under an explicit `--platform`
        // that would silently pull the wrong image; even by default it's safer to error with the list
        // of available arches than to hand back a mismatched rootfs.
        let digest = select_arch_digest(&manifest, want).ok_or_else(|| {
            let avail = available_arches(&manifest);
            OciError::Registry(if avail.is_empty() {
                format!("no linux/{} manifest in the index", want.arch)
            } else {
                format!(
                    "no linux/{} manifest - available: {}",
                    want.arch,
                    avail.join(", ")
                )
            })
        })?;
        // The index names the sub-manifest by digest; verify the fetched sub-manifest against it, so the
        // chain is content-addressed end to end (index -> arch manifest -> already-verified blobs).
        let sub = fetch_manifest(&registry, &repo, &digest, &auth)?;
        verify_digest_bytes(sub.as_bytes(), &digest)?;
        sub
    } else {
        manifest
    };

    let layers = layer_digests(&manifest);
    if layers.is_empty() {
        return Err(manifest_error(&manifest, &registry, &repo));
    }
    // Bound the layer COUNT before downloading any: a hostile manifest (limited only by the manifest
    // body cap → tens of thousands of digests) times MAX_LAYER_BYTES each is a large disk-fill. Real
    // images stay well under Docker's 127-layer ceiling; MAX_LAYERS is generous headroom that still
    // refuses an absurd manifest up front rather than mid-download.
    const MAX_LAYERS: usize = 512;
    if layers.len() > MAX_LAYERS {
        return Err(OciError::Registry(format!(
            "manifest lists {} layers (max {MAX_LAYERS}) - refusing a likely resource-exhaustion image",
            layers.len()
        )));
    }
    let total = layers.len();
    eprintln!(
        "→ {total} layer{} to download + extract",
        if total == 1 { "" } else { "s" }
    );
    std::fs::create_dir_all(dest).map_err(|e| OciError::Extract(e.to_string()))?;
    warn_if_windows_mount(dest);
    // ONE-CONNECTION PRE-DOWNLOAD (cold-pull speedup): fetch the config blob + every layer blob in a
    // SINGLE `curl` process (keep-alive reused across `--next`), so the whole blob set costs ONE TLS
    // handshake instead of one per blob - the measured cold-pull bottleneck was that each separate
    // `curl` process re-handshakes to the same registry host. Best-effort and TRANSPORT-ONLY: it writes
    // each blob to the SAME tmp path `fetch_config`/`download_layer` use, so they find it already there
    // and skip their own download; every blob is still sha256-verified and every layer still vetted +
    // merged no-follow, byte-identical to before. A no-op for Basic-credential registries (leaves that
    // audited off-argv `-K` path untouched) and on any failure (tmps cleaned → the per-blob path re-runs).
    download_blobs_oneconn(&registry, &repo, &manifest, &layers, &auth, dest);
    // The image's runtime config (entrypoint/env/…) - now usually already fetched above; `fetch_config`
    // reuses the pre-downloaded tmp when present. Best-effort: a missing/odd config yields defaults.
    let config = fetch_config(&registry, &repo, &manifest, &auth, dest);
    // PREFETCH: download layer K+1 concurrently while layer K is verified + extracted + merged. The
    // per-layer download command is UNCHANGED (same TLS pin, auth, timeouts) - only the SCHEDULING
    // overlaps the next layer's network with the current layer's CPU (decompress/extract). Extract +
    // merge stay strictly ordered (overlay whiteout semantics demand it), so the result is byte-identical
    // to the sequential path; security is untouched. Wall-clock ≈ slowest download + Σ extracts, not Σ both.
    let spawn_dl = |i: usize| {
        let (reg, rp, dig, dst, a) = (
            registry.clone(),
            repo.clone(),
            layers[i].clone(),
            dest.to_path_buf(),
            auth.clone(),
        );
        // Pass the layer INDEX so the tmp blob name is unique per layer, not per digest: an OCI manifest
        // may legally list the SAME digest for adjacent layers, and with prefetch two threads would else
        // `curl -o` the same `.kern-layer-<digest>.tar.gz` at once → torn read / spurious digest mismatch.
        std::thread::spawn(move || download_layer(i, &reg, &rp, &dig, &a, &dst))
    };
    // Escape hatch (like KERN_NO_SCOPE): KERN_NO_PREFETCH=1 → the pre-prefetch execution model,
    // downloads run INLINE (no worker thread at all), strictly before each extract. Off by default;
    // also used to A/B the speedup.
    //
    // NON-root ALSO disables prefetch - and this is a CORRECTNESS guarantee, not a perf choice: a
    // non-root unpack `fork()`s a userns child (see `unpack_as_root`), and forking while a prefetch
    // DOWNLOAD THREAD is live risks the classic fork-in-threaded-process deadlock (the child inherits a
    // possibly-locked allocator). With no prefetch thread, the process is single-threaded at every fork,
    // so the child can never deadlock. Root never forks here (it unpacks in-process), so it keeps the
    // overlap. The cost is only non-root multi-layer pulls losing download/extract overlap - a fair
    // price for a can't-deadlock guarantee on the exact hosts that fork (edge boards run as a user).
    let is_root = unsafe { libc::geteuid() == 0 };
    let prefetch = std::env::var_os("KERN_NO_PREFETCH").is_none() && is_root;
    let mut next = prefetch.then(|| spawn_dl(0));
    // index loop, not `.enumerate()`: we need `i + 1` to prefetch the NEXT layer's download.
    #[allow(clippy::needless_range_loop)]
    for i in 0..total {
        let tmp = match next.take() {
            Some(h) => h
                .join()
                .map_err(|_| OciError::Extract("layer download thread panicked".into()))??,
            None => download_layer(i, &registry, &repo, &layers[i], &auth, dest)?,
        };
        // Prefetch: start layer i+1's download BEFORE extracting i - the SINGLE spawn site - so its
        // network overlaps i's CPU.
        if prefetch && i + 1 < total {
            next = Some(spawn_dl(i + 1));
        }
        // On error, don't just bail: an already-spawned prefetch thread would detach and keep writing its
        // blob into `dest` after the pull failed. Wait for it - SAYING SO first: the join can take as
        // long as that download (the error is worth more than the wait; a detached writer is worse) -
        // and unlink its blob whatever the outcome (`download_layer` cleans up its own curl failures;
        // the deterministic tmp name covers a panicked thread).
        if let Err(e) = process_layer(&tmp, &layers[i], dest, i + 1, total) {
            if let Some(h) = next.take() {
                eprintln!(
                    "✗ layer {}/{total} failed - stopping the in-flight prefetch…",
                    i + 1
                );
                let _ = h.join();
                let _ = std::fs::remove_file(layer_tmp_path(dest, i + 1, &layers[i + 1]));
            }
            return Err(e);
        }
    }
    eprintln!("✓ pulled {image} → {} ({total} layers)", dest.display());
    Ok(config)
}

/// Fetch and parse the image's OCI config blob (the descriptor is in `manifest.config`). Best-effort:
/// any failure (missing descriptor, network, digest mismatch) returns the default config rather than
/// failing the pull - the box just falls back to a shell / the user's flags. The blob is
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
    let url = format!("{}/v2/{repo}/blobs/{digest}", reg_base(registry));
    // Independent size guard checked AFTER the download, BEFORE we read the blob into memory: curl's
    // `--max-filesize` only aborts a transfer whose length is known in advance, so a hostile registry
    // could stream a huge Content-Length-less body. A real config blob is a few KB; refuse over 4 MB.
    const MAX_CONFIG_BYTES: u64 = 4_000_000;
    let within_cap = || {
        std::fs::metadata(&tmp)
            .map(|m| m.len() <= MAX_CONFIG_BYTES)
            .unwrap_or(false)
    };
    // `tmp.exists()` = the one-connection batch pre-download already fetched it; else fetch it now.
    // Either way it is size-capped AND sha256-verified below before we read it.
    let parsed = if (tmp.exists() || download_blob_quiet(&url, &tmp_s, auth).is_ok())
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
/// STDIN config) exactly like every other request - the ONE place the "Basic creds never in argv"
/// decision is made for GET-style fetches (manifest + config blob). Returns curl's stdout (empty
/// when `base` already redirects the body to a file with `-o`).
pub(crate) fn curl_authed(base: &[&str], url: &str, auth: &Auth) -> Result<Vec<u8>, OciError> {
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

/// Quietly download a small blob (the config JSON) to `tmp` - no progress bar (unlike a layer), size-
/// and time-capped, https-pinned, with the same off-argv auth as every other request.
fn download_blob_quiet(url: &str, tmp: &str, auth: &Auth) -> Result<(), OciError> {
    let mut args = vec!["-sS", "-L"];
    args.extend_from_slice(pin_for_url(url));
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
        exposed_ports: exposed_ports_after(cfg),
    }
}

/// The container ports the image's `config.ExposedPorts` declares, as `(port, is_udp)`. That object is
/// keyed `"80/tcp"` / `"53/udp"` with empty `{}` values, so the only quoted strings inside it are the
/// keys - pull each and parse `<port>/<proto>`. Escape handling is unnecessary: a port key is ASCII
/// digits and one slash. Deduplicated; empty when the key is absent or malformed.
pub(crate) fn exposed_ports_after(cfg: &str) -> Vec<(u16, bool)> {
    let Some(obj) = object_after(cfg, "ExposedPorts") else {
        return Vec::new();
    };
    let mut out: Vec<(u16, bool)> = Vec::new();
    let mut in_str = false;
    let mut key = String::new();
    for c in obj.chars() {
        if in_str {
            if c == '"' {
                if let Some((num, proto)) = key.split_once('/') {
                    if let Ok(port) = num.parse::<u16>() {
                        let udp = proto.eq_ignore_ascii_case("udp");
                        if (udp || proto.eq_ignore_ascii_case("tcp")) && !out.contains(&(port, udp))
                        {
                            out.push((port, udp));
                        }
                    }
                }
                key.clear();
                in_str = false;
            } else {
                key.push(c);
            }
        } else if c == '"' {
            in_str = true;
        }
    }
    out
}

/// The tag an untagged reference means. `alpine` is `alpine:latest`, everywhere.
pub const DEFAULT_TAG: &str = "latest";

/// Split `image` into `(name, tag)` when it carries an EXPLICIT tag, else `None`.
///
/// **The single definition of "does this reference name a tag".** A trailing `:tag` only counts if
/// the part after `:` has no `/`, otherwise `localhost:5000/img` would read its port as a tag. A
/// digest (`img@sha256:<hex>`) splits at that same `:` and so counts as explicit, which is what we
/// want: a digest pins harder than a tag and must never have `:latest` bolted onto it.
pub fn split_tag(image: &str) -> Option<(&str, &str)> {
    match image.rsplit_once(':') {
        Some((n, t)) if !t.contains('/') && !n.is_empty() => Some((n, t)),
        _ => None,
    }
}

/// Give a reference its implied tag: `alpine` → `alpine:latest`. Already-tagged, digest-pinned and
/// empty references are returned unchanged.
///
/// Callers that key a cache, a file name or a lookup on the reference MUST go through this first.
/// Without it `alpine` and `alpine:latest` are two different keys for one image, which is how the
/// same 8.7 MB got stored twice, `rmi alpine` left `alpine:latest` behind, and a `save`+`load` round
/// trip renamed an image so the reference that worked before stopped resolving.
pub fn normalize_ref(image: &str) -> String {
    if image.is_empty() || split_tag(image).is_some() {
        return image.to_string();
    }
    format!("{image}:{DEFAULT_TAG}")
}

/// `[registry/]repo[:tag]` → `(registry, repo, reference)`. Bare names get `library/` +
/// `registry-1.docker.io`; the first path segment is a registry only if it looks like a host.
pub(crate) fn parse_ref(image: &str) -> Result<(String, String, String), OciError> {
    if image.is_empty() {
        return Err(OciError::Ref("empty".into()));
    }
    // A DIGEST pin (`name[:tag]@sha256:<hex>`) splits at `@`: the WHOLE `sha256:<hex>` is the manifest
    // reference. Handle it BEFORE `split_tag`, which splits on the LAST `:` and would tear the digest
    // into `name@sha256` + `<hex>`, yielding a nonsensical repo path so the pull never resolves - digest
    // pinning (a supply-chain feature) would silently be broken. The digest wins over any tag, so strip
    // a trailing `:tag` from the name too (keeping a `host:port`, which `split_tag` already distinguishes).
    let (name, reference) = match image.split_once('@') {
        Some((n, digest)) if !n.is_empty() && !digest.is_empty() => {
            let base = split_tag(n).map(|(b, _)| b).unwrap_or(n);
            (base.to_string(), digest.to_string())
        }
        _ => match split_tag(image) {
            Some((n, t)) => (n.to_string(), t.to_string()),
            None => (image.to_string(), DEFAULT_TAG.to_string()),
        },
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

/// Is `image` a syntactically valid OCI image reference (`[registry[:port]/]name[:tag][@digest]`)?
///
/// Used to tell a `COPY --from=<image>` apart from an unresolved build-stage name (or plain garbage):
/// the parser first checks for an earlier stage, and only falls back to "is this a real image ref?".
/// This mirrors the distribution-spec grammar closely enough to ACCEPT the everyday forms - `busybox`,
/// `nginx:alpine`, `ghcr.io/org/img:1.2`, `registry:5000/img@sha256:<hex>` - while REJECTING an
/// uppercase repo, a `..`/absolute path, whitespace, a stray `--flag`, or an empty string. It is pure
/// (no I/O), so it stays usable from the pure Dockerfile parser. Deliberately syntactic only - a
/// well-formed ref that doesn't exist still fails later, at pull time, with the registry's own error.
///
/// SSRF note: like `FROM`, an accepted ref names ANY registry host - including a numeric IP or
/// `localhost:<port>` - so a `FROM`/`COPY --from=<image>` in a Dockerfile triggers a build-time fetch
/// to whatever host the ref names. This is not a new capability (`FROM` already does it) and the
/// **Dockerfile author is the trust boundary** - they already choose the base images. The fetch itself
/// is HTTPS + TLS-pinned and runs the full pull hardening (sha256 blob verify, layer vetting), so a
/// plain-HTTP metadata endpoint (e.g. cloud IMDS `169.254.169.254`) fails the TLS handshake, not
/// silently exfiltrating. Kept syntactic on purpose: an allow/deny-list of registries is a
/// policy/config concern layered on top, not a job for the ref validator.
pub fn valid_reference(image: &str) -> bool {
    if image.is_empty() || image.len() > 255 {
        return false;
    }
    // Peel an optional `@<algo>:<hex>` digest off the end.
    let name_tag = match image.split_once('@') {
        Some((n, digest)) => {
            let Some((algo, hex)) = digest.split_once(':') else {
                return false;
            };
            if algo.is_empty()
                || hex.len() < 32
                || !algo.bytes().all(|b| b.is_ascii_alphanumeric())
                || !hex.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return false;
            }
            n
        }
        None => image,
    };
    // Split off an optional leading registry host: the first `/`-segment is a registry only if it looks
    // like a host (has a `.`/`:`, or is `localhost`) - matching `parse_ref`'s rule, so the two agree.
    let (registry, rest) = match name_tag.split_once('/') {
        Some((host, r)) if host.contains('.') || host.contains(':') || host == "localhost" => {
            (Some(host), r)
        }
        _ => (None, name_tag),
    };
    if let Some(host) = registry {
        if !valid_registry(host) {
            return false;
        }
    }
    // `rest` = `path[:tag]`. A `:` (host:port already peeled) after the last `/` introduces the tag.
    let (path, tag) = match rest.rsplit_once(':') {
        Some((p, t)) if !t.contains('/') => (p, Some(t)),
        _ => (rest, None),
    };
    if let Some(t) = tag {
        if !valid_tag(t) {
            return false;
        }
    }
    valid_repo_path(path)
}

/// A registry host: dot-separated labels (`[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?`) with an optional
/// `:<port>`. Accepts `localhost`, `ghcr.io`, `registry-1.docker.io`, `host:5000`.
fn valid_registry(host: &str) -> bool {
    let (h, port) = match host.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host, None),
    };
    if let Some(p) = port {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    if h.is_empty() {
        return false;
    }
    h.split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// An image tag: `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
fn valid_tag(tag: &str) -> bool {
    let b = tag.as_bytes();
    if b.is_empty() || b.len() > 128 {
        return false;
    }
    let head_ok = b[0].is_ascii_alphanumeric() || b[0] == b'_';
    head_ok
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-')
}

/// A repository path: one or more `/`-separated components, each a lowercase `[a-z0-9]` run with
/// interior `.`/`_`/`-` separators (no leading/trailing separator, no `..`). Rejects uppercase (OCI
/// repos are lowercase), a leading `/`, an empty component, and any `..` traversal.
fn valid_repo_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    path.split('/').all(valid_path_component)
}

/// One repository-path component: `[a-z0-9]+((\.|_|-)+[a-z0-9]+)*` - starts and ends alphanumeric
/// (lowercase), only `.`/`_`/`-` in between, and never a `..`.
fn valid_path_component(c: &str) -> bool {
    let b = c.as_bytes();
    if b.is_empty() {
        return false;
    }
    let is_alnum = |x: u8| x.is_ascii_lowercase() || x.is_ascii_digit();
    if !is_alnum(b[0]) || !is_alnum(b[b.len() - 1]) {
        return false;
    }
    if c.contains("..") {
        return false;
    }
    b.iter()
        .all(|&x| is_alnum(x) || x == b'.' || x == b'_' || x == b'-')
}

/// Explain a manifest that yielded no layers. A registry error body (`UNAUTHORIZED`/`denied`) or an
/// empty body (a bare `401`) almost always means a **private repo you're not logged into**, so point
/// at `kern login` rather than the opaque "no layers"; otherwise the tag is malformed or absent.
fn manifest_error(manifest: &str, registry: &str, repo: &str) -> OciError {
    let low = manifest.to_ascii_lowercase();

    // RATE LIMIT first, because it is the one a working setup hits and the one the old wording sent
    // people furthest from. Docker Hub answers an over-quota anonymous pull with HTTP 429 and
    // `{"errors":[{"code":"TOOMANYREQUESTS","message":"You have reached your unauthenticated pull rate
    // limit..."}]}`. That body contains none of the auth keywords below, so it fell through to "no
    // layers in manifest" and a hint about checking the image name - about an image whose name is
    // perfectly correct. Measured against Docker Hub on 2026-08-01 after a burst of pulls across six
    // machines. The registry's own `message` is quoted rather than paraphrased: it is the field the
    // distribution spec provides for exactly this, and it carries the current limit and its URL.
    if low.contains("toomanyrequests") || low.contains("rate limit") {
        let said = first_str(manifest, "message").unwrap_or_default();
        let said = if said.is_empty() {
            String::new()
        } else {
            format!(" - {said}")
        };
        return OciError::Registry(format!(
            "{registry} is rate-limiting this pull of '{repo}'{said}. Authenticate with \
             `kern login {registry}` (an authenticated pull has a much higher quota), or wait and \
             retry - the image name and tag are not the problem"
        ));
    }
    // The tag or the repository genuinely does not exist: the registry says which.
    if low.contains("manifest_unknown") || low.contains("name_unknown") {
        let said = first_str(manifest, "message").unwrap_or_default();
        return OciError::Registry(format!(
            "{registry} has no such manifest for '{repo}'{}",
            if said.is_empty() {
                String::new()
            } else {
                format!(" - {said}")
            }
        ));
    }
    let auth_ish = manifest.trim().is_empty()
        || low.contains("unauthorized")
        || low.contains("denied")
        || low.contains("authentication");
    if auth_ish {
        OciError::Registry(format!(
            "cannot access '{repo}' on {registry} - it may be private (run `kern login {registry}`) \
             or the tag may not exist"
        ))
    } else {
        OciError::Registry("no layers in manifest".into())
    }
}

/// A target platform for an image (`os/arch`), used to select a manifest from a multi-arch index and
/// to stamp the arch on push. kern models the two arches it runs on (amd64/arm64) and OS `linux`;
/// arm variants (v7/v8) are not selected (a documented limitation). One type so the host default, the
/// `--platform` override, and the push stamp can't drift into three different notions of "arch".
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Platform {
    pub os: String,
    pub arch: String,
}

impl Platform {
    /// This host's platform: `linux` + the compile-time arch (arm64 on aarch64, else amd64).
    pub fn host() -> Self {
        Platform {
            os: "linux".into(),
            arch: if cfg!(target_arch = "aarch64") {
                "arm64"
            } else {
                "amd64"
            }
            .into(),
        }
    }

    /// Parse a `--platform` string: `os/arch` or a bare `arch` (⇒ `linux/arch`). Arch aliases are
    /// normalised (`x86_64`/`x86-64`→`amd64`, `aarch64`/`arm64v8`→`arm64`). A 3-part `os/arch/variant`
    /// (e.g. `linux/arm/v7`) is rejected legibly - kern doesn't select variants. An unknown arch is
    /// allowed through (the registry error then lists the available arches); a non-`linux` OS is rejected.
    pub fn parse(s: &str) -> Result<Self, OciError> {
        let s = s.trim().to_ascii_lowercase();
        let parts: Vec<&str> = s.split('/').collect();
        let (os, arch) = match parts.as_slice() {
            [a] => ("linux", *a),
            [o, a] => (*o, *a),
            _ => {
                return Err(OciError::Ref(format!(
                    "platform '{s}': use os/arch (e.g. linux/arm64); variants (arm/v7) aren't supported"
                )))
            }
        };
        if os != "linux" {
            return Err(OciError::Ref(format!(
                "platform '{s}': only linux is supported"
            )));
        }
        let arch = match arch {
            "x86_64" | "x86-64" | "amd64" => "amd64",
            "aarch64" | "arm64" | "arm64v8" => "arm64",
            other => other,
        };
        Ok(Platform {
            os: os.into(),
            arch: arch.into(),
        })
    }

    /// Is this the host platform? (A host-equal `--platform` is a no-op - the normal native pull.)
    pub fn is_host(&self) -> bool {
        *self == Platform::host()
    }

    pub fn as_oci_arch(&self) -> &str {
        &self.arch
    }
}

/// Download a blob to `tmp`. curl runs with `--no-progress-meter` - its built-in bar is a mess for a
/// redirected CDN blob (it re-emits the `#=#=#O` connection meter on every hop), so kern prints its
/// own clean per-layer line instead (see `extract_layer`). `-S` still surfaces errors; `-L` follows
/// redirects (registries hand blobs off to a CDN) but `--proto-redir =https` (in `TLS_PIN`) keeps
/// every hop on TLS - a hostile registry can't redirect a blob to `http://`/`file://`. Bearer creds
/// go in a header; Basic creds go via `-K` STDIN (off-argv).
fn curl_download(url: &str, tmp: &str, auth: &Auth) -> Result<(), OciError> {
    let mut cmd = Command::new("curl");
    cmd.args(["--no-progress-meter", "-S", "-L"])
        .args(pin_for_url(url))
        .args([
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
    // a different I/O shape: stream to `-o tmp` and INHERIT stderr (only `-S` errors reach it now -
    // the progress meter is off) rather than capturing stdout - so it can't reuse that helper.
    let basic_cfg = auth.basic_config();
    if basic_cfg.is_some() {
        cmd.args(["-K", "-"]).stdin(Stdio::piped());
    }
    cmd.arg("--").arg(url).stderr(Stdio::inherit()); // curl's `-S` errors (if any) to the terminal
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

/// Pre-download the config blob + every layer blob in ONE `curl` process - `--next` between requests
/// makes curl reuse the SAME keep-alive connection, so the whole set pays ONE TLS handshake instead of
/// one per blob (the measured cold-pull bottleneck: each separate `curl` process re-handshakes to the
/// registry host). Best-effort and TRANSPORT-ONLY: each blob is written to the exact tmp path
/// `fetch_config` / `download_layer` use, so they find it and skip their own fetch; every blob is still
/// sha256-verified and every layer vetted + merged no-follow by the caller - byte-identical to the
/// per-blob path. Scoped to Bearer / anonymous auth (the public path - ~all of Docker Hub & GHCR): a
/// Basic-credential registry returns early, leaving the audited off-argv `-K` credential plumbing
/// untouched. On ANY curl failure every partial tmp is removed, so the caller's per-blob path re-runs.
fn download_blobs_oneconn(
    registry: &str,
    repo: &str,
    manifest: &str,
    layers: &[String],
    auth: &Auth,
    dest: &Path,
) {
    // Escape hatch (like KERN_NO_PREFETCH): opt out of the one-connection batch and let the per-blob
    // path run. For A/B measuring, or if a registry mishandles `--next` connection reuse.
    if kern_common::env_flag("KERN_NO_BLOB_BATCH") {
        return;
    }
    // Basic creds go off-argv via `-K` stdin; do NOT reshape that into a `--next` chain - fall back.
    let bearer = match auth {
        Auth::Basic { .. } => return,
        Auth::Bearer(t) => Some(format!("Authorization: Bearer {t}")),
        Auth::None => None,
    };
    // (url, tmp_path) for the config blob (if present) then each layer, in order - the exact tmp paths
    // `fetch_config` and `download_layer` expect.
    let mut blobs: Vec<(String, std::path::PathBuf)> = Vec::new();
    if let Some(d) = object_after(manifest, "config").and_then(|d| first_str(d, "digest")) {
        blobs.push((
            format!("{}/v2/{repo}/blobs/{d}", reg_base(registry)),
            dest.join(".kern-image-config.json"),
        ));
    }
    for (i, dig) in layers.iter().enumerate() {
        blobs.push((
            format!("{}/v2/{repo}/blobs/{dig}", reg_base(registry)),
            layer_tmp_path(dest, i, dig),
        ));
    }
    if blobs.len() < 2 {
        return; // 0–1 blobs: no second request to share a connection with - nothing to save.
    }
    // Build one `curl` command, a `--next`-separated segment per blob. curl RESETS per-request options
    // at `--next`, so the TLS pin + size cap + `-o` + Bearer header MUST be repeated on every segment
    // (dropping the pin on a later segment would silently weaken it - hence per-segment, identical to
    // `curl_download`'s single-blob options).
    let tmp_strs: Vec<String> = blobs
        .iter()
        .map(|(_, t)| t.to_string_lossy().into_owned())
        .collect();
    let mut args: Vec<&str> = Vec::new();
    for (i, (url, _)) in blobs.iter().enumerate() {
        if i > 0 {
            args.push("--next");
        }
        args.push("--no-progress-meter");
        args.push("-S");
        args.push("-L");
        args.extend_from_slice(pin_for_url(url));
        args.push("--max-redirs");
        args.push("10");
        args.push("--connect-timeout");
        args.push("10");
        args.push("--max-time");
        args.push("600");
        args.push("--max-filesize");
        args.push(MAX_LAYER_DOWNLOAD_BYTES);
        args.push("-o");
        args.push(tmp_strs[i].as_str());
        if let Some(h) = &bearer {
            args.push("-H");
            args.push(h.as_str());
        }
        // The URL goes POSITIONAL (no `--`): a leading `--` ends option parsing for the segment and
        // then swallows the following `--next` (breaking every later segment's `-o`, sending its body
        // to stdout). Safe without it - the URL always comes from `reg_base` (`https://…`, never `-`)
        // and `--proto =https` above rejects any non-https anyway.
        args.push(url.as_str());
    }
    if crate::net::curl(&args).is_err() {
        // Partial/failed batch: remove every tmp so the caller's per-blob path re-downloads cleanly -
        // a leftover partial would otherwise be picked up and (correctly) fail digest verification.
        for (_, t) in &blobs {
            let _ = std::fs::remove_file(t);
        }
    }
}

/// Drop every control character. The single definition of that rule in this crate: it is a security
/// property in two different places (a credential must not inject a curl directive, a registry's
/// error text must not inject a terminal escape), and two spellings of one rule is how one of them
/// silently stops matching the other.
fn without_control_chars(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Escape a value for curl's `-K` config double-quoted string: backslash-escape `\` and `"`, and
/// DROP control characters (`\n`/`\r`/…). A newline would otherwise close the `user = "…"` line and
/// let a crafted credential inject an arbitrary curl directive; control chars can't appear in a valid
/// HTTP Basic credential anyway. (`kern login` already reads a single line, so this is defence in
/// depth against a hand-edited credentials file.)
fn curl_cfg_escape(s: &str) -> String {
    without_control_chars(s)
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// How to authenticate requests to a registry, discovered from its `WWW-Authenticate` challenge.
/// `Clone` so a layer prefetch thread can carry its own copy (Bearer token / Basic creds are Strings).
#[derive(Clone)]
pub(crate) enum Auth {
    /// Open (or already-satisfied) - no `Authorization` header.
    None,
    /// A short-lived Bearer token from the registry's token endpoint (Docker Hub, GHCR, GitLab,
    /// Harbor, quay, …). Sent as a header (tokens are not the long-lived secret).
    Bearer(String),
    /// HTTP Basic - the `kern login` credentials, sent to curl **off-argv** via a `-K` STDIN config.
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
/// `WWW-Authenticate` challenge - so ANY compliant registry works (Docker Hub, GHCR, GitLab, Harbor,
/// quay, self-hosted `distribution`), not just Docker Hub. Pings `/v2/`: a `200` means no auth is
/// needed; a `401` carries the challenge. For a `Bearer` challenge we fetch a pull-scoped token from
/// the advertised realm (anonymously, or upgraded with `kern login` credentials for private repos);
/// for a `Basic` challenge we carry the credentials directly. Credentials always travel to curl via a
/// `-K` STDIN config, never argv, so another same-uid process can't read them from `/proc/<pid>/cmdline`.
fn discover_auth(registry: &str, repo: &str) -> Result<Auth, OciError> {
    discover_auth_scoped(registry, repo, "pull")
}

/// Like [`discover_auth`] but for an explicit `action` scope - `"pull"` for reads, `"push,pull"` for
/// an upload (`kern push`). Push needs a write-scoped token; everything else in the challenge dance
/// (realm/service parsing, credential-host trust, off-argv creds) is identical, so it's shared here.
pub(crate) fn discover_auth_scoped(
    registry: &str,
    repo: &str,
    action: &str,
) -> Result<Auth, OciError> {
    let headers = match crate::net::head_headers(&format!("{}/v2/", reg_base(registry))) {
        Ok(h) => h,
        // A registry that won't answer the ping (older/odd) - fall back to anonymous and let the
        // manifest fetch surface a clear error if auth turns out to be required.
        Err(_) => return Ok(Auth::None),
    };
    if http_status(&headers) != 401 {
        return Ok(Auth::None); // open registry, or already authorized
    }
    let creds = kern_common::registry_auth::lookup(registry);
    match parse_www_authenticate(&headers) {
        Some(Challenge::Bearer { realm, service }) => {
            // Ask the token endpoint for a token scoped to this repo + action. The realm/service come
            // from the (TLS-authenticated) challenge; the scope we request ourselves.
            let scope = format!("repository:{repo}:{action}");
            let sep = if realm.contains('?') { '&' } else { '?' };
            let url = format!("{realm}{sep}service={service}&scope={scope}");
            let mut base = vec!["-sSL"];
            base.extend_from_slice(reg_pin(registry));
            base.extend_from_slice(&[
                "--max-redirs",
                "5",
                "--max-filesize",
                "8000000", // a token response is tiny - cap it so a hostile realm can't OOM us
                "--connect-timeout",
                "10",
                "--max-time",
                "60",
                "--",
                url.as_str(),
            ]);
            // CREDENTIAL SAFETY (CVE-2020-15157 class): only send the stored credentials to the token
            // endpoint if its host belongs to the SAME registry (same host, or a subdomain of the
            // registry's parent domain - e.g. Docker Hub's registry-1.docker.io ↔ auth.docker.io). A
            // hostile/compromised registry could otherwise advertise `realm="https://evil/token"` and
            // harvest the creds the user stored for it. If the realm is foreign we withhold the creds
            // and fetch an ANONYMOUS token instead (fine for public repos; a private one then fails
            // with a clear 401), warning so it's never a silent behaviour change.
            let send_creds = creds
                .as_ref()
                .filter(|_| realm_host_trusted(&realm, registry));
            if creds.is_some() && send_creds.is_none() {
                eprintln!(
                    "kern: withholding credentials - {registry} pointed its auth to a different host \
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
                .ok_or_else(|| {
                    // A token endpoint that refuses answers with the registry's OWN diagnosis, and
                    // that is the only thing here worth reading. GHCR replies
                    // `{"errors":[{"code":"DENIED","message":"requested access to the resource is
                    // denied"}]}` when the account cannot write that namespace, and this used to be
                    // reported as "no auth token in token response" with a hint to run `kern login`,
                    // to a user who had just run `kern login` successfully. Measured on a real push
                    // to ghcr.io: the generic message sent the reader looking at the wrong thing.
                    // Carry the registry's message through, and keep the generic one only when the
                    // response has nothing to say.
                    //
                    // SCRUBBED: this text comes from a REMOTE server and is about to be printed to
                    // the operator's terminal. A hostile or compromised registry could answer with
                    // ANSI escapes and repaint the line, hide what it did, or move the cursor. kern
                    // already strips control characters from every other untrusted string it shows
                    // (registry search results, cached image refs); carrying a remote message
                    // through without the same filter would have opened that hole in the one place
                    // where the text is guaranteed to be attacker-influenced. Control characters
                    // include newline and tab, which is also what keeps a multi-line reply from
                    // breaking the single-line error format.
                    let why = first_str(&s, "message")
                        .or_else(|| first_str(&s, "details"))
                        .or_else(|| first_str(&s, "error_description"))
                        .or_else(|| first_str(&s, "error"))
                        .map(|m| without_control_chars(&m))
                        .filter(|m| !m.trim().is_empty());
                    match why {
                        Some(m) => OciError::Registry(format!(
                            "{registry} refused the token request: {m} (the credentials reached it, \
                             so this is about what that account may do with this name, not about \
                             logging in again)"
                        )),
                        None => OciError::Registry("no auth token in token response".into()),
                    }
                })?;
            Ok(Auth::Bearer(tok))
        }
        Some(Challenge::Basic) => {
            let (user, pass) = creds.ok_or_else(|| {
                OciError::Registry(format!(
                    "{registry} requires authentication - run `kern login {registry}`"
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
/// an unrelated host to harvest creds - the CVE-2020-15157 credential-leak class). The realm must be
/// `https://`. Both hosts are parsed the SAME way curl resolves them (userinfo + port stripped, see
/// [`host_from_authority`]) - a parser differential here would itself be an allowlist bypass.
fn realm_host_trusted(realm: &str, registry: &str) -> bool {
    let reg_host = host_from_authority(registry.split('/').next().unwrap_or(registry));
    let Some(after) = realm.strip_prefix("https://") else {
        return false; // non-TLS realm → never trust creds to it
    };
    let realm_host = host_from_authority(after.split(['/', '?', '#']).next().unwrap_or(after));
    if realm_host.is_empty() {
        return false;
    }
    // EXACT host match is always trusted.
    if realm_host == reg_host {
        return true;
    }
    // Otherwise, trust ONLY a known, hardcoded registry↔auth mapping. The old rule trusted ANY sibling
    // under the registry's parent domain (`realm_host.ends_with(".{parent}")`) - but on shared PaaS /
    // hosting / a delegated-subdomain org, an attacker who controls a sibling subdomain (say
    // `attacker.acme.com`) could make a hostile `registry.acme.com` point its auth realm there and
    // harvest the user's long-lived, WRITE-scoped `kern login` password. Credentials must never go to a
    // host the user didn't log into unless it's a real, known auth endpoint. (Hacker-mode audit.)
    known_auth_pair(&reg_host, &realm_host)
}

/// The hardcoded registry-host ↔ auth-realm-host pairs kern trusts for sending stored credentials to a
/// DIFFERENT host than the one the user logged into. Only well-known public registries whose auth lives
/// on a sibling host belong here - never a generic parent-domain rule (which a hostile sibling abuses).
fn known_auth_pair(reg_host: &str, realm_host: &str) -> bool {
    const PAIRS: &[(&str, &str)] = &[
        // Docker Hub: the registry is registry-1.docker.io, its token realm is auth.docker.io.
        ("registry-1.docker.io", "auth.docker.io"),
        ("docker.io", "auth.docker.io"),
        ("index.docker.io", "auth.docker.io"),
    ];
    PAIRS
        .iter()
        .any(|(r, a)| *r == reg_host && *a == realm_host)
}

/// The host of a URL authority as curl would dial it: drop any `userinfo@` (curl uses the part after
/// the LAST `@` as the host - a `realm="https://trusted:0@evil.com/…"` connects to `evil.com`, NOT
/// `trusted`) and any `:port`, lowercased (DNS is case-insensitive). Parsing the host the same way
/// curl resolves it is what keeps [`realm_host_trusted`] sound.
fn host_from_authority(authority: &str) -> String {
    let host = authority.rsplit('@').next().unwrap_or(authority);
    host.split(':').next().unwrap_or(host).to_ascii_lowercase()
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
    let url = format!("{}/v2/{repo}/manifests/{reference}", reg_base(registry));
    let accept = "Accept: application/vnd.oci.image.index.v1+json,\
        application/vnd.oci.image.manifest.v1+json,\
        application/vnd.docker.distribution.manifest.list.v2+json,\
        application/vnd.docker.distribution.manifest.v2+json";
    let mut args = vec!["-sSL"];
    args.extend_from_slice(reg_pin(registry));
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

/// First 12 hex of a `sha256:HEX` digest for progress lines (or the digest verbatim if not sha256).
fn short_digest(digest: &str) -> &str {
    digest
        .strip_prefix("sha256:")
        .map(|h| &h[..h.len().min(12)])
        .unwrap_or(digest)
}

/// Download ONE layer blob to a tmp file, returning its path. The download command is IDENTICAL to the
/// old inline one (same TLS pin, auth, redirects, timeouts) - split out only so the pull loop can
/// PREFETCH the next layer concurrently. No security logic lives here (verify/vet/extract/merge do).
fn download_layer(
    idx: usize,
    registry: &str,
    repo: &str,
    digest: &str,
    auth: &Auth,
    dest: &Path,
) -> Result<std::path::PathBuf, OciError> {
    let short = short_digest(digest);
    eprintln!("→ layer  {short}  downloading…");
    let url = format!("{}/v2/{repo}/blobs/{digest}", reg_base(registry));
    let tmp = layer_tmp_path(dest, idx, digest);
    let tmp_s = tmp.to_string_lossy().into_owned();
    // Already fetched by the one-connection batch pre-download? Use it (it wrote this exact path). The
    // blob is still sha256-verified + vetted by `process_layer` afterwards, so a bad batch download is
    // caught there exactly as a bad per-blob download would be.
    if !tmp.exists() {
        if let Err(e) = curl_download(&url, &tmp_s, auth) {
            // curl `-o` may have written a partial blob before failing - never leave it inside `dest`
            // (which can be the user's rootfs dir): a junk `.kern-layer-*` would end up visible at `/`
            // in every box booted from that rootfs.
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    Ok(tmp)
}

/// The tmp blob path for layer `idx` - per-INDEX (not per-digest): adjacent layers may legally
/// share a digest, and prefetch runs two downloads at once - a digest-only name would make them
/// collide on one file. One definition, so the download and the error-path cleanup can't drift.
fn layer_tmp_path(dest: &Path, idx: usize, digest: &str) -> std::path::PathBuf {
    dest.join(format!(
        ".kern-layer-{idx}-{}.tar.gz",
        digest.replace([':', '/'], "_")
    ))
}

/// Verify + vet + extract + merge ONE already-downloaded layer, strictly IN ORDER (never concurrent:
/// overlay whiteout semantics require sequential merge). Every security gate is here, unchanged from the
/// old `extract_layer`; only the download moved out (see `download_layer`). `tmp` is the downloaded blob.
fn process_layer(
    tmp: &Path,
    digest: &str,
    dest: &Path,
    idx: usize,
    total: usize,
) -> Result<(), OciError> {
    let short = short_digest(digest);

    // INTEGRITY: the blob's content must hash to its digest - defends against a compromised or
    // MITM'd registry (TLS only protects the transport), and against a corrupt download. Report the
    // downloaded size on the same line so a big multi-hundred-MB image shows real progress per layer
    // (curl's own meter is off - it's noise over a redirected CDN blob).
    let size = std::fs::metadata(tmp).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "  layer {idx}/{total}  {short}  {}  verifying + extracting…",
        kern_common::fmt_bytes(size)
    );
    if let Err(e) = verify_digest(tmp, digest) {
        let _ = std::fs::remove_file(tmp);
        return Err(e);
    }

    // Detect the codec from the verified bytes (gzip / zstd / uncompressed) ONCE, and reuse it for
    // both the vet and the extract so they can never disagree.
    let comp = detect_compression(tmp);

    // HARDENING: strip any device member into a FRESH PLAIN tar and RE-VET that with the unchanged
    // vetter - the security gate. Rejects path traversal, absolute members, oversized (bomb) layers, and
    // any device the strip missed (fail-closed: the re-vet still refuses `3`/`4`). A legitimate image
    // that ships an inert device node (amazonlinux's base layer) now pulls; the box's own fresh `/dev`
    // and dropped CAP_MKNOD keep the image's device PATHS inert regardless. Because the filtered layer is
    // a plain tar, the extraction below collapses to a single `tar -xf` - no codec branch, no zstd pipe.
    let filtered = match filter_layer(tmp, comp) {
        Ok(p) => p,
        Err(e) => {
            let _ = std::fs::remove_file(tmp);
            return Err(e);
        }
    };
    let _ = std::fs::remove_file(tmp); // the original compressed blob is consumed by the filter
    let filtered_s = filtered.to_string_lossy().into_owned();

    // ISOLATED STAGING: extract this layer into a FRESH empty sibling dir, never directly into
    // `dest`. Then merge it into `dest` ourselves with no-follow semantics (see `merge_layer`),
    // so a symlink planted by a previous layer cannot be traversed by this layer's writes - the
    // cross-layer symlink-escape class is closed structurally, not by trusting tar.
    //
    // The extract + merge + cleanup below touch the image's REAL modes (a 0555 dir, a setuid file), so
    // run them with the capability to override permissions - directly as root, or inside a forked
    // single-uid userns for a non-root user (see `unpack_as_root`). verify + vet above stayed in the
    // parent (they need no privilege and produce detailed errors). Plain `tar` here (no `unshare -r`
    // wrapper): we're already in-ns root when non-root, so it has the caps.
    let unpack = unpack_as_root(move || {
        let staging = dest.with_file_name(format!(".kern-stg-{}", digest.replace([':', '/'], "_")));
        // NOT best-effort. This clears a leftover staging from an interrupted earlier run BEFORE
        // extracting into it, and `create_dir_all` below succeeds whether or not the directory was
        // emptied - so a swallowed failure here would extract on top of content this run never
        // produced and merge the union as if it were the layer. Refuse instead: a staging we could not
        // clear is not a staging we can vouch for.
        remove_tree_no_follow(&staging).map_err(|e| {
            OciError::Extract(format!(
                "cannot clear the layer staging dir {}: {e}",
                staging.display()
            ))
        })?;
        std::fs::create_dir_all(&staging).map_err(|e| OciError::Extract(e.to_string()))?;
        let staging_s = staging.to_string_lossy().into_owned();
        // `--same-permissions`: preserve the image's EXACT modes, including the sticky bit and world-write
        // on `/tmp` (1777) that many images rely on - without it, tar as a non-root user applies the umask
        // (022) and drops world-write + sticky, so a workload that drops to a non-root uid can't write
        // `/tmp` (e.g. mariadb InnoDB temp files fail EACCES). Docker/podman extract with `-p` for the same
        // reason. `--no-same-owner` still maps ownership to the extracting user (we don't want the image's
        // raw uids on the host). `filter_layer` above already DROPPED every device node and STRIPPED the
        // setuid/setgid bit off every file (see `clear_suid_sgid`), so the modes tar restores here are only
        // the benign set - and a setuid bit would be doubly inert regardless (the box root mount is
        // MS_NOSUID and rootless extraction owns every file as the caller, never root).
        // Extract with the codec detected above. gzip → tar's own `-z`; plain → no decompressor (`-xf`);
        // zstd → pipe `zstd -dc` into `tar -xf -` rather than relying on `tar --zstd`, which BusyBox/musl
        // edge builds often lack even when a standalone `zstd` is present. `--no-same-owner`
        // `--same-permissions` are preserved on every path (see the mode-preservation note above).
        let extract_err = |e: OciError| -> OciError {
            discard_staging(&staging);
            e
        };
        // The filtered layer is a PLAIN tar with device members stripped, so extraction collapses to a
        // single `tar -xf` - no codec branch, no zstd pipe. `--same-permissions` preserves the image's
        // exact modes (sticky bit + world-write on `/tmp`); `--no-same-owner` maps ownership to the
        // extracting user (never the image's raw uids). `filter_layer` already re-vetted these bytes, and
        // tar consumes exactly them, so tar never sees a device node.
        let ok = Command::new("tar")
            .args([
                "-xf",
                &filtered_s,
                "-C",
                &staging_s,
                "--no-same-owner",
                "--same-permissions",
            ])
            .status()
            .map_err(|e| OciError::Tool("tar", e.to_string()))
            .map(|s| s.success());
        let succeeded = match ok {
            Ok(s) => s,
            Err(e) => return Err(extract_err(e)),
        };
        if !succeeded {
            discard_staging(&staging);
            return Err(OciError::Extract("layer extraction failed".into()));
        }
        let merged = merge_layer(&staging, dest);
        discard_staging(&staging);
        merged
    });
    let _ = std::fs::remove_file(&filtered); // remove the filtered plain tar (extraction consumed it)
    unpack
}

/// Verify `file` hashes to `digest` (`sha256:HEX`). Uses `sha256sum` (coreutils). An unknown
/// algorithm is skipped (not failed); a mismatch is a hard error.
fn verify_digest(file: &Path, digest: &str) -> Result<(), OciError> {
    let Some(expected) = digest.strip_prefix("sha256:") else {
        // Refuse any digest we can't verify - a non-sha256 algorithm must not be a free pass for
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
            "blob digest mismatch (expected {expected}, got {got}) - refusing"
        )));
    }
    Ok(())
}

/// Verify in-memory bytes (a manifest) against a `sha256:<hex>` digest, mirroring [`verify_digest`]
/// but WITHOUT a temp file - a manifest is already in memory and small. Refuses a non-sha256 algorithm
/// (no free pass for an unverified algorithm). sha256sum reads the bytes on stdin and emits its hash
/// only after EOF, so a blocking `write_all` of a small manifest cannot deadlock on the stdout pipe.
fn verify_digest_bytes(bytes: &[u8], digest: &str) -> Result<(), OciError> {
    let Some(expected) = digest.strip_prefix("sha256:") else {
        return Err(OciError::Registry(format!(
            "unsupported digest algorithm (only sha256 is verified): {digest}"
        )));
    };
    use std::io::Write;
    let mut child = Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| OciError::Tool("sha256sum", e.to_string()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| OciError::Tool("sha256sum", "no stdin".into()))?
        .write_all(bytes)
        .map_err(|e| OciError::Tool("sha256sum", e.to_string()))?;
    let out = child
        .wait_with_output()
        .map_err(|e| OciError::Tool("sha256sum", e.to_string()))?;
    if !out.status.success() {
        return Err(OciError::Tool("sha256sum", "hashing failed".into()));
    }
    let got = String::from_utf8_lossy(&out.stdout);
    let got = got.split_whitespace().next().unwrap_or("");
    if !got.eq_ignore_ascii_case(expected) {
        return Err(OciError::Registry(format!(
            "manifest digest mismatch (expected {expected}, got {got}) - refusing"
        )));
    }
    Ok(())
}

/// A tar member path that would escape the rootfs: absolute, `..`-traversing, or NUL-bearing.
pub(crate) fn unsafe_member_path(p: &str) -> bool {
    p.starts_with('/') || p.split('/').any(|c| c == "..") || p.contains('\0')
}

/// Canonicalize a (relative, already `..`-free) member path the way a tar extractor lays it on disk:
/// drop `.` and empty components (leading `./`, `//`, `/./`, trailing `/`). The symlink-escape tracking
/// keys on this, so a member spelled `./A/x` / `A//x` / `A/./x` can't slip past a symlink recorded as
/// `A` - the vetter's string view has to equal the filesystem's, or the textual prefix check is fooled.
pub(crate) fn normalize_member_path(p: &str) -> String {
    p.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// Is `p` AT, or UNDER, a recorded escaping symlink? True iff `p` itself or one of its ancestor
/// directories is a path in `set`. Walks `p`'s prefixes from the root down - O(path depth) HashSet
/// lookups, so vetting stays linear in the number of members even at the 2M-entry cap. Used for BOTH
/// the per-member escape check and the chain resolution (a symlink whose target lands here escapes).
pub(crate) fn under_escaping(p: &str, set: &std::collections::HashSet<String>) -> bool {
    if set.is_empty() {
        return false;
    }
    let mut prefix = String::new();
    for comp in p.split('/') {
        if prefix.is_empty() {
            prefix.push_str(comp);
        } else {
            prefix.push('/');
            prefix.push_str(comp);
        }
        if set.contains(&prefix) {
            return true;
        }
    }
    false
}

/// Max uncompressed bytes per layer - a decompression-bomb ceiling (2 GiB).
pub(crate) const MAX_LAYER_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Max entries per layer - a dir/empty-file *inode* bomb has ~0 byte total but still exhausts the fs.
const MAX_LAYER_ENTRIES: u64 = 2_000_000;
/// Max COMPRESSED bytes for a single layer download (curl `--max-filesize`), as a string for the argv.
/// Bounds a disk-fill DoS from a hostile registry; generous enough for any realistic layer (8 GB).
const MAX_LAYER_DOWNLOAD_BYTES: &str = "8000000000";

/// The TLS-pinning flags EVERY registry fetch must carry: HTTPS-only on the initial request AND on
/// every redirect hop (registries hand blobs to a CDN), with a bounded redirect count. Single-sourced
/// so a copy can't silently drop `--proto-redir =https` and let a hostile registry downgrade a hop to
/// `http://` or `file://`. (`--max-redirs` stays per-call - the count legitimately differs.)
pub(crate) const TLS_PIN: &[&str] = &["--proto", "=https", "--proto-redir", "=https"];

/// Is `registry` a loopback host (`localhost` / `127.x.y.z` / `[::1]`)? Loopback registries speak plain
/// HTTP (the local-dev / `registry:2` case) and are insecure-OK by default, like Docker - there's no
/// MITM to pin against over the loopback interface. Single source of truth, shared by pull AND push so
/// the two can't drift on which registries are treated as insecure.
///
/// SECURITY: the match must be EXACT, never a prefix. A naive `starts_with("127.")` would treat
/// `127.0.0.1.evil.com` (a real public domain an attacker controls) as loopback → HTTP + no TLS pin on
/// a REAL push/pull = MITM / credential leak. So a `127.` host is loopback only if it's a valid dotted
/// IPv4 in 127/8 (four numeric octets), and `localhost`/`::1` are exact-string matches.
pub(crate) fn is_loopback_registry(registry: &str) -> bool {
    // `localhost` is a NAME, not an IP - exact match, never a prefix (`localhost.evil.com` is NOT
    // loopback). NOTE (documented residual, per review): this trusts that `localhost` resolves to
    // loopback - the default, but not guaranteed if `/etc/hosts` is tampered. The decision is on the
    // STRING, never on DNS resolution: we never treat "an arbitrary host that resolves to 127.0.0.1"
    // as a reason for http (which would let `attacker.com`→127.0.0.1 bypass pinning).
    if registry == "localhost" || registry.starts_with("localhost:") {
        return true;
    }
    // A bare IPv6 loopback (`::1`, no port) - matched before the `:`-split, since it's all colons.
    if registry == "::1" {
        return true;
    }
    // Everything else: parse the HOST as a canonical IP and ask the stdlib. `IpAddr::is_loopback()` is
    // the DEFINITION of loopback (all of 127.0.0.0/8 and ::1). This closes the whole "form I forgot"
    // class BY CONSTRUCTION instead of enumerating: `127.0.0.1.evil.com` (not an IP → parse fails),
    // `127.999.0.1` / `127.0x1.0.1` (invalid octet → parse fails), `::ffff:127.0.0.1` (an IPv4-mapped
    // address whose `is_loopback()` is false) - ALL fall to NOT-loopback → https + TLS pin. A real
    // domain also fails to parse → pinned. Fail-closed in the safe direction for every non-IP host.
    let host = if let Some(rest) = registry.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest) // `[::1]` / `[::1]:port`
    } else {
        registry.split(':').next().unwrap_or(registry) // IPv4 host before `:port`
    };
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// `<scheme>://<registry>` - `http` for a loopback registry, `https` otherwise.
pub(crate) fn reg_base(registry: &str) -> String {
    let scheme = if is_loopback_registry(registry) {
        "http"
    } else {
        "https"
    };
    format!("{scheme}://{registry}")
}

/// The HTTPS-pin curl args for `registry` - `TLS_PIN` for a real registry, empty for loopback HTTP.
pub(crate) fn reg_pin(registry: &str) -> &'static [&'static str] {
    if is_loopback_registry(registry) {
        &[]
    } else {
        TLS_PIN
    }
}

/// The HTTPS-pin curl args for a URL, by its scheme: an `http://` URL (only ever produced by
/// `reg_base` for a loopback registry) needs no pin; anything else is pinned. Deriving from the URL
/// keeps `download_blob_quiet`/`curl_download` (which take a URL, not a registry) consistent with the
/// scheme `reg_base` already chose.
pub(crate) fn pin_for_url(url: &str) -> &'static [&'static str] {
    if url.starts_with("http://") {
        &[]
    } else {
        TLS_PIN
    }
}

/// One-time probe: can this host create a `unshare -r`-style single-uid user namespace? Mirrors the
/// old tar-probe style. Used to decide whether a NON-root unpack can gain CAP_DAC_OVERRIDE.
fn userns_ok() -> bool {
    use std::sync::OnceLock;
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        Command::new("unshare")
            .args(["-r", "true"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Run the mode-sensitive part of a layer unpack (extract + merge + cleanup) with the capability to
/// override file/dir permissions. ROOT (any OS, incl. WSL's default root) already has it → runs `f`
/// DIRECTLY, byte-identical to before (no fork, no userns). A NON-root user forks a child that maps
/// its uid to in-ns root (a single-uid user namespace - the same primitive as `unshare -r`), then
/// runs `f` there: with CAP_DAC_OVERRIDE/DAC_READ_SEARCH the extractor and merger never EACCES on an
/// image's restrictive dir/file modes (fedora's 0555 `etc/pki/...` dirs, a setuid `/usr/bin/sudo`) -
/// the exact failures a plain non-root unpack hit on edge boards. Falls back to a direct best-effort
/// run where userns is unavailable (no worse than before there).
///
/// FORK SAFETY (not by timing - by construction): forking a MULTI-threaded process is a deadlock
/// hazard (the child inherits a possibly-locked allocator). We fork ONLY on the non-root path, and the
/// caller (`pull`) DISABLES the layer-prefetch thread whenever non-root - so the process is provably
/// SINGLE-THREADED at every `fork()` here and the child can't inherit a held lock. Root keeps prefetch
/// but never forks. The child reports failure via a non-zero exit (its specific error already went to
/// the inherited stderr); the single-uid mapping means its in-ns root can only override perms on the
/// USER'S OWN files (a root-owned host file appears as the unmapped overflow uid → DAC still blocks
/// it), so the unpack gains no power over anything outside the user's own image cache.
pub(crate) fn unpack_as_root<F: FnOnce() -> Result<(), OciError>>(f: F) -> Result<(), OciError> {
    let is_root = unsafe { libc::geteuid() == 0 };
    if is_root || !userns_ok() {
        return f();
    }
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    // Flush our own buffered output so the forked child doesn't duplicate it on exit.
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return f(); // fork failed → best-effort direct run
    }
    if pid == 0 {
        // CHILD: enter a single-uid userns (real uid → in-ns 0) BEFORE any privileged fs op. `setgroups`
        // must be denied before writing gid_map in an unprivileged userns.
        let entered = unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0
            && std::fs::write("/proc/self/setgroups", "deny").is_ok()
            && std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).is_ok()
            && std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).is_ok();
        let code = if !entered {
            eprintln!("kern: could not enter a user namespace to unpack the layer");
            1
        } else {
            match f() {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("kern: {e}");
                    1
                }
            }
        };
        unsafe { libc::_exit(code) };
    }
    // PARENT: wait for the unpack child.
    let mut status = 0i32;
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        if unsafe { *libc::__errno_location() } != libc::EINTR {
            return Err(OciError::Extract(
                "waiting for the layer-unpack child failed".into(),
            ));
        }
    }
    let ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    ok.then_some(())
        .ok_or_else(|| OciError::Extract("layer extraction failed".into()))
}

/// How a layer blob is compressed. Detected from the blob's leading magic bytes (never from the
/// manifest's declared media type, which can lie or be omitted), so the codec is decided by the
/// actual, already-sha256-verified bytes. `Plain` is an uncompressed tar (`…tar`, no `+gzip`/`+zstd`)
/// - accepting it also fixes a latent gap where uncompressed OCI layers failed the gzip-only path.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compression {
    Gzip,
    Zstd,
    Plain,
}

/// Sniff a (verified, on-disk) layer blob's compression from its first bytes: gzip = `1f 8b`, zstd =
/// `28 b5 2f fd`, anything else = an uncompressed tar. Reads at most 4 bytes; a short/empty read is
/// treated as `Plain` (tar then errors cleanly). Called only AFTER `verify_digest`, so the content is
/// authentic - sniffing adds no attack surface.
pub(crate) fn detect_compression(path: &Path) -> Compression {
    use std::io::Read;
    let mut buf = [0u8; 4];
    let n = std::fs::File::open(path)
        .and_then(|mut f| f.read(&mut buf))
        .unwrap_or(0);
    match &buf[..n] {
        [0x1f, 0x8b, ..] => Compression::Gzip,
        [0x28, 0xb5, 0x2f, 0xfd] => Compression::Zstd,
        _ => Compression::Plain,
    }
}

/// Is a `zstd` decompressor available? Probed once. Used to give a specific
/// "install zstd" error BEFORE spawning, rather than a cryptic spawn failure, when a zstd-compressed
/// image is pulled on a host without it (common on BusyBox/musl edge boards).
fn zstd_available() -> bool {
    use std::sync::OnceLock;
    static Z: OnceLock<bool> = OnceLock::new();
    *Z.get_or_init(|| {
        Command::new("zstd")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// The specific, actionable error when a zstd layer is pulled without `zstd` installed.
fn zstd_missing() -> OciError {
    OciError::Tool(
        "zstd",
        "this image uses zstd-compressed layers but `zstd` is not installed".into(),
    )
}

/// Vet a downloaded layer tarball before extraction by reading its RAW tar headers in-process
/// (`gzip -dc` does ONLY the decompression). We deliberately do NOT parse `tar -tv`'s human-readable
/// text: it is locale-dependent and can be desynced by a member name that contains the ` -> ` /
/// ` link to ` delimiter, hiding an escaping link target - a real BusyBox-tar escape. Header fields
/// (name / prefix / linkname / typeflag) live at FIXED offsets, so this decision is sound on GNU and
/// BusyBox alike. Rejects: absolute / `..` paths, an escaping hardlink target (always) or symlink
/// target (on non-GNU tar), device/special nodes, a total uncompressed size over the 2 GiB bomb cap,
/// and an entry count over the inode cap. (Cross-layer symlink escapes are additionally handled
/// structurally by isolated staging + no-follow merge in [`merge_layer`].)
pub(crate) fn check_layer_safe(tar_path: &Path, comp: Compression) -> Result<(), OciError> {
    let path = tar_path.to_string_lossy();
    // Plain (uncompressed) tar: vet the file directly, no decompressor process.
    if comp == Compression::Plain {
        let mut f = std::fs::File::open(tar_path).map_err(|e| OciError::Extract(e.to_string()))?;
        return vet_tar_stream(&mut f);
    }
    // gzip / zstd: the decompressor does ONLY the decompression; `vet_tar_stream` (the fuzzed core)
    // reads the DECOMPRESSED stream and is codec-agnostic - so the entire hardening surface (bomb
    // caps, symlink/whiteout/device guards) is identical regardless of codec.
    let (bin, args) = match comp {
        Compression::Gzip => ("gzip", ["-dc", &path]),
        Compression::Zstd => {
            if !zstd_available() {
                return Err(zstd_missing());
            }
            ("zstd", ["-dc", &path])
        }
        // An uncompressed layer has no decompressor to spawn, and every caller reads it directly
        // instead of coming here. That makes this arm unreachable TODAY, which is exactly why it
        // must not be `unreachable!()`: the guarantee lives in the callers, so a later one that
        // forgets would turn a routing mistake into a panic in the middle of a pull. Refusing is
        // the same fail-closed answer the vetter gives everywhere else.
        Compression::Plain => return Err(OciError::Tool(
            "kern",
            "internal: a plain (uncompressed) layer was routed through the decompressing vetter"
                .into(),
        )),
    };
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            if bin == "zstd" {
                zstd_missing()
            } else {
                OciError::Tool("gzip", e.to_string())
            }
        })?;
    // `.stdout(Stdio::piped())` was set on the spawn above, so this is `Some` by construction; say so
    // with an error rather than an abort, since this runs while decompressing an untrusted layer.
    let Some(mut stdout) = child.stdout.take() else {
        return Err(OciError::Tool(
            bin,
            "child stdout was not piped".to_string(),
        ));
    };
    let res = vet_tar_stream(&mut stdout);
    // We stop reading at the end-of-archive marker (or on rejection), so the decompressor may take a
    // SIGPIPE - its exit status isn't meaningful here. Truncation/corruption is caught inside
    // `vet_tar_stream` (a short read before the end-of-archive marker is an error), so a cut-off unsafe
    // member can't slip.
    let _ = child.kill();
    let _ = child.wait();
    res
}

const TAR_BLOCK: usize = 512;
/// Cap on a GNU long-name / long-link / PAX record set - a real one is a few KB; refuse the absurd.
const TAR_MAX_LONG: u64 = 1 << 20;

/// Read up to `buf.len()` bytes (retrying on EINTR). Returns the count: `0` = clean EOF, `< len` = a
/// short final read.
fn read_block(r: &mut impl std::io::Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// A NUL-terminated tar header string field → an owned (lossy) String.
fn tar_field(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// A tar numeric field: octal (space/NUL-terminated), or GNU base-256 (high bit of the first byte).
/// Base-256 magnitude is accumulated in `u128` and rejected (returns `None`) if it doesn't fit in a
/// `u64` - `checked_shl(8)` on a `u64` only fails when the shift is ≥ 64, so it would SILENTLY WRAP a
/// large value, desyncing our byte-skip from what tar extracts. (A field this large exceeds our layer
/// caps anyway; refusing it is fail-closed.)
fn tar_num(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|&b| b & 0x80 != 0) {
        let mut v: u128 = (field[0] & 0x7f) as u128;
        for &b in &field[1..] {
            v = (v << 8) | (b as u128);
            if v > u64::MAX as u128 {
                return None;
            }
        }
        return Some(v as u64);
    }
    let s: String = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .map(|&b| b as char)
        .collect();
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}

/// Consume `len` bytes of member data plus its zero-padding to the next 512-block boundary, keeping
/// (returning) at most the first `keep` real bytes. Bounded memory regardless of `len`.
fn take_data(r: &mut impl std::io::Read, len: u64, keep: usize) -> Result<Vec<u8>, OciError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut left = len.div_ceil(TAR_BLOCK as u64) * TAR_BLOCK as u64;
    let mut real = len;
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n =
            read_block(r, &mut buf[..want]).map_err(|e| OciError::Tool("gzip", e.to_string()))?;
        if n == 0 {
            return Err(OciError::Extract("truncated layer data".into()));
        }
        let real_here = (n as u64).min(real) as usize; // real bytes precede any padding in this chunk
        if out.len() < keep {
            let room = keep - out.len();
            out.extend_from_slice(&buf[..real_here.min(room)]);
        }
        real = real.saturating_sub(n as u64);
        left -= n as u64;
    }
    Ok(out)
}

/// Copy `ceil(size/512)*512` bytes (a member's data + tar padding) VERBATIM from `r` to `w`, streamed
/// in 8 KiB chunks (never buffering a whole large file). Used by [`strip_device_members`] to re-emit an
/// accepted member's body byte-for-byte, so the extractor receives exactly what was read. A short read
/// before the expected end is a truncated layer (fail-closed).
fn pipe_data(
    r: &mut impl std::io::Read,
    size: u64,
    w: &mut impl std::io::Write,
) -> Result<(), OciError> {
    let mut buf = [0u8; 8192];
    let mut left = size.div_ceil(TAR_BLOCK as u64) * TAR_BLOCK as u64;
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n =
            read_block(r, &mut buf[..want]).map_err(|e| OciError::Tool("gzip", e.to_string()))?;
        if n == 0 {
            return Err(OciError::Extract("truncated layer data".into()));
        }
        w.write_all(&buf[..n])
            .map_err(|e| OciError::Extract(format!("write filtered layer: {e}")))?;
        left -= n as u64;
    }
    Ok(())
}

/// Read exactly `ceil(size/512)*512` bytes (a small GNU-`L`/`K` or PAX `x`/`g` record's data + padding)
/// into an owned buffer. `size` is `TAR_MAX_LONG`-capped by the caller, so the allocation is bounded.
/// [`strip_device_members`] buffers these raw bytes so an accepted member's preceding long-name/PAX
/// record is re-emitted verbatim before it. A short read is a truncated record (fail-closed).
fn read_raw_blocks(r: &mut impl std::io::Read, size: u64) -> Result<Vec<u8>, OciError> {
    let padded = (size.div_ceil(TAR_BLOCK as u64) * TAR_BLOCK as u64) as usize;
    let mut out = vec![0u8; padded];
    let mut off = 0;
    while off < padded {
        let n =
            read_block(r, &mut out[off..]).map_err(|e| OciError::Tool("gzip", e.to_string()))?;
        if n == 0 {
            return Err(OciError::Extract("truncated tar meta record".into()));
        }
        off += n;
    }
    Ok(out)
}

/// Clear the setuid/setgid bits (`0o6000`) from a regular-file tar header IN PLACE, recomputing the
/// header checksum so `tar` still accepts the block. A setuid/setgid bit on an image file is a
/// privilege lever ONLY if the file is later executed where its owner is privileged; in kern it is not:
/// the box root mount is `MS_NOSUID` (see `real.rs`) and rootless extraction owns every file as the
/// unprivileged caller (`--no-same-owner`), so the bit is already inert on both paths. Stripping it at
/// the source makes the on-disk rootfs safe-by-construction even OUTSIDE those two defenses - a `--dest`
/// tree bind-mounted elsewhere, or a `pull` run as real root and then executed on the host. This mirrors
/// the device drop and FIFO refusal in this same pass: an image artifact a sandbox never needs is
/// neutralised here, not trusted to a downstream mount flag. A header whose mode field does not parse as
/// a plain octal number is left byte-identical (nothing to strip we can reason about); the sticky bit
/// (`0o1000`, world-writable `/tmp`) is preserved - only `0o6000` is cleared.
fn clear_suid_sgid(header: &mut [u8; TAR_BLOCK]) {
    // A base-256 (high-bit) mode field is not something any writer emits for a 12-bit permission word;
    // treat it as "don't touch" rather than reason about it. `tar_num` also accepts base-256, so gate on
    // the raw first byte to be certain we only rewrite a plain octal field.
    if header[100] & 0x80 != 0 {
        return;
    }
    let Some(mode) = tar_num(&header[100..108]) else {
        return;
    };
    if mode & 0o6000 == 0 {
        return; // no setuid/setgid bit - leave the block byte-identical (no checksum churn)
    }
    let stripped = mode & !0o6000;
    // Canonical numeric field: 7 octal digits + NUL (what GNU tar writes and every mainstream reader
    // accepts). `stripped` is <= 0o7777, so it always fits in 7 digits.
    let m = format!("{stripped:07o}");
    header[100..107].copy_from_slice(m.as_bytes());
    header[107] = 0;
    // Recompute the checksum: the chksum field (148..156) counts as 8 spaces while summing, then holds
    // `<6 octal digits>\0<space>`. Every other byte is unchanged, so re-summing the whole block is both
    // correct and self-contained. The sum of 512 bytes (<= 512*255) never exceeds 6 octal digits.
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|&b| b as u32).sum();
    let chk = format!("{sum:06o}");
    header[148..154].copy_from_slice(chk.as_bytes());
    header[154] = 0;
    header[155] = b' ';
}

/// Re-emit `r` (a decompressed tar) to `w`, DROPPING every char/block device member (`3`/`4`), STRIPPING
/// the setuid/setgid bit off every regular file (see [`clear_suid_sgid`]), and copying the rest of every
/// member VERBATIM. The output is then re-vetted by [`check_layer_safe`] and only
/// then extracted, so this pass carries NO security guarantee of its own: a slip that leaves a device
/// in is caught (the re-vet refuses `3`/`4`), and a slip that corrupts the stream fails the re-vet or
/// `tar`. Its ONLY jobs are (1) drop device members so a legitimate image that ships an inert device
/// node (amazonlinux's base layer, images with `/dev/null`) can pull, and (2) stay byte-synchronized so
/// the output is a valid tar. It mirrors the vetter's STRUCTURAL typeflag handling (refuse sparse/
/// multivolume, and a nonzero size on link/dir) purely to avoid desyncing the cursor; the full
/// path/escape/bomb vetting is the re-vet's job and is deliberately NOT duplicated here.
pub(crate) fn strip_device_members(
    r: &mut impl std::io::Read,
    w: &mut impl std::io::Write,
) -> Result<(), OciError> {
    let bad = |m: &str| OciError::Extract(m.to_string());
    let wr = |w: &mut dyn std::io::Write, b: &[u8]| -> Result<(), OciError> {
        w.write_all(b)
            .map_err(|e| OciError::Extract(format!("write filtered layer: {e}")))
    };
    let mut header = [0u8; TAR_BLOCK];
    let mut total: u64 = 0;
    // Raw bytes (header + data) of GNU L/K and PAX x records staged for the NEXT member: flushed before
    // an accepted member, DROPPED if that member is a device. PAX g (global) is written straight through.
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let n = read_block(r, &mut header).map_err(|e| OciError::Tool("gzip", e.to_string()))?;
        if n == 0 {
            return Err(bad("truncated layer archive (no end-of-archive marker)"));
        }
        if n < TAR_BLOCK {
            return Err(bad("truncated tar header"));
        }
        if header.iter().all(|&b| b == 0) {
            // End-of-archive: emit the canonical two zero blocks and stop (a valid tar needs only the
            // marker; we do not copy the input's trailing padding). The re-vet runs on this output next.
            wr(w, &[0u8; TAR_BLOCK * 2])?;
            return Ok(());
        }
        let typeflag = header[156];
        let size = tar_num(&header[124..136]).ok_or_else(|| bad("bad tar size field"))?;
        // Bound emitted bytes up front (a decompression bomb would otherwise stream forever). The
        // re-vet caps again, but a gate must not depend on another gate.
        total = total.saturating_add(size);
        if size > MAX_LAYER_BYTES || total > MAX_LAYER_BYTES {
            return Err(bad(
                "layer exceeds the size cap (possible decompression bomb)",
            ));
        }
        match typeflag {
            // Per-member meta: buffer verbatim (header + capped data) for the following member.
            b'L' | b'K' | b'x' => {
                if size > TAR_MAX_LONG {
                    return Err(bad("oversized tar meta record"));
                }
                let raw = read_raw_blocks(r, size)?;
                pending.extend_from_slice(&header);
                pending.extend_from_slice(&raw);
            }
            // PAX global: not tied to one member; pass straight through, preserving stickiness.
            b'g' => {
                if size > TAR_MAX_LONG {
                    return Err(bad("oversized tar meta record"));
                }
                let raw = read_raw_blocks(r, size)?;
                wr(w, &header)?;
                wr(w, &raw)?;
            }
            // DEVICE: the whole point. Drop it and any meta that named it. A device node carries no
            // data (size 0); a nonzero size is a desync attempt, refused (the re-vet would too).
            b'3' | b'4' => {
                if size != 0 {
                    return Err(bad("device node with non-zero size (tar desync attack)"));
                }
                pending.clear();
            }
            // Sparse/multivolume: `size` is not the on-wire data length, so copying `size` bytes would
            // desync. The vetter refuses these; mirror it (never emit them).
            b'S' | b'M' => {
                return Err(bad(
                    "layer has a sparse or multivolume member (unsupported)",
                ));
            }
            // Symlink/hardlink/directory carry no data: a nonzero size desyncs a non-GNU extractor.
            // Mirror the vetter's refusal so the copy stays byte-synchronized.
            b'1' | b'2' | b'5' if size != 0 => {
                return Err(bad(
                    "layer has a symlink/hardlink/directory header with non-zero size",
                ));
            }
            // Every ordinary member (regular `0`/NUL/`7`, dir `5`, hardlink `1`, symlink `2`, and FIFO
            // `6` - which the re-vet still refuses, unchanged): copy verbatim. Flush staged meta first.
            b'0' | 0 | b'7' | b'5' | b'1' | b'2' | b'6' => {
                if !pending.is_empty() {
                    wr(w, &pending)?;
                    pending.clear();
                }
                // Strip setuid/setgid from image FILES (regular members only - setgid on a directory is
                // legitimate group-inheritance, not a privilege lever). The bit is already inert in a box
                // (root mount is `MS_NOSUID`) and on a rootless `--dest` tree (files owned by the
                // unprivileged extractor), so this changes nothing there; it hardens the one path those
                // two defenses don't cover - a tree used OUTSIDE a box, or a `pull` run as real root -
                // making the artifact safe-by-construction. Same stance as the device drop above.
                if matches!(typeflag, b'0' | 0 | b'7') {
                    clear_suid_sgid(&mut header);
                }
                wr(w, &header)?;
                pipe_data(r, size, w)?;
            }
            // Unknown type: refuse rather than guess `size`'s meaning and desync (mirrors the vetter).
            other => {
                return Err(bad(&format!(
                    "layer has an unsupported tar member type (0x{other:02x})"
                )));
            }
        }
    }
}

/// Produce a device-free, fully-vetted PLAIN tar for a layer, ready to hand to `tar -xf`.
///
/// Pipeline: decompress `tar_path` (per `comp`, same codecs as [`check_layer_safe`]) ->
/// [`strip_device_members`] into a fresh sibling temp -> [`check_layer_safe`] RE-VETS that temp with the
/// UNCHANGED vetter. Returns the temp's path on success; the caller extracts that PLAIN tar (no codec
/// branch) and removes it. The re-vet is the security gate: `strip` carries no guarantee of its own, so a
/// device it failed to drop, or any corruption it introduced, is caught here (fail-closed) before a
/// single byte is extracted. On any error the partial temp is removed.
pub(crate) fn filter_layer(
    tar_path: &Path,
    comp: Compression,
) -> Result<std::path::PathBuf, OciError> {
    let path = tar_path.to_string_lossy();
    let out_path = tar_path.with_extension("kernflt");
    let mut out = std::fs::File::create(&out_path)
        .map_err(|e| OciError::Extract(format!("create filtered layer: {e}")))?;
    let strip_res = match comp {
        Compression::Plain => std::fs::File::open(tar_path)
            .map_err(|e| OciError::Extract(e.to_string()))
            .and_then(|mut f| strip_device_members(&mut f, &mut out)),
        Compression::Gzip | Compression::Zstd => {
            let is_zstd = comp == Compression::Zstd;
            if is_zstd && !zstd_available() {
                let _ = std::fs::remove_file(&out_path);
                return Err(zstd_missing());
            }
            let bin = if is_zstd { "zstd" } else { "gzip" };
            match Command::new(bin)
                .args(["-dc", &path])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            {
                Err(e) => Err(if is_zstd {
                    zstd_missing()
                } else {
                    OciError::Tool("gzip", e.to_string())
                }),
                Ok(mut child) => {
                    let res = match child.stdout.take() {
                        None => Err(OciError::Extract("no decompressor stdout".into())),
                        Some(mut stdout) => strip_device_members(&mut stdout, &mut out),
                    };
                    // We stop reading at the end-of-archive marker, so the decompressor may take a
                    // SIGPIPE - its status is not meaningful; a truncated input is caught by `strip`.
                    let _ = child.kill();
                    let _ = child.wait();
                    res
                }
            }
        }
    };
    // Persist the output before re-vetting/extracting it, then close it so it can be re-read.
    use std::io::Write as _;
    let finish = strip_res.and_then(|()| {
        out.flush()
            .map_err(|e| OciError::Extract(format!("flush filtered layer: {e}")))
    });
    drop(out);
    if let Err(e) = finish {
        let _ = std::fs::remove_file(&out_path);
        return Err(e);
    }
    // RE-VET the filtered PLAIN tar with the UNCHANGED vetter - the security gate (fail-closed): any
    // device `strip` missed, or any corruption it introduced, is rejected here before extraction.
    if let Err(e) = check_layer_safe(&out_path, Compression::Plain) {
        let _ = std::fs::remove_file(&out_path);
        return Err(e);
    }
    Ok(out_path)
}

/// What `parse_pax` extracted from a PAX record set: the overriding `path`/`linkpath`, and whether any
/// `GNU.sparse.*` key was present (the PAX-encoded new-GNU sparse-file variant - a divergence surface we
/// refuse, same as a raw `'S'` typeflag).
struct PaxInfo {
    path: Option<String>,
    linkpath: Option<String>,
    sparse: bool,
}

/// Parse the PAX records we care about (`<len> key=value\n`…). Operates on the RAW bytes - never on a
/// lossy `&str` - so a `len` that an attacker tuned to fall inside a multi-byte UTF-8 sequence can't
/// panic on a char-boundary slice; malformed input just stops the scan. Only the final value is decoded
/// (lossily) to a `String`.
fn parse_pax(data: &[u8]) -> PaxInfo {
    let mut info = PaxInfo {
        path: None,
        linkpath: None,
        sparse: false,
    };
    let mut rest: &[u8] = data;
    while !rest.is_empty() {
        // `<len>` is ASCII digits up to the first space; `len` counts the whole "<len> k=v\n" record.
        let Some(sp) = rest.iter().position(|&b| b == b' ') else {
            break;
        };
        let Ok(len_str) = std::str::from_utf8(&rest[..sp]) else {
            break;
        };
        let Ok(len) = len_str.parse::<usize>() else {
            break;
        };
        if len <= sp || len > rest.len() {
            break;
        }
        // Byte-slice the record body (no char-boundary hazard), then decode only the value lossily.
        let mut body = &rest[sp + 1..len];
        if body.last() == Some(&b'\n') {
            body = &body[..body.len() - 1];
        }
        if let Some(eq) = body.iter().position(|&b| b == b'=') {
            let k = &body[..eq];
            match k {
                b"path" => info.path = Some(String::from_utf8_lossy(&body[eq + 1..]).into_owned()),
                b"linkpath" => {
                    info.linkpath = Some(String::from_utf8_lossy(&body[eq + 1..]).into_owned())
                }
                // Any GNU.sparse.* record marks a PAX-encoded sparse member → refuse (see the 'S' branch).
                _ if k.starts_with(b"GNU.sparse.") => info.sparse = true,
                _ => {}
            }
        }
        rest = &rest[len..];
    }
    info
}

/// Vet the raw (decompressed) tar stream `r` block by block. Resolves the effective path/linkname
/// through ustar `prefix`, GNU `L`/`K` long name/link, and PAX `x`/`g` `path=`/`linkpath=`, so what we
/// check is what tar will actually create - never a truncated or text-desynced approximation.
pub(crate) fn vet_tar_stream(r: &mut impl std::io::Read) -> Result<(), OciError> {
    let bad = |m: &str| OciError::Extract(m.to_string());
    let mut header = [0u8; TAR_BLOCK];
    let mut total: u64 = 0;
    let mut entries: u64 = 0;
    let mut next_name: Option<String> = None; // override carried by a preceding L / PAX block
    let mut next_link: Option<String> = None; // …K / PAX linkpath
                                              // Paths of symlinks seen SO FAR in this layer whose target ESCAPES the rootfs (absolute / `..`).
                                              // A symlink-following extractor (BusyBox tar) writing THROUGH one would land outside the staging
                                              // dir - so a LATER member that descends through one is the real escape (tracked, not the mere
                                              // existence of an absolute symlink, which every busybox-based image - alpine's `/bin/*` - has).
    let mut escaping_symlinks: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        let n = read_block(r, &mut header).map_err(|e| OciError::Tool("gzip", e.to_string()))?;
        if n == 0 {
            // Clean EOF with no end-of-archive zero block = truncated (an unsafe member could have
            // been cut off) → reject.
            return Err(bad("truncated layer archive (no end-of-archive marker)"));
        }
        if n < TAR_BLOCK {
            return Err(bad("truncated tar header"));
        }
        if header.iter().all(|&b| b == 0) {
            // A zero block STARTS the end-of-archive marker (POSIX wants two). Do NOT return here: a
            // single stray zero block followed by more members would let us stop vetting while the host
            // tar reads on and extracts them. Require the tail to be all-zero - any non-zero byte after
            // the marker is a hidden trailing member → reject. But do NOT drain to EOF unboundedly: a
            // hostile image can append gigabytes of zero blocks (a zero-bomb DoS). A legitimate tail is
            // a couple of zero blocks plus at most one blocking-factor of record padding (GNU default 20
            // blocks); cap generously and, once past the cap, stop reading - the extractor's own output
            // is already bounded by MAX_LAYER_BYTES, and a multi-MiB all-zero tail carries no member.
            const MAX_TAIL_BLOCKS: usize = 4096; // 2 MiB of trailing zero padding - absurdly generous
            let mut pad = [0u8; TAR_BLOCK];
            let mut tail_blocks = 0usize;
            loop {
                let m =
                    read_block(r, &mut pad).map_err(|e| OciError::Tool("gzip", e.to_string()))?;
                if m == 0 {
                    return Ok(()); // clean EOF after the zero marker - fully vetted
                }
                if pad[..m].iter().any(|&b| b != 0) {
                    return Err(bad(
                        "data after the end-of-archive marker (hidden trailing member)",
                    ));
                }
                tail_blocks += 1;
                if tail_blocks > MAX_TAIL_BLOCKS {
                    // All-zero so far, but an unbounded zero tail is a DoS. Everything we've read is
                    // padding (no member), and any real member would have shown a non-zero byte by now.
                    return Err(bad(
                        "excessive zero padding after end-of-archive marker (zero-bomb)",
                    ));
                }
            }
        }

        let typeflag = header[156];
        let size = tar_num(&header[124..136]).ok_or_else(|| bad("bad tar size field"))?;

        // GNU long-name/link and PAX headers carry the real path/linkname in their DATA, for the NEXT
        // entry - read (capped) and stash; they aren't entries themselves.
        //
        // FAIL-CLOSED ON AMBIGUITY: if two sources try to set the SAME field for one member (a GNU `L`
        // *and* a PAX `path=`, or `K` *and* a PAX `linkpath=`), we do NOT guess which one the host tar
        // will honour - GNU tar prefers PAX regardless of physical order, others differ, so any choice
        // we make can diverge from extraction. Legit images never mix two sources for one member, so we
        // simply reject. `set_once` enforces this: a second setter on an already-set slot is an error.
        fn set_once(slot: &mut Option<String>, val: String, what: &str) -> Result<(), OciError> {
            if slot.is_some() {
                return Err(OciError::Extract(format!(
                    "layer sets {what} for one member from two sources (ambiguous - refusing)"
                )));
            }
            *slot = Some(val);
            Ok(())
        }
        match typeflag {
            b'L' | b'K' => {
                if size > TAR_MAX_LONG {
                    return Err(bad("oversized tar long-name record"));
                }
                let s = tar_field(&take_data(r, size, size as usize)?);
                if typeflag == b'L' {
                    set_once(&mut next_name, s, "the path")?;
                } else {
                    set_once(&mut next_link, s, "the link target")?;
                }
                continue;
            }
            b'x' => {
                if size > TAR_MAX_LONG {
                    return Err(bad("oversized PAX record"));
                }
                let info = parse_pax(&take_data(r, size, size as usize)?);
                if info.sparse {
                    return Err(bad(
                        "layer has a PAX-encoded sparse member (unsupported - refusing)",
                    ));
                }
                if let Some(p) = info.path {
                    set_once(&mut next_name, p, "the path")?;
                }
                if let Some(lp) = info.linkpath {
                    set_once(&mut next_link, lp, "the link target")?;
                }
                continue;
            }
            b'g' => {
                // A PAX GLOBAL header is sticky across all following members, and most tars ignore
                // `path`/`linkpath` inside it entirely - so trusting it here would vet a name that
                // extraction never uses. A legit OCI layer never carries a global `path`/`linkpath`;
                // refuse the archive rather than guess. (Global records without those keys are benign
                // and simply skipped.)
                if size > TAR_MAX_LONG {
                    return Err(bad("oversized PAX record"));
                }
                let info = parse_pax(&take_data(r, size, size as usize)?);
                if info.sparse {
                    return Err(bad(
                        "layer has a PAX-encoded sparse member (unsupported - refusing)",
                    ));
                }
                if info.path.is_some() || info.linkpath.is_some() {
                    return Err(bad(
                        "layer carries a PAX global path/linkpath override (ambiguous - refusing)",
                    ));
                }
                continue;
            }
            // GNU SPARSE ('S') and MULTIVOLUME ('M') members are a hard divergence surface: the `size`
            // header field is the STORED (sparse) length, not the real extracted layout - the data does
            // NOT occupy `size` contiguous bytes, so skipping `size` bytes here desyncs our cursor from
            // what tar reads (→ a fake "next header" parsed from mid-data), and a sparse member also lets
            // `size` under-count the real file (a bomb the byte-cap can't see). An OCI layer never needs
            // either; refuse rather than emulate the sparse map. (The `GNU.sparse.*` PAX-encoded variant
            // is caught in `parse_pax` → the 'x' branch's set_once/`is_err`.)
            b'S' | b'M' => {
                return Err(bad(
                    "layer has a sparse or multivolume member (unsupported - refusing)",
                ));
            }
            // A FIFO ('6') is INERT toward the host (unlike a device node it reaches no hardware - it's
            // just a filesystem object in the staging rootfs), so accepting it would be safe. We refuse
            // it anyway, as a DELIBERATE, DOCUMENTED policy: an ephemeral sandbox rootfs has no
            // legitimate use for a named pipe baked into an image layer, and refusing keeps the member
            // set to the types kern actually models. This is an explicit choice with a clear message -
            // not the accidental "unsupported type" fallthrough - so a maintainer can flip it to accept
            // by moving `b'6'` into the allow-list on the line below.
            b'6' => {
                return Err(bad(
                    "layer has a FIFO member - refused by policy (not needed in a sandbox rootfs)",
                ));
            }
            // Known member typeflags that fall through to be vetted as a real entry below: regular
            // (`0`, NUL, and pre-POSIX `7` contiguous ≈ regular), directory (`5`), hardlink (`1`),
            // symlink (`2`), and device (`3`/`4`, rejected just below). Anything else is a typeflag we
            // don't model - fail CLOSED (don't silently treat an unknown vendor type as a regular file
            // and skip `size` bytes on a possibly-different-meaning field). Every other divergence class
            // in this vetter already fails closed; this keeps the last fallthrough consistent.
            b'0' | 0 | b'7' | b'5' | b'1' | b'2' | b'3' | b'4' => {}
            other => {
                return Err(bad(&format!(
                    "layer has an unsupported tar member type (0x{other:02x}) - refusing"
                )));
            }
        }

        entries += 1;
        if entries > MAX_LAYER_ENTRIES {
            return Err(bad("layer has too many entries (possible inode bomb)"));
        }

        let path = next_name.take().unwrap_or_else(|| {
            let name = tar_field(&header[0..100]);
            let prefix = tar_field(&header[345..500]);
            if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            }
        });
        let link = next_link.take().or_else(|| {
            let l = tar_field(&header[157..257]);
            (!l.is_empty()).then_some(l)
        });

        if typeflag == b'3' || typeflag == b'4' {
            return Err(bad("layer has a device node"));
        }
        if unsafe_member_path(&path) {
            return Err(OciError::Extract(format!("unsafe path in layer: {path}")));
        }
        // CANONICALIZE the way the extractor lays it on disk (drop `.`/empty components: leading `./`,
        // `//`, `/./`, trailing `/`) - else a member spelled `./A/x` or `A//x` would slip past a symlink
        // recorded as `A` (the vetter's string view must match the filesystem's). `..` already rejected.
        let path = normalize_member_path(&path);

        // SYMLINK-ESCAPE: reject any member AT or UNDER a symlink recorded earlier in THIS layer whose
        // (resolved) target escapes the rootfs. On a symlink-FOLLOWING extractor (BusyBox tar) such a
        // member writes OUTSIDE the isolated staging dir - whether it DESCENDS the symlink (`a/x` through
        // `a -> /etc`), writes a file straight ONTO it (`a` over `a -> /etc/x`, which tar opens through
        // the link), or the symlink was reached through a CHAIN (`b -> a -> /etc`). `under_escaping` is
        // O(path depth) HashSet lookups → linear even at 2M entries (a per-member scan of all prior
        // symlinks would be O(n²)). This REPLACES the old blanket "reject any escaping symlink target":
        // that also killed the ubiquitous, harmless absolute symlink (alpine's `/bin/* -> /bin/busybox`),
        // breaking every busybox-based image on a non-GNU-tar host (the shipped WSL distro, edge Pi/Alpine).
        if under_escaping(&path, &escaping_symlinks) {
            return Err(OciError::Extract(format!(
                "layer member '{path}' would be written through an escaping symlink (rootfs escape)"
            )));
        }
        // '1' HARDLINK target is resolved to a real path AT EXTRACTION (root-relative), and `link(2)`
        // follows symlinks in intermediate components → reject an absolute/`..` target (which hardlinks
        // a HOST inode straight in) AND a target that DESCENDS an escaping symlink recorded earlier in
        // THIS layer: `b -> a/passwd` through a prior `a -> /etc` hardlinks host `/etc/passwd` into the
        // rootfs (read = host-file disclosure, write = host corruption). That is the same symlink-descend
        // class the `under_escaping` check above closes for a member PATH, but here the escape is via the
        // hardlink's TARGET, which that check does not cover. A '2' SYMLINK's escaping target is tracked
        // below. (BusyBox tar - kern's edge/WSL/Alpine hosts - has no hardlink safety, and the vetter is
        // deliberately the tar-flavour-independent boundary, so this must be caught here.)
        if typeflag == b'1' {
            if let Some(t) = link.as_deref() {
                if unsafe_member_path(t)
                    || under_escaping(&normalize_member_path(t), &escaping_symlinks)
                {
                    return Err(OciError::Extract(format!(
                        "layer hardlink target escapes the rootfs: {path} -> {t}"
                    )));
                }
            }
        }

        // A symlink('2'), hardlink('1') or directory('5') header carries NO data - its `size` MUST be
        // 0. A hostile layer that puts a NON-ZERO size on one of these desyncs the vetter from the
        // extractor: WE skip `size` bytes (trusting the lie), but a non-GNU `tar` (BusyBox on the
        // musl/edge boards kern targets) does NOT skip data for these types - it reads the skipped block
        // as the NEXT header. So the attacker hides an escaping member (esc -> /etc/shadow) in the
        // "data" of a lying symlink: the vetter never sees it, BusyBox extracts it -> full escape-guard
        // bypass. Reject a non-zero size on these types BEFORE consuming, so the vetter and every
        // extractor agree on where the next header starts. (Found in a hacker-mode audit.)
        if matches!(typeflag, b'1' | b'2' | b'5') && size != 0 {
            return Err(bad(
                "layer has a symlink/hardlink/directory header with non-zero size (tar desync attack)",
            ));
        }
        // Record this symlink if its target ESCAPES the rootfs - DIRECTLY (absolute / `..`) or via a
        // CHAIN (a relative target that resolves onto an already-escaping symlink, e.g. `b -> a` where
        // `a -> /etc`). ADD-ONLY, never cleared: once a path holds an escaping symlink a later same-path
        // member must NOT un-guard it - a symlink-following extractor may leave the original link in place
        // (a dir/file written over it EEXISTs or is opened THROUGH it), and any member at/under it is
        // already refused by `under_escaping` above. The relative-target resolution is done against the
        // symlink's PARENT dir (that's what the link is relative to), normalized like any member path.
        if typeflag == b'2' {
            let target = link.as_deref().unwrap_or("");
            let escapes = unsafe_member_path(target) || {
                let parent = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                let resolved = normalize_member_path(&format!("{parent}/{target}"));
                under_escaping(&resolved, &escaping_symlinks)
            };
            if escapes {
                escaping_symlinks.insert(path.clone());
            }
        }
        // Cap BEFORE consuming the data: a single member with a huge size would otherwise stream its
        // entire (decompressed) body from gzip before the running total tripped the cap - a per-member
        // DoS. Checking the declared size up front bounds the work to one block.
        total = total.saturating_add(size);
        if size > MAX_LAYER_BYTES || total > MAX_LAYER_BYTES {
            return Err(bad(
                "layer exceeds the size cap (possible decompression bomb)",
            ));
        }
        take_data(r, size, 0)?; // skip the member data (regular files only; links/dirs are size 0)
    }
}

/// Merge an isolated layer staging tree into `dest` with **no-follow** semantics. Before writing
/// any entry, the destination parent must be symlink-free (else a previous layer planted a
/// symlink to escape through - refuse). `.wh.<name>` deletes `<name>`; `.wh..wh..opq` drops the
/// directory's lower-layer contents. Targets are removed without following symlinks, so the
/// merge can never write through one.
pub(crate) fn merge_layer(staging: &Path, dest: &Path) -> Result<(), OciError> {
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
        clear_dir(&dest.join(dir_rel))?;
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
            // `with_file_name("..")` then points at the rootfs's PARENT - `remove_no_follow` would
            // `remove_dir_all` files OUTSIDE the image (other pulled images / the store). `..` is a
            // real dir, so the no-follow symlink guard does not stop it. (Opaque marker handled above.)
            let plain_victim = !victim_name.is_empty()
                && victim_name != "."
                && victim_name != ".."
                && !victim_name.contains('/');
            if fname.as_ref() != ".wh..wh..opq" && plain_victim {
                remove_no_follow(&target.with_file_name(victim_name))?;
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
                    remove_no_follow(&target)?;
                    std::fs::create_dir(&target).map_err(|e| OciError::Extract(e.to_string()))?;
                }
                Err(_) => {
                    std::fs::create_dir(&target).map_err(|e| OciError::Extract(e.to_string()))?;
                }
            }
            // Copy the source dir's EXACT mode onto the merged dir - `create_dir` uses 0777&umask
            // (0755), which drops the sticky bit + world-write that images set on `/tmp` (1777). Without
            // this, a workload that drops to a non-root uid can't write `/tmp` (mariadb/mysql InnoDB temp
            // files fail EACCES). The staging was extracted with `--same-permissions`, so `src` carries
            // the image's real mode. (setuid/setgid bits on a rootfs dir are inert - the box root mount
            // is MS_NOSUID - so copying the full mode is safe.)
            if let Ok(m) = std::fs::metadata(&src) {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &target,
                    std::fs::Permissions::from_mode(m.permissions().mode()),
                );
            }
            merge_dir(base, &src, dest, dest_s)?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(&src).map_err(|e| OciError::Extract(e.to_string()))?;
            remove_no_follow(&target)?;
            std::os::unix::fs::symlink(&link, &target)
                .map_err(|e| OciError::Extract(e.to_string()))?;
        } else {
            // Regular file (device/special nodes were rejected by check_layer_safe).
            remove_no_follow(&target)?;
            if std::fs::rename(&src, &target).is_err() {
                std::fs::copy(&src, &target).map_err(|e| OciError::Extract(e.to_string()))?;
            }
        }
    }
    Ok(())
}

/// An open DIRECTORY descriptor, used to read and change a directory's mode by OBJECT rather than by
/// NAME.
///
/// `std::fs::metadata` and `std::fs::set_permissions` both follow symlinks. Every mode change in this
/// module is applied to a path built from attacker-supplied layer content, so a symlink at the final
/// component - planted by an earlier layer, or swapped in between a check and the call - would move
/// the `chmod` onto its target, potentially a directory outside the image. `merge_dir`'s
/// `whiteout_dir_symlink_free` guard already refuses such paths, but that is a check-then-use: this
/// closes the class structurally instead of relying on the ordering.
///
/// `O_DIRECTORY` refuses anything that is not a directory and `O_NOFOLLOW` refuses a symlink at the
/// final component, so the descriptor can only ever refer to a real directory; `fstat` and `fchmod`
/// then act on that descriptor, and re-pointing the name afterwards changes nothing.
struct DirHandle(libc::c_int);

impl DirHandle {
    /// Open `dir` for mode work. `None` if it is not a directory, is a symlink, or cannot be opened -
    /// each of which means there is no mode of ours to adjust here.
    fn open(dir: &Path) -> Option<Self> {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        // SAFETY: `c` is NUL-terminated and outlives the call; `open` only reads it.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        (fd >= 0).then_some(DirHandle(fd))
    }

    /// The directory's permission bits (`st_mode & 0o7777`), or `None` if `fstat` fails.
    fn mode(&self) -> Option<u32> {
        // SAFETY: `st` is fully initialised by `fstat` on success, and only read when it returns 0.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::fstat(self.0, &mut st) };
        (r == 0).then_some(st.st_mode & 0o7777)
    }

    /// Set the directory's permission bits. `false` if the kernel refused.
    fn chmod(&self, mode: u32) -> bool {
        // SAFETY: a plain syscall on a descriptor this handle owns.
        unsafe { libc::fchmod(self.0, mode as libc::mode_t) == 0 }
    }
}

impl Drop for DirHandle {
    fn drop(&mut self) {
        // SAFETY: the fd was opened by `open` above and is closed exactly once, here.
        unsafe { libc::close(self.0) };
    }
}

/// Grant OURSELVES `u+wx` on a directory we are about to descend into or empty, best-effort.
///
/// Unlinking an entry is governed by the mode of the DIRECTORY that holds it, and reading it needs
/// search permission, so a layer that shipped `chmod 555` on a directory blocks both. kern extracted
/// that directory, so it owns it and may chmod it. Best-effort on purpose: this is an enabler, not
/// the decision. If the chmod is refused, the `read_dir`/`remove_*` that follows fails and THAT error
/// is the one that propagates, naming the operation that actually mattered.
///
/// Nothing is granted to group or other, and only the bits needed to delete are added. Applied
/// through [`DirHandle`], so it can never land on a symlink's target.
fn grant_self_wx(dir: &Path) {
    let Some(h) = DirHandle::open(dir) else {
        return;
    };
    let Some(mode) = h.mode() else {
        return;
    };
    if mode & 0o300 != 0o300 {
        let _ = h.chmod(mode | 0o300);
    }
}

/// Delete a directory tree without ever following a symlink, repairing our own permissions as it
/// descends.
///
/// Replaces `std::fs::remove_dir_all` on image content for one reason: `remove_dir_all` gives up on a
/// directory it cannot enter, and an image may legitimately ship one. `chmod 555 /opt/foo` in one
/// layer and `rm -rf /opt/foo` in a later one is an ordinary Dockerfile; docker and containerd extract
/// as root and never meet the case, so refusing that pull would be a regression against them rather
/// than a hardening. Widening the victim's PARENT is not enough - emptying `foo` needs write+search on
/// `foo` itself, and on every directory below it.
///
/// ITERATIVE, with an explicit stack, so a deep tree cannot exhaust the call stack. Post-order: a
/// directory is removed only after its children are gone. Termination is structural rather than
/// capped - no symlink is ever traversed, so the walk stays inside one finite tree and cannot cycle
/// (a filesystem cannot contain a directory cycle without symlinks; hardlinked directories are
/// refused by every Linux filesystem).
///
/// NO-FOLLOW at every level: the file-vs-directory decision comes from `symlink_metadata`, so a
/// symlink to a directory is unlinked as a link and never descended. This is what stops a planted
/// `dir/escape -> /somewhere/else` from turning a whiteout into a deletion outside the rootfs.
///
/// Modes are NOT restored on the way out: every directory this touches is about to cease to exist.
/// If the removal fails partway, some directories are left wider than the image declared - but that
/// error fails the pull, so the half-deleted tree is never published as an image.
fn remove_tree_no_follow(root: &Path) -> std::io::Result<()> {
    // `(path, children_already_pushed)`. Pushing the directory back with `true` before its children
    // is what makes the traversal post-order under LIFO.
    let mut stack: Vec<(std::path::PathBuf, bool)> = vec![(root.to_path_buf(), false)];
    while let Some((dir, expanded)) = stack.pop() {
        if expanded {
            match std::fs::remove_dir(&dir) {
                Ok(()) => {}
                // Already gone: the end state we wanted.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            continue;
        }
        grant_self_wx(&dir);
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        stack.push((dir.clone(), true));
        for entry in rd {
            let entry = entry?;
            let path = entry.path();
            // `symlink_metadata`, never `metadata`: a symlink to a directory must be unlinked, not
            // descended. `entry.file_type()` is the same syscall-free source, but reading it again
            // here keeps the no-follow decision at the point it is used.
            let md = match std::fs::symlink_metadata(&path) {
                Ok(md) => md,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            if md.is_dir() {
                stack.push((path, false));
            } else {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }
    Ok(())
}

/// Remove a layer's staging directory after it has served its purpose, and SAY SO if that fails.
///
/// Best-effort by design: a cleanup that cannot run must not fail a pull whose layer already merged
/// correctly. Silent, however, it was the same defect class as the rest of this file - staging is
/// extracted with `--same-permissions`, so an image shipping a `chmod 555` directory made
/// `remove_dir_all` fail with `EACCES` and every pull of that image left a full copy of the layer on
/// disk with nothing to attribute the growth to. `remove_tree_no_follow` repairs the permissions it
/// needs, so this should now only fire on a real filesystem error, and when it does the message names
/// the path.
fn discard_staging(staging: &Path) {
    if let Err(e) = remove_tree_no_follow(staging) {
        eprintln!(
            "kern: could not remove the layer staging dir {}: {e} - it will keep using disk until \
             removed by hand",
            staging.display()
        );
    }
}

/// Remove a path without following symlinks (a symlink is unlinked, never traversed).
///
/// FALLIBLE ON PURPOSE. This is how an OCI whiteout deletes a file, and it used to return `()`: a
/// refused unlink was indistinguishable from a completed one, so `merge_layer` reported `Ok` while
/// the file the image declared deleted was still in the rootfs. Reachable from a plain image, not a
/// crafted one - `merge_dir` copies the staging directory's mode onto the destination BEFORE it
/// recurses into it, so a layer that both makes a directory read-only and deletes a file inside it
/// removes our own write permission on the parent first, and the unlink fails `EACCES`. Whiteouts
/// are how an image removes a secret, a setuid binary or a vulnerable library that an earlier layer
/// added, so "declared deleted, still present, nothing said" is the difference between the rootfs
/// the manifest describes and the rootfs on disk.
///
/// A missing path is the desired end state, not a failure.
///
/// On refusal it retries ONCE with our own write+search permission restored on the PARENT directory.
/// Unlinking is governed by the parent's mode, not the victim's, and kern extracted that parent, so
/// it owns it and may chmod it. The parent's mode is put back either way, so the image's declared
/// permissions still win: the widening exists only for the duration of the unlink.
///
/// No-follow is preserved across the retry: the decision between `remove_dir_all` and `remove_file`
/// comes from the ORIGINAL `symlink_metadata`, so a symlink is unlinked and never traversed, and a
/// racing replacement cannot turn a file removal into a directory walk.
fn remove_no_follow(p: &Path) -> Result<(), OciError> {
    let md = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        // ENOENT (or an unreadable parent) means there is nothing here to delete, which is exactly
        // what the whiteout asked for.
        Err(_) => return Ok(()),
    };
    let attempt = || -> std::io::Result<()> {
        if md.is_dir() {
            remove_tree_no_follow(p)
        } else {
            std::fs::remove_file(p)
        }
    };
    let first = match attempt() {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };

    // Retry with the parent widened. `parent()` is `None` only for a path with no directory
    // component, which cannot happen here: every caller joins onto the destination rootfs.
    let Some(parent) = p.parent() else {
        return Err(OciError::Extract(format!(
            "cannot remove {}: {first}",
            p.display()
        )));
    };
    // Widen through a DESCRIPTOR, never through the path: `set_permissions` follows symlinks, and this
    // parent is built from attacker-supplied layer content. One handle is held across both the widen
    // and the restore, so the two provably act on the SAME directory even if the name is re-pointed
    // in between.
    let handle = DirHandle::open(parent);
    let saved = handle.as_ref().and_then(DirHandle::mode);
    if let (Some(h), Some(mode)) = (handle.as_ref(), saved) {
        // u+wx: write to create/remove entries, execute to traverse. Nothing is granted to group or
        // other, and it lasts only until the restore below.
        let _ = h.chmod(mode | 0o300);
    }
    let second = attempt();
    if let (Some(h), Some(mode)) = (handle.as_ref(), saved) {
        // Restore unconditionally, including on the failure path: the image's mode is authoritative
        // and must not be left widened because a removal failed.
        let _ = h.chmod(mode);
    }
    second.map_err(|e| {
        OciError::Extract(format!(
            "cannot remove {} (whiteout or replacement): {e} (first attempt: {first})",
            p.display()
        ))
    })
}

/// Remove every direct child of `d` (no-follow). Used for opaque-dir whiteouts.
///
/// FALLIBLE for the same reason as [`remove_no_follow`]: an opaque whiteout that cannot be applied
/// leaves the directory's earlier contents in the rootfs, and returning `()` made that indistinguishable
/// from a directory that was cleared. A `read_dir` that fails with anything other than "the directory
/// is not there" is also a failure to apply the whiteout, not a reason to move on quietly.
fn clear_dir(d: &Path) -> Result<(), OciError> {
    let rd = match std::fs::read_dir(d) {
        Ok(rd) => rd,
        // Nothing to clear is the end state an opaque whiteout asks for.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(OciError::Extract(format!(
                "opaque whiteout: cannot read {}: {e}",
                d.display()
            )))
        }
    };
    {
        for e in rd.flatten() {
            // NEVER delete kern's own transient files: the layer cache dir (`dest`) also holds the
            // in-flight prefetch blob (`.kern-layer-<i>-*`) and, in `dest`'s parent, staging dirs.
            // A layer with a ROOT-LEVEL opaque whiteout (`.wh..wh..opq` at the tar root) makes the
            // merge `clear_dir(dest)` - without this skip, a (possibly hostile) image would wipe the
            // blob curl is still writing for the NEXT layer, ENOENT-ing the pull. Image members can
            // never legitimately be named `.kern-*` (nothing in an OCI layer is), so this is safe.
            if e.file_name().to_string_lossy().starts_with(".kern-") {
                continue;
            }
            remove_no_follow(&e.path())?;
        }
    }
    Ok(())
}

fn is_manifest_list(m: &str) -> bool {
    m.contains("\"manifests\"") || m.contains("manifest.list") || m.contains("image.index")
}

/// Pick the layer-bearing manifest digest for `want.arch` (+ os linux) from a manifest list / index.
/// EXACT match only - returns `None` if the requested arch isn't in the index (the caller then errors
/// with the available arches), never a wrong-arch fallback.
fn select_arch_digest(m: &str, want: &Platform) -> Option<String> {
    let manifests = array_after(m, "manifests")?;
    for obj in split_objects(manifests) {
        // Match on a whitespace-stripped copy so a pretty-printed index (`"architecture": "amd64"`)
        // works as well as Docker Hub's compact form. Digest extraction uses the original `obj`.
        let compact: String = obj.split_whitespace().collect();
        if compact.contains("\"unknown\"") {
            continue; // attestation / provenance entries
        }
        let is_arch = compact.contains(&format!("\"architecture\":\"{}\"", want.arch));
        if is_arch && compact.contains("\"os\":\"linux\"") {
            return first_str(obj, "digest");
        }
    }
    None
}

/// The distinct linux arches offered by a manifest index (skipping `unknown` attestation entries), so a
/// "no manifest for <arch>" error can list what IS available instead of leaving the user guessing.
fn available_arches(m: &str) -> Vec<String> {
    let Some(manifests) = array_after(m, "manifests") else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for obj in split_objects(manifests) {
        let compact: String = obj.split_whitespace().collect();
        if compact.contains("\"unknown\"") || !compact.contains("\"os\":\"linux\"") {
            continue;
        }
        if let Some(a) = first_str(obj, "architecture") {
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out
}

fn layer_digests(m: &str) -> Vec<String> {
    match array_after(m, "layers") {
        Some(layers) => all_str_values(layers, "digest"),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod token_error_tests {
    /// A registry's own words are carried into the error, so they must be stripped of control
    /// characters first: that text is remote, attacker-influenceable, and printed to a terminal.
    /// Without this, a crafted `message` could repaint the operator's line or hide what followed.
    #[test]
    fn a_registry_message_cannot_inject_terminal_escapes() {
        use super::without_control_chars as scrub;
        let hostile = "denied\u{1b}[2K\u{1b}[1A\u{1b}[32m ok, pushed\u{7}\nsecond line\ttab";
        let clean = scrub(hostile);
        assert!(
            !clean.chars().any(|c| c.is_control()),
            "no control character may survive: {clean:?}"
        );
        assert!(
            clean.starts_with("denied"),
            "the readable text is kept: {clean:?}"
        );
        assert!(
            clean.contains("second line"),
            "content is kept, only controls go: {clean:?}"
        );
        assert!(!clean.contains('\n') && !clean.contains('\t'));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_match_is_exact_not_prefix() {
        // Real loopback → http-insecure OK.
        assert!(is_loopback_registry("localhost"));
        assert!(is_loopback_registry("localhost:5000"));
        assert!(is_loopback_registry("127.0.0.1"));
        assert!(is_loopback_registry("127.0.0.1:5000"));
        assert!(is_loopback_registry("127.5.6.7"));
        assert!(is_loopback_registry("::1"));
        assert!(is_loopback_registry("[::1]:5000"));
        // SECURITY: an attacker domain that merely LOOKS loopback must NOT be treated as insecure -
        // else a real push/pull to it runs over http with no TLS pin (MITM / credential leak).
        assert!(!is_loopback_registry("127.0.0.1.evil.com")); // 5 parts, not an IPv4
        assert!(!is_loopback_registry("127x.evil.com"));
        assert!(!is_loopback_registry("localhost.evil.com"));
        assert!(!is_loopback_registry("127.0.0.1evil.com"));
        assert!(!is_loopback_registry("::1.evil.com"));
        assert!(!is_loopback_registry("ghcr.io"));
        assert!(!is_loopback_registry("registry-1.docker.io"));
        // Canonical-IP edge forms the stdlib parser rules on (review §A):
        assert!(!is_loopback_registry("127.999.0.1")); // invalid octet → not a valid IP → pinned
        assert!(!is_loopback_registry("::ffff:127.0.0.1")); // IPv4-mapped → is_loopback()==false → pinned
        assert!(is_loopback_registry("127.255.255.254")); // still 127/8 → loopback
                                                          // reg_base reflects the decision.
        assert_eq!(reg_base("localhost:5000"), "http://localhost:5000");
        assert_eq!(reg_base("ghcr.io"), "https://ghcr.io");
        assert_eq!(reg_base("127.0.0.1.evil.com"), "https://127.0.0.1.evil.com");
    }

    /// `alpine` and `alpine:latest` name ONE image, and everything that keys a cache, a file or a
    /// lookup on a reference has to agree on that. When they did not, the same 8.7 MB was stored
    /// twice, `rmi alpine` left `alpine:latest` behind, and `save` + `load` renamed an image so the
    /// reference that worked before stopped resolving after.
    ///
    /// The three rows that matter are the ones where a naive "does it contain a colon" would be
    /// wrong: a registry PORT is not a tag, a DIGEST must never be given one, and an already-tagged
    /// reference must come back byte-identical.
    #[test]
    fn an_untagged_reference_gets_latest_and_a_port_or_digest_does_not() {
        for (input, want) in [
            ("alpine", "alpine:latest"),
            ("ghcr.io/org/x", "ghcr.io/org/x:latest"),
            // A port is not a tag: the part after `:` contains a `/`.
            ("localhost:5000/img", "localhost:5000/img:latest"),
            // Already explicit: returned untouched, whatever the shape.
            ("alpine:3.19", "alpine:3.19"),
            ("localhost:5000/img:2", "localhost:5000/img:2"),
            // A digest pins harder than a tag and must not be given one.
            ("img@sha256:abc123", "img@sha256:abc123"),
            // Nothing to normalize.
            ("", ""),
        ] {
            assert_eq!(normalize_ref(input), want, "normalize_ref({input:?})");
            // Normalizing is idempotent: applying it twice must not append a second tag.
            assert_eq!(
                normalize_ref(&normalize_ref(input)),
                want,
                "normalize_ref is not idempotent for {input:?}"
            );
            // And it must never change what the reference RESOLVES to at the registry.
            if !input.is_empty() {
                assert_eq!(
                    parse_ref(input).ok(),
                    parse_ref(want).ok(),
                    "normalizing {input:?} changed how it resolves"
                );
            }
        }
    }

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
        // DIGEST pins: the whole `sha256:<hex>` is the manifest reference, and the name loses any tag
        // (a digest pins harder than a tag). A `host:port` must survive - it is not the digest's `:`.
        let dig = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            parse_ref(&format!("nginx@{dig}")).unwrap(),
            (DEFAULT_REGISTRY.into(), "library/nginx".into(), dig.into())
        );
        assert_eq!(
            parse_ref(&format!("ghcr.io/org/app@{dig}")).unwrap(),
            ("ghcr.io".into(), "org/app".into(), dig.into())
        );
        assert_eq!(
            parse_ref(&format!("nginx:1.2@{dig}")).unwrap(),
            (DEFAULT_REGISTRY.into(), "library/nginx".into(), dig.into()),
            "a digest pin drops the tag from the repo path"
        );
        assert_eq!(
            parse_ref(&format!("host:5000/img@{dig}")).unwrap(),
            ("host:5000".into(), "img".into(), dig.into()),
            "a host:port survives digest parsing"
        );
    }

    #[test]
    fn valid_reference_accepts_real_refs_rejects_garbage() {
        // Everyday forms an external `COPY --from=<image>` uses must be accepted.
        for ok in [
            "busybox",
            "nginx:alpine",
            "alpine:3.19",
            "library/alpine",
            "user/repo:tag",
            "ghcr.io/org/app:v1",
            "registry-1.docker.io/library/alpine:latest",
            "localhost:5000/img",
            "host:5000/img@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "my-app.v2/sub_dir:1.2.3",
        ] {
            assert!(valid_reference(ok), "should accept '{ok}'");
        }
        // Garbage / unresolved stage-looking junk must be rejected.
        for bad in [
            "",
            "CAP",            // uppercase repo (OCI repos are lowercase)
            "Bad_Name",       // uppercase
            "..",             // traversal
            "../evil",        // traversal (registry label empty)
            "/etc/passwd",    // absolute path → empty first component
            "-leadingdash",   // component can't start with '-'
            "trailingdash-",  // …or end with one
            "has space",      // whitespace
            "img@sha256:xyz", // digest hex too short / non-hex
            "img@notadigest", // digest without algo:hex
            "repo:BAD/tag",   // tag-looking part actually a path with uppercase
        ] {
            assert!(!valid_reference(bad), "should reject '{bad}'");
        }
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
        // Docker Hub: registry-1.docker.io must trust auth.docker.io (a known, hardcoded pair).
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
        // CRITICAL bypass class - userinfo (`user@host`) with/without a port: curl connects to the
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
        // `#` ends the authority (curl treats it as a fragment) - must not smuggle a foreign host.
        assert!(!realm_host_trusted(
            "https://ghcr.io:0@evil.com#x",
            "ghcr.io"
        ));
        // HACKER-MODE FIX: a same-parent SIBLING is NO LONGER trusted. The old parent-domain rule
        // trusted any `*.acme.com` for a `registry.acme.com` login - a hostile registry on shared
        // hosting could point its realm at an attacker-controlled sibling and harvest the write creds.
        assert!(!realm_host_trusted(
            "https://attacker.acme.com/token",
            "registry.acme.com"
        ));
        assert!(!realm_host_trusted(
            "https://auth.company.co.uk/token",
            "registry.company.co.uk"
        ));
        // A `label.co.uk` registry still must NOT cross-trust another `*.co.uk`.
        assert!(!realm_host_trusted(
            "https://attacker.co.uk/token",
            "myreg.co.uk"
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

    const ARCH_LIST: &str = r#"{"manifests":[
        {"digest":"sha256:aaa","platform":{"architecture":"amd64","os":"linux"}},
        {"digest":"sha256:bbb","platform":{"architecture":"arm64","os":"linux"}},
        {"digest":"sha256:ccc","platform":{"architecture":"unknown","os":"unknown"}}
    ]}"#;

    #[test]
    fn selects_host_arch_from_manifest_list() {
        let want = if Platform::host().arch == "arm64" {
            "sha256:bbb"
        } else {
            "sha256:aaa"
        };
        assert_eq!(
            select_arch_digest(ARCH_LIST, &Platform::host()).as_deref(),
            Some(want)
        );
    }

    #[test]
    fn selects_explicit_arch_regardless_of_host() {
        // An explicit platform picks THAT arch's digest, whatever the host is.
        let arm = Platform::parse("linux/arm64").unwrap();
        assert_eq!(
            select_arch_digest(ARCH_LIST, &arm).as_deref(),
            Some("sha256:bbb")
        );
        let x86 = Platform::parse("amd64").unwrap();
        assert_eq!(
            select_arch_digest(ARCH_LIST, &x86).as_deref(),
            Some("sha256:aaa")
        );
    }

    #[test]
    fn no_matching_arch_returns_none_no_fallback() {
        // A requested arch absent from the index yields None (NOT a wrong-arch fallback) - the pull
        // then errors with the available list. Locks the reviewer-mandated dropped fallback.
        let ppc = Platform {
            os: "linux".into(),
            arch: "ppc64le".into(),
        };
        assert_eq!(select_arch_digest(ARCH_LIST, &ppc), None);
        let avail = available_arches(ARCH_LIST);
        assert!(avail.contains(&"amd64".to_string()) && avail.contains(&"arm64".to_string()));
        assert!(
            !avail.contains(&"unknown".to_string()),
            "unknown is filtered"
        );
    }

    #[test]
    fn platform_parse_forms_and_aliases() {
        assert_eq!(Platform::parse("arm64").unwrap().arch, "arm64");
        assert_eq!(Platform::parse("aarch64").unwrap().arch, "arm64");
        assert_eq!(Platform::parse("linux/amd64").unwrap().arch, "amd64");
        assert_eq!(Platform::parse("x86_64").unwrap().arch, "amd64");
        assert_eq!(Platform::parse("LINUX/ARM64").unwrap().arch, "arm64");
        // variants and non-linux are rejected legibly.
        assert!(Platform::parse("linux/arm/v7").is_err());
        assert!(Platform::parse("windows/amd64").is_err());
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

    #[test]
    fn detect_compression_reads_magic_bytes() {
        let d = std::env::temp_dir().join(format!("kern-comp-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let write = |name: &str, bytes: &[u8]| {
            let p = d.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        };
        assert!(matches!(
            detect_compression(&write("g", &[0x1f, 0x8b, 0x08, 0x00])),
            Compression::Gzip
        ));
        assert!(matches!(
            detect_compression(&write("z", &[0x28, 0xb5, 0x2f, 0xfd])),
            Compression::Zstd
        ));
        // A ustar (uncompressed tar) or anything else → Plain, never a panic.
        assert!(matches!(
            detect_compression(&write("t", b"someth")),
            Compression::Plain
        ));
        // A full 2-byte gzip magic is still detected even in a tiny file.
        assert!(matches!(
            detect_compression(&write("g2", &[0x1f, 0x8b])),
            Compression::Gzip
        ));
        // A truncated (<2-byte) or empty file must not panic and falls to Plain.
        assert!(matches!(
            detect_compression(&write("s", &[0x1f])),
            Compression::Plain
        ));
        assert!(matches!(
            detect_compression(&write("e", &[])),
            Compression::Plain
        ));
        let _ = std::fs::remove_dir_all(&d);
    }

    fn have_zstd() -> bool {
        Command::new("zstd").arg("--version").output().is_ok()
    }

    /// A zstd-compressed layer must pass the SAME vetter as gzip (codec-agnostic hardening): build a
    /// benign tar, zstd-compress it, and confirm `check_layer_safe` accepts it. Skips where `zstd` or
    /// `tar` is absent (edge boards).
    #[test]
    fn zstd_layer_passes_the_vetter() {
        if !have_tar() || !have_zstd() {
            eprintln!("skip: no tar/zstd");
            return;
        }
        let d = std::env::temp_dir().join(format!("kern-zstd-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        std::fs::write(d.join("hello.txt"), b"hi").unwrap();
        // tar the benign file, then zstd it → layer.tar.zst
        let tar_path = d.join("layer.tar");
        assert!(Command::new("tar")
            .args([
                "-cf",
                &tar_path.to_string_lossy(),
                "-C",
                &d.to_string_lossy(),
                "hello.txt"
            ])
            .status()
            .unwrap()
            .success());
        let zst_path = d.join("layer.tar.zst");
        assert!(Command::new("zstd")
            .args([
                "-q",
                "-f",
                &tar_path.to_string_lossy(),
                "-o",
                &zst_path.to_string_lossy()
            ])
            .status()
            .unwrap()
            .success());
        assert!(matches!(detect_compression(&zst_path), Compression::Zstd));
        assert!(check_layer_safe(&zst_path, Compression::Zstd).is_ok());
        let _ = std::fs::remove_dir_all(&d);
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
                check_layer_safe(&evil, Compression::Gzip).is_err(),
                "an absolute-path layer must be rejected"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SECURITY: the layer re-emit pass MUST strip the setuid/setgid bit off a regular file. In a box
    /// the bit is inert (root mount is `MS_NOSUID`) and rootless extraction owns the file, but a `--dest`
    /// tree used OUTSIDE a box, or a `pull` run as real root, must be safe by construction. A benign file
    /// passes through untouched, and the rewritten header keeps a VALID checksum so `tar` still accepts
    /// it - this is a hand-built tar (no external `tar`, fully deterministic).
    #[test]
    fn strip_clears_setuid_and_keeps_a_valid_checksum() {
        // Minimal USTAR block for a regular file with the given name/mode/data, correct checksum.
        fn member(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..107].copy_from_slice(format!("{mode:07o}").as_bytes()); // mode: 7 octal + NUL
            h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes()); // size
            h[156] = b'0'; // regular file
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            h[148..156].fill(b' ');
            let sum: u32 = h.iter().map(|&b| b as u32).sum();
            h[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
            h[154] = 0;
            h[155] = b' ';
            let mut out = h.to_vec();
            out.extend_from_slice(data);
            let rem = data.len() % 512;
            if rem != 0 {
                out.extend(std::iter::repeat_n(0u8, 512 - rem));
            }
            out
        }
        // A 512-byte header's stored checksum equals the value recomputed over the block.
        fn checksum_ok(block: &[u8]) -> bool {
            let Some(stored) = tar_num(&block[148..156]) else {
                return false;
            };
            let mut b = [0u8; 512];
            b.copy_from_slice(&block[..512]);
            b[148..156].fill(b' ');
            let sum: u64 = b.iter().map(|&x| x as u64).sum();
            stored == sum
        }

        let mut input = Vec::new();
        input.extend(member("suid", 0o4755, b"x")); // setuid regular file -> must become 0755
        input.extend(member("plain", 0o0644, b"yy")); // benign -> must pass byte-identical
        input.extend([0u8; 1024]); // end-of-archive

        let mut out = Vec::new();
        strip_device_members(&mut &input[..], &mut out).expect("re-emit must succeed");

        let mode0 = tar_num(&out[100..108]).expect("mode field parses");
        assert_eq!(
            mode0 & 0o7777,
            0o0755,
            "setuid bit must be stripped (4755 -> 0755)"
        );
        assert!(
            checksum_ok(&out[..512]),
            "rewritten header must carry a valid tar checksum, or `tar` rejects the block"
        );

        // Second member starts after the first member's header(512)+data-block(512).
        let second = &out[1024..1536];
        let mode1 = tar_num(&second[100..108]).expect("mode field parses");
        assert_eq!(
            mode1 & 0o7777,
            0o0644,
            "a benign file's mode must be untouched"
        );
        assert!(
            checksum_ok(second),
            "the benign header must keep its original valid checksum"
        );

        // The whole stripped stream must still pass the vetter (a valid, safe tar).
        let tmp = std::env::temp_dir().join(format!("kern-strip-{}.tar", std::process::id()));
        std::fs::write(&tmp, &out).unwrap();
        assert!(
            check_layer_safe(&tmp, Compression::Plain).is_ok(),
            "the stripped tar must re-vet clean"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// SECURITY: merging a layer must never write THROUGH a symlink an earlier layer planted in
    /// the rootfs - the target outside the rootfs must stay untouched.
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

        let _ = merge_layer(&staging, &dest); // may replace or refuse - either way must be safe

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
    /// An OCI whiteout that CANNOT be applied must not pass for one that was.
    ///
    /// `remove_no_follow` returns `()`, so a failed unlink is indistinguishable from a successful
    /// one, and `merge_layer` returns `Ok`. The condition is reachable from a plain image, not a
    /// crafted one: `merge_dir` copies the staging directory's mode onto the destination BEFORE it
    /// recurses into it, so a layer that both makes a directory read-only and deletes a file inside
    /// it removes the caller's write permission on the parent first. The unlink then fails `EACCES`
    /// and the file the image declared deleted stays in the rootfs.
    ///
    /// That matters beyond tidiness: whiteouts are how an image removes a secret, a setuid binary or
    /// a vulnerable library added by an earlier layer. Silently not removing it is the difference
    /// between the rootfs the manifest describes and the rootfs on disk.
    ///
    /// Skipped when the test runs with DAC override (root ignores the directory mode), because there
    /// the precondition cannot be created at all - and a test that cannot fail is not a test.
    #[test]
    fn a_whiteout_that_cannot_be_applied_is_not_reported_as_applied() {
        let base = std::env::temp_dir().join(format!("kern-oci-wh-perm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // Precondition probe: can this uid write into a mode-0555 directory it owns? Root can.
        let probe = base.join("probe");
        std::fs::create_dir_all(&probe).expect("probe dir");
        set_mode(&probe, 0o555);
        let dac_override = std::fs::write(probe.join("x"), b"x").is_ok();
        set_mode(&probe, 0o755);
        if dac_override {
            let _ = std::fs::remove_dir_all(&base);
            return; // running with DAC override: the precondition is not constructible
        }

        // Destination rootfs from an earlier layer: `dir/victim` exists.
        let dest = base.join("dest");
        std::fs::create_dir_all(dest.join("dir")).expect("dest dir");
        std::fs::write(dest.join("dir/victim"), b"secret").expect("victim");

        // The new layer: same directory, made read-only, with a whiteout for `victim`.
        let staging = base.join("stg");
        std::fs::create_dir_all(staging.join("dir")).expect("staging dir");
        std::fs::write(staging.join("dir/.wh.victim"), b"").expect("whiteout marker");
        set_mode(&staging.join("dir"), 0o555);

        let merged = merge_layer(&staging, &dest);

        // Restore write permission before asserting, so the assertion failure path can still clean up.
        // BOTH directories: `staging/dir` is the one this test sets to 0555, and it holds the
        // `.wh.victim` marker. Leaving it read-only made every `remove_dir_all(&base)` below fail
        // with "cannot remove .../stg/dir/.wh.victim: Permission denied" - silently, because each is
        // behind a `let _ =` - so the test left its directory in /tmp on every single run. Measured:
        // six runs, six survivors, and a plain `rm -rf` from a shell could not remove them either.
        set_mode(&dest.join("dir"), 0o755);
        set_mode(&staging.join("dir"), 0o755);
        let survived = dest.join("dir/victim").exists();
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            !survived || merged.is_err(),
            "the whiteout was not applied and merge_layer still returned Ok: the file the image \
             declared deleted is still in the rootfs, and nothing said so"
        );
        assert!(
            !survived,
            "the whiteout must be APPLIED, not merely reported as failed: kern owns the parent \
             directory and can restore its own write permission to complete the unlink"
        );
    }

    /// The deep case the single-level retry does NOT cover, pinned as a behaviour rather than left as
    /// a sentence in a commit message.
    ///
    /// Removing `dir/inner` requires emptying `inner` first, which needs write+search on `inner`
    /// ITSELF, not on its parent. A layer that does `chmod 555 /opt/foo` and a later layer that does
    /// `rm -rf /opt/foo` produces exactly that: a `.wh.foo` whose victim is a directory kern cannot
    /// descend into. Widening only the parent is not enough.
    ///
    /// This is a legitimate image. Docker and containerd extract as root and never meet the case, so
    /// refusing the pull would be a functional regression against them, not a hardening. The removal
    /// therefore repairs permissions as it descends, and this test is the proof that it does.
    #[test]
    fn a_whiteout_of_a_read_only_directory_tree_is_applied() {
        let base = std::env::temp_dir().join(format!("kern-oci-wh-deep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        let probe = base.join("probe");
        std::fs::create_dir_all(&probe).expect("probe dir");
        set_mode(&probe, 0o555);
        let dac_override = std::fs::write(probe.join("x"), b"x").is_ok();
        set_mode(&probe, 0o755);
        if dac_override {
            let _ = std::fs::remove_dir_all(&base);
            return; // DAC override: the precondition cannot be constructed
        }

        // Earlier layer: `dir/inner/{victim,deeper/leaf}`, with BOTH inner levels read-only.
        let dest = base.join("dest");
        std::fs::create_dir_all(dest.join("dir/inner/deeper")).expect("dest tree");
        std::fs::write(dest.join("dir/inner/victim"), b"secret").expect("victim");
        std::fs::write(dest.join("dir/inner/deeper/leaf"), b"secret").expect("leaf");
        // A symlink pointing OUT of the tree: the removal must unlink it, never follow it.
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("keepme"), b"untouched").expect("keepme");
        std::os::unix::fs::symlink(&outside, dest.join("dir/inner/escape")).expect("escape link");
        set_mode(&dest.join("dir/inner/deeper"), 0o555);
        set_mode(&dest.join("dir/inner"), 0o555);

        // New layer: whiteout for the whole `inner` directory.
        let staging = base.join("stg");
        std::fs::create_dir_all(staging.join("dir")).expect("staging dir");
        std::fs::write(staging.join("dir/.wh.inner"), b"").expect("whiteout marker");

        let merged = merge_layer(&staging, &dest);

        // Re-widen whatever survived so the assertions can read, and cleanup can run.
        for p in [
            dest.join("dir/inner/deeper"),
            dest.join("dir/inner"),
            dest.join("dir"),
        ] {
            if p.exists() {
                let _ = std::fs::set_permissions(&p, {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::Permissions::from_mode(0o755)
                });
            }
        }
        let survived = dest.join("dir/inner").exists();
        let escaped = !outside.join("keepme").exists();
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&outside);

        assert!(
            !escaped,
            "the removal followed a symlink out of the rootfs and deleted its target"
        );
        assert!(
            merged.is_ok(),
            "a read-only directory tree is a legitimate image (chmod 555 then rm -rf); refusing the \
             pull would be a regression against docker, which extracts as root: {merged:?}"
        );
        assert!(
            !survived,
            "the whiteout of a read-only directory tree was not applied"
        );
    }

    /// Every mode change in this module must land on the DIRECTORY it names, never on a symlink's
    /// target.
    ///
    /// The paths are built from attacker-supplied layer content, and `std::fs::set_permissions`
    /// follows symlinks, so a planted `dir -> /somewhere/else` would have moved kern's `u+wx` widen
    /// onto a directory outside the image. `merge_dir`'s symlink guard already refuses such paths,
    /// but that is a check-then-use; `DirHandle` closes it structurally with
    /// `O_DIRECTORY | O_NOFOLLOW`, and this pins that.
    #[test]
    fn a_mode_change_never_follows_a_symlink_out_of_the_image() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("kern-oci-chmod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // The victim: a directory OUTSIDE the image, deliberately narrow.
        let victim = base.join("outside");
        std::fs::create_dir_all(&victim).expect("victim dir");
        set_mode(&victim, 0o500);

        // A layer planted `link -> outside` where kern is about to widen a directory.
        let link = base.join("link");
        std::os::unix::fs::symlink(&victim, &link).expect("plant the symlink");

        grant_self_wx(&link);

        let after = std::fs::metadata(&victim)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0);
        // Opening the symlink itself must be refused outright, and a regular file too.
        let opened_link = DirHandle::open(&link).is_some();
        let plain = base.join("plain");
        std::fs::write(&plain, b"x").expect("plain file");
        let opened_file = DirHandle::open(&plain).is_some();
        // A real directory still opens, or the guard would be indistinguishable from a broken open.
        let real = base.join("real");
        std::fs::create_dir_all(&real).expect("real dir");
        let opened_real = DirHandle::open(&real).is_some();

        let _ = std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            after, 0o500,
            "the widen followed the symlink and changed a directory outside the image"
        );
        assert!(!opened_link, "O_NOFOLLOW must refuse a symlink");
        assert!(!opened_file, "O_DIRECTORY must refuse a regular file");
        assert!(
            opened_real,
            "a real directory must still open, or the guard proves nothing"
        );
    }

    /// A registry that says WHY must not be paraphrased into something else.
    ///
    /// Docker Hub answers an over-quota anonymous pull with HTTP 429 and a `TOOMANYREQUESTS` body.
    /// That body carries none of the auth keywords the classifier looked for, so it fell through to
    /// "no layers in manifest" with a hint to check the image name - about an image whose name is
    /// correct. The bodies below are the real ones, captured from Docker Hub and from the OCI
    /// distribution spec's error shape.
    #[test]
    fn a_registry_error_is_reported_as_the_registry_stated_it() {
        let rate = r#"{"errors":[{"code":"TOOMANYREQUESTS","message":"You have reached your unauthenticated pull rate limit. https://www.docker.com/increase-rate-limit"}]}"#;
        let e = manifest_error(rate, "registry-1.docker.io", "library/alpine").to_string();
        assert!(
            e.contains("rate-limiting") && e.contains("kern login"),
            "a 429 must be reported as a rate limit with the way out: {e}"
        );
        assert!(
            !e.contains("no layers in manifest"),
            "a 429 must not be reported as a malformed manifest: {e}"
        );
        assert!(
            e.contains("increase-rate-limit"),
            "the registry's own message carries the limit and its URL; quote it: {e}"
        );

        let unknown = r#"{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}"#;
        let e = manifest_error(unknown, "ghcr.io", "org/app").to_string();
        assert!(
            e.contains("no such manifest"),
            "a MANIFEST_UNKNOWN must say the manifest is absent: {e}"
        );

        // The two pre-existing branches must still behave, or this test would be trading one wrong
        // answer for another.
        let denied = r#"{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}"#;
        let e = manifest_error(denied, "registry-1.docker.io", "private/app").to_string();
        assert!(
            e.contains("kern login"),
            "a denial still points at login: {e}"
        );
        let garbage = "{\"schemaVersion\":2}";
        let e = manifest_error(garbage, "r", "x").to_string();
        assert!(
            e.contains("no layers in manifest"),
            "a manifest with no layers is still exactly that: {e}"
        );
    }

    /// `chmod` helper for the tests above: a mode is set or the test is meaningless, so a failure is
    /// reported rather than ignored.
    fn set_mode(p: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
            .unwrap_or_else(|e| panic!("chmod {:o} on {}: {e}", mode, p.display()));
    }

    /// NOT delete the rootfs's PARENT. Without the guard, `with_file_name("..")` → `<dest>/..` and
    /// `remove_no_follow` would `remove_dir_all` files OUTSIDE the image (other pulled images / store).
    #[test]
    fn whiteout_dotdot_cannot_escape_the_rootfs() {
        let base = std::env::temp_dir().join(format!("kern-oci-wh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dest = base.join("dest");
        std::fs::create_dir_all(&dest).unwrap();
        // A sibling of `dest` - i.e. living under `dest/..` (== base) - that an escape would wipe.
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

    // ---- Raw tar-header vetter unit tests (no external tar; craft bytes in memory) ----

    const BLK: usize = 512;

    /// Build one 512-byte tar header with the given name, typeflag, size, and linkname.
    fn hdr(name: &[u8], typeflag: u8, size: u64, linkname: &[u8]) -> [u8; BLK] {
        let mut h = [0u8; BLK];
        let n = name.len().min(100);
        h[..n].copy_from_slice(&name[..n]);
        // size: 11 octal digits + NUL at [124..136]
        let s = format!("{size:011o}");
        h[124..124 + 11].copy_from_slice(s.as_bytes());
        h[156] = typeflag;
        let l = linkname.len().min(100);
        h[157..157 + l].copy_from_slice(&linkname[..l]);
        h
    }

    /// A data block padded to 512.
    fn data_block(bytes: &[u8]) -> Vec<u8> {
        let mut v = bytes.to_vec();
        let pad = (BLK - v.len() % BLK) % BLK;
        v.extend(vec![0u8; pad]);
        v
    }

    fn end_marker() -> Vec<u8> {
        vec![0u8; BLK * 2]
    }

    /// REGRESSION (CRITICAL, hacker-mode audit): a symlink/hardlink/directory header with a LYING
    /// non-zero size desyncs the vetter from a non-GNU (BusyBox) extractor. The vetter skips `size`
    /// bytes trusting the lie; BusyBox reads them as the next header. So a hidden escaping symlink
    /// (`esc -> /etc/shadow`) rides in the "data" of a size-512 symlink and slips past the escape guard.
    /// The vetter must REJECT a non-zero size on typeflags '1'/'2'/'5' before consuming.
    #[test]
    fn tar_link_or_dir_with_nonzero_size_is_rejected() {
        // Symlink header (typeflag '2', harmless linkname 'safe') with a FALSE size=512, followed by a
        // hidden second symlink header `esc -> /etc/shadow`. Pre-fix the vetter returned Ok (skipping
        // the hidden header); now it must reject the desync.
        for carrier in *b"215" {
            let mut stream = Vec::new();
            stream.extend_from_slice(&hdr(b"safe_looking", carrier, 512, b"safe"));
            stream.extend_from_slice(&hdr(b"esc", b'2', 0, b"/etc/shadow")); // the hidden escaper
            stream.extend(end_marker());
            // On the BusyBox target (gnu_tar=false) the desync is exploitable; reject regardless.
            for gnu in [false, true] {
                let mut r: &[u8] = &stream;
                let res = vet_tar_stream(&mut r);
                assert!(
                    res.is_err(),
                    "carrier {} size!=0 must be rejected (gnu_tar={gnu})",
                    carrier as char
                );
            }
        }
        // A legit symlink (size 0) with a safe target still passes.
        let mut ok = Vec::new();
        ok.extend_from_slice(&hdr(b"link", b'2', 0, b"target"));
        ok.extend(end_marker());
        let mut r: &[u8] = &ok;
        assert!(vet_tar_stream(&mut r).is_ok());
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    }

    /// The device-stripping re-emitter drops char/block device members ('3'/'4') and copies every other
    /// member verbatim, and its output re-vets CLEAN (device-free, structurally valid) - the fail-closed
    /// gate `filter_layer` relies on. This is what lets an image that ships an inert device node
    /// (amazonlinux's base layer) pull while the extractor never sees a device.
    #[test]
    fn strip_drops_devices_keeps_regular_and_revets_clean() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"hello.txt", b'0', 2, b""));
        stream.extend(data_block(b"hi"));
        stream.extend_from_slice(&hdr(b"dev/console", b'3', 0, b"")); // char device -> dropped
        stream.extend_from_slice(&hdr(b"dev/sda", b'4', 0, b"")); // block device -> dropped
        stream.extend_from_slice(&hdr(b"world.txt", b'0', 2, b""));
        stream.extend(data_block(b"yo"));
        stream.extend(end_marker());

        let mut out = Vec::new();
        {
            let mut r: &[u8] = &stream;
            strip_device_members(&mut r, &mut out).expect("strip a well-formed tar");
        }
        assert!(contains(&out, b"hello.txt"), "regular member must survive");
        assert!(contains(&out, b"world.txt"), "regular member must survive");
        assert!(
            !contains(&out, b"dev/console"),
            "char device must be stripped"
        );
        assert!(!contains(&out, b"dev/sda"), "block device must be stripped");
        // The re-emitted tar is device-free and valid, so the UNCHANGED vetter accepts it.
        let mut rr: &[u8] = &out;
        assert!(
            vet_tar_stream(&mut rr).is_ok(),
            "stripped output must re-vet clean"
        );
    }

    /// A device carried by a GNU long-name ('L') record: strip must drop BOTH the device AND the staged
    /// 'L' that named it (no orphan meta), stay byte-synchronized so the following member survives, and
    /// the output must re-vet clean.
    #[test]
    fn strip_drops_longnamed_device_with_its_meta() {
        let longname = vec![b'a'; 160]; // > 100 chars -> needs an L record
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"././@LongLink", b'L', longname.len() as u64, b""));
        stream.extend(data_block(&longname));
        stream.extend_from_slice(&hdr(b"dev/long", b'3', 0, b"")); // the device the L named
        stream.extend_from_slice(&hdr(b"after.txt", b'0', 1, b""));
        stream.extend(data_block(b"z"));
        stream.extend(end_marker());

        let mut out = Vec::new();
        {
            let mut r: &[u8] = &stream;
            strip_device_members(&mut r, &mut out).expect("strip succeeds");
        }
        assert!(
            !contains(&out, &longname),
            "the long-name record naming the device must be dropped, not orphaned"
        );
        assert!(
            contains(&out, b"after.txt"),
            "the following member must survive, in sync"
        );
        let mut rr: &[u8] = &out;
        assert!(
            vet_tar_stream(&mut rr).is_ok(),
            "stripped output re-vets clean"
        );
    }

    /// A device with a LYING non-zero size is a desync attempt: `strip` must refuse it (the re-vet would
    /// too), keeping the parser byte-synchronized rather than skipping attacker-chosen "data".
    #[test]
    fn strip_refuses_device_with_nonzero_size() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"dev/evil", b'3', 512, b"")); // device claiming 512 data bytes
        stream.extend(data_block(&[0x41; 512]));
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        let mut out = Vec::new();
        assert!(
            strip_device_members(&mut r, &mut out).is_err(),
            "a device node with non-zero size must be refused (desync)"
        );
    }

    /// REGRESSION (panic): a PAX record whose `<len>` falls INSIDE a multi-byte UTF-8 sequence must not
    /// panic on a char-boundary slice. `parse_pax` operates on bytes, so this just parses harmlessly.
    #[test]
    fn parse_pax_does_not_panic_on_midchar_len() {
        // "8 path=é" - bytes: 38 20 70 61 74 68 3d c3 a9 ; len=8 lands between the two bytes of 'é'.
        let payload = b"8 path=\xc3\xa9";
        let info = parse_pax(payload); // must not panic
                                       // The declared length truncates the value mid-char; lossy decode yields a replacement - fine,
                                       // the point is it does not crash `kern pull`.
        let _ = info.path;
    }

    /// REGRESSION (GNU sparse, raw): a `typeflag 'S'` member desyncs the vetter from the extractor (its
    /// `size` is the STORED length, not the real data layout) → must be refused, not skipped as regular.
    #[test]
    fn rejects_gnu_sparse_typeflag() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"sparsefile", b'S', 0, b""));
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        let err = format!("{:?}", vet_tar_stream(&mut r).unwrap_err());
        assert!(
            err.contains("sparse"),
            "a GNU sparse ('S') member must be refused, got: {err}"
        );
    }

    /// REGRESSION (multivolume): a `typeflag 'M'` continuation member is likewise a divergence surface.
    #[test]
    fn rejects_multivolume_typeflag() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"contd", b'M', 0, b""));
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        assert!(
            vet_tar_stream(&mut r).is_err(),
            "a multivolume ('M') member must be refused"
        );
    }

    /// REGRESSION (GNU sparse, PAX-encoded): a `GNU.sparse.*` PAX record marks a sparse member even with
    /// a regular typeflag - must be refused via `parse_pax`'s sparse flag.
    #[test]
    fn rejects_pax_encoded_sparse() {
        let mut stream = Vec::new();
        let pax = b"22 GNU.sparse.major=1\n"; // "22" + " " + "GNU.sparse.major=1\n"(19) = 22 bytes
        stream.extend_from_slice(&hdr(b"pax", b'x', pax.len() as u64, b""));
        stream.extend_from_slice(&data_block(pax));
        stream.extend_from_slice(&hdr(b"regular/file", b'0', 0, b""));
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        let err = format!("{:?}", vet_tar_stream(&mut r).unwrap_err());
        assert!(
            err.contains("sparse"),
            "a PAX-encoded sparse member must be refused, got: {err}"
        );
    }

    /// REGRESSION (zero-bomb): an all-zero tail far larger than any legit padding must be REFUSED, not
    /// drained forever (the fix for the early-return bug must not itself become a DoS).
    #[test]
    fn rejects_excessive_zero_padding() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"safe/file", b'0', 0, b""));
        stream.extend_from_slice(&vec![0u8; BLK * 5000]); // 5000 zero blocks » the 4096 cap
        let mut r: &[u8] = &stream;
        let err = format!("{:?}", vet_tar_stream(&mut r).unwrap_err());
        assert!(
            err.contains("zero-bomb"),
            "an unbounded zero tail must be refused, got: {err}"
        );
    }

    /// HARDENING (fail-closed): an unknown/vendor tar typeflag must be refused, not silently treated as
    /// a regular file (whose `size` field we'd then trust and skip).
    #[test]
    fn rejects_unknown_typeflag() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"weird", b'Z', 0, b"")); // 'Z' is not a modelled member type
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        let err = format!("{:?}", vet_tar_stream(&mut r).unwrap_err());
        assert!(
            err.contains("unsupported tar member type"),
            "unknown typeflag must be refused: {err}"
        );
    }

    /// POLICY (documented): a FIFO ('6') is inert toward the host but refused by deliberate policy -
    /// with a SPECIFIC message, not the generic "unsupported type" fallthrough. This test pins the
    /// decision: flipping the policy to accept must be a conscious change that updates this test.
    #[test]
    fn rejects_fifo_by_policy() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"var/run/pipe", b'6', 0, b""));
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        let err = format!("{:?}", vet_tar_stream(&mut r).unwrap_err());
        assert!(
            err.contains("FIFO"),
            "a FIFO must be refused with a specific policy message: {err}"
        );
    }

    /// The modelled member types (dir '5', regular '0', contiguous '7') still pass.
    #[test]
    fn accepts_known_member_typeflags() {
        for tf in *b"057" {
            let mut stream = Vec::new();
            stream.extend_from_slice(&hdr(b"usr/lib/thing", tf, 0, b""));
            stream.extend(end_marker());
            let mut r: &[u8] = &stream;
            assert!(
                vet_tar_stream(&mut r).is_ok(),
                "member typeflag {:?} should be accepted",
                tf as char
            );
        }
    }

    /// A normal short zero-padded tail (a couple of blocks) still passes - no false positive.
    #[test]
    fn accepts_normal_zero_padding() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"safe/file", b'0', 0, b""));
        stream.extend(end_marker()); // two zero blocks - the canonical end marker
        stream.extend_from_slice(&vec![0u8; BLK * 18]); // GNU pads to a 20-block record - legit
        let mut r: &[u8] = &stream;
        assert!(
            vet_tar_stream(&mut r).is_ok(),
            "normal trailing zero padding must pass"
        );
    }

    /// REGRESSION (base-256 wrap): an 11-byte-magnitude base-256 size must be REJECTED, not silently
    /// wrapped to a small u64 (which would desync the byte-skip from extraction).
    #[test]
    fn tar_num_rejects_oversized_base256() {
        let mut f = [0u8; 12];
        f[0] = 0x80; // base-256 flag, magnitude follows
        for b in f.iter_mut().skip(1) {
            *b = 0xff; // huge - far beyond u64
        }
        assert_eq!(
            tar_num(&f),
            None,
            "an oversized base-256 field must be refused, not wrapped"
        );
    }

    /// REGRESSION (L + PAX for one member): setting the path from two sources is ambiguous → reject.
    #[test]
    fn rejects_ambiguous_double_path_source() {
        let mut stream = Vec::new();
        // PAX 'x' with path="../../evil"
        let pax = b"18 path=../../evil\n"; // "18 " + "path=../../evil\n" = 18 bytes
        stream.extend_from_slice(&hdr(b"pax", b'x', pax.len() as u64, b""));
        stream.extend_from_slice(&data_block(pax));
        // GNU 'L' longname="safe" for the SAME member
        let long = b"safe\0";
        stream.extend_from_slice(&hdr(b"long", b'L', long.len() as u64, b""));
        stream.extend_from_slice(&data_block(long));
        // the real member
        stream.extend_from_slice(&hdr(b"placeholder", b'0', 0, b""));
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        assert!(
            vet_tar_stream(&mut r).is_err(),
            "two path sources for one member must be refused, not resolved to the wrong one"
        );
    }

    /// REGRESSION (PAX global path): a sticky global `path`/`linkpath` override is refused ON ITS OWN -
    /// the following member's header name is SAFE, so the ONLY thing that can trip the vetter is the
    /// global override itself (host tar would ignore it and extract the safe header name; a different
    /// tar might honour it - we don't guess, we refuse the archive).
    #[test]
    fn rejects_pax_global_path_override() {
        let mut stream = Vec::new();
        let g = b"13 path=safe\n"; // "13" + " " + "path=safe\n"(10) = 13 bytes total
        stream.extend_from_slice(&hdr(b"pax_global", b'g', g.len() as u64, b""));
        stream.extend_from_slice(&data_block(g));
        stream.extend_from_slice(&hdr(b"usr/bin/app", b'0', 0, b"")); // SAFE header name
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        let err = vet_tar_stream(&mut r).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("global"),
            "must be refused specifically for the global override, got: {msg}"
        );
    }

    /// REGRESSION (early zero-block): a member HIDDEN after a single stray zero block must still be
    /// vetted - we must not stop at the first zero block.
    #[test]
    fn rejects_member_hidden_after_a_zero_block() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"safe/file", b'0', 0, b""));
        stream.extend_from_slice(&[0u8; BLK]); // ONE stray zero block
        stream.extend_from_slice(&hdr(b"../../evil", b'0', 0, b"")); // hidden member after it
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        assert!(
            vet_tar_stream(&mut r).is_err(),
            "a member after a stray zero block must not slip past the vetter"
        );
    }

    /// An absolute hardlink target hardlinks a host inode into the image → always rejected.
    #[test]
    fn rejects_absolute_hardlink_target_raw() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"x link to y", b'1', 0, b"/etc/shadow"));
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        assert!(
            vet_tar_stream(&mut r).is_err(),
            "an absolute hardlink target must be refused (delimiter-in-name class stays dead)"
        );
    }

    /// REGRESSION (hardlink-through-symlink, host-inode escape): a hardlink whose TARGET descends an
    /// escaping symlink recorded earlier in the SAME layer (`a -> /etc`, then hardlink `b -> a/passwd`)
    /// resolves at extraction to host `/etc/passwd` and hardlinks that inode into the rootfs (read =
    /// host disclosure, write = host corruption). The vetter rejected an absolute/`..` hardlink target
    /// but not one that descends an escaping symlink - the same class the member-path check closes for
    /// symlinks, but via the hardlink's target.
    #[test]
    fn rejects_hardlink_through_an_escaping_symlink() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"a", b'2', 0, b"/etc")); // escaping symlink a -> /etc
        stream.extend_from_slice(&hdr(b"b", b'1', 0, b"a/passwd")); // hardlink b -> a/passwd (through a)
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        assert!(
            vet_tar_stream(&mut r).is_err(),
            "a hardlink descending an escaping symlink must be refused (host-inode escape)"
        );
    }

    /// REGRESSION (busybox images): alpine's `/bin/*` and `/usr/bin/*` are ABSOLUTE symlinks to
    /// `/bin/busybox`. The old guard blanket-rejected every escaping symlink target under non-GNU tar,
    /// so `kern box --image alpine` failed on EVERY BusyBox host (the shipped WSL distro, edge Pi/Alpine).
    /// A lone absolute symlink with nothing written through it must now PASS - on GNU tar AND BusyBox.
    #[test]
    fn accepts_absolute_symlinks_with_no_write_through() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"bin", b'5', 0, b"")); // dir
        stream.extend_from_slice(&hdr(b"bin/arch", b'2', 0, b"/bin/busybox")); // alpine applet symlink
        stream.extend_from_slice(&hdr(b"bin/sh", b'2', 0, b"/bin/busybox"));
        stream.extend_from_slice(&hdr(b"bin/busybox", b'0', 0, b"")); // the real binary
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        assert!(
            vet_tar_stream(&mut r).is_ok(),
            "absolute symlinks with no write-through must pass (the alpine regression)"
        );
    }

    #[test]
    fn exposed_ports_parses_proto_dedups_and_skips_garbage() {
        // The pod port-collision warning reads this. tcp/udp both, insertion order, deduplicated.
        let c = parse_image_config(
            r#"{"config":{"ExposedPorts":{"80/tcp":{},"443/tcp":{},"53/udp":{},"80/tcp":{}},"Cmd":["nginx"]}}"#,
        );
        assert_eq!(c.exposed_ports, vec![(80, false), (443, false), (53, true)]);
        // Absent -> empty (the common no-EXPOSE image).
        assert!(parse_image_config(r#"{"config":{"Cmd":["x"]}}"#)
            .exposed_ports
            .is_empty());
        // A garbage key (no `/`, or a port past u16) is SKIPPED, never a panic - the config comes off
        // an untrusted registry.
        let bad = parse_image_config(
            r#"{"config":{"ExposedPorts":{"notaport":{},"70000/tcp":{},"22/tcp":{}}}}"#,
        );
        assert_eq!(bad.exposed_ports, vec![(22, false)]);
    }

    /// SECURITY (the real escape the guard exists for): a symlink whose target escapes the rootfs
    /// (`evil -> /etc`) FOLLOWED by a member that writes THROUGH it (`evil/passwd`) would make a
    /// symlink-following extractor write to `/etc/passwd` on the HOST. Must be refused. Also the
    /// FILE-OVER-SYMLINK variant: a regular file written straight ONTO the escaping symlink path.
    #[test]
    fn rejects_write_through_an_escaping_symlink() {
        // (target, follow-member) - follow descends OR lands on the symlink.
        let cases: &[(&str, &str)] = &[
            ("/etc", "evil/passwd"),       // absolute escape, descend
            ("../../../../etc", "evil/x"), // `..` escape, descend
            ("/etc/cron.d/x", "evil"),     // file written straight onto the escaping symlink
        ];
        for (target, follow) in cases {
            let mut stream = Vec::new();
            stream.extend_from_slice(&hdr(b"evil", b'2', 0, target.as_bytes()));
            stream.extend_from_slice(&hdr(follow.as_bytes(), b'0', 0, b""));
            stream.extend(end_marker());
            let mut r: &[u8] = &stream;
            let res = vet_tar_stream(&mut r);
            assert!(
                res.is_err(),
                "member through an escaping symlink must be refused (target={target}, follow={follow})"
            );
            assert!(
                format!("{:?}", res.unwrap_err()).contains("escaping symlink"),
                "the refusal must name the symlink escape"
            );
        }
    }

    /// SECURITY (audit findings - the subtle bypasses of a naive textual guard). Each of these would
    /// escape on a symlink-following extractor while a first-cut guard passed it. All must be refused.
    #[test]
    fn rejects_symlink_escape_bypasses() {
        // Helper: a symlink member sequence followed by a write, expected to be refused.
        let refuse = |members: &[(&[u8], u8, &[u8])]| {
            let mut stream = Vec::new();
            for (name, tf, link) in members {
                stream.extend_from_slice(&hdr(name, *tf, 0, link));
            }
            stream.extend(end_marker());
            let mut r: &[u8] = &stream;
            assert!(
                vet_tar_stream(&mut r).is_err(),
                "must refuse: {:?}",
                members
                    .iter()
                    .map(|(n, _, _)| String::from_utf8_lossy(n))
                    .collect::<Vec<_>>()
            );
        };
        // CHAIN: b -> a -> /etc, then write through b. `a` escapes (absolute); `b`'s target `a`
        // resolves onto the escaping `a` → `b` escapes too → `b/passwd` refused.
        refuse(&[
            (b"a", b'2', b"/etc"),
            (b"b", b'2', b"a"),
            (b"b/passwd", b'0', b""),
        ]);
        // NORMALIZATION: symlink `a`, write spelled `./a/passwd` / `a//passwd` / `a/./passwd`.
        refuse(&[(b"a", b'2', b"/etc"), (b"./a/passwd", b'0', b"")]);
        refuse(&[(b"a", b'2', b"/etc"), (b"a//passwd", b'0', b"")]);
        refuse(&[(b"a", b'2', b"/etc"), (b"a/./passwd", b'0', b"")]);
        // NORMALIZATION of the SYMLINK name: recorded via a `.`/`//`-spelled name, write plain.
        refuse(&[(b"x/./a", b'2', b"/etc"), (b"x/a/passwd", b'0', b"")]);
        refuse(&[(b"a//b", b'2', b"/etc"), (b"a/b/passwd", b'0', b"")]);
        // SET-CLEARING: a -> /etc, then a dir at `a` (must NOT un-guard), then a/passwd.
        refuse(&[
            (b"a", b'2', b"/etc"),
            (b"a", b'5', b""),
            (b"a/passwd", b'0', b""),
        ]);
        // A symlink UNDER an escaping symlink can't even be created.
        refuse(&[(b"a", b'2', b"/etc"), (b"a/b", b'2', b"whatever")]);
    }

    /// A symlink with a SAFE (in-rootfs) target is NOT escaping, so writing through it stays inside
    /// staging - allowed. A deeper member that does NOT descend an escaping symlink is fine too. And a
    /// CHAIN of safe symlinks (c -> d -> real) stays allowed.
    #[test]
    fn safe_symlink_traversal_and_sibling_writes_pass() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"data", b'2', 0, b"real")); // relative, in-rootfs target
        stream.extend_from_slice(&hdr(b"data/file", b'0', 0, b"")); // writes through a SAFE symlink - ok
        stream.extend_from_slice(&hdr(b"d", b'2', 0, b"real2")); // safe
        stream.extend_from_slice(&hdr(b"c", b'2', 0, b"d")); // safe chain c -> d -> real2
        stream.extend_from_slice(&hdr(b"c/x", b'0', 0, b"")); // through a safe chain - ok
        stream.extend_from_slice(&hdr(b"lib", b'2', 0, b"/usr/lib")); // escaping symlink…
        stream.extend_from_slice(&hdr(b"libexec/tool", b'0', 0, b"")); // …but this does NOT descend it
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        assert!(
            vet_tar_stream(&mut r).is_ok(),
            "safe-symlink traversal, safe chains, and non-descending writes must pass"
        );
    }

    /// A plain, well-formed member stream is accepted.
    #[test]
    fn accepts_a_clean_raw_stream() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&hdr(b"usr/bin/app", b'0', 5, b""));
        stream.extend_from_slice(&data_block(b"hello"));
        stream.extend_from_slice(&hdr(b"etc/ssl/cert.pem", b'2', 0, b"/etc/ssl/real.pem"));
        stream.extend(end_marker());
        let mut r: &[u8] = &stream;
        assert!(
            vet_tar_stream(&mut r).is_ok(),
            "a normal member stream (incl. an absolute symlink target) should pass"
        );
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
                check_layer_safe(&good, Compression::Gzip).is_ok(),
                "a normal layer should pass"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
