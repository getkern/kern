//! Local image archive — `kern save` / `kern load`, the offline dual of push/pull. `save` writes a
//! `docker save`-compatible tar of a cached (single-layer) image; `load` imports such a tar — produced
//! by kern OR by `docker save` — for offline / air-gapped transfer.
//!
//! SECURITY: a loaded archive is **untrusted** exactly like a registry pull. `load` therefore routes
//! every tar it touches (the outer archive AND each layer.tar) through the SAME hardened path pull
//! uses — [`check_layer_safe`] (in-process header vetting: no setuid, no device nodes, no `..`/symlink
//! escape, 2 GiB bomb + entry-count caps) and, for layers, isolated-staging extraction + no-follow
//! [`merge_layer`]. There is no naive `tar -xf` on attacker bytes anywhere here.

use crate::pull::{
    check_layer_safe, detect_compression, merge_layer, unpack_as_root, Compression, ImageConfig,
};
use crate::push::{build_config_json, sha256_file, shell_quote, ImageConfigOut};
use crate::OciError;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// One image recovered from an archive: its tags, the assembled rootfs dir, and its runtime config.
pub struct Loaded {
    pub repo_tags: Vec<String>,
    pub rootfs: PathBuf,
    pub config: ImageConfig,
}

/// The hex part of a `sha256:<hex>` digest (for use as an in-archive filename).
fn hex_of(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

/// Minimal JSON string quoting (kern-oci is serde-free) — shared with the push manifest builder shape.
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if c.is_control() => o.push_str(&format!("\\u{:04x}", c as u32)),
            _ => o.push(c),
        }
    }
    o.push('"');
    o
}

// ── save ────────────────────────────────────────────────────────────────────────────────────────

/// Write a `docker save`-compatible archive of the single-layer image at `rootfs` (runtime `config`,
/// tagged `repo_tags`) to `out` (a file, or stdout when `None`). `work` is a caller-owned scratch dir.
pub fn save(
    rootfs: &Path,
    config: &ImageConfigOut,
    repo_tags: &[String],
    out: Option<&Path>,
    work: &Path,
) -> Result<(), OciError> {
    // 1. Pack the rootfs into an UNCOMPRESSED layer.tar (root-owned, setuid-stripped — same
    //    normalization as push), and take its sha256 (= the layer's diff_id).
    let layer_tar = work.join("layer.tar");
    pack_plain_layer(rootfs, &layer_tar)?;
    let diff_id = sha256_file(&layer_tar)?;
    let layer_id = hex_of(&diff_id).to_string();

    // 2. Config JSON (reused from the push builder) + its digest → `<confhex>.json`.
    let config_json = build_config_json(config, &diff_id);
    let conf_digest = sha256_bytes(config_json.as_bytes());
    let conf_name = format!("{}.json", hex_of(&conf_digest));

    // 3. Lay the docker-archive tree out under `work/layout`: `<confhex>.json`, `<layerid>/layer.tar`,
    //    `manifest.json`. Single layer (kern images are flattened).
    let layout = work.join("layout");
    let _ = std::fs::remove_dir_all(&layout);
    std::fs::create_dir_all(layout.join(&layer_id))
        .map_err(|e| OciError::Extract(format!("save layout: {e}")))?;
    std::fs::rename(&layer_tar, layout.join(&layer_id).join("layer.tar"))
        .map_err(|e| OciError::Extract(format!("save layer: {e}")))?;
    std::fs::write(layout.join(&conf_name), &config_json)
        .map_err(|e| OciError::Extract(format!("save config: {e}")))?;
    let tags_json = repo_tags.iter().map(|t| jstr(t)).collect::<Vec<_>>().join(",");
    let manifest = format!(
        "[{{\"Config\":{},\"RepoTags\":[{}],\"Layers\":[{}]}}]",
        jstr(&conf_name),
        tags_json,
        jstr(&format!("{layer_id}/layer.tar")),
    );
    std::fs::write(layout.join("manifest.json"), manifest)
        .map_err(|e| OciError::Extract(format!("save manifest: {e}")))?;

    // 4. Tar the layout to the destination (file or stdout). No compression — `docker save`'s default;
    //    the caller can pipe through gzip/zstd if they want a smaller file.
    let layout_s = layout.to_string_lossy().into_owned();
    let status = match out {
        Some(p) => Command::new("tar")
            .args(["-cf"])
            .arg(p)
            .args(["-C", &layout_s, "."])
            .status(),
        None => Command::new("tar")
            .args(["-cf", "-", "-C", &layout_s, "."])
            .status(),
    }
    .map_err(|e| OciError::Tool("tar", e.to_string()))?;
    let _ = std::fs::remove_dir_all(&layout);
    if !status.success() {
        return Err(OciError::Extract("tar of the archive failed".into()));
    }
    Ok(())
}

/// Tar `rootfs` into `out` (uncompressed), root-owned and setuid/setgid-stripped — the exact ownership
/// normalization the push layer packer applies (a preserved setuid bit + `--owner=0` would forge a
/// setuid-root binary in the exported image).
fn pack_plain_layer(rootfs: &Path, out: &Path) -> Result<(), OciError> {
    let stripped = Command::new("find")
        .arg(rootfs)
        .args(["-type", "f", "-perm", "/6000", "-exec", "chmod", "a-s", "{}", "+"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !stripped {
        return Err(OciError::Extract("stripping setuid before save failed".into()));
    }
    let ok = Command::new("tar")
        .args(["-C"])
        .arg(rootfs)
        .args(["--numeric-owner", "--owner=0", "--group=0", "-cf"])
        .arg(out)
        .arg(".")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(OciError::Extract("tar of rootfs failed".into()))
    }
}

/// sha256 of an in-memory byte slice → `sha256:<hex>`, via `sha256sum` (coreutils).
fn sha256_bytes(bytes: &[u8]) -> String {
    use std::io::Write;
    const ZERO: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let Ok(mut child) = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    else {
        return ZERO.into(); // shouldn't happen — sha256sum is a coreutils staple used across kern-oci
    };
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(bytes);
    }
    if let Ok(out) = child.wait_with_output() {
        let hex = String::from_utf8_lossy(&out.stdout);
        if let Some(h) = hex.split_whitespace().next() {
            if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                return format!("sha256:{h}");
            }
        }
    }
    ZERO.into()
}

// ── load ────────────────────────────────────────────────────────────────────────────────────────

/// Import a `docker save`-format archive from `src` (a file, or stdin when `None`), returning one
/// [`Loaded`] per image. Every tar (outer + each layer) is vetted by [`check_layer_safe`] before any
/// extraction, and layers are merged no-follow — an archive is as untrusted as a registry pull.
pub fn load(src: Option<&Path>, work: &Path) -> Result<Vec<Loaded>, OciError> {
    std::fs::create_dir_all(work).map_err(|e| OciError::Extract(format!("load work: {e}")))?;
    // Materialize the archive to a file (stdin → a temp file, so we can vet it before extracting).
    let archive = match src {
        Some(p) => p.to_path_buf(),
        None => {
            let dst = work.join("stdin.tar");
            let f = std::fs::File::create(&dst)
                .map_err(|e| OciError::Extract(format!("load stdin: {e}")))?;
            let ok = Command::new("cat")
                .stdout(f)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                return Err(OciError::Extract("reading the archive from stdin failed".into()));
            }
            dst
        }
    };

    // VET then extract the OUTER archive (json + layer tars — regular files, no privileged modes, so
    // no `unpack_as_root` needed here; the LAYERS get the privileged path below).
    check_layer_safe(&archive, Compression::Plain)?;
    let unpacked = work.join("unpacked");
    std::fs::create_dir_all(&unpacked).map_err(|e| OciError::Extract(e.to_string()))?;
    let ok = Command::new("tar")
        .args(["-xf"])
        .arg(&archive)
        .args(["-C"])
        .arg(&unpacked)
        .args(["--no-same-owner"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return Err(OciError::Extract("extracting the archive failed".into()));
    }

    let manifest = std::fs::read_to_string(unpacked.join("manifest.json")).map_err(|_| {
        OciError::Extract("not a docker-save archive (no manifest.json)".into())
    })?;

    let mut out = Vec::new();
    for (i, obj) in crate::json::split_objects(&manifest).into_iter().enumerate() {
        let config_rel =
            str_field(obj, "Config").ok_or_else(|| OciError::Extract("manifest: no Config".into()))?;
        let repo_tags = crate::json::str_array_after(obj, "RepoTags");
        let layers = crate::json::str_array_after(obj, "Layers");
        if layers.is_empty() {
            return Err(OciError::Extract("manifest: image has no layers".into()));
        }
        // Resolve each in-archive path SAFELY under `unpacked` (reject any `..`/absolute escape — the
        // manifest is attacker-controlled just like the tar members).
        let config_path = under(&unpacked, &config_rel)?;
        let config_json = std::fs::read_to_string(&config_path)
            .map_err(|e| OciError::Extract(format!("load config: {e}")))?;
        let config = parse_image_config(&config_json);

        // Build the rootfs by merging the layers in order, each through the hardened path.
        let rootfs = work.join(format!("rootfs-{i}"));
        std::fs::create_dir_all(&rootfs).map_err(|e| OciError::Extract(e.to_string()))?;
        for (j, layer_rel) in layers.iter().enumerate() {
            let layer = under(&unpacked, layer_rel)?;
            let comp = detect_compression(&layer);
            check_layer_safe(&layer, comp)?; // vet in the parent (detailed errors, no privilege)
            let staging = work.join(format!("stg-{i}-{j}"));
            let rootfs_c = rootfs.clone();
            let layer_c = layer.clone();
            let staging_c = staging.clone();
            unpack_as_root(move || {
                extract_into(&layer_c, comp, &staging_c)?;
                let r = merge_layer(&staging_c, &rootfs_c);
                let _ = std::fs::remove_dir_all(&staging_c);
                r
            })?;
        }
        out.push(Loaded {
            repo_tags,
            rootfs,
            config,
        });
    }
    Ok(out)
}

/// Extract a vetted layer tar (compression `comp`) into a FRESH `staging` dir, preserving the image's
/// exact modes and mapping ownership to the (in-ns root) extracting user — the same tar invocation
/// pull uses for a registry layer. Caller runs this inside [`unpack_as_root`].
fn extract_into(layer: &Path, comp: Compression, staging: &Path) -> Result<(), OciError> {
    let _ = std::fs::remove_dir_all(staging);
    std::fs::create_dir_all(staging).map_err(|e| OciError::Extract(e.to_string()))?;
    let staging_s = staging.to_string_lossy().into_owned();
    let ok = match comp {
        Compression::Gzip | Compression::Plain => {
            let flag = if matches!(comp, Compression::Gzip) {
                "-xzf"
            } else {
                "-xf"
            };
            Command::new("tar")
                .args([flag])
                .arg(layer)
                .args(["-C", &staging_s, "--no-same-owner", "--same-permissions"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
        Compression::Zstd => {
            // Same `zstd -dc | tar -xf -` shape as pull's zstd path (busybox/musl `tar --zstd` gaps).
            Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "zstd -dc -- {} | tar -xf - -C {} --no-same-owner --same-permissions",
                    shell_quote(&layer.to_string_lossy()),
                    shell_quote(&staging_s),
                ))
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }
    };
    if ok {
        Ok(())
    } else {
        let _ = std::fs::remove_dir_all(staging);
        Err(OciError::Extract("layer extraction failed".into()))
    }
}

/// Resolve `rel` (a manifest-supplied, UNTRUSTED path) under `base`, rejecting any component that
/// would escape (`..`, absolute, or a symlink pointing out). Belt-and-suspenders on top of the outer
/// `check_layer_safe`: the manifest's `Config`/`Layers` strings are attacker-controlled too.
fn under(base: &Path, rel: &str) -> Result<PathBuf, OciError> {
    if rel.starts_with('/') || rel.split('/').any(|c| c == ".." || c == ".") || rel.is_empty() {
        return Err(OciError::Extract(format!("unsafe archive path '{rel}'")));
    }
    let p = base.join(rel);
    // The file must exist AND its canonical path must stay under the canonical base (no symlink hop).
    let (cbase, cp) = (
        std::fs::canonicalize(base).map_err(|e| OciError::Extract(e.to_string()))?,
        std::fs::canonicalize(&p)
            .map_err(|_| OciError::Extract(format!("archive path missing: '{rel}'")))?,
    );
    if cp.starts_with(&cbase) {
        Ok(cp)
    } else {
        Err(OciError::Extract(format!("archive path escapes: '{rel}'")))
    }
}

/// Parse an OCI/Docker image `config.json` into the runtime [`ImageConfig`] (Env/Cmd/Entrypoint/
/// WorkingDir/User under the nested `"config"` object). Missing fields default; a garbled config
/// yields an empty config rather than failing the load (the rootfs is still usable).
fn parse_image_config(json: &str) -> ImageConfig {
    let cfg = crate::json::object_after(json, "config").unwrap_or(json);
    ImageConfig {
        entrypoint: crate::json::str_array_after(cfg, "Entrypoint"),
        cmd: crate::json::str_array_after(cfg, "Cmd"),
        env: crate::json::str_array_after(cfg, "Env"),
        workdir: str_field(cfg, "WorkingDir").filter(|s| !s.is_empty()),
        user: str_field(cfg, "User").filter(|s| !s.is_empty()),
    }
}

/// The string value of `"key"` in `json` (first occurrence), or `None`.
fn str_field(json: &str, key: &str) -> Option<String> {
    let pos = json.find(&format!("\"{key}\""))?;
    crate::json::value_after_colon(&json[pos..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_rejects_traversal_and_absolute() {
        let base = std::env::temp_dir();
        assert!(under(&base, "../etc/passwd").is_err());
        assert!(under(&base, "/etc/passwd").is_err());
        assert!(under(&base, "a/../../b").is_err());
        assert!(under(&base, "").is_err());
    }

    #[test]
    fn parse_config_extracts_runtime_fields() {
        let json = r#"{"architecture":"amd64","os":"linux","config":{"Env":["A=1","B=2"],"Entrypoint":["/bin/sh"],"Cmd":["-c","echo hi"],"WorkingDir":"/app","User":"1000"},"rootfs":{"type":"layers","diff_ids":["sha256:x"]}}"#;
        let c = parse_image_config(json);
        assert_eq!(c.env, vec!["A=1", "B=2"]);
        assert_eq!(c.entrypoint, vec!["/bin/sh"]);
        assert_eq!(c.cmd, vec!["-c", "echo hi"]);
        assert_eq!(c.workdir.as_deref(), Some("/app"));
        assert_eq!(c.user.as_deref(), Some("1000"));
        // an empty/garbled config → empty runtime config, not a panic.
        assert!(parse_image_config("{}").entrypoint.is_empty());
    }

    #[test]
    fn hex_of_strips_prefix() {
        assert_eq!(hex_of("sha256:abc123"), "abc123");
        assert_eq!(hex_of("abc123"), "abc123");
    }
}
