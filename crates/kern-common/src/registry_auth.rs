//! Registry credentials shared by `kern login`/`logout` (which write them) and the OCI pull path
//! (which reads them). Stored as a single owner-only (`0600`) file, one `registry <base64(user:pass)>`
//! line per registry — the same base64 encoding Docker's `config.json` uses (obfuscation, not
//! encryption: it keeps the password off a casual `cat`/shoulder-surf, and the `0600` mode plus the
//! owner-only config dir are the real protection).

use std::path::PathBuf;

/// The credentials file: `$XDG_CONFIG_HOME/kern/registry-auth` → `$HOME/.config/kern/registry-auth`.
pub fn creds_path() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(x).join("kern").join("registry-auth"));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/kern/registry-auth"))
}

/// Store `user`/`pass` for `registry` (replacing any existing entry). Writes the file `0600`.
///
/// Rejects a control character in any field (a newline in `user`/`pass` would otherwise survive the
/// base64 round-trip and later inject a directive into the curl `-K` config; whitespace in `registry`
/// would corrupt the line format `line_registry` parses). The parent config dir is created `0700`.
pub fn store(registry: &str, user: &str, pass: &str) -> std::io::Result<()> {
    let bad = |c: char| c.is_control();
    if registry.is_empty() || registry.chars().any(|c| bad(c) || c.is_whitespace()) {
        return Err(invalid(
            "registry name has whitespace or control characters",
        ));
    }
    if user.chars().any(bad) || pass.chars().any(bad) {
        return Err(invalid("username/password has control characters"));
    }
    let path = creds_path().ok_or_else(|| std::io::Error::other("no config dir (set $HOME)"))?;
    if let Some(parent) = path.parent() {
        // 0700 — the file mode protects the secret bytes, but the dir being owner-only keeps even the
        // *list* of registries you have credentials for private (parity with `~/.docker`).
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let enc = b64_encode(format!("{user}:{pass}").as_bytes());
    let mut lines: Vec<String> = read_lines(&path)
        .into_iter()
        .filter(|l| line_registry(l) != Some(registry))
        .collect();
    lines.push(format!("{registry} {enc}"));
    write_0600(&path, &lines.join("\n"))
}

fn invalid(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
}

/// Remove `registry`'s entry. Returns whether an entry was present.
pub fn remove(registry: &str) -> std::io::Result<bool> {
    let Some(path) = creds_path() else {
        return Ok(false);
    };
    let before = read_lines(&path);
    let after: Vec<String> = before
        .iter()
        .filter(|l| line_registry(l) != Some(registry))
        .cloned()
        .collect();
    let removed = after.len() != before.len();
    if removed {
        write_0600(&path, &after.join("\n"))?;
    }
    Ok(removed)
}

/// Look up `(user, pass)` for `registry`, or `None` if not logged in / unreadable.
pub fn lookup(registry: &str) -> Option<(String, String)> {
    let path = creds_path()?;
    for line in read_lines(&path) {
        if line_registry(&line) == Some(registry) {
            let enc = line.split_whitespace().nth(1)?;
            let decoded = String::from_utf8(b64_decode(enc)?).ok()?;
            let (u, p) = decoded.split_once(':')?;
            return Some((u.to_string(), p.to_string()));
        }
    }
    None
}

fn line_registry(line: &str) -> Option<&str> {
    let l = line.trim();
    (!l.is_empty())
        .then(|| l.split_whitespace().next())
        .flatten()
}

fn read_lines(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|s| {
            s.lines()
                .map(str::to_string)
                .filter(|l| !l.trim().is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn write_0600(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // `mode(0o600)` applies only when the file is *created*; re-assert it so a pre-existing
    // credentials file that was restored/synced with looser perms (0644) is tightened to 0600.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(body.as_bytes())?;
    if !body.is_empty() {
        f.write_all(b"\n")?;
    }
    Ok(())
}

// ── base64 (standard alphabet, with padding) — tiny, dependency-free ──

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|&c| c != b'=' && !c.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        for s in [
            "",
            "a",
            "ab",
            "abc",
            "abcd",
            "user:p@ss:w0rd",
            "hello world!",
        ] {
            let enc = b64_encode(s.as_bytes());
            assert_eq!(b64_decode(&enc).unwrap(), s.as_bytes(), "roundtrip {s:?}");
        }
        // A known vector.
        assert_eq!(b64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn line_registry_parsing() {
        assert_eq!(
            line_registry("registry-1.docker.io dXNlcjpwYXNz"),
            Some("registry-1.docker.io")
        );
        assert_eq!(line_registry("  "), None);
    }

    #[test]
    fn store_rejects_bad_fields_before_touching_disk() {
        // Validation runs before any filesystem access, so these fail regardless of $HOME.
        assert!(store("has space", "u", "p").is_err()); // whitespace in registry
        assert!(store("reg", "u\nx", "p").is_err()); // newline in username → config injection
        assert!(store("reg", "u", "p\rx").is_err()); // CR in password
        assert!(store("", "u", "p").is_err()); // empty registry
    }
}
