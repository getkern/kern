//! The one place kern shells out to `curl`. Keeping HTTP in a single helper (rather than a
//! dependency) is the project's "zero deps beyond libc/curl/tar" rule; [`crate::pull`] and
//! [`crate::search`] both go through here.

use crate::OciError;
use std::process::Command;

/// Run `curl <args>` and return stdout, or an `OciError::Tool` on a non-zero exit.
pub(crate) fn curl(args: &[&str]) -> Result<Vec<u8>, OciError> {
    let out = Command::new("curl")
        .args(args)
        .output()
        .map_err(|e| OciError::Tool("curl", e.to_string()))?;
    if !out.status.success() {
        return Err(OciError::Tool(
            "curl",
            format!(
                "exit {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ),
        ));
    }
    Ok(out.stdout)
}

/// Run `curl <args>` with extra options fed through **stdin** (`curl -K -`), returning stdout. Used
/// to pass registry credentials (`user = "u:p"`) WITHOUT putting the password in `curl`'s argv, where
/// any same-uid process could read it from `/proc/<pid>/cmdline`. `config` is curl's `-K` config-file
/// syntax.
pub(crate) fn curl_with_config(args: &[&str], config: &str) -> Result<Vec<u8>, OciError> {
    use std::io::Write;
    use std::process::Stdio;
    // `-K -` goes FIRST, before `args`: a caller's args may end with `-- <url>`, and anything after
    // `--` is treated as a URL, so a trailing `-K -` would be misread as URLs ("Protocol http…").
    let mut child = Command::new("curl")
        .arg("-K")
        .arg("-") // read additional config from stdin
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| OciError::Tool("curl", e.to_string()))?;
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(config.as_bytes());
        // drop closes stdin → curl proceeds
    }
    let out = child
        .wait_with_output()
        .map_err(|e| OciError::Tool("curl", e.to_string()))?;
    if !out.status.success() {
        return Err(OciError::Tool(
            "curl",
            format!(
                "exit {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ),
        ));
    }
    Ok(out.stdout)
}

/// Fetch just the response **headers** for `url` (body discarded), so the caller can read a
/// registry's `WWW-Authenticate` challenge and status line. https-only and does NOT follow
/// redirects (`-L` absent) — the `401` challenge is on the direct response, and a non-2xx status is
/// still a successful curl run (no `-f`), so it's returned rather than raised as an error.
pub(crate) fn head_headers(url: &str) -> Result<String, OciError> {
    let body = curl(&[
        "-sS",
        "--proto",
        "=https",
        "--max-filesize",
        "1000000", // headers only — cap so a hostile registry can't stream an endless body at us
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "-o",
        "/dev/null", // discard the body
        "-D",
        "-", // dump response headers to stdout
        "--",
        url,
    ])?;
    String::from_utf8(body).map_err(|_| OciError::Registry("non-UTF-8 headers".into()))
}

/// A plain `GET <url>` returning the body as a UTF-8 string — for small JSON APIs (Hub search).
/// Silent (`-s`), surfaces errors (`-S`), follows redirects (`-L`), bounded timeouts.
pub(crate) fn get(url: &str) -> Result<String, OciError> {
    let body = curl(&[
        "-sSL",
        "--proto",
        "=https", // the request itself must be https
        "--proto-redir",
        "=https", // …and every redirect too — no `file://`/`http://` SSRF via a hostile redirect
        "--max-redirs",
        "5",
        "--max-filesize",
        "8000000", // cap the response at ~8 MB (registry JSON is tiny) so a huge body can't OOM us
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--", // never treat a URL starting with `-` as a flag
        url,
    ])?;
    String::from_utf8(body).map_err(|_| OciError::Registry("non-UTF-8 response".into()))
}
