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
