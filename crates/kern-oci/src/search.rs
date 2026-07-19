//! Search Docker Hub for images - the backend of `kern search`. Uses the stable v1 search
//! endpoint that `docker search` itself uses (no auth, public repositories), so the set of
//! discoverable images is exactly Docker's.

use crate::json::{array_after, bool_field, first_str, split_objects, u64_field};
use crate::{net, OciError};

/// One Docker Hub search hit.
pub struct SearchResult {
    /// Repository name (`nginx`, `bitnami/postgresql`, …) - what you pass to `kern pull`.
    pub name: String,
    pub description: String,
    pub stars: u64,
    /// A Docker "official image" (the curated `library/*` set).
    pub official: bool,
}

/// Search Docker Hub for `query`, returning up to `limit` hits in the registry's order
/// (most-relevant first). Errors on an empty query or a network/parse failure.
pub fn search(query: &str, limit: usize) -> Result<Vec<SearchResult>, OciError> {
    if query.trim().is_empty() {
        return Err(OciError::Registry("empty search query".into()));
    }
    let url = format!(
        "https://index.docker.io/v1/search?q={}&n={}",
        urlencode(query),
        limit.clamp(1, 100)
    );
    let body = net::get(&url)?;
    let arr = array_after(&body, "results")
        .ok_or_else(|| OciError::Registry("unexpected search response (no results)".into()))?;
    let mut out = Vec::new();
    for obj in split_objects(arr) {
        let Some(name) = first_str(obj, "name") else {
            continue;
        };
        out.push(SearchResult {
            name,
            description: first_str(obj, "description").unwrap_or_default(),
            stars: u64_field(obj, "star_count").unwrap_or(0),
            official: bool_field(obj, "is_official").unwrap_or(false),
        });
    }
    Ok(out)
}

/// Percent-encode a search term for a query string: `alnum` and `-._~` pass through, everything
/// else (space, `/`, …) becomes `%XX`. Enough for image search terms; avoids a URL-lib dependency.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::urlencode;

    #[test]
    fn urlencode_escapes_specials() {
        assert_eq!(urlencode("nginx"), "nginx");
        assert_eq!(urlencode("a b/c"), "a%20b%2Fc");
        assert_eq!(urlencode("py.3-x_y~z"), "py.3-x_y~z");
    }
}
