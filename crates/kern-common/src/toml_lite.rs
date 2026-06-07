//! The tiny TOML-ish value readers shared by the `kern.toml` profile loader (`config`) and the
//! `compose` file parser. Both parse the same quoted-string / bool / `[...]` array / `#` comment
//! syntax, so keeping ONE definition here stops the two from drifting into subtly different rules.
//!
//! Lives in `kern-common` (not the CLI) so the `kern-compose` parser crate — which is CLI-free so it
//! can be fuzzed in isolation — and the CLI's `config` loader share the exact same scanners.

/// Everything before an unquoted `#` (a comment). A `#` inside a `"..."` string is kept — values are
/// quoted, so a `#` in a value is safe. Escape-aware, exactly like `split_top_commas`: a `\"` inside a
/// string does NOT close it (otherwise `command = ["say \" #hi"]` would have its `#` mis-stripped and
/// the truncated value would fail to parse). The two scanners MUST agree on string boundaries.
pub fn strip_comment(line: &str) -> &str {
    let (mut in_str, mut esc) = (false, false);
    for (i, c) in line.char_indices() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '#' {
            return &line[..i];
        }
    }
    line
}

/// A double-quoted string value → its contents (the surrounding quotes removed).
pub fn quoted_string(v: &str) -> Result<String, String> {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        Ok(v[1..v.len() - 1].to_string())
    } else {
        Err(format!("expected a quoted string, got `{v}`"))
    }
}

/// A `true`/`false` literal.
pub fn parse_bool(v: &str) -> Result<bool, String> {
    match v.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("expected `true` or `false`, got `{other}`")),
    }
}

/// Split on top-level commas — a comma inside a `"..."` string (escape-aware) does not split. Items
/// are returned verbatim (untrimmed); a trailing whitespace-only item is dropped.
pub fn split_top_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut in_str, mut esc) = (false, false);
    for c in s.chars() {
        if in_str {
            cur.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            cur.push(c);
        } else if c == ',' {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// A `["a", "b"]` array of quoted strings → the unquoted contents (empty items skipped).
pub fn string_array(v: &str) -> Result<Vec<String>, String> {
    let v = v.trim();
    let inner = v
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("expected an array `[...]`, got `{v}`"))?;
    split_top_commas(inner)
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(quoted_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_comment_keeps_escaped_quote_before_hash() {
        // Regression: `\"` must not close the string, so the trailing `#` stays part of the value.
        assert_eq!(
            strip_comment(r#"command = ["say \" #hi"]"#),
            r#"command = ["say \" #hi"]"#
        );
        // An unquoted # is still a comment.
        assert_eq!(strip_comment(r#"x = "v"  # note"#).trim_end(), r#"x = "v""#);
        // A # inside a normal quoted value is kept.
        assert_eq!(strip_comment(r##"x = "a#b""##), r##"x = "a#b""##);
    }
}
