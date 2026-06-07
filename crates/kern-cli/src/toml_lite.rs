//! The tiny TOML-ish value readers shared by the `kern.toml` profile loader (`config`) and the
//! `compose` file parser. Both parse the same quoted-string / bool / `[...]` array / `#` comment
//! syntax, so keeping ONE definition here stops the two from drifting into subtly different rules.

/// Everything before an unquoted `#` (a comment). A `#` inside a `"..."` string is kept — values are
/// quoted, so a `#` in a value is safe.
pub(crate) fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

/// A double-quoted string value → its contents (the surrounding quotes removed).
pub(crate) fn quoted_string(v: &str) -> Result<String, String> {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        Ok(v[1..v.len() - 1].to_string())
    } else {
        Err(format!("expected a quoted string, got `{v}`"))
    }
}

/// A `true`/`false` literal.
pub(crate) fn parse_bool(v: &str) -> Result<bool, String> {
    match v.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("expected `true` or `false`, got `{other}`")),
    }
}

/// Split on top-level commas — a comma inside a `"..."` string (escape-aware) does not split. Items
/// are returned verbatim (untrimmed); a trailing whitespace-only item is dropped.
pub(crate) fn split_top_commas(s: &str) -> Vec<String> {
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
pub(crate) fn string_array(v: &str) -> Result<Vec<String>, String> {
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
