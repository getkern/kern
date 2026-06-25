//! A tiny, dependency-free JSON reader — just enough to walk the registry's manifests and Docker
//! Hub's search response. Not a general parser: it finds keys/arrays/objects by string scanning,
//! which is sound for the well-formed, machine-generated JSON these APIs return. Shared by
//! [`crate::pull`] and [`crate::search`] so there is one string-scanner, not two.

/// Index of the `close` byte matching the `open` byte at `open_idx`, skipping bytes inside JSON
/// strings (so brackets in string values don't confuse nesting). `None` if unbalanced.
pub(crate) fn matching_bracket(s: &str, open_idx: usize, open: u8, close: u8) -> Option<usize> {
    let b = s.as_bytes();
    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for (i, &c) in b.iter().enumerate().skip(open_idx) {
        if in_str {
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// The `[...]` array (inclusive) following `"key"`.
pub(crate) fn array_after<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let k = json.find(&format!("\"{key}\""))?;
    let open = json[k..].find('[')? + k;
    let close = matching_bracket(json, open, b'[', b']')?;
    Some(&json[open..=close])
}

/// Split a `[...]` array into its top-level `{...}` objects.
pub(crate) fn split_objects(arr: &str) -> Vec<&str> {
    let b = arr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'{' {
            if let Some(end) = matching_bracket(arr, i, b'{', b'}') {
                out.push(&arr[i..=end]);
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// The next JSON string value after the first `:` in `s`, properly **unescaped** and
/// **escape-aware** (a `\"` inside the value doesn't end it). Only valid for STRING-valued keys —
/// for a numeric value use [`u64_field`]. Surrogate-pair `\uXXXX` (non-BMP) is skipped, not the
/// common case for registry/Hub fields.
pub(crate) fn value_after_colon(s: &str) -> Option<String> {
    let after = &s[s.find(':')? + 1..];
    let body = &after[after.find('"')? + 1..];
    let mut out = String::new();
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out), // unescaped closing quote
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'b' => out.push('\u{08}'),
                'f' => out.push('\u{0C}'),
                'u' => {
                    let mut code = 0u32;
                    for _ in 0..4 {
                        code = code * 16 + chars.next()?.to_digit(16)?;
                    }
                    if let Some(ch) = char::from_u32(code) {
                        out.push(ch);
                    }
                }
                other => out.push(other),
            },
            _ => out.push(c),
        }
    }
    None // unterminated string
}

/// First string value for `"key"` anywhere in `json`.
pub(crate) fn first_str(json: &str, key: &str) -> Option<String> {
    let k = json.find(&format!("\"{key}\""))?;
    value_after_colon(&json[k + key.len() + 2..])
}

/// All string values for `"key"` in `json`, in order.
pub(crate) fn all_str_values(json: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = json[from..].find(&needle) {
        let abs = from + rel + needle.len();
        if let Some(v) = value_after_colon(&json[abs..]) {
            out.push(v);
        }
        from = abs;
    }
    out
}

/// The substring right after the first `":"` of `"key"` (skipping leading whitespace), for reading
/// non-string scalars.
fn after_key_colon<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let k = json.find(&format!("\"{key}\""))?;
    let after = &json[k + key.len() + 2..];
    Some(after[after.find(':')? + 1..].trim_start())
}

/// First numeric (`u64`) value for `"key"` (e.g. a star count), or `None` if the key is absent or
/// not numeric.
pub(crate) fn u64_field(json: &str, key: &str) -> Option<u64> {
    let v = after_key_colon(json, key)?;
    let digits: String = v.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// First boolean value for `"key"`.
pub(crate) fn bool_field(json: &str, key: &str) -> Option<bool> {
    let v = after_key_colon(json, key)?;
    if v.starts_with("true") {
        Some(true)
    } else if v.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_and_objects() {
        let j = r#"{"results":[{"name":"nginx","star_count":21000,"is_official":true,"description":"web server"},{"name":"bob/nginx","star_count":5,"is_official":false}]}"#;
        let arr = array_after(j, "results").unwrap();
        let objs = split_objects(arr);
        assert_eq!(objs.len(), 2);
        assert_eq!(first_str(objs[0], "name").as_deref(), Some("nginx"));
        assert_eq!(u64_field(objs[0], "star_count"), Some(21000));
        assert_eq!(bool_field(objs[0], "is_official"), Some(true));
        assert_eq!(bool_field(objs[1], "is_official"), Some(false));
        assert_eq!(u64_field(objs[1], "star_count"), Some(5));
        // A bracket inside a string value must not break object splitting.
        let tricky = r#"[{"d":"a [b] c"},{"d":"x"}]"#;
        assert_eq!(split_objects(tricky).len(), 2);
    }

    #[test]
    fn strings_are_unescaped_and_escape_aware() {
        // `/` → `/`, an escaped quote doesn't end the value, `\n` decodes.
        let j = r#"{"description":"reverse / proxy \"quoted\"\nline"}"#;
        assert_eq!(
            first_str(j, "description").as_deref(),
            Some("reverse / proxy \"quoted\"\nline")
        );
    }
}
