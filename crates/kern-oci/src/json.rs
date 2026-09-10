//! A tiny, dependency-free JSON reader - just enough to walk the registry's manifests and Docker
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

/// The `open..=close` bracketed span (inclusive) following `"key"` - one implementation of
/// "find key → find opener → match its close" so the array and object walkers can't drift.
fn bracketed_after<'a>(json: &'a str, key: &str, open: u8, close: u8) -> Option<&'a str> {
    let k = json.find(&format!("\"{key}\""))?;
    let open_idx = json[k..].find(open as char)? + k;
    let close_idx = matching_bracket(json, open_idx, open, close)?;
    Some(&json[open_idx..=close_idx])
}

/// The `[...]` array (inclusive) following `"key"`.
pub(crate) fn array_after<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    bracketed_after(json, key, b'[', b']')
}

/// The `{...}` object (inclusive) following `"key"` - e.g. an OCI image config's `"config": {…}`.
pub(crate) fn object_after<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    bracketed_after(json, key, b'{', b'}')
}

/// One JSON escape, decoded from the characters that FOLLOW its backslash (already consumed).
///
/// ONE IMPLEMENTATION FOR BOTH READERS, because they drifted and the drift shipped. The array
/// reader below knew `\n`, `\t` and `\r` and passed every other escape through as the plain letter
/// after the backslash, so `>` decoded to `u003e`. Go's `encoding/json` - what Docker builds
/// image configs with - escapes `<`, `>` and `&` BY DEFAULT, and the arrays this reads are an
/// image's `Cmd`, `Entrypoint`, `Env` and `Healthcheck.Test`. Any of those three characters in an
/// image's own argv therefore arrived corrupted.
///
/// MEASURED on `supabase/postgres-meta:v0.99.0`, whose `HEALTHCHECK` is a JavaScript arrow
/// function: `(r) => {…}` reached the box as `(r) =u003e {…}`, a syntax error, so the service
/// reported `unhealthy` for as long as it ran while its own `/health` answered 200 to the same
/// request. The scalar reader (`value_after_colon`) had decoded `\uXXXX` correctly all along,
/// which is why one field was right and the one next to it was wrong.
///
/// `None` = the string ended mid-escape (truncated input, so the caller must stop). `Some(None)` =
/// an escape that decodes to no character - an unpaired surrogate half - which is skipped rather
/// than failing the whole parse.
fn decode_escape(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<Option<char>> {
    Some(match chars.next()? {
        'n' => Some('\n'),
        't' => Some('\t'),
        'r' => Some('\r'),
        'b' => Some('\u{08}'),
        'f' => Some('\u{0C}'),
        'u' => {
            let hi = hex4(chars)?;
            // The common case: a plain code point, `>` included.
            if !(0xD800..0xE000).contains(&hi) {
                return Some(char::from_u32(hi));
            }
            // A LOW half on its own builds nothing: there is no high half to pair it with.
            if hi >= 0xDC00 {
                return Some(None);
            }
            // A HIGH half is half a character; the low half follows as its own `\uXXXX`.
            if chars.peek() != Some(&'\\') {
                return Some(None);
            }
            chars.next();
            // What follows the backslash need not be another `\u`. Decode it on its own terms
            // rather than swallowing it: dropping a `\n` because the escape before it was
            // malformed would corrupt a second value to punish the first.
            if chars.peek() != Some(&'u') {
                return decode_escape(chars);
            }
            chars.next();
            let lo = hex4(chars)?;
            if !(0xDC00..0xE000).contains(&lo) {
                return Some(char::from_u32(lo));
            }
            char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
        }
        other => Some(other), // covers `"`, `\`, `/`, and anything else written after a backslash
    })
}

/// The four hex digits of a `\uXXXX`, or `None` if they are not there.
fn hex4(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<u32> {
    let mut code = 0u32;
    for _ in 0..4 {
        code = code * 16 + chars.next()?.to_digit(16)?;
    }
    Some(code)
}

/// The string ELEMENTS of the `[...]` array following `"key"` (a JSON string array like an OCI
/// config's `Env`/`Cmd`/`Entrypoint`). Escape-aware; empty if the key/array is absent.
pub(crate) fn str_array_after(json: &str, key: &str) -> Vec<String> {
    let Some(arr) = array_after(json, key) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut chars = arr.chars().peekable();
    while let Some(c) = chars.next() {
        if !in_str {
            in_str = c == '"';
            continue;
        }
        match c {
            '"' => {
                out.push(std::mem::take(&mut cur));
                in_str = false;
            }
            '\\' => match decode_escape(&mut chars) {
                Some(Some(ch)) => cur.push(ch),
                // An escape that decodes to nothing: skip it and keep reading the element.
                Some(None) => {}
                // Truncated mid-escape: the element has no closing quote either, so there is
                // nothing further to read. What was already complete is returned.
                None => break,
            },
            _ => cur.push(c),
        }
    }
    out
}

/// Split a `[...]` array into its top-level `{...}` objects.
pub(crate) fn split_objects(arr: &str) -> Vec<&str> {
    let b = arr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'{' {
            // A `{` either opens a complete object (jump past its close) or is unbalanced - and if it
            // doesn't close, no later brace can either, so stop. Advancing by one instead would
            // rescan to end-of-input for every unmatched `{`: O(n^2), a parse-time DoS on a crafted
            // array of open braces. (Found by the `oci_json` fuzz target.)
            let Some(end) = matching_bracket(arr, i, b'{', b'}') else {
                break;
            };
            out.push(&arr[i..=end]);
            i = end + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// The next JSON string value after the first `:` in `s`, properly **unescaped** and
/// **escape-aware** (a `\"` inside the value doesn't end it). Only valid for STRING-valued keys -
/// for a numeric value use [`u64_field`]. Escapes are decoded by [`decode_escape`], the same
/// routine the array reader uses, so the two cannot answer differently about one escape again.
pub(crate) fn value_after_colon(s: &str) -> Option<String> {
    let after = &s[s.find(':')? + 1..];
    let body = &after[after.find('"')? + 1..];
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out), // unescaped closing quote
            '\\' => {
                if let Some(ch) = decode_escape(&mut chars)? {
                    out.push(ch);
                }
            }
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
    fn object_and_string_array() {
        // An OCI-image-config-shaped blob: pull the inner `config` object, then its string arrays.
        let blob = r#"{"architecture":"amd64","config":{"Env":["PATH=/bin","REDIS_VERSION=8.8.0"],"Entrypoint":["docker-entrypoint.sh"],"Cmd":["redis-server"],"WorkingDir":"/data","User":"redis"},"os":"linux"}"#;
        let cfg = object_after(blob, "config").unwrap();
        assert_eq!(
            str_array_after(cfg, "Env"),
            vec!["PATH=/bin", "REDIS_VERSION=8.8.0"]
        );
        assert_eq!(
            str_array_after(cfg, "Entrypoint"),
            vec!["docker-entrypoint.sh"]
        );
        assert_eq!(str_array_after(cfg, "Cmd"), vec!["redis-server"]);
        assert_eq!(first_str(cfg, "WorkingDir").as_deref(), Some("/data"));
        assert_eq!(first_str(cfg, "User").as_deref(), Some("redis"));
        // Absent array → empty; a bracket inside a value doesn't break it.
        assert!(str_array_after(cfg, "Volumes").is_empty());
        assert_eq!(
            str_array_after(r#"{"a":["x [y]","z\tw"]}"#, "a"),
            vec!["x [y]", "z\tw"]
        );
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

    /// `\uXXXX` DECODES IN AN ARRAY, and the array is where an image's argv lives.
    ///
    /// Go's `encoding/json` - what Docker writes image configs with - escapes `<`, `>` and `&` by
    /// default, so these three appear as `<`, `>` and `&` in almost every real
    /// config. The array reader turned each into the letters `u003e`, silently, while the scalar
    /// reader next to it decoded them correctly.
    ///
    /// THE FIRST CASE IS THE ONE THAT WAS MEASURED, byte for byte from
    /// `supabase/postgres-meta:v0.99.0`: the image's own HEALTHCHECK is an arrow function, kern ran
    /// it as `(r) =u003e {…}`, node exited on a syntax error, and the service was `unhealthy` for
    /// its whole life while answering 200 on the very endpoint the check asks about.
    #[test]
    fn an_escaped_code_point_decodes_in_arrays_exactly_as_in_scalars() {
        let real = r#"{"Healthcheck":{"Test":["CMD-SHELL","node -e \"fetch('http://localhost:8080/health').then((r) => {if (r.status !== 200) throw new Error(r.status)})\""]}}"#;
        let test = str_array_after(real, "Test");
        assert_eq!(test.len(), 2);
        assert_eq!(test[0], "CMD-SHELL");
        assert!(
            test[1].contains("(r) => {"),
            "the arrow function must survive the parse: {}",
            test[1]
        );
        assert!(!test[1].contains("u003e"), "got: {}", test[1]);

        // The three Go escapes HTML-escapes by default, in an array and in a scalar, same answer.
        let both = r#"{"Cmd":["sh","-c","a && b > /log < /in"],"S":"a && b > /log < /in"}"#;
        let expected = "a && b > /log < /in";
        assert_eq!(str_array_after(both, "Cmd")[2], expected);
        assert_eq!(first_str(both, "S").as_deref(), Some(expected));

        // A surrogate PAIR builds the one character it spells, in both readers. Written as the two
        // ESCAPES a real encoder emits (not the character itself, which would test nothing).
        let pair = "{\"a\":[\"\\ud83d\\ude00\"],\"s\":\"\\ud83d\\ude00\"}";
        assert_eq!(str_array_after(pair, "a"), vec!["\u{1F600}"]);
        assert_eq!(first_str(pair, "s").as_deref(), Some("\u{1F600}"));

        // A HALF surrogate spells no character: it is skipped, and the rest of the value survives.
        assert_eq!(str_array_after(r#"{"a":["x\ud83dy"]}"#, "a"), vec!["xy"]);
        assert_eq!(str_array_after(r#"{"a":["x\udc00y"]}"#, "a"), vec!["xy"]);
        // A half surrogate followed by ANOTHER escape must not eat that escape.
        assert_eq!(
            str_array_after(r#"{"a":["x\ud83d\ty"]}"#, "a"),
            vec!["x\ty"]
        );

        // Truncated mid-escape: no panic, and no half-read element invented.
        assert!(str_array_after(r#"{"a":["x\u00"#, "a").is_empty());
        assert_eq!(value_after_colon(r#":"x\u00"#), None);
        // The plain escapes still decode, in the array reader too.
        assert_eq!(
            str_array_after(r#"{"a":["q\"q","s\\s","p\/p","\b\f"]}"#, "a"),
            vec!["q\"q", "s\\s", "p/p", "\u{08}\u{0C}"]
        );
    }
}
