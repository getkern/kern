//! Surgical, line-based edits to a `kern.toml` - used by the `kern top` **Profiles** tab so editing a
//! single profile can't destroy the rest of the file. kern's parser is deliberately *tolerant* (it
//! ignores sections/keys it doesn't model, so a config shared with another kern edition still loads);
//! that means a naive "parse → re-serialize" would silently drop every unknown section on save. These
//! helpers instead splice *only the one array-of-tables block* being edited and leave every other
//! byte - comments, blank lines, unknown `[gpu]`/`[intelligence]` sections - exactly as it was.
//!
//! A "block" is a `[[<header>]]` line and every line after it up to (but not including) the next line
//! that starts a new `[table]`/`[[array]]`, or end of file. A block is matched by its identity key,
//! which is `name = "…"` on a profile and `id = "…"` on a physical block.

/// The value of a block's IDENTITY key, if this trimmed line carries one.
///
/// TWO KEYS, BECAUSE THE FILE HAS TWO CONVENTIONS. A profile block identifies itself with
/// `name = "…"`; a PHYSICAL block (`[[cpu]]`, `[[gpu]]`, `[[disk]]`, `[[gpio]]`) identifies itself
/// with `id = "…"`. This function used to know only about `name`, which meant every lookup of a
/// physical block answered "not there" no matter what the file said. It went unnoticed while nothing
/// looked one up; the moment `config add` started materialising the physical block, the miss became
/// visible in the worst shape available:
///
///     $ kern config add vcpu:a --cpus 1        # into a file that already declares [[cpu]] cpu:0
///     error: refusing to write: two [[cpu]] entries share `id = "cpu:0"`
///
/// The lookup said absent, a second block was appended, and the whole-file parse guard caught the
/// duplicate and refused the write. Adding a profile to a config that already declared its hardware
/// failed outright. The guard doing its job is why this cost an error and not a corrupted file.
///
/// If a block carries both keys the first one wins, which is the same rule that already applied when
/// only `name` was read: `find_block` takes the first match it sees walking the block down.
fn name_value(trimmed: &str) -> Option<&str> {
    let rest = trimmed
        .strip_prefix("name")
        .or_else(|| trimmed.strip_prefix("id"))?
        .trim_start();
    let rest = rest.strip_prefix('=')?.trim();
    // The value may be followed by an inline comment (`name = "heavy"   # …`) - the starter config from
    // `kern config setup` writes exactly that. Take the QUOTED span (up to the closing quote), not
    // `strip_suffix('"')` on the whole line, which failed when a comment trailed the value → the block
    // wasn't found → `config add` on an existing name created a DUPLICATE instead of erroring.
    let (q, after) = if let Some(a) = rest.strip_prefix('"') {
        ('"', a)
    } else {
        let a = rest.strip_prefix('\'')?;
        ('\'', a)
    };
    let end = after.find(q)?;
    Some(&after[..end])
}

/// Is this the array-of-tables header for `header` (e.g. `[[vcpu]]`)? Tolerates inner whitespace.
fn is_header(trimmed: &str, header: &str) -> bool {
    trimmed
        .strip_prefix("[[")
        .and_then(|r| r.strip_suffix("]]"))
        .map(str::trim)
        == Some(header)
}

/// Any `[...]`/`[[...]]` line ends the current block.
fn starts_any_section(trimmed: &str) -> bool {
    trimmed.starts_with('[')
}

/// The line range `[start, end)` of the `[[header]]` block whose `name` equals `name`, or `None`.
/// `start` is the header line; `end` is the first line after the block (a following section header or
/// `lines.len()`).
fn find_block(lines: &[&str], header: &str, name: &str) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < lines.len() {
        if is_header(lines[i].trim(), header) {
            let start = i;
            let mut end = i + 1;
            let mut this_name = None;
            while end < lines.len() && !starts_any_section(lines[end].trim()) {
                if this_name.is_none() {
                    this_name = name_value(lines[end].trim());
                }
                end += 1;
            }
            if this_name == Some(name) {
                // Exclude trailing blank lines from the block so a replace/delete keeps the blank
                // separator BETWEEN blocks (an upsert would otherwise swallow it and squash them).
                let mut trimmed = end;
                while trimmed > start + 1 && lines[trimmed - 1].trim().is_empty() {
                    trimmed -= 1;
                }
                return Some((start, trimmed));
            }
            i = end;
        } else {
            i += 1;
        }
    }
    None
}

/// Does a `[[header]]` block named `name` already exist? Used to reject a new/renamed profile that
/// would silently clobber an existing one.
pub fn block_exists(raw: &str, header: &str, name: &str) -> bool {
    let lines: Vec<&str> = raw.lines().collect();
    find_block(&lines, header, name).is_some()
}

/// Insert or replace the `[[header]]` block named `name` (as identified by its own `name = "…"`,
/// which must be present in `body_lines`). If a block with that name exists it is replaced in place;
/// otherwise a new block is appended. Everything outside the block is preserved byte-for-byte.
///
/// `body_lines` are the block's `key = value` lines WITHOUT the `[[header]]` line (this adds it).
pub fn upsert_block(raw: &str, header: &str, name: &str, body_lines: &[String]) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    let mut block = Vec::with_capacity(body_lines.len() + 1);
    block.push(format!("[[{header}]]"));
    block.extend(body_lines.iter().cloned());

    if let Some((start, end)) = find_block(&lines, header, name) {
        let mut out: Vec<String> = Vec::with_capacity(lines.len());
        out.extend(lines[..start].iter().map(|s| s.to_string()));
        out.extend(block);
        out.extend(lines[end..].iter().map(|s| s.to_string()));
        with_trailing_newline(&out.join("\n"), raw)
    } else {
        // Append a fresh block, separated by a blank line from any existing content.
        append_section(raw, &block.join("\n"))
    }
}

/// The `key` of a `key = value` line (trimmed), or `None` for a comment / blank / section line.
fn line_key(trimmed: &str) -> Option<std::borrow::Cow<'_, str>> {
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
        return None;
    }
    // The key as the reader names it, so a quoted `"log_max_size"` is found by `get` and replaced by
    // `set` exactly as the reader applies it (`crate::config::toml_key`).
    trimmed.split_once('=').map(|(k, _)| {
        let k = k.trim();
        crate::config::toml_key(k).unwrap_or(std::borrow::Cow::Borrowed(k))
    })
}

/// Like [`upsert_block`], but **field-surgical**: when the block already exists it keeps every line
/// whose key is NOT in `managed` (and any comment lines), replacing only the managed fields with
/// `body_lines`. So a profile edit from the form / `kern config` preserves keys those surfaces don't
/// model - a hand-added `numa`, `nice`, `iops`, or a peripheral like `i2c` - instead of dropping them
/// (the same promise `upsert_block` makes for the rest of the *file*, now for the rest of the *block*).
///
/// `source_name` is the block being edited (for a rename it's the OLD name); `body_lines` carries the
/// new `name = "…"`. A managed field absent from `body_lines` is treated as cleared (removed) - so the
/// form can still empty a field. If no block named `source_name` exists, this is a plain insert.
// `managed` is `&[&'static str]` while `k` borrows a line (shorter lifetime), so `.contains(&k)` won't
// typecheck - the `iter().any()` is required, not a style choice.
#[allow(clippy::manual_contains)]
pub fn upsert_block_merge(
    raw: &str,
    header: &str,
    source_name: &str,
    new_name: &str,
    managed: &[&str],
    body_lines: &[String],
) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    let Some((start, end)) = find_block(&lines, header, source_name) else {
        // Nothing to merge onto → a fresh insert (the name is already in body_lines).
        return upsert_block(raw, header, new_name, body_lines);
    };
    // Keep the existing block's unmanaged keys (and comments); the managed keys + `name` come from
    // `body_lines`, so they are fully controlled by the caller (set, changed, or cleared).
    let preserved: Vec<String> = lines[start + 1..end]
        .iter()
        .filter_map(|l| match line_key(l.trim()) {
            Some(k) if k == "name" || managed.iter().any(|m| *m == k) => None,
            Some(_) => Some((*l).to_string()),
            None if l.trim().starts_with('#') => Some((*l).to_string()),
            None => None,
        })
        .collect();
    let mut block = Vec::with_capacity(body_lines.len() + preserved.len() + 1);
    block.push(format!("[[{header}]]"));
    block.extend(body_lines.iter().cloned());
    block.extend(preserved);
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    out.extend(lines[..start].iter().map(|s| s.to_string()));
    out.extend(block);
    out.extend(lines[end..].iter().map(|s| s.to_string()));
    with_trailing_newline(&out.join("\n"), raw)
}

/// Remove the `[[header]]` block named `name` (and a single trailing blank line, to avoid piling up
/// gaps). Returns the input unchanged if no such block exists.
pub fn delete_block(raw: &str, header: &str, name: &str) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    let Some((start, mut end)) = find_block(&lines, header, name) else {
        return raw.to_string();
    };
    // Swallow one trailing blank line so removals don't leave a growing run of blanks.
    if end < lines.len() && lines[end].trim().is_empty() {
        end += 1;
    }
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    out.extend(lines[..start].iter().map(|s| s.to_string()));
    out.extend(lines[end..].iter().map(|s| s.to_string()));
    let joined = out.join("\n");
    // Trim a leading blank the removal may have exposed at the very top.
    let joined = joined.strip_prefix('\n').unwrap_or(&joined).to_string();
    with_trailing_newline(&joined, raw)
}

/// Is this trimmed line the header of the single table `[table]` (not an array of tables)?
fn is_table_header(trimmed: &str, table: &str) -> bool {
    // Compared as the reader names it (`crate::config::key_path`): `[ "kern" ]` IS `[kern]`, so a
    // `set` lands in it instead of appending a second `[kern]`.
    !trimmed.starts_with("[[")
        && trimmed
            .strip_prefix('[')
            .and_then(|r| r.split_once(']'))
            .is_some_and(|(name, rest)| {
                let rest = rest.trim();
                crate::config::key_path(name).is_some_and(|p| p.join(".") == table)
                    && (rest.is_empty() || rest.starts_with('#'))
            })
}

/// Append `text` (lines, no trailing newline) as a new section, separated from any existing content
/// by a blank line: the rule `upsert_block` appends a block by too.
fn append_section(raw: &str, text: &str) -> String {
    let mut s = raw.to_string();
    if !s.is_empty() {
        if !s.ends_with('\n') {
            s.push('\n');
        }
        s.push('\n');
    }
    s.push_str(text);
    s.push('\n');
    s
}

/// Which lines lie INSIDE a multi-line string (`"""` or `'''`), the opening line excluded: what looks
/// like a header or a key there is string content, and the reader (`crate::config::parse`) reads it
/// as such. The edits below skip those lines, or `config set` wrote `publish_bind` into a `[kern]`
/// that was only text inside a string, `get` echoed it back, and the reader applied nothing, leaving
/// ports on 0.0.0.0 (found by review). Same opening rule as the reader: a value that starts with the
/// delimiter and does not close it on its own line.
fn inside_multiline_string(lines: &[&str]) -> Vec<bool> {
    let mut mask = vec![false; lines.len()];
    let mut open: Option<&str> = None;
    for (i, l) in lines.iter().enumerate() {
        if let Some(delim) = open {
            mask[i] = true;
            if l.contains(delim) {
                open = None;
            }
            continue;
        }
        let code = kern_common::toml_lite::strip_comment(l);
        if let Some((_, v)) = code.split_once('=') {
            let v = v.trim();
            for delim in ["\"\"\"", "'''"] {
                if v.starts_with(delim) && !v[3..].contains(delim) {
                    open = Some(delim);
                }
            }
        }
    }
    mask
}

/// Set `key` in the single table `[table]` to the whole line `line` (`key = value`), or remove it
/// with `None`. The key is replaced where it stands; a new key goes after the table's last key line,
/// and a missing table is appended at the end. Every other line is kept byte for byte.
pub fn set_table_key(raw: &str, table: &str, key: &str, line: Option<&str>) -> String {
    let lines: Vec<&str> = raw.lines().collect();
    let in_str = inside_multiline_string(&lines);
    let Some(start) =
        (0..lines.len()).find(|&i| !in_str[i] && is_table_header(lines[i].trim(), table))
    else {
        return match line {
            Some(line) => append_section(raw, &format!("[{table}]\n{line}")),
            None => raw.to_string(),
        };
    };
    let end = (start + 1..lines.len())
        .find(|&i| !in_str[i] && starts_any_section(lines[i].trim()))
        .unwrap_or(lines.len());
    let mut out: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();
    match (start + 1..end)
        .find(|&i| !in_str[i] && line_key(lines[i].trim()).as_deref() == Some(key))
    {
        Some(i) => match line {
            // The line's own comment stays with it: `log_max_size = "16m"   # my note` set to 10m
            // keeps `   # my note`, the spacing included. Only the `key = value` part is the
            // caller's to replace.
            Some(l) => {
                let code = kern_common::toml_lite::strip_comment(lines[i]);
                let comment = &lines[i][code.len()..];
                out[i] = if comment.is_empty() {
                    l.to_string()
                } else {
                    format!("{l}{}{comment}", &code[code.trim_end().len()..])
                };
            }
            None => {
                out.remove(i);
            }
        },
        None => {
            if let Some(l) = line {
                let after = (start + 1..end)
                    .rev()
                    .find(|&i| !in_str[i] && line_key(lines[i].trim()).is_some())
                    .unwrap_or(start);
                // Never inside a string that the last key opened: after its closing line.
                let after = (after + 1..end)
                    .take_while(|&i| in_str[i])
                    .last()
                    .unwrap_or(after);
                out.insert(after + 1, l.to_string());
            }
        }
    }
    with_trailing_newline(&out.join("\n"), raw)
}

/// The value of `key` in the single table `[table]`, as written (comment stripped, trimmed), or
/// `None` when the table or the key is absent. The reader twin of [`set_table_key`]: the same table
/// and key rules, so `kern config get` reports exactly the line `kern config set` wrote.
pub fn get_table_key(raw: &str, table: &str, key: &str) -> Option<String> {
    let lines: Vec<&str> = raw.lines().collect();
    let in_str = inside_multiline_string(&lines);
    let start =
        (0..lines.len()).find(|&i| !in_str[i] && is_table_header(lines[i].trim(), table))?;
    (start + 1..lines.len())
        .filter(|&i| !in_str[i])
        .take_while(|&i| !starts_any_section(lines[i].trim()))
        .find(|&i| line_key(lines[i].trim()).as_deref() == Some(key))
        .and_then(|i| lines[i].split_once('='))
        .map(|(_, v)| kern_common::toml_lite::strip_comment(v).trim().to_string())
}

/// Preserve the input's trailing-newline convention on the rebuilt text (`lines()` drops it).
fn with_trailing_newline(s: &str, original: &str) -> String {
    if original.ends_with('\n') && !s.ends_with('\n') {
        format!("{s}\n")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Text inside a multi-line string is not a header or a key: `set` neither writes into a `[kern]`
    /// that is string content nor replaces a `publish_bind` line inside a string (found by review:
    /// the write went where the reader applies nothing, and ports stayed on 0.0.0.0).
    #[test]
    fn a_multi_line_string_is_never_edited_as_a_table() {
        let raw = "[future]\nnote = \"\"\"\n[kern]\n\"\"\"\n";
        let out = set_table_key(
            raw,
            "kern",
            "publish_bind",
            Some("publish_bind = \"127.0.0.1\""),
        );
        assert!(
            out.ends_with("\"\"\"\n\n[kern]\npublish_bind = \"127.0.0.1\"\n"),
            "{out}"
        );
        assert_eq!(get_table_key(raw, "kern", "publish_bind"), None);
        let raw = "[kern]\nnotes = \"\"\"\npublish_bind = \"0.0.0.0\"\n\"\"\"\npublish_bind = \"0.0.0.0\"\n";
        let out = set_table_key(
            raw,
            "kern",
            "publish_bind",
            Some("publish_bind = \"127.0.0.1\""),
        );
        assert_eq!(
            out,
            "[kern]\nnotes = \"\"\"\npublish_bind = \"0.0.0.0\"\n\"\"\"\npublish_bind = \"127.0.0.1\"\n"
        );
        let c = crate::config::parse(&out).expect("parses");
        assert_eq!(c.kern.publish_bind.as_deref(), Some("127.0.0.1"));
    }

    /// A quoted header IS the table: `set` writes into `[ "kern" ]` instead of appending a second
    /// `[kern]`, which TOML refuses (reported: `Cannot declare ('kern',) twice`).
    #[test]
    fn a_quoted_header_is_the_table_a_set_writes_into() {
        let raw = "[ \"kern\" ]\nlog_max_size = \"10m\"\n";
        assert_eq!(
            set_table_key(raw, "kern", "log_max_file", Some("log_max_file = 2")),
            "[ \"kern\" ]\nlog_max_size = \"10m\"\nlog_max_file = 2\n"
        );
    }

    /// A quoted key is found and replaced as the bare one, because the reader applies it as such.
    #[test]
    fn a_quoted_key_is_found_and_replaced() {
        let raw = "[kern]\n\"log_max_size\" = \"10m\"\n";
        assert_eq!(
            get_table_key(raw, "kern", "log_max_size").as_deref(),
            Some("\"10m\"")
        );
        assert_eq!(
            set_table_key(raw, "kern", "log_max_size", Some("log_max_size = \"20m\"")),
            "[kern]\nlog_max_size = \"20m\"\n"
        );
    }

    /// Measured on 6d93b85: `config set` on a line carrying a comment dropped the comment.
    #[test]
    fn a_set_keeps_the_comment_on_the_line_it_replaces() {
        let raw = "[kern]\nlog_max_size = \"16m\"   # my own note\nlog_max_file = 2\n";
        assert_eq!(
            set_table_key(raw, "kern", "log_max_size", Some("log_max_size = \"10m\"")),
            "[kern]\nlog_max_size = \"10m\"   # my own note\nlog_max_file = 2\n"
        );
        // A `#` inside the value is not a comment and is not carried over.
        let raw = "[kern]\nlog_level = \"a#b\"\n";
        assert_eq!(
            set_table_key(raw, "kern", "log_level", Some("log_level = \"info\"")),
            "[kern]\nlog_level = \"info\"\n"
        );
        // Unset removes the line, comment and all.
        assert_eq!(
            set_table_key("[kern]\nx = 1 # c\n", "kern", "x", None),
            "[kern]\n"
        );
    }

    #[test]
    fn a_kern_key_is_set_in_place_added_after_the_last_key_and_removed() {
        let raw = "# mine\n[kern]\nlog_level = \"info\"  \n\n[[vcpu]]\nname = \"a\"\n";
        // Added after the table's last key, before the blank separator and the next block.
        let added = set_table_key(
            raw,
            "kern",
            "sandbox_history",
            Some("sandbox_history = \"disk\""),
        );
        assert_eq!(
            added,
            "# mine\n[kern]\nlog_level = \"info\"  \nsandbox_history = \"disk\"\n\n[[vcpu]]\nname = \"a\"\n"
        );
        // Replaced where it stands.
        let changed = set_table_key(
            &added,
            "kern",
            "sandbox_history",
            Some("sandbox_history = \"off\""),
        );
        assert_eq!(changed, added.replace("\"disk\"", "\"off\""));
        // Removed, which gives the original back.
        assert_eq!(
            set_table_key(&changed, "kern", "sandbox_history", None),
            raw
        );
        // A key of the same name in ANOTHER table is not touched.
        let other = "[[vcpu]]\nsandbox_history = 1\n";
        assert_eq!(
            set_table_key(
                other,
                "kern",
                "sandbox_history",
                Some("sandbox_history = \"off\"")
            ),
            "[[vcpu]]\nsandbox_history = 1\n\n[kern]\nsandbox_history = \"off\"\n"
        );
        // No table and nothing to set: unchanged.
        assert_eq!(set_table_key(other, "kern", "x", None), other);
        // An empty file gets the table alone.
        assert_eq!(
            set_table_key("", "kern", "k", Some("k = 1")),
            "[kern]\nk = 1\n"
        );
    }

    #[test]
    fn name_value_parses_both_quote_styles() {
        assert_eq!(name_value(r#"name = "web""#), Some("web"));
        assert_eq!(name_value("name='db'"), Some("db"));
        assert_eq!(name_value("nickname = \"x\""), None);
        assert_eq!(name_value("cpus = \"0-3\""), None);
    }

    /// A PHYSICAL BLOCK IS FOUND BY ITS `id`, and it was not.
    ///
    /// Reproduces exactly what the live audit hit: a config that already declares `[[cpu]] cpu:0`,
    /// then `kern config add vcpu:a`. The lookup answered "absent", a second `[[cpu]]` was appended,
    /// and the whole-file parse guard refused the write with "two [[cpu]] entries share id".
    /// Declaring the hardware first made adding a profile fail.
    #[test]
    fn a_physical_block_is_found_by_its_id() {
        let raw = "[[cpu]]\nid = \"cpu:0\"\ncores = 8\n\n[[disk]]\nid = \"d0\"\npath = \"/\"\n";
        assert!(block_exists(raw, "cpu", "cpu:0"));
        assert!(block_exists(raw, "disk", "d0"));
        assert!(!block_exists(raw, "cpu", "cpu:1"));
        assert!(!block_exists(raw, "gpio", "cpu:0")); // right id, wrong section
                                                      // The identity keys do not leak into each other: an `id` does not answer a `name` lookup on
                                                      // a different block, because the section is matched first.
        assert!(!block_exists("[[vcpu]]\nname = \"a\"\n", "cpu", "a"));
        // A key that merely STARTS with `id` is not an identity key.
        assert_eq!(name_value("identity = \"x\""), None);
        assert_eq!(name_value("ids = \"x\""), None);
        assert_eq!(
            name_value(r#"id = "cpu:0"   # the whole host"#),
            Some("cpu:0")
        );
    }

    #[test]
    fn upsert_replaces_only_the_named_block() {
        let raw = "\
# my config
[[vcpu]]
name = \"heavy\"
cpus = 8.0

[[vcpu]]
name = \"light\"
cpus = 2.0

[gpu]
model = \"secret\"
";
        let body = vec!["name = \"heavy\"".to_string(), "cpus = 4.0".to_string()];
        let out = upsert_block(raw, "vcpu", "heavy", &body);
        assert!(out.contains("cpus = 4.0"));
        assert!(!out.contains("cpus = 8.0"), "old value replaced");
        assert!(out.contains("name = \"light\""), "sibling untouched");
        assert!(out.contains("[gpu]"), "unknown section preserved");
        assert!(out.contains("model = \"secret\""), "unknown key preserved");
        assert!(out.contains("# my config"), "comment preserved");
    }

    #[test]
    fn upsert_keeps_the_blank_line_between_blocks() {
        // Regression: replacing a block must not swallow the blank separator before the next block.
        let raw = "[[disk]]\nname = \"disk:0\"\npath = \"/\"\n\n[[vdisk]]\nname = \"scratch\"\nsize = \"2g\"\n";
        let out = upsert_block(
            raw,
            "disk",
            "disk:0",
            &["name = \"disk:0\"".into(), "path = \"/mnt/ssd\"".into()],
        );
        assert!(out.contains("path = \"/mnt/ssd\""));
        assert!(
            out.contains("path = \"/mnt/ssd\"\n\n[[vdisk]]"),
            "blank line between blocks preserved, got:\n{out}"
        );
    }

    #[test]
    fn upsert_appends_a_new_block_when_absent() {
        let raw = "[[vcpu]]\nname = \"a\"\ncpus = 1.0\n";
        let body = vec!["name = \"b\"".to_string(), "cpus = 2.0".to_string()];
        let out = upsert_block(raw, "vcpu", "b", &body);
        assert!(out.contains("name = \"a\""));
        assert!(out.contains("name = \"b\""));
        assert_eq!(out.matches("[[vcpu]]").count(), 2);
    }

    #[test]
    fn upsert_into_empty_file() {
        let body = vec!["name = \"x\"".to_string(), "cpus = 1.0".to_string()];
        let out = upsert_block("", "vcpu", "x", &body);
        assert_eq!(out, "[[vcpu]]\nname = \"x\"\ncpus = 1.0\n");
    }

    #[test]
    fn delete_removes_only_the_named_block() {
        let raw = "\
[[vcpu]]
name = \"a\"
cpus = 1.0

[[vcpu]]
name = \"b\"
cpus = 2.0

[intelligence]
mode = \"auto\"
";
        let out = delete_block(raw, "vcpu", "a");
        assert!(!out.contains("name = \"a\""));
        assert!(out.contains("name = \"b\""));
        assert!(out.contains("[intelligence]"), "unknown section preserved");
        assert_eq!(out.matches("[[vcpu]]").count(), 1);
    }

    #[test]
    fn block_exists_detects_by_section_and_name() {
        let raw = "[[vcpu]]\nname = \"a\"\n\n[[vdisk]]\nname = \"b\"\n";
        assert!(block_exists(raw, "vcpu", "a"));
        assert!(block_exists(raw, "vdisk", "b"));
        assert!(!block_exists(raw, "vdisk", "a")); // right name, wrong section
        assert!(!block_exists(raw, "vcpu", "zzz"));
    }

    #[test]
    fn name_value_handles_inline_comments_and_spacing() {
        // Regression: `kern config setup` writes `name = "heavy"   # comment`. The old parser did
        // `strip_suffix('"')` on the whole line, which failed when a comment trailed → block not found →
        // `config add` created a DUPLICATE instead of erroring. Take the quoted span, ignore the rest.
        assert_eq!(
            name_value(r#"name = "heavy"   # ~half this host"#),
            Some("heavy")
        );
        assert_eq!(name_value(r#"name="tight""#), Some("tight"));
        assert_eq!(name_value(r#"name  =  'single'  # c"#), Some("single"));
        assert_eq!(name_value(r#"name = "ok""#), Some("ok"));
        assert_eq!(name_value("notname = \"x\""), None);
        // And through block_exists on a setup-style commented line.
        let raw = "[[vcpu]]\nname = \"heavy\"   # half the host\ncpus = 4\n";
        assert!(
            block_exists(raw, "vcpu", "heavy"),
            "commented name must be found"
        );
    }

    #[test]
    fn delete_absent_block_is_noop() {
        let raw = "[[vcpu]]\nname = \"a\"\n";
        assert_eq!(delete_block(raw, "vcpu", "zzz"), raw);
    }

    #[test]
    fn merge_preserves_unmanaged_and_controls_managed() {
        let raw = "\
[[vcpu]]
name = \"h\"
cpus = 4
memory = \"512m\"
numa = 1
nice = -5
";
        let managed = ["cpus", "cpuset", "memory", "backend"];
        // Edit: change cpus, OMIT memory (cleared), keep the unmanaged numa/nice.
        let body = vec!["name = \"h\"".to_string(), "cpus = 8".to_string()];
        let out = upsert_block_merge(raw, "vcpu", "h", "h", &managed, &body);
        assert!(out.contains("cpus = 8"));
        assert!(!out.contains("cpus = 4"), "managed field replaced");
        assert!(
            !out.contains("memory"),
            "omitted managed field is cleared:\n{out}"
        );
        assert!(out.contains("numa = 1"), "unmanaged field kept");
        assert!(out.contains("nice = -5"), "unmanaged field kept");
    }

    #[test]
    fn merge_rename_carries_unmanaged_fields() {
        let raw = "[[vcpu]]\nname = \"h\"\ncpus = 4\nnuma = 1\n";
        let managed = ["cpus", "cpuset", "memory", "backend"];
        let body = vec!["name = \"beast\"".to_string(), "cpus = 4".to_string()];
        let out = upsert_block_merge(raw, "vcpu", "h", "beast", &managed, &body);
        assert!(out.contains("name = \"beast\""));
        assert!(!out.contains("name = \"h\""), "old name gone after rename");
        assert!(
            out.contains("numa = 1"),
            "unmanaged carried across the rename"
        );
        assert_eq!(out.matches("[[vcpu]]").count(), 1);
    }

    #[test]
    fn merge_absent_block_is_a_plain_insert() {
        let out = upsert_block_merge(
            "",
            "vcpu",
            "x",
            "x",
            &["cpus"],
            &["name = \"x\"".into(), "cpus = 2".into()],
        );
        assert!(out.contains("[[vcpu]]") && out.contains("cpus = 2"));
    }

    #[test]
    fn different_sections_with_same_name_are_distinct() {
        let raw = "[[vcpu]]\nname = \"x\"\ncpus = 1.0\n\n[[vdisk]]\nname = \"x\"\nsize = \"2g\"\n";
        // Editing the vcpu:x must not touch vdisk:x.
        let out = upsert_block(
            raw,
            "vcpu",
            "x",
            &["name = \"x\"".into(), "cpus = 9.0".into()],
        );
        assert!(out.contains("cpus = 9.0"));
        assert!(out.contains("size = \"2g\""), "vdisk:x untouched");
    }
}

#[cfg(test)]
mod get_table_key_tests {
    use super::*;

    #[test]
    fn get_reads_the_value_set_wrote_and_nothing_outside_the_table() {
        let raw = "# top\n[kern]\nlog_max_size = \"10m\"   # mine\n\n[[vcpu]]\nlog_max_size = 1\n";
        assert_eq!(
            get_table_key(raw, "kern", "log_max_size").as_deref(),
            Some("\"10m\"")
        );
        assert_eq!(get_table_key(raw, "kern", "build_keep"), None);
        assert_eq!(
            get_table_key("[[vcpu]]\nbuild_keep = 3\n", "kern", "build_keep"),
            None
        );
        let set = set_table_key(raw, "kern", "build_keep", Some("build_keep = 200"));
        assert_eq!(
            get_table_key(&set, "kern", "build_keep").as_deref(),
            Some("200")
        );
        let unset = set_table_key(&set, "kern", "build_keep", None);
        assert_eq!(get_table_key(&unset, "kern", "build_keep"), None);
        assert_eq!(unset, raw, "set then unset leaves the file byte for byte");
    }
}
