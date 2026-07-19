//! Surgical, line-based edits to a `kern.toml` - used by the `kern top` **Profiles** tab so editing a
//! single profile can't destroy the rest of the file. kern's parser is deliberately *tolerant* (it
//! ignores sections/keys it doesn't model, so a config shared with the private runtime still loads);
//! that means a naive "parse → re-serialize" would silently drop every unknown section on save. These
//! helpers instead splice *only the one array-of-tables block* being edited and leave every other
//! byte - comments, blank lines, unknown `[gpu]`/`[intelligence]` sections - exactly as it was.
//!
//! A "block" is a `[[<header>]]` line and every line after it up to (but not including) the next line
//! that starts a new `[table]`/`[[array]]`, or end of file. A block is matched by its `name = "…"`.

/// The value of `name = "…"` on a block header line's body, if this trimmed line is a `name` key.
fn name_value(trimmed: &str) -> Option<&str> {
    let rest = trimmed.strip_prefix("name")?.trim_start();
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
        let mut s = raw.to_string();
        if !s.is_empty() {
            if !s.ends_with('\n') {
                s.push('\n');
            }
            s.push('\n');
        }
        s.push_str(&block.join("\n"));
        s.push('\n');
        s
    }
}

/// The `key` of a `key = value` line (trimmed), or `None` for a comment / blank / section line.
fn line_key(trimmed: &str) -> Option<&str> {
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
        return None;
    }
    trimmed.split_once('=').map(|(k, _)| k.trim())
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

    #[test]
    fn name_value_parses_both_quote_styles() {
        assert_eq!(name_value(r#"name = "web""#), Some("web"));
        assert_eq!(name_value("name='db'"), Some("db"));
        assert_eq!(name_value("nickname = \"x\""), None);
        assert_eq!(name_value("cpus = \"0-3\""), None);
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
