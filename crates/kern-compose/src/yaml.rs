//! A YAML-lite parser for `docker-compose.yml` → kern [`ComposeBox`](super::ComposeBox)es.
//!
//! **Why hand-rolled.** The whole compose surface is dependency-free by design (like the TOML parser
//! and the OCI tar vetter). We parse the SUBSET of compose that real stacks use and **degrade the long
//! tail with a warning** rather than promise full compatibility — the honest "drop-in-with-degrade"
//! posture. A field we can't map is warned about and skipped (or reconstructed), never silently
//! mis-converted: a mis-converted field is worse than a skipped one because it *runs and lies*.
//!
//! **Security posture (this is semi-trusted input — a compose from a third-party repo).**
//!  * Never a panic on any input: only `char_indices`/byte-safe slicing, iterative (no recursion → no
//!    stack overflow on deep nesting), and a nesting cap. Property-fuzzed (see `fuzz/`).
//!  * **Anchors/aliases (`&`/`*`) are NOT expanded** — a `&a [*a]` billion-laughs is not even
//!    representable because we refuse the document on sight of a structural anchor/alias, never follow
//!    the reference. (Hand-rolled means WE control this, not a library that might expand first.)
//!  * Every value is treated as a raw string — no numeric coercion, so YAML 1.1's sexagesimal trap
//!    (`22:22` → 1342) can't fire on a port.
//!  * `build:` `context`/`dockerfile` are paths the caller CONFINES under the compose dir (traversal).
//!
//! The grammar we accept: space-indented `key: value`, `- ` list items, inline `[…]`/`{…}`, `#`
//! comments, double/single quotes. We REFUSE (with a clear error): tab indentation, block scalars
//! (`|`/`>`), anchors/aliases, tags (`!!`), merge keys (`<<`), and 2nd+ documents (`---`).

use super::{BuildDirective, ComposeBox};

/// Max indentation depth we track — a compose service tree is 3-4 deep; anything past this is refused
/// rather than parsed, bounding work and stack (we're iterative, but this caps pathological input).
const MAX_DEPTH: usize = 32;

/// Parse a compose YAML document into boxes. Warnings for the degraded long tail go to stderr; the
/// return is the mappable boxes (or a hard error for a malformed / unsupported-structural document).
///
/// `pub(crate)`: reached only through the crate's one public door, [`super::parse`] (which sniffs
/// YAML vs TOML first). The `yaml` module itself is private, so this was never externally reachable —
/// the narrower marker just says so.
pub(crate) fn parse(text: &str) -> Result<Vec<ComposeBox>, String> {
    // Refuse structural YAML we deliberately don't support, BEFORE any parsing — so a billion-laughs
    // or a tab-indented file fails fast with a clear reason, never reaches the line scanner.
    prescreen(text)?;

    // Interpolate `${VAR}` / `${VAR:-default}` at the DOCUMENT level, like Docker — so it works
    // everywhere (ports, command, volumes, environment, build.args), not just in a couple of fields. A
    // per-field pass would miss `ports: ["${PORT}:80"]`; Docker substitutes over the whole file before
    // parsing, and so do we. Unset with no default → empty + warn (Docker semantics), never a literal
    // `${VAR}` left to confuse a downstream tool.
    let text = interpolate_document(text);
    let text = text.as_str();

    let lines = lex(text)?;
    let root = build_tree(&lines)?;

    // Top level must have `services:`. `volumes:`/`networks:`/`version:`/`name:` are recognized;
    // everything else at the top is warned and ignored.
    // Top-level `secrets:` definitions (`name -> file`) — collected first so a service's
    // `secrets: [name]` reference can be resolved to its file. Only the `file:`-backed form maps to
    // kern (`--secret <file>:<name>` → `/run/secrets/<name>`); `external:`/`environment:` secrets warn.
    let secret_files = collect_secret_files(&root);

    let mut boxes = Vec::new();
    let mut have_services = false;
    for (key, node) in &root.children {
        match key.as_str() {
            "services" => {
                have_services = true;
                for (name, svc) in &node.children {
                    // A duplicate service key is a real authoring mistake (two blocks, same name) —
                    // reject it rather than launch two boxes with the same name (which then collide at
                    // start with an opaque "already running", or silently shadow). Docker's YAML parser
                    // rejects duplicate mapping keys too.
                    if boxes.iter().any(|b: &ComposeBox| b.name == *name) {
                        return Err(format!("duplicate service '{name}'"));
                    }
                    boxes.push(service_to_box(name, svc, &secret_files)?);
                }
            }
            "volumes" | "networks" | "version" | "name" | "configs" | "secrets" => {
                // `volumes:`/`secrets:` top-level are consumed elsewhere (volumes auto-created on `-v`
                // use; secrets pre-collected above). `networks:` is the one we actively warn about.
                if key == "networks" {
                    warn("'networks:' ignored — kern connects pod members by name (shared netns)");
                }
            }
            other => warn(&format!("top-level '{other}:' ignored (unsupported)")),
        }
    }
    if !have_services {
        return Err("no `services:` block found".to_string());
    }
    if boxes.is_empty() {
        return Err("`services:` is empty".to_string());
    }
    // A service must resolve to something runnable: an `image` (or a `build:` that produces one). Catch
    // it HERE with a precise message, not later as an opaque "need --rootfs or --image" from the box —
    // parity with the TOML parser's image/rootfs check.
    for b in &boxes {
        let has_image = b.image.as_deref().is_some_and(|s| !s.is_empty());
        let has_rootfs = b.rootfs.as_deref().is_some_and(|s| !s.is_empty());
        if !has_image && !has_rootfs && b.build.is_none() {
            return Err(format!(
                "service '{}' has no `image:`, `rootfs:` or `build:` (nothing to run)",
                b.name
            ));
        }
    }
    degrade_orphan_health_gates(&mut boxes);
    Ok(boxes)
}

/// Resolve `depends_healthy` edges that point at a box with NO `health_cmd` (typically because that
/// box's healthcheck wasn't convertible and we omitted it). Instead of letting `validate_conditions`
/// hard-abort the whole `up` with a message disconnected from the root cause, we DEGRADE the edge to a
/// plain `depends_on` (start-order) and warn ONCE with the causal chain — the honest drop-in-with-
/// degrade posture, and what the omit-healthcheck warning already promised. (Adversarial review: the
/// parser must not promise a degrade it doesn't deliver.)
fn degrade_orphan_health_gates(boxes: &mut [ComposeBox]) {
    // Which service names lack a health command (so a `service_healthy` gate toward them is unsatisfiable).
    let no_health: std::collections::HashSet<String> = boxes
        .iter()
        .filter(|b| b.health_cmd.is_none())
        .map(|b| b.name.clone())
        .collect();
    for b in boxes.iter_mut() {
        let mut kept = Vec::new();
        for dep in std::mem::take(&mut b.depends_healthy) {
            if no_health.contains(&dep) {
                warn(&format!(
                    "service '{}': dependency '{dep}' has no usable healthcheck → its `service_healthy` gate is degraded to start-order (depends_on); verify that's acceptable",
                    b.name
                ));
                if !b.depends_on.contains(&dep) {
                    b.depends_on.push(dep);
                }
            } else {
                kept.push(dep);
            }
        }
        b.depends_healthy = kept;
    }
}

/// Reject structural YAML we don't support, up front, with a precise reason. This is the billion-laughs
/// / tab-indent / multi-doc guard — cheaper and safer than parsing-then-detecting.
fn prescreen(text: &str) -> Result<(), String> {
    for (i, raw) in text.lines().enumerate() {
        let ln = i + 1;
        // Strip a trailing comment for this scan (a `#` inside quotes is handled by the lexer; here we
        // only need to catch structural markers, and those never live inside quotes in a real compose).
        let line = strip_comment_rough(raw);
        let t = line.trim_start();
        if t.is_empty() {
            continue;
        }
        // Tab indentation is invalid YAML and a classic parser trap — refuse rather than guess.
        if line.starts_with('\t')
            || (line.len() > line.trim_start_matches(' ').len() && line.contains('\t'))
        {
            return Err(format!(
                "line {ln}: tab indentation not supported (use spaces)"
            ));
        }
        // 2nd+ document — parse only the first.
        if t == "---" || t == "..." {
            if i == 0 {
                continue; // a leading `---` is fine
            }
            return Err(format!(
                "line {ln}: multi-document YAML not supported (kern reads one compose per file)"
            ));
        }
        // Anchors / aliases / tags / merge keys: refuse on sight, never expand (billion-laughs guard).
        // `after_seq_markers` strips leading `- ` sequence markers first, so a `- *alias` LIST ITEM
        // is caught too — not only a mapping value. (Regression: an alias in list position, e.g.
        // `command:\n  - *boom`, used to slip through `t` (which starts with `- `) AND
        // `value_after_colon` (a list item has no `:`), reaching the box as the literal string
        // `*boom` — a silent mis-conversion, exactly what the module header promises never happens.)
        let structural = after_seq_markers(t);
        if structural.starts_with('&')
            || structural.starts_with('*')
            || structural.starts_with("<<")
        {
            return Err(format!(
                "line {ln}: YAML anchors/aliases/merge-keys not supported (rewrite the value inline)"
            ));
        }
        // A `&anchor`/`*alias` after a `:` (value position) — scan the unquoted part of the value.
        if let Some(v) = value_after_colon(line) {
            let vt = v.trim_start();
            if vt.starts_with('&') || vt.starts_with('*') {
                return Err(format!(
                    "line {ln}: YAML anchors/aliases not supported (rewrite the value inline)"
                ));
            }
        }
        // Block scalars — the `|`/`>` at value position introduces multi-line text we don't parse.
        if let Some(v) = value_after_colon(line) {
            let vt = v.trim();
            if vt == "|"
                || vt == ">"
                || vt.starts_with("|-")
                || vt.starts_with(">-")
                || vt.starts_with("|+")
                || vt.starts_with(">+")
            {
                return Err(format!(
                    "line {ln}: block scalars (`|`/`>`) not supported (use a single-line value)"
                ));
            }
        }
        // An anchor/alias as a TOKEN inside an inline collection — `[*x]`, `[a, *x]`, `{k: *x}`. The
        // two checks above only see the START of the line or the char right after the key `:`; an alias
        // nested inside `[…]`/`{…}` would slip through and reach the box as the literal `*x` (same silent
        // mis-conversion as the list-item case). Scan the whole line (outside quotes) for a `&`/`*` that
        // opens a token: preceded by `[`, `{`, `,` or `:` (with optional spaces).
        if line_has_inline_anchor(line) {
            return Err(format!(
                "line {ln}: YAML anchors/aliases not supported (rewrite the value inline)"
            ));
        }
        // Explicit type tags.
        if t.contains("!!") {
            return Err(format!("line {ln}: YAML type tags (`!!`) not supported"));
        }
        // Unbalanced inline collection at value position — a `[` / `{` that doesn't close on the same
        // line. Without this a `command: [unterminated` would be SILENTLY accepted as the single
        // element `[unterminated` (a lie: a malformed list treated as valid). Refuse it explicitly.
        if let Some(v) = value_after_colon(line) {
            let vt = v.trim();
            if (vt.starts_with('[') || vt.starts_with('{')) && !brackets_balanced(vt) {
                return Err(format!(
                    "line {ln}: unbalanced `[`/`{{` in an inline value (unterminated list/map)"
                ));
            }
        }
    }
    Ok(())
}

/// Are `[`/`]` and `{`/`}` balanced in `s`, ignoring brackets inside quotes? Depth never goes negative
/// and returns to zero. Used to reject an inline collection that isn't closed on its line.
fn brackets_balanced(s: &str) -> bool {
    let mut depth = 0i32;
    let mut q: Option<char> = None;
    for c in s.chars() {
        if let Some(qc) = q {
            if c == qc {
                q = None;
            }
        } else {
            match c {
                '"' | '\'' => q = Some(c),
                '[' | '{' => depth += 1,
                ']' | '}' => {
                    depth -= 1;
                    if depth < 0 {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }
    depth == 0 && q.is_none()
}

/// Byte index of the FIRST top-level key-terminating `:` in `line` (not inside quotes, followed by
/// end-of-line or whitespace), or `None`. The single source of truth for "where does the key end" —
/// both `value_after_colon` and `split_key` derive from it, so key/value slicing can't drift. `:` is
/// ASCII, so the returned index is always a char boundary.
fn colon_index(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut q = 0u8; // 0 = none, else the quote char
    for (i, &c) in bytes.iter().enumerate() {
        if q != 0 {
            if c == q {
                q = 0;
            }
        } else if c == b'"' || c == b'\'' {
            q = c;
        } else if c == b':'
            && (i + 1 >= bytes.len() || bytes[i + 1] == b' ' || bytes[i + 1] == b'\t')
        {
            return Some(i);
        }
    }
    None
}

/// The substring of `line` after the key-terminating `:` (see [`colon_index`]), or `None` if none.
fn value_after_colon(line: &str) -> Option<&str> {
    colon_index(line).map(|i| &line[i + 1..])
}

/// True if `line` contains a YAML anchor (`&x`) or alias (`*x`) as a structural TOKEN (`[*x]`,
/// `[a, *x]`, `{k: *x}`, `{&a k: v}`) — as opposed to a `&`/`*` that is ordinary scalar text
/// (`my*repo`, `2*2`, `a&b`, or anything inside quotes).
///
/// Closed BY CONSTRUCTION, not by enumerating openers. A `&`/`*` outside quotes starts a token — and
/// is therefore an anchor/alias — iff it is NOT preceded (ignoring spaces) by *scalar content*. The
/// complement is the whole trick: if the previous significant byte is scalar content (alphanumeric or
/// the plain-scalar punctuation `_ - . / %% @ + ~`), the `&`/`*` is part of a value; otherwise it opens
/// one — after a separator/opener (`[ { , :`), a `-` list marker, at line start, whatever. Defining
/// "starts a token" (rather than listing the openers that can precede one) means any present-or-future
/// flow separator is covered, and the fuzz can PROVE completeness (no unflagged token-opening `&`/`*`)
/// instead of trusting a hand-kept opener list — the same move as `IpAddr::is_loopback()` for the push
/// loopback check: a canonical definition, not a maintained enumeration.
fn line_has_inline_anchor(line: &str) -> bool {
    fn is_scalar_content(b: u8) -> bool {
        b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b'-' | b'.' | b'/' | b'%' | b'@' | b'+' | b'~')
    }
    let mut q = 0u8; // active quote char, else 0
    let mut prev_content = false; // was the last non-space significant byte scalar content?
    for &c in line.as_bytes() {
        if q != 0 {
            if c == q {
                q = 0;
                prev_content = false; // a closing quote ends a scalar; the quote is not content
            }
            continue;
        }
        match c {
            b'"' | b'\'' => {
                q = c;
                prev_content = false; // an opening quote starts a NEW scalar, not a continuation
            }
            b' ' | b'\t' => {} // spaces don't change whether the last token was content
            b'&' | b'*' => {
                if !prev_content {
                    return true; // token-opening & / * outside quotes → anchor/alias
                }
                prev_content = true; // part of a scalar value (e.g. `a*b`)
            }
            other => prev_content = is_scalar_content(other),
        }
    }
    false
}

/// Strip leading YAML block-sequence markers (`- `, possibly nested `- - `) and surrounding spaces,
/// returning the content that actually starts the node. Used by the prescreen so a structural
/// anchor/alias in LIST-ITEM position (`- *alias`) is seen, not just one in mapping-value position.
/// `-` is ASCII, so every slice is on a char boundary.
fn after_seq_markers(s: &str) -> &str {
    let mut rest = s.trim_start();
    // A bare `-` (empty list item on its own line) is not a marker to strip past — only `- ` (marker
    // followed by content) is. Loop to peel nested `- - x`.
    while let Some(after) = rest.strip_prefix("- ") {
        rest = after.trim_start();
    }
    rest
}

/// The code part of `line` with any trailing `#` comment removed (quote-aware, `#` at BOL or after
/// whitespace). A thin wrapper over the one comment scanner, [`split_at_comment`], so the prescreen,
/// the lexer, and the interpolation pass can never drift on where a comment starts.
fn strip_comment_rough(line: &str) -> &str {
    split_at_comment(line).0
}

/// One lexed line: its indentation (in spaces) and content (comment-stripped, right-trimmed).
struct Line {
    lineno: usize,
    indent: usize,
    content: String,
}

/// Lex the document into non-blank, comment-stripped lines with their space-indent measured.
fn lex(text: &str) -> Result<Vec<Line>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let ln = i + 1;
        if raw.trim() == "---" || raw.trim() == "..." {
            continue; // document markers (prescreen already bounded to the first doc)
        }
        let stripped = strip_comment_precise(raw);
        if stripped.trim().is_empty() {
            continue;
        }
        let indent = stripped.len() - stripped.trim_start_matches(' ').len();
        out.push(Line {
            lineno: ln,
            indent,
            content: stripped.trim().to_string(),
        });
    }
    Ok(out)
}

/// The code part of `line` (comment removed), owned, with leading indentation preserved (the lexer
/// measures indent after). A thin wrapper over the one comment scanner, [`split_at_comment`].
fn strip_comment_precise(line: &str) -> String {
    split_at_comment(line).0.to_string()
}

/// A parsed node: a scalar value and/or child mappings and/or list items. YAML is a tree; we model the
/// slice we need — a mapping (`children`) whose values may be scalars, nested mappings, or sequences.
#[derive(Default)]
struct Node {
    /// Inline scalar on the same line as the key (`image: alpine` → `"alpine"`), if any.
    scalar: Option<String>,
    /// Child mappings, in document order (`key -> node`). Order-preserving for determinism.
    children: Vec<(String, Node)>,
    /// Sequence items (`- x`) as raw scalar strings, in order.
    items: Vec<String>,
}

impl Node {
    fn child(&self, key: &str) -> Option<&Node> {
        self.children.iter().find(|(k, _)| k == key).map(|(_, n)| n)
    }
}

/// Build the mapping tree from lexed lines using an explicit indentation stack (iterative — no
/// recursion, so a deeply-nested document can't overflow the stack; `MAX_DEPTH` caps it anyway).
fn build_tree(lines: &[Line]) -> Result<Node, String> {
    let mut root = Node::default();
    // `path` = child-index chain from root to the CURRENTLY-OPEN mapping; `cols[k]` = the indentation
    // column of the key that opened `path[k]`. Invariant: a child at column C belongs to the deepest
    // open mapping whose opening column is < C. Before placing a line we pop every open level whose
    // column is >= C (they've ended). Iterative — deep nesting can't overflow the stack.
    let mut path: Vec<usize> = Vec::new();
    let mut cols: Vec<usize> = Vec::new();
    // A block-mapping list item being folded into an inline `{…}` string (long-form ports etc.):
    // (path to the owning node, index in its `items`, the dash column). `None` when no item-map is open.
    // Continuation lines (deeper `key: value`) append to it; anything else closes it (appends `}`).
    let mut item_map: Option<(Vec<usize>, usize, usize)> = None;

    for ln in lines {
        // Close an open block-mapping item if this line is NOT its continuation (same path, deeper
        // indent, `key: value`). Closing appends the `}` so `reconstruct_port_item` sees a valid inline.
        if let Some((im_path, im_idx, im_col)) = item_map.clone() {
            let is_continuation =
                im_path == path && ln.indent > im_col && colon_index(&ln.content).is_some();
            if !is_continuation {
                descend_mut(&mut root, &im_path).items[im_idx].push('}');
                item_map = None;
            } else {
                let acc = &mut descend_mut(&mut root, &path).items[im_idx];
                acc.push_str(", ");
                acc.push_str(&ln.content);
                continue;
            }
        }

        // Dedent / sibling: pop levels whose opening column is >= this line's column. A list item (`-`)
        // lives AT its key's child-indent, so the same rule applies.
        while let Some(&c) = cols.last() {
            if ln.indent <= c {
                path.pop();
                cols.pop();
            } else {
                break;
            }
        }
        if path.len() > MAX_DEPTH {
            return Err(format!(
                "line {}: nesting too deep (max {MAX_DEPTH})",
                ln.lineno
            ));
        }

        // List item: append to the mapping that opened the current level. A YAML sequence item is a
        // dash FOLLOWED BY WHITESPACE (`- x`) or a bare `-` (empty). A dash NOT followed by space is
        // part of a key — e.g. `--net:` is a (bad) key, NOT the list item `-net:`. Matching a bare
        // `strip_prefix('-')` mis-parsed `--net:` as a list item; require the space/EOL boundary.
        let is_list_item = ln.content == "-"
            || ln
                .content
                .strip_prefix('-')
                .is_some_and(|r| r.starts_with([' ', '\t']));
        if is_list_item {
            let item = ln.content[1..].trim();
            if item.is_empty() {
                return Err(format!("line {}: empty list item", ln.lineno));
            }
            let cur = descend_mut(&mut root, &path);
            // A list item that is itself a `key: value` (a block-mapping element, e.g. the long-form
            // `- target: 443` with `published: 8443` on the next deeper line) opens a mapping. Model it
            // WITHOUT a full list-of-maps type: start folding it into an inline `{k: v, …}` string that
            // `reconstruct_port_item` already parses; continuation lines append (see the loop top),
            // and it's closed with `}` when the mapping ends. A plain scalar item is pushed as-is.
            if colon_index(item).is_some() {
                cur.items.push(format!("{{{item}"));
                item_map = Some((path.clone(), cur.items.len() - 1, ln.indent));
            } else {
                cur.items.push(item.to_string());
            }
            continue;
        }

        // `key:` or `key: value`.
        let (key, val) = split_key(&ln.content, ln.lineno)?;
        let inline = val.filter(|v| !v.is_empty());
        let mut node = Node::default();
        if let Some(v) = inline {
            let vt = v.trim();
            // ALWAYS keep the raw value as `scalar` — a converter that wants the verbatim value
            // (`environment`, where `CFG: {"k":"v"}` is a JSON string that must NOT be structured) reads
            // it as-is. ADDITIONALLY, for an inline TABLE (`{…}`), also parse it into `children`, so a
            // converter that wants structure (`healthcheck`/`depends_on`/`build`) reads children. Keeping
            // BOTH avoids the two-sided bug: an inline table was dropped when only-scalar (env/health/
            // conditions vanished), and a JSON env value was over-structured when only-children (the
            // env var came out empty). Each converter picks the representation it needs.
            node.scalar = Some(v.to_string());
            if vt.starts_with('{') {
                let parsed = parse_inline_table(vt);
                node.children = parsed.children;
            }
        }
        let cur = descend_mut(&mut root, &path);
        cur.children.push((key.to_string(), node));
        // No inline scalar → this key opens a nested mapping/sequence: push it as the new open level.
        if inline.is_none() {
            let idx = cur.children.len() - 1;
            path.push(idx);
            cols.push(ln.indent);
        }
    }
    // Close a block-mapping list item still open at end-of-document.
    if let Some((im_path, im_idx, _)) = item_map {
        descend_mut(&mut root, &im_path).items[im_idx].push('}');
    }
    Ok(root)
}

/// Walk `root` down the child-index `path`, returning `&mut` to the addressed node.
fn descend_mut<'a>(root: &'a mut Node, path: &[usize]) -> &'a mut Node {
    let mut cur = root;
    for &idx in path {
        cur = &mut cur.children[idx].1;
    }
    cur
}

/// Split a `key: value` line into `(key, Some(value))` or a bare `key:` into `(key, Some(""))`.
/// Quote-aware on the key side so a quoted key with a `:` is handled; the value keeps its raw form
/// (unquoted here — `scalar_str` unquotes at use).
fn split_key(content: &str, lineno: usize) -> Result<(&str, Option<&str>), String> {
    let Some(colon) = colon_index(content) else {
        return Err(format!("line {lineno}: expected `key: value`"));
    };
    // Slice at the colon index directly — no length arithmetic, so no risk of an unsigned underflow
    // if the helpers ever change. `colon` and `colon + 1` are ASCII-`:` boundaries.
    let key = strip_quotes(content[..colon].trim());
    if key.is_empty() {
        return Err(format!("line {lineno}: empty key"));
    }
    Ok((key, Some(content[colon + 1..].trim())))
}

/// Strip one layer of matching single/double quotes from a scalar, if present. YAML single-quotes
/// don't process escapes; double-quotes do, but for compose values (paths, images, commands) we treat
/// the inner text verbatim — no numeric coercion, no escape expansion — which is exactly what we want
/// (verbatim → the sexagesimal trap can't fire, and argv values reach `kern box` unmodified).
fn strip_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// A scalar value as an owned, unquoted string.
fn scalar_str(s: &str) -> String {
    strip_quotes(s.trim()).to_string()
}

/// Parse a YAML inline table `{k: v, k2: {…}, k3: [a, b]}` into a [`Node`] with `children`. Values that
/// are themselves inline tables recurse; inline lists / scalars are stored as the child's `scalar`
/// (the value converters already parse a `[…]` scalar). Depth- and quote-aware comma split; slicing on
/// ASCII delimiters only. This is what makes `healthcheck: {…}` / `environment: {…}` / `depends_on:
/// {…}` all work from the inline form, uniformly.
fn parse_inline_table(s: &str) -> Node {
    let mut node = Node::default();
    let inner = s
        .trim()
        .strip_prefix('{')
        .and_then(|x| x.strip_suffix('}'))
        .unwrap_or(s);
    for entry in split_top_commas(inner) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some(colon) = colon_index_or_first(entry) else {
            continue;
        };
        let key = scalar_str(&entry[..colon]);
        if key.is_empty() {
            continue;
        }
        let val = entry[colon + 1..].trim();
        let mut child = Node::default();
        if val.starts_with('{') {
            child = parse_inline_table(val); // nested table (e.g. depends_on's `{condition: …}`)
        } else if !val.is_empty() {
            child.scalar = Some(val.to_string()); // scalar or inline list `[…]`
        }
        node.children.push((key, child));
    }
    node
}

/// The index of the first `:` in an inline-table entry that separates key from value — quote-aware so
/// a `:` inside a quoted key/value doesn't split early. Unlike `colon_index` (which requires the `:`
/// be followed by space/EOL, YAML block rule), an inline-table `{k:v}` may have no space, so we take
/// the first top-level unquoted `:`.
fn colon_index_or_first(s: &str) -> Option<usize> {
    let mut q: Option<char> = None;
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            _ if Some(c) == q => q = None,
            '"' | '\'' if q.is_none() => q = Some(c),
            '{' | '[' if q.is_none() => depth += 1,
            '}' | ']' if q.is_none() => depth -= 1,
            ':' if q.is_none() && depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// Is a node's scalar a YAML truthy (`true`/`yes`/`on`/`1`)? For boolean compose keys like `read_only`.
fn scalar_is_true(node: &Node) -> bool {
    node.scalar
        .as_deref()
        .map(scalar_str)
        .map(|s| matches!(s.to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1"))
        .unwrap_or(false)
}

/// Parse an inline YAML list `[a, b, "c d"]` OR a block list (already collected in `node.items`) into a
/// vec of unquoted strings. Depth-aware split so a nested `[]`/`{}` inside an item isn't broken on its
/// commas; quote-aware so a comma inside quotes is preserved.
fn parse_inline_list(s: &str) -> Vec<String> {
    let s = s.trim();
    let inner = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    split_top_commas(inner)
        .into_iter()
        .map(|x| scalar_str(&x))
        .filter(|x| !x.is_empty())
        .collect()
}

/// Split on top-level commas (depth 0, outside quotes) — shared shape with the TOML depends parser.
fn split_top_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut q: Option<char> = None;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        if let Some(qc) = q {
            if c == qc {
                q = None;
            }
        } else if c == '"' || c == '\'' {
            q = Some(c);
        } else if c == '[' || c == '{' {
            depth += 1;
        } else if c == ']' || c == '}' {
            depth -= 1;
        } else if c == ',' && depth == 0 {
            out.push(s[start..i].to_string());
            start = i + 1;
        }
    }
    out.push(s[start..].to_string());
    out
}

/// A list value for a compose key: either the inline `[…]` scalar or the block `- ` items.
fn list_value(node: &Node) -> Vec<String> {
    if let Some(sc) = &node.scalar {
        if sc.trim_start().starts_with('[') {
            return parse_inline_list(sc);
        }
        // A bare scalar where a list is expected (`command: echo hi`) → single element.
        return vec![scalar_str(sc)];
    }
    node.items
        .iter()
        .map(|it| {
            // A block item may itself be an inline list element or a quoted string.
            scalar_str(it)
        })
        .collect()
}

/// A service's `secrets:` reference names. Short form is a list of names (`[db_pw, api_key]`); long
/// form is a list of maps each with a `source:` (`[{source: db_pw, target: …}]`) — we take `source`
/// (the target is always `/run/secrets/<source>` in kern). Returns the referenced secret names.
fn secret_refs(node: &Node) -> Vec<String> {
    let mut out = Vec::new();
    for it in list_value(node) {
        let it = it.trim();
        if it.starts_with('{') {
            // long-form inline `{source: name, target: …}` — pull `source`.
            let n = parse_inline_table(it);
            if let Some(src) = n.child("source").and_then(|s| s.scalar.as_deref()) {
                out.push(scalar_str(src));
            }
        } else if !it.is_empty() {
            out.push(scalar_str(it));
        }
    }
    // Block long-form (`- source: name` on its own lines) is handled too: `build_tree` folds each
    // block list item's `key: value` children into an inline `{source: name, …}` scalar, so it arrives
    // at the `{`-prefixed branch above. No separate code path needed.
    out
}

/// Collect top-level `secrets:` definitions into `name -> file` for the `file:`-backed form (the only
/// one kern maps: it delivers the file at `/run/secrets/<name>`). A secret with no `file:` (external,
/// or environment-backed) yields no entry → a service referencing it warns at conversion.
fn collect_secret_files(root: &Node) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    if let Some(sec) = root.child("secrets") {
        for (name, def) in &sec.children {
            if let Some(file) = def.child("file").and_then(|f| f.scalar.as_deref()) {
                out.insert(name.clone(), scalar_str(file));
            }
        }
    }
    out
}

/// Convert one `services:` entry into a `ComposeBox`, applying every mapping rule + degrade-with-warn.
/// `secret_files` maps a top-level secret name to its backing file (for `secrets: [name]` refs).
fn service_to_box(
    name: &str,
    svc: &Node,
    secret_files: &std::collections::HashMap<String, String>,
) -> Result<ComposeBox, String> {
    kern_common::BoxName::parse(name)
        .map_err(|e| format!("service '{name}': invalid name: {e}"))?;
    let mut b = ComposeBox::new(name.to_string());
    // `entrypoint` + `command` are composed as `entrypoint ++ command` (Docker semantics) — but ONLY
    // after the whole service is parsed, since the two keys can appear in EITHER order in the file.
    // Merging inline (as before) was order-dependent: if `entrypoint` came first, `command` hadn't been
    // read yet, then `command` overwrote the merge → the entrypoint was dropped and the box tried to
    // exec the bare command as a program.
    let mut entrypoint: Vec<String> = Vec::new();
    // Whether the entrypoint was written in SHELL form (a bare string `entrypoint: /init here` →
    // `sh -c "/init here"`) vs EXEC form (a list). It changes how `command` composes: Docker appends
    // `command` only to an EXEC-form entrypoint; a shell-form entrypoint is the whole command and
    // `command` is dropped (appending it would make the args shell positional params, not entrypoint
    // args — the box would run `/init here` and silently discard `command`). See the merge below.
    let mut entrypoint_is_shell_form = false;

    for (key, node) in &svc.children {
        match key.as_str() {
            "image" => b.image = node.scalar.as_deref().map(scalar_str),
            // `rootfs`/`bind_rootfs` are kern-native keys (not Docker compose) — accepted so a kern
            // stack authored in YAML can use a host rootfs dir instead of an OCI image.
            "rootfs" => b.rootfs = node.scalar.as_deref().map(scalar_str),
            "bind_rootfs" => b.bind_rootfs = scalar_is_true(node),
            "container_name" => {} // kern names the box by the service key; ignore
            "command" => b.command = command_value(node),
            "entrypoint" => {
                let (ep, shell_form) = entrypoint_value(node);
                entrypoint = ep;
                entrypoint_is_shell_form = shell_form;
            }
            "environment" => b.env = kv_pairs(node),
            "env_file" => b.env_file = list_value(node),
            "ports" => b.ports = ports_value(node, name),
            "volumes" => b.volumes = volumes_value(node),
            "depends_on" => apply_depends(&mut b, node),
            "healthcheck" => apply_healthcheck(&mut b, node, name),
            "restart" => apply_restart(&mut b, node, name),
            "user" => b.user = node.scalar.as_deref().map(scalar_str),
            "working_dir" | "workdir" => b.workdir = node.scalar.as_deref().map(scalar_str),
            "build" => b.build = Some(build_value(node)),
            // Resource / capability / hardening keys — these map 1:1 to `kern box` flags the runtime
            // already enforces, so CONVERT them (not warn-and-ignore): a compose that sets `mem_limit`
            // or `read_only` must get those limits, else the stack "runs but without the constraints
            // the user asked for" — worse than a visible gap.
            "mem_limit" | "memory" => b.memory = node.scalar.as_deref().map(scalar_str),
            "memswap_limit" | "mem_swap_limit" => {
                b.swap_max = node.scalar.as_deref().map(scalar_str)
            }
            "cpus" => b.cpus = node.scalar.as_deref().map(scalar_str),
            "cpuset" => b.cpuset = node.scalar.as_deref().map(scalar_str),
            "pids_limit" => b.pids_limit = node.scalar.as_deref().map(scalar_str),
            "hostname" => b.hostname = node.scalar.as_deref().map(scalar_str),
            "cap_add" => b.cap_add = list_value(node),
            "cap_drop" => b.cap_drop = list_value(node),
            "tmpfs" => b.tmpfs = list_value(node),
            "read_only" => b.read_only = scalar_is_true(node),
            // `privileged: true` has no kern equivalent (rootless by design) — warn, don't silently
            // pretend. The box runs UNprivileged; a workload needing real privilege will notice.
            "privileged" => {
                if scalar_is_true(node) {
                    warn(&format!(
                        "service '{name}': 'privileged: true' has no kern equivalent (rootless) — running unprivileged"
                    ));
                }
            }
            "secrets" => {
                // A service `secrets: [name, …]` (or long-form `{source: name, target: …}`) references
                // top-level secret definitions. Map each `file:`-backed one to `--secret <file>:<name>`
                // (kern delivers it at `/run/secrets/<name>`, mode 0400) — matching compose's mount
                // point exactly. `<file>` is relative → `compose()` makes it absolute (dir-confined).
                for entry in secret_refs(node) {
                    match secret_files.get(&entry) {
                        Some(file) => b.secrets.push(format!("{file}:{entry}")),
                        None => warn(&format!(
                            "service '{name}': secret '{entry}' has no top-level `file:` definition — skipped (external/env secrets aren't supported)"
                        )),
                    }
                }
            }
            "networks" | "deploy" | "configs" | "labels" | "logging" | "profiles" | "expose"
            | "extends" | "init" | "stdin_open" | "tty" | "domainname" => {
                warn(&format!("service '{name}': '{key}:' ignored (unsupported)"));
            }
            other => warn(&format!(
                "service '{name}': '{other}:' ignored (unsupported)"
            )),
        }
    }
    // Compose entrypoint + command AFTER the loop (order-independent). Docker's rule depends on the
    // entrypoint FORM:
    //  * EXEC-form entrypoint (a list) → final argv is `entrypoint ++ command`.
    //  * SHELL-form entrypoint (`entrypoint: /init here` → `sh -c "/init here"`) → the shell string IS
    //    the whole command; Docker IGNORES `command`. Appending it would put the args after
    //    `sh -c <string>`, where they become the shell's positional params ($0,$1…) — NOT arguments to
    //    the entrypoint — so the box would run `/init here` and silently discard `command` (a "runs and
    //    lies" mis-conversion the audit caught). We drop `command` with a warning instead.
    if !entrypoint.is_empty() {
        if entrypoint_is_shell_form {
            if !b.command.is_empty() {
                warn(&format!(
                    "service '{name}': a shell-form `entrypoint` ignores `command` (Docker semantics) — `command` dropped; use an exec-form (list) entrypoint to pass args"
                ));
            }
            b.command = entrypoint;
        } else {
            let mut merged = entrypoint;
            merged.append(&mut b.command);
            b.command = merged;
        }
    }
    Ok(b)
}

/// `command`: exec-form list → argv verbatim; shell-form string → `sh -c "<string>"` (Docker semantics).
fn command_value(node: &Node) -> Vec<String> {
    command_argv(node).0
}

/// The entrypoint argv PLUS whether it was shell-form (a bare string) — the merge with `command`
/// branches on it (see `service_to_box`). Shares one parser with `command`, so the two can't drift.
fn entrypoint_value(node: &Node) -> (Vec<String>, bool) {
    command_argv(node)
}

/// Parse a `command`/`entrypoint` node → `(argv, is_shell_form)`. `is_shell_form` is true only for a
/// bare (non-`[`) scalar string, which we wrap as `sh -c "<string>"`; a list (inline or block) is
/// exec-form (`false`).
fn command_argv(node: &Node) -> (Vec<String>, bool) {
    if let Some(sc) = &node.scalar {
        let sc = sc.trim();
        if sc.starts_with('[') {
            return (parse_inline_list(sc), false); // exec-form
        }
        if !sc.is_empty() {
            // shell-form: a bare string is run via a shell, like Docker.
            return (
                vec!["sh".to_string(), "-c".to_string(), scalar_str(sc)],
                true,
            );
        }
    }
    if !node.items.is_empty() {
        return (node.items.iter().map(|i| scalar_str(i)).collect(), false); // exec-form block list
    }
    (Vec::new(), false)
}

/// A `K=v` collection written in either compose shape — a list of `- K=v` (or bare `- KEY`, passed
/// through like Docker) and/or a map of `K: v` — flattened to `["K=v", …]`. Shared by `environment`
/// and `build.args`, which have the identical YAML shape, so the two can't drift. `${VAR}` is already
/// substituted document-wide (see `interpolate_document`), so values are used verbatim here.
fn kv_pairs(node: &Node) -> Vec<String> {
    let mut out = Vec::new();
    for it in &node.items {
        out.push(scalar_str(it));
    }
    for (k, v) in &node.children {
        let raw = v.scalar.as_deref().map(scalar_str).unwrap_or_default();
        out.push(format!("{k}={raw}"));
    }
    out
}

/// Substitute `${VAR}` and `${VAR:-default}` throughout the compose text from the host env, like
/// Docker's pre-parse interpolation. Handles `$$` → literal `$` (Docker's escape). An unset var with
/// no default → empty string + one warning (Docker semantics), never a leftover literal `${VAR}` that
/// would confuse a downstream tool. `$VAR` without braces and other `${...}` operators are left as-is.
///
/// COMMENT-AWARE: a `${VAR}` inside a trailing `#` comment is NOT substituted and raises no unset-var
/// warning (the comment text is dropped by the lexer anyway; interpolating it only produced spurious
/// stderr noise — audit finding). We split each line at its first unquoted `#`, interpolate the code
/// part, and re-attach the comment verbatim.
fn interpolate_document(text: &str) -> String {
    if !text.contains('$') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    // `text.lines()` drops the line terminators; rebuild them. A trailing newline is preserved by
    // checking the original. We interpolate only the pre-comment part of each line.
    let ends_with_nl = text.ends_with('\n');
    let mut first = true;
    for line in text.lines() {
        if !first {
            out.push('\n');
        }
        first = false;
        let (code, comment) = split_at_comment(line);
        out.push_str(&interpolate_fragment(code));
        out.push_str(comment); // verbatim — no interpolation, no warning
    }
    if ends_with_nl {
        out.push('\n');
    }
    out
}

/// Split a line into `(code, comment)` at the first unquoted `#` (the `#` and everything after it is
/// the comment). Quote-aware, matching the lexer's comment rule so we agree on where a value ends.
fn split_at_comment(line: &str) -> (&str, &str) {
    let bytes = line.as_bytes();
    let mut q = 0u8;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if q != 0 {
            if c == q {
                q = 0;
            }
        } else if c == b'"' || c == b'\'' {
            q = c;
        } else if c == b'#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return (&line[..i], &line[i..]);
        }
        i += 1;
    }
    (line, "")
}

/// Interpolate `${VAR}`/`${VAR:-default}`/`$$` in a single comment-free fragment. Slices are at
/// `${`/`}`/`$$` ASCII offsets, so multibyte values in the document are never sliced mid-char.
fn interpolate_fragment(text: &str) -> String {
    if !text.contains('$') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(tail) = after.strip_prefix('$') {
            // `$$` → literal `$`.
            out.push('$');
            rest = tail;
            continue;
        }
        let Some(inner) = after.strip_prefix('{') else {
            // `$` not followed by `{` (or `$`): leave the `$` and continue (bare `$VAR` passthrough).
            out.push('$');
            rest = after;
            continue;
        };
        let Some(end) = inner.find('}') else {
            // Unterminated `${` — leave it literal (the prescreen doesn't reject it here); a downstream
            // parse error will surface if it matters. Don't loop forever.
            out.push_str("${");
            rest = inner;
            continue;
        };
        let expr = &inner[..end];
        // Nested/odd interpolation like `${A${B}}` (Docker doesn't support it either): the first `}`
        // closes at `A${B`, which would substitute empty and leak a stray `}` downstream. If the expr
        // contains a `$` or `{`, pass the WHOLE `${expr}` through verbatim — never emit a fragment.
        if expr.contains('$') || expr.contains('{') {
            out.push_str("${");
            out.push_str(expr);
            out.push('}');
            rest = &inner[end + 1..];
            continue;
        }
        let (var, default) = match expr.split_once(":-") {
            Some((v, d)) => (v, Some(d)),
            None => (expr, None),
        };
        match std::env::var(var)
            .ok()
            .or_else(|| default.map(String::from))
        {
            Some(val) => out.push_str(&val),
            None => warn(&format!(
                "${{{var}}} is not set (no default) — substituted empty (set it in your shell, like Docker)"
            )),
        }
        rest = &inner[end + 1..];
    }
    out.push_str(rest);
    out
}

/// `ports`: each entry → a `--publish` string, RAW (no numeric coercion → the sexagesimal trap can't
/// fire). Long-form (`{target,published,...}`) is reconstructed from fields, not passed verbatim.
/// `/udp` (and any non-TCP proto) is refused-with-warning — kern publishes TCP only, and silently
/// dropping the proto would mislead. A plain `host:box` (no host-IP) publishes on kern's loopback
/// default, which differs from Docker's all-interfaces default → warn so a Docker user isn't surprised
/// their service "doesn't answer from outside".
fn ports_value(node: &Node, svc: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_spec = |spec: String| {
        let (host_port, proto) = match spec.rsplit_once('/') {
            Some((p, proto)) => (p.to_string(), Some(proto.to_ascii_lowercase())),
            None => (spec.clone(), None),
        };
        if let Some(pr) = &proto {
            if pr != "tcp" {
                warn(&format!(
                    "service '{svc}': port '{spec}' uses /{pr} — kern publishes TCP only, entry SKIPPED"
                ));
                return;
            }
        }
        // host:box with no host-IP → kern binds loopback (secure default, unlike Docker's 0.0.0.0).
        let colons = host_port.matches(':').count();
        if colons == 1 {
            warn(&format!(
                "service '{svc}': port '{host_port}' bound to 127.0.0.1 (kern is loopback-default, unlike Docker); use 0.0.0.0:{host_port} to expose on all interfaces"
            ));
        }
        out.push(host_port);
    };

    // Block or inline list of entries.
    let entries: Vec<String> = if let Some(sc) = &node.scalar {
        if sc.trim_start().starts_with('[') {
            parse_inline_list(sc)
        } else {
            vec![scalar_str(sc)]
        }
    } else if !node.items.is_empty() {
        // Items may be scalars ("8080:80") or inline-table long-form ({target: 80, published: 8080}).
        node.items
            .iter()
            .map(|it| reconstruct_port_item(it, svc))
            .collect()
    } else {
        // A `ports:` whose entries are BLOCK mappings (a `- ` opening a nested mapping over several
        // lines, rather than an inline `{…}`) lands here with no scalar/items — a shape we don't
        // reconstruct. NEVER silently drop it: warn so the user knows a port wasn't published.
        if !node.children.is_empty() {
            warn(&format!(
                "service '{svc}': block-mapping long-form `ports` not supported — use inline `{{target: N, published: M}}` or a \"M:N\" string; entry SKIPPED"
            ));
        }
        Vec::new()
    };
    for e in entries {
        if !e.is_empty() {
            push_spec(e);
        }
    }
    out
}

/// Turn one `ports` list item into a `[ip:]host:box[/proto]` string. A plain scalar passes through; an
/// inline-table long-form (`{target: 80, published: 8080, protocol: udp}`) is REBUILT from its fields
/// (never passed verbatim — it's an object, not a string).
fn reconstruct_port_item(item: &str, svc: &str) -> String {
    let t = item.trim();
    if !t.starts_with('{') {
        return scalar_str(t);
    }
    let inner = t.trim_start_matches('{').trim_end_matches('}');
    let (mut target, mut published, mut proto, mut host_ip) =
        (String::new(), String::new(), String::new(), String::new());
    for field in split_top_commas(inner) {
        if let Some((k, v)) = field.split_once(':') {
            let (k, v) = (k.trim(), scalar_str(v));
            match k {
                "target" => target = v,
                "published" => published = v,
                "protocol" => proto = v,
                "host_ip" => host_ip = v,
                _ => {}
            }
        }
    }
    if target.is_empty() {
        warn(&format!(
            "service '{svc}': a long-form port has no `target` — skipped"
        ));
        return String::new();
    }
    let published = if published.is_empty() {
        target.clone()
    } else {
        published
    };
    let mut spec = if host_ip.is_empty() {
        format!("{published}:{target}")
    } else {
        format!("{host_ip}:{published}:{target}")
    };
    if !proto.is_empty() {
        spec.push('/');
        spec.push_str(&proto);
    }
    spec
}

/// `volumes`: each `src:dst[:ro]` entry verbatim (kern's `-v` grammar matches compose's short form).
fn volumes_value(node: &Node) -> Vec<String> {
    list_value(node)
}

/// `depends_on`: short list → start-order; long-form map with `condition:` → healthy/completed buckets.
fn apply_depends(b: &mut ComposeBox, node: &Node) {
    // Route one (dep, condition) into the right bucket.
    fn route(b: &mut ComposeBox, dep: &str, cond: &str) {
        match cond {
            "service_healthy" => b.depends_healthy.push(dep.to_string()),
            "service_completed_successfully" => b.depends_completed.push(dep.to_string()),
            "service_started" => b.depends_on.push(dep.to_string()),
            other => {
                warn(&format!(
                    "service '{}': depends_on '{dep}' condition '{other}' unknown → treated as start-order",
                    b.name
                ));
                b.depends_on.push(dep.to_string());
            }
        }
    }
    // Inline / block short list (`[a, b]` scalar or `- a` items) → start-order.
    if node.items.is_empty() && node.children.is_empty() {
        if node.scalar.is_some() {
            b.depends_on = list_value(node);
        }
        return;
    }
    if !node.items.is_empty() {
        b.depends_on = list_value(node);
        return;
    }
    // Long-form (block OR inline `{db: {condition: …}}` — both now parsed into `children` by
    // `parse_inline_table`): each child is a service with an optional `condition:` mapping.
    for (dep, spec) in &node.children {
        let cond = spec
            .child("condition")
            .and_then(|c| c.scalar.as_deref())
            .map(scalar_str)
            .unwrap_or_else(|| "service_started".to_string());
        route(b, dep, &cond);
    }
}

/// `healthcheck`: map `test` fedele (CMD exec → argv; CMD-SHELL / bare-string → `sh -c`), else OMIT +
/// warn (a half-converted health lies and breaks a downstream `depends_healthy`; `compose()` degrades
/// that gate with a linked warning). `interval`/`timeout`/`retries`/`start_period` map 1:1.
fn apply_healthcheck(b: &mut ComposeBox, node: &Node, svc: &str) {
    // `disable: true` → no health.
    if node
        .child("disable")
        .and_then(|d| d.scalar.as_deref())
        .map(scalar_str)
        .as_deref()
        == Some("true")
    {
        return;
    }
    let Some(test) = node.child("test") else {
        warn(&format!(
            "service '{svc}': healthcheck has no `test` — omitted"
        ));
        return;
    };
    let cmd = healthcheck_test(test);
    match cmd {
        Some(c) => b.health_cmd = Some(c),
        None => {
            // Omit the health entirely rather than half-convert it (a partial health lies). Any
            // `depends_healthy` edge toward this box is degraded to start-order later in
            // `degrade_orphan_health_gates`, which emits the linked, direction-correct warning.
            warn(&format!(
                "service '{svc}': healthcheck `test` not convertible — omitted"
            ));
            return;
        }
    }
    if let Some(v) = node.child("interval").and_then(|n| n.scalar.as_deref()) {
        b.health_interval = parse_duration_secs(&scalar_str(v));
    }
    if let Some(v) = node.child("retries").and_then(|n| n.scalar.as_deref()) {
        // `retries` is a plain count (`--health-retries <n>`), no duration suffix.
        b.health_retries = Some(scalar_str(v));
    }
    // `timeout`/`start_period` map to `--health-{timeout,start-period} <seconds>` — an INTEGER count of
    // seconds. Docker writes them as durations (`30s`, `1m30s`, `0s`), so we must convert, not pass the
    // raw string: `--health-timeout 30s` fails the CLI's `u64` parse. Route them through the same
    // `parse_duration_secs` as `interval`; an unparseable/overflowing value is dropped (box default)
    // rather than forwarded to fail the child. (Found by an extreme test: `start_period: 0s` / any
    // `timeout: 30s`, the standard Docker form, aborted the box.)
    if let Some(v) = node.child("timeout").and_then(|n| n.scalar.as_deref()) {
        b.health_timeout = parse_duration_secs(&scalar_str(v)).map(|s| s.to_string());
    }
    if let Some(v) = node.child("start_period").and_then(|n| n.scalar.as_deref()) {
        // `0s` is a legitimate value (no grace), and `parse_duration_secs` returns `None` for 0 (its
        // `total > 0` gate) — but `--health-start-period 0` is valid and meaningful, so map a parsed-
        // or-zero duration explicitly: only a truly unparseable value is dropped.
        let raw = scalar_str(v);
        b.health_start_period = duration_secs_allowing_zero(&raw).map(|s| s.to_string());
    }
}

/// Like [`parse_duration_secs`] but 0 is a valid result (not `None`). `interval`/`timeout` treat 0 as
/// "unset → default", but `start_period: 0s` means "no grace" and must reach the box as `0`.
fn duration_secs_allowing_zero(s: &str) -> Option<i64> {
    let t = s.trim();
    if t == "0" || t == "0s" {
        return Some(0);
    }
    parse_duration_secs(t)
}

/// Convert a healthcheck `test` to a health command, or `None` if not faithfully convertible.
///  * `["CMD", "curl", "-f", "u"]`      → exec-form → `curl -f u` (argv joined for `--health-cmd`)
///  * `["CMD-SHELL", "curl -f u"]`      → shell-form → the shell string
///  * bare string `"curl -f u"`         → IMPLICIT CMD-SHELL (Docker) → the string (NEVER split-on-space)
///  * `["NONE"]`                        → no health → `None` (caller omits)
fn healthcheck_test(node: &Node) -> Option<String> {
    // Inline / block list form.
    let list = if let Some(sc) = &node.scalar {
        let sc = sc.trim();
        if sc.starts_with('[') {
            Some(parse_inline_list(sc))
        } else if !sc.is_empty() {
            // Bare string = implicit CMD-SHELL. Return verbatim (the box wraps it in `sh -c`).
            return Some(scalar_str(sc));
        } else {
            None
        }
    } else if !node.items.is_empty() {
        Some(node.items.iter().map(|i| scalar_str(i)).collect())
    } else {
        None
    };
    let list = list?;
    let (head, rest) = list.split_first()?;
    match head.as_str() {
        "NONE" => None,
        "CMD-SHELL" => rest.first().cloned(),
        "CMD" => {
            if rest.is_empty() {
                None
            } else {
                // exec-form: join argv into a command line the health-checker runs.
                Some(rest.join(" "))
            }
        }
        // A list whose first item isn't a known directive → treat the whole thing as a shell string
        // only if it's a single element; otherwise not faithfully convertible.
        _ if list.len() == 1 => Some(list[0].clone()),
        _ => None,
    }
}

/// A compose duration (`30s`, `1m30s`, or a bare number of seconds) → whole seconds. Best-effort; a
/// form we don't understand — OR one that overflows — yields `None` (the box uses its default
/// interval).
///
/// The value is UNTRUSTED (a third-party `interval:`), so every step uses CHECKED arithmetic: a huge
/// digit-run like `6000000000000000h` must fall back to `None`, never panic (debug) or wrap to a
/// nonsense value (release). This is the parser's "never a panic, never a lie" contract on the one
/// compose field routed through here. (Found by the extreme audit; the older randomized fuzz never
/// emitted a long digit-run after `interval:`.)
fn parse_duration_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let mut total: i64 = 0;
    let mut num = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            let n: i64 = num.parse().ok()?; // >19 digits → parse Err → None (no panic)
            num.clear();
            let secs = match c {
                's' => n,
                'm' => n.checked_mul(60)?,
                'h' => n.checked_mul(3600)?,
                _ => return None,
            };
            total = total.checked_add(secs)?;
        }
    }
    if !num.is_empty() {
        total = total.checked_add(num.parse::<i64>().ok()?)?;
    }
    (total > 0).then_some(total)
}

/// `restart`: `no`→off; `on-failure`→on; `always`/`unless-stopped`→on + warn (kern has on-failure only).
fn apply_restart(b: &mut ComposeBox, node: &Node, svc: &str) {
    let v = node.scalar.as_deref().map(scalar_str).unwrap_or_default();
    match v.as_str() {
        "" | "no" => b.restart = false,
        "on-failure" => b.restart = true,
        "always" | "unless-stopped" => {
            b.restart = true;
            warn(&format!(
                "service '{svc}': restart '{v}' → kern uses on-failure (restarts on non-zero exit, not always)"
            ));
        }
        other => {
            warn(&format!(
                "service '{svc}': unknown restart '{other}' — treated as on-failure"
            ));
            b.restart = true;
        }
    }
}

/// `build`: resolve to a [`BuildDirective`]. `context`/`dockerfile` are kept RELATIVE (the caller in
/// `compose()` confines them under the compose file's dir — traversal guard). `args` values are
/// already `${VAR}`-substituted document-wide.
fn build_value(node: &Node) -> BuildDirective {
    // Short form: `build: ./dir`
    if let Some(sc) = &node.scalar {
        let sc = scalar_str(sc);
        if !sc.is_empty() {
            return BuildDirective {
                context: sc,
                dockerfile: None,
                args: Vec::new(),
            };
        }
    }
    // Long form: `build: {context:, dockerfile:, args:}`
    let context = node
        .child("context")
        .and_then(|n| n.scalar.as_deref())
        .map(scalar_str)
        .unwrap_or_else(|| ".".to_string());
    let dockerfile = node
        .child("dockerfile")
        .and_then(|n| n.scalar.as_deref())
        .map(scalar_str);
    // `args` is the same `- K=v` list / `K: v` map shape as `environment`.
    let args = node.child("args").map(kv_pairs).unwrap_or_default();
    BuildDirective {
        context,
        dockerfile,
        args,
    }
}

/// Emit a compat warning to stderr. Prefixed so it's clearly kern's compose-import voice, and so the
/// user sees exactly which part of their compose didn't map 1:1.
fn warn(msg: &str) {
    eprintln!("kern compose: {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxes(y: &str) -> Vec<ComposeBox> {
        parse(y).unwrap()
    }

    #[test]
    fn minimal_services_map_to_boxes() {
        let y = "services:\n  web:\n    image: nginx:alpine\n    command: [\"nginx\", \"-g\", \"daemon off;\"]\n";
        let b = boxes(y);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].name, "web");
        assert_eq!(b[0].image.as_deref(), Some("nginx:alpine"));
        assert_eq!(b[0].command, ["nginx", "-g", "daemon off;"]);
    }

    #[test]
    fn command_shell_form_wraps_in_sh_c() {
        let y = "services:\n  a:\n    image: alpine\n    command: echo hello world\n";
        assert_eq!(boxes(y)[0].command, ["sh", "-c", "echo hello world"]);
    }

    #[test]
    fn environment_map_and_list_and_interpolation() {
        std::env::set_var("KERN_TEST_IMPORT_VAR", "resolved");
        let y = "services:\n  a:\n    image: alpine\n    environment:\n      FOO: bar\n      BAZ: ${KERN_TEST_IMPORT_VAR}\n      MISS: ${KERN_TEST_UNSET_XYZ:-fallback}\n";
        let env = &boxes(y)[0].env;
        assert!(env.contains(&"FOO=bar".to_string()));
        assert!(env.contains(&"BAZ=resolved".to_string()));
        assert!(env.contains(&"MISS=fallback".to_string()));
        std::env::remove_var("KERN_TEST_IMPORT_VAR");
    }

    #[test]
    fn unresolvable_var_substitutes_empty_never_literal() {
        // Docker semantics: an unset `${VAR}` with no default → EMPTY string, never a literal `${VAR}`
        // reaching the box (which would make an app fail three levels down with a confusing config).
        let y = "services:\n  a:\n    image: alpine\n    environment:\n      X: ${KERN_DEFINITELY_UNSET_ABC}\n";
        let env = &boxes(y)[0].env;
        assert!(
            !env.iter().any(|e| e.contains("${")),
            "literal ${{}} must never reach the box: {env:?}"
        );
        assert!(
            env.contains(&"X=".to_string()),
            "unresolvable var → empty value: {env:?}"
        );
    }

    #[test]
    fn interpolation_is_document_wide_not_just_env() {
        // The bug the field-test found: `${VAR}` in `ports` (not just environment) must interpolate,
        // like Docker's pre-parse substitution.
        std::env::set_var("KERN_TEST_PORT", "9099");
        let y = "services:\n  a:\n    image: alpine\n    command: [\"true\"]\n    ports:\n      - \"${KERN_TEST_PORT}:80\"\n";
        assert_eq!(boxes(y)[0].ports, ["9099:80"]);
        std::env::remove_var("KERN_TEST_PORT");
    }

    #[test]
    fn depends_on_conditions_route_to_buckets() {
        let y = "services:\n  db:\n    image: postgres\n    healthcheck:\n      test: [\"CMD\", \"pg_isready\"]\n  app:\n    image: alpine\n    depends_on:\n      db:\n        condition: service_healthy\n      migrate:\n        condition: service_completed_successfully\n  migrate:\n    image: alpine\n";
        let app = boxes(y).into_iter().find(|b| b.name == "app").unwrap();
        assert_eq!(app.depends_healthy, ["db"]);
        assert_eq!(app.depends_completed, ["migrate"]);
    }

    #[test]
    fn inline_table_depends_on_routes_conditions() {
        // The copy-pasted one-liner form `depends_on: {x: {condition: ...}}` lands in `scalar`, not
        // `children` — it MUST still route to the right bucket. The bug: it was dropped, so a
        // `service_completed_successfully` gate silently became no-dependency and the dependent
        // started regardless of the init's exit.
        let y = "services:\n  db:\n    image: r\n    healthcheck:\n      test: [\"CMD\",\"redis-cli\",\"ping\"]\n  m:\n    image: a\n  app:\n    image: a\n    depends_on: {db: {condition: service_healthy}, m: {condition: service_completed_successfully}}\n";
        let app = boxes(y).into_iter().find(|b| b.name == "app").unwrap();
        assert_eq!(app.depends_healthy, ["db"]);
        assert_eq!(app.depends_completed, ["m"]);
        assert!(app.depends_on.is_empty());
        // Bare inline `{x: {}}` (no condition) → start-order.
        let y2 = "services:\n  x:\n    image: a\n  app:\n    image: a\n    depends_on: {x: {}}\n";
        let app2 = boxes(y2).into_iter().find(|b| b.name == "app").unwrap();
        assert_eq!(app2.depends_on, ["x"]);
    }

    #[test]
    fn entrypoint_and_command_compose_order_independent() {
        // `entrypoint ++ command`, whichever order the keys appear (the merge must happen AFTER the
        // whole service is parsed, not inline — else `command` overwrites the merge).
        let ep_first = "services:\n  a:\n    image: alpine\n    entrypoint: [\"echo\", \"P\"]\n    command: [\"x\", \"y\"]\n";
        let cmd_first = "services:\n  a:\n    image: alpine\n    command: [\"x\", \"y\"]\n    entrypoint: [\"echo\", \"P\"]\n";
        for y in [ep_first, cmd_first] {
            assert_eq!(boxes(y)[0].command, ["echo", "P", "x", "y"], "for:\n{y}");
        }
    }

    #[test]
    fn shell_form_entrypoint_ignores_command_like_docker() {
        // Audit regression: a SHELL-form entrypoint (`sh -c "<string>"`) must NOT have `command`
        // appended — the args would become the shell's positional params and `command` would be
        // silently discarded. Docker ignores `command` for a shell-form entrypoint; so do we (+warn).
        let y = "services:\n  a:\n    image: x\n    entrypoint: /init here\n    command: run now\n";
        assert_eq!(boxes(y)[0].command, ["sh", "-c", "/init here"]);
        // EXEC-form (list) entrypoint still composes with command.
        let y2 = "services:\n  a:\n    image: x\n    entrypoint: [\"/bin/entry\"]\n    command: [\"arg1\"]\n";
        assert_eq!(boxes(y2)[0].command, ["/bin/entry", "arg1"]);
        // Shell-form entrypoint alone (no command) is unchanged.
        let y3 = "services:\n  a:\n    image: x\n    entrypoint: /init here\n";
        assert_eq!(boxes(y3)[0].command, ["sh", "-c", "/init here"]);
    }

    #[test]
    fn interpolation_nested_brace_does_not_leak_a_literal() {
        // Audit regression: `${A${B}}` must NOT substitute `A${B` and leave a stray `}` — the whole
        // odd expression is passed through verbatim (Docker doesn't support nested interpolation).
        assert_eq!(interpolate_document("x=${A${B}}"), "x=${A${B}}");
        // A normal `${VAR:-def}` still works.
        assert_eq!(interpolate_document("x=${UNSET_XYZ_KERN:-def}"), "x=def");
    }

    #[test]
    fn interpolation_skips_comments() {
        // Audit regression: a `${VAR}` inside a trailing comment must not be interpolated (no spurious
        // unset-var warning, comment text left verbatim). The value part is still interpolated.
        assert_eq!(
            interpolate_document("image: x  # see ${SOME_UNSET_XYZ}"),
            "image: x  # see ${SOME_UNSET_XYZ}"
        );
        assert_eq!(
            interpolate_document("cmd: ${UNSET_XYZ_KERN:-run}  # ${ALSO_UNSET}"),
            "cmd: run  # ${ALSO_UNSET}"
        );
        // A `#` inside quotes is NOT a comment — interpolation applies across it.
        assert_eq!(
            interpolate_document("v: \"${UNSET_XYZ_KERN:-a#b}\""),
            "v: \"a#b\""
        );
    }

    #[test]
    fn compose_secrets_map_to_run_secrets() {
        // A service `secrets: [s]` + top-level `secrets: {s: {file: ./f}}` → `--secret ./f:s`.
        let y = "services:\n  a:\n    image: alpine\n    secrets: [\"s\"]\nsecrets:\n  s:\n    file: ./mysecret.txt\n";
        assert_eq!(boxes(y)[0].secrets, ["./mysecret.txt:s"]);
        // A referenced secret with no top-level `file:` def → skipped (warned), not a bogus entry.
        let y2 = "services:\n  a:\n    image: alpine\n    secrets: [\"ghost\"]\n";
        assert!(boxes(y2)[0].secrets.is_empty());
    }

    #[test]
    fn duplicate_service_key_is_rejected() {
        // Two service blocks with the same name is an authoring mistake — reject, don't launch two
        // boxes with a colliding name (opaque "already running" later) or silently shadow.
        let y = "services:\n  a:\n    image: alpine\n  a:\n    image: nginx\n";
        let err = match parse(y) {
            Err(e) => e,
            Ok(_) => panic!("expected duplicate-service error"),
        };
        assert!(err.contains("duplicate service"), "got: {err}");
    }

    #[test]
    fn inline_table_environment_and_healthcheck_parse() {
        // Systemic inline-table fix: `environment: {K: v}` and `healthcheck: {test: […]}` in the
        // one-liner form must parse (they used to sit unparsed in `scalar` and get dropped).
        let y = "services:\n  a:\n    image: alpine\n    environment: {FOO: bar, BAZ: qux}\n    healthcheck: {test: [\"CMD\", \"true\"], interval: 2s, retries: 3}\n";
        let b = &boxes(y)[0];
        assert!(b.env.contains(&"FOO=bar".to_string()));
        assert!(b.env.contains(&"BAZ=qux".to_string()));
        assert_eq!(b.health_cmd.as_deref(), Some("true"));
        assert_eq!(b.health_interval, Some(2));
    }

    #[test]
    fn healthcheck_durations_convert_to_bare_seconds() {
        // Extreme-test regression: `--health-timeout`/`--health-start-period` are integer SECONDS in
        // the CLI, but Docker writes them as durations (`30s`, `1m`, `0s`). Passing the raw `"30s"`
        // aborted the box ("usage: --health-start-period <seconds>"). They must convert like `interval`.
        let y = "services:\n  a:\n    image: x\n    healthcheck:\n      test: t\n      interval: 2s\n      timeout: 30s\n      start_period: 1m30s\n      retries: 4\n";
        let b = &boxes(y)[0];
        assert_eq!(b.health_interval, Some(2));
        assert_eq!(b.health_timeout.as_deref(), Some("30")); // 30s → "30", not "30s"
        assert_eq!(b.health_start_period.as_deref(), Some("90")); // 1m30s → 90
        assert_eq!(b.health_retries.as_deref(), Some("4")); // a plain count, unchanged
                                                            // `start_period: 0s` (no grace) is legitimate and must reach the box as `0`, not be dropped.
        let y0 = "services:\n  a:\n    image: x\n    healthcheck:\n      test: t\n      start_period: 0s\n";
        assert_eq!(boxes(y0)[0].health_start_period.as_deref(), Some("0"));
    }

    #[test]
    fn env_value_with_braces_is_not_over_parsed() {
        // The DUAL of the inline-table fix (review P1): a `{`-containing value in `environment` (a JSON
        // config, very common) must stay a verbatim STRING, not be structured into a table (which made
        // the env var come out empty). Both quoted and raw forms keep the value.
        let y = "services:\n  a:\n    image: alpine\n    environment:\n      CFG: {key: val}\n      JSON: \"{\\\"k\\\":\\\"v\\\"}\"\n";
        let env = &boxes(y)[0].env;
        assert!(
            env.iter()
                .any(|e| e.starts_with("CFG=") && e.contains("key")),
            "CFG lost: {env:?}"
        );
        assert!(
            env.iter()
                .any(|e| e.starts_with("JSON=") && e.contains("k")),
            "JSON lost: {env:?}"
        );
        // And the structural inline forms STILL parse (depends/healthcheck read children).
        let y2 = "services:\n  db:\n    image: r\n    healthcheck:\n      test: [\"CMD\",\"true\"]\n  app:\n    image: a\n    depends_on: {db: {condition: service_healthy}}\n";
        let app = boxes(y2).into_iter().find(|b| b.name == "app").unwrap();
        assert_eq!(app.depends_healthy, ["db"]);
    }

    #[test]
    fn partial_stack_failure_honors_depends_chain() {
        // Review P3 (the untested angle): a failed service must not start its dependents, but the
        // parser-level guarantee is that the dependency edge exists. (Runtime behaviour — independent
        // services start, dependents don't — is verified live; here we assert the edge is recorded so
        // `validate`/`wait` can enforce it.)
        let y = "services:\n  bad:\n    image: a\n    command: [\"false\"]\n  dep:\n    image: a\n    depends_on: {bad: {condition: service_completed_successfully}}\n";
        let dep = boxes(y).into_iter().find(|b| b.name == "dep").unwrap();
        assert_eq!(dep.depends_completed, ["bad"]);
    }

    #[test]
    fn healthcheck_cmd_exec_vs_shell_vs_bare() {
        let y = "services:\n  a:\n    image: alpine\n    healthcheck:\n      test: [\"CMD\", \"pg_isready\", \"-U\", \"app\"]\n";
        assert_eq!(boxes(y)[0].health_cmd.as_deref(), Some("pg_isready -U app"));
        let y2 = "services:\n  a:\n    image: alpine\n    healthcheck:\n      test: [\"CMD-SHELL\", \"pg_isready || exit 1\"]\n";
        assert_eq!(
            boxes(y2)[0].health_cmd.as_deref(),
            Some("pg_isready || exit 1")
        );
        let y3 =
            "services:\n  a:\n    image: alpine\n    healthcheck:\n      test: curl -f localhost\n";
        // bare string = implicit CMD-SHELL → verbatim, NEVER split on spaces
        assert_eq!(
            boxes(y3)[0].health_cmd.as_deref(),
            Some("curl -f localhost")
        );
    }

    #[test]
    fn healthcheck_test_reads_present_representation_not_expected() {
        // Review P1 "third state": `healthcheck.test` is SOMETIMES a string (CMD-SHELL) and SOMETIMES a
        // list (exec). With the dual scalar+children representation, the converter must read whichever
        // is PRESENT for the value's form, not blindly the same one — else the block/inline × list/bare
        // matrix drops or mis-parses a cell. All four cells must resolve to the same command.
        let cases = [
            // (yaml, expected)
            ("services:\n  a:\n    image: r\n    healthcheck:\n      test: [\"CMD\",\"redis-cli\",\"ping\"]\n", "redis-cli ping"), // block list
            ("services:\n  a:\n    image: r\n    healthcheck: {test: [\"CMD\",\"redis-cli\",\"ping\"]}\n", "redis-cli ping"), // inline list
            ("services:\n  a:\n    image: r\n    healthcheck:\n      test: \"redis-cli ping\"\n", "redis-cli ping"), // block bare-string
            ("services:\n  a:\n    image: r\n    healthcheck: {test: \"redis-cli ping\"}\n", "redis-cli ping"), // inline bare-string
        ];
        for (y, expected) in cases {
            assert_eq!(
                boxes(y)[0].health_cmd.as_deref(),
                Some(expected),
                "for:\n{y}"
            );
        }
    }

    #[test]
    fn ports_reconstructs_and_warns() {
        let y = "services:\n  a:\n    image: alpine\n    ports:\n      - \"8080:80\"\n";
        assert_eq!(boxes(y)[0].ports, ["8080:80"]);
    }

    #[test]
    fn ports_long_form_rebuilt_from_fields() {
        let y = "services:\n  a:\n    image: alpine\n    ports:\n      - {target: 80, published: 8080}\n";
        assert_eq!(boxes(y)[0].ports, ["8080:80"]);
    }

    #[test]
    fn ports_udp_is_skipped_not_silently_tcp() {
        let y = "services:\n  a:\n    image: alpine\n    ports:\n      - \"53:53/udp\"\n";
        assert!(
            boxes(y)[0].ports.is_empty(),
            "udp must be skipped, not converted to tcp"
        );
    }

    #[test]
    fn restart_always_maps_on_failure() {
        let y = "services:\n  a:\n    image: alpine\n    restart: always\n";
        assert!(boxes(y)[0].restart);
    }

    #[test]
    fn build_short_and_long_form() {
        let y = "services:\n  a:\n    build: ./svc\n";
        let bd = boxes(y)[0].build.clone().unwrap();
        assert_eq!(bd.context, "./svc");
        let y2 =
            "services:\n  a:\n    build:\n      context: ./svc\n      dockerfile: Custom.file\n";
        let bd2 = boxes(y2)[0].build.clone().unwrap();
        assert_eq!(bd2.context, "./svc");
        assert_eq!(bd2.dockerfile.as_deref(), Some("Custom.file"));
    }

    #[test]
    fn rejects_anchors_aliases_tabs_multidoc_blockscalar() {
        assert!(parse("services:\n  a: &anchor\n    image: alpine\n").is_err());
        assert!(parse("services:\n  a:\n    image: *alias\n").is_err());
        assert!(parse("services:\n\timage: alpine\n").is_err()); // tab
        assert!(
            parse("services:\n  a:\n    image: alpine\n---\nservices:\n  b:\n    image: x\n")
                .is_err()
        );
        assert!(parse("services:\n  a:\n    command: |\n      echo hi\n").is_err());
        // block scalar
        // Audit regression: an anchor/alias in LIST-ITEM position must be refused too — it used to
        // slip past both the `t`-prefix check (line starts with `- `) and `value_after_colon` (a list
        // item has no `:`), reaching the box as the literal `*boom`. `after_seq_markers` closes it.
        assert!(
            parse("services:\n  a:\n    image: alpine\n    command:\n      - *boom\n").is_err()
        );
        assert!(
            parse("services:\n  a:\n    image: alpine\n    command:\n      - &x hi\n").is_err()
        );
        // A hyphen that is NOT a sequence marker (a value that begins with '-', e.g. a flag) must NOT
        // be mistaken for one and must still parse.
        assert!(
            parse("services:\n  a:\n    image: alpine\n    command:\n      - --version\n").is_ok()
        );
        // An anchor/alias as a structural token must be refused in EVERY inline position — the two
        // positional checks only see line-start / after-`:`. `line_has_inline_anchor` closes this by
        // construction (a token-opening `&`/`*` outside quotes), not by an opener list, so a value
        // (`[*x]`), a nested value (`{test: [*x]}`), AND a KEY (`{&a k: v}`) are all caught.
        assert!(parse("services:\n  a:\n    image: alpine\n    command: [*boom, x]\n").is_err());
        assert!(
            parse("services:\n  a:\n    image: alpine\n    healthcheck: {test: *boom}\n").is_err()
        );
        assert!(parse("services:\n  a:\n    image: alpine\n    environment: {K: &a v}\n").is_err());
        // Anchor as a MAP KEY, and alias NESTED inside a `{…}`-wrapped `[…]` — the cases an opener
        // list ("preceded by `[{,:`") had to reason about; the token-start definition covers them.
        assert!(parse("services:\n  a:\n    image: x\n    environment: {&a k: v}\n").is_err());
        assert!(parse("services:\n  a:\n    image: x\n    healthcheck: {test: [*a]}\n").is_err());
        // No FALSE POSITIVES: a `*`/`&` preceded by scalar content (a glob, arithmetic, an `&` in a
        // value, or anything inside quotes) is NOT a token-opening anchor and must still parse.
        assert!(parse("services:\n  a:\n    image: my*repo/x\n").is_ok());
        assert!(parse("services:\n  a:\n    image: x\n    command: [\"echo\", \"2*2\"]\n").is_ok());
        assert!(parse("services:\n  a:\n    image: x\n    environment: {K: \"v*v\"}\n").is_ok());
        assert!(
            parse("services:\n  a:\n    image: x\n    environment: {URL: \"a&b=c\"}\n").is_ok()
        );
    }

    #[test]
    fn inline_anchor_detection_matches_an_independent_oracle() {
        // Completeness PROOF (not enumeration): generate lines with `&`/`*` in every position among a
        // small alphabet, and check `line_has_inline_anchor` against an INDEPENDENT oracle written a
        // different way — a right-to-left scan that, for each unquoted `&`/`*`, walks back over spaces
        // and asks "is the previous significant char scalar content?". If the two ever disagree, either
        // the guard misses a token-opening anchor (a hole) or over-flags a scalar (a false positive).
        fn oracle(line: &str) -> bool {
            let b = line.as_bytes();
            // Mark which byte offsets are inside quotes (single OR double, no escapes in YAML flow).
            let mut inq = vec![false; b.len()];
            let (mut q, mut i) = (0u8, 0usize);
            while i < b.len() {
                if q != 0 {
                    inq[i] = true; // the closing quote itself counts as "in quote" for this mark
                    if b[i] == q {
                        q = 0;
                    }
                } else if b[i] == b'"' || b[i] == b'\'' {
                    q = b[i];
                    inq[i] = true;
                }
                i += 1;
            }
            let is_content = |c: u8| {
                c.is_ascii_alphanumeric()
                    || matches!(c, b'_' | b'-' | b'.' | b'/' | b'%' | b'@' | b'+' | b'~')
            };
            for (idx, &c) in b.iter().enumerate() {
                if (c == b'&' || c == b'*') && !inq[idx] {
                    // Walk left over spaces to the previous significant, non-quoted byte. A `&`/`*` is
                    // itself "already inside a value" if IT was preceded by content, so we treat a
                    // preceding `&`/`*` as content too (skip past it and keep looking) — a `b&*` run is
                    // one plain scalar, not two anchors. This mirrors the guard's forward `prev_content`
                    // latch; writing the walk L→R-independently (here R→L) is what makes it a check.
                    let mut j = idx;
                    let prev_is_content = loop {
                        if j == 0 {
                            break false; // line start → opens a token
                        }
                        j -= 1;
                        if b[j] == b' ' || b[j] == b'\t' {
                            continue;
                        }
                        if inq[j] && (b[j] == b'"' || b[j] == b'\'') {
                            break false; // a quote is a scalar boundary, not content
                        }
                        if b[j] == b'&' || b[j] == b'*' {
                            continue; // part of the same scalar run — keep walking back
                        }
                        break !inq[j] && is_content(b[j]);
                    };
                    if !prev_is_content {
                        return true;
                    }
                }
            }
            false
        }
        let alphabet: [u8; 14] = *b"&* \t[]{}:,\"'ab";
        let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        for _ in 0..50_000 {
            let len = next() % 14;
            let mut line = String::new();
            for _ in 0..len {
                line.push(alphabet[next() % alphabet.len()] as char);
            }
            assert_eq!(
                line_has_inline_anchor(&line),
                oracle(&line),
                "guard vs oracle disagree on {line:?}"
            );
        }
    }

    #[test]
    fn no_services_is_an_error() {
        assert!(parse("version: \"3\"\nvolumes:\n  data:\n").is_err());
    }

    #[test]
    fn service_without_image_or_build_is_rejected_at_parse() {
        // Field-test edge: a service with neither image nor build must fail at parse with a precise
        // message, not later as an opaque "need --rootfs or --image" from the box.
        let err = parse("services:\n  a:\n    command: [\"echo\", \"hi\"]\n").unwrap_err();
        assert!(err.contains("no `image:`"), "got: {err}");
        // An empty image string counts as absent.
        assert!(parse("services:\n  a:\n    image: \"\"\n").is_err());
    }

    #[test]
    fn unbalanced_inline_collection_is_rejected() {
        // `command: [unterminated` must NOT be silently accepted as the element `[unterminated`.
        assert!(parse("services:\n  a:\n    image: x\n    command: [unterminated\n").is_err());
        assert!(parse("services:\n  a:\n    image: x\n    environment: {K: v\n").is_err());
        // A balanced inline list is fine.
        assert!(parse("services:\n  a:\n    image: x\n    command: [a, b]\n").is_ok());
    }

    #[test]
    fn double_dash_key_is_a_name_not_a_list_item() {
        // `--net:` starts with `-` but is a (bad) KEY, not the list item `-net:`. It must be validated
        // as a service name (→ invalid), not mis-parsed as a sequence element.
        let err = parse("services:\n  --net:\n    image: alpine\n").unwrap_err();
        assert!(
            err.contains("invalid name") || err.contains("--net"),
            "got: {err}"
        );
        // A real list item (`- x`) still parses.
        let b = parse("services:\n  a:\n    image: x\n    command:\n      - echo\n      - hi\n")
            .unwrap();
        assert_eq!(b[0].command, ["echo", "hi"]);
    }

    #[test]
    fn orphan_health_gate_degrades_to_start_order() {
        // db's healthcheck is NONE → omitted → no health_cmd. app's `service_healthy` gate toward db
        // must DEGRADE to depends_on (start-order), NOT leave an unsatisfiable depends_healthy that
        // aborts the up (the reviewer's D1: no promise of a degrade that doesn't happen).
        let y = "services:\n  db:\n    image: alpine\n    healthcheck:\n      test: [\"NONE\"]\n  app:\n    image: alpine\n    depends_on:\n      db:\n        condition: service_healthy\n";
        let app = parse(y)
            .unwrap()
            .into_iter()
            .find(|b| b.name == "app")
            .unwrap();
        assert!(
            app.depends_healthy.is_empty(),
            "orphan gate must not remain in depends_healthy"
        );
        assert_eq!(
            app.depends_on,
            ["db"],
            "gate must be degraded to start-order"
        );
    }

    #[test]
    fn healthy_gate_kept_when_dep_has_health() {
        // The degrade must NOT fire when the dep DOES have a usable healthcheck.
        let y = "services:\n  db:\n    image: alpine\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n  app:\n    image: alpine\n    depends_on:\n      db:\n        condition: service_healthy\n";
        let app = parse(y)
            .unwrap()
            .into_iter()
            .find(|b| b.name == "app")
            .unwrap();
        assert_eq!(app.depends_healthy, ["db"]);
        assert!(app.depends_on.is_empty());
    }

    #[test]
    fn randomized_fuzz_never_panics_incl_multibyte_and_deep() {
        // Property: parse() NEVER panics on ANY input — Err or Ok only. Covers the two classes plain
        // examples miss: MULTIBYTE at a slice boundary (byte-safe slicing / char_indices) and DEEP
        // NESTING (iterative + MAX_DEPTH → no stack overflow). Deterministic LCG, reproducible.
        let alphabet: [&str; 18] = [
            ":",
            " ",
            "-",
            "[",
            "]",
            "{",
            "}",
            "\"",
            "'",
            "\n",
            "services",
            "image",
            "a",
            "é",
            "→",
            "🦀",
            // A long digit-run + a duration suffix — the class the audit found `parse_duration_secs`
            // could overflow-panic on (e.g. reaching `interval: 9999999999999999h`).
            "9999999999999999",
            "h",
        ];
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        for _ in 0..20_000 {
            let len = next() % 60;
            let mut s = String::new();
            for _ in 0..len {
                s.push_str(alphabet[next() % alphabet.len()]);
            }
            let _ = parse(&s); // must not panic for any input
        }
        // Explicit deep nesting (2000 levels of `  key:`) — must be refused (MAX_DEPTH) or parsed, no
        // stack overflow.
        let mut deep = String::from("services:\n");
        for i in 0..2000 {
            deep.push_str(&" ".repeat(2 + i % 40));
            deep.push_str("k:\n");
        }
        let _ = parse(&deep);
        // Billion-laughs shape — must be refused by the anchor prescreen, not expanded.
        assert!(parse("services:\n  a: &x [*x, *x]\n").is_err());
    }

    #[test]
    fn duration_overflow_falls_back_to_none_not_panic() {
        // Audit regression: an unbounded untrusted `interval:` must never overflow-panic (debug) nor
        // wrap to a nonsense value (release) — a form that overflows falls back to None (box default).
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("1m30s"), Some(90));
        assert_eq!(parse_duration_secs("2h"), Some(7200));
        assert_eq!(parse_duration_secs("6000000000000000h"), None); // n*3600 overflows → None
        assert_eq!(parse_duration_secs("200000000000000000m"), None); // n*60 overflows → None
        assert_eq!(parse_duration_secs("9223372036854775807s5s"), None); // total add overflows → None
        assert_eq!(parse_duration_secs("99999999999999999999"), None); // >i64 bare number → None
                                                                       // And through the real public entry point, as a healthcheck.interval — parse must not panic.
        let y = "services:\n  a:\n    image: x\n    healthcheck:\n      test: t\n      interval: 6000000000000000h\n";
        let _ = parse(y); // Ok or Err, never a panic
    }
}
