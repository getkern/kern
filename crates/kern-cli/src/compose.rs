//! `kern compose` — minimal TOML orchestration.
//!
//! Parses a small TOML subset (no external crate): `[box.NAME]` tables with `image`/`rootfs`
//! (string), `command`/`depends_on` (string arrays). Boxes are started detached in
//! dependency order (`depends_on`), so `kern compose up.toml` brings up a stack and `kern ps`
//! shows it. The parser is intentionally strict and reports the offending line.

use std::collections::{HashMap, HashSet, VecDeque};

/// One service in a compose file.
pub struct ComposeBox {
    pub name: String,
    pub image: Option<String>,
    pub rootfs: Option<String>,
    pub command: Vec<String>,
    pub depends_on: Vec<String>,
}

/// Parse the compose document into boxes (file order preserved).
pub fn parse(text: &str) -> Result<Vec<ComposeBox>, String> {
    let mut boxes: Vec<ComposeBox> = Vec::new();
    let mut cur: Option<usize> = None;
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = parse_box_header(line) {
            if boxes.iter().any(|b| b.name == name) {
                return Err(format!("line {}: duplicate box '{name}'", i + 1));
            }
            boxes.push(ComposeBox {
                name,
                image: None,
                rootfs: None,
                command: Vec::new(),
                depends_on: Vec::new(),
            });
            cur = Some(boxes.len() - 1);
            continue;
        }
        let idx = cur.ok_or_else(|| format!("line {}: key outside any [box.NAME] table", i + 1))?;
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected `key = value`", i + 1))?;
        let b = &mut boxes[idx];
        match key.trim() {
            "image" => b.image = Some(parse_string(val).map_err(|e| line_err(i, &e))?),
            "rootfs" => b.rootfs = Some(parse_string(val).map_err(|e| line_err(i, &e))?),
            "command" => b.command = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            "depends_on" => b.depends_on = parse_string_array(val).map_err(|e| line_err(i, &e))?,
            other => return Err(format!("line {}: unknown key '{other}'", i + 1)),
        }
    }
    if boxes.is_empty() {
        return Err("no [box.NAME] tables found".into());
    }
    for b in &boxes {
        if b.image.is_none() && b.rootfs.is_none() {
            return Err(format!("box '{}': needs `image` or `rootfs`", b.name));
        }
    }
    Ok(boxes)
}

/// Dependency order (a box starts after everything in its `depends_on`). Errors on an unknown
/// dependency or a cycle.
pub fn topo_order(boxes: &[ComposeBox]) -> Result<Vec<String>, String> {
    let names: HashSet<&str> = boxes.iter().map(|b| b.name.as_str()).collect();
    let mut indeg: HashMap<&str, usize> = boxes.iter().map(|b| (b.name.as_str(), 0)).collect();
    let mut succ: HashMap<&str, Vec<&str>> = HashMap::new();
    for b in boxes {
        for d in &b.depends_on {
            if !names.contains(d.as_str()) {
                return Err(format!("box '{}' depends on unknown box '{d}'", b.name));
            }
            succ.entry(d.as_str()).or_default().push(b.name.as_str());
            *indeg.get_mut(b.name.as_str()).unwrap() += 1;
        }
    }
    // Seed the queue in file order for a deterministic result.
    let mut queue: VecDeque<&str> = boxes
        .iter()
        .map(|b| b.name.as_str())
        .filter(|n| indeg[n] == 0)
        .collect();
    let mut order = Vec::with_capacity(boxes.len());
    while let Some(n) = queue.pop_front() {
        order.push(n.to_string());
        if let Some(ms) = succ.get(n) {
            for &m in ms {
                let e = indeg.get_mut(m).unwrap();
                *e -= 1;
                if *e == 0 {
                    queue.push_back(m);
                }
            }
        }
    }
    if order.len() != boxes.len() {
        return Err("dependency cycle detected".into());
    }
    Ok(order)
}

fn line_err(i: usize, e: &str) -> String {
    format!("line {}: {e}", i + 1)
}

fn strip_comment(line: &str) -> &str {
    // `#` outside a string starts a comment. (Values are quoted, so a `#` inside quotes is safe.)
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

fn parse_box_header(line: &str) -> Option<String> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    let name = inner.strip_prefix("box.")?.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn parse_string(v: &str) -> Result<String, String> {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        Ok(v[1..v.len() - 1].to_string())
    } else {
        Err(format!("expected a quoted string, got `{v}`"))
    }
}

fn parse_string_array(v: &str) -> Result<Vec<String>, String> {
    let v = v.trim();
    let inner = v
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("expected an array `[...]`, got `{v}`"))?;
    let mut out = Vec::new();
    for part in split_top_commas(inner) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(parse_string(part)?);
    }
    Ok(out)
}

/// Split on commas that are not inside a quoted string.
fn split_top_commas(s: &str) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"
        # a small stack
        [box.web]
        image = "alpine"
        command = ["/bin/sh", "-c", "echo hi, there"]
        depends_on = ["db"]

        [box.db]
        image = "alpine"
    "#;

    #[test]
    fn parses_boxes_and_values() {
        let boxes = parse(DOC).unwrap();
        assert_eq!(boxes.len(), 2);
        let web = &boxes[0];
        assert_eq!(web.name, "web");
        assert_eq!(web.image.as_deref(), Some("alpine"));
        // the comma inside the quoted string must NOT split the array
        assert_eq!(web.command, ["/bin/sh", "-c", "echo hi, there"]);
        assert_eq!(web.depends_on, ["db"]);
    }

    #[test]
    fn topo_respects_depends_on() {
        let boxes = parse(DOC).unwrap();
        let order = topo_order(&boxes).unwrap();
        let (a, b) = (
            order.iter().position(|n| n == "db").unwrap(),
            order.iter().position(|n| n == "web").unwrap(),
        );
        assert!(a < b, "db must start before web: {order:?}");
    }

    #[test]
    fn detects_cycles_and_unknown_deps() {
        let cyc =
            "[box.a]\nimage=\"x\"\ndepends_on=[\"b\"]\n[box.b]\nimage=\"x\"\ndepends_on=[\"a\"]";
        assert!(topo_order(&parse(cyc).unwrap()).is_err());
        let unknown = "[box.a]\nimage=\"x\"\ndepends_on=[\"ghost\"]";
        assert!(topo_order(&parse(unknown).unwrap()).is_err());
    }

    #[test]
    fn rejects_box_without_image_or_rootfs() {
        assert!(parse("[box.a]\ncommand=[\"x\"]").is_err());
    }
}
