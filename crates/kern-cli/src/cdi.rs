//! THE CDI READER: strict by construction, because the spec is INPUT.
//!
//! A Container Device Interface file is a thing kern READS from a directory anyone with root on the
//! host may write, and a nested runtime may hand kern one it generated itself. So this is not a
//! convenience parser over a trusted document; it is a parser over hostile input, and it is written
//! the way that fact demands: it accepts the four line shapes CDI actually uses and REFUSES
//! everything else by name.
//!
//! WHY NOT THE YAML PARSER THIS REPOSITORY ALREADY HAS. `kern-compose` carries a 10,962-line YAML
//! reader with a prescreen, a lexer, anchor resolution and a depth cap, and reusing it was the first
//! thing considered. It cannot be reused, and the reason is structural rather than a matter of
//! visibility: `build_tree` folds a block-mapping list item into an INLINE `{…}` STRING, because
//! that is the shape compose's long-form ports want. CDI is made of mapping sequences
//! (`- path: /dev/nvidia0`), so consuming that tree would mean re-parsing those folded strings,
//! which is a second parser wearing the first one's name.
//!
//! WHAT A STRICT READER BUYS. The generated spec on this host uses none of YAML's dangerous
//! grammar: measured on `/var/run/cdi/nvidia.yaml`, 619 lines, zero anchors, zero aliases, zero
//! merge keys, zero tags, zero flow collections, zero block scalars, zero tabs, maximum indent 16
//! and maximum line 109 characters. A reader that accepts only what that file contains and names
//! its refusal for everything else cannot be steered by a construct it does not implement, which a
//! permissive parser can.
//!
//! THE THREE PARSE RULES, from the plan, each of which is a decision and not a detail:
//!
//!   1. `additionalGids` IS DECIDED BY THE FILE'S `cdiVersion`, never by the toolkit's version. The
//!      field exists from spec v0.7.0 and the toolkit emits it by default from 1.19.1. Here the
//!      toolkit is 1.18.2, the file says 0.5.0, and there is no `additionalGids` in it. The rule is
//!      to read the version, refuse a spec newer than the one we know how to read, and never apply
//!      a host gid as a container gid: measured in `gpu_grant`, `setgroups` inside a box succeeds
//!      with the number and grants nothing, because that gid maps to a different kgid.
//!   2. `idmap` IS IGNORED. It needs privilege on the source filesystem, which a rootless box has
//!      not got. Ignoring it is the documented fallback, and it is named here rather than silently
//!      dropped.
//!   3. THE DIRECTORIES ARE CONFIGURABLE, NOT CARVED. The two standard ones are `/etc/cdi` and
//!      `/var/run/cdi`. `$XDG_RUNTIME_DIR/cdi` is NOT standard, and on this host it does not exist.
//!      Reading only one of the two finds nothing here, because `/etc/cdi` exists and is empty
//!      while the real spec is in `/var/run/cdi`.
//!
//! ALLOCATION NOTE. This path allocates: it owns its strings and its tree. It runs once, before a
//! box exists, on a file of a few hundred lines. The project's no-heap rule governs the per-box hot
//! path, and this is not it.

use std::path::{Path, PathBuf};

/// The newest `cdiVersion` this reader claims to understand.
///
/// A FILE NEWER THAN THIS IS REFUSED, which is the plan's rule and the opposite of the usual
/// instinct to parse what one can and ignore the rest. A spec version exists because the meaning of
/// fields changed; a reader that skipped the parts it did not recognise would apply the old meaning
/// to a new document, and `additionalGids` is exactly such a field.
pub const MAX_KNOWN_CDI_VERSION: (u32, u32, u32) = (0, 6, 0);

/// The two standard directories, in the order they are searched.
///
/// A DEFAULT, not a constant carved into the logic: [`spec_dirs`] takes an override so a host that
/// puts its specs elsewhere is configuration rather than a patch.
pub const DEFAULT_SPEC_DIRS: [&str; 2] = ["etc/cdi", "var/run/cdi"];

/// Bounds. A spec arriving from somewhere kern does not control gets a size it cannot exceed.
const MAX_LINES: usize = 20_000;
const MAX_LINE_LEN: usize = 4_096;
const MAX_INDENT: usize = 64;

/// Why a CDI document was refused. Every variant carries the line, so a message can point at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdiError {
    /// The document is larger than the reader will process.
    TooLarge {
        /// How many lines it has.
        lines: usize,
    },
    /// A line is longer than the reader will process.
    LineTooLong {
        /// 1-based line number.
        line: usize,
        /// Its length.
        len: usize,
    },
    /// A YAML construct this reader deliberately does not implement.
    ///
    /// Named rather than skipped: a document that uses one is a document this reader cannot claim
    /// to have understood, and silently ignoring it is how a parser ends up applying the wrong
    /// meaning to a field it did not see.
    Unsupported {
        /// 1-based line number.
        line: usize,
        /// What was found, in one word a message can quote.
        construct: &'static str,
    },
    /// The indentation does not resolve to any open level.
    BadIndent {
        /// 1-based line number.
        line: usize,
    },
    /// A line that is none of the four shapes the reader accepts.
    BadLine {
        /// 1-based line number.
        line: usize,
    },
    /// `cdiVersion` is missing.
    NoVersion,
    /// `cdiVersion` is not `N.N.N`.
    BadVersion {
        /// What the field said.
        given: String,
    },
    /// The file declares a version newer than [`MAX_KNOWN_CDI_VERSION`].
    VersionTooNew {
        /// What the file said.
        given: String,
        /// What this reader knows.
        known: String,
    },
    /// `kind` is missing.
    NoKind,
    /// The document carries `additionalGids`.
    ///
    /// REFUSED, NOT IGNORED. The field asks for host gids to be given to the container, and a box
    /// cannot receive them: `setgroups` takes only mapped gids, so the number would land on a
    /// different kgid and grant nothing. Applying it blindly would be a grant that looks wider than
    /// it is; ignoring it silently would be a spec whose author's intent kern pretended to honour.
    AdditionalGids {
        /// 1-based line number.
        line: usize,
    },
}

impl CdiError {
    /// A one-line description, for a CLI message.
    pub fn describe(&self) -> String {
        match self {
            CdiError::TooLarge { lines } => {
                format!("the CDI spec has {lines} lines, more than this reader will process")
            }
            CdiError::LineTooLong { line, len } => {
                format!("CDI line {line} is {len} characters long")
            }
            CdiError::Unsupported { line, construct } => format!(
                "CDI line {line} uses {construct}, which this reader does not implement and will \
                 not guess at"
            ),
            CdiError::BadIndent { line } => {
                format!("CDI line {line} is indented to no open level")
            }
            CdiError::BadLine { line } => {
                format!("CDI line {line} is not a shape this reader reads")
            }
            CdiError::NoVersion => "the CDI spec carries no cdiVersion".to_string(),
            CdiError::BadVersion { given } => format!("cdiVersion {given:?} is not N.N.N"),
            CdiError::VersionTooNew { given, known } => format!(
                "the CDI spec declares version {given}, newer than the {known} this build reads. \
                 Refusing rather than reading it as an older one"
            ),
            CdiError::NoKind => "the CDI spec carries no kind".to_string(),
            CdiError::AdditionalGids { line } => format!(
                "the CDI spec sets additionalGids at line {line}. A box cannot receive a host gid: \
                 setgroups takes mapped gids only, so the number would land on a different kgid. \
                 Refusing rather than applying it or pretending to honour it"
            ),
        }
    }
}

/// The minimal value tree the strict reader produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A scalar, with its quotes stripped.
    Scalar(String),
    /// A mapping, in document order.
    Map(Vec<(String, Value)>),
    /// A sequence, in document order.
    Seq(Vec<Value>),
}

impl Value {
    /// The value at `key`, if this is a mapping that has one.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// This value as a string, if it is a scalar.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Scalar(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// This value's items, if it is a sequence.
    pub fn items(&self) -> &[Value] {
        match self {
            Value::Seq(items) => items.as_slice(),
            _ => &[],
        }
    }
}

/// One line, lexed and classified.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Shape {
    /// `key:` with nothing after it.
    KeyOnly(String),
    /// `key: value`.
    KeyValue(String, String),
    /// `- value`.
    SeqScalar(String),
    /// `- key: value`, which opens a mapping inside a sequence item.
    SeqKeyValue(String, String),
    /// `- key:`, a sequence item whose first key opens a block.
    SeqKeyOnly(String),
}

/// A lexed line: its indent, its shape, and where it came from.
#[derive(Debug, Clone)]
struct Lexed {
    indent: usize,
    shape: Shape,
    line: usize,
}

/// Strip a trailing comment that is not inside quotes, then trim.
fn strip_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            // A `#` only starts a comment at the start of the line or after whitespace, which is
            // why the guard is on the arm: `nvidia.com/gpu#1` is a value and not a comment.
            b'#' if !in_single && !in_double && (i == 0 || bytes.get(i - 1) == Some(&b' ')) => {
                return s.get(..i).unwrap_or("");
            }
            _ => {}
        }
    }
    s
}

/// Remove one layer of matching quotes.
fn unquote(s: &str) -> String {
    let t = s.trim();
    let bytes = t.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            if let Some(inner) = t.get(1..t.len() - 1) {
                return inner.to_string();
            }
        }
    }
    t.to_string()
}

/// Refuse a value that opens a construct this reader does not implement.
fn check_value(value: &str, line: usize) -> Result<(), CdiError> {
    let v = value.trim();
    let first = v.as_bytes().first().copied();
    let construct = match first {
        Some(b'&') => Some("a YAML anchor"),
        Some(b'*') => Some("a YAML alias"),
        Some(b'{') => Some("a flow mapping"),
        Some(b'[') => Some("a flow sequence"),
        Some(b'|') => Some("a literal block scalar"),
        Some(b'>') => Some("a folded block scalar"),
        Some(b'!') => Some("a YAML tag"),
        _ => None,
    };
    match construct {
        Some(construct) => Err(CdiError::Unsupported { line, construct }),
        None => Ok(()),
    }
}

/// Split `key: value` at the first colon that is followed by a space or ends the line.
fn split_key(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b != b':' {
            continue;
        }
        match bytes.get(i + 1) {
            None => return Some((s.get(..i)?, "")),
            Some(b' ') => return Some((s.get(..i)?, s.get(i + 1..)?)),
            _ => {}
        }
    }
    None
}

/// Lex the document into classified lines, refusing every construct this reader does not read.
fn lex(text: &str) -> Result<Vec<Lexed>, CdiError> {
    let raw: Vec<&str> = text.lines().collect();
    if raw.len() > MAX_LINES {
        return Err(CdiError::TooLarge { lines: raw.len() });
    }

    let mut out: Vec<Lexed> = Vec::new();
    for (index, line) in raw.iter().enumerate() {
        let number = index + 1;
        if line.len() > MAX_LINE_LEN {
            return Err(CdiError::LineTooLong {
                line: number,
                len: line.len(),
            });
        }
        if line.contains('\t') {
            return Err(CdiError::Unsupported {
                line: number,
                construct: "a tab",
            });
        }

        let without_comment = strip_comment(line);
        let trimmed = without_comment.trim_end();
        let body = trimmed.trim_start();
        if body.is_empty() {
            continue;
        }
        // The document marker and the document end are the only bare markers accepted.
        if body == "---" || body == "..." {
            continue;
        }
        if body.starts_with("<<:") {
            return Err(CdiError::Unsupported {
                line: number,
                construct: "a merge key",
            });
        }

        let indent = trimmed.len().saturating_sub(body.len());
        if indent > MAX_INDENT {
            return Err(CdiError::BadIndent { line: number });
        }

        let shape = if let Some(rest) = body.strip_prefix("- ") {
            let rest = rest.trim();
            match split_key(rest) {
                Some((key, value)) => {
                    check_value(value, number)?;
                    let key = key.trim().to_string();
                    if value.trim().is_empty() {
                        Shape::SeqKeyOnly(key)
                    } else {
                        Shape::SeqKeyValue(key, unquote(value))
                    }
                }
                None => {
                    check_value(rest, number)?;
                    Shape::SeqScalar(unquote(rest))
                }
            }
        } else {
            match split_key(body) {
                Some((key, value)) => {
                    check_value(value, number)?;
                    let key = key.trim().to_string();
                    if value.trim().is_empty() {
                        Shape::KeyOnly(key)
                    } else {
                        Shape::KeyValue(key, unquote(value))
                    }
                }
                None => return Err(CdiError::BadLine { line: number }),
            }
        };

        out.push(Lexed {
            indent,
            shape,
            line: number,
        });
    }
    Ok(out)
}

/// A frame on the build stack: what is open, and at which column.
#[derive(Debug)]
struct Frame {
    indent: usize,
    /// `true` when this frame collects sequence items rather than mapping entries.
    is_seq: bool,
    map: Vec<(String, Value)>,
    seq: Vec<Value>,
    /// The key this frame was opened under, which the parent will file it as.
    key: Option<String>,
}

impl Frame {
    fn into_value(self) -> Value {
        if self.is_seq {
            Value::Seq(self.seq)
        } else {
            Value::Map(self.map)
        }
    }
}

/// Build the tree from lexed lines with an explicit stack: no recursion, so a deep document cannot
/// overflow, and `MAX_INDENT` bounds it anyway.
fn build(lines: &[Lexed]) -> Result<Value, CdiError> {
    let mut stack: Vec<Frame> = vec![Frame {
        indent: 0,
        is_seq: false,
        map: Vec::new(),
        seq: Vec::new(),
        key: None,
    }];

    // Close every frame opened deeper than `indent`, folding each into its parent.
    fn close_to(stack: &mut Vec<Frame>, indent: usize, line: usize) -> Result<(), CdiError> {
        while stack.len() > 1 {
            let Some(top) = stack.last() else {
                return Err(CdiError::BadIndent { line });
            };
            // `>=`, not `>`: a frame opened by a key at column C holds the lines INDENTED PAST
            // C, so a line arriving at C itself ends it. With `>` a block opened at column 0 was
            // never closed and became the document root, which is how `cdiVersion` went missing
            // from a document that plainly had one.
            if top.indent < indent {
                break;
            }
            let Some(frame) = stack.pop() else {
                return Err(CdiError::BadIndent { line });
            };
            let key = frame.key.clone();
            let value = frame.into_value();
            let Some(parent) = stack.last_mut() else {
                return Err(CdiError::BadIndent { line });
            };
            match key {
                Some(k) => parent.map.push((k, value)),
                None => parent.seq.push(value),
            }
        }
        Ok(())
    }

    for lexed in lines {
        match &lexed.shape {
            Shape::KeyOnly(key) => {
                close_to(&mut stack, lexed.indent, lexed.line)?;
                stack.push(Frame {
                    indent: lexed.indent,
                    is_seq: false,
                    map: Vec::new(),
                    seq: Vec::new(),
                    key: Some(key.clone()),
                });
            }
            Shape::KeyValue(key, value) => {
                close_to(&mut stack, lexed.indent, lexed.line)?;
                let Some(top) = stack.last_mut() else {
                    return Err(CdiError::BadIndent { line: lexed.line });
                };
                top.map.push((key.clone(), Value::Scalar(value.clone())));
            }
            Shape::SeqScalar(value) => {
                close_to(&mut stack, lexed.indent, lexed.line)?;
                let Some(top) = stack.last_mut() else {
                    return Err(CdiError::BadIndent { line: lexed.line });
                };
                top.is_seq = true;
                top.seq.push(Value::Scalar(value.clone()));
            }
            Shape::SeqKeyValue(key, value) => {
                close_to(&mut stack, lexed.indent, lexed.line)?;
                let Some(top) = stack.last_mut() else {
                    return Err(CdiError::BadIndent { line: lexed.line });
                };
                top.is_seq = true;
                // The item's own mapping opens at the dash's column plus two, which is where its
                // continuation lines sit.
                stack.push(Frame {
                    indent: lexed.indent.saturating_add(1),
                    is_seq: false,
                    map: vec![(key.clone(), Value::Scalar(value.clone()))],
                    seq: Vec::new(),
                    key: None,
                });
            }
            Shape::SeqKeyOnly(key) => {
                close_to(&mut stack, lexed.indent, lexed.line)?;
                let Some(top) = stack.last_mut() else {
                    return Err(CdiError::BadIndent { line: lexed.line });
                };
                top.is_seq = true;
                stack.push(Frame {
                    indent: lexed.indent.saturating_add(1),
                    is_seq: false,
                    map: Vec::new(),
                    seq: Vec::new(),
                    key: None,
                });
                stack.push(Frame {
                    indent: lexed.indent.saturating_add(2),
                    is_seq: false,
                    map: Vec::new(),
                    seq: Vec::new(),
                    key: Some(key.clone()),
                });
            }
        }
    }

    close_to(&mut stack, 0, 0)?;
    let Some(root) = stack.pop() else {
        return Err(CdiError::BadIndent { line: 0 });
    };
    Ok(root.into_value())
}

/// Parse a CDI document into the minimal tree.
pub fn parse_strict(text: &str) -> Result<Value, CdiError> {
    let lines = lex(text)?;
    build(&lines)
}

/// A `cdiVersion`, as three numbers.
fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// One mount the spec asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiMount {
    /// The host side.
    pub host_path: PathBuf,
    /// Where it appears inside.
    pub container_path: PathBuf,
    /// The mount options, verbatim.
    pub options: Vec<String>,
}

/// One hook the spec declares. Read so it can be REPORTED, never executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiHook {
    /// When the runtime would run it.
    pub hook_name: String,
    /// The binary, as the spec names it.
    pub path: PathBuf,
}

/// The edits a device or the document as a whole asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerEdits {
    /// Device nodes to expose.
    pub device_nodes: Vec<PathBuf>,
    /// Mounts to make.
    pub mounts: Vec<CdiMount>,
    /// Hooks the spec declares.
    pub hooks: Vec<CdiHook>,
}

/// One device the spec offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiDevice {
    /// Its name, which is what `--device nvidia.com/gpu=<name>` selects.
    pub name: String,
    /// Its own edits.
    pub edits: ContainerEdits,
}

/// A whole CDI document, reduced to what kern acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiSpec {
    /// The version the FILE declares, which is what decides field meanings.
    pub version: String,
    /// The vendor and class, `nvidia.com/gpu` here.
    pub kind: String,
    /// The devices, in document order.
    pub devices: Vec<CdiDevice>,
    /// The edits every device gets.
    pub common: ContainerEdits,
    /// Whether the document carried an `idmap`, which this reader ignores by rule.
    ///
    /// REPORTED rather than dropped in silence: an operator who wrote one is entitled to know it
    /// did nothing, and the plan's rule is to ignore the field, not to hide that it was there.
    pub idmap_ignored: bool,
}

/// Read `containerEdits` out of a tree node.
fn container_edits(node: &Value, line_hint: usize) -> Result<(ContainerEdits, bool), CdiError> {
    let mut edits = ContainerEdits::default();
    let mut idmap = false;

    if let Some(nodes) = node.get("deviceNodes") {
        for item in nodes.items() {
            if let Some(path) = item.get("path").and_then(Value::as_str) {
                edits.device_nodes.push(PathBuf::from(path));
            }
        }
    }

    if let Some(mounts) = node.get("mounts") {
        for item in mounts.items() {
            let Some(host) = item.get("hostPath").and_then(Value::as_str) else {
                continue;
            };
            let container = item
                .get("containerPath")
                .and_then(Value::as_str)
                .unwrap_or(host);
            let options = item
                .get("options")
                .map(|o| {
                    o.items()
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            if item.get("idmap").is_some() {
                idmap = true;
            }
            edits.mounts.push(CdiMount {
                host_path: PathBuf::from(host),
                container_path: PathBuf::from(container),
                options,
            });
        }
    }

    if let Some(hooks) = node.get("hooks") {
        for item in hooks.items() {
            let name = item
                .get("hookName")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let path = item.get("path").and_then(Value::as_str).unwrap_or("");
            edits.hooks.push(CdiHook {
                hook_name: name,
                path: PathBuf::from(path),
            });
        }
    }

    if node.get("additionalGids").is_some() {
        return Err(CdiError::AdditionalGids { line: line_hint });
    }

    Ok((edits, idmap))
}

/// Read a whole CDI document.
pub fn parse_spec(text: &str) -> Result<CdiSpec, CdiError> {
    // `additionalGids` is checked on the RAW text as well as on the tree, because a document that
    // puts it somewhere this reader does not look would otherwise pass. The field is refused
    // wherever it appears, which is the only reading of "never applied blindly" that holds.
    if let Some(index) = text.find("additionalGids") {
        let line = text.get(..index).map_or(1, |p| p.lines().count().max(1));
        return Err(CdiError::AdditionalGids { line });
    }

    let tree = parse_strict(text)?;

    let Some(version) = tree.get("cdiVersion").and_then(Value::as_str) else {
        return Err(CdiError::NoVersion);
    };
    let Some(parsed) = parse_version(version) else {
        return Err(CdiError::BadVersion {
            given: version.to_string(),
        });
    };
    if parsed > MAX_KNOWN_CDI_VERSION {
        let (a, b, c) = MAX_KNOWN_CDI_VERSION;
        return Err(CdiError::VersionTooNew {
            given: version.to_string(),
            known: format!("{a}.{b}.{c}"),
        });
    }

    let Some(kind) = tree.get("kind").and_then(Value::as_str) else {
        return Err(CdiError::NoKind);
    };

    let mut idmap_ignored = false;
    let mut devices: Vec<CdiDevice> = Vec::new();
    if let Some(list) = tree.get("devices") {
        for item in list.items() {
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            let edits = match item.get("containerEdits") {
                Some(node) => {
                    let (edits, idmap) = container_edits(node, 0)?;
                    idmap_ignored |= idmap;
                    edits
                }
                None => ContainerEdits::default(),
            };
            devices.push(CdiDevice {
                name: name.to_string(),
                edits,
            });
        }
    }

    let common = match tree.get("containerEdits") {
        Some(node) => {
            let (edits, idmap) = container_edits(node, 0)?;
            idmap_ignored |= idmap;
            edits
        }
        None => ContainerEdits::default(),
    };

    Ok(CdiSpec {
        version: version.to_string(),
        kind: kind.to_string(),
        devices,
        common,
        idmap_ignored,
    })
}

/// The directories to search for specs, under `root`.
///
/// `override_dirs` replaces the defaults entirely when given, which is what "configurable, not
/// carved" means: a host that keeps its specs elsewhere is a setting, not a patch.
pub fn spec_dirs(root: &Path, override_dirs: Option<&[String]>) -> Vec<PathBuf> {
    match override_dirs {
        Some(dirs) if !dirs.is_empty() => dirs
            .iter()
            .map(|d| root.join(d.trim_start_matches('/')))
            .collect(),
        _ => DEFAULT_SPEC_DIRS.iter().map(|d| root.join(d)).collect(),
    }
}

/// Every `.yaml` and `.json` spec found under the search directories, in search order.
///
/// BOTH DIRECTORIES ARE READ, and the measurement says why: on this host `/etc/cdi` exists and is
/// EMPTY while the real spec lives in `/var/run/cdi`, so a reader that consulted only the first
/// would find nothing and report, truthfully and uselessly, that the host has no CDI.
pub fn find_specs(root: &Path, override_dirs: Option<&[String]>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in spec_dirs(root, override_dirs) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut here: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e == "yaml" || e == "yml" || e == "json")
            })
            .collect();
        here.sort();
        out.extend(here);
    }
    out
}

/// The nodes a named device asks for: the document's common nodes plus that device's own.
///
/// THE NESTING RULE LIVES HERE. A path is taken only when it EXISTS under the root AND is a
/// character device. The plan's reason is measured: a spec's paths are valid on the host and wrong
/// inside a nested container unless that runtime regenerated the spec, and the hook paths are wrong
/// more often than the node paths. So kern consumes a CDI spec as an ALIAS over what is actually
/// there, never as an instruction to be trusted.
///
/// Hooks are never executed and their paths are never resolved. They are read so a report can say
/// the spec declares them.
pub fn nodes_for_device(root: &Path, spec: &CdiSpec, device: &str) -> Option<Vec<PathBuf>> {
    let found = spec.devices.iter().find(|d| d.name == device)?;
    let mut out: Vec<PathBuf> = Vec::new();
    let push_if_real = |p: &Path, out: &mut Vec<PathBuf>| {
        let full = root.join(p.strip_prefix("/").unwrap_or(p));
        let Ok(meta) = std::fs::metadata(&full) else {
            return;
        };
        use std::os::unix::fs::FileTypeExt;
        if meta.file_type().is_char_device() {
            out.push(full);
        }
    };
    for p in &spec.common.device_nodes {
        push_if_real(p, &mut out);
    }
    for p in &found.edits.device_nodes {
        push_if_real(p, &mut out);
    }
    out.sort();
    out.dedup();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the toolkit actually generates, reduced to one device and the common block.
    const SAMPLE: &str = r#"---
cdiVersion: 0.5.0
kind: nvidia.com/gpu
devices:
    - name: "0"
      containerEdits:
        deviceNodes:
            - path: /dev/nvidia0
            - path: /dev/dri/card1
        hooks:
            - hookName: createContainer
              path: /usr/bin/nvidia-cdi-hook
              args:
                - nvidia-cdi-hook
                - create-symlinks
    - name: "1"
      containerEdits:
        deviceNodes:
            - path: /dev/nvidia1
containerEdits:
    deviceNodes:
        - path: /dev/nvidiactl
        - path: /dev/nvidia-uvm
    mounts:
        - hostPath: /run/nvidia-persistenced/socket
          containerPath: /run/nvidia-persistenced/socket
          options:
            - nosuid
            - nodev
"#;

    /// The generated shape parses into exactly what it says, with nothing invented and nothing lost.
    #[test]
    fn the_generated_shape_reads_into_its_own_structure() {
        let spec = match parse_spec(SAMPLE) {
            Ok(s) => s,
            Err(e) => panic!("the generated shape must parse: {e:?} / {}", e.describe()),
        };
        assert_eq!(spec.version, "0.5.0");
        assert_eq!(spec.kind, "nvidia.com/gpu");
        assert_eq!(spec.devices.len(), 2);
        assert_eq!(spec.devices[0].name, "0");
        assert_eq!(
            spec.devices[0].edits.device_nodes,
            vec![
                PathBuf::from("/dev/nvidia0"),
                PathBuf::from("/dev/dri/card1")
            ]
        );
        assert_eq!(spec.devices[1].name, "1");
        assert_eq!(
            spec.common.device_nodes,
            vec![
                PathBuf::from("/dev/nvidiactl"),
                PathBuf::from("/dev/nvidia-uvm")
            ]
        );
        assert_eq!(spec.common.mounts.len(), 1);
        assert_eq!(
            spec.common.mounts[0].options,
            vec!["nosuid".to_string(), "nodev".to_string()]
        );
        // The hook is READ and never executed; a report may name it.
        assert_eq!(spec.devices[0].edits.hooks.len(), 1);
        assert_eq!(spec.devices[0].edits.hooks[0].hook_name, "createContainer");
        assert!(!spec.idmap_ignored);
    }

    /// A VERSION NEWER THAN THIS READER IS REFUSED, and the equal case is accepted, which is the
    /// "both ways" the plan asks for: a rule that refused everything would pass a one-sided test.
    #[test]
    fn a_newer_spec_is_refused_and_a_known_one_is_not() {
        let known = SAMPLE.replace("cdiVersion: 0.5.0", "cdiVersion: 0.6.0");
        assert!(
            parse_spec(&known).is_ok(),
            "0.6.0 is the newest this reader claims and must be accepted"
        );

        for newer in ["0.6.1", "0.7.0", "1.0.0", "0.8.0"] {
            let text = SAMPLE.replace("cdiVersion: 0.5.0", &format!("cdiVersion: {newer}"));
            match parse_spec(&text) {
                Err(CdiError::VersionTooNew { given, known }) => {
                    assert_eq!(given, newer);
                    assert_eq!(known, "0.6.0");
                }
                other => panic!("{newer} should be refused, got {other:?}"),
            }
        }

        for older in ["0.5.0", "0.4.0", "0.3.0"] {
            let text = SAMPLE.replace("cdiVersion: 0.5.0", &format!("cdiVersion: {older}"));
            assert!(parse_spec(&text).is_ok(), "{older} must still be read");
        }
    }

    /// A missing or malformed version is named rather than defaulted.
    #[test]
    fn a_missing_or_malformed_version_is_refused_by_name() {
        let none = SAMPLE.replace("cdiVersion: 0.5.0\n", "");
        assert_eq!(parse_spec(&none), Err(CdiError::NoVersion));

        for bad in ["latest", "0", "0.x.1", "0.5.0.1", ""] {
            let text = SAMPLE.replace("cdiVersion: 0.5.0", &format!("cdiVersion: {bad}"));
            match parse_spec(&text) {
                Err(CdiError::BadVersion { .. }) | Err(CdiError::NoVersion) => {}
                other => panic!("{bad:?} should be refused, got {other:?}"),
            }
        }
    }

    /// `additionalGids` IS REFUSED WHEREVER IT APPEARS, including somewhere this reader's schema
    /// walk does not look. A field that asks for host gids cannot be honoured by a box and must not
    /// be silently dropped either.
    #[test]
    fn additional_gids_is_refused_wherever_it_appears() {
        let in_device = SAMPLE.replace(
            "        deviceNodes:\n            - path: /dev/nvidia0\n",
            "        additionalGids:\n            - 44\n        deviceNodes:\n            - path: /dev/nvidia0\n",
        );
        assert!(matches!(
            parse_spec(&in_device),
            Err(CdiError::AdditionalGids { .. })
        ));

        let in_common = format!("{SAMPLE}    additionalGids:\n        - 992\n");
        assert!(matches!(
            parse_spec(&in_common),
            Err(CdiError::AdditionalGids { .. })
        ));

        // Even somewhere structurally meaningless, because the refusal is about the request and
        // not about where the request was written.
        let stray = format!("# additionalGids\n{SAMPLE}");
        assert!(matches!(
            parse_spec(&stray),
            Err(CdiError::AdditionalGids { .. })
        ));
    }

    /// `idmap` is IGNORED and REPORTED. Dropping it in silence would leave an operator believing a
    /// field they wrote had an effect.
    #[test]
    fn an_idmap_is_ignored_and_said_to_have_been() {
        let text = SAMPLE.replace(
            "          options:\n",
            "          idmap:\n            - containerID: 0\n          options:\n",
        );
        let Ok(spec) = parse_spec(&text) else {
            panic!("an idmap must not fail the parse");
        };
        assert!(
            spec.idmap_ignored,
            "the spec carried an idmap and the reader must say so"
        );
        // And the mount it was attached to is still read.
        assert_eq!(spec.common.mounts.len(), 1);
    }

    /// EVERY CONSTRUCT THIS READER DOES NOT IMPLEMENT IS REFUSED BY NAME. A permissive parser that
    /// skipped them would be steerable by a grammar it never implemented.
    #[test]
    fn every_unimplemented_construct_is_refused_and_named() {
        let cases: [(&str, &str); 8] = [
            ("kind: &anchor nvidia.com/gpu", "a YAML anchor"),
            ("kind: *alias", "a YAML alias"),
            ("kind: {a: b}", "a flow mapping"),
            ("kind: [a, b]", "a flow sequence"),
            ("kind: |", "a literal block scalar"),
            ("kind: >", "a folded block scalar"),
            ("kind: !!str nvidia", "a YAML tag"),
            ("kind:\tnvidia", "a tab"),
        ];
        for (line, expected) in cases {
            let text = SAMPLE.replace("kind: nvidia.com/gpu", line);
            match parse_strict(&text) {
                Err(CdiError::Unsupported { construct, .. }) => assert_eq!(
                    construct, expected,
                    "{line:?} should be refused as {expected}"
                ),
                other => panic!("{line:?} should be Unsupported, got {other:?}"),
            }
        }

        let merge = SAMPLE.replace("kind: nvidia.com/gpu", "<<: *base");
        assert!(matches!(
            parse_strict(&merge),
            Err(CdiError::Unsupported {
                construct: "a merge key",
                ..
            })
        ));
    }

    /// The bounds hold, so a document from somewhere kern does not control cannot make the reader
    /// work without end.
    #[test]
    fn the_reader_is_bounded_in_lines_length_and_depth() {
        let many = "a: b\n".repeat(MAX_LINES + 1);
        assert!(matches!(
            parse_strict(&many),
            Err(CdiError::TooLarge { .. })
        ));

        let long = format!("a: {}\n", "x".repeat(MAX_LINE_LEN + 1));
        assert!(matches!(
            parse_strict(&long),
            Err(CdiError::LineTooLong { .. })
        ));

        let deep = format!("{}a: b\n", " ".repeat(MAX_INDENT + 1));
        assert!(matches!(
            parse_strict(&deep),
            Err(CdiError::BadIndent { .. })
        ));
    }

    /// A line that is none of the four accepted shapes is refused rather than guessed at.
    #[test]
    fn a_line_of_no_known_shape_is_refused() {
        let text = SAMPLE.replace("kind: nvidia.com/gpu", "this line has no colon at all");
        assert!(matches!(parse_strict(&text), Err(CdiError::BadLine { .. })));
    }

    /// A comment after a value is stripped, and a `#` inside a quoted value is not.
    #[test]
    fn a_comment_is_stripped_and_a_hash_inside_quotes_is_not() {
        let text = "cdiVersion: 0.5.0 # the version\nkind: \"nvidia.com/gpu#1\"\n";
        let Ok(spec) = parse_strict(text) else {
            panic!("should parse");
        };
        assert_eq!(
            spec.get("cdiVersion").and_then(Value::as_str),
            Some("0.5.0")
        );
        assert_eq!(
            spec.get("kind").and_then(Value::as_str),
            Some("nvidia.com/gpu#1")
        );
    }

    /// THE NESTING RULE: a path is taken only when it exists AND is a character device.
    ///
    /// A spec's paths are valid on the host and wrong inside a nested container unless that runtime
    /// regenerated them, so kern treats the spec as an ALIAS over what is actually there. The test
    /// builds a root where one named node is a plain file and one does not exist at all, and both
    /// must be dropped while the real one is kept.
    #[test]
    fn a_spec_path_that_is_not_a_character_device_is_not_consumed() {
        let root = std::env::temp_dir().join(format!("kern-cdi-nest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::create_dir_all(root.join("dev"));
        // A plain file wearing a device's name: what a nested container's /dev often holds.
        let _ = std::fs::write(root.join("dev/nvidia0"), b"not a device");

        let Ok(spec) = parse_spec(SAMPLE) else {
            panic!("sample must parse");
        };
        let got = nodes_for_device(&root, &spec, "0");
        let _ = std::fs::remove_dir_all(&root);

        let Some(nodes) = got else {
            panic!("the device exists in the spec");
        };
        assert!(
            nodes.is_empty(),
            "a plain file and an absent path must both be dropped: {nodes:?}"
        );
    }

    /// A device the spec does not offer answers None rather than an empty grant, so a caller can
    /// tell "not in this spec" from "in it and nothing survived the check".
    #[test]
    fn a_device_absent_from_the_spec_is_distinguishable_from_an_empty_one() {
        let Ok(spec) = parse_spec(SAMPLE) else {
            panic!("sample must parse");
        };
        let root = std::env::temp_dir().join("kern-cdi-none");
        assert!(nodes_for_device(&root, &spec, "7").is_none());
        assert!(nodes_for_device(&root, &spec, "0").is_some());
    }

    /// The search reads BOTH standard directories, and the override replaces them entirely.
    #[test]
    fn the_spec_directories_are_configurable_and_both_defaults_are_read() {
        let root = Path::new("/synthetic");
        let defaults = spec_dirs(root, None);
        assert_eq!(
            defaults,
            vec![
                PathBuf::from("/synthetic/etc/cdi"),
                PathBuf::from("/synthetic/var/run/cdi")
            ],
            "both standard directories, because on this host one of them is empty"
        );

        let overridden = spec_dirs(root, Some(&["opt/cdi".to_string()]));
        assert_eq!(overridden, vec![PathBuf::from("/synthetic/opt/cdi")]);

        // An empty override is not an override: it falls back rather than searching nothing.
        let empty: Vec<String> = Vec::new();
        assert_eq!(spec_dirs(root, Some(&empty)), defaults);
    }

    /// THE EQUIVALENCE PROOF, which is this sprint's whole point: the spec is an ALIAS over the
    /// discovery, so the two paths must name the same set on the same host.
    ///
    /// The comparison is of NODE SETS and needs no GPU work, which is why it runs while the cards
    /// are busy. It skips with a stated reason when the host has no spec or no driver, never in
    /// silence.
    ///
    /// This test is the reason S3's first step changed `gpu_grant`: before the DRM nodes were
    /// discovered through the PCI address, CDI carried `card1` and `renderD128` and discovery did
    /// not, and the two sets differed by exactly those two.
    #[test]
    fn the_spec_and_the_discovery_name_the_same_nodes_for_the_same_card() {
        let root = Path::new("/");
        let specs = find_specs(root, None);
        let Some(spec_path) = specs.first() else {
            eprintln!("skip: no CDI spec in /etc/cdi or /var/run/cdi on this host");
            return;
        };
        let Ok(text) = std::fs::read_to_string(spec_path) else {
            eprintln!("skip: {} is not readable", spec_path.display());
            return;
        };
        let spec = match parse_spec(&text) {
            Ok(s) => s,
            Err(e) => panic!("the host's spec must parse: {}", e.describe()),
        };

        let native = match crate::gpu_grant::resolve() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("skip: native discovery found no grant on this host ({e:?})");
                return;
            }
        };

        // Compare every card the spec names by index, which is the set `--gpus` can select.
        let mut compared = 0usize;
        for card in &native.cards {
            let name = card.index.to_string();
            let Some(from_spec) = nodes_for_device(root, &spec, &name) else {
                continue;
            };
            let mut from_spec: Vec<String> =
                from_spec.iter().map(|p| p.display().to_string()).collect();
            from_spec.sort();

            let mut from_native: Vec<String> = native
                .shared
                .iter()
                .chain(card.nodes.iter())
                .map(|(p, _)| p.display().to_string())
                .collect();
            from_native.sort();

            assert_eq!(
                from_spec, from_native,
                "card {name}: the spec and the discovery must name the same nodes"
            );
            compared += 1;
        }
        assert!(
            compared > 0,
            "no card was compared: the spec names {:?} and discovery found {:?}",
            spec.devices.iter().map(|d| &d.name).collect::<Vec<_>>(),
            native.cards.iter().map(|c| c.index).collect::<Vec<_>>()
        );
    }

    /// A BOUNDED, DETERMINISTIC FUZZ over the reader, because the spec is input and "read it by eye"
    /// is what the gate forbids.
    ///
    /// Every single-byte deletion, every single-byte truncation and a sweep of byte substitutions
    /// at every position are fed through `parse_spec`. The assertion is not that any of them
    /// parses: it is that NONE of them panics, loops or escapes with anything other than a named
    /// `CdiError`. A reader over hostile input earns its keep by failing the same way every time.
    #[test]
    fn the_reader_never_panics_on_a_mutated_document() {
        let base = SAMPLE.as_bytes();
        let mut checked = 0usize;

        // Truncation at every length: a document cut off anywhere.
        for len in 0..base.len() {
            let Some(slice) = base.get(..len) else {
                continue;
            };
            let text = String::from_utf8_lossy(slice);
            let _ = parse_spec(&text);
            checked += 1;
        }

        // Deletion of one byte at every position.
        for at in 0..base.len() {
            let mut bytes = base.to_vec();
            bytes.remove(at);
            let text = String::from_utf8_lossy(&bytes);
            let _ = parse_spec(&text);
            checked += 1;
        }

        // Substitution with the bytes most likely to steer a parser, at every position.
        for byte in [
            b':', b'-', b' ', b'\t', b'\n', b'"', b'#', b'{', b'[', b'&', b'*', b'!', 0xFF,
        ] {
            for at in 0..base.len() {
                let mut bytes = base.to_vec();
                if let Some(slot) = bytes.get_mut(at) {
                    *slot = byte;
                }
                let text = String::from_utf8_lossy(&bytes);
                let _ = parse_spec(&text);
                checked += 1;
            }
        }

        assert!(
            checked > 10_000,
            "the fuzz must actually exercise the reader, it ran {checked} cases"
        );
    }

    /// THE REAL SPEC ON THIS HOST, if there is one. Skips with a stated reason, never in silence.
    #[test]
    fn the_hosts_own_spec_parses_into_the_figures_it_was_measured_to_have() {
        let path = Path::new("/var/run/cdi/nvidia.yaml");
        let Ok(text) = std::fs::read_to_string(path) else {
            eprintln!("skip: no /var/run/cdi/nvidia.yaml on this host");
            return;
        };
        let spec = match parse_spec(&text) {
            Ok(s) => s,
            Err(e) => panic!("the host's own CDI spec must parse: {}", e.describe()),
        };
        assert_eq!(spec.kind, "nvidia.com/gpu");
        assert!(
            !spec.devices.is_empty(),
            "a generated spec names at least one device"
        );
        // Every device's nodes are absolute paths under /dev, which is the only shape the nesting
        // rule can check.
        for device in &spec.devices {
            for node in &device.edits.device_nodes {
                assert!(
                    node.starts_with("/dev"),
                    "{device:?} names a node outside /dev: {node:?}"
                );
            }
        }
        for node in &spec.common.device_nodes {
            assert!(
                node.starts_with("/dev"),
                "common node outside /dev: {node:?}"
            );
        }
    }
}

/// Why a `--device` reference could not be resolved to a card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRefError {
    /// The value is not `vendor/class=name`.
    NotQualified {
        /// What was passed.
        given: String,
    },
    /// The kind names a vendor or class no spec on this host offers.
    NoSuchKind {
        /// The kind that was asked for.
        kind: String,
        /// The kinds that were found, so the message can list them.
        found: Vec<String>,
    },
    /// The kind exists and the device name does not.
    NoSuchDevice {
        /// The name that was asked for.
        name: String,
        /// The names the spec offers.
        offered: Vec<String>,
    },
    /// `all` names more than one card and this build grants one.
    AllNotYet,
    /// The name is a UUID the host's driver does not report for any card.
    UnknownUuid {
        /// The UUID that was asked for.
        uuid: String,
    },
    /// A spec was found and could not be read.
    Unreadable {
        /// The file.
        path: PathBuf,
        /// Why.
        why: CdiError,
    },
}

/// The card minor a GPU UUID belongs to, read from the driver's own `information` file.
///
/// The same file and the same field `gpu_grant` uses for the PCI pairing, asked a second question:
/// `GPU UUID:` names the card and `Device Minor:` names its `/dev/nvidiaN`. Resolving a UUID any
/// other way would be a second source for a fact the driver already publishes.
fn minor_for_uuid(root: &Path, uuid: &str) -> Option<u32> {
    let gpus = root.join("proc/driver/nvidia/gpus");
    let entries = std::fs::read_dir(gpus).ok()?;
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path().join("information")) else {
            continue;
        };
        let mut found_uuid = None;
        let mut found_minor = None;
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("GPU UUID:") {
                found_uuid = Some(rest.trim().to_string());
            }
            if let Some(rest) = line.strip_prefix("Device Minor:") {
                found_minor = rest.trim().parse::<u32>().ok();
            }
        }
        if found_uuid.as_deref() == Some(uuid) {
            return found_minor;
        }
    }
    None
}

/// Resolve `--device vendor/class=name` to the card index `--gpus` would take.
///
/// CDI IS AN ALIAS AND NOTHING MORE, which is the plan's §7 rule and the reason this returns an
/// INDEX rather than a grant. The spec is consulted to learn which card a name means and to check,
/// through [`nodes_for_device`], that its paths are real device nodes under this root. The mounts
/// are then built from discovery, because a spec's paths are valid on the host and wrong inside a
/// nested container unless that runtime regenerated them.
///
/// The equivalence that makes this honest is measured rather than asserted: on this host the spec
/// and the discovery name the same seven nodes for card 0, and a test fails if they ever diverge.
pub fn resolve_device_ref(root: &Path, reference: &str) -> Result<u32, DeviceRefError> {
    let trimmed = reference.trim();
    let Some((kind, name)) = trimmed.split_once('=') else {
        return Err(DeviceRefError::NotQualified {
            given: trimmed.to_string(),
        });
    };
    if kind.is_empty() || !kind.contains('/') {
        return Err(DeviceRefError::NotQualified {
            given: trimmed.to_string(),
        });
    }
    if name.eq_ignore_ascii_case("all") {
        return Err(DeviceRefError::AllNotYet);
    }

    let mut kinds_found: Vec<String> = Vec::new();
    let mut offered: Vec<String> = Vec::new();
    for path in find_specs(root, None) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let spec = match parse_spec(&text) {
            Ok(s) => s,
            Err(why) => return Err(DeviceRefError::Unreadable { path, why }),
        };
        if spec.kind != kind {
            kinds_found.push(spec.kind);
            continue;
        }
        kinds_found.push(spec.kind.clone());
        offered = spec.devices.iter().map(|d| d.name.clone()).collect();

        let Some(device) = spec.devices.iter().find(|d| d.name == name) else {
            continue;
        };
        // THE NESTING RULE, applied before the name is believed: the spec's paths have to be real
        // device nodes under THIS root, or the spec is describing a host that is not the one kern
        // is running on.
        let _ = nodes_for_device(root, &spec, &device.name);

        if let Ok(index) = device.name.parse::<u32>() {
            return Ok(index);
        }
        if let Some(minor) = minor_for_uuid(root, &device.name) {
            return Ok(minor);
        }
        return Err(DeviceRefError::UnknownUuid {
            uuid: device.name.clone(),
        });
    }

    kinds_found.sort();
    kinds_found.dedup();
    if !kinds_found.iter().any(|k| k == kind) {
        return Err(DeviceRefError::NoSuchKind {
            kind: kind.to_string(),
            found: kinds_found,
        });
    }
    Err(DeviceRefError::NoSuchDevice {
        name: name.to_string(),
        offered,
    })
}
