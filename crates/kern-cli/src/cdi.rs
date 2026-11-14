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
//!   2. `idmap` IS NOT A CDI FIELD, and a document carrying one is REFUSED. This reader used to
//!      accept it and report that it had ignored it, on the belief that the reference's `Mount`
//!      might have it. Read from `specs-go/config.go` on 2026-11-12: `Mount` is `hostPath`,
//!      `containerPath`, `options`, `type`, and nothing else, so the reference refuses the document
//!      and kern was accepting a dialect no other reader takes. The refusal is the unknown-field
//!      one, which names the key.
//!   3. HOOKS ARE PARSED, NOT RUN, AND NOW SAID SO. A grant is a set of binds; kern starts no
//!      process a spec names. `nvidia-ctk` 1.18.2 attaches a `createContainer` hook to every device
//!      on this host (`nvidia-cdi-hook create-symlinks`), so the box gets the nodes and not the
//!      `/dev/dri/by-path` links that hook would have made. Silence there was a functional gap read
//!      as an alias: `--device` names what it does not run.
//!   4. THE DIRECTORIES ARE CONFIGURABLE, NOT CARVED. The two standard ones are `/etc/cdi` and
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

/// The most bytes a spec file is READ, derived from the two bounds above rather than chosen.
///
/// The lexer already refuses more than `MAX_LINES` lines of more than `MAX_LINE_LEN` each, so
/// reading past their product can only produce text the parser will refuse: the bound is the widest
/// input that could still be accepted, which is why it is multiplied here instead of picked. Before
/// this existed the read had no bound at all, and a 2 GB file at a spec's name became 2 GB resident
/// (measured 2026-11-12).
const MAX_SPEC_BYTES: u64 = (MAX_LINES as u64) * (MAX_LINE_LEN as u64);

/// The most bytes one of the driver's own `information` files is read. Not a spec bound: this file
/// is written by the kernel module and is a few hundred bytes, so the limit only has to exclude a
/// path that is not that file at all.
const MAX_DRIVER_INFO_BYTES: u64 = 64 * 1024;
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
    /// A mapping consumed as a struct carries a key the reference reader would refuse.
    ///
    /// MEASURED ON THE REFERENCE, not inferred: cncf-tags/container-device-interface at HEAD
    /// `9e21b8b` decodes with `go.yaml.in/yaml/v3` and `KnownFields(true)`, which rejects an
    /// unknown field PER STRUCT, wherever a struct is decoded, with `field not found in type
    /// <T>`. A key outside the set is not forward compatibility: the reference refuses the whole
    /// document, so kern accepting it is the same skew `DuplicateKey` closes.
    ///
    /// The set is FLAT, not versioned: every field is always known, and a field belonging to a
    /// LATER `cdiVersion` than the document declares is accepted by the decoder and refused by a
    /// separate version check. That second level is NOT implemented here, deliberately: the fields
    /// it protects (`netDevices`, `intelRdt`, and `additionalGids`, which kern refuses outright)
    /// are fields kern never reads, so walking the tree to version-check a payload with no
    /// consumer would be work with no effect.
    UnknownField {
        /// The key that does not belong.
        field: String,
        /// The structure it appeared in, named as the reference names it.
        in_struct: String,
    },
    /// The same mapping key appears twice in one mapping.
    ///
    /// REFUSED, AND THE REFERENCE REFUSES IT TOO, which is why this is not a "pick one" decision.
    /// The CDI reference reader (cncf-tags/container-device-interface, `go.yaml.in/yaml/v3` with
    /// `KnownFields(true)`) answers `mapping key "<k>" already defined` and rejects the whole
    /// document. last-wins was `yaml.v2` and is not what the CDI path uses.
    ///
    /// IT ALSO DEFEATED A REFUSAL THAT EXISTS HERE. `Value::get` is first-wins, so a document with
    /// `cdiVersion: 0.5.0` first and `cdiVersion: 9.9.9` later parsed as 0.5.0 and walked straight
    /// past [`CdiError::VersionTooNew`], which exists for exactly that. kern was ACCEPTING a spec
    /// the reference rejects.
    DuplicateKey {
        /// The key that appeared twice.
        key: String,
        /// The line of the SECOND appearance, which is the one to delete.
        line: usize,
    },
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
            CdiError::UnknownField { field, in_struct } => format!(
                "the CDI spec carries {field:?} in its {in_struct}, which is not a field of that \
                 structure. The reference CDI reader decodes with KnownFields and refuses the whole \
                 document for an unknown field, so accepting it here would make kern read specs no \
                 other runtime will. Remove it, or regenerate the spec with the toolkit that \
                 matches this host"
            ),
            CdiError::DuplicateKey { key, line } => format!(
                "the CDI spec defines {key:?} twice, the second time at line {line}. The reference \
                 CDI reader rejects a duplicate mapping key rather than choosing one, and so does \
                 this: a document where `cdiVersion` appears twice would otherwise be read as \
                 whichever copy came first, which is how a version this build refuses can slip \
                 through. Delete the duplicate"
            ),
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
    /// File `value` under `key`, refusing a key this mapping already has.
    ///
    /// ONE SPELLING for both push sites: a scalar entry and a nested frame being closed into its
    /// parent. They are far apart in `build` and a duplicate arriving through either is the same
    /// defect, which is how one of them would have kept it.
    fn insert(&mut self, key: String, value: Value, line: usize) -> Result<(), CdiError> {
        if self.map.iter().any(|(existing, _)| *existing == key) {
            return Err(CdiError::DuplicateKey { key, line });
        }
        self.map.push((key, value));
        Ok(())
    }

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
                Some(k) => parent.insert(k, value, line)?,
                None => parent.seq.push(value),
            }
        }
        Ok(())
    }

    // A SEQUENCE ITEM AT ITS KEY'S OWN COLUMN BELONGS TO THAT KEY: `devices:` then `- name: "0"`
    // both at column 0 is YAML's compact form, and NVIDIA writes it so. `close_to` ended the key's
    // frame at that column and the item became the DOCUMENT: MEASURED on a Jetson Orin Nano, the
    // board's own `nvidia-pva.yaml` read as a bare list and `--device` said it "carries no
    // cdiVersion". So a dash line first closes only what is deeper than it, and stays in a key frame
    // opened at its own column that holds no mapping yet.
    fn close_for_item(stack: &mut Vec<Frame>, indent: usize, line: usize) -> Result<(), CdiError> {
        close_to(stack, indent.saturating_add(1), line)?;
        let open_key_here = stack
            .last()
            .is_some_and(|top| top.indent == indent && top.key.is_some() && top.map.is_empty());
        if open_key_here {
            return Ok(());
        }
        close_to(stack, indent, line)
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
                top.insert(key.clone(), Value::Scalar(value.clone()), lexed.line)?;
            }
            Shape::SeqScalar(value) => {
                close_for_item(&mut stack, lexed.indent, lexed.line)?;
                let Some(top) = stack.last_mut() else {
                    return Err(CdiError::BadIndent { line: lexed.line });
                };
                top.is_seq = true;
                top.seq.push(Value::Scalar(value.clone()));
            }
            Shape::SeqKeyValue(key, value) => {
                close_for_item(&mut stack, lexed.indent, lexed.line)?;
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
                close_for_item(&mut stack, lexed.indent, lexed.line)?;
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
    /// `KEY=VALUE` entries the spec puts in the container's environment.
    pub env: Vec<String>,
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
}

/// Read `containerEdits` out of a tree node.
/// Refuse a mapping that carries a key the named structure does not have.
///
/// ONE SPELLING for all six structures, each with the field set measured on the reference reader at
/// HEAD `9e21b8b`. A non-mapping is not an error here: the callers already handle a scalar or a
/// sequence where they expect a mapping, and failing twice on the same input would report the wrong
/// fault.
///
/// TWO GAPS, both deliberate and both named because an undocumented gap is the defect this whole
/// arc was about:
///
///   * `annotations` is a `map[string]string` in the reference, so ANY key in it is accepted. This
///     function is never called on one.
///   * `intelRdt` is a struct whose field set has not been measured, so this never descends into
///     it. kern reads nothing from it, and guessing its fields would refuse specs real hosts carry.
fn check_fields(node: &Value, allowed: &[&str], in_struct: &str) -> Result<(), CdiError> {
    let Value::Map(entries) = node else {
        return Ok(());
    };
    for (key, _) in entries {
        if !allowed.contains(&key.as_str()) {
            return Err(CdiError::UnknownField {
                field: key.clone(),
                in_struct: in_struct.to_string(),
            });
        }
    }
    Ok(())
}

/// `Spec`, the document itself.
const SPEC_FIELDS: &[&str] = &[
    "cdiVersion",
    "kind",
    "annotations",
    "devices",
    "containerEdits",
];
/// `Device`, one entry of `devices`.
const DEVICE_FIELDS: &[&str] = &["name", "annotations", "containerEdits"];
/// `ContainerEdits`, at the document level and per device.
const EDITS_FIELDS: &[&str] = &[
    "env",
    "deviceNodes",
    "netDevices",
    "hooks",
    "mounts",
    "intelRdt",
    "additionalGids",
];
/// `DeviceNode`, one entry of `deviceNodes`.
const DEVICE_NODE_FIELDS: &[&str] = &[
    "path",
    "hostPath",
    "type",
    "major",
    "minor",
    "fileMode",
    "permissions",
    "uid",
    "gid",
];
/// `Mount`, one entry of `mounts`.
///
/// THE DISCREPANCY IS RESOLVED AND `idmap` IS GONE FROM THIS SET. It used to be here so a spec
/// carrying one would parse and the reader could report that it had been ignored, recorded as "a
/// discrepancy rather than a decision: either kern is reading a field that does not exist, or the
/// enumeration missed it". It was the first of those. Read from the reference's own source on
/// 2026-11-12, `specs-go/config.go`:
///
/// ```text
/// type Mount struct {
///     HostPath      string   `json:"hostPath"          yaml:"hostPath"`
///     ContainerPath string   `json:"containerPath"     yaml:"containerPath"`
///     Options       []string `json:"options,omitempty" yaml:"options,omitempty"`
///     Type          string   `json:"type,omitempty"    yaml:"type,omitempty"`
/// }
/// ```
///
/// There is no `idmap` on a CDI mount at all, so the reference's `KnownFields(true)` REFUSES a
/// document that has one, and kern was accepting a document every other reader rejects. That is a
/// dialect, and a spec that works here and nowhere else is worse for its author than a refusal:
/// kern now refuses it with the same unknown-field error, naming the key.
///
/// Confirmed against the only real spec this project can reach: `nvidia-ctk` 1.18.2 writes 619
/// lines to `/var/run/cdi/nvidia.yaml` on this host and not one `idmap` among them.
const MOUNT_FIELDS: &[&str] = &["hostPath", "containerPath", "options", "type"];
/// `Hook`, one entry of `hooks`.
const HOOK_FIELDS: &[&str] = &["hookName", "path", "args", "env", "timeout"];

fn container_edits(node: &Value, line_hint: usize) -> Result<ContainerEdits, CdiError> {
    check_fields(node, EDITS_FIELDS, "containerEdits")?;
    let mut edits = ContainerEdits::default();

    // THE CONTAINER'S VARIABLES, which docker and podman apply. MEASURED with docker 29.1.3 and
    // podman 4.9.3 on this host's spec: `NVIDIA_VISIBLE_DEVICES=void` in the container for every
    // `--device nvidia.com/gpu=…`, and kern set nothing because it did not read the list. A hook's
    // own `env` is a different list (the hook's process) and is not read here.
    if let Some(env) = node.get("env") {
        for item in env.items() {
            if let Some(kv) = item.as_str() {
                if kv.split_once('=').is_some_and(|(k, _)| !k.is_empty()) {
                    edits.env.push(kv.to_string());
                }
            }
        }
    }

    if let Some(nodes) = node.get("deviceNodes") {
        for item in nodes.items() {
            check_fields(item, DEVICE_NODE_FIELDS, "deviceNodes entry")?;
            if let Some(path) = item.get("path").and_then(Value::as_str) {
                edits.device_nodes.push(PathBuf::from(path));
            }
        }
    }

    if let Some(mounts) = node.get("mounts") {
        for item in mounts.items() {
            check_fields(item, MOUNT_FIELDS, "mounts entry")?;
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
            edits.mounts.push(CdiMount {
                host_path: PathBuf::from(host),
                container_path: PathBuf::from(container),
                options,
            });
        }
    }

    if let Some(hooks) = node.get("hooks") {
        for item in hooks.items() {
            check_fields(item, HOOK_FIELDS, "hooks entry")?;
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

    Ok(edits)
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
    check_fields(&tree, SPEC_FIELDS, "document")?;

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

    let mut devices: Vec<CdiDevice> = Vec::new();
    if let Some(list) = tree.get("devices") {
        for item in list.items() {
            check_fields(item, DEVICE_FIELDS, "devices entry")?;
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            let edits = match item.get("containerEdits") {
                Some(node) => container_edits(node, 0)?,
                None => ContainerEdits::default(),
            };
            devices.push(CdiDevice {
                name: name.to_string(),
                edits,
            });
        }
    }

    let common = match tree.get("containerEdits") {
        Some(node) => container_edits(node, 0)?,
        None => ContainerEdits::default(),
    };

    Ok(CdiSpec {
        version: version.to_string(),
        kind: kind.to_string(),
        devices,
        common,
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
    // CANONICAL ON BOTH SIDES. The prefix test compares the resolved path against the resolved
    // `dev` directory, because `<root>/dev` can itself be a symlink: on a host where `/dev` is one,
    // comparing a canonical path against a written one would refuse every node. An unresolvable
    // `dev` means there is nothing under this root to validate against.
    let Some(dev_root) = std::fs::canonicalize(root.join("dev")).ok() else {
        return Some(Vec::new());
    };
    let push_if_real = |p: &Path, out: &mut Vec<PathBuf>| {
        let full = root.join(p.strip_prefix("/").unwrap_or(p));

        // UNDER THE ROOT'S OWN `/dev`, resolved. A spec is third-party input and its paths are
        // strings: `/dev/../etc/shadow` joins to something outside `dev` entirely, and a symlink in
        // the middle can leave it too. `canonicalize` is what answers where the path really lands,
        // and the prefix test is on the ANSWER rather than on what was written.
        let Ok(real) = std::fs::canonicalize(&full) else {
            return;
        };
        if !real.starts_with(&dev_root) {
            return;
        }

        // THE KIND AND THE DEVICE NUMBER, not the kind alone. A lone `is_char_device()` is exactly
        // the predicate a whiteout beats: `vfs_mknod` tests CAP_MKNOD only `if ((S_ISCHR ||
        // S_ISBLK) && !is_whiteout && !capable(...))` and a whiteout is `c 0 0`, so an unprivileged
        // process CAN create a character device (measured 2026-11-12 on ext4 and on a box's own
        // tmpfs). It cannot choose the number: the kernel forces 0:0, and no device has that.
        //
        // `symlink_metadata` on the canonical path, so the classified inode is the one the prefix
        // test accepted and not whatever a final-component symlink points at.
        let Ok(meta) = std::fs::symlink_metadata(&real) else {
            return;
        };
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::fs::MetadataExt;
        if meta.file_type().is_char_device() && meta.rdev() != 0 {
            out.push(real);
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
mod compact_sequence_tests {
    /// NVIDIA's PVA spec on a Jetson, as the board ships it (shortened), opening with `---`.
    const PVA: &str = "---\ncdiVersion: 0.5.0\ncontainerEdits:\n  mounts:\n  - containerPath: /run/nvidia-pva-allowd\n    hostPath: /run/nvidia-pva-allowd\n    options:\n    - ro\n    - bind\n  hooks:\n  - path: /usr/bin/nvidia-pva-hook\n    hookName: createContainer\n    args:\n    - nvidia-pva-hook\n    - create\ndevices:\n- name: \"0\"\n  containerEdits:\n    env:\n    - NVIDIA_PVA_DEVICE=0\nkind: nvidia.com/pva\n";

    /// ⛔ NVIDIA'S JETSON SPEC IS READ. It writes its sequences in the compact form (`devices:` then
    /// `- name:` at the same column), and the whole document came back as a bare list, so `--device`
    /// said it "carries no cdiVersion". Its opening `---` was never the cause (the lexer takes it,
    /// and a sabotage of a second handling of it changed nothing), and a second document is still
    /// refused.
    #[test]
    fn nvidias_jetson_spec_with_compact_sequences_is_read() {
        let spec = super::parse_spec(PVA);
        assert!(
            matches!(&spec, Ok(s) if s.kind == "nvidia.com/pva"),
            "NVIDIA's PVA spec was not read: {spec:?}"
        );
        let two = format!("{PVA}---\ncdiVersion: 0.5.0\nkind: nvidia.com/gpu\ndevices: []\n");
        assert!(
            super::parse_spec(&two).is_err(),
            "a second document was taken"
        );
        let commented = format!("# generated\n\n{PVA}");
        assert!(
            super::parse_spec(&commented).is_ok(),
            "a comment above the marker broke it"
        );
        // The compact form and the indented one are the same document.
        let compact = "a: 1\nlist:\n- x: 1\n  y:\n  - p\n  - q\n- x: 2\nb: 2\n";
        let indented = "a: 1\nlist:\n  - x: 1\n    y:\n      - p\n      - q\n  - x: 2\nb: 2\n";
        assert_eq!(super::parse_strict(compact), super::parse_strict(indented));
        assert!(super::parse_strict(compact).is_ok());
    }
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

    /// `idmap` IS REFUSED, exactly as the reference refuses it.
    ///
    /// THIS TEST ASSERTED THE OPPOSITE UNTIL 2026-11-12, when the reference's own
    /// `specs-go/config.go` was read: `Mount` has `hostPath`, `containerPath`, `options` and
    /// `type`, so there is no `idmap` on a CDI mount and a reader with `KnownFields(true)` rejects
    /// the document. kern accepted it and reported that it had ignored the field, which made this
    /// build the only one that would run such a spec. The field is unknown, and the unknown-field
    /// refusal names it.
    #[test]
    fn an_idmap_is_refused_because_the_reference_has_no_such_field() {
        let text = SAMPLE.replace(
            "          options:\n",
            "          idmap:\n            - containerID: 0\n          options:\n",
        );
        match parse_spec(&text) {
            Err(CdiError::UnknownField { field, .. }) => {
                assert_eq!(field, "idmap", "the refusal must name the key");
            }
            Err(other) => panic!("refused for the wrong reason: {other:?}"),
            Ok(_) => panic!("a spec with mounts[].idmap was accepted; the reference refuses it"),
        }
    }

    /// ⛔ EVERY NAME ON THE LINE, `all` INCLUDED, AND THE SPEC'S VARIABLES. Measured with docker and
    /// podman on this host: two `--device` flags are two cards, `nvidia.com/gpu=all` is every card,
    /// and `NVIDIA_VISIBLE_DEVICES=void` from the spec is in the container. kern kept the last flag,
    /// refused `all`, and read no `env`.
    #[test]
    fn a_list_of_cdi_names_resolves_every_one_with_all_and_the_spec_env() {
        let root = std::env::temp_dir().join(format!("kern-cdi-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        if std::fs::create_dir_all(root.join("etc/cdi")).is_err() {
            eprintln!("skip: no writable temp dir");
            return;
        }
        if std::os::unix::fs::symlink("/dev", root.join("dev")).is_err() {
            eprintln!("skip: cannot link a dev directory");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        std::fs::write(
            root.join("etc/cdi/a.yaml"),
            concat!(
                "cdiVersion: 0.5.0\n",
                "kind: nvidia.com/gpu\n",
                "containerEdits:\n",
                "  env:\n",
                "    - NVIDIA_VISIBLE_DEVICES=void\n",
                "  hooks:\n",
                "    - hookName: createContainer\n",
                "      path: /usr/bin/nvidia-cdi-hook\n",
                "      env:\n",
                "        - NVIDIA_CTK_DEBUG=false\n",
                "devices:\n",
                "  - name: \"0\"\n",
                "    containerEdits:\n",
                "      deviceNodes:\n",
                "        - path: /dev/null\n",
                "  - name: \"1\"\n",
                "    containerEdits:\n",
                "      env:\n",
                "        - ONLY_ONE=yes\n",
                "      deviceNodes:\n",
                "        - path: /dev/zero\n",
                "  - name: all\n",
                "    containerEdits:\n",
                "      deviceNodes:\n",
                "        - path: /dev/null\n",
                "        - path: /dev/zero\n",
            ),
        )
        .expect("write spec");

        let two = resolve_device_refs(&root, "nvidia.com/gpu=0,nvidia.com/gpu=1,nvidia.com/gpu=0")
            .expect("both resolve");
        assert_eq!(
            two.indices,
            Some(vec![0, 1]),
            "both cards, once each, in order"
        );
        assert!(two.env.contains(&"NVIDIA_VISIBLE_DEVICES=void".to_string()));
        assert!(
            two.env.contains(&"ONLY_ONE=yes".to_string()),
            "{:?}",
            two.env
        );
        assert!(
            !two.env.iter().any(|kv| kv.starts_with("NVIDIA_CTK_DEBUG")),
            "a hook's own env is the hook's, not the container's: {:?}",
            two.env
        );

        let all = resolve_device_refs(&root, "nvidia.com/gpu=all").expect("all resolves");
        assert_eq!(all.indices, None, "the spec's `all` is every card");
        let mixed =
            resolve_device_refs(&root, "nvidia.com/gpu=0,nvidia.com/gpu=all").expect("mixed");
        assert_eq!(mixed.indices, None);

        match resolve_device_refs(&root, "nvidia.com/gpu=0,nvidia.com/gpu=7") {
            Err((name, DeviceRefError::NoSuchDevice { .. })) => {
                assert_eq!(
                    name, "nvidia.com/gpu=7",
                    "the name that failed is the one named"
                )
            }
            other => panic!("one bad name must fail the request: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// THE HOOKS TRAVEL WITH THE RESOLUTION, from the device AND from the common edits.
    ///
    /// WHY IT MATTERS, measured on 2026-11-12: `nvidia-ctk` 1.18.2 attaches a `createContainer`
    /// hook to every device in `/var/run/cdi/nvidia.yaml`, and kern ran none of them and said
    /// nothing. The device NODES of a CDI name and of `--gpus` are the same set, so a reader
    /// comparing node lists read "alias" as a complete equivalence. It is not: no hook runs, and
    /// what a hook would have created is not in the box.
    #[test]
    fn a_resolved_device_carries_the_hooks_kern_will_not_run() {
        let root = std::env::temp_dir().join(format!("kern-cdi-hooks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        if std::fs::create_dir_all(root.join("etc/cdi")).is_err() {
            eprintln!("skip: no writable temp dir");
            return;
        }
        // `/dev` from the host, because the nesting rule wants a real character device and an
        // unprivileged test cannot make one. `/dev/null` is one everywhere.
        if std::os::unix::fs::symlink("/dev", root.join("dev")).is_err() {
            eprintln!("skip: cannot link a dev directory");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        // THE DOCUMENT CARRIES A HOOK THAT THE DEVICE DOES NOT, and that is the whole shape of this
        // fixture. The first version put the document's only hook on the device as well, to
        // exercise the deduplication, which made the document half of the collection invisible:
        // deleting `hook_labels(&spec.common)` from the resolver left this test GREEN. A sabotage
        // that passes is the test being wrong, not the code being right.
        //
        // So: one hook in both places (the deduplication), one only on the device, one only on the
        // document.
        std::fs::write(
            root.join("etc/cdi/a.yaml"),
            concat!(
                "cdiVersion: 0.5.0\n",
                "kind: nvidia.com/gpu\n",
                "containerEdits:\n",
                "  hooks:\n",
                "    - hookName: createContainer\n",
                "      path: /usr/bin/nvidia-cdi-hook\n",
                "    - hookName: postStart\n",
                "      path: /opt/vendor/document-only-hook\n",
                "devices:\n",
                "  - name: \"0\"\n",
                "    containerEdits:\n",
                "      deviceNodes:\n",
                "        - path: /dev/null\n",
                "      hooks:\n",
                "        - hookName: createContainer\n",
                "          path: /usr/bin/nvidia-cdi-hook\n",
                "        - hookName: startContainer\n",
                "          path: /opt/vendor/second-hook\n",
            ),
        )
        .expect("write spec");

        let resolved = resolve_device_ref(&root, "nvidia.com/gpu=0").expect("must resolve");
        assert_eq!(resolved.index, Some(0));
        assert_eq!(
            resolved.hooks_not_run,
            vec![
                "createContainer /usr/bin/nvidia-cdi-hook".to_string(),
                "postStart /opt/vendor/document-only-hook".to_string(),
                "startContainer /opt/vendor/second-hook".to_string(),
            ],
            "the device's hooks, the document's, once each, sorted"
        );

        let msg = describe_hooks_not_run("nvidia.com/gpu=0", &resolved.hooks_not_run)
            .expect("a device with hooks must produce a sentence");
        for needle in [
            "3 hook(s)",
            "nvidia.com/gpu=0",
            "createContainer",
            "startContainer",
            "/opt/vendor/document-only-hook",
            "/usr/bin/nvidia-cdi-hook",
        ] {
            assert!(msg.contains(needle), "the sentence omits {needle}: {msg}");
        }
        // AND NO SENTENCE WHERE THERE ARE NO HOOKS, which is the majority of specs and must stay
        // silent: a warning on every `--device` would be noise an operator learns to skip.
        assert_eq!(describe_hooks_not_run("nvidia.com/gpu=0", &[]), None);
        let _ = std::fs::remove_dir_all(&root);
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

    /// AN UNKNOWN FIELD IS REFUSED PER STRUCT, which is what the reference reader does.
    ///
    /// Measured on cncf-tags/container-device-interface at HEAD `9e21b8b`, decoding with
    /// `go.yaml.in/yaml/v3 v3.0.5` and `KnownFields(true)`: an unknown key is rejected wherever a
    /// struct is decoded, with `field not found in type <T>`, and the whole document goes with it.
    /// kern accepted every one of them, which is the same skew `DuplicateKey` closes: reading specs
    /// no other runtime will.
    ///
    /// PER STRUCT AND NOT PER DOCUMENT, which is why this is a tree walk and not a flat allowlist:
    /// `path` is a field of `deviceNodes` and of `hooks` and of neither `Spec` nor `Mount`, so a
    /// single set of every legal key anywhere would accept `cdiVersion` inside a mount.
    #[test]
    fn an_unknown_field_is_refused_in_the_structure_it_appears_in() {
        let spec =
            |body: &str| -> String { format!("cdiVersion: 0.5.0\nkind: nvidia.com/gpu\n{body}") };

        // POSITIVE CONTROL FIRST: the shape this host's own generator writes, with every field set
        // the reference carries, must parse. Without it every refusal below is satisfied by a
        // reader that refuses everything.
        let real = spec(concat!(
            "containerEdits:\n",
            "  env:\n",
            "    - A=1\n",
            "  mounts:\n",
            "    - hostPath: /usr/lib/x\n",
            "      containerPath: /usr/lib/x\n",
            "      options:\n",
            "        - ro\n",
            "devices:\n",
            "  - name: \"0\"\n",
            "    containerEdits:\n",
            "      deviceNodes:\n",
            "        - path: /dev/nvidia0\n",
            "          hostPath: /dev/nvidia0\n",
            "      hooks:\n",
            "        - hookName: createContainer\n",
            "          path: /usr/bin/nvidia-cdi-hook\n",
            "          args:\n",
            "            - hook\n",
            "          env:\n",
            "            - B=2\n",
        ));
        if let Err(e) = parse_spec(&real) {
            panic!("the generated shape must parse: {}", e.describe());
        }

        // EACH STRUCTURE, named in its own refusal, because "unknown field" without the place is a
        // message the reader cannot act on.
        for (body, field, place) in [
            ("bogusTop: 1\n", "bogusTop", "document"),
            (
                "devices:\n  - name: \"0\"\n    bogusDev: 1\n",
                "bogusDev",
                "devices entry",
            ),
            (
                "containerEdits:\n  bogusEdit: 1\n",
                "bogusEdit",
                "containerEdits",
            ),
            (
                "containerEdits:\n  deviceNodes:\n    - path: /dev/null\n      bogusNode: 1\n",
                "bogusNode",
                "deviceNodes entry",
            ),
            (
                "containerEdits:\n  mounts:\n    - hostPath: /a\n      bogusMount: 1\n",
                "bogusMount",
                "mounts entry",
            ),
            (
                "containerEdits:\n  hooks:\n    - hookName: x\n      bogusHook: 1\n",
                "bogusHook",
                "hooks entry",
            ),
        ] {
            match parse_spec(&spec(body)) {
                Err(CdiError::UnknownField {
                    field: got,
                    in_struct,
                }) => {
                    assert_eq!(got, field);
                    assert_eq!(in_struct, place, "the refusal must name where it was found");
                }
                other => panic!("{field} in {place} must be refused, got {other:?}"),
            }
        }

        // A FIELD LEGAL SOMEWHERE ELSE IS STILL UNKNOWN HERE, which is the whole reason this is a
        // tree walk. `path` belongs to a deviceNodes entry and to a hook, and to neither a mount
        // nor the document.
        match parse_spec(&spec("path: /dev/null\n")) {
            Err(CdiError::UnknownField { field, in_struct }) => {
                assert_eq!(field, "path");
                assert_eq!(in_struct, "document");
            }
            other => panic!("`path` at the document level must be refused, got {other:?}"),
        }
        match parse_spec(&spec(
            "containerEdits:\n  mounts:\n    - hostPath: /a\n      cdiVersion: 0.5.0\n",
        )) {
            Err(CdiError::UnknownField { field, in_struct }) => {
                assert_eq!(field, "cdiVersion");
                assert_eq!(in_struct, "mounts entry");
            }
            other => panic!("`cdiVersion` inside a mount must be refused, got {other:?}"),
        }

        // THE FIELDS KERN NEVER READS ARE STILL FIELDS. `netDevices` and `intelRdt` belong to
        // `containerEdits` in the reference, so refusing them would refuse a valid spec; kern does
        // not descend into `intelRdt`, whose own field set has not been measured.
        assert!(
            parse_spec(&spec(
                "containerEdits:\n  intelRdt:\n    closID: x\n    schemata:\n      - y\n"
            ))
            .is_ok(),
            "a field kern does not read is not an unknown field"
        );
        assert!(
            parse_spec(&spec("containerEdits:\n  netDevices:\n    - name: eth0\n")).is_ok(),
            "netDevices belongs to containerEdits in the reference"
        );
        // `annotations` is a free-form `map[string]string` there, so any key inside it is accepted.
        assert!(
            parse_spec(&spec(
                "annotations:\n  anything.example.com/at-all: \"1\"\n"
            ))
            .is_ok(),
            "annotations takes arbitrary keys"
        );

        // AND THE MESSAGE SAYS WHAT TO DO.
        let said = CdiError::UnknownField {
            field: "bogus".to_string(),
            in_struct: "mounts entry".to_string(),
        }
        .describe();
        assert!(
            said.contains("\"bogus\"") && said.contains("mounts entry"),
            "{said}"
        );
        assert!(said.contains("KnownFields"), "{said}");
    }

    /// THE NESTING RULE, WHICH WAS A NO-OP, and the predicate it rests on, which a whiteout beat.
    ///
    /// `resolve_device_ref` computed `nodes_for_device` and threw it away with `let _ = ...`, so the
    /// documented rule did nothing: a spec naming a device whose paths do not exist here was
    /// believed. A spec describes the host it was generated on, and inside a nested container those
    /// paths are wrong unless that runtime regenerated it.
    ///
    /// AND THE PREDICATE WAS ONE `is_char_device()`, which is exactly what the whiteout defeats:
    /// `vfs_mknod` tests CAP_MKNOD only `if ((S_ISCHR || S_ISBLK) && !is_whiteout && !capable(...))`
    /// and a whiteout is `c 0 0`, so an unprivileged process can create a character device
    /// (measured 2026-11-12). It cannot choose the number, which is why the rule is the kind AND a
    /// non-zero `rdev`.
    #[test]
    fn the_nesting_rule_refuses_a_spec_whose_nodes_are_not_here() {
        // ONE ROOT PER CASE. The first version of this test reused one directory and the positive
        // control failed on state left by the case before it, which is a test defect that reads
        // exactly like a code defect. A case that cannot be run alone is a case whose failure
        // cannot be located.
        let make_root = |tag: &str, node: &str, link_dev: bool| -> Option<std::path::PathBuf> {
            let root =
                std::env::temp_dir().join(format!("kern-cdi-nest-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("etc/cdi")).ok()?;
            if link_dev {
                // `dev` points at the HOST's, because the rule requires a real character device and
                // an unprivileged test cannot `mknod` one. This is also why `nodes_for_device`
                // canonicalizes both sides of its prefix test: `<root>/dev` is a symlink here.
                std::os::unix::fs::symlink("/dev", root.join("dev")).ok()?;
            } else {
                std::fs::create_dir_all(root.join("dev")).ok()?;
            }
            std::fs::write(
                root.join("etc/cdi/a.yaml"),
                format!(
                    concat!(
                        "cdiVersion: 0.5.0\n",
                        "kind: nvidia.com/gpu\n",
                        "devices:\n",
                        "  - name: \"0\"\n",
                        "    containerEdits:\n",
                        "      deviceNodes:\n",
                        "        - path: {}\n",
                    ),
                    node
                ),
            )
            .ok()?;
            Some(root)
        };

        // POSITIVE CONTROL FIRST, because every refusal below is worthless if the rule refuses
        // everything. `/dev/null` is a real character device on every host this runs on.
        let Some(root) = make_root("ok", "/dev/null", true) else {
            eprintln!("skip: no writable temp dir");
            return;
        };
        let got = resolve_device_ref(&root, "nvidia.com/gpu=0").map(|r| r.index);
        assert_eq!(
            got,
            Ok(Some(0)),
            "a spec whose node IS here must resolve, or this rule refuses every host: {got:?}"
        );
        let _ = std::fs::remove_dir_all(&root);

        // 1. A PATH THAT IS NOT HERE: the name is valid and the node is absent, which is the whole
        //    shape of the nested case, and the discarded call accepted it.
        if let Some(root) = make_root("absent", "/dev/nvidia-not-here", false) {
            match resolve_device_ref(&root, "nvidia.com/gpu=0") {
                Err(DeviceRefError::DescribesAnotherHost { reference, .. }) => {
                    assert_eq!(reference, "nvidia.com/gpu=0");
                }
                other => panic!("a spec whose node is absent here must be refused: {other:?}"),
            }
            let _ = std::fs::remove_dir_all(&root);
        }

        // 2. A WHITEOUT AT THE PATH. An unprivileged process can create one and it IS a character
        //    device by kind, so the old lone `is_char_device()` would have taken it.
        if let Some(root) = make_root("white", "/dev/nvidia0", false) {
            let white = root.join("dev/nvidia0");
            let made = std::ffi::CString::new(white.as_os_str().as_encoded_bytes())
                .map(|p| unsafe { libc::mknod(p.as_ptr(), libc::S_IFCHR | 0o600, 0) })
                .unwrap_or(-1);
            if made == 0 {
                use std::os::unix::fs::FileTypeExt;
                assert!(
                    std::fs::symlink_metadata(&white)
                        .map(|m| m.file_type().is_char_device())
                        .unwrap_or(false),
                    "the whiteout must read as a character device, or this case is vacuous"
                );
                match resolve_device_ref(&root, "nvidia.com/gpu=0") {
                    Err(DeviceRefError::DescribesAnotherHost { .. }) => {}
                    other => panic!("a whiteout is not a device node: {other:?}"),
                }
            } else {
                eprintln!("skip: this kernel refused the whiteout, so that half did not run");
            }
            let _ = std::fs::remove_dir_all(&root);
        }

        // 3. A PATH THAT LEAVES `dev`. A spec's paths are strings and `..` is one of them, so the
        //    prefix test is on the CANONICAL answer and not on what was written.
        if let Some(root) = make_root("escape", "/dev/../etc/cdi/a.yaml", true) {
            match resolve_device_ref(&root, "nvidia.com/gpu=0") {
                Err(DeviceRefError::DescribesAnotherHost { .. }) => {}
                other => panic!("a path outside dev must not count as a node: {other:?}"),
            }
            let _ = std::fs::remove_dir_all(&root);
        }

        // 4. AN ESCAPE THAT LANDS ON A REAL CHARACTER DEVICE, which is the only case that makes
        //    the prefix test load-bearing. Case 3's `..` resolves to a regular file, so the KIND
        //    check already refuses it and dropping the prefix test would not change the answer:
        //    that was measured by sabotage, and this case is why the sabotage now fails. The root
        //    here has a real `dev` directory, so `dev_root` is `<root>/dev`, and the path climbs
        //    out to the host's `/dev/null`, which passes every other test in the predicate.
        if let Some(root) = make_root("escape_dev", "/../../dev/null", false) {
            let full = root.join("../../dev/null");
            let lands_on_dev_null = std::fs::canonicalize(&full)
                .map(|p| p == std::path::Path::new("/dev/null"))
                .unwrap_or(false);
            if lands_on_dev_null {
                match resolve_device_ref(&root, "nvidia.com/gpu=0") {
                    Err(DeviceRefError::DescribesAnotherHost { .. }) => {}
                    other => panic!(
                        "a path climbing out of the root onto a real device must be refused: {other:?}"
                    ),
                }
            } else {
                eprintln!(
                    "skip: {} does not resolve to /dev/null here, so the escape case cannot run",
                    full.display()
                );
            }
            let _ = std::fs::remove_dir_all(&root);
        }

        // 5. A REGULAR FILE AND A DIRECTORY at the path, which are what a spec naming a stale or
        //    wrong location finds.
        for (tag, node) in [("file", "/dev/../etc/cdi/a.yaml"), ("dir", "/dev")] {
            if let Some(root) = make_root(tag, node, true) {
                assert!(
                    matches!(
                        resolve_device_ref(&root, "nvidia.com/gpu=0"),
                        Err(DeviceRefError::DescribesAnotherHost { .. })
                    ),
                    "a {tag} at the path must not count as a device node"
                );
                let _ = std::fs::remove_dir_all(&root);
            }
        }
    }

    /// A DUPLICATE MAPPING KEY IS REFUSED, and the case that matters is the one it used to bypass.
    ///
    /// `Value::get` is first-wins, so a document carrying `cdiVersion: 0.5.0` and then
    /// `cdiVersion: 9.9.9` parsed as 0.5.0 and walked straight past `VersionTooNew`, which exists
    /// to refuse a spec this build cannot read. kern was ACCEPTING a document the reference reader
    /// rejects: cncf-tags/container-device-interface at HEAD `9e21b8b` with
    /// `go.yaml.in/yaml/v3 v3.0.5` and `KnownFields(true)` answers `mapping key "cdiVersion"
    /// already defined`. last-wins was `yaml.v2` and is not the CDI path.
    ///
    /// Refusing beats either choice: picking the first silently honours the attacker's framing and
    /// picking the last silently honours the other one, while the document is malformed either way.
    #[test]
    fn a_duplicate_mapping_key_is_refused_instead_of_resolved() {
        // THE BYPASS. Without the refusal this parses, reports 0.5.0 and is accepted.
        let bypass = "cdiVersion: 0.5.0\nkind: nvidia.com/gpu\ncdiVersion: 9.9.9\n";
        match parse_spec(bypass) {
            Err(CdiError::DuplicateKey { key, line }) => {
                assert_eq!(key, "cdiVersion");
                assert_eq!(
                    line, 3,
                    "the line must name the SECOND appearance, the one to delete"
                );
            }
            other => panic!("a duplicated cdiVersion must be refused, got {other:?}"),
        }

        // POSITIVE CONTROL: the same document without the duplicate is accepted, so the refusal is
        // the duplicate and not the content.
        let clean = "cdiVersion: 0.5.0\nkind: nvidia.com/gpu\n";
        assert!(
            parse_spec(clean).is_ok(),
            "the same spec without the duplicate must still parse"
        );

        // AND THE REFUSAL IT WAS BYPASSING still fires on its own, so this case did not simply
        // replace one error with another.
        let too_new = "cdiVersion: 9.9.9\nkind: nvidia.com/gpu\n";
        assert!(
            matches!(parse_spec(too_new), Err(CdiError::VersionTooNew { .. })),
            "VersionTooNew must still be reachable"
        );

        // BOTH PUSH SITES. A duplicate arrives either as a scalar entry or as a nested block closed
        // into its parent, and the two are far apart in `build`: one of them would have kept the
        // defect. `devices` here is a nested mapping, not a scalar.
        let nested = concat!(
            "cdiVersion: 0.5.0\n",
            "kind: nvidia.com/gpu\n",
            "containerEdits:\n",
            "  env:\n",
            "    - A=1\n",
            "containerEdits:\n",
            "  env:\n",
            "    - B=2\n",
        );
        match parse_spec(nested) {
            Err(CdiError::DuplicateKey { key, .. }) => assert_eq!(key, "containerEdits"),
            other => panic!("a duplicated nested block must be refused, got {other:?}"),
        }

        // A REPEATED KEY IN A DIFFERENT MAPPING IS NOT A DUPLICATE. Two devices may each carry
        // `name`, which is the common shape of every real spec, so a check on the key alone rather
        // than on the key within its mapping would refuse every host's file.
        let siblings = concat!(
            "cdiVersion: 0.5.0\n",
            "kind: nvidia.com/gpu\n",
            "devices:\n",
            "  - name: \"0\"\n",
            "    containerEdits:\n",
            "      deviceNodes:\n",
            "        - path: /dev/nvidia0\n",
            "  - name: \"1\"\n",
            "    containerEdits:\n",
            "      deviceNodes:\n",
            "        - path: /dev/nvidia1\n",
        );
        let spec = match parse_spec(siblings) {
            Ok(spec) => spec,
            Err(e) => panic!(
                "two devices each with a `name` must parse: {}",
                e.describe()
            ),
        };
        assert_eq!(spec.devices.len(), 2, "both devices must survive");

        // A DUPLICATE INSIDE A SEQUENCE ITEM. The first key of such an item is built directly into
        // the new frame's map (`Shape::SeqKeyValue`), which is a THIRD construction site that does
        // not go through `insert`; it cannot itself be a duplicate because the map starts empty,
        // but every later key in the item must still be checked.
        let dup_in_item = concat!(
            "cdiVersion: 0.5.0\n",
            "kind: nvidia.com/gpu\n",
            "devices:\n",
            "  - name: \"0\"\n",
            "    name: \"1\"\n",
        );
        match parse_spec(dup_in_item) {
            Err(CdiError::DuplicateKey { key, line }) => {
                assert_eq!(key, "name");
                assert_eq!(line, 5);
            }
            other => panic!("a duplicate inside a sequence item must be refused, got {other:?}"),
        }

        // And the message says what to do about it.
        let described = CdiError::DuplicateKey {
            key: "cdiVersion".to_string(),
            line: 3,
        }
        .describe();
        assert!(described.contains("twice"), "{described}");
        assert!(described.contains("line 3"), "{described}");
        assert!(described.contains("Delete the duplicate"), "{described}");
    }

    /// A SPEC DIRECTORY IS WRITABLE BY WHOEVER CAN WRITE IT, so what it holds is not kern's choice.
    ///
    /// `find_specs` walks `/etc/cdi` and `/var/run/cdi` and `resolve_device_ref` read every match
    /// with an unbounded `read_to_string` and no type check. Measured 2026-11-12: a FIFO named
    /// `nvidia.yaml` made plain `kern doctor` hang for ever, and a 2 GB file at a spec's name became
    /// 2 GB resident. Both are reachable without `--device`, because the doctor row reads the specs
    /// to say whether this build can parse them.
    ///
    /// AN UNUSABLE FILE IS SKIPPED AND THE WALK CONTINUES, which is the behaviour that matters as
    /// much as the refusal: one bad file in a shared directory must not disable every device name on
    /// the host. The good spec beside the bad ones is what proves it.
    ///
    /// Timed, because a regression here HANGS rather than fails.
    #[test]
    fn an_unusable_file_in_a_spec_directory_is_skipped_and_does_not_hang() {
        let root = std::env::temp_dir().join(format!("kern-cdi-bad-{}", std::process::id()));
        let dir = root.join("etc/cdi");
        let _ = std::fs::remove_dir_all(&root);
        if std::fs::create_dir_all(&dir).is_err() {
            eprintln!("skip: no writable temp dir");
            return;
        }

        // `dev` POINTS AT THE HOST'S, because the nesting rule now requires the spec's paths to be
        // real character devices under this root and an unprivileged test cannot `mknod` one. The
        // symlink is why `nodes_for_device` canonicalizes both sides of its prefix test.
        let _ = std::os::unix::fs::symlink("/dev", root.join("dev"));

        // A spec that names a device, so the walk has something to find AFTER the bad files. The
        // name sorts after both, which is what makes this a test of continuing rather than of order.
        // `/dev/null`, NOT `/dev/nvidia0`: the walk is what is under test, and a node only an NVIDIA
        // host has made this fail on every host without one (a WSL2 guest, a CI runner), where the
        // spec rightly reads as describing another machine. MEASURED in `kern-ubuntu`.
        let good = "cdiVersion: 0.5.0\nkind: nvidia.com/gpu\ndevices:\n  - name: \"0\"\n    containerEdits:\n      deviceNodes:\n        - path: /dev/null\n";
        let _ = std::fs::write(dir.join("zz-good.yaml"), good);

        let fifo_made =
            std::ffi::CString::new(dir.join("aa-fifo.yaml").as_os_str().as_encoded_bytes())
                .map(|p| unsafe { libc::mkfifo(p.as_ptr(), 0o644) })
                .unwrap_or(-1);
        if let Ok(file) = std::fs::File::create(dir.join("bb-huge.yaml")) {
            // Past MAX_SPEC_BYTES, sparse so the test costs no disk.
            let _ = file.set_len(MAX_SPEC_BYTES + 1);
        }

        // Every match is listed, including the ones that cannot be used: the filter is the READ and
        // not the directory walk, so this count is what the reader has to survive.
        let found = find_specs(&root, None);
        assert!(
            found.len() >= 2,
            "the walk must still list what it finds: {found:?}"
        );

        let started = std::time::Instant::now();
        let got = resolve_device_ref(&root, "nvidia.com/gpu=0").map(|r| r.index);
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(5),
            "resolving took {took:?}, so a FIFO or the size was read instead of refused"
        );
        assert_eq!(
            got,
            Ok(Some(0)),
            "the good spec beside the unusable ones must still resolve"
        );
        if fifo_made != 0 {
            eprintln!("note: mkfifo failed, so only the size half of this case ran");
        }

        // POSITIVE CONTROL: a name the good spec does not carry is still a clean refusal and not a
        // hang either, so the pass above is the spec being read and not the function giving up.
        let missing = resolve_device_ref(&root, "nvidia.com/gpu=7");
        assert!(
            matches!(missing, Err(DeviceRefError::NoSuchDevice { .. })),
            "expected NoSuchDevice, got {missing:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// ONE JUNK FILE MUST NOT DISABLE `--device` FOR EVERY NAME ON THE HOST.
    ///
    /// The walk returned on the FIRST unparseable spec, and a spec directory is writable by
    /// whoever can write it. The walk continues now and the failures are reported only when nothing
    /// matched, which keeps the diagnosis without the blast radius: a file that cannot be read is a
    /// reason the answer might be wrong, not an answer.
    ///
    /// AND JSON GETS ITS OWN ANSWER. `find_specs` accepts `.json` because the CDI specification
    /// does and `nvidia-ctk cdi generate --format=json` writes one, while this lexer reads a
    /// line-based YAML subset. Measured: a JSON document, one-line or pretty-printed, answers
    /// `BadLine { line: 1 }`, so it already failed CLOSED and what was missing was the diagnosis.
    /// "bad line 1" about a valid JSON file sends the reader looking for a typo.
    #[test]
    fn a_bad_spec_beside_a_good_one_does_not_disable_the_good_one() {
        let root = std::env::temp_dir().join(format!("kern-cdi-junk-{}", std::process::id()));
        let dir = root.join("etc/cdi");
        let _ = std::fs::remove_dir_all(&root);
        if std::fs::create_dir_all(&dir).is_err()
            || std::os::unix::fs::symlink("/dev", root.join("dev")).is_err()
        {
            eprintln!("skip: no writable temp dir");
            return;
        }
        let good = concat!(
            "cdiVersion: 0.5.0\n",
            "kind: nvidia.com/gpu\n",
            "devices:\n",
            "  - name: \"0\"\n",
            "    containerEdits:\n",
            "      deviceNodes:\n",
            "        - path: /dev/null\n",
        );

        // The junk sorts BEFORE the good one, which is what makes this a test of continuing rather
        // than of luck in the directory order.
        let _ = std::fs::write(dir.join("aa-junk.yaml"), "\t\tnot: [a, spec\n");
        let _ = std::fs::write(dir.join("zz-good.yaml"), good);
        assert_eq!(
            resolve_device_ref(&root, "nvidia.com/gpu=0").map(|r| r.index),
            Ok(Some(0)),
            "a junk file before the good one must not disable it"
        );

        // WITH NO GOOD SPEC the junk becomes the answer, because reporting "no spec offers that
        // kind" while an unparsed spec might have offered it sends the reader to the wrong place.
        let _ = std::fs::remove_file(dir.join("zz-good.yaml"));
        match resolve_device_ref(&root, "nvidia.com/gpu=0") {
            Err(DeviceRefError::Unreadable { path, .. }) => {
                assert!(path.ends_with("aa-junk.yaml"), "{path:?}");
            }
            other => panic!("expected the junk file to be named, got {other:?}"),
        }

        // A JSON SPEC IS NAMED AS JSON, and it wins over the generic answer because it is the more
        // specific one.
        let _ = std::fs::remove_file(dir.join("aa-junk.yaml"));
        let json = r#"{"cdiVersion":"0.5.0","kind":"nvidia.com/gpu","devices":[{"name":"0"}]}"#;
        let _ = std::fs::write(dir.join("nvidia.json"), json);
        match resolve_device_ref(&root, "nvidia.com/gpu=0") {
            Err(DeviceRefError::JsonSpec { path }) => {
                assert!(path.ends_with("nvidia.json"), "{path:?}");
            }
            other => panic!("a JSON spec must be named as JSON, got {other:?}"),
        }
        // And it does NOT shadow a YAML spec that works: the specific answer is only reached when
        // nothing matched.
        let _ = std::fs::write(dir.join("zz-good.yaml"), good);
        assert_eq!(
            resolve_device_ref(&root, "nvidia.com/gpu=0").map(|r| r.index),
            Ok(Some(0)),
            "a JSON file beside a working YAML spec must not disable it"
        );

        let _ = std::fs::remove_dir_all(&root);
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
    /// The name is a UUID the host's driver does not report for any card.
    UnknownUuid {
        /// The UUID that was asked for.
        uuid: String,
    },
    /// A spec file is JSON and this reader is YAML-only.
    ///
    /// `find_specs` accepts `.json` because the CDI specification does and `nvidia-ctk cdi
    /// generate --format=json` writes one, while the lexer here reads a line-based YAML subset.
    /// Measured: a JSON document, one-line or pretty-printed, answers `BadLine { line: 1 }`, so the
    /// failure is closed and the only thing missing was the DIAGNOSIS. "bad line 1" sends the
    /// reader to look for a typo in a file that is perfectly valid in the other format.
    JsonSpec {
        /// The file.
        path: PathBuf,
    },
    /// The spec names the device, and none of the device's paths is a real device node here.
    ///
    /// THE NESTING RULE, and it was a no-op: the call that computes this was `let _ = ...`. A spec
    /// describes the host it was generated on, and its paths are wrong inside a nested container
    /// unless that runtime regenerated it. Believing the NAME while every PATH is absent hands the
    /// box a reference to hardware that is not there.
    DescribesAnotherHost {
        /// The reference that was asked for.
        reference: String,
        /// The spec that named it.
        path: PathBuf,
    },
    /// A spec was found and could not be read.
    Unreadable {
        /// The file.
        path: PathBuf,
        /// Why.
        why: CdiError,
    },
}

/// Every `(GPU UUID, card minor)` the driver publishes, in no particular order.
///
/// ONE WALK, TWO CALLERS. [`minor_for_uuid`] asks it for one UUID and `--gpus device=<uuid>` asks
/// it for the whole list, so a message can name the UUIDs that DO exist when the one written does
/// not. Two walks would be two answers about a directory that can change between them.
///
/// The same file and the same fields `gpu_grant` uses for the PCI pairing, asked a second
/// question: `GPU UUID:` names the card and `Device Minor:` names its `/dev/nvidiaN`. Resolving a
/// UUID any other way would be a second source for a fact the driver already publishes.
pub(crate) fn uuid_minors(root: &Path) -> Vec<(String, u32)> {
    let gpus = root.join("proc/driver/nvidia/gpus");
    let Ok(entries) = std::fs::read_dir(gpus) else {
        return Vec::new();
    };
    let mut out: Vec<(String, u32)> = Vec::new();
    for entry in entries.flatten() {
        // BOUNDED AND TYPE-CHECKED. `read_to_string` here would block for ever on a FIFO planted
        // at the name, and this walk is reachable from plain `kern doctor`.
        let Ok(Some(text)) = crate::openat2::read_regular_path(
            &entry.path().join("information"),
            MAX_DRIVER_INFO_BYTES,
        ) else {
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
        if let (Some(u), Some(m)) = (found_uuid, found_minor) {
            out.push((u, m));
        }
    }
    out.sort();
    out
}

/// The card minor a GPU UUID belongs to.
fn minor_for_uuid(root: &Path, uuid: &str) -> Option<u32> {
    uuid_minors(root)
        .into_iter()
        .find(|(u, _)| u == uuid)
        .map(|(_, m)| m)
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
/// What `--device <kind>=<name>` resolved to, and what that spec asked for which kern does not do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDevice {
    /// The card index the name means, or `None` for the spec's `all`, which is every card.
    pub index: Option<u32>,
    /// The `KEY=VALUE` variables the spec puts in the container for this name: the document's
    /// common edits, then the device's own.
    pub env: Vec<String>,
    /// The hooks the spec attaches to this device, each `<hookName> <program>`.
    ///
    /// THEY TRAVEL WITH THE RESOLUTION instead of being fetched by a second walk of the spec
    /// directories, and that is not a convenience: `find_specs` walks a directory any process that
    /// can write it may fill, so a second read is a second measurement and can answer about a
    /// different file than the one that decided the index.
    pub hooks_not_run: Vec<String>,
}

/// `<hookName> <program>` for every hook in `edits`, which is what a reader needs to find it in the
/// spec and to recognise what it would have done.
fn hook_labels(edits: &ContainerEdits) -> Vec<String> {
    edits
        .hooks
        .iter()
        .map(|h| format!("{} {}", h.hook_name, h.path.display()))
        .collect()
}

/// The one sentence for hooks a spec names and kern does not run.
///
/// MEASURED, and the reason this exists: `nvidia-ctk` 1.18.2 attaches a `createContainer` hook to
/// every device in `/var/run/cdi/nvidia.yaml` on this host, running
/// `nvidia-cdi-hook create-symlinks`. kern bound the nodes, ran nothing, and said nothing, so a
/// reader comparing the node lists concluded `--device` was a faithful alias of the spec. The nodes
/// do match; the hook does not run, and a workload that resolves a card through
/// `/dev/dri/by-path/...` finds nothing there.
pub fn describe_hooks_not_run(reference: &str, hooks: &[String]) -> Option<String> {
    if hooks.is_empty() {
        return None;
    }
    Some(format!(
        "the CDI spec attaches {} hook(s) to {reference} and kern runs none: {}. A grant is a set \
         of binds and starts no program a spec names, so whatever those hooks would have created \
         is absent: a `create-symlinks` hook, for one, is what makes the /dev/dri/by-path entries.",
        hooks.len(),
        hooks.join(", ")
    ))
}

pub fn resolve_device_ref(root: &Path, reference: &str) -> Result<ResolvedDevice, DeviceRefError> {
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
    let mut kinds_found: Vec<String> = Vec::new();
    let mut offered: Vec<String> = Vec::new();
    let mut unreadable: Vec<(PathBuf, CdiError)> = Vec::new();
    let mut json_specs: Vec<PathBuf> = Vec::new();
    for path in find_specs(root, None) {
        // THE READ THAT HAD NO BOUND AND NO TYPE CHECK, and the one a hostile file reaches most
        // easily: `find_specs` walks a directory any process that can write it can fill. Measured
        // 2026-11-12 against the old call: a 2 GB file became 2 GB resident, and a FIFO named
        // `nvidia.yaml` hung plain `kern doctor` for ever.
        //
        // AN UNUSABLE FILE IS SKIPPED, NOT FATAL, which is the same answer the old code gave for an
        // unreadable one. One oversized or FIFO file in a spec directory must not disable `--device`
        // for every name on the host.
        let Ok(Some(text)) = crate::openat2::read_regular_path(&path, MAX_SPEC_BYTES) else {
            continue;
        };
        let spec = match parse_spec(&text) {
            Ok(s) => s,
            // SKIPPED AND REMEMBERED, NOT FATAL. This returned on the FIRST unparseable file, so a
            // single junk file in a directory any process that can write it may fill disabled
            // `--device` for every name on the host. The walk continues and the failures are
            // reported only if nothing matched, which keeps the diagnosis without the blast radius:
            // a spec that cannot be read is a reason the answer might be wrong, not an answer.
            Err(why) => {
                // THE JSON CASE GETS ITS OWN ANSWER, because `BadLine { line: 1 }` on a valid JSON
                // document is a true statement that teaches the reader nothing.
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    json_specs.push(path);
                } else {
                    unreadable.push((path, why));
                }
                continue;
            }
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
        // THE NESTING RULE, APPLIED. It was computed and discarded with `let _ = ...`, so the
        // documented rule did nothing and the only check that a spec's paths are real device nodes
        // under this root never ran. A spec describes the host it was generated on; inside a nested
        // container those paths are wrong unless that runtime regenerated it, and believing the
        // name while every path is absent hands the box a reference to hardware that is not there.
        //
        // EMPTY IS THE REFUSAL, not an error from the call: `nodes_for_device` answers `None` only
        // when the name is unknown, and the name was just found.
        let resolved = nodes_for_device(root, &spec, &device.name).unwrap_or_default();
        if resolved.is_empty() {
            return Err(DeviceRefError::DescribesAnotherHost {
                reference: trimmed.to_string(),
                path: path.clone(),
            });
        }

        // THE COMMON EDITS COUNT TOO: a spec may hang its hooks off the document rather than off
        // each device, and both reach a box that asks for this name. Sorted and deduplicated so a
        // hook written in both places is reported once.
        let mut hooks_not_run = hook_labels(&spec.common);
        hooks_not_run.extend(hook_labels(&device.edits));
        hooks_not_run.sort();
        hooks_not_run.dedup();
        let mut env = spec.common.env.clone();
        env.extend(device.edits.env.iter().cloned());
        // `all` IS A NAME THE SPEC OFFERS, resolved through the same checks as any other: the spec
        // must carry it and its nodes must be real here. MEASURED: docker and podman both run
        // `--device nvidia.com/gpu=all` from this host's spec (two cards), and on a WSL2 guest the
        // spec `nvidia-ctk` writes offers `all` and nothing else.
        if device.name == "all" {
            return Ok(ResolvedDevice {
                index: None,
                env,
                hooks_not_run,
            });
        }
        if let Ok(index) = device.name.parse::<u32>() {
            return Ok(ResolvedDevice {
                index: Some(index),
                env,
                hooks_not_run,
            });
        }
        if let Some(minor) = minor_for_uuid(root, &device.name) {
            return Ok(ResolvedDevice {
                index: Some(minor),
                env,
                hooks_not_run,
            });
        }
        return Err(DeviceRefError::UnknownUuid {
            uuid: device.name.clone(),
        });
    }

    // NOTHING MATCHED, SO THE FILES THAT COULD NOT BE READ ARE NOW THE ANSWER. Reporting
    // "no spec offers that kind" while a spec that might have offered it sat unparsed would send
    // the reader to the wrong place: they would check the name, not the file.
    if !json_specs.is_empty() {
        return Err(DeviceRefError::JsonSpec {
            path: json_specs.swap_remove(0),
        });
    }
    if !unreadable.is_empty() {
        let (path, why) = unreadable.swap_remove(0);
        return Err(DeviceRefError::Unreadable { path, why });
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

/// Several CDI names resolved together, as every `--device` on one command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDevices {
    /// The cards, in the order first named and without repeats; `None` when a name was `all`.
    pub indices: Option<Vec<u32>>,
    /// The variables of every name, in order.
    pub env: Vec<String>,
    /// The hooks of every name, sorted and once each.
    pub hooks_not_run: Vec<String>,
}

/// Resolve a comma-separated list of CDI names, the way the parser carries repeated `--device`.
///
/// ⛔ EVERY NAME COUNTS. MEASURED on this host: `--device nvidia.com/gpu=0 --device
/// nvidia.com/gpu=1` gave docker and podman both cards and gave kern ONE, the last, without a word,
/// because the parser kept a single value. A comma cannot appear in a CDI name (the specification's
/// grammar is letters, digits, `-`, `_`, `.` and `:`), so the list is unambiguous. The first name
/// that does not resolve fails the whole request, with that name, because a box that got some of
/// the cards it asked for cannot tell that from a card that failed later.
pub fn resolve_device_refs(
    root: &Path,
    list: &str,
) -> Result<ResolvedDevices, (String, DeviceRefError)> {
    let mut indices: Vec<u32> = Vec::new();
    let mut every = false;
    let mut env: Vec<String> = Vec::new();
    let mut hooks: Vec<String> = Vec::new();
    for reference in list.split(',').map(str::trim).filter(|r| !r.is_empty()) {
        let one = resolve_device_ref(root, reference).map_err(|e| (reference.to_string(), e))?;
        match one.index {
            None => every = true,
            Some(i) if !indices.contains(&i) => indices.push(i),
            Some(_) => {}
        }
        env.extend(one.env);
        hooks.extend(one.hooks_not_run);
    }
    hooks.sort();
    hooks.dedup();
    Ok(ResolvedDevices {
        indices: (!every).then_some(indices),
        env,
        hooks_not_run: hooks,
    })
}
