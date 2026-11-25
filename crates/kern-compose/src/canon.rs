//! `docker compose config`'s output: the project as Docker Compose prints it after loading it.
//!
//! # What this reproduces, and from what
//!
//! Docker Compose v5 loads a file with compose-go (v2.13.0 for Compose 5.3.1), normalises it, and
//! prints it with `go.yaml.in/yaml/v4` under `WithV3Defaults()` and `SetIndent(2)`. kern answered
//! `config` with a summary of its own, so a script that reads the resolved file (`config | yq`, a
//! CI step diffing it, `config --format json`) got prose instead. Every rule below was read from
//! those sources and checked against `docker compose config` on the same files: the field order of
//! each structure, how a short form is expanded, how a scalar is typed, and the emitter's choice of
//! quoting and line folding.
//!
//! Three layers, each a function of the one before:
//!
//! * [`Val`]: the file as YAML, after kern's own front end (interpolation, anchors, `extends:`,
//!   `!reset`), with each scalar remembering whether it was quoted, because compose-go types an
//!   unquoted `2024-01-02` as a timestamp and a quoted one as text.
//! * [`Out`]: the normalised project, typed as compose-go's structures type it.
//! * [`emit`]: the YAML text, byte for byte as the emitter writes it.

/// A YAML value as the file wrote it.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    /// An absent value (`key:` with nothing after it), or `null`/`~` written plain.
    Null,
    /// A scalar: its text, and whether it was quoted or a block scalar in the file. A plain scalar
    /// is typed by [`resolve`]; a quoted one is always a string.
    Scalar(String, bool),
    Seq(Vec<Val>),
    /// A mapping, in file order.
    Map(Vec<(String, Val)>),
}

impl Val {
    /// The entry `key` of a mapping.
    pub fn get(&self, key: &str) -> Option<&Val> {
        match self {
            Val::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The text of a scalar, whatever its type; `None` for a collection or null.
    pub fn text(&self) -> Option<&str> {
        match self {
            Val::Scalar(s, _) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Parse a flow collection or a scalar as kern's line parser hands it over: `[a, "b"]`,
    /// `{k: v}`, or a scalar with its quotes still on.
    pub fn from_flow(raw: &str) -> Val {
        let mut p = Flow {
            s: raw.trim().as_bytes(),
            i: 0,
        };
        let v = p.value(0);
        p.skip_ws();
        if p.i < p.s.len() {
            // Text after a complete flow value: not a flow collection after all (`[a] b`).
            return scalar_of(raw.trim());
        }
        v
    }
}

/// A scalar as written: quoted forms are decoded and marked as strings, a plain one keeps its text.
fn scalar_of(raw: &str) -> Val {
    let t = raw.trim();
    let b = t.as_bytes();
    if b.len() >= 2 && b.first() == Some(&b'"') && b.last() == Some(&b'"') {
        return Val::Scalar(decode_double(t.get(1..t.len() - 1).unwrap_or("")), true);
    }
    if b.len() >= 2 && b.first() == Some(&b'\'') && b.last() == Some(&b'\'') {
        return Val::Scalar(t.get(1..t.len() - 1).unwrap_or("").replace("''", "'"), true);
    }
    if matches!(t, "" | "~" | "null" | "Null" | "NULL") {
        return Val::Null;
    }
    Val::Scalar(t.to_string(), false)
}

/// The escapes a double-quoted YAML scalar takes. An unknown escape is kept as written.
fn decode_double(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some(' ') => out.push(' '),
            Some('e') => out.push('\u{1b}'),
            Some('a') => out.push('\u{7}'),
            Some('b') => out.push('\u{8}'),
            Some('v') => out.push('\u{b}'),
            Some('f') => out.push('\u{c}'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// A recursive-descent reader of YAML flow collections, bounded in depth.
struct Flow<'a> {
    s: &'a [u8],
    i: usize,
}

/// The deepest flow collection read. `prescreen` in `yaml.rs` refuses a deeper one BY NAME before
/// any parsing, so the cut below is never what a reader sees.
pub(crate) const FLOW_MAX_DEPTH: usize = 64;

impl Flow<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Val {
        self.skip_ws();
        if depth > FLOW_MAX_DEPTH {
            // CONSUME the rest: returning without moving `i` left the caller's item loop facing the
            // same `[` forever, pushing a Null each turn. MEASURED: `labels:` with 70 nested `[`
            // grew `kern compose config` past 4 GiB in 0.8 s and aborted.
            self.i = self.s.len();
            return Val::Null;
        }
        match self.peek() {
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_ws();
                    match self.peek() {
                        Some(b']') => {
                            self.i += 1;
                            break;
                        }
                        None => break,
                        Some(b',') => {
                            self.i += 1;
                        }
                        _ => items.push(self.value(depth + 1)),
                    }
                }
                Val::Seq(items)
            }
            Some(b'{') => {
                self.i += 1;
                let mut entries = Vec::new();
                loop {
                    self.skip_ws();
                    match self.peek() {
                        Some(b'}') => {
                            self.i += 1;
                            break;
                        }
                        None => break,
                        Some(b',') => {
                            self.i += 1;
                        }
                        _ => {
                            let key = match self.scalar_token(true) {
                                Val::Scalar(k, _) => k,
                                _ => String::new(),
                            };
                            self.skip_ws();
                            let v = if self.peek() == Some(b':') {
                                self.i += 1;
                                self.skip_ws();
                                if matches!(self.peek(), Some(b',' | b'}')) {
                                    Val::Null
                                } else {
                                    self.value(depth + 1)
                                }
                            } else {
                                Val::Null
                            };
                            entries.push((key, v));
                        }
                    }
                }
                Val::Map(entries)
            }
            _ => self.scalar_token(false),
        }
    }

    /// A scalar inside a flow collection: quoted, or plain up to `,` `]` `}` (and `: ` for a key).
    fn scalar_token(&mut self, is_key: bool) -> Val {
        self.skip_ws();
        let start = self.i;
        match self.peek() {
            Some(q @ (b'"' | b'\'')) => {
                self.i += 1;
                while let Some(c) = self.peek() {
                    self.i += 1;
                    if c == b'\\' && q == b'"' {
                        self.i += 1;
                        continue;
                    }
                    if c == q {
                        if q == b'\'' && self.peek() == Some(b'\'') {
                            self.i += 1;
                            continue;
                        }
                        break;
                    }
                }
                let raw =
                    std::str::from_utf8(self.s.get(start..self.i).unwrap_or(&[])).unwrap_or("");
                scalar_of(raw)
            }
            _ => {
                while let Some(c) = self.peek() {
                    if matches!(c, b',' | b']' | b'}') {
                        break;
                    }
                    if c == b':'
                        && (is_key
                            || matches!(
                                self.s.get(self.i + 1),
                                None | Some(b' ' | b',' | b']' | b'}')
                            ))
                    {
                        break;
                    }
                    self.i += 1;
                }
                let raw =
                    std::str::from_utf8(self.s.get(start..self.i).unwrap_or(&[])).unwrap_or("");
                scalar_of(raw)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Typing: what compose-go's loader makes of a plain scalar (go-yaml v4 `resolve`).
// ---------------------------------------------------------------------------------------------

/// The type a plain scalar resolves to, with the value where it matters for printing.
#[derive(Debug, Clone, PartialEq)]
pub enum Typed {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    /// A timestamp, already in Go's `time.Time.String()` form.
    Time(String),
    Str(String),
}

/// go-yaml v4's `resolve("", s)` for a plain scalar.
pub fn resolve(s: &str) -> Typed {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => return Typed::Null,
        "true" | "True" | "TRUE" => return Typed::Bool(true),
        "false" | "False" | "FALSE" => return Typed::Bool(false),
        ".nan" | ".NaN" | ".NAN" => return Typed::Float(f64::NAN),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => {
            return Typed::Float(f64::INFINITY)
        }
        "-.inf" | "-.Inf" | "-.INF" => return Typed::Float(f64::NEG_INFINITY),
        "-0" | "-0.0" => return Typed::Float(-0.0),
        _ => {}
    }
    let Some(&first) = s.as_bytes().first() else {
        return Typed::Null;
    };
    match first {
        b'.' => {
            if let Some(f) = go_parse_float(s) {
                return Typed::Float(f);
            }
        }
        b'0'..=b'9' | b'+' | b'-' => {
            if let Some(t) = parse_timestamp(s) {
                return Typed::Time(t);
            }
            let plain = s.replace('_', "");
            if let Some(i) = go_parse_int(&plain) {
                return Typed::Int(i);
            }
            if is_yaml_style_float(&plain) {
                if let Some(f) = go_parse_float(&plain) {
                    return Typed::Float(f);
                }
            }
        }
        _ => {}
    }
    Typed::Str(s.to_string())
}

/// `strconv.ParseInt(s, 0, 64)`: an optional sign, then decimal, `0x`, `0o`, `0b`, or a leading
/// `0` for octal.
fn go_parse_int(s: &str) -> Option<i64> {
    let (neg, body) = match s.as_bytes().first() {
        Some(b'-') => (true, s.get(1..)?),
        Some(b'+') => (false, s.get(1..)?),
        _ => (false, s),
    };
    if body.is_empty() {
        return None;
    }
    let (radix, digits) =
        if let Some(r) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
            (16, r)
        } else if let Some(r) = body.strip_prefix("0o").or_else(|| body.strip_prefix("0O")) {
            (8, r)
        } else if let Some(r) = body.strip_prefix("0b").or_else(|| body.strip_prefix("0B")) {
            (2, r)
        } else if body.len() > 1 && body.starts_with('0') {
            (8, body.get(1..)?)
        } else {
            (10, body)
        };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let mag = i128::from_str_radix(digits, radix).ok()?;
    let v = if neg { -mag } else { mag };
    i64::try_from(v).ok()
}

/// `^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?$`
fn is_yaml_style_float(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if matches!(b.first(), Some(b'+' | b'-')) {
        i += 1;
    }
    let digits = |i: &mut usize| -> usize {
        let start = *i;
        while matches!(b.get(*i), Some(b'0'..=b'9')) {
            *i += 1;
        }
        *i - start
    };
    if b.get(i) == Some(&b'.') {
        i += 1;
        if digits(&mut i) == 0 {
            return false;
        }
    } else {
        if digits(&mut i) == 0 {
            return false;
        }
        if b.get(i) == Some(&b'.') {
            i += 1;
            digits(&mut i);
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return false;
        }
    }
    i == b.len()
}

/// `strconv.ParseFloat(s, 64)` for the forms a YAML file holds: decimal with an exponent, `inf`,
/// `nan`. Hex floats are not a YAML form and fall back to `None`.
fn go_parse_float(s: &str) -> Option<f64> {
    if s.contains('_') {
        return None;
    }
    let l = s.to_ascii_lowercase();
    match l.trim_start_matches(['+', '-']) {
        "inf" | "infinity" => {
            return Some(if l.starts_with('-') {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            })
        }
        "nan" => return Some(f64::NAN),
        _ => {}
    }
    if !s
        .bytes()
        .all(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        return None;
    }
    s.parse::<f64>().ok()
}

/// go-yaml's timestamp forms (`2006-1-2`, with `T`/`t`/space and a time, `Z` or an offset), as
/// `time.Time.String()` prints them: `2006-01-02 15:04:05.999999999 -0700 MST`, where a UTC time is
/// `+0000 UTC` and an offset without a zone name repeats the offset.
fn parse_timestamp(s: &str) -> Option<String> {
    // Date part: YYYY-M-D.
    let b = s.as_bytes();
    let num = |from: usize, min: usize, max: usize| -> Option<(u32, usize)> {
        let mut i = from;
        while i < b.len() && i - from < max && b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i - from < min {
            return None;
        }
        Some((s.get(from..i)?.parse().ok()?, i))
    };
    let (year, i) = num(0, 4, 4)?;
    if b.get(i) != Some(&b'-') {
        return None;
    }
    let (month, i) = num(i + 1, 1, 2)?;
    if b.get(i) != Some(&b'-') {
        return None;
    }
    let (day, i) = num(i + 1, 1, 2)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let date = format!("{year:04}-{month:02}-{day:02}");
    if i == b.len() {
        return Some(format!("{date} 00:00:00 +0000 UTC"));
    }
    let sep = *b.get(i)?;
    if !matches!(sep, b'T' | b't' | b' ') {
        return None;
    }
    let (hh, i) = num(i + 1, 1, 2)?;
    if b.get(i) != Some(&b':') {
        return None;
    }
    let (mm, i) = num(i + 1, 1, 2)?;
    if b.get(i) != Some(&b':') {
        return None;
    }
    let (ss, mut i) = num(i + 1, 1, 2)?;
    if hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let mut frac = String::new();
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        frac = s.get(start..i)?.trim_end_matches('0').to_string();
        if i == start {
            return None;
        }
    }
    let time = if frac.is_empty() {
        format!("{hh:02}:{mm:02}:{ss:02}")
    } else {
        format!("{hh:02}:{mm:02}:{ss:02}.{frac}")
    };
    let rest = s.get(i..)?;
    // go-yaml's three layouts: a space-separated time takes no zone, a `T`-separated one requires
    // `Z` or `±hh:mm` (Go's `Z07:00`). Anything else is a string.
    let zone = match (sep, rest) {
        (b' ', "") => "+0000 UTC".to_string(),
        (b' ', _) => return None,
        (_, "Z") => "+0000 UTC".to_string(),
        (_, r) => {
            let (sign, body) = match r.as_bytes().first() {
                Some(b'+') => ('+', r.get(1..)?),
                Some(b'-') => ('-', r.get(1..)?),
                _ => return None,
            };
            let (h, m) = body.split_once(':')?;
            if h.len() != 2
                || m.len() != 2
                || !h.bytes().chain(m.bytes()).all(|c| c.is_ascii_digit())
            {
                return None;
            }
            let off = format!("{sign}{h}{m}");
            format!("{off} {off}")
        }
    };
    Some(format!("{date} {time} {zone}"))
}

/// `strconv.FormatFloat(f, 'g', -1, bits)`, which both the YAML representer and Go's `%v` print:
/// the shortest digits that read back as the same value, in `%e` form when the decimal exponent is
/// below -4 or at least 6 (Go's rule for the shortest precision), `%f` otherwise. `bits` is 32 for a
/// `float32` field (compose-go's `cpus`), so `0.1` stays `0.1`.
pub fn go_format_float(f: f64, bits: u32) -> String {
    if f.is_nan() {
        return "NaN".to_string();
    }
    if f.is_infinite() {
        return if f > 0.0 { "+Inf" } else { "-Inf" }.to_string();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0" } else { "0" }.to_string();
    }
    // Rust's `{:e}` prints the shortest round-trip digits of the value at its own width.
    let sci = if bits == 32 {
        format!("{:e}", f as f32)
    } else {
        format!("{f:e}")
    };
    let (mant, exp) = match sci.split_once('e') {
        Some((m, e)) => (m.to_string(), e.parse::<i32>().unwrap_or(0)),
        None => (sci.clone(), 0),
    };
    let sign = if mant.starts_with('-') { "-" } else { "" };
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    if !(-4..6).contains(&exp) {
        let (h, t) = digits.split_at(1.min(digits.len()));
        let m = if t.is_empty() {
            h.to_string()
        } else {
            format!("{h}.{t}")
        };
        let es = if exp < 0 { '-' } else { '+' };
        return format!("{sign}{m}e{es}{:02}", exp.abs());
    }
    if exp < 0 {
        let zeros = "0".repeat(usize::try_from(-exp - 1).unwrap_or(0));
        return format!("{sign}0.{zeros}{digits}");
    }
    let int_len = usize::try_from(exp + 1).unwrap_or(1);
    if digits.len() <= int_len {
        let pad = "0".repeat(int_len - digits.len());
        format!("{sign}{digits}{pad}")
    } else {
        let (a, b) = digits.split_at(int_len);
        format!("{sign}{a}.{b}")
    }
}

/// `fmt.Sprint` of a typed scalar, which is how compose-go turns a non-string value in a string map
/// (`environment`, `labels`, `build.args`) into its text: `1` is `"1"`, an unquoted date is its
/// `time.Time`, `true` is `"true"`, null stays null.
pub fn go_sprint(t: &Typed) -> Option<String> {
    match t {
        Typed::Null => None,
        Typed::Bool(b) => Some(b.to_string()),
        Typed::Int(i) => Some(i.to_string()),
        Typed::Float(f) => Some(go_format_float(*f, 64)),
        Typed::Time(s) | Typed::Str(s) => Some(s.clone()),
    }
}

// ---------------------------------------------------------------------------------------------
// The typed output tree, and the emitter.
// ---------------------------------------------------------------------------------------------

/// A value as compose-go's structures hold it, ready for the emitter.
#[derive(Debug, Clone, PartialEq)]
pub enum Out {
    Null,
    Bool(bool),
    /// An integer field (`retries`, `target`, `cpu_shares`).
    Int(i64),
    /// A float field, already formatted (`cpus: 1.5`).
    Float(String),
    /// A string field. How it is quoted is the emitter's business (see [`scalar_style`]).
    Str(String),
    Seq(Vec<Out>),
    /// A mapping, in the order it is printed: a structure's field order, or sorted for a Go map.
    Map(Vec<(String, Out)>),
}

impl Out {
    pub fn str(s: impl Into<String>) -> Out {
        Out::Str(s.into())
    }

    fn is_empty_collection(&self) -> bool {
        matches!(self, Out::Seq(v) if v.is_empty()) || matches!(self, Out::Map(m) if m.is_empty())
    }
}

/// A Go `map[string]...`: keys sorted, as the YAML representer sorts them.
pub fn go_map(mut entries: Vec<(String, Out)>) -> Out {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Out::Map(entries)
}

/// How the emitter writes a scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Plain,
    Single,
    Double,
    Literal,
}

/// What the emitter's `analyzeScalar` learns about a value.
struct Analysis {
    multiline: bool,
    block_plain_allowed: bool,
    single_quoted_allowed: bool,
    block_allowed: bool,
}

/// libyaml's `is_printable`, which is narrower than YAML's: a tab, a CR, U+0085 and every character
/// above U+FFFF are NOT printable to the emitter, so a double-quoted scalar escapes them.
fn is_printable(c: char) -> bool {
    c == '\n'
        || ('\u{20}'..='\u{7E}').contains(&c)
        || ('\u{A0}'..='\u{D7FF}').contains(&c)
        || (('\u{E000}'..='\u{FFFD}').contains(&c) && c != '\u{FEFF}')
}

fn is_line_break(c: char) -> bool {
    matches!(c, '\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// The emitter's `analyzeScalar`, for block context (the only one a compose file is printed in).
fn analyze(value: &str) -> Analysis {
    if value.is_empty() {
        return Analysis {
            multiline: false,
            block_plain_allowed: true,
            single_quoted_allowed: true,
            block_allowed: false,
        };
    }
    let chars: Vec<char> = value.chars().collect();
    let mut block_indicators = value.starts_with("---") || value.starts_with("...");
    let (mut line_breaks, mut special, mut tabs) = (false, false, false);
    let (mut leading_space, mut leading_break, mut trailing_space, mut trailing_break) =
        (false, false, false, false);
    let (mut break_space, mut space_break) = (false, false);
    let (mut prev_space, mut prev_break) = (false, false);
    let mut preceded_by_ws = true;
    let n = chars.len();
    for (i, &c) in chars.iter().enumerate() {
        let followed_by_ws = chars
            .get(i + 1)
            .is_none_or(|&d| d == ' ' || d == '\t' || is_line_break(d));
        if i == 0 {
            match c {
                '#' | ',' | '[' | ']' | '{' | '}' | '&' | '*' | '!' | '|' | '>' | '\'' | '"'
                | '%' | '@' | '`' => block_indicators = true,
                '?' | ':' | '-' if followed_by_ws => block_indicators = true,
                _ => {}
            }
        } else {
            match c {
                ':' if followed_by_ws => block_indicators = true,
                '#' if preceded_by_ws => block_indicators = true,
                _ => {}
            }
        }
        if c == '\t' {
            tabs = true;
        } else if !is_printable(c) {
            special = true;
        }
        if c == ' ' {
            if i == 0 {
                leading_space = true;
            }
            if i + 1 == n {
                trailing_space = true;
            }
            if prev_break {
                break_space = true;
            }
            prev_space = true;
            prev_break = false;
        } else if is_line_break(c) {
            line_breaks = true;
            if i == 0 {
                leading_break = true;
            }
            if i + 1 == n {
                trailing_break = true;
            }
            if prev_space {
                space_break = true;
            }
            prev_space = false;
            prev_break = true;
        } else {
            prev_space = false;
            prev_break = false;
        }
        preceded_by_ws = c == ' ' || c == '\t' || is_line_break(c);
    }
    let mut a = Analysis {
        multiline: line_breaks,
        block_plain_allowed: true,
        single_quoted_allowed: true,
        block_allowed: true,
    };
    if leading_space || leading_break || trailing_space || trailing_break {
        a.block_plain_allowed = false;
    }
    if trailing_space {
        a.block_allowed = false;
    }
    if break_space {
        a.block_plain_allowed = false;
        a.single_quoted_allowed = false;
    }
    if space_break || tabs || special {
        a.block_plain_allowed = false;
        a.single_quoted_allowed = false;
    }
    if space_break || special {
        a.block_allowed = false;
    }
    if line_breaks {
        a.block_plain_allowed = false;
    }
    if block_indicators {
        a.block_plain_allowed = false;
    }
    a
}

/// `^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?$`
fn is_base60_float(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if matches!(b.first(), Some(b'+' | b'-')) {
        i += 1;
    }
    if !b.get(i).is_some_and(u8::is_ascii_digit) {
        return false;
    }
    while b.get(i).is_some_and(|c| c.is_ascii_digit() || *c == b'_') {
        i += 1;
    }
    let mut groups = 0;
    while b.get(i) == Some(&b':') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) && i - start < 2 {
            i += 1;
        }
        let g = s.get(start..i).unwrap_or("");
        let ok = match g.len() {
            1 => true,
            2 => g
                .as_bytes()
                .first()
                .is_some_and(|d| (b'0'..=b'5').contains(d)),
            _ => false,
        };
        if !ok {
            return false;
        }
        groups += 1;
    }
    if groups == 0 {
        return false;
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(|c| c.is_ascii_digit() || *c == b'_') {
            i += 1;
        }
    }
    i == b.len()
}

fn is_old_bool(s: &str) -> bool {
    matches!(
        s,
        "y" | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "on"
            | "On"
            | "ON"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "off"
            | "Off"
            | "OFF"
    )
}

/// The style a string is written in: the representer's choice, then the desolver's, then the
/// emitter's `selectScalarStyle`. `simple_key` is a mapping key.
fn scalar_style(s: &str, simple_key: bool) -> Style {
    let a = analyze(s);
    // Representer.
    let mut style = if s.contains('\n') {
        let literal_ok = s.len() >= 2 && s.chars().any(|c| !c.is_whitespace());
        if literal_ok {
            Style::Literal
        } else {
            Style::Double
        }
    } else if is_base60_float(s) || is_old_bool(s) || s == "<<" {
        Style::Single
    } else {
        Style::Plain
    };
    // Desolver: a plain string that would read back as another type is quoted, in the quote
    // preference (`QuoteLegacy` is double).
    if style == Style::Plain && !matches!(resolve(s), Typed::Str(_)) {
        style = Style::Double;
    }
    // Emitter.
    if simple_key && a.multiline {
        style = Style::Double;
    }
    if style == Style::Plain && (!a.block_plain_allowed || (s.is_empty() && simple_key)) {
        style = Style::Single;
    }
    if style == Style::Single && !a.single_quoted_allowed {
        style = Style::Double;
    }
    if style == Style::Literal && (!a.block_allowed || simple_key) {
        style = Style::Double;
    }
    style
}

/// The emitter: block mappings and sequences at 2-space indentation, sequences indented under
/// their key (`WithCompactSeqIndent(false)`), empty collections in flow form, scalars folded at
/// column 80.
struct Emitter {
    out: String,
    column: usize,
    whitespace: bool,
    indention: bool,
}

const BEST_WIDTH: usize = 80;

impl Emitter {
    fn put(&mut self, c: char) {
        self.out.push(c);
        if c == '\n' {
            self.column = 0;
        } else {
            self.column += 1;
        }
    }

    fn put_str(&mut self, s: &str) {
        for c in s.chars() {
            self.put(c);
        }
    }

    fn line_break(&mut self) {
        self.put('\n');
        self.whitespace = true;
        self.indention = true;
    }

    fn write_indent(&mut self, indent: usize) {
        if !self.indention || self.column > indent || (self.column == indent && !self.whitespace) {
            self.line_break();
        }
        while self.column < indent {
            self.put(' ');
        }
        self.whitespace = true;
    }

    fn indicator(&mut self, ind: &str, need_ws: bool, is_ws: bool, is_indention: bool) {
        if need_ws && !self.whitespace {
            self.put(' ');
        }
        self.put_str(ind);
        self.whitespace = is_ws;
        self.indention = self.indention && is_indention;
    }

    /// A scalar at `indent` (the indentation its continuation lines take).
    fn scalar(&mut self, s: &str, indent: usize, simple_key: bool) {
        match scalar_style(s, simple_key) {
            Style::Plain => self.plain(s, indent, !simple_key),
            Style::Single => self.single(s, indent, !simple_key),
            Style::Double => self.double(s, indent, !simple_key),
            Style::Literal => self.literal(s, indent),
        }
    }

    /// A scalar the representer writes plain whatever it holds (a number, a bool, null).
    fn plain_token(&mut self, s: &str) {
        if !self.whitespace {
            self.put(' ');
        }
        self.put_str(s);
        self.whitespace = false;
        self.indention = false;
    }

    fn plain(&mut self, s: &str, indent: usize, allow_breaks: bool) {
        if !s.is_empty() && !self.whitespace {
            self.put(' ');
        }
        let chars: Vec<char> = s.chars().collect();
        let mut spaces = false;
        let mut breaks = false;
        let mut i = 0;
        while let Some(&c) = chars.get(i) {
            if c == ' ' {
                if allow_breaks
                    && !spaces
                    && self.column > BEST_WIDTH
                    && chars.get(i + 1) != Some(&' ')
                {
                    self.write_indent(indent);
                } else {
                    self.put(' ');
                }
                spaces = true;
            } else if is_line_break(c) {
                if !breaks && c == '\n' {
                    self.line_break();
                }
                self.line_break();
                breaks = true;
            } else {
                if breaks {
                    self.write_indent(indent);
                }
                self.put(c);
                self.indention = false;
                spaces = false;
                breaks = false;
            }
            i += 1;
        }
        if !s.is_empty() {
            self.whitespace = false;
        }
        self.indention = false;
    }

    fn single(&mut self, s: &str, indent: usize, allow_breaks: bool) {
        self.indicator("'", true, false, false);
        let chars: Vec<char> = s.chars().collect();
        let n = chars.len();
        let mut spaces = false;
        let mut breaks = false;
        for (i, &c) in chars.iter().enumerate() {
            if c == ' ' {
                if allow_breaks
                    && !spaces
                    && self.column > BEST_WIDTH
                    && i > 0
                    && i + 1 < n
                    && chars.get(i + 1) != Some(&' ')
                {
                    self.write_indent(indent);
                } else {
                    self.put(' ');
                }
                spaces = true;
            } else if is_line_break(c) {
                if !breaks && c == '\n' {
                    self.line_break();
                }
                self.line_break();
                breaks = true;
            } else {
                if breaks {
                    self.write_indent(indent);
                }
                if c == '\'' {
                    self.put('\'');
                }
                self.put(c);
                self.indention = false;
                spaces = false;
                breaks = false;
            }
        }
        self.indicator("'", false, false, false);
        self.whitespace = false;
        self.indention = false;
    }

    fn double(&mut self, s: &str, indent: usize, allow_breaks: bool) {
        self.indicator("\"", true, false, false);
        let chars: Vec<char> = s.chars().collect();
        let n = chars.len();
        let mut spaces = false;
        for (i, &c) in chars.iter().enumerate() {
            if !is_printable(c) || c == '\u{FEFF}' || is_line_break(c) || c == '"' || c == '\\' {
                self.put('\\');
                match c {
                    '\0' => self.put('0'),
                    '\u{7}' => self.put('a'),
                    '\u{8}' => self.put('b'),
                    '\t' => self.put('t'),
                    '\n' => self.put('n'),
                    '\u{b}' => self.put('v'),
                    '\u{c}' => self.put('f'),
                    '\r' => self.put('r'),
                    '\u{1b}' => self.put('e'),
                    '"' => self.put('"'),
                    '\\' => self.put('\\'),
                    '\u{85}' => self.put('N'),
                    '\u{A0}' => self.put('_'),
                    '\u{2028}' => self.put('L'),
                    '\u{2029}' => self.put('P'),
                    other => {
                        let v = other as u32;
                        if v <= 0xFF {
                            self.put_str(&format!("x{v:02X}"));
                        } else if v <= 0xFFFF {
                            self.put_str(&format!("u{v:04X}"));
                        } else {
                            self.put_str(&format!("U{v:08X}"));
                        }
                    }
                }
                spaces = false;
            } else if c == ' ' {
                if allow_breaks && !spaces && self.column > BEST_WIDTH && i > 0 && i + 1 < n {
                    self.write_indent(indent);
                    if chars.get(i + 1) == Some(&' ') {
                        self.put('\\');
                    }
                } else {
                    self.put(' ');
                }
                spaces = true;
            } else {
                self.put(c);
                spaces = false;
            }
        }
        self.indicator("\"", false, false, false);
        self.whitespace = false;
        self.indention = false;
    }

    fn literal(&mut self, s: &str, indent: usize) {
        self.indicator("|", true, false, false);
        if s.starts_with(' ') {
            self.indicator("2", false, false, false);
        }
        let mut rev = s.chars().rev();
        let last = rev.next();
        let before = rev.next();
        let chomp = match (last, before) {
            (None, _) => Some("-"),
            (Some(l), _) if !is_line_break(l) => Some("-"),
            (Some(_), None) => Some("+"),
            (Some(_), Some(b)) if is_line_break(b) => Some("+"),
            _ => None,
        };
        if let Some(h) = chomp {
            self.indicator(h, false, false, false);
        }
        self.line_break();
        self.whitespace = true;
        let mut breaks = true;
        for c in s.chars() {
            if is_line_break(c) {
                self.line_break();
                breaks = true;
            } else {
                if breaks {
                    self.write_indent(indent);
                }
                self.put(c);
                self.indention = false;
                breaks = false;
            }
        }
    }

    /// A node as a mapping value or a sequence item. `indent` is the enclosing collection's.
    fn node(&mut self, v: &Out, indent: usize, in_seq_item: bool) {
        // A scalar's continuation indentation: the next multiple of 2 above `indent`, or `indent + 2`
        // inside a sequence item (`increaseIndent`).
        let scalar_indent = if in_seq_item {
            indent + 2
        } else {
            2 * ((indent + 2) / 2)
        };
        match v {
            Out::Null => self.plain_token("null"),
            Out::Bool(b) => self.plain_token(if *b { "true" } else { "false" }),
            Out::Int(i) => self.plain_token(&i.to_string()),
            Out::Float(f) => self.plain_token(f),
            Out::Str(s) => self.scalar(s, scalar_indent, false),
            Out::Seq(items) if items.is_empty() => self.indicator("[]", true, false, false),
            Out::Map(m) if m.is_empty() => self.indicator("{}", true, false, false),
            Out::Seq(items) => {
                let ind = if in_seq_item {
                    indent + 2
                } else {
                    2 * ((indent + 2) / 2)
                };
                for item in items {
                    self.write_indent(ind);
                    self.indicator("-", true, false, true);
                    self.node(item, ind, true);
                }
            }
            Out::Map(entries) => {
                let ind = if in_seq_item {
                    indent + 2
                } else {
                    2 * ((indent + 2) / 2)
                };
                self.map_body(entries, ind);
            }
        }
    }

    fn map_body(&mut self, entries: &[(String, Out)], ind: usize) {
        for (k, val) in entries {
            self.write_indent(ind);
            self.scalar(k, ind, true);
            self.indicator(":", false, false, false);
            self.node_after_key(val, ind);
        }
    }

    fn node_after_key(&mut self, v: &Out, ind: usize) {
        match v {
            Out::Seq(items) if !items.is_empty() => self.node(v, ind, false),
            Out::Map(m) if !m.is_empty() => self.node(v, ind, false),
            _ => self.node(v, ind, false),
        }
    }
}

/// The YAML text of `root` (a mapping), as the encoder writes a document.
pub fn emit(root: &Out) -> String {
    let mut e = Emitter {
        out: String::new(),
        column: 0,
        whitespace: true,
        indention: true,
    };
    match root {
        Out::Map(entries) if !entries.is_empty() => e.map_body(entries, 0),
        other if other.is_empty_collection() => e.node(other, 0, false),
        other => e.node(other, 0, false),
    }
    if !e.out.ends_with('\n') {
        e.out.push('\n');
    }
    e.out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Out {
        Out::str(v)
    }

    /// THE SCALAR STYLES DOCKER PRINTED, one per rule. Measured with `docker compose config` on
    /// Compose 5.3.1 (an `environment:` of quoted values, keys sorted as Go sorts a map).
    #[test]
    fn scalars_are_quoted_and_folded_as_docker_prints_them() {
        let env = go_map(vec![
            ("BOOL".into(), s("true")),
            ("COLON".into(), s("a: b")),
            ("DASH".into(), s("-x")),
            ("FLOAT".into(), s("1.5")),
            ("HASH".into(), s("a #b")),
            ("HEX".into(), s("0x1F")),
            ("LEAD".into(), s(" leading")),
            (
                "LONG".into(),
                s("a very long value that will certainly exceed the eighty column limit of the emitter for sure yes"),
            ),
            ("MULTI".into(), s("line one\nline two\n")),
            ("NULLS".into(), s("null")),
            ("NUM".into(), s("0755")),
            ("QMARK".into(), s("?x")),
            ("STAR".into(), s("*star")),
            ("TAB".into(), s("a\tb")),
            ("TILDE".into(), s("~")),
            ("UNICODE".into(), s("café")),
            ("Y".into(), s("yes")),
        ]);
        let doc = Out::Map(vec![(
            "services".into(),
            Out::Map(vec![(
                "a".into(),
                Out::Map(vec![("environment".into(), env)]),
            )]),
        )]);
        let want = "services:
  a:
    environment:
      BOOL: \"true\"
      COLON: 'a: b'
      DASH: -x
      FLOAT: \"1.5\"
      HASH: 'a #b'
      HEX: \"0x1F\"
      LEAD: ' leading'
      LONG: a very long value that will certainly exceed the eighty column limit of
        the emitter for sure yes
      MULTI: |
        line one
        line two
      NULLS: \"null\"
      NUM: \"0755\"
      QMARK: ?x
      STAR: '*star'
      TAB: \"a\\tb\"
      TILDE: \"~\"
      UNICODE: café
      'Y': 'yes'
";
        assert_eq!(emit(&doc), want);
    }

    /// SEQUENCES INDENT UNDER THEIR KEY, a mapping item starts on the dash's line, empty
    /// collections are flow, numbers and null are plain. From Docker's output for a port, a
    /// volume and a network.
    #[test]
    fn collections_are_laid_out_as_docker_prints_them() {
        let doc = Out::Map(vec![(
            "web".into(),
            Out::Map(vec![
                (
                    "ports".into(),
                    Out::Seq(vec![Out::Map(vec![
                        ("mode".into(), s("ingress")),
                        ("target".into(), Out::Int(80)),
                        ("published".into(), s("8080")),
                    ])]),
                ),
                (
                    "volumes".into(),
                    Out::Seq(vec![Out::Map(vec![
                        ("type".into(), s("volume")),
                        ("volume".into(), Out::Map(vec![])),
                    ])]),
                ),
                (
                    "networks".into(),
                    go_map(vec![("default".into(), Out::Null)]),
                ),
                ("command".into(), Out::Seq(vec![])),
                ("cpus".into(), Out::Float("1.5".into())),
            ]),
        )]);
        let want = "web:
  ports:
    - mode: ingress
      target: 80
      published: \"8080\"
  volumes:
    - type: volume
      volume: {}
  networks:
    default: null
  command: []
  cpus: 1.5
";
        assert_eq!(emit(&doc), want);
    }

    #[test]
    fn plain_scalars_type_as_go_yaml_types_them() {
        assert_eq!(resolve("1"), Typed::Int(1));
        assert_eq!(resolve("0755"), Typed::Int(493));
        assert_eq!(resolve("0x1F"), Typed::Int(31));
        assert_eq!(resolve("1.5"), Typed::Float(1.5));
        assert_eq!(resolve("yes"), Typed::Str("yes".into()));
        assert_eq!(resolve("true"), Typed::Bool(true));
        assert_eq!(resolve("~"), Typed::Null);
        assert_eq!(
            resolve("2024-01-02"),
            Typed::Time("2024-01-02 00:00:00 +0000 UTC".into())
        );
        assert_eq!(resolve("1000:1000"), Typed::Str("1000:1000".into()));
        assert!(!is_base60_float("1000:1000"));
        assert!(is_base60_float("1:20"));
        assert_eq!(go_format_float(0.5, 32), "0.5");
        assert_eq!(go_format_float(1.5, 64), "1.5");
        assert_eq!(go_format_float(2.0, 32), "2");
        assert_eq!(go_format_float(1_000_000.0, 64), "1e+06");
        assert_eq!(go_format_float(123_456.0, 64), "123456");
        assert_eq!(go_format_float(0.0001, 64), "0.0001");
        assert_eq!(go_format_float(0.00001, 64), "1e-05");
    }

    #[test]
    fn flow_collections_read_back() {
        assert_eq!(
            Val::from_flow(r#"["CMD", "true"]"#),
            Val::Seq(vec![
                Val::Scalar("CMD".into(), true),
                Val::Scalar("true".into(), true)
            ])
        );
        assert_eq!(
            Val::from_flow("{driver: nvidia, count: 1, capabilities: [gpu]}"),
            Val::Map(vec![
                ("driver".into(), Val::Scalar("nvidia".into(), false)),
                ("count".into(), Val::Scalar("1".into(), false)),
                (
                    "capabilities".into(),
                    Val::Seq(vec![Val::Scalar("gpu".into(), false)])
                ),
            ])
        );
        assert_eq!(
            Val::from_flow("http://x:8080/y"),
            Val::Scalar("http://x:8080/y".into(), false)
        );
    }

    /// Past the depth the reader stops and CONSUMES the input: the item loop used to face the same
    /// `[` forever and push a Null each turn, until the allocator gave up.
    #[test]
    fn a_flow_value_past_the_depth_ends() {
        let n = FLOW_MAX_DEPTH + 10;
        let raw = "[".repeat(n) + &"]".repeat(n);
        let mut v = Val::from_flow(&raw);
        let mut levels = 0;
        while let Val::Seq(mut items) = v {
            assert!(items.len() <= 1, "level {levels} has {} items", items.len());
            levels += 1;
            v = items.pop().unwrap_or(Val::Null);
        }
        assert!(levels <= FLOW_MAX_DEPTH + 1, "{levels}");
    }
}

// ---------------------------------------------------------------------------------------------
// The project: compose-go's normalisation, field by field.
// ---------------------------------------------------------------------------------------------

/// Looks a variable up in the environment.
pub type EnvLookup = dyn Fn(&str) -> Option<String>;

/// Reads an `env_file:` as `(key, value)` pairs in file order; `Err` names the file.
pub type EnvFileReader = dyn Fn(&std::path::Path) -> Result<Vec<(String, Option<String>)>, String>;

/// What [`project`] needs besides the files.
pub struct ProjectInput<'a> {
    /// The project name the run uses.
    pub name: &'a str,
    /// The project directory, absolute: relative paths resolve against it.
    pub dir: &'a std::path::Path,
    /// The active profiles (`COMPOSE_PROFILES`/`--profile`); `*` activates every one.
    pub profiles: &'a [String],
    /// Looks a variable up in the environment, for an `environment:` entry written without a value.
    pub env: &'a EnvLookup,
    /// Reads an `env_file:`, as `(key, value)` pairs in file order; `Err` names the file.
    pub env_file: &'a EnvFileReader,
    /// `--format json`: the fields compose-go's JSON tags do not omit when empty are kept
    /// (`command`/`entrypoint` null, a network's `ipam`, `deploy`'s `resources`/`placement`), and
    /// the top level is a sorted map, as `Project.MarshalJSON` builds it.
    pub json: bool,
    /// Leave out the networks, volumes, secrets and configs no service uses, as every view but
    /// `--no-interpolate` does (that one prints the model before compose-go trims it).
    pub prune: bool,
}

/// The project Docker Compose prints for `config`, from the file trees in `-f` order (each already
/// through kern's front end).
///
/// # Errors
///
/// An `env_file:` that cannot be read, as `config` refuses one.
pub fn project(files: &[Val], inp: &ProjectInput) -> Result<Out, String> {
    let merged = files
        .iter()
        .cloned()
        .reduce(merge_top)
        .unwrap_or(Val::Map(Vec::new()));
    let services_in = match merged.get("services") {
        Some(Val::Map(m)) => m.clone(),
        _ => Vec::new(),
    };
    // Profiles: a service with profiles runs only when one of them is active.
    let all = inp.profiles.iter().any(|p| p == "*");
    let active = |svc: &Val| -> bool {
        let ps = strings_of(svc.get("profiles"));
        ps.is_empty() || all || ps.iter().any(|p| inp.profiles.contains(p))
    };
    let mut services: Vec<(String, Out)> = Vec::new();
    let mut uses_default_network = false;
    for (name, svc) in &services_in {
        if !active(svc) {
            continue;
        }
        let (out, default_net) = service(name, svc, &services_in, inp)?;
        uses_default_network |= default_net;
        services.push((name.clone(), out));
    }
    // ONLY WHAT A SERVICE USES, as `WithoutUnnecessaryResources` keeps it: a network, a volume, a
    // secret or a config no active service names is not printed. MEASURED: a declared `n1` that
    // no service joins was absent from Docker's output and printed by kern.
    let mut used_nets: Vec<String> = Vec::new();
    let mut used_vols: Vec<String> = Vec::new();
    let mut used_secrets: Vec<String> = Vec::new();
    let mut used_configs: Vec<String> = Vec::new();
    for (_, svc) in &services {
        if let Some(Out::Map(n)) = out_get(svc, "networks") {
            used_nets.extend(n.iter().map(|(k, _)| k.clone()));
        }
        if let Some(Out::Seq(vols)) = out_get(svc, "volumes") {
            for v in vols {
                if let (Some(Out::Str(t)), Some(Out::Str(src))) =
                    (out_get(v, "type"), out_get(v, "source"))
                {
                    if t == "volume" {
                        used_vols.push(src.clone());
                    }
                }
            }
        }
        let sources = |o: Option<&Out>| -> Vec<String> {
            match o {
                Some(Out::Seq(refs)) => refs
                    .iter()
                    .filter_map(|r| match out_get(r, "source") {
                        Some(Out::Str(s)) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            }
        };
        used_secrets.extend(sources(out_get(svc, "secrets")));
        if let Some(b) = out_get(svc, "build") {
            used_secrets.extend(sources(out_get(b, "secrets")));
        }
        used_configs.extend(sources(out_get(svc, "configs")));
    }
    let mut top: Vec<(String, Out)> = vec![
        ("name".into(), Out::str(inp.name)),
        ("services".into(), go_map(services)),
    ];
    // Networks: the declared ones, and `default` when a service is on it.
    let mut nets: Vec<(String, Out)> = Vec::new();
    if let Some(Val::Map(m)) = merged.get("networks") {
        for (k, v) in m {
            if !inp.prune || used_nets.contains(k) {
                nets.push((k.clone(), network(k, v, inp)));
            }
        }
    }
    if uses_default_network && !nets.iter().any(|(k, _)| k == "default") {
        let mut d = vec![(
            "name".to_string(),
            Out::str(format!("{}_default", inp.name)),
        )];
        if inp.json {
            d.push(("ipam".into(), Out::Map(Vec::new())));
        }
        nets.push(("default".into(), Out::Map(d)));
    }
    if !nets.is_empty() {
        top.push(("networks".into(), go_map(nets)));
    }
    for (key, f) in [
        ("volumes", volume as fn(&str, &Val, &ProjectInput) -> Out),
        ("secrets", secret_or_config),
        ("configs", secret_or_config),
    ] {
        if let Some(Val::Map(m)) = merged.get(key) {
            let used = match key {
                "volumes" => &used_vols,
                "secrets" => &used_secrets,
                _ => &used_configs,
            };
            let entries: Vec<(String, Out)> = m
                .iter()
                .filter(|(k, _)| !inp.prune || used.contains(k))
                .map(|(k, v)| (k.clone(), f(k, v, inp)))
                .collect();
            if !entries.is_empty() {
                top.push((key.into(), go_map(entries)));
            }
        }
    }
    // Top-level extensions (`x-*`), kept as generic values.
    let mut ext: Vec<(String, Out)> = Vec::new();
    if let Val::Map(m) = &merged {
        for (k, v) in m {
            if k.starts_with("x-") {
                ext.push((k.clone(), generic(v)));
            }
        }
    }
    ext.sort_by(|a, b| a.0.cmp(&b.0));
    top.extend(ext);
    if inp.json {
        return Ok(go_map(top));
    }
    Ok(Out::Map(top))
}

/// Two files' trees merged the way compose-go merges `-f` files: mappings key by key, a later
/// scalar or list replacing an earlier one, except where a service list is merged by identity
/// (see [`merge_service`]).
fn merge_top(base: Val, over: Val) -> Val {
    match (base, over) {
        (Val::Map(mut b), Val::Map(o)) => {
            for (k, ov) in o {
                match b.iter_mut().find(|(bk, _)| *bk == k) {
                    Some((_, bv)) if k == "services" => {
                        *bv = merge_services(std::mem::replace(bv, Val::Null), ov);
                    }
                    Some((_, bv)) => *bv = merge_value(std::mem::replace(bv, Val::Null), ov),
                    None => b.push((k, ov)),
                }
            }
            Val::Map(b)
        }
        (_, o) => o,
    }
}

fn merge_value(base: Val, over: Val) -> Val {
    match (base, over) {
        (Val::Map(mut b), Val::Map(o)) => {
            for (k, ov) in o {
                match b.iter_mut().find(|(bk, _)| *bk == k) {
                    Some((_, bv)) => *bv = merge_value(std::mem::replace(bv, Val::Null), ov),
                    None => b.push((k, ov)),
                }
            }
            Val::Map(b)
        }
        (_, o) => o,
    }
}

fn merge_services(base: Val, over: Val) -> Val {
    match (base, over) {
        (Val::Map(mut b), Val::Map(o)) => {
            for (k, ov) in o {
                match b.iter_mut().find(|(bk, _)| *bk == k) {
                    Some((_, bv)) => *bv = merge_service(std::mem::replace(bv, Val::Null), ov),
                    None => b.push((k, ov)),
                }
            }
            Val::Map(b)
        }
        (_, o) => o,
    }
}

/// compose-go's override rules for one service: sequences that name things are unioned (`ports`,
/// `expose`, `dns`, `dns_search`, `tmpfs`, `cap_add`, `cap_drop`, `extra_hosts`, `external_links`,
/// `security_opt`, `volumes`, `secrets`, `configs`, `devices`), mappings merge, everything else is
/// replaced; `command`, `entrypoint` and `healthcheck.test` are replaced whole.
fn merge_service(base: Val, over: Val) -> Val {
    const UNION: &[&str] = &[
        "ports",
        "expose",
        "dns",
        "dns_search",
        "tmpfs",
        "cap_add",
        "cap_drop",
        "extra_hosts",
        "external_links",
        "security_opt",
        "volumes",
        "secrets",
        "configs",
        "devices",
        "env_file",
        "group_add",
        "links",
        "profiles",
    ];
    match (base, over) {
        (Val::Map(mut b), Val::Map(o)) => {
            for (k, ov) in o {
                match b.iter_mut().find(|(bk, _)| *bk == k) {
                    Some((_, bv)) if UNION.contains(&k.as_str()) => {
                        let mut items = seq_items(std::mem::replace(bv, Val::Null));
                        for i in seq_items(ov) {
                            if !items.contains(&i) {
                                items.push(i);
                            }
                        }
                        *bv = Val::Seq(items);
                    }
                    Some((_, bv)) if matches!(k.as_str(), "command" | "entrypoint") => *bv = ov,
                    Some((_, bv)) if matches!(k.as_str(), "environment" | "labels") => {
                        *bv = merge_value(
                            as_mapping(std::mem::replace(bv, Val::Null)),
                            as_mapping(ov),
                        );
                    }
                    Some((_, bv)) => *bv = merge_value(std::mem::replace(bv, Val::Null), ov),
                    None => b.push((k, ov)),
                }
            }
            Val::Map(b)
        }
        (_, o) => o,
    }
}

fn seq_items(v: Val) -> Vec<Val> {
    match v {
        Val::Seq(s) => s,
        Val::Null => Vec::new(),
        other => vec![other],
    }
}

/// A `KEY=value` list as a mapping (an `environment:`/`labels:` list), so two files merge by key.
fn as_mapping(v: Val) -> Val {
    match v {
        Val::Seq(items) => Val::Map(
            items
                .into_iter()
                .filter_map(|i| {
                    let t = i.text()?.to_string();
                    Some(match t.split_once('=') {
                        Some((k, v)) => (k.to_string(), Val::Scalar(v.to_string(), true)),
                        None => (t, Val::Null),
                    })
                })
                .collect(),
        ),
        other => other,
    }
}

/// Every string of a scalar-or-list value.
fn strings_of(v: Option<&Val>) -> Vec<String> {
    match v {
        Some(Val::Seq(items)) => items.iter().filter_map(scalar_text).collect(),
        Some(other) => scalar_text(other).into_iter().collect(),
        None => Vec::new(),
    }
}

/// A scalar as the string compose-go decodes it into: a quoted one as written, a plain one by its
/// type (`fmt.Sprint`), null as nothing.
fn scalar_text(v: &Val) -> Option<String> {
    match v {
        Val::Scalar(s, true) => Some(s.clone()),
        Val::Scalar(s, false) => go_sprint(&resolve(s)),
        _ => None,
    }
}

/// A scalar for a string FIELD: compose-go decodes the YAML value into a Go string, which for a
/// plain number keeps its digits as written.
fn field_str(v: &Val) -> Option<String> {
    match v {
        Val::Scalar(s, _) => Some(s.clone()),
        _ => None,
    }
}

fn field_int(v: &Val) -> Option<i64> {
    match v {
        Val::Scalar(s, _) => match resolve(s.trim()) {
            Typed::Int(i) => Some(i),
            Typed::Float(f) if f.fract() == 0.0 => Some(f as i64),
            _ => None,
        },
        _ => None,
    }
}

fn field_float(v: &Val, bits: u32) -> Option<Out> {
    match v {
        Val::Scalar(s, _) => match resolve(s.trim()) {
            Typed::Int(i) => Some(Out::Float(go_format_float(i as f64, bits))),
            Typed::Float(f) => Some(Out::Float(go_format_float(f, bits))),
            _ => None,
        },
        _ => None,
    }
}

fn field_bool(v: &Val) -> Option<bool> {
    match v {
        Val::Scalar(s, _) => match s.trim() {
            "true" | "True" | "TRUE" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" => Some(true),
            "false" | "False" | "FALSE" | "no" | "No" | "NO" | "off" | "Off" | "OFF" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// A size (`512m`, `1g`, a byte count) as compose-go's `UnitBytes` prints it: the bytes, as a
/// string. go-units' `RAMInBytes`: binary units, case-insensitive, an optional `b`.
fn unit_bytes(v: &Val) -> Option<Out> {
    let s = field_str(v)?;
    let t = s.trim().to_ascii_lowercase();
    if let Ok(n) = t.parse::<i64>() {
        return Some(Out::str(n.to_string()));
    }
    let t = t.strip_suffix('b').unwrap_or(&t);
    let (num, mult): (&str, f64) = match t.chars().last()? {
        'k' => (t.get(..t.len() - 1)?, 1024.0),
        'm' => (t.get(..t.len() - 1)?, 1024.0 * 1024.0),
        'g' => (t.get(..t.len() - 1)?, 1024.0 * 1024.0 * 1024.0),
        't' => (t.get(..t.len() - 1)?, 1024.0_f64.powi(4)),
        'p' => (t.get(..t.len() - 1)?, 1024.0_f64.powi(5)),
        _ => (t, 1.0),
    };
    let n: f64 = num.trim().parse().ok()?;
    Some(Out::str(((n * mult) as i64).to_string()))
}

/// A duration as compose-go's `Duration` prints it: Go's `time.Duration.String()`.
fn duration(v: &Val) -> Option<Out> {
    let s = field_str(v)?;
    let nanos = parse_go_duration(s.trim())?;
    Some(Out::str(go_duration_string(nanos)))
}

/// `str2duration.ParseDuration`: Go's units plus `d` and `w`, a bare number meaning seconds.
fn parse_go_duration(s: &str) -> Option<i128> {
    if let Ok(n) = s.parse::<i64>() {
        return Some(i128::from(n) * 1_000_000_000);
    }
    let mut total: i128 = 0;
    let b = s.as_bytes();
    let mut i = 0;
    let neg = b.first() == Some(&b'-');
    if neg || b.first() == Some(&b'+') {
        i += 1;
    }
    if i >= b.len() {
        return None;
    }
    while i < b.len() {
        let start = i;
        while b.get(i).is_some_and(|c| c.is_ascii_digit() || *c == b'.') {
            i += 1;
        }
        let num: f64 = s.get(start..i)?.parse().ok()?;
        let ustart = i;
        while b
            .get(i)
            .is_some_and(|c| c.is_ascii_alphabetic() || *c == 0xc2 || *c == 0xb5)
        {
            i += 1;
        }
        let unit = s.get(ustart..i)?;
        let mult: f64 = match unit {
            "ns" => 1.0,
            "us" | "µs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            "d" => 86400e9,
            "w" => 604_800e9,
            _ => return None,
        };
        total = total.checked_add((num * mult) as i128)?;
    }
    Some(if neg { -total } else { total })
}

/// Go's `time.Duration.String()`: `1h2m3s`, `1m30s`, `500ms`, `0s`.
fn go_duration_string(n: i128) -> String {
    if n == 0 {
        return "0s".into();
    }
    let neg = n < 0;
    let u = n.unsigned_abs();
    let sign = if neg { "-" } else { "" };
    if u < 1_000_000_000 {
        let (val, unit) = if u < 1_000 {
            (u.to_string(), "ns")
        } else if u < 1_000_000 {
            (trim_frac(u, 1_000), "µs")
        } else {
            (trim_frac(u, 1_000_000), "ms")
        };
        return format!("{sign}{val}{unit}");
    }
    let total_secs = u / 1_000_000_000;
    let frac = u % 1_000_000_000;
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    let secs = if frac == 0 {
        s.to_string()
    } else {
        let f = format!("{frac:09}");
        format!("{s}.{}", f.trim_end_matches('0'))
    };
    let mut out = String::from(sign);
    if h > 0 {
        out.push_str(&format!("{h}h{m}m"));
    } else if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    out.push_str(&format!("{secs}s"));
    out
}

fn trim_frac(u: u128, unit: u128) -> String {
    let whole = u / unit;
    let frac = u % unit;
    if frac == 0 {
        return whole.to_string();
    }
    let digits = unit.to_string().len() - 1;
    let f = format!("{frac:0digits$}");
    format!("{whole}.{}", f.trim_end_matches('0'))
}

/// A path the file wrote, resolved as compose-go resolves it: `~` is the home directory, a relative
/// path joins the project directory, and the result is cleaned (Go's `filepath.Clean`).
fn abs_path(p: &str, dir: &std::path::Path) -> String {
    let joined = if let Some(rest) = p.strip_prefix("~/") {
        std::env::var("HOME").map_or_else(|_| p.to_string(), |h| format!("{h}/{rest}"))
    } else if p == "~" {
        std::env::var("HOME").unwrap_or_else(|_| p.to_string())
    } else if p.starts_with('/') {
        p.to_string()
    } else {
        format!("{}/{p}", dir.display())
    };
    clean_path(&joined)
}

/// Go's `filepath.Clean` for an absolute path.
pub(crate) fn clean_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

/// compose-go's `shellwords.Parse` of a string `command:`/`entrypoint:`: words split on unquoted
/// blanks, quotes removed, a backslash escaping the next character outside single quotes.
fn shell_split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    let (mut sq, mut dq) = (false, false);
    while let Some(c) = chars.next() {
        match c {
            '\\' if !sq => {
                if let Some(n) = chars.next() {
                    if dq && !matches!(n, '"' | '\\' | '$' | '`') {
                        cur.push('\\');
                    }
                    cur.push(n);
                    in_word = true;
                }
            }
            '\'' if !dq => {
                sq = !sq;
                in_word = true;
            }
            '"' if !sq => {
                dq = !dq;
                in_word = true;
            }
            ' ' | '\t' | '\n' if !sq && !dq => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            other => {
                cur.push(other);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

/// A `command:`/`entrypoint:` as compose-go's `ShellCommand` prints it: a list, a string split as a
/// shell splits it, an empty string an empty list.
fn shell_command(v: &Val) -> Option<Out> {
    match v {
        Val::Seq(items) => Some(Out::Seq(
            items.iter().filter_map(scalar_text).map(Out::Str).collect(),
        )),
        Val::Scalar(s, _) => Some(Out::Seq(shell_split(s).into_iter().map(Out::Str).collect())),
        _ => None,
    }
}

/// A `KEY: value` mapping or a `KEY=value` list as a Go `map[string]string` (`Mapping`): sorted,
/// a list entry without `=` an empty string (labels) or null (`MappingWithEquals`, environment).
fn mapping(v: &Val, null_without_value: bool, env: Option<&EnvLookup>) -> Out {
    let mut entries: Vec<(String, Out)> = Vec::new();
    let mut set = |k: String, v: Option<String>| {
        let o = match v {
            Some(s) => Out::Str(s),
            None if null_without_value => match env.and_then(|f| f(&k)) {
                Some(s) => Out::Str(s),
                None => Out::Null,
            },
            None => Out::str(""),
        };
        match entries.iter_mut().find(|(ek, _)| *ek == k) {
            Some((_, ev)) => *ev = o,
            None => entries.push((k, o)),
        }
    };
    match v {
        Val::Map(m) => {
            for (k, val) in m {
                set(k.clone(), scalar_text(val));
            }
        }
        Val::Seq(items) => {
            for i in items {
                let Some(t) = scalar_text(i) else { continue };
                match t.split_once('=') {
                    Some((k, val)) => set(k.to_string(), Some(val.to_string())),
                    None => set(t, None),
                }
            }
        }
        _ => {}
    }
    go_map(entries)
}

/// One service, normalised; and whether it sits on the project's `default` network.
fn service(
    name: &str,
    svc: &Val,
    all: &[(String, Val)],
    inp: &ProjectInput,
) -> Result<(Out, bool), String> {
    let get = |k: &str| svc.get(k);
    let mut f: Vec<(&'static str, Out)> = Vec::new();
    let s = |k: &'static str, f: &mut Vec<(&'static str, Out)>| {
        if let Some(v) = get(k).and_then(field_str) {
            f.push((k, Out::Str(v)));
        }
    };
    let list = |k: &'static str, f: &mut Vec<(&'static str, Out)>| {
        let items = strings_of(get(k));
        if get(k).is_some() && !items.is_empty() {
            f.push((k, Out::Seq(items.into_iter().map(Out::Str).collect())));
        }
    };
    let int = |k: &'static str, f: &mut Vec<(&'static str, Out)>| {
        if let Some(v) = get(k).and_then(field_int) {
            f.push((k, Out::Int(v)));
        }
    };
    let boolean = |k: &'static str, f: &mut Vec<(&'static str, Out)>| {
        if get(k).and_then(field_bool) == Some(true) {
            f.push((k, Out::Bool(true)));
        }
    };
    let bytes = |k: &'static str, f: &mut Vec<(&'static str, Out)>| {
        if let Some(v) = get(k).and_then(unit_bytes) {
            f.push((k, v));
        }
    };

    // The dependencies the service has without naming them: `links:`, `network_mode: service:X`
    // and `volumes_from: X` start X first, and restart with it (`restart: true`).
    let mut depends: Vec<(String, Out)> = Vec::new();
    match get("depends_on") {
        Some(Val::Seq(items)) => {
            for i in items.iter().filter_map(scalar_text) {
                depends.push((i, dependency(None, None, None)));
            }
        }
        Some(Val::Map(m)) => {
            for (k, d) in m {
                depends.push((
                    k.clone(),
                    dependency(
                        d.get("condition").and_then(field_str),
                        d.get("restart").and_then(field_bool),
                        d.get("required").and_then(field_bool),
                    ),
                ));
            }
        }
        _ => {}
    }
    let mut implied: Vec<String> = Vec::new();
    for l in strings_of(get("links")) {
        implied.push(l.split(':').next().unwrap_or(&l).to_string());
    }
    if let Some(nm) = get("network_mode").and_then(field_str) {
        if let Some(x) = nm.strip_prefix("service:") {
            implied.push(x.to_string());
        }
    }
    for vf in strings_of(get("volumes_from")) {
        let target = vf.split(':').next().unwrap_or(&vf).to_string();
        if !target.starts_with("container:") && all.iter().any(|(n, _)| *n == target) {
            implied.push(target);
        }
    }
    for x in implied {
        if !depends.iter().any(|(k, _)| *k == x) {
            depends.push((x, dependency(None, Some(true), None)));
        }
    }

    // In compose-go v2.13.0's field order (see the module documentation).
    list("profiles", &mut f);
    if let Some(Val::Map(a)) = get("annotations") {
        f.push(("annotations", mapping(&Val::Map(a.clone()), false, None)));
    }
    if get("attach").and_then(field_bool) == Some(false) {
        f.push(("attach", Out::Bool(false)));
    }
    if let Some(b) = get("build") {
        f.push(("build", build(b, inp)));
    }
    if let Some(Val::Map(m)) = get("blkio_config") {
        f.push(("blkio_config", generic(&Val::Map(m.clone()))));
    }
    list("cap_add", &mut f);
    list("cap_drop", &mut f);
    s("cgroup_parent", &mut f);
    s("cgroup", &mut f);
    int("cpu_count", &mut f);
    if let Some(v) = get("cpu_percent").and_then(|v| field_float(v, 32)) {
        f.push(("cpu_percent", v));
    }
    int("cpu_period", &mut f);
    int("cpu_quota", &mut f);
    int("cpu_rt_period", &mut f);
    int("cpu_rt_runtime", &mut f);
    if let Some(v) = get("cpus").and_then(|v| field_float(v, 32)) {
        f.push(("cpus", v));
    }
    s("cpuset", &mut f);
    int("cpu_shares", &mut f);
    match get("command").and_then(shell_command) {
        Some(c) => f.push(("command", c)),
        None if inp.json => f.push(("command", Out::Null)),
        None => {}
    }
    if let Some(Val::Seq(items)) = get("configs") {
        f.push(("configs", file_refs(items, None)));
    }
    s("container_name", &mut f);
    if let Some(Val::Map(m)) = get("credential_spec") {
        f.push(("credential_spec", generic(&Val::Map(m.clone()))));
    }
    if !depends.is_empty() {
        f.push(("depends_on", go_map(depends)));
    }
    if let Some(d) = get("deploy") {
        f.push(("deploy", deploy(d, inp.json)));
    }
    list("device_cgroup_rules", &mut f);
    if let Some(Val::Seq(items)) = get("devices") {
        f.push(("devices", devices(items)));
    }
    list("dns", &mut f);
    list("dns_opt", &mut f);
    list("dns_search", &mut f);
    s("dockerfile", &mut f);
    s("domainname", &mut f);
    match get("entrypoint").and_then(shell_command) {
        Some(e) => f.push(("entrypoint", e)),
        None if inp.json => f.push(("entrypoint", Out::Null)),
        None => {}
    }
    // `env_file:` is read into `environment:` and not printed; an entry in `environment:` wins.
    let mut env_entries: Vec<(String, Out)> = Vec::new();
    for ef in env_files(get("env_file")) {
        let path = abs_path(&ef.0, inp.dir);
        match (inp.env_file)(std::path::Path::new(&path)) {
            Ok(pairs) => {
                for (k, v) in pairs {
                    let o = v.map_or(Out::Null, Out::Str);
                    match env_entries.iter_mut().find(|(ek, _)| *ek == k) {
                        Some((_, ev)) => *ev = o,
                        None => env_entries.push((k, o)),
                    }
                }
            }
            Err(e) if ef.1 => return Err(e),
            Err(_) => {}
        }
    }
    if let Some(e) = get("environment") {
        if let Out::Map(m) = mapping(e, true, Some(inp.env)) {
            for (k, v) in m {
                match env_entries.iter_mut().find(|(ek, _)| *ek == k) {
                    Some((_, ev)) => *ev = v,
                    None => env_entries.push((k, v)),
                }
            }
        }
    }
    if !env_entries.is_empty() {
        f.push(("environment", go_map(env_entries)));
    }
    if get("expose").is_some() {
        let items = strings_of(get("expose"));
        if !items.is_empty() {
            f.push((
                "expose",
                Out::Seq(items.into_iter().map(Out::Str).collect()),
            ));
        }
    }
    list("external_links", &mut f);
    if let Some(h) = get("extra_hosts") {
        f.push(("extra_hosts", extra_hosts(h)));
    }
    list("group_add", &mut f);
    if let Some(g) = get("gpus") {
        f.push(("gpus", gpus(g)));
    }
    s("hostname", &mut f);
    if let Some(h) = get("healthcheck") {
        f.push(("healthcheck", healthcheck(h)));
    }
    s("image", &mut f);
    if let Some(b) = get("init").and_then(field_bool) {
        f.push(("init", Out::Bool(b)));
    }
    s("ipc", &mut f);
    s("isolation", &mut f);
    if let Some(l) = get("labels") {
        f.push(("labels", mapping(l, false, None)));
    }
    list("label_file", &mut f);
    list("links", &mut f);
    if let Some(Val::Map(m)) = get("logging") {
        f.push(("logging", logging(m)));
    }
    s("log_driver", &mut f);
    if let Some(l) = get("log_opt") {
        f.push(("log_opt", mapping(l, false, None)));
    }
    bytes("mem_limit", &mut f);
    bytes("mem_reservation", &mut f);
    bytes("memswap_limit", &mut f);
    bytes("mem_swappiness", &mut f);
    s("mac_address", &mut f);
    s("net", &mut f);
    s("network_mode", &mut f);
    let mut default_net = false;
    if get("network_mode").is_none() {
        let nets = service_networks(get("networks"));
        default_net = match &nets {
            Out::Map(m) => m.iter().any(|(k, _)| k == "default"),
            _ => false,
        };
        f.push(("networks", nets));
    }
    boolean("oom_kill_disable", &mut f);
    int("oom_score_adj", &mut f);
    s("pid", &mut f);
    int("pids_limit", &mut f);
    s("platform", &mut f);
    if let Some(Val::Seq(items)) = get("ports") {
        f.push(("ports", ports(items)));
    }
    boolean("privileged", &mut f);
    s("pull_policy", &mut f);
    boolean("read_only", &mut f);
    s("restart", &mut f);
    s("runtime", &mut f);
    int("scale", &mut f);
    if let Some(Val::Seq(items)) = get("secrets") {
        f.push(("secrets", file_refs(items, Some("/run/secrets/"))));
    }
    list("security_opt", &mut f);
    bytes("shm_size", &mut f);
    boolean("stdin_open", &mut f);
    if let Some(d) = get("stop_grace_period").and_then(duration) {
        f.push(("stop_grace_period", d));
    }
    s("stop_signal", &mut f);
    if let Some(l) = get("storage_opt") {
        f.push(("storage_opt", mapping(l, false, None)));
    }
    if let Some(l) = get("sysctls") {
        f.push(("sysctls", mapping(l, false, None)));
    }
    list("tmpfs", &mut f);
    boolean("tty", &mut f);
    if let Some(Val::Map(m)) = get("ulimits") {
        f.push(("ulimits", ulimits(m, inp.json)));
    }
    boolean("use_api_socket", &mut f);
    s("user", &mut f);
    s("userns_mode", &mut f);
    s("uts", &mut f);
    s("volume_driver", &mut f);
    if let Some(Val::Seq(items)) = get("volumes") {
        f.push(("volumes", volumes(items, inp)));
    }
    list("volumes_from", &mut f);
    s("working_dir", &mut f);
    // Extensions last, sorted (an inline map). Not in JSON: the field's tag there is `json:"-"`.
    let mut ext: Vec<(String, Out)> = match svc {
        _ if inp.json => Vec::new(),
        Val::Map(m) => m
            .iter()
            .filter(|(k, _)| k.starts_with("x-"))
            .map(|(k, v)| (k.clone(), generic(v)))
            .collect(),
        _ => Vec::new(),
    };
    ext.sort_by(|a, b| a.0.cmp(&b.0));
    let _ = name;
    let mut out: Vec<(String, Out)> = f.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    out.extend(ext);
    Ok((Out::Map(out), default_net))
}

/// A `depends_on` entry: `condition` (default `service_started`), `restart` when true, `required`
/// (default true), in that order.
fn dependency(condition: Option<String>, restart: Option<bool>, required: Option<bool>) -> Out {
    let mut m = vec![(
        "condition".to_string(),
        Out::Str(condition.unwrap_or_else(|| "service_started".into())),
    )];
    if restart == Some(true) {
        m.push(("restart".into(), Out::Bool(true)));
    }
    m.push(("required".into(), Out::Bool(required.unwrap_or(true))));
    Out::Map(m)
}

/// `build:` as `BuildConfig`: a string is the context, the context is made absolute (not a URL),
/// and `dockerfile` defaults to `Dockerfile`.
fn build(v: &Val, inp: &ProjectInput) -> Out {
    let (ctx, m) = match v {
        Val::Scalar(s, _) => (s.clone(), Vec::new()),
        Val::Map(m) => (
            m.iter()
                .find(|(k, _)| k == "context")
                .and_then(|(_, v)| field_str(v))
                .unwrap_or_else(|| ".".into()),
            m.clone(),
        ),
        _ => (".".into(), Vec::new()),
    };
    let is_url = ctx.contains("://") || ctx.starts_with("git@");
    let context = if is_url { ctx } else { abs_path(&ctx, inp.dir) };
    let get = |k: &str| m.iter().find(|(mk, _)| mk == k).map(|(_, v)| v);
    let mut out: Vec<(String, Out)> = vec![("context".into(), Out::Str(context))];
    let dockerfile_inline = get("dockerfile_inline").and_then(field_str);
    if dockerfile_inline.is_none() {
        out.push((
            "dockerfile".into(),
            Out::Str(
                get("dockerfile")
                    .and_then(field_str)
                    .unwrap_or_else(|| "Dockerfile".into()),
            ),
        ));
    }
    if let Some(d) = dockerfile_inline {
        out.push(("dockerfile_inline".into(), Out::Str(d)));
    }
    if let Some(a) = get("args") {
        // An argument with no value takes the environment's, and is left out when it has none.
        if let Out::Map(args) = mapping(a, true, Some(inp.env)) {
            out.push((
                "args".into(),
                Out::Map(args.into_iter().filter(|(_, v)| *v != Out::Null).collect()),
            ));
        }
    }
    let ssh = strings_of(get("ssh"));
    if !ssh.is_empty() {
        out.push((
            "ssh".into(),
            Out::Seq(ssh.into_iter().map(Out::Str).collect()),
        ));
    }
    if let Some(l) = get("labels") {
        out.push(("labels".into(), mapping(l, false, None)));
    }
    for k in ["cache_from", "cache_to"] {
        let items = strings_of(get(k));
        if !items.is_empty() {
            out.push((
                k.into(),
                Out::Seq(items.into_iter().map(Out::Str).collect()),
            ));
        }
    }
    if get("no_cache").and_then(field_bool) == Some(true) {
        out.push(("no_cache".into(), Out::Bool(true)));
    }
    if let Some(Val::Map(ac)) = get("additional_contexts") {
        out.push((
            "additional_contexts".into(),
            mapping(&Val::Map(ac.clone()), false, None),
        ));
    }
    if get("pull").and_then(field_bool) == Some(true) {
        out.push(("pull".into(), Out::Bool(true)));
    }
    if let Some(h) = get("extra_hosts") {
        out.push(("extra_hosts".into(), extra_hosts(h)));
    }
    for k in ["isolation", "network", "target"] {
        if let Some(v) = get(k).and_then(field_str) {
            out.push((k.into(), Out::Str(v)));
        }
    }
    if let Some(Val::Seq(items)) = get("secrets") {
        out.push(("secrets".into(), file_refs(items, None)));
    }
    if let Some(v) = get("shm_size").and_then(unit_bytes) {
        out.push(("shm_size".into(), v));
    }
    let tags = strings_of(get("tags"));
    if !tags.is_empty() {
        out.push((
            "tags".into(),
            Out::Seq(tags.into_iter().map(Out::Str).collect()),
        ));
    }
    if let Some(Val::Map(u)) = get("ulimits") {
        out.push(("ulimits".into(), ulimits(u, inp.json)));
    }
    let platforms = strings_of(get("platforms"));
    if !platforms.is_empty() {
        out.push((
            "platforms".into(),
            Out::Seq(platforms.into_iter().map(Out::Str).collect()),
        ));
    }
    if get("privileged").and_then(field_bool) == Some(true) {
        out.push(("privileged".into(), Out::Bool(true)));
    }
    Out::Map(out)
}

/// The `env_file:` entries as `(path, required)`.
fn env_files(v: Option<&Val>) -> Vec<(String, bool)> {
    match v {
        Some(Val::Seq(items)) => items
            .iter()
            .filter_map(|i| match i {
                Val::Map(_) => Some((
                    i.get("path").and_then(field_str)?,
                    i.get("required").and_then(field_bool).unwrap_or(true),
                )),
                other => Some((scalar_text(other)?, true)),
            })
            .collect(),
        Some(other) => scalar_text(other)
            .map(|p| vec![(p, true)])
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

/// `extra_hosts:` as `HostsList` prints it: `host=ip`, sorted.
fn extra_hosts(v: &Val) -> Out {
    let mut list: Vec<String> = match v {
        Val::Map(m) => m
            .iter()
            .filter_map(|(k, v)| Some(format!("{k}={}", scalar_text(v)?)))
            .collect(),
        other => strings_of(Some(other))
            .into_iter()
            .map(|e| {
                if e.contains('=') {
                    e
                } else {
                    match e.split_once(':') {
                        Some((h, ip)) => format!("{h}={ip}"),
                        None => e,
                    }
                }
            })
            .collect(),
    };
    list.sort();
    Out::Seq(list.into_iter().map(Out::Str).collect())
}

/// `gpus:`: `all` is one request for every device (`count: -1`).
fn gpus(v: &Val) -> Out {
    match v {
        Val::Scalar(s, _) if s == "all" => {
            Out::Seq(vec![Out::Map(vec![("count".into(), Out::Int(-1))])])
        }
        Val::Seq(items) => Out::Seq(items.iter().map(device_request).collect()),
        other => generic(other),
    }
}

/// One `DeviceRequest`: capabilities, driver, count (`all` is -1), device_ids, options.
fn device_request(v: &Val) -> Out {
    let mut m: Vec<(String, Out)> = Vec::new();
    let caps = strings_of(v.get("capabilities"));
    if !caps.is_empty() {
        m.push((
            "capabilities".into(),
            Out::Seq(caps.into_iter().map(Out::Str).collect()),
        ));
    }
    if let Some(d) = v.get("driver").and_then(field_str) {
        m.push(("driver".into(), Out::Str(d)));
    }
    if let Some(c) = v.get("count") {
        match field_str(c).as_deref() {
            Some("all") => m.push(("count".into(), Out::Int(-1))),
            _ => {
                if let Some(n) = field_int(c) {
                    m.push(("count".into(), Out::Int(n)));
                }
            }
        }
    }
    let ids = strings_of(v.get("device_ids"));
    if !ids.is_empty() {
        m.push((
            "device_ids".into(),
            Out::Seq(ids.into_iter().map(Out::Str).collect()),
        ));
    }
    if let Some(o) = v.get("options") {
        m.push(("options".into(), mapping(o, false, None)));
    }
    Out::Map(m)
}

/// `healthcheck:`: `test` as a list (a string is `CMD-SHELL`), the durations normalised, `disable`
/// only when true.
fn healthcheck(v: &Val) -> Out {
    let mut m: Vec<(String, Out)> = Vec::new();
    match v.get("test") {
        Some(Val::Seq(items)) => m.push((
            "test".into(),
            Out::Seq(items.iter().filter_map(scalar_text).map(Out::Str).collect()),
        )),
        Some(t) => {
            if let Some(s) = scalar_text(t) {
                m.push((
                    "test".into(),
                    Out::Seq(vec![Out::str("CMD-SHELL"), Out::Str(s)]),
                ));
            }
        }
        None => {}
    }
    for k in ["timeout", "interval"] {
        if let Some(d) = v.get(k).and_then(duration) {
            m.push((k.into(), d));
        }
    }
    if let Some(r) = v.get("retries").and_then(field_int) {
        m.push(("retries".into(), Out::Int(r)));
    }
    for k in ["start_period", "start_interval"] {
        if let Some(d) = v.get(k).and_then(duration) {
            m.push((k.into(), d));
        }
    }
    if v.get("disable").and_then(field_bool) == Some(true) {
        m.push(("disable".into(), Out::Bool(true)));
    }
    Out::Map(m)
}

fn logging(m: &[(String, Val)]) -> Out {
    let mut out: Vec<(String, Out)> = Vec::new();
    let v = Val::Map(m.to_vec());
    if let Some(d) = v.get("driver").and_then(field_str) {
        out.push(("driver".into(), Out::Str(d)));
    }
    if let Some(o) = v.get("options") {
        out.push(("options".into(), mapping(o, false, None)));
    }
    Out::Map(out)
}

/// `ulimits:` as `UlimitsConfig`: a bare number is `single`, printed as the number; a mapping is
/// `soft` and `hard`. Sorted by name.
fn ulimits(m: &[(String, Val)], json: bool) -> Out {
    let entries = m
        .iter()
        .map(|(k, v)| {
            let o = match v {
                Val::Map(_) => {
                    let mut l: Vec<(String, Out)> = Vec::new();
                    for key in ["soft", "hard"] {
                        if let Some(n) = v.get(key).and_then(field_int) {
                            l.push((key.into(), Out::Int(n)));
                        }
                    }
                    Out::Map(l)
                }
                // `UlimitsConfig` prints a non-zero `single` as the number and anything else as
                // `soft`/`hard`, so `core: 0` comes out as both at 0.
                // In JSON the zero `soft`/`hard` are omitted (`omitempty`), so it is `{}`.
                other => match field_int(other) {
                    Some(0) if json => Out::Map(Vec::new()),
                    Some(0) => Out::Map(vec![
                        ("soft".into(), Out::Int(0)),
                        ("hard".into(), Out::Int(0)),
                    ]),
                    Some(n) => Out::Int(n),
                    None => Out::Null,
                },
            };
            (k.clone(), o)
        })
        .collect();
    go_map(entries)
}

/// `networks:` of a service: a list is a map of nulls, a mapping keeps each network's settings, no
/// key is the `default` network. Sorted.
fn service_networks(v: Option<&Val>) -> Out {
    match v {
        Some(Val::Seq(items)) => go_map(
            items
                .iter()
                .filter_map(scalar_text)
                .map(|n| (n, Out::Null))
                .collect(),
        ),
        Some(Val::Map(m)) => go_map(
            m.iter()
                .map(|(k, v)| {
                    let o = match v {
                        Val::Map(nm) => service_network(nm),
                        _ => Out::Null,
                    };
                    (k.clone(), o)
                })
                .collect(),
        ),
        _ => go_map(vec![("default".into(), Out::Null)]),
    }
}

fn service_network(m: &[(String, Val)]) -> Out {
    let v = Val::Map(m.to_vec());
    let mut out: Vec<(String, Out)> = Vec::new();
    let aliases = strings_of(v.get("aliases"));
    if !aliases.is_empty() {
        out.push((
            "aliases".into(),
            Out::Seq(aliases.into_iter().map(Out::Str).collect()),
        ));
    }
    if let Some(d) = v.get("driver_opts") {
        out.push(("driver_opts".into(), mapping(d, false, None)));
    }
    if let Some(p) = v.get("gw_priority").and_then(field_int) {
        out.push(("gw_priority".into(), Out::Int(p)));
    }
    for k in ["interface_name", "ipv4_address", "ipv6_address"] {
        if let Some(s) = v.get(k).and_then(field_str) {
            out.push((k.into(), Out::Str(s)));
        }
    }
    let ll = strings_of(v.get("link_local_ips"));
    if !ll.is_empty() {
        out.push((
            "link_local_ips".into(),
            Out::Seq(ll.into_iter().map(Out::Str).collect()),
        ));
    }
    if let Some(s) = v.get("mac_address").and_then(field_str) {
        out.push(("mac_address".into(), Out::Str(s)));
    }
    if let Some(p) = v.get("priority").and_then(field_int) {
        out.push(("priority".into(), Out::Int(p)));
    }
    // A network written `{}` is a configuration that sets nothing, printed `{}`; one written with
    // no value is null (see `service_networks`).
    Out::Map(out)
}

/// `ports:` as `ServicePortConfig`s: a short spec is parsed and a range expanded into one entry per
/// port, as compose-go's `ParsePortConfig` does.
fn ports(items: &[Val]) -> Out {
    let mut out: Vec<Out> = Vec::new();
    for i in items {
        match i {
            Val::Map(_) => {
                let mut m: Vec<(String, Out)> = Vec::new();
                if let Some(n) = i.get("name").and_then(field_str) {
                    m.push(("name".into(), Out::Str(n)));
                }
                m.push((
                    "mode".into(),
                    Out::Str(
                        i.get("mode")
                            .and_then(field_str)
                            .unwrap_or_else(|| "ingress".into()),
                    ),
                ));
                if let Some(h) = i.get("host_ip").and_then(field_str) {
                    m.push(("host_ip".into(), Out::Str(h)));
                }
                if let Some(t) = i.get("target").and_then(field_int) {
                    m.push(("target".into(), Out::Int(t)));
                }
                if let Some(p) = i.get("published").and_then(scalar_text) {
                    m.push(("published".into(), Out::Str(p)));
                }
                m.push((
                    "protocol".into(),
                    Out::Str(
                        i.get("protocol")
                            .and_then(field_str)
                            .unwrap_or_else(|| "tcp".into()),
                    ),
                ));
                if let Some(a) = i.get("app_protocol").and_then(field_str) {
                    m.push(("app_protocol".into(), Out::Str(a)));
                }
                out.push(Out::Map(m));
            }
            other => {
                if let Some(spec) = scalar_text(other) {
                    out.extend(short_port(&spec));
                }
            }
        }
    }
    Out::Seq(out)
}

/// One short port spec: `[ip:][published[-end]:]target[-end][/proto]`, `[::1]` for an IPv6 host.
fn short_port(spec: &str) -> Vec<Out> {
    let (body, proto) = match spec.rsplit_once('/') {
        Some((b, p)) => (b, p.to_string()),
        None => (spec, "tcp".to_string()),
    };
    let (ip, rest) = if let Some(r) = body.strip_prefix('[') {
        match r.split_once("]:") {
            Some((ip, rest)) => (Some(ip.to_string()), rest.to_string()),
            None => (None, body.to_string()),
        }
    } else {
        let parts: Vec<&str> = body.split(':').collect();
        match parts.len() {
            3 => (
                Some(parts.first().copied().unwrap_or_default().to_string()),
                format!(
                    "{}:{}",
                    parts.get(1).copied().unwrap_or_default(),
                    parts.get(2).copied().unwrap_or_default()
                ),
            ),
            _ => (None, body.to_string()),
        }
    };
    let (published, target) = match rest.rsplit_once(':') {
        Some((p, t)) => (Some(p.to_string()).filter(|p| !p.is_empty()), t.to_string()),
        None => (None, rest.clone()),
    };
    let range = |s: &str| -> Option<(i64, i64)> {
        match s.split_once('-') {
            Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
            None => {
                let n: i64 = s.trim().parse().ok()?;
                Some((n, n))
            }
        }
    };
    let Some((t0, t1)) = range(&target) else {
        return Vec::new();
    };
    let pub_range = published.as_deref().and_then(range);
    let entry = |t: i64, p: Option<String>| -> Out {
        let mut m: Vec<(String, Out)> = vec![("mode".into(), Out::str("ingress"))];
        if let Some(h) = &ip {
            if !h.is_empty() {
                m.push(("host_ip".into(), Out::Str(h.clone())));
            }
        }
        m.push(("target".into(), Out::Int(t)));
        if let Some(p) = p {
            m.push(("published".into(), Out::Str(p)));
        }
        m.push(("protocol".into(), Out::Str(proto.clone())));
        Out::Map(m)
    };
    let mut out = Vec::new();
    for (k, t) in (t0..=t1).enumerate() {
        let p = match (pub_range, &published) {
            (Some((p0, p1)), _) if t1 > t0 && p1 - p0 == t1 - t0 => {
                Some((p0 + k as i64).to_string())
            }
            (_, Some(p)) => Some(p.clone()),
            _ => None,
        };
        out.push(entry(t, p));
    }
    out
}

/// `secrets:`/`configs:` of a service as `FileReferenceConfig`s. A short secret is mounted at
/// `/run/secrets/<name>`; a short config gets no target.
fn file_refs(items: &[Val], default_dir: Option<&str>) -> Out {
    Out::Seq(
        items
            .iter()
            .map(|i| match i {
                Val::Map(_) => {
                    let mut m: Vec<(String, Out)> = Vec::new();
                    let source = i.get("source").and_then(field_str).unwrap_or_default();
                    m.push(("source".into(), Out::Str(source.clone())));
                    match i.get("target").and_then(field_str) {
                        Some(t) => m.push(("target".into(), Out::Str(t))),
                        None => {
                            if let Some(d) = default_dir {
                                m.push(("target".into(), Out::Str(format!("{d}{source}"))));
                            }
                        }
                    }
                    for k in ["uid", "gid"] {
                        if let Some(s) = i.get(k).and_then(field_str) {
                            m.push((k.into(), Out::Str(s)));
                        }
                    }
                    if let Some(Val::Scalar(raw, _)) = i.get("mode") {
                        if let Typed::Int(n) = resolve(raw) {
                            m.push(("mode".into(), Out::Str(format!("{n:04o}"))));
                        }
                    }
                    Out::Map(m)
                }
                other => {
                    let source = scalar_text(other).unwrap_or_default();
                    let mut m = vec![("source".to_string(), Out::Str(source.clone()))];
                    if let Some(d) = default_dir {
                        m.push(("target".into(), Out::Str(format!("{d}{source}"))));
                    }
                    Out::Map(m)
                }
            })
            .collect(),
    )
}

/// `devices:` as `DeviceMapping`s: `source[:target[:permissions]]`.
fn devices(items: &[Val]) -> Out {
    Out::Seq(
        items
            .iter()
            .map(|i| match i {
                Val::Map(_) => {
                    let mut m: Vec<(String, Out)> = Vec::new();
                    for k in ["source", "target", "permissions"] {
                        if let Some(s) = i.get(k).and_then(field_str) {
                            m.push((k.into(), Out::Str(s)));
                        }
                    }
                    Out::Map(m)
                }
                other => {
                    let spec = scalar_text(other).unwrap_or_default();
                    let mut parts = spec.splitn(3, ':');
                    let src = parts.next().unwrap_or_default().to_string();
                    let dst = parts.next().map_or_else(|| src.clone(), str::to_string);
                    let perm = parts.next().unwrap_or("rwm").to_string();
                    Out::Map(vec![
                        ("source".into(), Out::Str(src)),
                        ("target".into(), Out::Str(dst)),
                        ("permissions".into(), Out::Str(perm)),
                    ])
                }
            })
            .collect(),
    )
}

/// `deploy:` as `DeployConfig`.
fn deploy(v: &Val, json: bool) -> Out {
    let mut m: Vec<(String, Out)> = Vec::new();
    if let Some(s) = v.get("mode").and_then(field_str) {
        m.push(("mode".into(), Out::Str(s)));
    }
    if let Some(n) = v.get("replicas").and_then(field_int) {
        m.push(("replicas".into(), Out::Int(n)));
    }
    if let Some(l) = v.get("labels") {
        m.push(("labels".into(), mapping(l, false, None)));
    }
    for k in ["update_config", "rollback_config"] {
        if let Some(u) = v.get(k) {
            // `UpdateConfig`: parallelism, delay, failure_action, monitor, max_failure_ratio, order.
            let mut um: Vec<(String, Out)> = Vec::new();
            if let Some(n) = u.get("parallelism").and_then(field_int) {
                um.push(("parallelism".into(), Out::Int(n)));
            }
            if let Some(d) = u.get("delay").and_then(duration) {
                um.push(("delay".into(), d));
            }
            if let Some(s) = u.get("failure_action").and_then(field_str) {
                um.push(("failure_action".into(), Out::Str(s)));
            }
            if let Some(d) = u.get("monitor").and_then(duration) {
                um.push(("monitor".into(), d));
            }
            if let Some(f) = u.get("max_failure_ratio").and_then(|v| field_float(v, 32)) {
                um.push(("max_failure_ratio".into(), f));
            }
            if let Some(s) = u.get("order").and_then(field_str) {
                um.push(("order".into(), Out::Str(s)));
            }
            m.push((k.into(), Out::Map(um)));
        }
    }
    if let Some(r) = v.get("resources") {
        let mut rm: Vec<(String, Out)> = Vec::new();
        for k in ["limits", "reservations"] {
            if let Some(lim) = r.get(k) {
                let mut l: Vec<(String, Out)> = Vec::new();
                if let Some(c) = lim.get("cpus").and_then(|v| field_float(v, 32)) {
                    l.push(("cpus".into(), c));
                }
                if let Some(b) = lim.get("memory").and_then(unit_bytes) {
                    l.push(("memory".into(), b));
                }
                if let Some(p) = lim.get("pids").and_then(field_int) {
                    l.push(("pids".into(), Out::Int(p)));
                }
                if let Some(Val::Seq(d)) = lim.get("devices") {
                    l.push((
                        "devices".into(),
                        Out::Seq(d.iter().map(device_request).collect()),
                    ));
                }
                if let Some(g) = lim.get("generic_resources") {
                    l.push(("generic_resources".into(), generic(g)));
                }
                rm.push((k.into(), Out::Map(l)));
            }
        }
        m.push(("resources".into(), Out::Map(rm)));
    } else if json {
        m.push(("resources".into(), Out::Map(Vec::new())));
    }
    if let Some(rp) = v.get("restart_policy") {
        let mut r: Vec<(String, Out)> = Vec::new();
        if let Some(c) = rp.get("condition").and_then(field_str) {
            r.push(("condition".into(), Out::Str(c)));
        }
        if let Some(d) = rp.get("delay").and_then(duration) {
            r.push(("delay".into(), d));
        }
        if let Some(n) = rp.get("max_attempts").and_then(field_int) {
            r.push(("max_attempts".into(), Out::Int(n)));
        }
        if let Some(d) = rp.get("window").and_then(duration) {
            r.push(("window".into(), d));
        }
        m.push(("restart_policy".into(), Out::Map(r)));
    }
    if let Some(p) = v.get("placement") {
        m.push(("placement".into(), generic(p)));
    } else if json {
        m.push(("placement".into(), Out::Map(Vec::new())));
    }
    if let Some(s) = v.get("endpoint_mode").and_then(field_str) {
        m.push(("endpoint_mode".into(), Out::Str(s)));
    }
    Out::Map(m)
}

/// `volumes:` of a service as `ServiceVolumeConfig`s.
fn volumes(items: &[Val], inp: &ProjectInput) -> Out {
    Out::Seq(items.iter().map(|i| service_volume(i, inp)).collect())
}

fn service_volume(i: &Val, inp: &ProjectInput) -> Out {
    if let Val::Map(_) = i {
        let ty = i
            .get("type")
            .and_then(field_str)
            .unwrap_or_else(|| "volume".into());
        let mut m: Vec<(String, Out)> = vec![("type".into(), Out::Str(ty.clone()))];
        if let Some(src) = i.get("source").and_then(field_str) {
            let src = if ty == "bind" {
                abs_path(&src, inp.dir)
            } else {
                src
            };
            m.push(("source".into(), Out::Str(src)));
        }
        if let Some(t) = i.get("target").and_then(field_str) {
            m.push(("target".into(), Out::Str(t)));
        }
        if i.get("read_only").and_then(field_bool) == Some(true) {
            m.push(("read_only".into(), Out::Bool(true)));
        }
        if let Some(c) = i.get("consistency").and_then(field_str) {
            m.push(("consistency".into(), Out::Str(c)));
        }
        match ty.as_str() {
            // A long-form bind prints `bind:` only when the file wrote one; the short form always
            // has it (compose-go fills it in when it expands the string).
            "bind" if i.get("bind").is_some() => m.push((
                "bind".into(),
                match i.get("bind") {
                    Some(b @ Val::Map(_)) => {
                        let mut bm: Vec<(String, Out)> = Vec::new();
                        for k in ["selinux", "propagation"] {
                            if let Some(s) = b.get(k).and_then(field_str) {
                                bm.push((k.into(), Out::Str(s)));
                            }
                        }
                        if let Some(c) = b.get("create_host_path").and_then(field_bool) {
                            bm.push(("create_host_path".into(), Out::Bool(c)));
                        }
                        if let Some(r) = b.get("recursive").and_then(field_str) {
                            bm.push(("recursive".into(), Out::Str(r)));
                        }
                        Out::Map(bm)
                    }
                    _ => Out::Map(Vec::new()),
                },
            )),
            "volume" => m.push((
                "volume".into(),
                match i.get("volume") {
                    Some(vv @ Val::Map(_)) => {
                        let mut vm: Vec<(String, Out)> = Vec::new();
                        if let Some(l) = vv.get("labels") {
                            vm.push(("labels".into(), mapping(l, false, None)));
                        }
                        if vv.get("nocopy").and_then(field_bool) == Some(true) {
                            vm.push(("nocopy".into(), Out::Bool(true)));
                        }
                        if let Some(s) = vv.get("subpath").and_then(field_str) {
                            vm.push(("subpath".into(), Out::Str(s)));
                        }
                        Out::Map(vm)
                    }
                    _ => Out::Map(Vec::new()),
                },
            )),
            "tmpfs" => {
                if let Some(t @ Val::Map(_)) = i.get("tmpfs") {
                    let mut tm: Vec<(String, Out)> = Vec::new();
                    if let Some(sz) = t.get("size").and_then(unit_bytes) {
                        tm.push(("size".into(), sz));
                    }
                    if let Some(Val::Scalar(raw, _)) = t.get("mode") {
                        if let Typed::Int(n) = resolve(raw) {
                            tm.push(("mode".into(), Out::Int(n)));
                        }
                    }
                    m.push(("tmpfs".into(), Out::Map(tm)));
                }
            }
            _ => {}
        }
        return Out::Map(m);
    }
    // Short syntax: `[source:]target[:mode]`.
    let spec = scalar_text(i).unwrap_or_default();
    let parts: Vec<&str> = spec.split(':').collect();
    let (source, target, opts) = match parts.as_slice() {
        [t] => (None, (*t).to_string(), ""),
        [s, t] => (Some((*s).to_string()), (*t).to_string(), ""),
        [s, t, o, ..] => (Some((*s).to_string()), (*t).to_string(), *o),
        [] => (None, String::new(), ""),
    };
    let is_bind = source
        .as_deref()
        .is_some_and(|s| s.starts_with('.') || s.starts_with('/') || s.starts_with('~'));
    let ty = if is_bind { "bind" } else { "volume" };
    let mut m: Vec<(String, Out)> = vec![("type".into(), Out::str(ty))];
    if let Some(s) = source {
        let s = if is_bind { abs_path(&s, inp.dir) } else { s };
        m.push(("source".into(), Out::Str(s)));
    }
    m.push(("target".into(), Out::Str(target)));
    let opts: Vec<&str> = opts.split(',').filter(|o| !o.is_empty()).collect();
    if opts.contains(&"ro") {
        m.push(("read_only".into(), Out::Bool(true)));
    }
    if is_bind {
        let mut bm: Vec<(String, Out)> = Vec::new();
        if let Some(z) = opts.iter().find(|o| matches!(**o, "z" | "Z")) {
            bm.push(("selinux".into(), Out::str(*z)));
        }
        if let Some(p) = opts.iter().find(|o| {
            matches!(
                **o,
                "shared" | "rshared" | "slave" | "rslave" | "private" | "rprivate"
            )
        }) {
            bm.push(("propagation".into(), Out::str(*p)));
        }
        m.push(("bind".into(), Out::Map(bm)));
    } else {
        let mut vm: Vec<(String, Out)> = Vec::new();
        if opts.contains(&"nocopy") {
            vm.push(("nocopy".into(), Out::Bool(true)));
        }
        m.push(("volume".into(), Out::Map(vm)));
    }
    Out::Map(m)
}

/// A top-level network: its name is `<project>_<key>` unless it is external (its own name) or
/// names itself.
fn network(key: &str, v: &Val, inp: &ProjectInput) -> Out {
    let external = v.get("external").and_then(field_bool) == Some(true);
    let name = v.get("name").and_then(field_str).unwrap_or_else(|| {
        if external {
            key.to_string()
        } else {
            format!("{}_{key}", inp.name)
        }
    });
    let mut m: Vec<(String, Out)> = vec![("name".into(), Out::Str(name))];
    if let Some(d) = v.get("driver").and_then(field_str) {
        m.push(("driver".into(), Out::Str(d)));
    }
    if let Some(d) = v.get("driver_opts") {
        m.push(("driver_opts".into(), mapping(d, false, None)));
    }
    if let Some(ipam) = v.get("ipam") {
        let mut im: Vec<(String, Out)> = Vec::new();
        if let Some(d) = ipam.get("driver").and_then(field_str) {
            im.push(("driver".into(), Out::Str(d)));
        }
        if let Some(Val::Seq(pools)) = ipam.get("config") {
            let ps = pools
                .iter()
                .map(|p| {
                    let mut pm: Vec<(String, Out)> = Vec::new();
                    for k in ["subnet", "gateway", "ip_range"] {
                        if let Some(s) = p.get(k).and_then(field_str) {
                            pm.push((k.into(), Out::Str(s)));
                        }
                    }
                    if let Some(a) = p.get("aux_addresses") {
                        pm.push(("aux_addresses".into(), mapping(a, false, None)));
                    }
                    Out::Map(pm)
                })
                .collect();
            im.push(("config".into(), Out::Seq(ps)));
        }
        if let Some(o) = ipam.get("options") {
            im.push(("options".into(), mapping(o, false, None)));
        }
        m.push(("ipam".into(), Out::Map(im)));
    } else if inp.json {
        m.push(("ipam".into(), Out::Map(Vec::new())));
    }
    if external {
        m.push(("external".into(), Out::Bool(true)));
    }
    for k in ["internal", "attachable"] {
        if v.get(k).and_then(field_bool) == Some(true) {
            m.push((k.into(), Out::Bool(true)));
        }
    }
    if let Some(l) = v.get("labels") {
        m.push(("labels".into(), mapping(l, false, None)));
    }
    for k in ["enable_ipv4", "enable_ipv6"] {
        if let Some(b) = v.get(k).and_then(field_bool) {
            m.push((k.into(), Out::Bool(b)));
        }
    }
    Out::Map(m)
}

/// A top-level volume, named as a network is.
fn volume(key: &str, v: &Val, inp: &ProjectInput) -> Out {
    let external = v.get("external").and_then(field_bool) == Some(true);
    let name = v.get("name").and_then(field_str).unwrap_or_else(|| {
        if external {
            key.to_string()
        } else {
            format!("{}_{key}", inp.name)
        }
    });
    let mut m: Vec<(String, Out)> = vec![("name".into(), Out::Str(name))];
    if let Some(d) = v.get("driver").and_then(field_str) {
        m.push(("driver".into(), Out::Str(d)));
    }
    if let Some(d) = v.get("driver_opts") {
        m.push(("driver_opts".into(), mapping(d, false, None)));
    }
    if external {
        m.push(("external".into(), Out::Bool(true)));
    }
    if let Some(l) = v.get("labels") {
        m.push(("labels".into(), mapping(l, false, None)));
    }
    Out::Map(m)
}

/// A top-level secret or config (`FileObjectConfig`): name, file (absolute), environment, content,
/// external, labels, driver, driver_opts, template_driver.
fn secret_or_config(key: &str, v: &Val, inp: &ProjectInput) -> Out {
    let external = v.get("external").and_then(field_bool) == Some(true);
    let name = v.get("name").and_then(field_str).unwrap_or_else(|| {
        if external {
            key.to_string()
        } else {
            format!("{}_{key}", inp.name)
        }
    });
    let mut m: Vec<(String, Out)> = vec![("name".into(), Out::Str(name))];
    if let Some(f) = v.get("file").and_then(field_str) {
        m.push(("file".into(), Out::Str(abs_path(&f, inp.dir))));
    }
    for k in ["environment", "content"] {
        if let Some(s) = v.get(k).and_then(field_str) {
            m.push((k.into(), Out::Str(s)));
        }
    }
    if external {
        m.push(("external".into(), Out::Bool(true)));
    }
    if let Some(l) = v.get("labels") {
        m.push(("labels".into(), mapping(l, false, None)));
    }
    if let Some(d) = v.get("driver").and_then(field_str) {
        m.push(("driver".into(), Out::Str(d)));
    }
    if let Some(d) = v.get("driver_opts") {
        m.push(("driver_opts".into(), mapping(d, false, None)));
    }
    if let Some(t) = v.get("template_driver").and_then(field_str) {
        m.push(("template_driver".into(), Out::Str(t)));
    }
    Out::Map(m)
}

/// A value with no schema (an extension, a block kern does not model): mappings sorted as a Go
/// `map[string]any`, scalars by their YAML type.
fn generic(v: &Val) -> Out {
    match v {
        Val::Null => Out::Null,
        Val::Scalar(s, true) => Out::Str(s.clone()),
        Val::Scalar(s, false) => match resolve(s) {
            Typed::Null => Out::Null,
            Typed::Bool(b) => Out::Bool(b),
            Typed::Int(i) => Out::Int(i),
            Typed::Float(f) => Out::Float(go_format_float(f, 64)),
            Typed::Time(t) => Out::Str(t),
            Typed::Str(s) => Out::Str(s),
        },
        Val::Seq(items) => Out::Seq(items.iter().map(generic).collect()),
        Val::Map(m) => go_map(m.iter().map(|(k, v)| (k.clone(), generic(v))).collect()),
    }
}

/// Every string the project holds, with `$` written `$$`, as compose-go prints a resolved model so
/// that reading it back does not interpolate a second time.
pub fn escape_dollars(o: Out) -> Out {
    match o {
        Out::Str(s) => Out::Str(s.replace('$', "$$")),
        Out::Seq(v) => Out::Seq(v.into_iter().map(escape_dollars).collect()),
        Out::Map(m) => Out::Map(m.into_iter().map(|(k, v)| (k, escape_dollars(v))).collect()),
        other => other,
    }
}

/// Every path a file writes, resolved against THAT file's directory, before files are merged: an
/// `include:`d file or a second `-f` in another directory names paths relative to itself. Covers
/// `build` (its context), the bind sources of `volumes`, `env_file`, and the `file` of a top-level
/// secret or config. A URL build context is left as it is.
pub fn absolutize(v: Val, dir: &std::path::Path) -> Val {
    let Val::Map(mut top) = v else {
        return v;
    };
    for (k, val) in &mut top {
        match k.as_str() {
            "services" => {
                if let Val::Map(svcs) = val {
                    for (_, svc) in svcs.iter_mut() {
                        absolutize_service(svc, dir);
                    }
                }
            }
            "secrets" | "configs" => {
                if let Val::Map(defs) = val {
                    for (_, d) in defs.iter_mut() {
                        if let Val::Map(m) = d {
                            for (dk, dv) in m.iter_mut() {
                                if dk == "file" {
                                    abs_scalar(dv, dir);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Val::Map(top)
}

fn abs_scalar(v: &mut Val, dir: &std::path::Path) {
    if let Val::Scalar(s, q) = v {
        *v = Val::Scalar(abs_path(s, dir), *q);
    }
}

fn absolutize_service(svc: &mut Val, dir: &std::path::Path) {
    let Val::Map(m) = svc else {
        return;
    };
    for (k, val) in m.iter_mut() {
        match k.as_str() {
            "build" => match val {
                Val::Scalar(s, _) if !(s.contains("://") || s.starts_with("git@")) => {
                    abs_scalar(val, dir)
                }
                Val::Map(bm) => {
                    for (bk, bv) in bm.iter_mut() {
                        if bk == "context" {
                            if let Val::Scalar(s, _) = bv {
                                if !(s.contains("://") || s.starts_with("git@")) {
                                    abs_scalar(bv, dir);
                                }
                            }
                        }
                    }
                }
                _ => {}
            },
            "env_file" => match val {
                Val::Scalar(..) => abs_scalar(val, dir),
                Val::Seq(items) => {
                    for i in items.iter_mut() {
                        match i {
                            Val::Scalar(..) => abs_scalar(i, dir),
                            Val::Map(em) => {
                                for (ek, ev) in em.iter_mut() {
                                    if ek == "path" {
                                        abs_scalar(ev, dir);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            },
            "volumes" => {
                if let Val::Seq(items) = val {
                    for i in items.iter_mut() {
                        match i {
                            Val::Scalar(spec, q) => {
                                let mut parts: Vec<String> =
                                    spec.split(':').map(str::to_string).collect();
                                let relative = parts.len() >= 2
                                    && parts
                                        .first()
                                        .is_some_and(|s| s.starts_with('.') || s.starts_with('~'));
                                if relative {
                                    if let Some(first) = parts.first_mut() {
                                        *first = abs_path(first, dir);
                                    }
                                    *i = Val::Scalar(parts.join(":"), *q);
                                }
                            }
                            Val::Map(vm) => {
                                let is_bind = vm
                                    .iter()
                                    .any(|(k, v)| k == "type" && v.text() == Some("bind"));
                                if is_bind {
                                    for (vk, vv) in vm.iter_mut() {
                                        if vk == "source" {
                                            abs_scalar(vv, dir);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// `json.MarshalIndent(v, "", "  ")` of the project: two-space indentation, `": "` after a key,
/// `{}`/`[]` for an empty collection, Go's HTML-safe string escapes, no newline at the end.
pub fn emit_json(root: &Out) -> String {
    let mut out = String::new();
    json_value(root, 0, &mut out);
    out
}

fn json_pad(depth: usize, out: &mut String) {
    out.push('\n');
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn json_value(v: &Out, depth: usize, out: &mut String) {
    match v {
        Out::Null => out.push_str("null"),
        Out::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Out::Int(i) => out.push_str(&i.to_string()),
        Out::Float(f) => out.push_str(f),
        Out::Str(s) => json_string(s, out),
        Out::Seq(items) if items.is_empty() => out.push_str("[]"),
        Out::Map(m) if m.is_empty() => out.push_str("{}"),
        Out::Seq(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_pad(depth + 1, out);
                json_value(item, depth + 1, out);
            }
            json_pad(depth, out);
            out.push(']');
        }
        Out::Map(m) => {
            out.push('{');
            for (i, (k, val)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_pad(depth + 1, out);
                json_string(k, out);
                out.push_str(": ");
                json_value(val, depth + 1, out);
            }
            json_pad(depth, out);
            out.push('}');
        }
    }
}

/// A string as Go's `encoding/json` writes it with HTML escaping on (the default): `<`, `>`, `&`,
/// U+2028 and U+2029 as `\u` escapes, a control character as `\u00XX` except `\n`, `\r`, `\t`.
fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------------------------------------
// `config`'s other views, read from the same project the YAML prints.
// ---------------------------------------------------------------------------------------------

/// The services of a printed project, as `(name, service)`.
fn services_of(project: &Out) -> Vec<(&str, &Out)> {
    match project {
        Out::Map(top) => match top.iter().find(|(k, _)| k == "services") {
            Some((_, Out::Map(s))) => s.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn out_get<'a>(m: &'a Out, key: &str) -> Option<&'a Out> {
    match m {
        Out::Map(e) => e.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

/// `config --images`: each service's image, or `<project>-<service>` for one that only builds, in
/// service order (`api.GetImageNameOrDefault`).
pub fn view_images(project: &Out, name: &str) -> Vec<String> {
    services_of(project)
        .into_iter()
        .map(|(svc, s)| match out_get(s, "image") {
            Some(Out::Str(i)) => i.clone(),
            _ => format!("{name}-{svc}"),
        })
        .collect()
}

/// `config --volumes`: the project's volumes a service uses, sorted. Docker prints them in the
/// order of a Go map, which is random (measured: three runs, three orders), so any order is one
/// Docker can print; sorted is the one that is also stable.
pub fn view_volumes(project: &Out) -> Vec<String> {
    let declared: Vec<&str> = match out_get(project, "volumes") {
        Some(Out::Map(v)) => v.iter().map(|(k, _)| k.as_str()).collect(),
        _ => Vec::new(),
    };
    let mut used: Vec<String> = Vec::new();
    for (_, s) in services_of(project) {
        if let Some(Out::Seq(vols)) = out_get(s, "volumes") {
            for v in vols {
                if let (Some(Out::Str(t)), Some(Out::Str(src))) =
                    (out_get(v, "type"), out_get(v, "source"))
                {
                    if t == "volume" && declared.contains(&src.as_str()) && !used.contains(src) {
                        used.push(src.clone());
                    }
                }
            }
        }
    }
    used.sort();
    used
}

/// `config --networks`: the networks a service is on, `default` included, sorted (see
/// [`view_volumes`] for the order).
pub fn view_networks(project: &Out) -> Vec<String> {
    let mut used: Vec<String> = Vec::new();
    for (_, s) in services_of(project) {
        if let Some(Out::Map(nets)) = out_get(s, "networks") {
            for (n, _) in nets {
                if !used.contains(n) {
                    used.push(n.clone());
                }
            }
        }
    }
    used.sort();
    used
}

/// `config --profiles`: every profile any service names, active or not, sorted.
pub fn view_profiles(files: &[Val]) -> Vec<String> {
    let mut set: Vec<String> = Vec::new();
    for f in files {
        if let Some(Val::Map(svcs)) = f.get("services") {
            for (_, s) in svcs {
                for p in strings_of(s.get("profiles")) {
                    if !set.contains(&p) {
                        set.push(p);
                    }
                }
            }
        }
    }
    set.sort();
    set
}

/// The compact JSON `ServiceHash` digests for a service: the service as `--format json` prints it,
/// without `build`, `pull_policy`, `scale`, `deploy.replicas`, `depends_on` and `profiles`, and
/// with no whitespace (`json.Marshal`). `project` must be the JSON-shaped project.
pub fn hash_input(project: &Out, service: &str) -> Option<String> {
    let (_, s) = services_of(project)
        .into_iter()
        .find(|(n, _)| *n == service)?;
    let Out::Map(fields) = s else {
        return None;
    };
    let kept: Vec<(String, Out)> = fields
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "build" | "pull_policy" | "scale" | "depends_on" | "profiles"
            )
        })
        .map(|(k, v)| {
            if k == "deploy" {
                if let Out::Map(d) = v {
                    return (
                        k.clone(),
                        Out::Map(
                            d.iter()
                                .filter(|(dk, _)| dk != "replicas")
                                .cloned()
                                .collect(),
                        ),
                    );
                }
            }
            (k.clone(), v.clone())
        })
        .collect();
    let pretty = emit_json(&Out::Map(kept));
    Some(compact_json(&pretty))
}

/// Pretty JSON from [`emit_json`] without the whitespace between tokens, as `json.Marshal` writes
/// it. Whitespace inside a string is kept.
fn compact_json(pretty: &str) -> String {
    let mut out = String::with_capacity(pretty.len());
    let mut in_str = false;
    let mut escaped = false;
    for c in pretty.chars() {
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            ' ' | '\n' | '\t' | '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// One variable a file references, as `config --variables` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    pub name: String,
    pub required: bool,
    pub default: String,
    pub alternate: String,
}

/// Every `$VAR`/`${VAR...}` a file text references (`template.ExtractVariables`), by name, sorted:
/// `:?`/`?` make it required, `:-`/`-` give a default, `:+`/`+` an alternate value. `$$` is an
/// escape and names nothing; a comment names nothing.
pub fn extract_variables(texts: &[String]) -> Vec<Variable> {
    let mut out: Vec<Variable> = Vec::new();
    for text in texts {
        for line in text.lines() {
            let code = strip_yaml_comment(line);
            let b = code.as_bytes();
            let mut i = 0;
            while i < b.len() {
                if b.get(i) != Some(&b'$') {
                    i += 1;
                    continue;
                }
                if b.get(i + 1) == Some(&b'$') {
                    i += 2;
                    continue;
                }
                if b.get(i + 1) == Some(&b'{') {
                    let start = i + 2;
                    let mut j = start;
                    let mut depth = 1;
                    while j < b.len() && depth > 0 {
                        match b.get(j) {
                            Some(b'{') => depth += 1,
                            Some(b'}') => depth -= 1,
                            _ => {}
                        }
                        j += 1;
                    }
                    let inner = code.get(start..j.saturating_sub(1)).unwrap_or("");
                    if let Some(v) = parse_braced(inner) {
                        add_variable(&mut out, v);
                    }
                    i = j;
                    continue;
                }
                let start = i + 1;
                let mut j = start;
                while b
                    .get(j)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
                {
                    j += 1;
                }
                if j > start && b.get(start).is_some_and(|c| !c.is_ascii_digit()) {
                    add_variable(
                        &mut out,
                        Variable {
                            name: code.get(start..j).unwrap_or("").to_string(),
                            required: false,
                            default: String::new(),
                            alternate: String::new(),
                        },
                    );
                }
                i = j.max(i + 1);
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn add_variable(out: &mut Vec<Variable>, v: Variable) {
    if !out.iter().any(|e| e.name == v.name) {
        out.push(v);
    }
}

fn parse_braced(inner: &str) -> Option<Variable> {
    let end = inner
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(inner.len());
    let name = inner.get(..end)?.to_string();
    if name.is_empty() {
        return None;
    }
    let rest = inner.get(end..).unwrap_or("");
    let mut v = Variable {
        name,
        required: false,
        default: String::new(),
        alternate: String::new(),
    };
    for (op, kind) in [
        (":?", 0),
        ("?", 0),
        (":-", 1),
        ("-", 1),
        (":+", 2),
        ("+", 2),
    ] {
        if let Some(val) = rest.strip_prefix(op) {
            match kind {
                0 => v.required = true,
                1 => v.default = val.to_string(),
                _ => v.alternate = val.to_string(),
            }
            break;
        }
    }
    Some(v)
}

/// A line without its YAML comment: a `#` at the start or after a blank, outside quotes.
fn strip_yaml_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let (mut sq, mut dq) = (false, false);
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'\'' if !dq => sq = !sq,
            b'"' if !sq => dq = !dq,
            b'#' if !sq && !dq && (i == 0 || matches!(b.get(i - 1), Some(b' ' | b'\t'))) => {
                return line.get(..i).unwrap_or(line);
            }
            _ => {}
        }
    }
    line
}

/// The variables table as Docker's formatter prints it: a `tabwriter` with a minimum cell width of
/// 20, one cell of padding... each column as wide as its widest cell plus 3, and at least 20.
pub fn variables_table(vars: &[Variable]) -> String {
    let rows: Vec<[String; 4]> = std::iter::once([
        "NAME".to_string(),
        "REQUIRED".to_string(),
        "DEFAULT VALUE".to_string(),
        "ALTERNATE VALUE".to_string(),
    ])
    .chain(vars.iter().map(|v| {
        [
            v.name.clone(),
            v.required.to_string(),
            v.default.clone(),
            v.alternate.clone(),
        ]
    }))
    .collect();
    let width = |col: usize| -> usize {
        rows.iter()
            .map(|r| r.get(col).map_or(0, |c| c.chars().count()))
            .max()
            .unwrap_or(0)
            .saturating_add(3)
            .max(20)
    };
    let widths = [width(0), width(1), width(2)];
    let mut out = String::new();
    for r in &rows {
        for (i, cell) in r.iter().enumerate() {
            match widths.get(i) {
                Some(w) => {
                    out.push_str(cell);
                    out.push_str(&" ".repeat(w.saturating_sub(cell.chars().count())));
                }
                None => out.push_str(cell),
            }
        }
        out.push('\n');
    }
    out
}

/// Every mapping sorted by key, as the `--no-interpolate` view prints a model that was never
/// decoded into compose-go's structures.
pub fn sort_all(o: Out) -> Out {
    match o {
        Out::Map(m) => go_map(m.into_iter().map(|(k, v)| (k, sort_all(v))).collect()),
        Out::Seq(v) => Out::Seq(v.into_iter().map(sort_all).collect()),
        other => other,
    }
}

/// The service names of a printed project, in its order.
pub fn service_names(project: &Out) -> Vec<String> {
    services_of(project)
        .into_iter()
        .map(|(n, _)| n.to_string())
        .collect()
}

/// `config SERVICE...`: the project with those services and every service they depend on, as
/// compose-go selects them.
///
/// # Errors
///
/// A name that is not a service of the project, as Docker answers it.
pub fn select_services(project: Out, wanted: &[String]) -> Result<Out, String> {
    let all = service_names(&project);
    for w in wanted {
        if !all.contains(w) {
            return Err(format!("no such service: {w}"));
        }
    }
    let mut keep: Vec<String> = Vec::new();
    let mut queue: Vec<String> = wanted.to_vec();
    while let Some(n) = queue.pop() {
        if keep.contains(&n) {
            continue;
        }
        if let Some((_, s)) = services_of(&project).into_iter().find(|(sn, _)| *sn == n) {
            if let Some(Out::Map(deps)) = out_get(s, "depends_on") {
                for (d, _) in deps {
                    queue.push(d.clone());
                }
            }
        }
        keep.push(n);
    }
    let Out::Map(top) = project else {
        return Ok(project);
    };
    Ok(Out::Map(
        top.into_iter()
            .map(|(k, v)| {
                if k == "services" {
                    if let Out::Map(svcs) = v {
                        return (
                            k,
                            Out::Map(svcs.into_iter().filter(|(n, _)| keep.contains(n)).collect()),
                        );
                    }
                }
                (k, v)
            })
            .collect(),
    ))
}
