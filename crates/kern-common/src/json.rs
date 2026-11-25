//! A strict JSON reader for bodies a client sends (RFC 8259), with the limits a server needs.
//!
//! Not the scanner `kern-oci` keeps for registry manifests: that one finds keys by searching
//! well-formed machine output. A request body is whatever a client wrote, so this one parses the
//! whole text into a tree and refuses anything RFC 8259 does not allow (trailing commas, comments,
//! single quotes, bare words, control bytes in strings, a lone surrogate), with a depth cap so a
//! nested `[[[[...` cannot exhaust the stack, and nothing after the value but whitespace.

/// One JSON value. An object keeps its members in the order written; a repeated key is refused at
/// parse time, so a reader never has to choose between two answers.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// The number as written, checked against the JSON grammar; read it with [`Value::as_i64`] or
    /// [`Value::as_f64`].
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

/// How deep arrays and objects may nest.
pub const MAX_DEPTH: usize = 64;

impl Value {
    /// The member `key` of an object; `None` for a missing key or a non-object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// An integer, when the number is one that fits.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => n.parse().ok(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Obj(m) => Some(m),
            _ => None,
        }
    }

    /// `null` or absent, as a client means "not set".
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// Why a text is not JSON, with the byte offset where it stopped being.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub at: usize,
    pub what: &'static str,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not JSON at byte {}: {}", self.at, self.what)
    }
}

/// Parse `text` as exactly one JSON value.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err("something follows the value"));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self, what: &'static str) -> ParseError {
        ParseError { at: self.i, what }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &[u8]) -> bool {
        if self.b.get(self.i..self.i + lit.len()) == Some(lit) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nested deeper than 64"));
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::Str),
            Some(b't') if self.eat(b"true") => Ok(Value::Bool(true)),
            Some(b'f') if self.eat(b"false") => Ok(Value::Bool(false)),
            Some(b'n') if self.eat(b"null") => Ok(Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("not the start of a value")),
            None => Err(self.err("the text ends where a value was due")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Obj(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("an object key must be a string"));
            }
            let key = self.string()?;
            if members.iter().any(|(k, _)| *k == key) {
                return Err(self.err("a key appears twice in one object"));
            }
            self.ws();
            if !self.eat(b":") {
                return Err(self.err("a ':' was due after the key"));
            }
            self.ws();
            let v = self.value(depth + 1)?;
            members.push((key, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Obj(members));
                }
                _ => return Err(self.err("',' or '}' was due")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(self.err("',' or ']' was due")),
            }
        }
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("a digit was due")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("a digit was due after '.'"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("a digit was due in the exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        let text =
            std::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err("not UTF-8"))?;
        Ok(Value::Num(text.to_string()))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let h = self
            .b
            .get(self.i..self.i + 4)
            .ok_or_else(|| self.err("four hex digits were due after \\u"))?;
        let s = std::str::from_utf8(h).map_err(|_| self.err("not hex"))?;
        let v = u32::from_str_radix(s, 16).map_err(|_| self.err("not hex"))?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1;
        let mut out = String::new();
        loop {
            // The run up to the next quote, backslash or control byte, copied in one piece.
            let start = self.i;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            let run =
                std::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err("not UTF-8"))?;
            out.push_str(run);
            match self.peek() {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let esc = self
                        .peek()
                        .ok_or_else(|| self.err("the text ends in an escape"))?;
                    self.i += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if !self.eat(b"\\u") {
                                    return Err(self.err("a high surrogate without its pair"));
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("a high surrogate without its pair"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err("a low surrogate on its own"));
                            } else {
                                hi
                            };
                            out.push(
                                char::from_u32(cp).ok_or_else(|| self.err("not a character"))?,
                            );
                        }
                        _ => return Err(self.err("not an escape JSON knows")),
                    }
                }
                Some(_) => return Err(self.err("a control byte inside a string")),
                None => return Err(self.err("a string that does not end")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_docker_create_body_reads_whole() {
        let body = r#"{"Image":"nginx:alpine","Cmd":["sh","-c","echo \"hi\""],"Env":["A=1"],
            "ExposedPorts":{"80/tcp":{}},"HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"","HostPort":""}]},
            "AutoRemove":false,"Memory":0},"Labels":{"org.testcontainers":"true"},"Tty":false,"N":-1.5e3}"#;
        let v = parse(body).unwrap_or(Value::Null);
        assert_eq!(v.get("Image").and_then(Value::as_str), Some("nginx:alpine"));
        let cmd: Vec<&str> = v
            .get("Cmd")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(cmd, vec!["sh", "-c", "echo \"hi\""]);
        let pb = v.get("HostConfig").and_then(|h| h.get("PortBindings"));
        assert!(pb
            .and_then(|p| p.get("80/tcp"))
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() == 1));
        assert_eq!(
            v.get("HostConfig")
                .and_then(|h| h.get("Memory"))
                .and_then(Value::as_i64),
            Some(0)
        );
        assert_eq!(v.get("Tty").and_then(Value::as_bool), Some(false));
        assert_eq!(v.get("N").and_then(Value::as_f64), Some(-1500.0));
    }

    #[test]
    fn escapes_and_surrogate_pairs_decode() {
        let v = parse(r#""a\u00e9\ud83d\ude00\n\/""#).unwrap_or(Value::Null);
        assert_eq!(v.as_str(), Some("aé😀\n/"));
    }

    #[test]
    fn what_rfc_8259_does_not_allow_is_refused() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{'a':1}",
            "{a:1}",
            "01",
            "1.",
            "-",
            "1e",
            "tru",
            "\"\\x\"",
            "\"a\u{1}b\"",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "{\"a\":1}{",
            "[1] 2",
            "{\"a\":1,\"a\":2}",
            "/*c*/1",
            "NaN",
            "\"open",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn nesting_is_capped() {
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 2), "]".repeat(MAX_DEPTH + 2));
        assert!(parse(&deep).is_err());
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
    }
}
