//! `--egress-secret`: a header the egress proxy adds to a box's requests, so the code in the box
//! never holds the key it is using.
//!
//! THE MODEL. The box reaches the internet only through kern's filtering proxy (see `egress.rs`).
//! For a host with a secret rule, the box sends PLAIN HTTP to that host (`http://api.example.com/v1/
//! ...`, through `HTTP_PROXY`, which kern sets), with no key. The proxy, on the host:
//!
//! 1. vets the host and every address it resolves to exactly as for any other request;
//! 2. drops any header of the rule's name the box sent, so the box cannot choose the value, and the
//!    connection-level headers that belong to the box's leg;
//! 3. sends the request to `https://<host>` itself, with the rule's header, through the host's
//!    `curl` (kern has no TLS stack; it already uses that `curl` to pull images), pinned with
//!    `--resolve` to the address step 1 vetted, so the name cannot be re-resolved elsewhere;
//! 4. relays the answer, with every verbatim occurrence of the secret replaced by `[kern-secret]`,
//!    so an upstream that echoes request headers back does not hand the key to the box.
//!
//! The value is read by the kern that starts the box (from its own environment or a file), handed to
//! the proxy over a pipe, never in an argv (which any process of the machine can read) and never in
//! the box's environment. The proxy marks itself non-dumpable. A `CONNECT` to a host with a rule is
//! refused: it would be the box's own TLS, without the key, and the answer would be a confusing 401.
//!
//! What it does not do: a key the upstream echoes in pieces, or transformed, is not recognised; a
//! body sent with `Transfer-Encoding: chunked` is refused with 411 (bodies need a length); WebSocket
//! upgrades are refused with 501.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;

/// One rule as the proxy holds it: requests to `host` get `header: value`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretRule {
    pub(crate) host: String,
    pub(crate) header: String,
    /// The header's full value (`Bearer <key>` with a scheme).
    pub(crate) value: String,
    /// The secret alone, what the answer is scrubbed of.
    pub(crate) secret: String,
}

/// Never print a value: a rule shows up in debug output and error paths.
impl std::fmt::Debug for SecretRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SecretRule {{ host: {:?}, header: {:?}, value: <{} bytes> }}",
            self.host,
            self.header,
            self.value.len()
        )
    }
}

/// Where a rule's value comes from, as written on the command line. Holds no value, so it is what
/// the box's recorded arguments, `ps` and `inspect` carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretSpec {
    pub host: String,
    pub header: String,
    source: Source,
    scheme: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    Env(String),
    File(String),
}

/// The usage line, in one place.
pub const USAGE: &str =
    "--egress-secret host=<domain>,header=<name>,env=<VAR>|file=<path>[,scheme=<Bearer|...>]";

/// Shortest secret kern accepts: shorter, scrubbing it from answers would rewrite ordinary text.
const MIN_SECRET: usize = 8;
/// Longest header value kern sends.
const MAX_VALUE: usize = 8 * 1024;

/// Headers a rule may not set: they frame the request or belong to one connection, so the proxy
/// owns them.
const RESERVED: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
    "expect",
];

/// RFC 9110 `token`: the characters of a header name, a method and an auth scheme.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

impl SecretSpec {
    /// `host=H,header=N,env=VAR|file=PATH[,scheme=S]`. Every key once; nothing else.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let bad = |why: &str| format!("--egress-secret '{spec}': {why} ({USAGE})");
        let (mut host, mut header, mut source, mut scheme) = (None, None, None, None);
        for part in spec.split(',') {
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| bad(&format!("'{part}' is not key=value")))?;
            let (k, v) = (k.trim(), v.trim());
            let slot_taken = match k {
                "host" => host.replace(v.to_string()).is_some(),
                "header" => header.replace(v.to_string()).is_some(),
                "env" => source.replace(Source::Env(v.to_string())).is_some(),
                "file" => source.replace(Source::File(v.to_string())).is_some(),
                "scheme" => scheme.replace(v.to_string()).is_some(),
                other => return Err(bad(&format!("unknown key '{other}'"))),
            };
            if slot_taken {
                return Err(bad(&format!(
                    "'{k}' given twice (env and file count as one)"
                )));
            }
        }
        let host = host.ok_or_else(|| bad("host= is missing"))?;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.contains('*') || !super::valid_allow_entry(&host) {
            return Err(bad("host must be one domain, with no wildcard"));
        }
        let header = header.ok_or_else(|| bad("header= is missing"))?;
        if !is_token(&header) {
            return Err(bad("header= is not a header name"));
        }
        if RESERVED.contains(&header.to_ascii_lowercase().as_str()) {
            return Err(bad(&format!(
                "header {header} frames the request or belongs to one connection, so the proxy \
                 owns it"
            )));
        }
        let source = source.ok_or_else(|| bad("env= or file= is missing"))?;
        match &source {
            Source::Env(var) if var.is_empty() || var.contains('=') => {
                return Err(bad("env= names a variable"))
            }
            Source::File(path) if !path.starts_with('/') => {
                return Err(bad("file= is an absolute path"))
            }
            _ => {}
        }
        if let Some(s) = &scheme {
            if !is_token(s) {
                return Err(bad("scheme= is one word (Bearer, Token, ...)"));
            }
        }
        Ok(Self {
            host,
            header,
            source,
            scheme,
        })
    }

    /// The rule, with the value read NOW: from `env` (this kern's environment) or the file. A file's
    /// one trailing newline is not part of the value.
    pub fn resolve(&self, env: impl Fn(&str) -> Option<OsString>) -> Result<SecretRule, String> {
        let raw = match &self.source {
            Source::Env(var) => env(var)
                .ok_or_else(|| {
                    format!(
                        "--egress-secret for {}: the variable {var} is not set in the environment \
                         kern was started from",
                        self.host
                    )
                })?
                .into_string()
                .map_err(|_| format!("--egress-secret for {}: {var} is not UTF-8", self.host))?,
            Source::File(path) => std::fs::read_to_string(path)
                .map_err(|e| format!("--egress-secret for {}: {path}: {e}", self.host))?,
        };
        let secret = raw
            .strip_suffix("\r\n")
            .or_else(|| raw.strip_suffix('\n'))
            .unwrap_or(&raw)
            .to_string();
        if secret.bytes().any(|c| c < 0x20 || c == 0x7f) {
            return Err(format!(
                "--egress-secret for {}: the value carries a control character (a newline inside \
                 it?), which no header can hold",
                self.host
            ));
        }
        if secret.len() < MIN_SECRET {
            return Err(format!(
                "--egress-secret for {}: the value is {} bytes; kern takes {MIN_SECRET} or more, \
                 so it can tell the key from ordinary text in an answer",
                self.host,
                secret.len()
            ));
        }
        let value = match &self.scheme {
            Some(s) => format!("{s} {secret}"),
            None => secret.clone(),
        };
        if value.len() > MAX_VALUE {
            return Err(format!(
                "--egress-secret for {}: the value is longer than {MAX_VALUE} bytes",
                self.host
            ));
        }
        Ok(SecretRule {
            host: self.host.clone(),
            header: self.header.clone(),
            value,
            secret,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Launcher to proxy: the rules over a pipe.

const MAGIC: &[u8] = b"kern-egress-secrets-1\n";

fn put(out: &mut Vec<u8>, s: &str) {
    let n = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// The bytes the launcher writes into the proxy's pipe.
pub(crate) fn encode(rules: &[SecretRule]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    for r in rules {
        put(&mut out, &r.host);
        put(&mut out, &r.header);
        put(&mut out, &r.value);
        put(&mut out, &r.secret);
    }
    out
}

/// Read what [`encode`] wrote. `None` on any malformed byte: the proxy then refuses to start, so a
/// box never runs with fewer rules than were asked for.
pub(crate) fn decode(bytes: &[u8]) -> Option<Vec<SecretRule>> {
    let mut rest = bytes.strip_prefix(MAGIC)?;
    let mut take = || -> Option<String> {
        let (len, tail) = rest.split_at_checked(4)?;
        let n = usize::try_from(u32::from_le_bytes(len.try_into().ok()?)).ok()?;
        let (s, tail) = tail.split_at_checked(n)?;
        rest = tail;
        String::from_utf8(s.to_vec()).ok()
    };
    let mut rules = Vec::new();
    while let Some(host) = take() {
        let header = take()?;
        let value = take()?;
        let secret = take()?;
        if !is_token(&header) || value.bytes().any(|c| c < 0x20 || c == 0x7f) {
            return None;
        }
        rules.push(SecretRule {
            host,
            header,
            value,
            secret,
        });
    }
    // `take` stops at the end only when nothing is left; a stray byte is a malformed stream.
    rest.is_empty().then_some(rules)
}

/// The rule for `host`, by exact name: a subdomain of a rule's host gets no key.
pub(crate) fn rule_for<'a>(rules: &'a [SecretRule], host: &str) -> Option<&'a SecretRule> {
    let h = super::normalized_host(host)?;
    rules.iter().find(|r| r.host == h)
}

// ---------------------------------------------------------------------------------------------
// The answer, scrubbed of the secret.

/// What a verbatim occurrence of the secret becomes in an answer.
pub(crate) const MARK: &[u8] = b"[kern-secret]";

/// A streaming replace of `needle` by [`MARK`]: bytes are released as soon as they can no longer be
/// the start of an occurrence, so a streamed answer (server-sent events) keeps streaming.
pub(crate) struct Scrub<'a> {
    needle: &'a [u8],
    carry: Vec<u8>,
}

impl<'a> Scrub<'a> {
    pub(crate) fn new(needle: &'a [u8]) -> Self {
        Self {
            needle,
            carry: Vec::with_capacity(needle.len() * 2),
        }
    }

    pub(crate) fn push(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.carry.extend_from_slice(data);
        let n = self.needle.len();
        let Some(&first) = self.needle.first() else {
            out.append(&mut self.carry);
            return;
        };
        let mut i = 0;
        while i + n <= self.carry.len() {
            // Copy up to the next byte that could start an occurrence in one go.
            match self.carry[i..].iter().position(|&c| c == first) {
                None => {
                    out.extend_from_slice(&self.carry[i..]);
                    i = self.carry.len();
                    break;
                }
                Some(off) => {
                    out.extend_from_slice(&self.carry[i..i + off]);
                    i += off;
                }
            }
            if i + n > self.carry.len() {
                break;
            }
            if &self.carry[i..i + n] == self.needle {
                out.extend_from_slice(MARK);
                i += n;
            } else {
                out.push(self.carry[i]);
                i += 1;
            }
        }
        self.carry.drain(..i);
    }

    /// The bytes held back at the end: fewer than the needle, so they cannot be one.
    pub(crate) fn finish(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.carry);
    }
}

// ---------------------------------------------------------------------------------------------
// The request the proxy sends.

/// The request, ready for `curl`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Outgoing {
    pub(crate) method: String,
    pub(crate) url: String,
    pub(crate) upstream_port: u16,
    /// One `Name: value` a line, for `curl -H @file`: the box's headers minus the ones the proxy
    /// owns, then the rule's.
    pub(crate) headers: String,
    pub(crate) body_len: u64,
    pub(crate) expect_continue: bool,
}

/// A refusal of the box's request, as a status and the reason the body carries.
pub(crate) type Reject = (u16, &'static str);

/// Build the outgoing request from the box's head (`request_line`, then the header lines). The head
/// already passed `httphead::framing`, so its lines are CRLF-separated, its names are tokens and it
/// carries at most one valid `Content-Length`.
pub(crate) fn outgoing(
    request_line: &str,
    headers: &str,
    host: &str,
    port: u16,
    rule: &SecretRule,
) -> Result<Outgoing, Reject> {
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target), Some(_version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err((400, "the request line is not METHOD TARGET VERSION"));
    };
    if !is_token(method) {
        return Err((400, "the method is not a token"));
    }
    // The proxied target is absolute (`http://host[:port]/path`); the path is what follows the
    // authority, and the authority is the host the proxy already vetted.
    let after_scheme = target.strip_prefix("http://").ok_or((
        400,
        "a request through the proxy names an absolute http:// URL",
    ))?;
    let path = match after_scheme.find(['/', '?']) {
        Some(at) if after_scheme[at..].starts_with('?') => format!("/{}", &after_scheme[at..]),
        Some(at) => after_scheme[at..].to_string(),
        None => "/".to_string(),
    };
    let upstream_port = if port == 80 { 443 } else { port };
    let url = if upstream_port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{upstream_port}{path}")
    };
    // The names `Connection` lists are this leg's too.
    let mut dropped: Vec<String> = RESERVED.iter().map(|s| (*s).to_string()).collect();
    dropped.push(rule.header.to_ascii_lowercase());
    for line in headers.split("\r\n") {
        if let Some((n, v)) = line.split_once(':') {
            if n.trim().eq_ignore_ascii_case("connection") {
                dropped.extend(
                    v.split(',')
                        .map(|t| t.trim().to_ascii_lowercase())
                        .filter(|t| !t.is_empty()),
                );
            }
        }
    }
    let mut out = String::new();
    let mut body_len = 0u64;
    let mut expect_continue = false;
    let (mut has_ua, mut has_accept) = (false, false);
    for line in headers.split("\r\n").filter(|l| !l.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let lower = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match lower.as_str() {
            "transfer-encoding" => return Err((411, "a body needs a Content-Length here")),
            "upgrade" => return Err((501, "upgrades (WebSocket) are not relayed")),
            "content-length" => {
                body_len = value
                    .parse()
                    .map_err(|_| (400, "Content-Length is not a number"))?;
                continue;
            }
            "expect" => {
                expect_continue = value.eq_ignore_ascii_case("100-continue");
                continue;
            }
            _ => {}
        }
        if dropped.contains(&lower) {
            continue;
        }
        has_ua |= lower == "user-agent";
        has_accept |= lower == "accept";
        out.push_str(name.trim());
        out.push_str(": ");
        out.push_str(value);
        out.push('\n');
    }
    out.push_str(&rule.header);
    out.push_str(": ");
    out.push_str(&rule.value);
    out.push('\n');
    // curl's own defaults stay out of a request the box shaped: an empty value removes them.
    out.push_str("Expect:\n");
    if !has_ua {
        out.push_str("User-Agent:\n");
    }
    if !has_accept {
        out.push_str("Accept:\n");
    }
    Ok(Outgoing {
        method: method.to_string(),
        url,
        upstream_port,
        headers: out,
        body_len,
        expect_continue,
    })
}

/// `curl`'s argv for `o`, pinned to `ip`, reading the headers from descriptor `headers_fd`. `-q`
/// first: no `.curlrc` changes what is sent.
pub(crate) fn curl_args(
    o: &Outgoing,
    host: &str,
    ip: std::net::IpAddr,
    headers_fd: i32,
) -> Vec<String> {
    let addr = match ip {
        std::net::IpAddr::V6(a) => format!("[{a}]"),
        std::net::IpAddr::V4(a) => a.to_string(),
    };
    let mut a: Vec<String> = [
        "-q",
        "--silent",
        "--show-error",
        "--http1.1",
        "--include",
        "--no-buffer",
        "--path-as-is",
        "--globoff",
        "--proto",
        "=https",
        "--max-redirs",
        "0",
        "--connect-timeout",
        "10",
        "--noproxy",
        "*",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    a.push("-H".to_string());
    a.push(format!("@/dev/fd/{headers_fd}"));
    a.push("--resolve".to_string());
    a.push(format!("{host}:{}:{addr}", o.upstream_port));
    if o.method.eq_ignore_ascii_case("HEAD") {
        a.push("--head".to_string());
    } else {
        a.push("--request".to_string());
        a.push(o.method.clone());
    }
    if o.body_len > 0 {
        a.push("--data-binary".to_string());
        a.push("@-".to_string());
    }
    a.push("--url".to_string());
    a.push(o.url.clone());
    a
}

/// The answer's head as the box gets it: informational heads already skipped by the caller; the
/// framing of the upstream leg (`Transfer-Encoding`, `Content-Length`, which curl decoded and the
/// scrub may change) and its connection headers removed; `Connection: close`, so the body ends where
/// the stream ends.
pub(crate) fn rewrite_response_head(head: &str) -> String {
    let mut lines = head.split("\r\n").filter(|l| !l.is_empty());
    let mut out = String::new();
    if let Some(status) = lines.next() {
        out.push_str(status);
        out.push_str("\r\n");
    }
    for line in lines {
        let name = line
            .split_once(':')
            .map_or("", |(n, _)| n)
            .trim()
            .to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "transfer-encoding"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
        ) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

/// Is this head an informational (1xx) one, which curl prints before the final answer?
fn informational(head: &str) -> bool {
    head.split_whitespace()
        .nth(1)
        .is_some_and(|code| code.len() == 3 && code.starts_with('1'))
}

fn reject(client: &mut impl Write, status: u16, why: &str) {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        411 => "Length Required",
        501 => "Not Implemented",
        _ => "Bad Gateway",
    };
    let body = format!("kern: egress secret: {why}\n");
    let _ = write!(
        client,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// The answer to a `CONNECT` for a host with a rule.
pub(crate) fn refuse_connect(client: &mut impl Write) {
    reject(
        client,
        403,
        "this host gets its key from kern: send plain http:// requests to it through the proxy",
    );
}

/// Serve one request to a host with a rule (see the module comment). `head` is everything read up to
/// and including the blank line; the body, if any, is still in `client`.
pub(crate) fn serve(
    mut client: std::os::unix::net::UnixStream,
    request_line: &str,
    headers: &str,
    host: &str,
    port: u16,
    rule: &SecretRule,
    policy: &super::EgressPolicy,
) {
    let o = match outgoing(request_line, headers, host, port, rule) {
        Ok(o) => o,
        Err((status, why)) => return reject(&mut client, status, why),
    };
    // THE ADDRESS IS VETTED HERE, by the proxy's own rules, and curl is pinned to it: curl resolving
    // the name itself would be a second answer the rules never saw (DNS rebinding to 127.0.0.1).
    let ip = match super::vetted_addrs(host, o.upstream_port, policy) {
        Ok(addrs) => match addrs.first() {
            Some(a) => a.ip(),
            None => return reject(&mut client, 502, "the host did not resolve"),
        },
        Err(_) => {
            return reject(
                &mut client,
                502,
                "the host's addresses are not open to this box",
            )
        }
    };
    let mut hfds = [0i32; 2];
    // SAFETY: pipe2 into a local array of two descriptors.
    if unsafe { libc::pipe2(hfds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return reject(&mut client, 502, "no pipe for the request headers");
    }
    let (hr, hw) = (hfds[0], hfds[1]);
    // The headers fit the pipe (a head is at most 16 KiB, a value 8 KiB): written before the spawn,
    // then the write end closed, so curl reads them to EOF.
    {
        // SAFETY: `hw` is the write end just created and owned by nothing else.
        let mut w = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(hw) };
        if w.write_all(o.headers.as_bytes()).is_err() {
            // SAFETY: closing the read end created above.
            unsafe { libc::close(hr) };
            return reject(
                &mut client,
                502,
                "the request headers could not be handed over",
            );
        }
    }
    let path = crate::global_env("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin"));
    let mut cmd = std::process::Command::new("curl");
    cmd.args(curl_args(&o, host, ip, hr))
        .env_clear()
        .env("PATH", path)
        .stdin(if o.body_len > 0 {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // THE HEADERS' DESCRIPTOR KEEPS ITS NUMBER: its close-on-exec flag is cleared in the child alone,
    // rather than moved onto a fixed number that could already be one of std's own descriptors.
    // SAFETY: fcntl only, async-signal-safe, in the forked child before exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::fcntl(hr, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawned = cmd.spawn();
    // SAFETY: the parent's copy of the read end; the child keeps its own.
    unsafe { libc::close(hr) };
    let mut child = match spawned {
        Ok(c) => c,
        Err(_) => {
            return reject(
                &mut client,
                502,
                "curl could not be started on this machine",
            )
        }
    };
    if o.expect_continue {
        let _ = client.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    // THE BODY, exactly its length, on a thread of its own: curl may start answering before the body
    // is all sent, and one thread doing both could fill one pipe while waiting on the other.
    let feeder = match (child.stdin.take(), client.try_clone()) {
        (Some(mut stdin), Ok(mut from)) => {
            let n = o.body_len;
            let _ = from.set_read_timeout(Some(std::time::Duration::from_secs(60)));
            Some(std::thread::spawn(move || {
                let mut limited = (&mut from).take(n);
                let _ = std::io::copy(&mut limited, &mut stdin);
            }))
        }
        (Some(_), Err(_)) => {
            let _ = child.kill();
            let _ = child.wait();
            return reject(&mut client, 502, "the request body could not be relayed");
        }
        (None, _) => None,
    };
    let relayed = match child.stdout.take() {
        Some(out) => relay_answer(out, &mut client, rule.secret.as_bytes()),
        None => Relayed::NoHead,
    };
    // The box went away mid-answer: curl is stopped, not waited for (a stream can last minutes).
    if relayed == Relayed::BoxGone {
        let _ = child.kill();
    }
    if let Some(f) = feeder {
        let _ = f.join();
    }
    let sent = relayed != Relayed::NoHead;
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.by_ref().take(4096).read_to_string(&mut err);
    }
    let _ = child.wait();
    if !sent {
        let line = err
            .lines()
            .last()
            .unwrap_or("no answer")
            .replace(&rule.secret, "[kern-secret]");
        reject(
            &mut client,
            502,
            &format!("{host}: the request got no answer ({line})"),
        );
    }
}

/// How the relay of an answer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relayed {
    /// curl ended before a head: the caller answers 502.
    NoHead,
    /// The answer reached the box to its end.
    Done,
    /// The box stopped reading.
    BoxGone,
}

/// Relay curl's output to the box: skip informational heads, rewrite the final head, then stream
/// the body, all through the scrub.
fn relay_answer(
    mut from: std::process::ChildStdout,
    client: &mut std::os::unix::net::UnixStream,
    needle: &[u8],
) -> Relayed {
    let mut scrub = Scrub::new(needle);
    let mut buf = vec![0u8; 16 * 1024];
    let mut pending: Vec<u8> = Vec::new();
    // Heads first.
    let body_start = loop {
        let Some(end) = super::head_end(&pending) else {
            if pending.len() > 64 * 1024 {
                return Relayed::NoHead;
            }
            match from.read(&mut buf) {
                Ok(0) | Err(_) => return Relayed::NoHead,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
            continue;
        };
        let head = String::from_utf8_lossy(&pending[..end]).into_owned();
        if informational(&head) {
            pending.drain(..end);
            continue;
        }
        let rewritten = rewrite_response_head(&head);
        let mut out = Vec::with_capacity(rewritten.len());
        scrub.push(rewritten.as_bytes(), &mut out);
        // The head is complete: nothing of it may wait in the scrub for the body's first bytes.
        scrub.finish(&mut out);
        if client.write_all(&out).is_err() {
            return Relayed::BoxGone;
        }
        break end;
    };
    let mut out = Vec::with_capacity(buf.len() + MARK.len());
    scrub.push(&pending[body_start..], &mut out);
    if client.write_all(&out).is_err() {
        return Relayed::BoxGone;
    }
    loop {
        out.clear();
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => scrub.push(&buf[..n], &mut out),
        }
        if !out.is_empty() && client.write_all(&out).is_err() {
            return Relayed::BoxGone;
        }
    }
    out.clear();
    scrub.finish(&mut out);
    let _ = client.write_all(&out);
    Relayed::Done
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> SecretRule {
        SecretRule {
            host: "api.example.com".into(),
            header: "Authorization".into(),
            value: "Bearer sk-test-0123456789".into(),
            secret: "sk-test-0123456789".into(),
        }
    }

    #[test]
    fn a_spec_names_its_parts_once_and_refuses_what_the_proxy_owns() {
        let s = SecretSpec::parse("host=API.Example.com.,header=Authorization,env=K,scheme=Bearer");
        assert_eq!(
            s.as_ref().map(|s| (s.host.as_str(), s.header.as_str())),
            Ok(("api.example.com", "Authorization"))
        );
        for bad in [
            "header=Authorization,env=K",
            "host=*.example.com,header=A,env=K",
            "host=a.com,header=Host,env=K",
            "host=a.com,header=content-length,env=K",
            "host=a.com,header=Bad Name,env=K",
            "host=a.com,header=A",
            "host=a.com,header=A,env=K,file=/f",
            "host=a.com,header=A,file=relative",
            "host=a.com,header=A,env=K,scheme=two words",
            "host=a.com,header=A,env=K,color=red",
            "host=a.com,header=A,env",
        ] {
            assert!(SecretSpec::parse(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn the_value_is_read_from_the_launchers_environment_and_checked() {
        let s = SecretSpec::parse("host=a.com,header=x-api-key,env=K")
            .unwrap_or_else(|e| panic!("{e}"));
        let r = s.resolve(|k| (k == "K").then(|| OsString::from("abcdefgh12")));
        assert_eq!(
            r.map(|r| (r.value, r.secret)),
            Ok(("abcdefgh12".into(), "abcdefgh12".into()))
        );
        assert!(s.resolve(|_| None).is_err());
        assert!(s.resolve(|_| Some(OsString::from("short"))).is_err());
        assert!(s.resolve(|_| Some(OsString::from("abc\ndefghij"))).is_err());
        let b = SecretSpec::parse("host=a.com,header=Authorization,env=K,scheme=Bearer")
            .unwrap_or_else(|e| panic!("{e}"));
        let r = b.resolve(|_| Some(OsString::from("abcdefgh12\n")));
        assert_eq!(r.map(|r| r.value), Ok("Bearer abcdefgh12".into()));
    }

    #[test]
    fn a_rule_prints_without_its_value() {
        let d = format!("{:?}", rule());
        assert!(!d.contains("sk-test"), "{d}");
    }

    #[test]
    fn the_pipe_carries_the_rules_whole_or_not_at_all() {
        let rules = vec![
            rule(),
            SecretRule {
                host: "b.com".into(),
                ..rule()
            },
        ];
        let bytes = encode(&rules);
        assert_eq!(decode(&bytes), Some(rules));
        assert_eq!(decode(&bytes[..bytes.len() - 1]), None);
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(decode(&extra), None);
        assert_eq!(decode(b"other"), None);
        assert_eq!(decode(MAGIC), Some(Vec::new()));
    }

    #[test]
    fn a_rule_matches_its_host_exactly_and_no_subdomain() {
        let rules = vec![rule()];
        assert!(rule_for(&rules, "API.example.com").is_some());
        assert!(rule_for(&rules, "api.example.com.").is_some());
        assert!(rule_for(&rules, "x.api.example.com").is_none());
        assert!(rule_for(&rules, "example.com").is_none());
    }

    #[test]
    fn the_scrub_replaces_the_secret_across_any_split() {
        let needle = b"sk-test-0123456789";
        let text = b"a sk-test-0123456789 b sk-test-0123456789sk-test-0123456789 sk-test-01 end";
        let want = b"a [kern-secret] b [kern-secret][kern-secret] sk-test-01 end".to_vec();
        for split in 0..text.len() {
            for split2 in split..text.len() {
                let mut s = Scrub::new(needle);
                let mut out = Vec::new();
                s.push(&text[..split], &mut out);
                s.push(&text[split..split2], &mut out);
                s.push(&text[split2..], &mut out);
                s.finish(&mut out);
                assert_eq!(out, want, "split at {split},{split2}");
            }
        }
    }

    #[test]
    fn the_outgoing_request_drops_the_boxs_key_and_the_connection_headers() {
        let headers = "Host: api.example.com\r\nAuthorization: Bearer stolen-or-fake\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\nProxy-Authorization: Basic x\r\n\r\n";
        let o = outgoing(
            "POST http://api.example.com/v1/chat?x=1 HTTP/1.1",
            headers,
            "api.example.com",
            80,
            &rule(),
        );
        let Ok(o) = o else {
            panic!("{o:?}");
        };
        assert_eq!(o.method, "POST");
        assert_eq!(o.url, "https://api.example.com/v1/chat?x=1");
        assert_eq!(o.body_len, 12);
        assert_eq!(
            o.headers,
            "Content-Type: application/json\nAuthorization: Bearer sk-test-0123456789\nExpect:\nUser-Agent:\nAccept:\n"
        );
        let o = outgoing(
            "GET http://api.example.com:8443 HTTP/1.1",
            "",
            "api.example.com",
            8443,
            &rule(),
        );
        assert_eq!(o.map(|o| o.url), Ok("https://api.example.com:8443/".into()));
        let o = outgoing(
            "GET http://api.example.com?q HTTP/1.1",
            "",
            "api.example.com",
            80,
            &rule(),
        );
        assert_eq!(o.map(|o| o.url), Ok("https://api.example.com/?q".into()));
        let o = outgoing(
            "POST http://api.example.com/ HTTP/1.1",
            "Transfer-Encoding: chunked\r\n",
            "api.example.com",
            80,
            &rule(),
        );
        assert_eq!(
            o.map(|_| ()),
            Err((411, "a body needs a Content-Length here"))
        );
        let o = outgoing(
            "GET http://api.example.com/ HTTP/1.1",
            "Upgrade: websocket\r\n",
            "api.example.com",
            80,
            &rule(),
        );
        assert!(matches!(o, Err((501, _))));
        let o = outgoing("GET /relative HTTP/1.1", "", "api.example.com", 80, &rule());
        assert!(matches!(o, Err((400, _))));
    }

    #[test]
    fn curl_is_pinned_to_the_vetted_address_and_reads_no_rc_file() {
        let o = Outgoing {
            method: "GET".into(),
            url: "https://api.example.com/".into(),
            upstream_port: 443,
            headers: String::new(),
            body_len: 0,
            expect_continue: false,
        };
        let a = curl_args(
            &o,
            "api.example.com",
            "203.0.113.7"
                .parse()
                .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0])),
            9,
        );
        assert_eq!(a.first().map(String::as_str), Some("-q"));
        let joined = a.join(" ");
        assert!(
            joined.contains("--resolve api.example.com:443:203.0.113.7"),
            "{joined}"
        );
        assert!(joined.contains("--proto =https"), "{joined}");
        assert!(!joined.contains("sk-"), "{joined}");
        assert!(joined.contains("-H @/dev/fd/9"), "{joined}");
        let v6 = curl_args(
            &o,
            "api.example.com",
            "2001:db8::1"
                .parse()
                .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0])),
            9,
        );
        assert!(v6.join(" ").contains("api.example.com:443:[2001:db8::1]"));
    }

    #[test]
    fn the_answer_head_loses_the_upstream_framing_and_closes() {
        let h = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n";
        assert_eq!(
            rewrite_response_head(h),
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
        );
        assert!(informational("HTTP/1.1 103 Early Hints\r\n\r\n"));
        assert!(!informational("HTTP/1.1 200 OK\r\n\r\n"));
    }
}
