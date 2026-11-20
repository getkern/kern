//! One reader of an HTTP/1.x request head, for every place kern decides something from one.
//!
//! TWO READERS, ONE DECISION. The egress proxy decides which host a box may reach from a head the box
//! wrote, and the local router (`<service>.<project>.localhost`) decides which service a head is for.
//! Both read the same fields: where the head ends, which lines are header lines, which of them is
//! `Host`, and what host the request line names. A rule learned by one reader and not the other is
//! the defect kern keeps repeating (a derived condition computed in two places), and here it sits on
//! a security boundary, so the rules live once, in this module, and both call it.
//!
//! STRICT ON PURPOSE. A head the reader and the server behind it could split differently is how a
//! second request, or a second `Host`, is smuggled past the decision. So a head with a bare LF or a
//! bare CR, a NUL, a folded header line (obs-fold), whitespace before a field's colon, a line with no
//! colon, two `Content-Length`s, `Transfer-Encoding` together with `Content-Length`, or a
//! `Transfer-Encoding` other than one plain `chunked`, is refused rather than repaired: real clients
//! (curl, wget, pip, browsers) send none of these.

/// Why a head was refused. Every variant answers 400 at both readers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A `\n` not preceded by `\r`.
    BareLf,
    /// A `\r` not followed by `\n`.
    BareCr,
    /// A NUL or another control byte other than a tab, in the head.
    ControlByte,
    /// The request line is not `METHOD SP target SP HTTP/1.x`.
    RequestLine,
    /// A header line that starts with a space or a tab (obs-fold, RFC 9112 §5.2).
    ObsFold,
    /// A header line with no `:`, an empty name, or whitespace before the `:`.
    FieldName,
    /// More than one `Content-Length`, or one that is not a number.
    ContentLength,
    /// `Transfer-Encoding` with `Content-Length`, more than one, or other than `chunked`.
    TransferEncoding,
    /// No host at all: no absolute-form target and no `Host`.
    NoHost,
    /// A `Host` that names no host.
    EmptyHost,
    /// Two or more `Host` lines, whatever they say.
    DuplicateHost,
    /// The request line names one host and `Host` another.
    HostMismatch,
}

impl Refusal {
    /// The sentence a refusal answers with.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::BareLf => "a line of the request head ends in a bare LF",
            Refusal::BareCr => "the request head has a CR that does not end a line",
            Refusal::ControlByte => "the request head has a control byte",
            Refusal::RequestLine => "the request line is not METHOD target HTTP/1.x",
            Refusal::ObsFold => "a header line is folded onto the one before it",
            Refusal::FieldName => {
                "a header line has no name, no colon, or a space before the colon"
            }
            Refusal::ContentLength => "Content-Length is repeated or not a number",
            Refusal::TransferEncoding => {
                "Transfer-Encoding is repeated, not chunked, or given with Content-Length"
            }
            Refusal::NoHost => "the request names no host",
            Refusal::EmptyHost => "the Host header names no host",
            Refusal::DuplicateHost => "a request must name exactly one Host",
            Refusal::HostMismatch => "the request line and the Host header name different hosts",
        }
    }
}

/// Where the head in `buf` ends: the index just past the blank line, or `None` while it has not
/// arrived. A head that ends in a bare `\n\n` (or `\r\n\n`) is ended there too, so that [`framing`]
/// refuses it at once instead of the reader waiting for a CRLF that never comes.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            match buf.get(i + 1) {
                Some(b'\n') => return Some(i + 2),
                Some(b'\r') if buf.get(i + 2) == Some(&b'\n') => return Some(i + 3),
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Does this head contain a BARE LF, a `\n` not preceded by `\r`?
///
/// A security control with no coverage is a security control until somebody changes the line above
/// it: a mutation sweep once flipped this comparison and 920 tests stayed green, so it is a function
/// with its own tests.
pub fn has_bare_lf(head: &[u8]) -> bool {
    head.iter()
        .enumerate()
        .any(|(i, &b)| b == b'\n' && (i == 0 || head[i - 1] != b'\r'))
}

/// Check how the head is framed, before anything is read out of it. `Ok` means every line ends in
/// CRLF, the request line has three parts and an HTTP/1.x version, every header line is `name:value`
/// with nothing folded, and the body length is said at most once, one way.
pub fn framing(head: &[u8]) -> Result<(), Refusal> {
    if has_bare_lf(head) {
        return Err(Refusal::BareLf);
    }
    for (i, &b) in head.iter().enumerate() {
        match b {
            b'\r' if head.get(i + 1) != Some(&b'\n') => return Err(Refusal::BareCr),
            b'\r' | b'\n' | b'\t' => {}
            0..=0x1f | 0x7f => return Err(Refusal::ControlByte),
            _ => {}
        }
    }
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = request_line.split(' ').collect();
    match parts.as_slice() {
        [m, t, v]
            if !m.is_empty()
                && m.bytes().all(|b| b.is_ascii_alphabetic())
                && !t.is_empty()
                && (*v == "HTTP/1.1" || *v == "HTTP/1.0") => {}
        _ => return Err(Refusal::RequestLine),
    }
    let mut content_length: Option<&str> = None;
    let mut transfer_encoding = 0usize;
    for line in lines {
        if line.is_empty() {
            // The blank line that ends the head (and the empty piece after it).
            continue;
        }
        if line.starts_with([' ', '\t']) {
            return Err(Refusal::ObsFold);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Refusal::FieldName);
        };
        if name.is_empty() || name.bytes().any(|b| b == b' ' || b == b'\t') {
            return Err(Refusal::FieldName);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(Refusal::ContentLength);
            }
            content_length = Some(value);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encoding += 1;
            if transfer_encoding > 1 || !value.eq_ignore_ascii_case("chunked") {
                return Err(Refusal::TransferEncoding);
            }
        }
    }
    if transfer_encoding > 0 && content_length.is_some() {
        return Err(Refusal::TransferEncoding);
    }
    Ok(())
}

/// "The same host", spelled once: no trailing root dot, lowercase. `None` for a name that
/// normalises to nothing. Every comparison of two hosts goes through it, so a folding rule cannot be
/// learned by one side of a comparison and not the other.
pub fn normalized_host(host: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        None
    } else {
        Some(h)
    }
}

/// The bare host of an authority (`host`, `host:port`, `[v6]:port`, `user@host`), normalised.
///
/// `[userinfo@]` is stripped FIRST, at the LAST `@`: `http://allowed.com@evil.com/` names `evil.com`,
/// and the host vetted must be the host dialled.
pub fn host_of_authority(authority: &str) -> Option<String> {
    let a = authority.trim();
    let a = a.rsplit_once('@').map(|(_, h)| h).unwrap_or(a);
    let host = if let Some(rest) = a.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        a.rsplit_once(':').map(|(h, _)| h).unwrap_or(a)
    };
    normalized_host(host)
}

/// The host of an absolute-form request target (`GET http://host[:port]/path HTTP/1.1`), or `None`
/// when the target is not absolute-form.
pub fn absolute_target_host(request_line: &str) -> Option<String> {
    let target = request_line.split_whitespace().nth(1)?;
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    host_of_authority(authority)
}

/// Every `Host` field value in the header part of a head, in order.
///
/// ONE PLACE RECOGNISES THE HEADER: the host a request is for and the check that the head names only
/// that host must find the same field, so both go through here. A line with whitespace before its
/// colon is not this header: [`framing`] refuses such a head before this is asked.
pub fn host_header_values(headers: &str) -> impl Iterator<Item = &str> {
    headers
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case("Host"))
        .map(|(_, v)| v.trim())
}

/// The host a plain-HTTP request is for: the absolute-form target when there is one, which a client
/// cannot launder through a header, else the first `Host`.
pub fn parse_http_host(request_line: &str, headers: &str) -> Option<String> {
    absolute_target_host(request_line).or_else(|| {
        host_header_values(headers)
            .next()
            .and_then(host_of_authority)
    })
}

/// Whether a head is self-consistent about WHICH host it is for, given the host already taken from it
/// (`target`): at most one `Host`, and if there is one it names `target`. No `Host` at all is
/// consistent (HTTP/1.0 without one is legal and nothing can disagree). A `Host` present but naming
/// no host is not absent: forwarding a field an upstream may read differently is the same class as
/// carrying two.
pub fn http_head_names_one_host(target: &str, headers: &str) -> bool {
    let mut values = host_header_values(headers);
    match (values.next(), values.next()) {
        (None, _) => true,
        (Some(_), Some(_)) => false,
        (Some(v), None) => match (host_of_authority(v), normalized_host(target)) {
            (Some(h), Some(t)) => h == t,
            _ => false,
        },
    }
}

/// The one host a well-framed head is for, or why there is not exactly one: the absolute-form target
/// or the `Host`, and when both are present they must agree. For a reader that routes by name and has
/// no allowlist to consult first (the egress proxy asks [`parse_http_host`], its allowlist, then
/// [`http_head_names_one_host`], so a refusal there cannot tell a box what is on its list).
pub fn the_host(request_line: &str, headers: &str) -> Result<String, Refusal> {
    let mut values = host_header_values(headers);
    let (first, second) = (values.next(), values.next());
    if second.is_some() {
        return Err(Refusal::DuplicateHost);
    }
    let from_header = match first {
        Some(v) => Some(host_of_authority(v).ok_or(Refusal::EmptyHost)?),
        None => None,
    };
    match (absolute_target_host(request_line), from_header) {
        (Some(t), Some(h)) if t != h => Err(Refusal::HostMismatch),
        (Some(t), _) => Ok(t),
        (None, Some(h)) => Ok(h),
        (None, None) => Err(Refusal::NoHost),
    }
}

/// The request line and the header part of a framed head: `(request line, "\r\n<headers>\r\n\r\n")`.
pub fn split_head(head: &str) -> (&str, &str) {
    match head.find("\r\n") {
        Some(i) => (&head[..i], &head[i..]),
        None => (head, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(s: &str) -> Result<(), Refusal> {
        framing(s.as_bytes())
    }

    #[test]
    fn a_head_ends_at_its_blank_line_in_every_spelling() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nBODY"), Some(27));
        assert_eq!(head_end(b"GET / HTTP/1.1\nHost: a\n\n"), Some(24));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: a\r\n"), None);
        assert_eq!(head_end(b""), None);
    }

    #[test]
    fn a_well_formed_head_passes() {
        assert_eq!(
            frame("GET / HTTP/1.1\r\nHost: a.localhost\r\nAccept: */*\r\n\r\n"),
            Ok(())
        );
        assert_eq!(
            frame("POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n"),
            Ok(())
        );
        assert_eq!(
            frame("POST /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: Chunked\r\n\r\n"),
            Ok(())
        );
        assert_eq!(
            frame("CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n"),
            Ok(())
        );
        assert_eq!(frame("GET / HTTP/1.0\r\n\r\n"), Ok(()));
    }

    /// The request-smuggling shapes, each refused with the reason that names it.
    #[test]
    fn the_known_smuggling_shapes_are_refused() {
        let cases: &[(&str, Refusal)] = &[
            // CL.CL: two lengths, the reader takes one and the server the other.
            ("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 44\r\n\r\n", Refusal::ContentLength),
            // Even two that agree: one of them is the one nobody checked.
            ("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", Refusal::ContentLength),
            ("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\n", Refusal::ContentLength),
            ("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 5\r\n\r\n", Refusal::ContentLength),
            // TE.CL and CL.TE.
            ("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n", Refusal::TransferEncoding),
            ("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n", Refusal::TransferEncoding),
            // TE.TE: two encodings, or one disguised.
            ("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n", Refusal::TransferEncoding),
            ("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n", Refusal::TransferEncoding),
            ("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n", Refusal::TransferEncoding),
            // A name the reader trims and a server does not.
            ("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n", Refusal::FieldName),
            ("GET / HTTP/1.1\r\nHost : evil.com\r\n\r\n", Refusal::FieldName),
            ("GET / HTTP/1.1\r\nHost\r\n\r\n", Refusal::FieldName),
            (
                "GET / HTTP/1.1\r\n: x\r\n\r\n",
                Refusal::FieldName,
            ),
            // obs-fold: a second Host, or a TE, carried on a continuation line.
            ("GET / HTTP/1.1\r\nHost: a\r\n Host: evil.com\r\n\r\n", Refusal::ObsFold),
            ("POST / HTTP/1.1\r\nHost: a\r\nX: y\r\n\tTransfer-Encoding: chunked\r\n\r\n", Refusal::ObsFold),
            // Line ends a server may split on and the reader does not.
            ("GET / HTTP/1.1\nHost: a\r\n\r\n", Refusal::BareLf),
            ("GET / HTTP/1.1\r\nHost: a\rHost: evil.com\r\n\r\n", Refusal::BareCr),
            ("GET / HTTP/1.1\r\nHost: a\0b\r\n\r\n", Refusal::ControlByte),
            // A request line that is not three parts.
            ("GET  / HTTP/1.1\r\nHost: a\r\n\r\n", Refusal::RequestLine),
            ("GET / HTTP/2\r\nHost: a\r\n\r\n", Refusal::RequestLine),
            ("GET /\r\nHost: a\r\n\r\n", Refusal::RequestLine),
        ];
        for (head, want) in cases {
            assert_eq!(frame(head), Err(*want), "{head:?}");
        }
    }

    #[test]
    fn the_host_is_one_and_agrees_with_the_request_line() {
        let host = |head: &str| {
            let (l, h) = split_head(head);
            the_host(l, h)
        };
        assert_eq!(
            host("GET / HTTP/1.1\r\nHost: Web.Shop.Localhost.:8080\r\n\r\n"),
            Ok("web.shop.localhost".into())
        );
        assert_eq!(host("GET / HTTP/1.1\r\nhost: a\r\n\r\n"), Ok("a".into()));
        assert_eq!(host("GET http://a/x HTTP/1.1\r\n\r\n"), Ok("a".into()));
        assert_eq!(
            host("GET http://a:80/x HTTP/1.1\r\nHost: A.\r\n\r\n"),
            Ok("a".into())
        );
        assert_eq!(
            host("GET http://a/ HTTP/1.1\r\nHost: b\r\n\r\n"),
            Err(Refusal::HostMismatch)
        );
        assert_eq!(
            host("GET http://a@b/ HTTP/1.1\r\nHost: a\r\n\r\n"),
            Err(Refusal::HostMismatch)
        );
        assert_eq!(
            host("GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n"),
            Err(Refusal::DuplicateHost)
        );
        assert_eq!(
            host("GET / HTTP/1.1\r\nHost:   \r\n\r\n"),
            Err(Refusal::EmptyHost)
        );
        assert_eq!(
            host("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"),
            Err(Refusal::NoHost)
        );
        assert_eq!(
            host("GET / HTTP/1.1\r\nX-Forwarded-Host: a\r\n\r\n"),
            Err(Refusal::NoHost)
        );
    }

    #[test]
    fn an_absolute_target_ends_at_its_path_query_or_fragment() {
        assert_eq!(
            absolute_target_host("GET http://a?x=b.com HTTP/1.1"),
            Some("a".into())
        );
        assert_eq!(
            absolute_target_host("GET http://a#b.com HTTP/1.1"),
            Some("a".into())
        );
        assert_eq!(
            absolute_target_host("GET http://[::1]:8080/ HTTP/1.1"),
            Some("::1".into())
        );
        assert_eq!(absolute_target_host("GET / HTTP/1.1"), None);
    }
}
