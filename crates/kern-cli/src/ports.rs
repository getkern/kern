//! `-p [ip:]host:box` parsing. The forwarder itself lives in `kern_isolation` (it must fork before
//! the sandbox `unshare`, where only the isolation crate has the host-namespace context).

/// Parse a `-p` spec: `[ip:]hostport:boxport[/tcp|/udp]` (ports 1..=65535). The optional leading IPv4
/// is the host bind address; it defaults to **`127.0.0.1`** (loopback only) — secure by default, so a
/// published service isn't accidentally exposed to the LAN. Use `0.0.0.0:8080:80` to bind every
/// interface deliberately. An optional trailing `/tcp` (default) or `/udp` selects the protocol.
/// Returns `(bind_ip_host_order, host_port, box_port, is_udp)`; `None` if malformed.
pub fn parse(spec: &str) -> Option<(u32, u16, u16, bool)> {
    // Optional trailing protocol: `…/udp` or `…/tcp` (anything else is a malformed spec, not silent tcp).
    let (spec, udp) = match spec.rsplit_once('/') {
        Some((head, p)) if p.eq_ignore_ascii_case("udp") => (head, true),
        Some((head, p)) if p.eq_ignore_ascii_case("tcp") => (head, false),
        Some(_) => return None,
        None => (spec, false),
    };
    let parts: Vec<&str> = spec.split(':').collect();
    let (ip, h, b) = match parts.as_slice() {
        [h, b] => (0x7f00_0001u32, *h, *b), // default: 127.0.0.1 (loopback only)
        [ip, h, b] => (parse_ipv4(ip)?, *h, *b),
        _ => return None,
    };
    let host: u16 = h.trim().parse().ok().filter(|p| *p > 0)?;
    let boxp: u16 = b.trim().parse().ok().filter(|p| *p > 0)?;
    Some((ip, host, boxp, udp))
}

/// Format a parsed `-p` mapping for display (the inverse of [`parse`], e.g. `127.0.0.1:8080->80` or
/// `…->53/udp`) — always showing the bind address so the exposure is visible.
pub fn fmt(ip: u32, host: u16, boxp: u16, udp: bool) -> String {
    format!(
        "{}.{}.{}.{}:{host}->{boxp}{}",
        ip >> 24 & 0xff,
        ip >> 16 & 0xff,
        ip >> 8 & 0xff,
        ip & 0xff,
        if udp { "/udp" } else { "" }
    )
}

/// `a.b.c.d` → a `u32` in host byte order. `None` if not four 0..=255 octets.
fn parse_ipv4(s: &str) -> Option<u32> {
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut v = 0u32;
    for o in octets {
        v = (v << 8) | o.parse::<u8>().ok()? as u32;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    const LO: u32 = 0x7f00_0001;

    #[test]
    fn parses_tcp_udp_and_ip() {
        // default proto is tcp, default bind is loopback
        assert_eq!(parse("8080:80"), Some((LO, 8080, 80, false)));
        // explicit /tcp and /udp
        assert_eq!(parse("8080:80/tcp"), Some((LO, 8080, 80, false)));
        assert_eq!(parse("5353:53/udp"), Some((LO, 5353, 53, true)));
        assert_eq!(parse("53:53/UDP"), Some((LO, 53, 53, true))); // case-insensitive
                                                                  // with an explicit bind ip
        assert_eq!(parse("0.0.0.0:53:53/udp"), Some((0, 53, 53, true)));
        // round-trips through fmt (shows /udp only for udp)
        assert_eq!(fmt(LO, 5353, 53, true), "127.0.0.1:5353->53/udp");
        assert_eq!(fmt(LO, 8080, 80, false), "127.0.0.1:8080->80");
    }

    #[test]
    fn rejects_malformed_and_unknown_proto() {
        assert_eq!(parse("8080:80/sctp"), None); // unknown proto → not silent tcp
        assert_eq!(parse("8080:80/"), None);
        assert_eq!(parse("abc"), None);
        assert_eq!(parse("0:80"), None); // port 0 rejected
        assert_eq!(parse("8080:99999"), None); // out of range
        assert_eq!(parse("8080:80/udp/extra"), None); // trailing token "extra" is not a known proto
    }
}
