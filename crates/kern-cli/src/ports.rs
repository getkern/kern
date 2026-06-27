//! `-p [ip:]host:box` parsing. The forwarder itself lives in `kern_isolation` (it must fork before
//! the sandbox `unshare`, where only the isolation crate has the host-namespace context).

/// Longest port range a single `-p` may expand to — a guard so `-p 1-65535:…` can't fork tens of
/// thousands of forwarder processes.
const MAX_RANGE: usize = 1024;

/// Parse a `-p` spec: `[ip:]hostport:boxport[/tcp|/udp]`, where either port may be a `START-END` RANGE
/// (e.g. `8000-8010:9000-9010`). Ports are 1..=65535. The optional leading IPv4 is the host bind
/// address; it defaults to **`127.0.0.1`** (loopback only) — secure by default, so a published service
/// isn't accidentally exposed to the LAN. Use `0.0.0.0:…` to bind every interface deliberately. A
/// trailing `/tcp` (default) or `/udp` selects the protocol. Returns the EXPANDED list of
/// `(bind_ip_host_order, host_port, box_port, is_udp)` mappings (one for a single port, N for a range);
/// `None` if malformed, if the host/box ranges differ in length, or if the range exceeds [`MAX_RANGE`].
pub fn parse(spec: &str) -> Option<Vec<(u32, u16, u16, bool)>> {
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
    let (hs, he) = parse_port_or_range(h)?;
    let (bs, be) = parse_port_or_range(b)?;
    // A host range must map onto a box range of the SAME length (like Docker); a single box port with a
    // host range is ambiguous and rejected.
    if he - hs != be - bs {
        return None;
    }
    let count = (he - hs) as usize + 1;
    if count > MAX_RANGE {
        return None;
    }
    Some(
        (0..count as u16)
            .map(|k| (ip, hs + k, bs + k, udp))
            .collect(),
    )
}

/// Parse a `PORT` or a `START-END` range (each 1..=65535, `START <= END`). Returns `(start, end)`
/// with `end == start` for a single port; `None` if malformed or out of range.
fn parse_port_or_range(s: &str) -> Option<(u16, u16)> {
    let s = s.trim();
    match s.split_once('-') {
        Some((a, z)) => {
            let start: u16 = a.trim().parse().ok().filter(|p| *p > 0)?;
            let end: u16 = z.trim().parse().ok().filter(|p| *p > 0)?;
            (start <= end).then_some((start, end))
        }
        None => {
            let p: u16 = s.parse().ok().filter(|p| *p > 0)?;
            Some((p, p))
        }
    }
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
        // default proto is tcp, default bind is loopback; a single port → a one-element list
        assert_eq!(parse("8080:80"), Some(vec![(LO, 8080, 80, false)]));
        assert_eq!(parse("8080:80/tcp"), Some(vec![(LO, 8080, 80, false)]));
        assert_eq!(parse("5353:53/udp"), Some(vec![(LO, 5353, 53, true)]));
        assert_eq!(parse("53:53/UDP"), Some(vec![(LO, 53, 53, true)])); // case-insensitive
        assert_eq!(parse("0.0.0.0:53:53/udp"), Some(vec![(0, 53, 53, true)]));
        // round-trips through fmt (shows /udp only for udp)
        assert_eq!(fmt(LO, 5353, 53, true), "127.0.0.1:5353->53/udp");
        assert_eq!(fmt(LO, 8080, 80, false), "127.0.0.1:8080->80");
    }

    #[test]
    fn expands_port_ranges() {
        // equal-length host/box ranges expand to one mapping per port
        assert_eq!(
            parse("8000-8002:9000-9002/udp"),
            Some(vec![
                (LO, 8000, 9000, true),
                (LO, 8001, 9001, true),
                (LO, 8002, 9002, true),
            ])
        );
        // an ip applies to the whole range
        assert_eq!(
            parse("0.0.0.0:80-81:80-81"),
            Some(vec![(0, 80, 80, false), (0, 81, 81, false)])
        );
        // a range mapping onto a single box port is ambiguous → rejected (like Docker)
        assert_eq!(parse("8000-8010:80"), None);
        // mismatched range lengths → rejected
        assert_eq!(parse("8000-8002:9000-9005"), None);
        // reversed range → rejected
        assert_eq!(parse("8010-8000:8010-8000"), None);
        // a range over the fork-guard cap → rejected
        assert_eq!(parse("1-2000:1-2000"), None);
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
