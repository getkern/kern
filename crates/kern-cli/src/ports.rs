//! `-p [ip:]host:box` parsing. The forwarder itself lives in `kern_isolation` (it must fork before
//! the sandbox `unshare`, where only the isolation crate has the host-namespace context).

/// Parse a `-p` spec: `[ip:]hostport:boxport` (ports 1..=65535). The optional leading IPv4 is the
/// host bind address; it defaults to **`127.0.0.1`** (loopback only) — secure by default, so a
/// published service isn't accidentally exposed to the LAN. Use `0.0.0.0:8080:80` to bind every
/// interface deliberately. Returns `(bind_ip_host_order, host_port, box_port)`; `None` if malformed.
pub fn parse(spec: &str) -> Option<(u32, u16, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (ip, h, b) = match parts.as_slice() {
        [h, b] => (0x7f00_0001u32, *h, *b), // default: 127.0.0.1 (loopback only)
        [ip, h, b] => (parse_ipv4(ip)?, *h, *b),
        _ => return None,
    };
    let host: u16 = h.trim().parse().ok().filter(|p| *p > 0)?;
    let boxp: u16 = b.trim().parse().ok().filter(|p| *p > 0)?;
    Some((ip, host, boxp))
}

/// Format a parsed `-p` mapping for display (the inverse of [`parse`], e.g.
/// `127.0.0.1:8080->80`) — always showing the bind address so the exposure is visible.
pub fn fmt(ip: u32, host: u16, boxp: u16) -> String {
    format!(
        "{}.{}.{}.{}:{host}->{boxp}",
        ip >> 24 & 0xff,
        ip >> 16 & 0xff,
        ip >> 8 & 0xff,
        ip & 0xff
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
