//! `-p [ip:]host:box` parsing. The forwarder itself lives in `kern_isolation` (it must fork before
//! the sandbox `unshare`, where only the isolation crate has the host-namespace context).

/// Longest port range a single `-p` may expand to - a guard so `-p 1-65535:…` can't fork tens of
/// thousands of forwarder processes.
const MAX_RANGE: usize = 1024;

/// Parse a `-p` spec: `[ip:]hostport:boxport[/tcp|/udp]`, where either port may be a `START-END` RANGE
/// (e.g. `8000-8010:9000-9010`). Ports are 1..=65535. The optional leading IPv4 is the host bind
/// address; it defaults to **`127.0.0.1`** (loopback only) - secure by default, so a published service
/// isn't accidentally exposed to the LAN. Use `0.0.0.0:…` to bind every interface deliberately. A
/// trailing `/tcp` (default) or `/udp` selects the protocol. Returns the EXPANDED list of [`PortMap`]s
/// (one for a single port, N for a range); `None` if malformed, if the host/box ranges differ in
/// length, or if the range exceeds [`MAX_RANGE`].
pub fn parse(spec: &str) -> Option<Vec<kern_isolation::PortMap>> {
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
            .map(|k| kern_isolation::PortMap {
                bind_ip: ip,
                host: hs + k,
                box_port: bs + k,
                udp,
            })
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

/// Format a [`PortMap`] for display (the inverse of [`parse`], e.g. `127.0.0.1:8080->80` or
/// `…->53/udp`) - always showing the bind address so the exposure is visible.
pub fn fmt(m: &kern_isolation::PortMap) -> String {
    format!(
        "{}.{}.{}.{}:{}->{}{}",
        m.bind_ip >> 24 & 0xff,
        m.bind_ip >> 16 & 0xff,
        m.bind_ip >> 8 & 0xff,
        m.bind_ip & 0xff,
        m.host,
        m.box_port,
        if m.udp { "/udp" } else { "" }
    )
}

/// The INVERSE of [`fmt`], defined next to it so the two cannot drift: read one rendered mapping
/// (`IP:HOST->BOX` or `IP:HOST->BOX/udp`) back into a [`kern_isolation::PortMap`].
///
/// WHY THIS EXISTS AS A FUNCTION rather than as a `split` at the call site: the published mapping is
/// stored in the registry as the string [`fmt`] produced, so anything that answers "which host
/// address serves this box port" has to read that grammar back. A hand-rolled split at each call
/// site is how one of them ends up disagreeing with the writer. `fmt_parse_round_trips` pins the
/// pair, so a change to either without the other fails the build.
///
/// Total and allocation-free on the parse path: every malformed shape returns `None` rather than
/// panicking, including a missing arrow, a non-IPv4 left side, a port outside 1..=65535 and a
/// protocol suffix that is neither `tcp` nor `udp`.
pub fn parse_display(s: &str) -> Option<kern_isolation::PortMap> {
    let s = s.trim();
    // Protocol suffix first: `…/udp`, `…/tcp`, or nothing. Anything else is malformed rather than
    // silently TCP, matching `parse`'s rule for the same suffix.
    let (s, udp) = match s.rsplit_once('/') {
        Some((head, p)) if p.eq_ignore_ascii_case("udp") => (head, true),
        Some((head, p)) if p.eq_ignore_ascii_case("tcp") => (head, false),
        Some(_) => return None,
        None => (s, false),
    };
    let (left, box_s) = s.split_once("->")?;
    // `rsplit_once(':')`: the address is IPv4 here (`fmt` writes four octets), so the LAST colon
    // separates the host port. Splitting on the first would take `127` as the address.
    let (ip_s, host_s) = left.rsplit_once(':')?;
    let bind_ip = parse_ipv4(ip_s)?;
    let host: u16 = host_s.parse().ok().filter(|p| *p > 0)?;
    let box_port: u16 = box_s.trim().parse().ok().filter(|p| *p > 0)?;
    Some(kern_isolation::PortMap {
        bind_ip,
        host,
        box_port,
        udp,
    })
}

/// Read a registry `ports` field (`fmt` joined with `", "`) into its mappings, dropping any element
/// that does not parse rather than failing the whole read: a single unreadable entry must not hide
/// the ones a caller can act on. An empty field yields an empty vector.
pub fn parse_display_list(s: &str) -> Vec<kern_isolation::PortMap> {
    s.split(',').filter_map(parse_display).collect()
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

    /// `fmt` AND `parse_display` ARE ONE PAIR, and this is the only thing that keeps them one.
    ///
    /// The registry stores a mapping as the string `fmt` produced; every reader of that field has to
    /// invert it. Exhaustive over the axes that can differ (bind address, either port at its
    /// boundary, protocol) rather than over a sample, because the failure mode of a broken inverse is
    /// a silently wrong answer, not a crash.
    #[test]
    fn fmt_parse_round_trips() {
        let cases = [
            kern_isolation::PortMap {
                bind_ip: 0x7f00_0001,
                host: 8080,
                box_port: 80,
                udp: false,
            },
            kern_isolation::PortMap {
                bind_ip: 0,
                host: 443,
                box_port: 8443,
                udp: false,
            },
            kern_isolation::PortMap {
                bind_ip: 0x7f00_0001,
                host: 53,
                box_port: 53,
                udp: true,
            },
            kern_isolation::PortMap {
                bind_ip: 0xc0a8_0101,
                host: 1,
                box_port: 65535,
                udp: false,
            },
            kern_isolation::PortMap {
                bind_ip: 0xffff_ffff,
                host: 65535,
                box_port: 1,
                udp: true,
            },
        ];
        for want in cases {
            let rendered = fmt(&want);
            let got = parse_display(&rendered)
                .unwrap_or_else(|| panic!("parse_display rejected what fmt wrote: {rendered}"));
            assert_eq!(got.bind_ip, want.bind_ip, "bind_ip lost in {rendered}");
            assert_eq!(got.host, want.host, "host port lost in {rendered}");
            assert_eq!(got.box_port, want.box_port, "box port lost in {rendered}");
            assert_eq!(got.udp, want.udp, "protocol lost in {rendered}");
        }
    }

    /// Every malformed shape answers `None`. A parser for a field read out of a file on disk is an
    /// attack surface as much as a convenience, so the refusals are enumerated rather than assumed:
    /// a corrupt registry entry must not become a wrong host address.
    #[test]
    fn parse_display_refuses_every_malformed_shape() {
        for bad in [
            "",                        // empty
            "127.0.0.1:8080",          // no arrow
            "->80",                    // no left side
            "127.0.0.1:8080->",        // no box port
            "127.0.0.1:0->80",         // host port 0
            "127.0.0.1:8080->0",       // box port 0
            "127.0.0.1:8080->99999",   // box port out of range
            "127.0.0.1:99999->80",     // host port out of range
            "127.0.0.1.5:8080->80",    // five octets
            "127.0.0:8080->80",        // three octets
            "256.0.0.1:8080->80",      // octet out of range
            "localhost:8080->80",      // not an IPv4 literal
            "8080->80",                // no address at all
            "127.0.0.1:8080->80/sctp", // unknown protocol
            "127.0.0.1:80 80->80",     // space inside the address side
        ] {
            assert!(
                parse_display(bad).is_none(),
                "parse_display accepted a malformed mapping: {bad:?}"
            );
        }
    }

    /// A list read from the registry keeps the entries it can read. One unreadable element must not
    /// take the readable ones with it: the caller is answering "which host address serves this box
    /// port", and losing every answer because of a neighbour is the wrong failure.
    #[test]
    fn parse_display_list_keeps_what_it_can_read() {
        let got = parse_display_list("127.0.0.1:18081->8000, garbage, 0.0.0.0:443->8443/udp");
        assert_eq!(got.len(), 2, "expected the two readable mappings: {got:?}");
        assert_eq!(got[0].host, 18081);
        assert_eq!(got[0].box_port, 8000);
        assert_eq!(got[1].bind_ip, 0);
        assert_eq!(got[1].box_port, 8443);
        assert!(got[1].udp);
        assert!(
            parse_display_list("").is_empty(),
            "an empty field is no mappings"
        );
    }
    use super::*;
    use kern_isolation::PortMap;
    const LO: u32 = 0x7f00_0001;

    fn pm(bind_ip: u32, host: u16, box_port: u16, udp: bool) -> PortMap {
        PortMap {
            bind_ip,
            host,
            box_port,
            udp,
        }
    }

    #[test]
    fn parses_tcp_udp_and_ip() {
        // default proto is tcp, default bind is loopback; a single port → a one-element list
        assert_eq!(parse("8080:80"), Some(vec![pm(LO, 8080, 80, false)]));
        assert_eq!(parse("8080:80/tcp"), Some(vec![pm(LO, 8080, 80, false)]));
        assert_eq!(parse("5353:53/udp"), Some(vec![pm(LO, 5353, 53, true)]));
        assert_eq!(parse("53:53/UDP"), Some(vec![pm(LO, 53, 53, true)])); // case-insensitive
        assert_eq!(parse("0.0.0.0:53:53/udp"), Some(vec![pm(0, 53, 53, true)]));
        // round-trips through fmt (shows /udp only for udp)
        assert_eq!(fmt(&pm(LO, 5353, 53, true)), "127.0.0.1:5353->53/udp");
        assert_eq!(fmt(&pm(LO, 8080, 80, false)), "127.0.0.1:8080->80");
    }

    #[test]
    fn expands_port_ranges() {
        // equal-length host/box ranges expand to one mapping per port
        assert_eq!(
            parse("8000-8002:9000-9002/udp"),
            Some(vec![
                pm(LO, 8000, 9000, true),
                pm(LO, 8001, 9001, true),
                pm(LO, 8002, 9002, true),
            ])
        );
        // an ip applies to the whole range
        assert_eq!(
            parse("0.0.0.0:80-81:80-81"),
            Some(vec![pm(0, 80, 80, false), pm(0, 81, 81, false)])
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

    /// THE ROUND TRIP HOLDS OVER THE WHOLE SPACE, not over a handful of chosen cases.
    ///
    /// This is the gate that lets the registry keep ONE representation. `ports` is stored as the
    /// string `fmt` produces and read back by `compose port` through `parse_display`, which is two
    /// readings of one field and therefore a drift surface: a change to how a mapping is rendered
    /// that the parser cannot read back would make `compose port` answer for a box that publishes.
    ///
    /// The alternative a reviewer proposed was to store the structured value and format at display
    /// time, deleting the parser. It is not available: `fmt`'s output IS the only wire format there
    /// is, so a decoder for it is `parse_display` under another name, and adding a SECOND structured
    /// field would duplicate state rather than remove a parser, while changing the existing field's
    /// encoding would make a running kern read nothing for boxes a previous kern started.
    ///
    /// So the drift is closed by exhausting the space instead: every bind address shape that `fmt`
    /// can emit, the full range of both ports at their boundaries, and both protocols. 4 x 9 x 9 x 2
    /// combinations, each asserted to survive `fmt` then `parse_display` unchanged, and each asserted
    /// to survive the list form too, because `compose port` reads a comma-joined list and a separator
    /// that appears inside an element would break only there.
    #[test]
    fn fmt_and_parse_display_round_trip_over_the_whole_space() {
        let ips = [0u32, 0x7f00_0001, 0xc0a8_0001, 0xffff_ffff];
        // PORT 0 IS DELIBERATELY ABSENT, and the first version of this test included it and failed.
        // `parse_display` refuses it, because `0` means "any port" to `bind` and a published mapping
        // on it addresses nothing; it is one of the malformed shapes that function exists to reject.
        // The inverse is defined over VALID mappings, so a `PortMap` with port 0 is outside the space
        // rather than a lost round trip. A registry entry cannot contain one: a forwarder that bound
        // port 0 would have recorded the port the kernel chose.
        let ports = [1u16, 80, 443, 1024, 8080, 65534, 65535, 32768, 49152];
        let mut checked = 0usize;
        for ip in ips {
            for host in ports {
                for box_port in ports {
                    for udp in [false, true] {
                        let m = kern_isolation::PortMap {
                            bind_ip: ip,
                            host,
                            box_port,
                            udp,
                        };
                        let rendered = fmt(&m);
                        let back = parse_display(&rendered);
                        assert_eq!(
                            back.as_ref()
                                .map(|b| (b.bind_ip, b.host, b.box_port, b.udp)),
                            Some((m.bind_ip, m.host, m.box_port, m.udp)),
                            "round trip lost {m:?} through {rendered:?}"
                        );
                        // AND THROUGH THE LIST, which is how the registry actually stores it. A
                        // rendering that contained the separator would pass the single-element check
                        // and fail here, which is the failure `compose port` would see.
                        let list = format!("{rendered}, {rendered}");
                        assert_eq!(
                            parse_display_list(&list).len(),
                            2,
                            "the list form must survive too: {list:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 4 * 9 * 9 * 2, "the whole space must be walked");
    }
}
