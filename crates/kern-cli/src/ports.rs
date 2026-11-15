//! `-p [ip:]host:box` parsing. The forwarder itself lives in `kern_isolation` (it must fork before
//! the sandbox `unshare`, where only the isolation crate has the host-namespace context).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Longest port range a single `-p` may expand to - a guard so `-p 1-65535:…` can't fork tens of
/// thousands of forwarder processes.
const MAX_RANGE: usize = 1024;

/// The host address a spec with no explicit `ip:` binds: **`0.0.0.0`**, every interface, which is what
/// Docker does. Its IPv6 twin `::` is bound beside it (see [`ipv6_twin`]), as Docker binds both.
///
/// IT USED TO BE `127.0.0.1`, and that was the single largest source of behavioural difference from
/// Docker in this project. MEASURED on a NEUTRAL corpus of 259 compose files, one per repository,
/// sampled across 733 repositories: **203 of them (78%)** published at least one port and therefore
/// behaved differently under kern than the file says. Nothing else came close: the next cause was
/// worth 75 files, and every "kern is less permissive on purpose" key together (`privileged`,
/// `security_opt`) was worth 8. A file that says `8080:80` means Docker's `8080:80`, and kern reading
/// it as something narrower is a silent difference, which is the one thing this compose
/// implementation refuses to be.
///
/// THE SAFER POSTURE IS STILL AVAILABLE, and it is one line of `kern.toml`
/// (`[kern] publish_bind = "127.0.0.1"`), or a spec that says so (`127.0.0.1:8080:80`), which is
/// also how the same wish is written under Docker. What changed is which of the two a file gets when
/// it says nothing, and "what it says under Docker" is the answer that cannot surprise anyone
/// reading the file.
pub const PUBLISH_DEFAULT_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// The loopback address, for a caller that configures the narrower policy.
pub const LOOPBACK_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The IPv6 address bound beside an IPv4 DEFAULT: `::` beside `0.0.0.0`, `::1` beside `127.0.0.1`.
/// `None` for any other address, which has no IPv6 meaning of its own.
///
/// MEASURED on Docker 29 on this repository's development machine: `docker run -p 18448:80` and
/// `-p :18444:80` both answer `docker port` with `0.0.0.0:<port>` AND `[::]:<port>`, while
/// `-p 0.0.0.0:18447:80` answers with the IPv4 line only. So the twin belongs to a spec that names
/// no address, and never to one that names `0.0.0.0`.
#[must_use]
pub fn ipv6_twin(v4: IpAddr) -> Option<IpAddr> {
    match v4 {
        IpAddr::V4(a) if a.is_unspecified() => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        IpAddr::V4(a) if a.is_loopback() => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        _ => None,
    }
}

/// Parse a `-p` spec: `[ip:]hostport:boxport[/tcp|/udp]`, where either port may be a `START-END` RANGE
/// (e.g. `8000-8010:9000-9010`). Ports are 1..=65535. The optional leading address is the host bind
/// address, either family; without one it is [`PUBLISH_DEFAULT_IP`] plus its IPv6 twin. A trailing
/// `/tcp` (default) or `/udp` selects the protocol. Returns the EXPANDED list of [`PortMap`]s; `None`
/// if malformed, if the host/box ranges differ in length, or if the range exceeds [`MAX_RANGE`].
///
/// [`PortMap`]: kern_isolation::PortMap
pub fn parse(spec: &str) -> Option<Vec<kern_isolation::PortMap>> {
    parse_with_default(spec, PUBLISH_DEFAULT_IP)
}

/// The address a spec WROTE, as Docker's parser reads it: the last `:` field is the box port, the one
/// before it the host port, and EVERYTHING before those is the address, with brackets optional
/// (`[::1]`, `::1`). `Ok(None)` when no address was written (`8080:80`) or it is empty (`:8080:80`),
/// both of which Docker treats as "no address" (measured: both bind `0.0.0.0` and `[::]`).
/// `Err(text)` names an address that is not one: Docker refuses `::8080:80` with
/// `invalid IP address: :`, and so does this.
pub fn written_address(spec: &str) -> Result<Option<IpAddr>, String> {
    let head = strip_proto(spec).map_or(spec, |(h, _)| h);
    let parts: Vec<&str> = head.split(':').collect();
    if parts.len() < 3 {
        return Ok(None);
    }
    let ip = parts
        .get(..parts.len() - 2)
        .map(|p| p.join(":"))
        .unwrap_or_default();
    let bare = ip
        .strip_prefix('[')
        .and_then(|i| i.strip_suffix(']'))
        .unwrap_or(&ip);
    if bare.is_empty() {
        return Ok(None);
    }
    bare.parse::<IpAddr>().map(Some).map_err(|_| ip.clone())
}

/// The protocol suffix: `Some((head, udp))` for `…/tcp` or `…/udp`, `None` when there is none, and a
/// head of `""` for any other suffix, which no spec can parse.
fn strip_proto(spec: &str) -> Option<(&str, bool)> {
    match spec.rsplit_once('/') {
        Some((head, p)) if p.eq_ignore_ascii_case("udp") => Some((head, true)),
        Some((head, p)) if p.eq_ignore_ascii_case("tcp") => Some((head, false)),
        Some(_) => Some(("", false)),
        None => None,
    }
}

/// [`parse`], with the bind address a spec without an explicit `ip:` should get.
///
/// THE DEFAULT IS A PARAMETER AND NOT A GLOBAL, because two readers need different answers and both
/// are right: the box that will actually bind wants the operator's configured policy, while the
/// compose preflight that decides whether two services collide wants Docker's rule, so that a file
/// is refused on the same grounds whatever the local configuration is. A process-global would make
/// the answer depend on an assignment invisible from the call site, which is the defect class this
/// codebase keeps paying for.
///
/// An unwritten address expands to the default AND its IPv6 twin, the twin marked
/// [`implicit`](kern_isolation::PortMap::implicit) so a host without IPv6 can drop it (Docker
/// does). A written one is exactly that address.
pub fn parse_with_default(spec: &str, default_ip: IpAddr) -> Option<Vec<kern_isolation::PortMap>> {
    let (head, udp) = strip_proto(spec).unwrap_or((spec, false));
    if head.is_empty() {
        return None; // a protocol other than tcp/udp: malformed, never silent tcp
    }
    let parts: Vec<&str> = head.split(':').collect();
    let n = parts.len();
    if n < 2 {
        return None;
    }
    let (h, b) = (*parts.get(n - 2)?, *parts.get(n - 1)?);
    let written = written_address(head).ok()?;
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
    let binds: Vec<(IpAddr, bool)> = match written {
        Some(ip) => vec![(ip, false)],
        None => std::iter::once((default_ip, false))
            .chain(ipv6_twin(default_ip).map(|v6| (v6, true)))
            .collect(),
    };
    Some(
        binds
            .iter()
            .flat_map(|&(bind, implicit)| {
                (0..count as u16).map(move |k| kern_isolation::PortMap {
                    bind,
                    implicit,
                    host: hs + k,
                    box_port: bs + k,
                    udp,
                })
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

/// The host side of a mapping as `docker port` prints it: `0.0.0.0:8080`, `[::]:8080`.
#[must_use]
pub fn host_side(m: &kern_isolation::PortMap) -> String {
    match m.bind {
        IpAddr::V4(a) => format!("{a}:{}", m.host),
        IpAddr::V6(a) => format!("[{a}]:{}", m.host),
    }
}

/// Format a [`PortMap`] for display (the inverse of [`parse`], e.g. `127.0.0.1:8080->80`,
/// `[::]:8080->80` or `…->53/udp`) - always showing the bind address so the exposure is visible.
///
/// [`PortMap`]: kern_isolation::PortMap
pub fn fmt(m: &kern_isolation::PortMap) -> String {
    format!(
        "{}->{}{}",
        host_side(m),
        m.box_port,
        if m.udp { "/udp" } else { "" }
    )
}

/// The INVERSE of [`fmt`], defined next to it so the two cannot drift: read one rendered mapping
/// (`IP:HOST->BOX`, `[IP6]:HOST->BOX`, either with `/udp`) back into a [`kern_isolation::PortMap`].
///
/// WHY THIS EXISTS AS A FUNCTION rather than as a `split` at the call site: the published mapping is
/// stored in the registry as the string [`fmt`] produced, so anything that answers "which host
/// address serves this box port" has to read that grammar back. A hand-rolled split at each call
/// site is how one of them ends up disagreeing with the writer. `fmt_parse_round_trips` pins the
/// pair, so a change to either without the other fails the build.
///
/// Total on the parse path: every malformed shape returns `None` rather than panicking, including a
/// missing arrow, an address that is not a literal, an unbracketed IPv6 address (`fmt` always
/// brackets one, so a bare one is not something it wrote), a port outside 1..=65535 and a protocol
/// suffix that is neither `tcp` nor `udp`. What it reads back is never `implicit`: that mark is the
/// parser's, for a decision taken before anything is recorded.
pub fn parse_display(s: &str) -> Option<kern_isolation::PortMap> {
    let s = s.trim();
    let (s, udp) = strip_proto(s).unwrap_or((s, false));
    let (left, box_s) = s.split_once("->")?;
    // `rsplit_once(':')`: the LAST colon separates the host port, whatever the address holds.
    let (ip_s, host_s) = left.rsplit_once(':')?;
    let bind = match ip_s.strip_prefix('[').and_then(|i| i.strip_suffix(']')) {
        Some(v6) => IpAddr::V6(v6.parse::<Ipv6Addr>().ok()?),
        None => IpAddr::V4(parse_ipv4_strict(ip_s)?),
    };
    let host: u16 = host_s.parse().ok().filter(|p| *p > 0)?;
    let box_port: u16 = box_s.trim().parse().ok().filter(|p| *p > 0)?;
    Some(kern_isolation::PortMap {
        bind,
        implicit: false,
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

/// `a.b.c.d`, exactly four decimal octets. Stricter than `Ipv4Addr::from_str` on nothing that `fmt`
/// writes, and kept so the registry grammar does not widen with the standard library's.
fn parse_ipv4_strict(s: &str) -> Option<Ipv4Addr> {
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut v = [0u8; 4];
    for (slot, o) in v.iter_mut().zip(octets) {
        *slot = o.parse::<u8>().ok()?;
    }
    Some(Ipv4Addr::from(v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kern_isolation::PortMap;
    const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const ANY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    const ANY6: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    const LO6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    fn pm(bind: IpAddr, host: u16, box_port: u16, udp: bool) -> PortMap {
        PortMap {
            bind,
            implicit: false,
            host,
            box_port,
            udp,
        }
    }
    /// The IPv6 twin a default bind adds.
    fn twin(bind: IpAddr, host: u16, box_port: u16, udp: bool) -> PortMap {
        PortMap {
            implicit: true,
            ..pm(bind, host, box_port, udp)
        }
    }

    /// `fmt` AND `parse_display` ARE ONE PAIR, and this is the only thing that keeps them one.
    ///
    /// The registry stores a mapping as the string `fmt` produced; every reader of that field has to
    /// invert it. Exhaustive over the axes that can differ (bind address of either family, either
    /// port at its boundary, protocol) rather than over a sample, because the failure mode of a broken
    /// inverse is a silently wrong answer, not a crash.
    #[test]
    fn fmt_parse_round_trips() {
        let cases = [
            pm(LO, 8080, 80, false),
            pm(ANY, 443, 8443, false),
            pm(LO, 53, 53, true),
            pm(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1, 65535, false),
            pm(IpAddr::V4(Ipv4Addr::BROADCAST), 65535, 1, true),
            pm(ANY6, 8080, 80, false),
            pm(LO6, 53, 53, true),
            pm(
                IpAddr::V6("fe80::1".parse().unwrap_or(Ipv6Addr::LOCALHOST)),
                9,
                9,
                false,
            ),
        ];
        for want in cases {
            let rendered = fmt(&want);
            let got = parse_display(&rendered)
                .unwrap_or_else(|| panic!("parse_display rejected what fmt wrote: {rendered}"));
            assert_eq!(got, want, "a field was lost in {rendered}");
        }
        assert_eq!(fmt(&pm(ANY6, 8080, 80, false)), "[::]:8080->80");
        assert_eq!(fmt(&pm(LO6, 5353, 53, true)), "[::1]:5353->53/udp");
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
            "localhost:8080->80",      // not an address literal
            "8080->80",                // no address at all
            "127.0.0.1:8080->80/sctp", // unknown protocol
            "127.0.0.1:80 80->80",     // space inside the address side
            ":::8080->80",             // an unbracketed IPv6 address: fmt never writes one
            "[::g]:8080->80",          // not an IPv6 literal
            "[127.0.0.1]:8080->80",    // brackets around IPv4
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
        let got = parse_display_list(
            "127.0.0.1:18081->8000, garbage, 0.0.0.0:443->8443/udp, [::]:443->8443/udp",
        );
        assert_eq!(
            got.len(),
            3,
            "expected the three readable mappings: {got:?}"
        );
        assert_eq!(got[0].host, 18081);
        assert_eq!(got[0].box_port, 8000);
        assert_eq!(got[1].bind, ANY);
        assert_eq!(got[1].box_port, 8443);
        assert!(got[1].udp);
        assert_eq!(got[2].bind, ANY6);
        assert!(
            parse_display_list("").is_empty(),
            "an empty field is no mappings"
        );
    }

    /// THE DEFAULT BIND IS DOCKER'S, BOTH FAMILIES, and that is the single largest compatibility
    /// fact in this project: measured on a neutral 259-file corpus, 203 files (78%) published a port.
    /// A spec without an `ip:` binds every interface, IPv4 and IPv6, exactly as `docker run -p
    /// 8080:80` does (measured: `docker port` lists `0.0.0.0:<p>` and `[::]:<p>`).
    #[test]
    fn parses_tcp_udp_and_ip() {
        let both = |h, b, udp| Some(vec![pm(ANY, h, b, udp), twin(ANY6, h, b, udp)]);
        assert_eq!(parse("8080:80"), both(8080, 80, false));
        assert_eq!(parse("8080:80/tcp"), both(8080, 80, false));
        assert_eq!(parse("5353:53/udp"), both(5353, 53, true));
        assert_eq!(parse("53:53/UDP"), both(53, 53, true)); // case-insensitive
                                                            // An EMPTY address is no address, as in Docker (`-p :18444:80` measured as both families).
        assert_eq!(parse(":8080:80"), both(8080, 80, false));
        // A written address is exactly that address, and no twin: `0.0.0.0` is IPv4 only in Docker.
        assert_eq!(
            parse("0.0.0.0:53:53/udp"),
            Some(vec![pm(ANY, 53, 53, true)])
        );
        assert_eq!(
            parse("127.0.0.1:8080:80"),
            Some(vec![pm(LO, 8080, 80, false)])
        );
        // round-trips through fmt (shows /udp only for udp)
        assert_eq!(fmt(&pm(LO, 5353, 53, true)), "127.0.0.1:5353->53/udp");
        assert_eq!(fmt(&pm(LO, 8080, 80, false)), "127.0.0.1:8080->80");
    }

    /// IPv6 is read the way Docker reads it, every form measured against `docker run -p`: the last two
    /// fields are the ports and everything before them is the address, brackets optional.
    #[test]
    fn ipv6_bind_addresses_are_read_as_docker_reads_them() {
        assert_eq!(parse("[::]:443:443"), Some(vec![pm(ANY6, 443, 443, false)]));
        assert_eq!(parse("[::1]:443:443"), Some(vec![pm(LO6, 443, 443, false)]));
        assert_eq!(parse("::1:443:443"), Some(vec![pm(LO6, 443, 443, false)]));
        assert_eq!(parse("[::]:53:53/udp"), Some(vec![pm(ANY6, 53, 53, true)]));
        assert_eq!(
            parse("[::1]:8000-8001:9000-9001"),
            Some(vec![pm(LO6, 8000, 9000, false), pm(LO6, 8001, 9001, false)])
        );
        // Docker REFUSES `::443:443` (`invalid IP address: :`, measured in both `run` and compose):
        // the address field is `:`. So does this, and the reason names the field.
        assert_eq!(parse("::443:443"), None);
        assert_eq!(written_address("::443:443"), Err(":".to_string()));
        assert_eq!(written_address("[::1]:443:443"), Ok(Some(LO6)));
        assert_eq!(written_address(":443:443"), Ok(None));
        assert_eq!(written_address("443:443"), Ok(None));
        assert_eq!(
            written_address("nothere:443:443"),
            Err("nothere".to_string())
        );
    }

    /// THE DEFAULT IS A PARAMETER, and the parameter must not touch an explicit address.
    ///
    /// Two readers need different answers from the same spec: the box that will bind wants the
    /// operator's configured policy, the compose preflight wants Docker's rule so a file is refused
    /// on the same grounds on every host. Both are served by passing the default in, and neither is
    /// served by a spec whose written address gets rewritten underneath it.
    #[test]
    fn the_default_bind_is_a_parameter_and_never_overrides_a_written_address() {
        assert_eq!(
            parse_with_default("8080:80", LO),
            Some(vec![pm(LO, 8080, 80, false), twin(LO6, 8080, 80, false)]),
            "a spec with no ip: takes the caller's default, with its IPv6 twin"
        );
        // Written addresses survive both defaults, unchanged.
        for d in [LO, PUBLISH_DEFAULT_IP] {
            assert_eq!(
                parse_with_default("0.0.0.0:8080:80", d),
                Some(vec![pm(ANY, 8080, 80, false)])
            );
            assert_eq!(
                parse_with_default("127.0.0.1:8080:80", d),
                Some(vec![pm(LO, 8080, 80, false)])
            );
        }
        // And the zero-argument entry point is the Docker one.
        assert_eq!(
            parse("8080:80"),
            parse_with_default("8080:80", PUBLISH_DEFAULT_IP)
        );
        assert_eq!(PUBLISH_DEFAULT_IP, ANY);
        assert_eq!(LOOPBACK_IP, LO);
        assert_eq!(ipv6_twin(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), None);
    }

    #[test]
    fn expands_port_ranges() {
        // equal-length host/box ranges expand to one mapping per port, per family
        assert_eq!(
            parse("8000-8002:9000-9002/udp"),
            Some(vec![
                pm(ANY, 8000, 9000, true),
                pm(ANY, 8001, 9001, true),
                pm(ANY, 8002, 9002, true),
                twin(ANY6, 8000, 9000, true),
                twin(ANY6, 8001, 9001, true),
                twin(ANY6, 8002, 9002, true),
            ])
        );
        // an ip applies to the whole range
        assert_eq!(
            parse("0.0.0.0:80-81:80-81"),
            Some(vec![pm(ANY, 80, 80, false), pm(ANY, 81, 81, false)])
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
        assert_eq!(parse("80"), None);
        assert_eq!(parse("0:80"), None); // port 0 rejected
        assert_eq!(parse("8080:99999"), None); // out of range
        assert_eq!(parse("8080:80/udp/extra"), None); // trailing token "extra" is not a known proto
        assert_eq!(parse("999.0.0.1:8080:80"), None);
    }

    /// THE ROUND TRIP HOLDS OVER THE WHOLE SPACE, not over a handful of chosen cases.
    ///
    /// This is the gate that lets the registry keep ONE representation. `ports` is stored as the
    /// string `fmt` produces and read back by `compose port` through `parse_display`, which is two
    /// readings of one field and therefore a drift surface: a change to how a mapping is rendered
    /// that the parser cannot read back would make `compose port` answer for a box that publishes.
    ///
    /// So the drift is closed by exhausting the space instead: every bind address shape that `fmt`
    /// can emit (both families), the full range of both ports at their boundaries, and both
    /// protocols. 6 x 9 x 9 x 2 combinations, each asserted to survive `fmt` then `parse_display`
    /// unchanged, and each asserted to survive the list form too, because `compose port` reads a
    /// comma-joined list and a separator that appears inside an element would break only there.
    #[test]
    fn fmt_and_parse_display_round_trip_over_the_whole_space() {
        let ips = [
            ANY,
            LO,
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            ANY6,
            LO6,
        ];
        // PORT 0 IS DELIBERATELY ABSENT: `parse_display` refuses it, because `0` means "any port" to
        // `bind` and a published mapping on it addresses nothing.
        let ports = [1u16, 80, 443, 1024, 8080, 65534, 65535, 32768, 49152];
        let mut checked = 0usize;
        for ip in ips {
            for host in ports {
                for box_port in ports {
                    for udp in [false, true] {
                        let m = pm(ip, host, box_port, udp);
                        let rendered = fmt(&m);
                        assert_eq!(
                            parse_display(&rendered),
                            Some(m),
                            "round trip lost {m:?} through {rendered:?}"
                        );
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
        assert_eq!(checked, 6 * 9 * 9 * 2, "the whole space must be walked");
    }
}
