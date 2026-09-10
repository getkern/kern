//! The four RTNETLINK calls kern needs to put a stack's services on one bridge.
//!
//! WHY NETLINK AT ALL, when every other network call in this crate is an `ioctl`. Bringing an
//! interface up and giving it an address have ioctl forms and keep using them ([`crate::real`]).
//! CREATING a `veth` pair, CREATING a `bridge`, attaching a link to a master and MOVING a link into
//! another network namespace have none: they are `RTM_NEWLINK` with nested `IFLA_LINKINFO`
//! attributes, and there has never been an ioctl for them. So this module exists to build four
//! messages by hand rather than to depend on `iproute2` being installed, which kern does not require
//! anywhere else.
//!
//! WHAT IT IS FOR. A kern stack runs in ONE network namespace, so its services share `127.0.0.1`: a
//! port a service binds on the loopback is reachable from every other service, which under Docker it
//! would not be. The alternative kern already had is a namespace per service with a TCP relay per
//! ORDERED PAIR PER PORT, which is quadratic: measured on a six-service stack, bring-up went from
//! 170-183 ms to 247-352 ms and the process count from 56 to 122. A bridge is linear - one `veth`
//! per service - and gives each service its own loopback, which is the thing the relay wiring buys
//! and the pod cannot.
//!
//! ROOTLESS, AND THAT WAS MEASURED BEFORE ANY OF THIS WAS WRITTEN. In a user namespace kern owns:
//! a bridge is created, a `veth` pair is created, one end is moved into a member's own network
//! namespace, and the member reaches the bridge. The member keeps its OWN `127.0.0.1`: a listener
//! bound to the loopback of one member is NOT reachable from another, which is exactly Docker's
//! semantics and exactly what the shared namespace cannot do.
//!
//! THE MEMBER SHARES THE POD'S USER NAMESPACE AND ONLY UNSHARES ITS NETWORK ONE. That is what makes
//! the move legal: moving a link needs `CAP_NET_ADMIN` in BOTH namespaces, and a member that
//! unshared its own user namespace too would own a network namespace the holder has no power over.
//! Measured: holder and member on `user:[4026534213]`, member on its own `net:[4026534280]`, move
//! accepted.

use std::io;

/// `AF_NETLINK` socket protocol for routing/link messages.
const NETLINK_ROUTE: libc::c_int = 0;

// Message types and flags. Named here rather than pulled from `libc`, which does not expose the
// `IFLA_*` attribute numbers at all on every target.
const RTM_NEWLINK: u16 = 16;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 2;

const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
/// Inside a `veth`'s `IFLA_INFO_DATA`: the description of the OTHER end.
const VETH_INFO_PEER: u16 = 1;

/// Round up to netlink's 4-byte alignment. Both `NLMSG_ALIGN` and `RTA_ALIGN` are this.
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// One `rtattr`: a 4-byte header (`len`, `type`) then the payload, padded to 4.
fn push_attr(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = 4 + payload.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align4(out.len()), 0);
}

/// Start a nested attribute, returning where its length has to be written once the nest is closed.
fn open_nest(out: &mut Vec<u8>, kind: u16) -> usize {
    let at = out.len();
    out.extend_from_slice(&0u16.to_ne_bytes()); // length, filled in by `close_nest`
    out.extend_from_slice(&kind.to_ne_bytes());
    at
}

/// Write the length of a nest opened at `at`, now that everything inside it has been pushed.
fn close_nest(out: &mut [u8], at: usize) {
    let len = (out.len() - at) as u16;
    out[at..at + 2].copy_from_slice(&len.to_ne_bytes());
}

/// A name as netlink wants it: the bytes plus a terminating NUL.
fn cstr(name: &str) -> Vec<u8> {
    let mut v = name.as_bytes().to_vec();
    v.push(0);
    v
}

/// `struct ifinfomsg`, all zeroes except the interface index when one is given.
fn ifinfomsg(index: i32) -> [u8; 16] {
    let mut m = [0u8; 16];
    // family (1) pad (1) type (2) index (4) flags (4) change (4)
    m[4..8].copy_from_slice(&index.to_ne_bytes());
    m
}

/// Send one `RTM_NEWLINK` and wait for its acknowledgement.
///
/// SYNCHRONOUS AND ACKED, because the caller's next step depends on this one having happened: a
/// `veth` is created and then immediately moved, and a move that raced the creation would fail with
/// an errno that says nothing about the cause. `NLM_F_ACK` makes the kernel answer every request,
/// success included, so there is always something to read and a silent failure is not possible.
fn send_newlink(payload: &[u8], flags: u16) -> io::Result<()> {
    // SAFETY: a socket/bind/send/recv sequence on a netlink socket, every buffer sized from the
    // value being written.
    unsafe {
        let sock = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        );
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        if libc::bind(
            sock,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) != 0
        {
            let e = io::Error::last_os_error();
            libc::close(sock);
            return Err(e);
        }

        let total = 16 + payload.len();
        let mut msg: Vec<u8> = Vec::with_capacity(total);
        msg.extend_from_slice(&(total as u32).to_ne_bytes()); // nlmsg_len
        msg.extend_from_slice(&RTM_NEWLINK.to_ne_bytes()); // nlmsg_type
        msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | flags).to_ne_bytes()); // nlmsg_flags
        msg.extend_from_slice(&1u32.to_ne_bytes()); // nlmsg_seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid: the kernel fills it in
        msg.extend_from_slice(payload);

        let sent = libc::send(sock, msg.as_ptr().cast(), msg.len(), 0);
        if sent < 0 {
            let e = io::Error::last_os_error();
            libc::close(sock);
            return Err(e);
        }

        let mut buf = [0u8; 4096];
        let got = libc::recv(sock, buf.as_mut_ptr().cast(), buf.len(), 0);
        libc::close(sock);
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        let got = got as usize;
        if got < 20 {
            return Err(io::Error::other("netlink reply too short to be an ack"));
        }
        let kind = u16::from_ne_bytes([buf[4], buf[5]]);
        if kind != NLMSG_ERROR {
            // Anything else for a request that asked for an ack is not something this module knows
            // how to read, and treating it as success would hide a failure.
            return Err(io::Error::other(format!(
                "netlink answered message type {kind}, not an ack"
            )));
        }
        // `nlmsgerr.error` is a NEGATIVE errno, and zero means success.
        let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if err == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(-err))
        }
    }
}

/// Create a bridge interface in the current network namespace.
pub fn add_bridge(name: &str) -> io::Result<()> {
    let mut p = ifinfomsg(0).to_vec();
    push_attr(&mut p, IFLA_IFNAME, &cstr(name));
    let li = open_nest(&mut p, IFLA_LINKINFO);
    push_attr(&mut p, IFLA_INFO_KIND, &cstr("bridge"));
    close_nest(&mut p, li);
    send_newlink(&p, NLM_F_CREATE | NLM_F_EXCL)
}

/// Create a `veth` pair: `name` in this namespace, `peer` as its other end.
///
/// BOTH ENDS ARE NAMED IN ONE MESSAGE, which is the only way the kernel makes a pair. The peer is a
/// whole nested `ifinfomsg` of its own inside `IFLA_INFO_DATA`, not just a name, which is the shape
/// that took the longest to get right and the reason this is a function rather than an inline
/// message.
pub fn add_veth(name: &str, peer: &str) -> io::Result<()> {
    let mut p = ifinfomsg(0).to_vec();
    push_attr(&mut p, IFLA_IFNAME, &cstr(name));
    let li = open_nest(&mut p, IFLA_LINKINFO);
    push_attr(&mut p, IFLA_INFO_KIND, &cstr("veth"));
    let data = open_nest(&mut p, IFLA_INFO_DATA);
    let peer_nest = open_nest(&mut p, VETH_INFO_PEER);
    p.extend_from_slice(&ifinfomsg(0));
    push_attr(&mut p, IFLA_IFNAME, &cstr(peer));
    close_nest(&mut p, peer_nest);
    close_nest(&mut p, data);
    close_nest(&mut p, li);
    send_newlink(&p, NLM_F_CREATE | NLM_F_EXCL)
}

/// Attach `index` to the bridge with index `master`.
pub fn set_master(index: i32, master: i32) -> io::Result<()> {
    let mut p = ifinfomsg(index).to_vec();
    push_attr(&mut p, IFLA_MASTER, &master.to_ne_bytes());
    send_newlink(&p, 0)
}

/// Move the interface with index `index` into the network namespace of process `pid`.
///
/// AFTER THIS THE INDEX IS MEANINGLESS HERE: the interface is gone from this namespace and will
/// have a different index in the target. Callers resolve the name on the far side.
pub fn move_to_netns(index: i32, pid: i32) -> io::Result<()> {
    let mut p = ifinfomsg(index).to_vec();
    push_attr(&mut p, IFLA_NET_NS_PID, &pid.to_ne_bytes());
    send_newlink(&p, 0)
}

/// The kernel's index for an interface name in the current namespace, or `None` if there is none.
pub fn index_of(name: &str) -> Option<i32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the duration of the call.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        None
    } else {
        i32::try_from(idx).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attribute encoder, checked against the layout the kernel actually parses.
    ///
    /// PURE AND ASSERTED BYTE BY BYTE, because everything else in this module is a syscall whose
    /// failure mode is an errno with no detail: `EINVAL` from a malformed nest says nothing about
    /// which nest. A wrong length here is the most likely defect and the hardest to see.
    #[test]
    fn an_attribute_is_length_type_payload_padded_to_four() {
        let mut out = Vec::new();
        push_attr(&mut out, IFLA_IFNAME, &cstr("br0"));
        // 4 header + 4 payload ("br0\0") = 8, already aligned.
        assert_eq!(out.len(), 8);
        assert_eq!(u16::from_ne_bytes([out[0], out[1]]), 8);
        assert_eq!(u16::from_ne_bytes([out[2], out[3]]), IFLA_IFNAME);
        assert_eq!(&out[4..8], b"br0\0");

        // A payload that does NOT land on 4 must be padded, and the LENGTH must still be the real
        // one: the kernel reads the declared length and skips to the next aligned offset. Writing
        // the padded length here is the classic bug and it produces `EINVAL` with no clue.
        let mut out = Vec::new();
        push_attr(&mut out, IFLA_IFNAME, &cstr("veth0"));
        assert_eq!(u16::from_ne_bytes([out[0], out[1]]), 10, "declared length");
        assert_eq!(out.len(), 12, "padded to four");
    }

    /// A nest's length covers the nest header and everything inside it.
    #[test]
    fn a_nest_reports_its_own_length_including_what_it_holds() {
        let mut out = Vec::new();
        let at = open_nest(&mut out, IFLA_LINKINFO);
        push_attr(&mut out, IFLA_INFO_KIND, &cstr("bridge"));
        close_nest(&mut out, at);
        // 4 (nest header) + 4 + 7 ("bridge\0") padded to 12 = 16.
        assert_eq!(out.len(), 16);
        assert_eq!(u16::from_ne_bytes([out[0], out[1]]), 16);
        assert_eq!(u16::from_ne_bytes([out[2], out[3]]), IFLA_LINKINFO);
    }

    /// `ifinfomsg` is 16 bytes and the index sits at offset 4.
    ///
    /// A struct written by hand rather than taken from `libc`, so its shape is asserted rather than
    /// assumed: an index at the wrong offset addresses a different interface, which is the worst
    /// possible failure for `move_to_netns`.
    #[test]
    fn ifinfomsg_puts_the_index_where_the_kernel_reads_it() {
        let m = ifinfomsg(7);
        assert_eq!(m.len(), 16);
        assert_eq!(i32::from_ne_bytes([m[4], m[5], m[6], m[7]]), 7);
        assert!(m[..4].iter().all(|b| *b == 0), "family/type stay zero");
        assert!(m[8..].iter().all(|b| *b == 0), "flags/change stay zero");
    }

    /// THE MESSAGES ARE RUN AGAINST THE KERNEL, in a namespace the test creates itself.
    ///
    /// Every assertion above is about bytes; none of them proves the kernel accepts the result. A
    /// malformed nest fails with `EINVAL` and no detail, so the only way to know these four messages
    /// are right is to send them. The child unshares a user AND network namespace, which is what
    /// gives it `CAP_NET_ADMIN` over a network of its own without touching the machine's.
    ///
    /// FORKED RATHER THAN RUN IN PROCESS: unsharing a user namespace is not permitted for a
    /// multi-threaded process, and a test binary has threads. The child reports through its exit
    /// status, so a failure here is a failure of the message and not of the harness.
    #[test]
    fn the_four_messages_are_accepted_by_the_kernel() {
        // SAFETY: fork in a test binary; the child only unshares, sends netlink messages and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // Codes are distinct so a failure names the step that failed.
            let code = || -> i32 {
                // SAFETY: unshare on the freshly forked child.
                if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
                    return 10; // no unprivileged user namespaces on this host
                }
                let _ = std::fs::write("/proc/self/setgroups", b"deny");
                let _ = std::fs::write("/proc/self/uid_map", b"0 0 1");
                let _ = std::fs::write("/proc/self/gid_map", b"0 0 1");
                if add_bridge("kbr0").is_err() {
                    return 11;
                }
                if index_of("kbr0").is_none() {
                    return 12;
                }
                if add_veth("kv0", "kp0").is_err() {
                    return 13;
                }
                let (Some(v), Some(br)) = (index_of("kv0"), index_of("kbr0")) else {
                    return 14;
                };
                if set_master(v, br).is_err() {
                    return 15;
                }
                // The peer end exists here until something moves it, which is what the pod holder
                // does with the member's pid. Moving it to pid 1 is not permitted, and the failure
                // proves the message reaches the kernel rather than being silently dropped.
                let Some(p) = index_of("kp0") else {
                    return 16;
                };
                if move_to_netns(p, 1).is_ok() {
                    return 17; // moving into init's netns must NOT be allowed from here
                }
                // Creating the same bridge twice must be refused: `NLM_F_EXCL` is what makes a
                // second holder for the same pod an error instead of a silent no-op.
                if add_bridge("kbr0").is_ok() {
                    return 18;
                }
                0
            }();
            // SAFETY: exiting the forked child without running the parent's atexit handlers.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0i32;
        // SAFETY: waiting on the child just forked.
        assert!(
            unsafe { libc::waitpid(pid, &mut status, 0) } == pid,
            "waitpid"
        );
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        if code == 10 {
            eprintln!("skipping: this host does not allow unprivileged user namespaces");
            return;
        }
        assert_eq!(
            code, 0,
            "a netlink message the kernel refused (see the code table in this test)"
        );
    }

    /// A POD'S NETWORK SPLITS INTO A GATEWAY AND A MASK, and refuses what cannot hold a stack.
    ///
    /// The bridge takes the first host address, which is the convention every reader expects and
    /// what Docker does with its own bridges; members start at `.2`. A `/31` or `/32` has no room
    /// for a bridge and a member, so it is refused rather than producing a pod where the first
    /// `kern box` fails with an errno about an address.
    #[test]
    fn a_pod_network_gives_the_bridge_the_first_address() {
        use crate::real::{mask_of, pod_bridge_parts};
        use std::net::Ipv4Addr;

        let (gw, mask, prefix) = pod_bridge_parts("10.89.0.0/24").expect("a /24 is a network");
        assert_eq!(gw, Ipv4Addr::new(10, 89, 0, 1));
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix, 24);

        // An address that is not the network base is normalised to it, so a file written
        // `10.89.0.7/24` still produces the same bridge as `10.89.0.0/24` rather than a second one.
        assert_eq!(
            pod_bridge_parts("10.89.0.7/24").map(|(g, _, _)| g),
            Some(Ipv4Addr::new(10, 89, 0, 1))
        );
        assert_eq!(
            pod_bridge_parts("172.20.0.0/16").expect("a /16").0,
            Ipv4Addr::new(172, 20, 0, 1)
        );

        // Too small to hold a bridge and a member, or not a network at all.
        for bad in [
            "10.89.0.0/31",
            "10.89.0.0/32",
            "10.89.0.0/7",
            "10.89.0.0",
            "10.89.0.0/x",
            "not-a-network/24",
            "",
        ] {
            assert!(pod_bridge_parts(bad).is_none(), "{bad:?} must be refused");
        }

        // The mask is the same function the members use, so a member cannot disagree with the
        // bridge about how wide the network is.
        assert_eq!(mask_of(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(mask_of(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(mask_of(30), Ipv4Addr::new(255, 255, 255, 252));
    }

    /// `lo` exists in every namespace and is index 1; a name nobody created has no index.
    #[test]
    fn index_of_finds_the_loopback_and_nothing_else() {
        assert_eq!(index_of("lo"), Some(1));
        assert_eq!(index_of("kern-no-such-interface"), None);
        // A name with a NUL cannot be an interface name and must not panic.
        assert_eq!(index_of("bad\0name"), None);
    }
}
