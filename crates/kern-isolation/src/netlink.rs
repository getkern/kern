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

/// Create a `veth` pair whose PEER END IS BORN in the network namespace of process `pid`.
///
/// WHY THIS EXISTS AND [`add_veth`] + [`move_to_netns`] IS NOT ENOUGH. Moving an existing interface
/// between network namespaces calls `synchronize_net()` in the kernel, which waits a full RCU grace
/// period. MEASURED on this machine, five pairs each, in a user namespace: the move costs 14-22 ms
/// and creating the peer directly in the target costs 1-2 ms. That difference is paid ONCE PER
/// SERVICE and it is serial, so it was the whole per-service cost of the bridge wiring: a stack of
/// eight services spent about 180 ms of its 400 waiting for eight grace periods.
///
/// THE SHAPE IS [`add_veth`]'s WITH ONE MORE ATTRIBUTE, `IFLA_NET_NS_PID` inside the peer's own
/// nested `ifinfomsg`. The kernel reads it while registering the peer and registers it THERE, so no
/// interface ever changes namespace and there is nothing to synchronize. It is the same message
/// `ip link add X type veth peer name Y netns <pid>` sends.
///
/// `pid` IS READ IN THE CALLER'S PID NAMESPACE, like every other `IFLA_NET_NS_PID`.
pub fn add_veth_peer_in_netns(name: &str, peer: &str, pid: i32) -> io::Result<()> {
    let mut p = ifinfomsg(0).to_vec();
    push_attr(&mut p, IFLA_IFNAME, &cstr(name));
    let li = open_nest(&mut p, IFLA_LINKINFO);
    push_attr(&mut p, IFLA_INFO_KIND, &cstr("veth"));
    let data = open_nest(&mut p, IFLA_INFO_DATA);
    let peer_nest = open_nest(&mut p, VETH_INFO_PEER);
    p.extend_from_slice(&ifinfomsg(0));
    push_attr(&mut p, IFLA_IFNAME, &cstr(peer));
    push_attr(&mut p, IFLA_NET_NS_PID, &pid.to_ne_bytes());
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
                // PROBE ALL THE WAY DOWN. These three writes were ignored, and the namespace
                // succeeding was read as "this host can do it". An Ubuntu 23.10+ host GRANTS the
                // namespace and REFUSES the map, so the child went on with no capabilities in it
                // and every netlink message after this point failed - reported as "the kernel
                // refused message X" on a host where the kernel was never asked with authority.
                let _ = std::fs::write("/proc/self/setgroups", b"deny");
                if std::fs::write("/proc/self/uid_map", b"0 0 1").is_err()
                    || std::fs::write("/proc/self/gid_map", b"0 0 1").is_err()
                {
                    return 19; // the namespace was granted and its map refused
                }
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
        if code == 19 {
            eprintln!(
                "skipping: this host grants the user namespace and refuses its id map, so nothing \
                 in it has the capability these messages need"
            );
            return;
        }
        assert_eq!(
            code, 0,
            "a netlink message the kernel refused (see the code table in this test)"
        );
    }

    /// THE PEER IS BORN IN THE OTHER NAMESPACE, and this proves it rather than timing it.
    ///
    /// WHY IT IS NOT A BENCHMARK. The reason this message exists is speed: moving an interface
    /// between network namespaces waits an RCU grace period, measured at 14-22 ms against 1-2 ms to
    /// create the peer in place, and that difference is paid once per service. A test that asserted
    /// milliseconds would fail on a loaded machine and pass on a kern that quietly fell back to the
    /// move, so it asserts the PROPERTY the speed comes from: no interface changes namespace.
    ///
    /// THREE OBSERVATIONS, AND ALL THREE ARE NEEDED:
    ///   - the near end is HERE, so the pair was really created;
    ///   - the far end is NOT here, which is the thing that distinguishes this from [`add_veth`];
    ///   - the far end IS in the target namespace, read from INSIDE it by a process that `setns`es
    ///     there. Without this third one the test would pass on a kernel that accepted the message
    ///     and created only one end.
    ///
    /// The CONTROL is [`add_veth`] in the same namespace moments later: both of ITS ends are here.
    /// Without it, "the far end is not here" would also be satisfied by a veth that was never made.
    #[test]
    fn a_veth_peer_can_be_born_in_another_namespace() {
        // SAFETY: fork in a test binary; the child only unshares, sends netlink messages and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            let code = || -> i32 {
                // SAFETY: unshare on the freshly forked child.
                if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
                    return 10; // no unprivileged user namespaces on this host
                }
                // PROBE ALL THE WAY DOWN. These three writes were ignored, and the namespace
                // succeeding was read as "this host can do it". An Ubuntu 23.10+ host GRANTS the
                // namespace and REFUSES the map, so the child went on with no capabilities in it
                // and every netlink message after this point failed - reported as "the kernel
                // refused message X" on a host where the kernel was never asked with authority.
                let _ = std::fs::write("/proc/self/setgroups", b"deny");
                if std::fs::write("/proc/self/uid_map", b"0 0 1").is_err()
                    || std::fs::write("/proc/self/gid_map", b"0 0 1").is_err()
                {
                    return 19; // the namespace was granted and its map refused
                }
                // A SECOND NETWORK NAMESPACE TO AIM AT, held open by a child that does nothing else.
                //
                // AND A PIPE, BECAUSE THE FORK ALONE IS A RACE THIS TEST ALREADY LOST. Without the
                // handshake the message below is sent while the grandchild may not have reached its
                // `unshare` yet; the pid then still names THIS namespace, the kernel does exactly
                // what it was asked and creates the peer here, and the test reports that the feature
                // does not work. It looked like a kernel that ignores the attribute and it was a
                // test that did not wait.
                let mut sync: [libc::c_int; 2] = [-1, -1];
                // SAFETY: `sync` is a live two-element array; `pipe` writes both slots or neither.
                if unsafe { libc::pipe(sync.as_mut_ptr()) } != 0 {
                    return 11;
                }
                // SAFETY: fork from the same single-threaded child.
                let target = unsafe { libc::fork() };
                if target < 0 {
                    return 11;
                }
                if target == 0 {
                    // SAFETY: the grandchild unshares its own network namespace, says so on the
                    // pipe, and then waits to be killed; it touches nothing shared.
                    unsafe {
                        libc::close(sync[0]);
                        if libc::unshare(libc::CLONE_NEWNET) != 0 {
                            libc::_exit(1);
                        }
                        let byte: [u8; 1] = [1];
                        libc::write(sync[1], byte.as_ptr().cast(), 1);
                        libc::sleep(30);
                        libc::_exit(0);
                    }
                }
                // SAFETY: the read end is this process's; a one-byte read on a pipe whose only
                // writer is the grandchild returns 1 after the unshare, or 0 if it died first.
                let ready = unsafe {
                    libc::close(sync[1]);
                    let mut byte = [0u8; 1];
                    let n = libc::read(sync[0], byte.as_mut_ptr().cast(), 1);
                    libc::close(sync[0]);
                    n == 1
                };
                if !ready {
                    return 11; // the target never got a namespace of its own
                }
                let verdict = {
                    if add_veth_peer_in_netns("kvf", "kpf", target).is_err() {
                        12
                    } else if index_of("kvf").is_none() {
                        13 // the near end must be here: the pair was not created at all
                    } else if index_of("kpf").is_some() {
                        14 // the far end is HERE, so it was not born in the target namespace
                    } else {
                        // READ FROM INSIDE THE TARGET. A third process, because `setns` would move
                        // this one and every check after it.
                        // SAFETY: fork from the same single-threaded child.
                        let reader = unsafe { libc::fork() };
                        if reader < 0 {
                            15
                        } else if reader == 0 {
                            let path = format!("/proc/{target}/ns/net\0");
                            // SAFETY: the path is NUL-terminated above; the fd is only `setns`ed.
                            let code = unsafe {
                                let fd = libc::open(
                                    path.as_ptr().cast::<libc::c_char>(),
                                    libc::O_RDONLY | libc::O_CLOEXEC,
                                );
                                if fd < 0 {
                                    1
                                } else if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                                    2
                                } else if index_of("kpf").is_none() {
                                    3
                                } else {
                                    0
                                }
                            };
                            // SAFETY: leaving the forked reader without the parent's handlers.
                            unsafe { libc::_exit(code) };
                        } else {
                            let mut st = 0i32;
                            // SAFETY: waiting on the reader just forked.
                            if unsafe { libc::waitpid(reader, &mut st, 0) } != reader {
                                16
                            } else if !libc::WIFEXITED(st) || libc::WEXITSTATUS(st) != 0 {
                                17 // the far end is not in the target namespace either
                            } else if add_veth("kvc", "kpc").is_err() {
                                18
                            } else if index_of("kvc").is_none() || index_of("kpc").is_none() {
                                19 // the CONTROL failed: an ordinary pair must leave both ends here
                            } else {
                                0
                            }
                        }
                    }
                };
                // SAFETY: the grandchild is this process's own child and is still sleeping.
                unsafe {
                    libc::kill(target, libc::SIGKILL);
                    let mut st = 0i32;
                    libc::waitpid(target, &mut st, 0);
                }
                verdict
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
        if code == 19 {
            eprintln!(
                "skipping: this host grants the user namespace and refuses its id map, so nothing \
                 in it has the capability these messages need"
            );
            return;
        }
        assert_eq!(
            code, 0,
            "the peer end was not born in the target namespace (see the code table in this test)"
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
            // LOOPBACK, and it is here because it was ACCEPTED and then silently broke the pod.
            // MEASURED with `--bridge 127.0.0.0/8`: the holder built the bridge without error, two
            // members joined with `127.0.0.5/8` and `127.0.0.6/8` and started, and then neither
            // could reach the other and the peer's name did not resolve. The kernel routes 127/8 to
            // `lo` inside each namespace, so nothing ever crossed the bridge.
            "127.0.0.0/8",
            "127.0.0.0/24",
            "127.42.0.0/16",
        ] {
            assert!(pod_bridge_parts(bad).is_none(), "{bad:?} must be refused");
        }
        // CONTROL: the refusal is about loopback, not about the shape of those strings. A network
        // one octet away parses, or the three lines above would hold for a parser that refuses
        // everything with a `/8` or a leading `1`.
        assert!(pod_bridge_parts("128.0.0.0/8").is_some());
        assert!(pod_bridge_parts("10.127.0.0/16").is_some());

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
