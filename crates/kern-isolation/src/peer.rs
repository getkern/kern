//! Peer-to-peer reachability between two boxes that do NOT share a network namespace.
//!
//! # Why this exists
//!
//! A `kern compose` stack is one pod on one network namespace, which is what makes peers resolve
//! each other on `127.0.0.1` for free. `--no-pod` removes the pod, and with it every way one service
//! has of reaching another: MEASURED, a service's namespace then holds only loopback and no routes,
//! so a peer is unreachable by name AND by address, and a port published to the host does not reach a
//! peer either. That makes the flag useless as the escape hatch it is offered as for a container-port
//! collision, because a stack whose services never talk is not the kind of stack that has two
//! services binding one port.
//!
//! This module is the mechanism that closes that: a relay that makes box B's listening port reachable
//! from inside box A, at an address of A's own loopback. Nothing here runs unless a stack asks for it.
//!
//! # The constraint that decides the architecture, measured rather than assumed
//!
//! A process that has entered box A's user namespace can no longer reach box B's. It does not fail at
//! `setns`; it fails one step earlier, at `open("/proc/<B>/ns/user")`, with `EACCES`. Verified on a
//! live host with two boxes: `setns(user A)` and `setns(net A)` both return 0, and the following open
//! of B's user namespace is refused.
//!
//! So ONE process cannot bind inside A and connect inside B. The shape that follows is two processes,
//! both forked from the HOST namespaces before either enters anything, joined by a socketpair:
//!
//!   * the **listener** enters A, binds `alias:port` on A's loopback, accepts, and hands each accepted
//!     socket to the connector as an `SCM_RIGHTS` message;
//!   * the **connector** enters B and, per received socket, forks a pump that connects to B's
//!     `127.0.0.1:port` and moves bytes.
//!
//! File descriptors are not namespaced, which is why the hand-off works across the boundary at all.
//!
//! # Failure modes, enumerated before the code
//!
//!  1. **`socketpair`/`pipe`/`fork` failure.** Each is an early `Err` carrying the errno, and any
//!     child already forked is killed and reaped, so a partial spawn never leaks a process.
//!  2. **`enter_box_ns` refused.** Reported by the child over its status pipe as `EACCES`-class errno
//!     BEFORE it starts serving, so the caller learns at spawn time rather than at first connection.
//!  3. **`bind` refused inside A** (the alias:port is taken there). Same status pipe, real errno.
//!  4. **Peer B is not listening.** `connect` fails per connection; that connection is closed and the
//!     relay keeps serving. A service that starts later works without restarting the relay.
//!  5. **Connector slower than the listener.** The socketpair fills and `sendmsg` blocks the accept
//!     loop. That IS the backpressure, bounded by `SO_SNDBUF`, and it is deliberate: queueing accepted
//!     sockets without bound is how a relay turns a slow peer into an fd exhaustion.
//!  6. **Parent death.** Both halves arm `PR_SET_PDEATHSIG(SIGKILL)` and then re-check `getppid`,
//!     closing the window where the parent died between the fork and the prctl. EVERY PUMP ARMS IT
//!     TOO, against the connector, because `PDEATHSIG` is not inherited across `fork`: without that,
//!     killing the holder took the two halves and left a pump alive, still bridging two boxes'
//!     namespaces after the teardown meant to remove it, `compose down` included.
//!  7. **Zombie accumulation and unbounded forks.** The connector reaps its own pumps with
//!     `WNOHANG` before every fork and refuses past `MAX_LIVE_PUMPS`, rather than setting `SIGCHLD`
//!     to `SIG_IGN`: the kernel would reap them, but then nothing knows how many are live, and a
//!     bound needs a count. A box that opens connections faster than its peer closes them therefore
//!     meets a refusal instead of the user's `RLIMIT_NPROC`. The cap is the STACK's budget divided
//!     by the number of relays, because a per-relay number alone is never the binding constraint.
//!  8. **`SIGPIPE`.** A peer that closes mid-pump would otherwise kill the pump process silently.
//!     Ignored in both children, so a broken connection is an `EPIPE` return the pump handles.
//!  9. **`EINTR`.** `sendmsg`/`recvmsg` are retried on `EINTR`; every other error ends that message.
//! 10. **A relay pointed at a box that shares OUR namespace.** Refused by the caller, which must not
//!     hand this module a `--net` box: entering "its" namespace would be entering the host's, and the
//!     relay would publish a host service under a peer's name. [`spawn`] re-checks by comparing the
//!     two boxes' net-namespace identities and refuses when they are the same.

use crate::ports::{
    bind_host_socket, connect_box_loopback_from, drop_all_capabilities, enter_box_ns_pinned,
    pump_bidir, restrict_capabilities, source_address_is_bindable,
};
use std::mem;

/// Bytes reserved for the `SCM_RIGHTS` control message. `cmsghdr` is 16 bytes on every Linux ABI kern
/// builds for and the payload is one `RawFd`, so `CMSG_SPACE(4)` is 24; 64 is a deliberate margin that
/// still fits in a cache line. [`assert_cmsg_fits`] checks it against the platform at run time rather
/// than trusting this comment.
const CMSG_BUF: usize = 64;

/// Control-message buffer with `cmsghdr`'s alignment. A `[u8; N]` would be 1-aligned and every
/// `CMSG_FIRSTHDR` cast on it would be undefined behaviour.
#[repr(C)]
union CmsgSpace {
    hdr: libc::cmsghdr,
    bytes: [u8; CMSG_BUF],
}

impl CmsgSpace {
    const fn new() -> Self {
        Self {
            bytes: [0u8; CMSG_BUF],
        }
    }
}

/// One live relay: two processes making `B:port` reachable at `alias:port` inside A.
///
/// Dropping it kills both, so a relay cannot outlive the value that owns it. The pids are kept rather
/// than pidfds because the same struct has to work on the oldest kernel kern supports, and the kill
/// is guarded by the same "never a non-positive pid" rule as everything else in this tree.
/// `Debug` is derived, not hand-written: `expect_err` on `spawn` requires the `Ok` side to be
/// printable, and a relay's fields are two pids, an address and a port, none of them a secret.
#[derive(Debug)]
pub struct PeerRelay {
    listener_pid: i32,
    connector_pid: i32,
    /// Loopback alias the peer answers on, inside A. Host byte order.
    pub alias_ip: u32,
    /// Port, identical on both sides: the alias exists so the peer's port needs no translation.
    pub port: u16,
}

impl PeerRelay {
    /// Kill and reap both halves. Idempotent: a pid already gone is a no-op, and a non-positive pid is
    /// never signalled (`kill(0, …)` hits the caller's process group and `kill(-1, …)` every process
    /// the user owns - the class this codebase closed once and does not reopen here).
    fn shutdown(&mut self) {
        for pid in [self.listener_pid, self.connector_pid] {
            if pid > 0 {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let mut st: libc::c_int = 0;
                unsafe { libc::waitpid(pid, &mut st, 0) };
            }
        }
        self.listener_pid = -1;
        self.connector_pid = -1;
    }

    /// Whether `pid` is one of this relay's two halves.
    ///
    /// The owner of a relay set blocks on its children and learns only that SOMETHING died; this is
    /// how it turns a pid back into the edge that stopped working, so a report can name the edge
    /// rather than the stack.
    pub fn owns(&self, pid: i32) -> bool {
        pid > 0 && (self.listener_pid == pid || self.connector_pid == pid)
    }

    /// Kill and reap both halves NOW, leaving the value inert. Public because a self-healing owner
    /// replaces a relay in place and must retire the old one before the new one binds the same alias;
    /// `Drop` would run at the wrong moment for that.
    pub fn stop(&mut self) {
        self.shutdown();
    }
}

impl Drop for PeerRelay {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Highest service index that gets a loopback alias. `127.0.0.1` is the box's OWN loopback, so peer
/// aliases start at `.2`; `127.0.0.255` is the broadcast address of that /24 and is not usable, which
/// leaves `.2 ..= .254`, i.e. 253 peers. A compose stack with more services than that is not a stack
/// this mechanism should silently half-serve.
pub const MAX_PEER_INDEX: usize = 253;

/// The loopback alias for the peer at `index` (0-based), in host byte order.
///
/// `index 0 -> 127.0.0.2`, `1 -> 127.0.0.3`, and so on. `None` past [`MAX_PEER_INDEX`], so a caller
/// that grows past the range gets a refusal it must handle rather than a wrapped address that would
/// silently collide with another peer's.
///
/// THE `.1` IS RESERVED AND THAT IS THE WHOLE POINT: a service keeps binding its own
/// `127.0.0.1:<port>` while its peers answer at other addresses, which is what removes the
/// container-port collision instead of merely working around it.
pub const fn peer_alias(index: usize) -> Option<u32> {
    if index >= MAX_PEER_INDEX {
        return None;
    }
    // 127.0.0.(index + 2). `as u32` is exact: the guard above bounds `index` to 252.
    Some(0x7f00_0000 | (index as u32 + 2))
}

/// Render an alias as dotted quad into a caller-owned buffer, returning the used slice.
///
/// No allocation: this is called while building a hosts file for every service of a stack, and a
/// `format!` per line is a heap round trip for four numbers that never exceed three digits.
pub fn alias_to_dotted(ip: u32, out: &mut [u8; 15]) -> &str {
    let mut n = 0usize;
    for shift in [24u32, 16, 8, 0] {
        if shift != 24 {
            out[n] = b'.';
            n += 1;
        }
        let octet = ((ip >> shift) & 0xff) as u8;
        if octet >= 100 {
            out[n] = b'0' + octet / 100;
            n += 1;
        }
        if octet >= 10 {
            out[n] = b'0' + (octet / 10) % 10;
            n += 1;
        }
        out[n] = b'0' + octet % 10;
        n += 1;
    }
    // SAFETY-free: every byte written above is ASCII, so the slice is valid UTF-8 by construction.
    // `from_utf8` is used rather than the unchecked form because the check is a length-bounded scan
    // on at most 15 bytes and this is not a per-packet path.
    core::str::from_utf8(&out[..n]).unwrap_or("0.0.0.0")
}

/// `errno` as an `i32`, without allocating an `io::Error` on a path that may run per connection.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// The platform's `CMSG_SPACE` for one file descriptor must fit [`CMSG_BUF`].
///
/// A runtime check rather than a comment: the constant is a claim about a C macro on the target, and
/// the cost of being wrong is a truncated control message that silently transfers no descriptor.
fn assert_cmsg_fits() -> bool {
    // SAFETY: `CMSG_SPACE` is a pure computation on its argument.
    let need = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as libc::c_uint) } as usize;
    need <= CMSG_BUF
}

/// Send one file descriptor over `sock` as an `SCM_RIGHTS` message.
///
/// Carries one byte of real payload because a control message with no data may be discarded, which
/// would lose the descriptor without an error anywhere. Retries on `EINTR`; every other failure ends
/// the attempt and is the caller's to handle.
fn send_fd(sock: i32, fd: i32) -> bool {
    if !assert_cmsg_fits() {
        return false;
    }
    let mut byte = [b'k'; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut space = CmsgSpace::new();
    // SAFETY: `msghdr` is a plain C struct; zeroing it is the documented way to start one.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: the union's `bytes` arm is `CMSG_BUF` initialised bytes with `cmsghdr` alignment.
    msg.msg_control = unsafe { space.bytes.as_mut_ptr().cast() };
    // `as _`, NOT `as libc::size_t`. `msg_controllen` is `size_t` on x86_64 glibc and `socklen_t`
    // (a `u32`) on aarch64 musl, so naming either one hard-codes a target: this module compiled on
    // the development host and failed on the aarch64 release target, which kern publishes. Letting
    // inference take the field's own type is the only spelling that is right on both.
    msg.msg_controllen =
        unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as libc::c_uint) } as _;
    // SAFETY: `msg_control` points at `msg_controllen` writable, aligned bytes, so the first header
    // is in bounds; the payload write below is `CMSG_LEN` bytes inside that same region.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return false;
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as libc::c_uint) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const i32 as *const u8,
            libc::CMSG_DATA(cmsg),
            mem::size_of::<libc::c_int>(),
        );
        loop {
            let n = libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL);
            if n < 0 && errno() == libc::EINTR {
                continue;
            }
            return n > 0;
        }
    }
}

/// Receive one file descriptor sent by [`send_fd`], or `-1`.
///
/// `-1` covers three distinct outcomes deliberately: the peer closed (0 bytes), a real error, and a
/// message that carried no descriptor. The caller's response is identical in all three (stop serving
/// this connection), and distinguishing them would mean an error type on a path that must not
/// allocate.
fn recv_fd(sock: i32) -> i32 {
    if !assert_cmsg_fits() {
        return -1;
    }
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut space = CmsgSpace::new();
    // SAFETY: as in `send_fd`.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: same union invariant as the send path.
    unsafe {
        msg.msg_control = space.bytes.as_mut_ptr().cast();
        msg.msg_controllen = CMSG_BUF as _;
        let n = loop {
            let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
            if n < 0 && errno() == libc::EINTR {
                continue;
            }
            break n;
        };
        if n <= 0 {
            return -1;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            || (*cmsg).cmsg_len < libc::CMSG_LEN(mem::size_of::<libc::c_int>() as libc::c_uint) as _
        {
            return -1;
        }
        let mut fd: libc::c_int = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut libc::c_int as *mut u8,
            mem::size_of::<libc::c_int>(),
        );
        fd
    }
}

/// Write an `i32` status to a pipe, retrying on `EINTR` and on a short write.
fn write_status(fd: i32, status: i32) {
    let bytes = status.to_ne_bytes();
    let mut off = 0usize;
    while off < bytes.len() {
        // SAFETY: writing `bytes.len() - off` bytes from inside an owned array.
        let n = unsafe { libc::write(fd, bytes.as_ptr().add(off).cast(), bytes.len() - off) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return;
        }
        if n == 0 {
            return;
        }
        off += n as usize;
    }
}

/// Read one `i32` status. `None` when the child died before writing, which is itself an answer: the
/// caller reports it as a spawn failure rather than waiting forever for a relay that will never serve.
fn read_status(fd: i32) -> Option<i32> {
    let mut bytes = [0u8; 4];
    let mut off = 0usize;
    while off < bytes.len() {
        // SAFETY: reading into `bytes.len() - off` bytes of an owned array.
        let n = unsafe { libc::read(fd, bytes.as_mut_ptr().add(off).cast(), bytes.len() - off) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return None;
        }
        if n == 0 {
            return None; // EOF: the child exited without reporting
        }
        off += n as usize;
    }
    Some(i32::from_ne_bytes(bytes))
}

/// Arm death-with-the-parent and confirm the parent is still the one we forked from.
///
/// Both halves are load-bearing. `PR_SET_PDEATHSIG` only fires on a FUTURE death, so a parent that
/// died between the `fork` and the `prctl` would leave exactly the orphan this prevents; the
/// `getppid` comparison detects that reparent and exits. Copied in shape, deliberately, from the port
/// forwarder, which was written after six such orphans were found holding host ports.
fn die_with_parent(parent: i32) -> bool {
    // SAFETY: `prctl` with `PR_SET_PDEATHSIG` takes a signal number and ignores the rest.
    unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        );
    }
    unsafe { libc::getppid() == parent }
}

/// Most relays one stack may create.
///
/// THE MESH IS QUADRATIC AND THE ALIAS RANGE DOES NOT BOUND IT. `assign_aliases` caps a stack at 253
/// services, which sounds like a limit and is not one for this: 253 services with one port each is
/// `253 * 252` = 63,756 relays and 127,513 processes, against an `RLIMIT_NPROC` of 126,965 on the
/// machine this was measured on. The worst case kern permitted therefore exceeded the process limit
/// of the host, and would have failed somewhere in the middle with an errno rather than a sentence.
///
/// MEASURED, release build, on a 32-service stack: 992 relays, 1,987 processes, 474 MB of real
/// resident memory (the sum of the per-process RSS is four times that and counts shared pages
/// repeatedly), `up` in 1.54 s and `down` in 0.41 s. So a relay costs two processes and roughly
/// 240 kB, and this cap is set where that product is still a number a developer would accept on a
/// laptop: 1,024 relays is about 2,049 processes and half a gigabyte.
///
/// Refused rather than trimmed. Serving some of a mesh is the silent-partial-success shape this
/// module refuses everywhere else, and a stack this wide is not a stack `--no-pod` was meant for.
pub const MAX_RELAYS: usize = 1024;

/// Concurrent forwarded pumps a WHOLE STACK will carry, shared out across its relays.
///
/// THE PER-RELAY NUMBER ALONE IS NOT A BOUND, and it was one until this was reworked. At 256 per
/// relay, a four-service stack with three ports each has 24 relays, so the number that actually
/// mattered was 6,144 processes from one stack: that meets `RLIMIT_NPROC` and the cgroup `pids`
/// limit long before it meets any single relay's cap. A bound that is never the binding constraint
/// is a bound in name.
///
/// So the budget is stated for the STACK and divided by the number of relays in the plan, which the
/// holder knows because it has just read that plan.
const STACK_PUMP_BUDGET: usize = 1024;

/// Fewest concurrent pumps any one relay is given, however many share the budget. Without a floor a
/// wide stack divides its way down to a relay that can carry one connection at a time.
pub const MIN_LIVE_PUMPS: usize = 16;

/// Most concurrent pumps any one relay is given, however few share the budget.
pub const MAX_LIVE_PUMPS: usize = 256;

/// The per-relay pump cap for a plan holding `relays` relays.
///
/// THE REACHABLE FORM IS WHAT MAKES THIS WORTH BOUNDING HERE and not in the `-p` forwarder, which has
/// the same shape: a relay's listening socket lives INSIDE a box, so the party that can saturate it
/// is a container. The forwarder faces the host, where whoever can saturate it already owns the
/// machine.
pub const fn pump_cap_for(relays: usize) -> usize {
    if relays == 0 {
        return MAX_LIVE_PUMPS;
    }
    let share = STACK_PUMP_BUDGET / relays;
    if share < MIN_LIVE_PUMPS {
        MIN_LIVE_PUMPS
    } else if share > MAX_LIVE_PUMPS {
        MAX_LIVE_PUMPS
    } else {
        share
    }
}

/// A box's PID 1 together with the kernel start-time that pins it.
///
/// THE TWO TRAVEL AS ONE VALUE ON PURPOSE. A bare pid is a number the kernel is free to hand to an
/// unrelated process the moment the box's init exits, and every consumer that then opens
/// `/proc/<pid>/ns/*` lands in a stranger's namespaces. The registry already learned this lesson and
/// exposes the pid only through a start-time-checked accessor; passing the pid alone across this
/// crate boundary would have thrown that check away at the door. Keeping them in one struct means a
/// caller cannot supply one without the other.
///
/// A `starttime` of `0` means "not pinned", which the entry path treats as "skip the comparison". It
/// exists for the `-p` forwarder, whose pid is resolved through a supervisor that is itself pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxRef {
    /// PID 1 of the box, in host numbering.
    pub pid1: i32,
    /// `/proc/<pid1>/stat` field 22, as recorded when the box registered.
    pub starttime: u64,
}

/// The listener half: enter A, bind `alias:port` on A's loopback, and hand every accepted socket to
/// the connector. Never returns.
fn listener_main(status: i32, pair: i32, a: BoxRef, alias_ip: u32, port: u16, parent: i32) -> ! {
    // SAFETY: setting a disposition on this process only.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    if !die_with_parent(parent) {
        unsafe { libc::_exit(0) };
    }
    if !enter_box_ns_pinned(a.pid1, a.starttime) {
        write_status(status, if errno() != 0 { errno() } else { libc::EACCES });
        unsafe { libc::_exit(1) };
    }
    // NARROW BEFORE THE BIND, ZERO AFTER. Entering A's user namespace granted a full effective set,
    // and the only thing left that can need one is this bind: a service on port 80 puts it under
    // `CAP_NET_BIND_SERVICE`. Holding just that one across the bind makes the window one capability
    // wide rather than forty-one, and there is no reason for it to be wider.
    //
    // NOTHING BETWEEN THESE TWO CALLS MAY TOUCH A PATH, AN ENVIRONMENT VARIABLE OR A FILE. This half
    // still holds the HOST mount namespace, so a log line, a `getenv` or an error formatter placed
    // here would put a host filesystem inside the window. `bind_host_socket` takes an address and a
    // port and calls `socket`/`setsockopt`/`bind`; keep it that way.
    // `CAP_NET_BIND_SERVICE` is capability 10. Spelled here because this `libc` version does not
    // export the constant, and the number is fixed by the kernel ABI rather than by a header.
    const CAP_NET_BIND_SERVICE: u32 = 10;
    if !restrict_capabilities(1u64 << CAP_NET_BIND_SERVICE) {
        write_status(status, if errno() != 0 { errno() } else { libc::EPERM });
        unsafe { libc::_exit(1) };
    }
    let listener = match bind_host_socket(alias_ip, port, false) {
        Ok(fd) => fd,
        Err(e) => {
            write_status(status, e);
            unsafe { libc::_exit(1) };
        }
    };
    // AND NOW TO ZERO. Everything past this line is `accept` and `sendmsg`, neither of which needs
    // a capability at all.
    //
    // FAIL-CLOSED: a half that cannot shed them does not serve. It would still work, and that is
    // precisely the trade this refuses - the relay keeps the HOST mount namespace, so it is the one
    // process in the stack with a host filesystem view reachable from inside a box, and its own
    // privilege is the boundary.
    if !drop_all_capabilities() {
        write_status(status, if errno() != 0 { errno() } else { libc::EPERM });
        unsafe { libc::_exit(1) };
    }
    // LAST, AFTER THE BIND AND THE DROP. See `seccomp::install_relay_filter` for why this half gets a
    // denylist where a box gets an allowlist. Fail-closed: a half that cannot be filtered does not
    // serve, because the filter is what stands between a box-reachable socket and a host mount view.
    if crate::seccomp::install_relay_filter().is_err() {
        write_status(status, if errno() != 0 { errno() } else { libc::EPERM });
        unsafe { libc::_exit(1) };
    }
    write_status(status, 0);
    // The status pipe has done its job; keeping it open would hold a descriptor for the process's
    // whole life and keep the parent's read end from ever seeing EOF.
    unsafe { libc::close(status) };
    loop {
        let conn = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
        if conn < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            break;
        }
        // A failed hand-off closes the connection rather than leaking the descriptor. It also means
        // the connector is gone, so there is nothing left to serve: stop.
        let ok = send_fd(pair, conn);
        unsafe { libc::close(conn) };
        if !ok {
            break;
        }
    }
    unsafe { libc::_exit(0) }
}

/// The connector half: enter B and, per received socket, fork a pump that connects to B's loopback.
/// Never returns.
fn connector_main(
    status: i32,
    pair: i32,
    b: BoxRef,
    port: u16,
    parent: i32,
    from_alias: u32,
    pump_cap: usize,
) -> ! {
    // SAFETY: a disposition on this process only. `SIGCHLD` is deliberately LEFT AT DEFAULT here,
    // unlike the port forwarder: the loop below reaps its own pumps because it has to count them.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    if !die_with_parent(parent) {
        unsafe { libc::_exit(0) };
    }
    if !enter_box_ns_pinned(b.pid1, b.starttime) {
        write_status(status, if errno() != 0 { errno() } else { libc::EACCES });
        unsafe { libc::_exit(1) };
    }
    // IMMEDIATELY, unlike the listener: this half only ever calls `connect` on a loopback address
    // above 1024 or not, and `connect` needs no capability at any port. See `drop_all_capabilities`.
    if !drop_all_capabilities() {
        write_status(status, if errno() != 0 { errno() } else { libc::EPERM });
        unsafe { libc::_exit(1) };
    }
    // LAST, and INHERITED BY EVERY PUMP: a seccomp filter survives `fork`, so the per-connection
    // children are covered without installing anything of their own. See
    // `seccomp::install_relay_filter`. Fail-closed for the same reason as the listener.
    if crate::seccomp::install_relay_filter().is_err() {
        write_status(status, if errno() != 0 { errno() } else { libc::EPERM });
        unsafe { libc::_exit(1) };
    }
    // CHECKED ONCE, HERE, and not per connection. Every forwarded connection is made FROM the calling
    // service's own alias so the receiving service can tell its peers apart (see
    // `connect_box_loopback_from`). If that address cannot be bound in this namespace, every future
    // connection would fail one at a time, in a child, with nowhere to report it. Failing at start-up
    // instead makes it the spawn error the holder already knows how to surface.
    if !source_address_is_bindable(from_alias) {
        write_status(
            status,
            if errno() != 0 {
                errno()
            } else {
                libc::EADDRNOTAVAIL
            },
        );
        unsafe { libc::_exit(1) };
    }
    write_status(status, 0);
    unsafe { libc::close(status) };
    // Read ONCE, before any pump exists: each pump arms `PDEATHSIG` against this pid, and reading it
    // in the child after the fork would race a `getppid` that has already been reparented.
    // SAFETY: returns this process's pid and cannot fail.
    let my_pid = unsafe { libc::getpid() };
    let mut live: usize = 0;
    loop {
        let conn = recv_fd(pair);
        if conn < 0 {
            break;
        }
        // REAP FIRST, THEN COUNT. `SIGCHLD` used to be `SIG_IGN` here, which let the kernel reap the
        // pumps and made the number of live ones unknowable; with no number there is no bound, and
        // with no bound a box that opens connections faster than its peer closes them turns this
        // process into a fork loop until `RLIMIT_NPROC` stops it. That limit belongs to the USER, so
        // the next process it refuses to create is not necessarily one of these.
        //
        // The count only has to be right at the moment of the fork, and `recv_fd` blocks in between,
        // so reaping here and nowhere else is sufficient. Zombies can sit between two connections,
        // bounded by `pump_cap`, which is the same bound this is enforcing.
        loop {
            let mut st: libc::c_int = 0;
            // SAFETY: reaps this process's own children without blocking; writes only into `st`.
            let r = unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) };
            if r <= 0 {
                break;
            }
            live = live.saturating_sub(1);
        }
        if live >= pump_cap {
            // REFUSED, NOT QUEUED. Closing the descriptor gives the client a connection that opens
            // and immediately ends, which is what a saturated server does. Queueing would move the
            // unbounded growth into this process's memory instead of into the process table.
            unsafe { libc::close(conn) };
            continue;
        }
        // SAFETY: `fork` in a single-threaded process; the child touches only async-signal-safe calls
        // and its own descriptors.
        let c = unsafe { libc::fork() };
        if c == 0 {
            unsafe { libc::close(pair) };
            // THE PUMP DIES WITH THE CONNECTOR, and it did not until this line existed.
            //
            // `PR_SET_PDEATHSIG` is NOT inherited across `fork`, so arming it in the two halves left
            // every pump unprotected. MEASURED: killing the holder took the listener and the
            // connector with it and left ONE process behind, still holding a connection open between
            // two boxes' namespaces. A probe blocked in `read` on that connection never saw it end.
            //
            // That is worse than a leaked process: a pump is the thing that bridges two isolation
            // domains, and it was outliving the teardown meant to remove it. `compose down` has the
            // same shape, so a stack could be brought down and still be relaying.
            //
            // Armed against the CONNECTOR rather than the holder, because the connector is this
            // process's parent and `PDEATHSIG` fires on the parent's death. The holder's own death
            // kills the connector, which then kills its pumps, so the cascade reaches the whole tree.
            if !die_with_parent(my_pid) {
                unsafe {
                    libc::close(conn);
                    libc::_exit(0);
                }
            }
            let peer = connect_box_loopback_from(from_alias, port, libc::SOCK_STREAM);
            if peer < 0 {
                unsafe {
                    libc::close(conn);
                    libc::_exit(1);
                }
            }
            crate::ports::set_nodelay(conn);
            crate::ports::set_nodelay(peer);
            pump_bidir(conn, peer);
            unsafe {
                libc::close(peer);
                libc::close(conn);
                libc::_exit(0);
            }
        }
        // Parent of the pump: the descriptor now belongs to the child.
        unsafe { libc::close(conn) };
        if c > 0 {
            live += 1;
        }
        if c < 0 {
            // Cannot fork: drop this connection and keep serving rather than dying, so a transient
            // process-table pressure does not take the relay down with it.
            continue;
        }
    }
    unsafe { libc::_exit(0) }
}

/// Two boxes share one network namespace when their `/proc/<pid>/ns/net` resolve to the same inode.
///
/// Fails CLOSED (`true` on any read failure): a relay between two boxes that are really the same
/// namespace would bind and connect in one place, which is not a relay but a loop, and refusing it
/// costs nothing.
fn same_netns(a_pid1: i32, b_pid1: i32) -> bool {
    let ino = |pid: i32| -> Option<(u64, u64)> {
        let md = std::fs::metadata(format!("/proc/{pid}/ns/net")).ok()?;
        use std::os::unix::fs::MetadataExt;
        Some((md.dev(), md.ino()))
    };
    match (ino(a_pid1), ino(b_pid1)) {
        (Some(x), Some(y)) => x == y,
        _ => true,
    }
}

/// Spawn one relay so that, inside box `a_pid1`, `alias_ip:port` reaches `b_pid1`'s
/// `127.0.0.1:port`.
///
/// Both children are forked from the CALLER's namespaces, which must be the host's: the measured
/// constraint in this module's header is why that is not negotiable.
///
/// # Errors
///
/// A message naming the syscall and the errno. Every early failure kills and reaps whatever was
/// already forked, so a failed spawn leaves no process behind.
pub fn spawn(
    a: BoxRef,
    alias_ip: u32,
    b: BoxRef,
    port: u16,
    from_alias: u32,
    pump_cap: usize,
) -> Result<PeerRelay, String> {
    let (a_pid1, b_pid1) = (a.pid1, b.pid1);
    if a_pid1 <= 0 || b_pid1 <= 0 {
        return Err(format!(
            "peer relay: refusing a non-positive pid (a={a_pid1}, b={b_pid1})"
        ));
    }
    if port == 0 {
        return Err("peer relay: port 0 is not a port".to_string());
    }
    if same_netns(a_pid1, b_pid1) {
        return Err(
            "peer relay: the two boxes share one network namespace (or their namespaces could not \
             be read); there is nothing to relay"
                .to_string(),
        );
    }
    if !assert_cmsg_fits() {
        return Err(
            "peer relay: this platform's CMSG_SPACE does not fit the control buffer".into(),
        );
    }
    let mut pair = [0i32; 2];
    // SOCK_SEQPACKET: SCM_RIGHTS travels with a message, and a stream would let two hand-offs merge.
    //
    // ANONYMOUS, AND IT MUST STAY ANONYMOUS. `socketpair` creates an unnamed pair, so no process in
    // either box's network namespace can address it: the descriptor is the only handle, and it exists
    // only in these two children. Replacing it with an abstract `AF_UNIX` name would break that, and
    // not subtly - the abstract namespace is scoped per NETWORK namespace, so a box sharing the
    // relay's netns could connect to that name and either receive descriptors it was handed or send
    // its own. The fd-passing channel would become reachable from the thing it isolates.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!("peer relay: socketpair: {}", errno()));
    }
    let mut lst = [0i32; 2];
    let mut cst = [0i32; 2];
    let mk_pipe = |fds: &mut [i32; 2]| -> bool {
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) == 0 }
    };
    if !mk_pipe(&mut lst) {
        let e = errno();
        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
        return Err(format!("peer relay: pipe: {e}"));
    }
    if !mk_pipe(&mut cst) {
        let e = errno();
        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
            libc::close(lst[0]);
            libc::close(lst[1]);
        }
        return Err(format!("peer relay: pipe: {e}"));
    }
    let parent = unsafe { libc::getpid() };

    // SAFETY: `fork` in a process that is single-threaded on this path (the caller runs before the
    // sandbox fork, exactly as the port forwarder does).
    let l_pid = unsafe { libc::fork() };
    if l_pid < 0 {
        let e = errno();
        unsafe {
            libc::close(pair[0]);
            libc::close(pair[1]);
            libc::close(lst[0]);
            libc::close(lst[1]);
            libc::close(cst[0]);
            libc::close(cst[1]);
        }
        return Err(format!("peer relay: fork (listener): {e}"));
    }
    if l_pid == 0 {
        unsafe {
            libc::close(pair[1]);
            libc::close(lst[0]);
            libc::close(cst[0]);
            libc::close(cst[1]);
        }
        listener_main(lst[1], pair[0], a, alias_ip, port, parent);
    }

    let c_pid = unsafe { libc::fork() };
    if c_pid < 0 {
        let e = errno();
        // GUARDED, THOUGH IT IS PROVABLY POSITIVE HERE: `l_pid < 0` returned above and `l_pid == 0`
        // never reaches this line (the child does not return from `listener_main`). The check costs a
        // compare and removes a `kill(0, …)` / `kill(-1, …)` that a future reordering could reach,
        // which is the exact class this tree already shipped a security fix for.
        unsafe {
            if l_pid > 0 {
                libc::kill(l_pid, libc::SIGKILL);
                let mut st: libc::c_int = 0;
                libc::waitpid(l_pid, &mut st, 0);
            }
            libc::close(pair[0]);
            libc::close(pair[1]);
            libc::close(lst[0]);
            libc::close(lst[1]);
            libc::close(cst[0]);
            libc::close(cst[1]);
        }
        return Err(format!("peer relay: fork (connector): {e}"));
    }
    if c_pid == 0 {
        unsafe {
            libc::close(pair[0]);
            libc::close(lst[0]);
            libc::close(lst[1]);
            libc::close(cst[0]);
        }
        connector_main(cst[1], pair[1], b, port, parent, from_alias, pump_cap);
    }

    // Parent: every end the children own is closed here, so an EOF on a status pipe really means the
    // child exited rather than "the parent still holds the write end".
    unsafe {
        libc::close(pair[0]);
        libc::close(pair[1]);
        libc::close(lst[1]);
        libc::close(cst[1]);
    }
    let mut relay = PeerRelay {
        listener_pid: l_pid,
        connector_pid: c_pid,
        alias_ip,
        port,
    };
    let l_status = read_status(lst[0]);
    let c_status = read_status(cst[0]);
    unsafe {
        libc::close(lst[0]);
        libc::close(cst[0]);
    }
    match (l_status, c_status) {
        (Some(0), Some(0)) => Ok(relay),
        (Some(e), _) if e != 0 => {
            relay.shutdown();
            Err(format!(
                "peer relay: binding {}.{}.{}.{}:{port} inside the calling box: errno {e}",
                alias_ip >> 24 & 0xff,
                alias_ip >> 16 & 0xff,
                alias_ip >> 8 & 0xff,
                alias_ip & 0xff
            ))
        }
        (_, Some(e)) if e != 0 => {
            relay.shutdown();
            Err(format!(
                "peer relay: entering the peer box's namespaces: errno {e}"
            ))
        }
        _ => {
            relay.shutdown();
            Err("peer relay: a half exited before reporting; nothing is serving".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `open(path, O_WRONLY)` + one `write`, with no allocation anywhere. `path` must be
    /// NUL-terminated. Returns whether the whole buffer was written.
    fn write_file_raw(path: &[u8], data: &[u8]) -> bool {
        // SAFETY: `path` is NUL-terminated by the caller; the write reads `data`'s own bytes.
        unsafe {
            let fd = libc::open(path.as_ptr().cast(), libc::O_WRONLY);
            if fd < 0 {
                return false;
            }
            let n = libc::write(fd, data.as_ptr().cast(), data.len());
            libc::close(fd);
            n == data.len() as isize
        }
    }

    /// Write `0 <id> 1` to a uid/gid map file without allocating: the digits are rendered into a
    /// stack buffer, which is what a forked child of a threaded process is allowed to do.
    fn write_uid_map_raw(path: &[u8], id: u32) -> bool {
        let mut buf = [0u8; 32];
        let mut n = 0usize;
        for b in b"0 " {
            buf[n] = *b;
            n += 1;
        }
        // Render the decimal digits most-significant first, without `format!`.
        let mut digits = [0u8; 10];
        let mut d = 0usize;
        let mut v = id;
        if v == 0 {
            digits[0] = b'0';
            d = 1;
        }
        while v > 0 {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
        while d > 0 {
            d -= 1;
            buf[n] = digits[d];
            n += 1;
        }
        for b in b" 1" {
            buf[n] = *b;
            n += 1;
        }
        write_file_raw(path, &buf[..n])
    }

    /// A namespace fixture: a child in its OWN user+net namespace with loopback up. Returns its pid,
    /// or `None` when this host refuses unprivileged user namespaces, which is a skip and not a
    /// failure (the CI runners' AppArmor profile refuses the `uid_map` write).
    ///
    /// `serve_port` non-zero makes the child a one-shot TCP echo on `127.0.0.1:serve_port`, which is
    /// the peer end of the relay under test. Zero makes it an idle namespace, which is the near end.
    fn ns_child(serve_port: u16, ready: i32) -> Option<i32> {
        // SAFETY: fork in a test binary; the child below touches only its own descriptors and
        // async-signal-safe calls before it either serves or pauses.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return None;
        }
        // THE IDS ARE READ BEFORE THE UNSHARE, and that ordering is the whole bug this line fixes.
        // `uid_map` must state the uid as the PARENT namespace sees it. After `unshare(CLONE_NEWUSER)`
        // the process is unmapped, so `geteuid()` answers the overflow uid (65534), and writing
        // `0 65534 1` is refused with EPERM because that is not the caller's real uid. Measured: the
        // child reported 2201 (EPERM at the uid_map write) until this moved above the unshare, which
        // is also why the production helper takes the ids as ARGUMENTS rather than reading them.
        // SAFETY: reads of this process's own credentials.
        let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
        if pid == 0 {
            // SAFETY: unshare on this process only.
            // Distinct code per step: a single errno cannot say WHICH call refused, and a skip that
            // cannot name its reason is indistinguishable from a test that never ran.
            let ok = unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } == 0;
            if !ok {
                write_status(ready, 1000 + errno());
                unsafe { libc::_exit(1) };
            }
            // RAW SYSCALLS, NOT `std::fs::write`. This is a child of a fork from cargo's
            // MULTI-THREADED test harness: only the calling thread survives, so any allocator lock a
            // sibling thread held at fork time is held forever here, and every allocating call is a
            // hazard. Measured: routing this through the production helper (which formats a `String`
            // per map) reported EPERM at the first write on a host where the same sequence succeeds
            // in a single-threaded process. The fix is the discipline, not the permission.
            //
            // Buffers are stack arrays written with `snprintf`-free formatting: the maps are
            // `0 <uid> 1`, and a `u32` is at most ten digits.
            if !write_file_raw(b"/proc/self/setgroups\0", b"deny") {
                write_status(ready, 2100 + errno());
                unsafe { libc::_exit(1) };
            }
            if !write_uid_map_raw(b"/proc/self/uid_map\0", euid) {
                write_status(ready, 2200 + errno());
                unsafe { libc::_exit(1) };
            }
            if !write_uid_map_raw(b"/proc/self/gid_map\0", egid) {
                write_status(ready, 2300 + errno());
                unsafe { libc::_exit(1) };
            }
            crate::real::bring_loopback_up();
            if serve_port == 0 {
                write_status(ready, 0);
                unsafe { libc::close(ready) };
                // Idle: hold the namespace open for the relay's listener half.
                loop {
                    unsafe { libc::pause() };
                }
            }
            let srv = match bind_host_socket(0x7f00_0001, serve_port, false) {
                Ok(fd) => fd,
                Err(e) => {
                    write_status(ready, 3000 + e);
                    unsafe { libc::_exit(1) };
                }
            };
            write_status(ready, 0);
            unsafe { libc::close(ready) };
            loop {
                // SAFETY: accept on a socket this process owns.
                let c = unsafe { libc::accept(srv, std::ptr::null_mut(), std::ptr::null_mut()) };
                if c < 0 {
                    if errno() == libc::EINTR {
                        continue;
                    }
                    break;
                }
                let msg = b"PEER-OK";
                // SAFETY: writing an owned buffer to an accepted socket.
                unsafe {
                    libc::write(c, msg.as_ptr().cast(), msg.len());
                    libc::close(c);
                }
            }
            unsafe { libc::_exit(0) };
        }
        Some(pid)
    }

    /// THE GATE FOR THIS MODULE: a byte crosses two network namespaces that share nothing.
    ///
    /// Box B listens on its own `127.0.0.1:PORT`; box A holds a namespace with only loopback. The
    /// relay makes B's port answer at `127.0.0.2:PORT` INSIDE A. The assertion is made from inside A,
    /// by a process that entered A's namespaces, so it is the same reachability a service would have
    /// - not a host-side approximation of it.
    ///
    /// The negative half is structural rather than a second assertion: before the relay exists there
    /// is nothing at `127.0.0.2` in A, which is exactly the state the `--no-pod` measurement found
    /// and this module was written to change. It is asserted first, so a host where the address
    /// somehow already answered would fail here rather than pass the whole test for the wrong reason.
    #[test]
    fn a_connection_crosses_two_namespaces_through_the_relay() {
        const PORT: u16 = 47_811;
        const ALIAS: u32 = 0x7f00_0002; // 127.0.0.2

        let mut rb = [0i32; 2];
        let mut ra = [0i32; 2];
        // SAFETY: each fills a two-element array.
        if unsafe { libc::pipe(rb.as_mut_ptr()) } != 0
            || unsafe { libc::pipe(ra.as_mut_ptr()) } != 0
        {
            eprintln!("skip: cannot create a pipe");
            return;
        }
        let Some(b_pid) = ns_child(PORT, rb[1]) else {
            eprintln!("skip: cannot fork");
            return;
        };
        let Some(a_pid) = ns_child(0, ra[1]) else {
            eprintln!("skip: cannot fork");
            return;
        };
        // SAFETY: the write ends belong to the children now.
        unsafe {
            libc::close(rb[1]);
            libc::close(ra[1]);
        }
        let b_ready = read_status(rb[0]);
        let a_ready = read_status(ra[0]);
        // SAFETY: closing read ends this test owns.
        unsafe {
            libc::close(rb[0]);
            libc::close(ra[0]);
        }
        let reap = |pid: i32| {
            if pid > 0 {
                // SAFETY: signalling a child this test forked.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    let mut st: libc::c_int = 0;
                    libc::waitpid(pid, &mut st, 0);
                }
            }
        };
        if b_ready != Some(0) || a_ready != Some(0) {
            reap(a_pid);
            reap(b_pid);
            eprintln!(
                "skip: unprivileged user namespaces unusable here (b={b_ready:?}, a={a_ready:?})"
            );
            return;
        }

        // The source alias the connector binds inside B. Distinct from `ALIAS` so the assertion
        // below is about the target's address and cannot pass by the two being equal.
        const FROM: u32 = 0x7f00_0003;
        let relay = match spawn(
            BoxRef {
                pid1: a_pid,
                starttime: 0,
            },
            ALIAS,
            BoxRef {
                pid1: b_pid,
                starttime: 0,
            },
            PORT,
            FROM,
            MAX_LIVE_PUMPS,
        ) {
            Ok(r) => r,
            Err(e) => {
                reap(a_pid);
                reap(b_pid);
                // A host that refuses `setns` into a child user namespace cannot run this at all;
                // that is a skip, and the message says which half refused.
                eprintln!("skip: the relay could not be spawned here: {e}");
                return;
            }
        };

        // Probe FROM INSIDE A, in a forked child so the test process keeps its own namespaces.
        let mut pr = [0i32; 2];
        // SAFETY: fills a two-element array.
        assert_eq!(unsafe { libc::pipe(pr.as_mut_ptr()) }, 0, "probe pipe");
        // SAFETY: fork in a test binary.
        let probe = unsafe { libc::fork() };
        assert!(probe >= 0, "fork the probe");
        if probe == 0 {
            // SAFETY: the read end belongs to the parent.
            unsafe { libc::close(pr[0]) };
            if !enter_box_ns_pinned(a_pid, 0) {
                write_status(pr[1], -1);
                unsafe { libc::_exit(1) };
            }
            let s = connect_alias(ALIAS, PORT);
            if s < 0 {
                write_status(pr[1], -2);
                unsafe { libc::_exit(1) };
            }
            let mut buf = [0u8; 16];
            // SAFETY: reading into an owned buffer.
            let n = unsafe { libc::read(s, buf.as_mut_ptr().cast(), buf.len()) };
            // SAFETY: closing a descriptor this process owns.
            unsafe { libc::close(s) };
            let ok = n == 7 && &buf[..7] == b"PEER-OK";
            write_status(pr[1], if ok { 0 } else { -3 });
            unsafe { libc::_exit(0) };
        }
        // SAFETY: the write end belongs to the probe.
        unsafe { libc::close(pr[1]) };
        let verdict = read_status(pr[0]);
        // SAFETY: closing a descriptor this test owns, then reaping the probe.
        unsafe {
            libc::close(pr[0]);
            let mut st: libc::c_int = 0;
            libc::waitpid(probe, &mut st, 0);
        }
        drop(relay); // kills both halves before the boxes go, so no orphan outlives the test
        reap(a_pid);
        reap(b_pid);

        match verdict {
            Some(0) => {}
            Some(-1) => eprintln!("skip: this host refuses setns into a child user namespace"),
            other => panic!(
                "the relay did not carry the connection across the namespace boundary: {other:?} \
                 (-2 = connect refused inside A, -3 = wrong bytes)"
            ),
        }
    }

    /// Connect to `alias:port` in the CURRENT network namespace. The near-end twin of
    /// `connect_box_loopback`, which is fixed at `127.0.0.1`.
    fn connect_alias(ip: u32, port: u16) -> i32 {
        // SAFETY: creating and connecting a socket owned by this process.
        unsafe {
            let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if s < 0 {
                return -1;
            }
            let addr = crate::ports::addr_in(ip, port);
            if libc::connect(
                s,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) != 0
            {
                libc::close(s);
                return -1;
            }
            s
        }
    }

    /// The alias sequence starts at `.2`, is dense, and stops rather than wrapping.
    ///
    /// A wrapped alias would hand two different peers the same address, and the symptom would be a
    /// service quietly talking to the wrong peer - the worst shape of failure this mechanism can
    /// have, because both ends look healthy.
    #[test]
    fn peer_aliases_are_dense_start_at_two_and_stop() {
        assert_eq!(
            peer_alias(0),
            Some(0x7f00_0002),
            "the first peer is 127.0.0.2"
        );
        assert_eq!(peer_alias(1), Some(0x7f00_0003));
        assert_eq!(
            peer_alias(252),
            Some(0x7f00_00fe),
            "the last usable is 127.0.0.254"
        );
        assert_eq!(
            peer_alias(MAX_PEER_INDEX),
            None,
            "one past the range refuses"
        );
        assert_eq!(peer_alias(usize::MAX), None, "and so does anything beyond");
        // Never `.1` (the box's own loopback) and never `.255` (broadcast of that /24).
        for i in 0..MAX_PEER_INDEX {
            let Some(ip) = peer_alias(i) else {
                panic!("index {i} is inside the range and must have an alias");
            };
            assert_ne!(
                ip & 0xff,
                1,
                "index {i} collided with the box's own loopback"
            );
            assert_ne!(ip & 0xff, 255, "index {i} landed on the broadcast address");
            assert_eq!(ip >> 8, 0x7f_0000, "index {i} left 127.0.0.0/24");
        }
        // Injective over the whole range: two peers must never share an address.
        let mut seen = [false; 256];
        for i in 0..MAX_PEER_INDEX {
            let Some(ip) = peer_alias(i) else { continue };
            let last = (ip & 0xff) as usize;
            assert!(!seen[last], "index {i} reused 127.0.0.{last}");
            seen[last] = true;
        }
    }

    /// Rendering is exact at every octet boundary, and allocates nothing.
    #[test]
    fn an_alias_renders_as_a_dotted_quad() {
        let mut buf = [0u8; 15];
        assert_eq!(alias_to_dotted(0x7f00_0002, &mut buf), "127.0.0.2");
        assert_eq!(alias_to_dotted(0x7f00_000a, &mut buf), "127.0.0.10");
        assert_eq!(alias_to_dotted(0x7f00_0064, &mut buf), "127.0.0.100");
        assert_eq!(alias_to_dotted(0x7f00_00fe, &mut buf), "127.0.0.254");
        assert_eq!(alias_to_dotted(0x7f00_0001, &mut buf), "127.0.0.1");
        assert_eq!(alias_to_dotted(0, &mut buf), "0.0.0.0");
        assert_eq!(alias_to_dotted(0xffff_ffff, &mut buf), "255.255.255.255");
        assert_eq!(alias_to_dotted(0x0a00_0001, &mut buf), "10.0.0.1");
    }

    /// Every alias in the range round-trips through the renderer to the same four octets. A renderer
    /// that dropped a digit would produce an address that parses to a DIFFERENT host, which is the
    /// silent-wrong-peer failure again, one layer up.
    #[test]
    fn every_alias_renders_to_its_own_octets() {
        let mut buf = [0u8; 15];
        for i in 0..MAX_PEER_INDEX {
            let Some(ip) = peer_alias(i) else { continue };
            let text = alias_to_dotted(ip, &mut buf).to_string();
            let parts: Vec<u32> = text.split('.').filter_map(|p| p.parse().ok()).collect();
            assert_eq!(parts.len(), 4, "{text} is not four octets");
            let back = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
            assert_eq!(
                back, ip,
                "{text} does not read back as the alias it came from"
            );
        }
    }

    /// The control buffer must fit this platform's `CMSG_SPACE(size_of::<int>())`. If it does not,
    /// `sendmsg` silently transfers no descriptor and the relay looks alive while serving nothing.
    #[test]
    fn the_control_buffer_fits_one_descriptor() {
        assert!(
            assert_cmsg_fits(),
            "CMSG_SPACE for one fd exceeds CMSG_BUF ({CMSG_BUF})"
        );
        // SAFETY: pure computation.
        let need = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as libc::c_uint) };
        assert!(need as usize >= mem::size_of::<libc::cmsghdr>());
    }

    /// The buffer carries `cmsghdr`'s alignment. A 1-aligned array would make every `CMSG_FIRSTHDR`
    /// cast undefined behaviour, which is the kind of thing that works until it does not.
    #[test]
    fn the_control_buffer_is_aligned_for_cmsghdr() {
        let space = CmsgSpace::new();
        // SAFETY: reading the address of an initialised union arm.
        let addr = unsafe { space.bytes.as_ptr() } as usize;
        assert_eq!(
            addr % mem::align_of::<libc::cmsghdr>(),
            0,
            "the control buffer must satisfy cmsghdr's alignment"
        );
    }

    /// A descriptor survives the hand-off, and what arrives is the SAME open file description: the
    /// receiver reads what the sender's peer wrote. Asserted with a real socketpair rather than a
    /// mock, because the property under test is the kernel's, not this module's arithmetic.
    #[test]
    fn a_descriptor_survives_the_handoff() {
        let mut carrier = [0i32; 2];
        let mut payload = [0i32; 2];
        // SAFETY: both take a two-element array to fill.
        assert_eq!(
            unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, carrier.as_mut_ptr())
            },
            0,
            "socketpair (carrier)"
        );
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, payload.as_mut_ptr()) },
            0,
            "socketpair (payload)"
        );
        assert!(send_fd(carrier[0], payload[0]), "send_fd failed");
        let got = recv_fd(carrier[1]);
        assert!(got >= 0, "recv_fd returned {got}");
        assert_ne!(got, payload[0], "a received fd is a NEW descriptor number");

        // Write on the far end of the payload pair; read it through the descriptor that travelled.
        let msg = b"through";
        // SAFETY: writing an owned buffer to an open socket.
        let n = unsafe { libc::write(payload[1], msg.as_ptr().cast(), msg.len()) };
        assert_eq!(n, msg.len() as isize, "write to the payload peer");
        let mut buf = [0u8; 16];
        // SAFETY: reading into an owned buffer from the received descriptor.
        let r = unsafe { libc::read(got, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(r, msg.len() as isize, "read through the transferred fd");
        assert_eq!(&buf[..msg.len()], msg, "the bytes are the same open file");

        for fd in [carrier[0], carrier[1], payload[0], payload[1], got] {
            // SAFETY: closing descriptors this test owns.
            unsafe { libc::close(fd) };
        }
    }

    /// A carrier with nothing to receive answers -1 rather than blocking forever or returning a
    /// descriptor number that was never sent. The three failing shapes collapse to one answer on
    /// purpose; see `recv_fd`.
    #[test]
    fn receiving_from_a_closed_carrier_is_minus_one() {
        let mut carrier = [0i32; 2];
        // SAFETY: fills a two-element array.
        assert_eq!(
            unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, carrier.as_mut_ptr())
            },
            0
        );
        // SAFETY: closing the write end makes the read end return EOF rather than block.
        unsafe { libc::close(carrier[0]) };
        assert_eq!(recv_fd(carrier[1]), -1, "EOF on the carrier is -1");
        // SAFETY: closing a descriptor this test owns.
        unsafe { libc::close(carrier[1]) };
    }

    /// A message that carries data but NO control payload is not a descriptor. Without this check the
    /// receiver would read uninitialised control space as an fd number and close, or pump, whatever
    /// descriptor that integer happened to name.
    #[test]
    fn a_message_without_a_control_payload_is_not_a_descriptor() {
        let mut carrier = [0i32; 2];
        // SAFETY: fills a two-element array.
        assert_eq!(
            unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, carrier.as_mut_ptr())
            },
            0
        );
        let byte = [b'x'; 1];
        // SAFETY: writing an owned buffer.
        let n = unsafe { libc::write(carrier[0], byte.as_ptr().cast(), 1) };
        assert_eq!(n, 1);
        assert_eq!(
            recv_fd(carrier[1]),
            -1,
            "a plain byte must not be read as a descriptor"
        );
        for fd in carrier {
            // SAFETY: closing descriptors this test owns.
            unsafe { libc::close(fd) };
        }
    }

    /// THE PUMP CAP IS THE STACK'S BUDGET DIVIDED, not a per-relay number that never binds.
    ///
    /// It was a flat 256 per relay, and a four-service stack with three ports each has 24 relays, so
    /// the number that actually applied was 6,144 processes: `RLIMIT_NPROC` and the cgroup `pids`
    /// limit are reached long before any single relay's cap. Asserted at both ends, because a bound
    /// with no floor divides a wide stack down to a relay that carries one connection at a time.
    #[test]
    fn the_pump_cap_shares_one_stack_budget_and_has_both_ends() {
        assert_eq!(pump_cap_for(0), MAX_LIVE_PUMPS, "no relays: the ceiling");
        assert_eq!(
            pump_cap_for(1),
            MAX_LIVE_PUMPS,
            "one relay cannot exceed it"
        );
        assert_eq!(
            pump_cap_for(4),
            MAX_LIVE_PUMPS,
            "1024/4 is still the ceiling"
        );
        assert_eq!(
            pump_cap_for(8),
            STACK_PUMP_BUDGET / 8,
            "and then it divides"
        );
        // 1024/24 is 42, NOT the floor. The first version of this assertion said it was, which is
        // how a bound comes to look tighter than it is: the floor only takes over past 64 relays,
        // and that is exactly where the aggregate stops being the budget.
        assert_eq!(pump_cap_for(24), 42, "1024/24, above the floor");
        assert_eq!(
            pump_cap_for(64),
            MIN_LIVE_PUMPS,
            "1024/64 is exactly the floor"
        );
        assert_eq!(
            pump_cap_for(65),
            MIN_LIVE_PUMPS,
            "and past it the floor holds"
        );
        assert_eq!(pump_cap_for(100_000), MIN_LIVE_PUMPS, "however far past");

        // THE AGGREGATE IS WHAT THE BOUND IS FOR, so it is the thing asserted. Above the point where
        // the floor takes over the product grows again, which is deliberate and bounded by the alias
        // range: 253 services is the most a stack can have, and the floor keeps every relay usable.
        for n in [1usize, 2, 4, 8, 16, 32, 64] {
            let total = pump_cap_for(n) * n;
            assert!(
                total <= STACK_PUMP_BUDGET,
                "{n} relays would allow {total} pumps, over the {STACK_PUMP_BUDGET} budget"
            );
        }
    }

    /// Spawning refuses a non-positive pid before it forks anything. `kill(0, …)` hits the caller's
    /// process group and `kill(-1, …)` every process the user owns; a relay that accepted such a pid
    /// would arm exactly that at teardown.
    #[test]
    fn a_non_positive_pid_is_refused_before_anything_is_forked() {
        for (a, b) in [(0, 1), (1, 0), (-1, 1), (1, -1), (0, 0)] {
            let e = spawn(
                BoxRef {
                    pid1: a,
                    starttime: 0,
                },
                0x7f00_0002,
                BoxRef {
                    pid1: b,
                    starttime: 0,
                },
                8080,
                0x7f00_0003,
                MAX_LIVE_PUMPS,
            )
            .expect_err("must refuse");
            assert!(
                e.contains("non-positive pid"),
                "the refusal must name the reason: {e}"
            );
        }
    }

    /// Port 0 is refused: it means "any port" to `bind`, so a relay would listen somewhere nobody
    /// can address and report success.
    #[test]
    fn port_zero_is_refused() {
        let e = spawn(
            BoxRef {
                pid1: 1,
                starttime: 0,
            },
            0x7f00_0002,
            BoxRef {
                pid1: 2,
                starttime: 0,
            },
            0,
            0x7f00_0003,
            MAX_LIVE_PUMPS,
        )
        .expect_err("must refuse");
        assert!(e.contains("port 0"), "{e}");
    }

    /// Two pids in the SAME network namespace have nothing to relay, and this process is its own
    /// example. Fails closed on an unreadable namespace, so a relay is never spawned on a guess.
    #[test]
    fn two_boxes_in_one_namespace_are_refused() {
        let me = std::process::id() as i32;
        assert!(same_netns(me, me), "a pid shares a namespace with itself");
        let me_ref = BoxRef {
            pid1: me,
            starttime: 0,
        };
        let e = spawn(
            me_ref,
            0x7f00_0002,
            me_ref,
            8080,
            0x7f00_0003,
            MAX_LIVE_PUMPS,
        )
        .expect_err("must refuse");
        assert!(e.contains("share one network namespace"), "{e}");
        assert!(
            same_netns(me, 1_000_000_000),
            "an unreadable namespace fails CLOSED"
        );
    }

    /// `shutdown` is idempotent and never signals a non-positive pid. Driven on a relay whose pids
    /// are already cleared, which is the state the second call sees.
    #[test]
    fn shutting_down_twice_signals_nothing_the_second_time() {
        let mut r = PeerRelay {
            listener_pid: -1,
            connector_pid: -1,
            alias_ip: 0x7f00_0002,
            port: 8080,
        };
        r.shutdown();
        r.shutdown();
        assert_eq!(r.listener_pid, -1);
        assert_eq!(r.connector_pid, -1);
    }
}
