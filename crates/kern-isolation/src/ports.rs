//! Rootless TCP **and UDP** port publishing (`-p host:box[/tcp|/udp]`). A forwarder process is forked
//! **before** the sandbox `unshare`, so it stays in the HOST network + user namespace (like `kern
//! exec`). It is then told the box's PID 1 over a pipe; it binds the host port (host net ns) and
//! forks a single-threaded worker that joins the box's user+net namespaces and connects to the box's
//! `127.0.0.1:<box_port>`, pumping bytes. No box-side proxy, no shared socket, no extra deps.
//!
//! - **TCP**: one worker per accepted connection (a byte pump with half-close).
//! - **UDP**: one worker per *client* — a wildcard host socket sees each client's first datagram, then
//!   a `SO_REUSEPORT` socket *connected* to that client takes over its later datagrams (the kernel
//!   routes a connected match ahead of the wildcard), relaying whole datagrams to a box-side UDP
//!   socket. Per-client workers are capped so a spoofed-source flood can't fork-bomb.
//!
//! Why fork pre-unshare: the post-unshare parent is already inside the box's (isolated) net ns, so
//! a forwarder spawned there would bind the box's loopback, not a host-reachable port. Why
//! per-connection/-client fork (not threads): `setns(CLONE_NEWUSER)` is refused in a multithreaded
//! process.

use std::mem;
use std::ptr;

/// A forwarder forked before the box's namespaces existed. Activate it with the box PID 1 once the
/// box is forked; [`stop`](PortForwarder::stop) tears it down.
pub struct PortForwarder {
    pid: i32,
    /// Pipe write end: the box's PID 1 is sent here to start forwarding; closing it (without a
    /// pid) makes the waiting forwarder exit (e.g. if sandbox setup fails before the box forks).
    activate: i32,
}

impl PortForwarder {
    /// Send the box's PID 1 so the forwarder can reach the box's namespaces, then close the pipe.
    pub fn activate(&self, pid1: i32) {
        let bytes = pid1.to_ne_bytes();
        unsafe {
            libc::write(self.activate, bytes.as_ptr().cast(), bytes.len());
            libc::close(self.activate);
        }
    }

    /// Stop the forwarder (and, via its process group membership, leave nothing listening).
    pub fn stop(&self) {
        unsafe { libc::kill(self.pid, libc::SIGTERM) };
    }
}

/// Pre-flight: verify every `-p` host port can actually be bound (`AF_INET`, matching the mapping's
/// TCP/UDP type) BEFORE the box is declared started. Uses `SO_REUSEADDR` only — NOT `SO_REUSEPORT` —
/// on purpose: the UDP forwarder adds `SO_REUSEPORT` (for its per-client sockets), but a REUSEPORT
/// probe here would bind happily ALONGSIDE another REUSEPORT holder and falsely pass the conflict
/// check. Without this preflight a taken host port only fails inside the forked forwarder — whose
/// stderr a detached box swallows — so the box prints "✔ started" while nothing listens. Returns the
/// first conflicting `(host_port, os-error)`. Best-effort: a socket-creation failure is skipped (the
/// forwarder still reports its own bind error as the backstop).
pub fn preflight(ports: &[(u32, u16, u16, bool)]) -> Result<(), (u16, String)> {
    for &(ip, hp, _bp, udp) in ports {
        let ty = if udp {
            libc::SOCK_DGRAM
        } else {
            libc::SOCK_STREAM
        };
        let s = unsafe { libc::socket(libc::AF_INET, ty, 0) };
        if s < 0 {
            continue;
        }
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                s,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        let addr = addr_in(ip, hp);
        let r = unsafe { libc::bind(s, &addr as *const _ as *const libc::sockaddr, ADDR_LEN) };
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(s) };
        if r != 0 {
            return Err((hp, err.to_string()));
        }
    }
    Ok(())
}

/// Fork one forwarder per `(host_port, box_port)` mapping. MUST be called BEFORE the sandbox
/// `unshare`, so each forwarder inherits the host network + user namespace. Each blocks until
/// [`activate`](PortForwarder::activate) sends the box PID 1.
pub fn fork_forwarders(ports: &[(u32, u16, u16, bool)]) -> Vec<PortForwarder> {
    let mut out = Vec::new();
    for &(ip, hp, bp, udp) in ports {
        let mut p = [0i32; 2];
        if unsafe { libc::pipe(p.as_mut_ptr()) } != 0 {
            eprintln!("kern: -p {hp}:{bp}: pipe failed");
            continue;
        }
        let (rd, wr) = (p[0], p[1]);
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe {
                libc::close(rd);
                libc::close(wr);
            }
            continue;
        }
        if pid == 0 {
            // CHILD = forwarder (still in the host ns). Wait for PID 1, then forward forever.
            unsafe { libc::close(wr) };
            // Shed inherited fds (keep our pipe `rd`) — drops the detached box's readiness pipe so
            // it can't hang `kern box -d`, and the box's scratch/registry fds.
            crate::shed_inherited_fds(rd);
            let mut buf = [0u8; 4];
            let n = unsafe { libc::read(rd, buf.as_mut_ptr().cast(), buf.len()) };
            if n != 4 {
                unsafe { libc::_exit(0) }; // parent gave up (EOF) before the box started
            }
            forwarder_main(i32::from_ne_bytes(buf), ip, hp, bp, udp)
        }
        unsafe { libc::close(rd) };
        eprintln!(
            "→ publishing {}.{}.{}.{}:{hp} → box :{bp}{}",
            ip >> 24 & 0xff,
            ip >> 16 & 0xff,
            ip >> 8 & 0xff,
            ip & 0xff,
            if udp { "/udp" } else { "" }
        );
        if ip == 0 {
            eprintln!("  warning: bound 0.0.0.0 — box port {bp} is reachable from the network");
        }
        out.push(PortForwarder { pid, activate: wr });
    }
    out
}

fn forwarder_main(box_pid1: i32, bind_ip: u32, host_port: u16, box_port: u16, udp: bool) -> ! {
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) }; // auto-reap per-client relays
    if udp {
        udp_forwarder(box_pid1, bind_ip, host_port, box_port);
    }
    let listener = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if listener < 0 {
        unsafe { libc::_exit(1) };
    }
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            listener,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    let addr = addr_in(bind_ip, host_port); // bind_ip:host_port (host net ns)
    if unsafe {
        libc::bind(
            listener,
            &addr as *const _ as *const libc::sockaddr,
            ADDR_LEN,
        )
    } != 0
    {
        eprintln!(
            "kern: -p {host_port}:{box_port}: cannot bind host port {host_port}: {}",
            std::io::Error::last_os_error()
        );
        unsafe { libc::_exit(1) };
    }
    if unsafe { libc::listen(listener, 128) } != 0 {
        unsafe { libc::_exit(1) };
    }
    loop {
        let conn = unsafe { libc::accept(listener, ptr::null_mut(), ptr::null_mut()) };
        if conn < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        let c = unsafe { libc::fork() }; // single-threaded child → setns(USER) allowed
        if c == 0 {
            unsafe { libc::close(listener) };
            connector_main(box_pid1, box_port, conn);
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::close(conn) };
    }
    unsafe { libc::_exit(0) }
}

/// Join the box's user+net namespaces (we start in the host ns, where we have the privilege to enter
/// the box's child user ns — exactly as `kern exec` does). Single-threaded caller only (setns(USER)).
/// Returns `false` on any failure. After this, sockets created here live in the BOX's net ns.
fn enter_box_ns(box_pid1: i32) -> bool {
    let open_ns = |kind: &str| -> i32 {
        let path = format!("/proc/{box_pid1}/ns/{kind}\0");
        unsafe {
            libc::open(
                path.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        }
    };
    unsafe {
        let (user, net) = (open_ns("user"), open_ns("net"));
        if user < 0 || net < 0 {
            return false;
        }
        let ok = libc::setns(user, libc::CLONE_NEWUSER) == 0
            && libc::setns(net, libc::CLONE_NEWNET) == 0;
        libc::close(user);
        libc::close(net);
        ok
    }
}

/// Enter the box namespaces, connect to the box's loopback `box_port`, and pump bytes against the
/// accepted host connection `conn`.
fn connector_main(box_pid1: i32, box_port: u16, conn: i32) {
    if !enter_box_ns(box_pid1) {
        return;
    }
    unsafe {
        let bs = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if bs < 0 {
            return;
        }
        let addr = addr_in(0x7f00_0001, box_port); // 127.0.0.1:box_port
        if libc::connect(bs, &addr as *const _ as *const libc::sockaddr, ADDR_LEN) != 0 {
            libc::close(bs);
            return;
        }
        pump_bidir(conn, bs);
        libc::close(bs);
    }
}

/// Set `SO_REUSEADDR` + `SO_REUSEPORT` on `s` (best-effort). REUSEPORT lets each per-client UDP relay
/// bind the same host port; the kernel then routes a client's datagrams to its own *connected* socket.
fn reuse_addr_port(s: i32) {
    let one: libc::c_int = 1;
    for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
        unsafe {
            libc::setsockopt(
                s,
                libc::SOL_SOCKET,
                opt,
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

/// UDP publish. A wildcard host socket receives each client's FIRST datagram; a per-client child then
/// binds a `SO_REUSEPORT` socket *connected* to that client (so the kernel routes its later datagrams
/// straight to the child, not back here) and relays to a box-side UDP socket. Each relay idles out
/// (see `pump_dgram`) so a request/response client's process/sockets are freed, and the parent's
/// recent-client table is TIME-bounded (not a lifetime blacklist), so a long-lived resolver never hits
/// a cumulative ceiling and a client can reconnect after its relay dies. The group dies with the box.
fn udp_forwarder(box_pid1: i32, bind_ip: u32, host_port: u16, box_port: u16) -> ! {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        unsafe { libc::_exit(1) };
    }
    reuse_addr_port(sock);
    let addr = addr_in(bind_ip, host_port);
    if unsafe { libc::bind(sock, &addr as *const _ as *const libc::sockaddr, ADDR_LEN) } != 0 {
        eprintln!(
            "kern: -p {host_port}:{box_port}/udp: cannot bind host port {host_port}: {}",
            std::io::Error::last_os_error()
        );
        unsafe { libc::_exit(1) };
    }
    // Recently-forked clients (ip:port → when). Its ONLY job is to dedupe the ~ms race window between
    // us reading a client's first datagram and its child binding the connected socket that steals the
    // client's later datagrams. It is TIME-BOUNDED (pruned to `DEDUP_TTL`), NOT a lifetime blacklist —
    // so a long-lived resolver never hits a cumulative ceiling, and a client whose relay died can
    // reconnect once its stale entry ages out. The size cap is a secondary flood guard on RECENT peers.
    const DEDUP_TTL: std::time::Duration = std::time::Duration::from_secs(5);
    const MAX_RECENT: usize = 1024;
    let mut seen: std::collections::HashMap<u64, std::time::Instant> =
        std::collections::HashMap::new();
    let mut buf = [0u8; 65535];
    loop {
        let mut caddr: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut clen = ADDR_LEN;
        let n = unsafe {
            libc::recvfrom(
                sock,
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                &mut caddr as *mut _ as *mut libc::sockaddr,
                &mut clen,
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        let now = std::time::Instant::now();
        seen.retain(|_, &mut t| now.duration_since(t) < DEDUP_TTL);
        // key = client (ip:port). A datagram from a client we forked a relay for in the last DEDUP_TTL
        // only reaches us in the race window before its child took over → drop it (UDP is lossy; the
        // client retransmits to the child). A brand-new (or aged-out) client forks a fresh relay.
        let key = ((caddr.sin_addr.s_addr as u64) << 16) | caddr.sin_port as u64;
        if seen.contains_key(&key) || seen.len() >= MAX_RECENT {
            continue;
        }
        seen.insert(key, now);
        let c = unsafe { libc::fork() };
        if c == 0 {
            unsafe { libc::close(sock) };
            udp_relay_child(
                box_pid1,
                bind_ip,
                host_port,
                box_port,
                caddr,
                &buf[..n as usize],
            );
            unsafe { libc::_exit(0) };
        }
    }
    unsafe { libc::_exit(0) }
}

/// One client's UDP relay: a host socket connected to the client (so it sends replies back to exactly
/// that client) + a box-side socket connected to `127.0.0.1:box_port`, forwarding datagrams both ways.
/// `first` is the initial datagram already read by the parent. Runs until either socket errors.
fn udp_relay_child(
    box_pid1: i32,
    bind_ip: u32,
    host_port: u16,
    box_port: u16,
    client: libc::sockaddr_in,
    first: &[u8],
) {
    unsafe {
        let hs = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if hs < 0 {
            return;
        }
        reuse_addr_port(hs);
        let ha = addr_in(bind_ip, host_port);
        if libc::bind(hs, &ha as *const _ as *const libc::sockaddr, ADDR_LEN) != 0
            || libc::connect(hs, &client as *const _ as *const libc::sockaddr, ADDR_LEN) != 0
        {
            return; // a racing sibling already owns this client's 4-tuple
        }
        if !enter_box_ns(box_pid1) {
            return;
        }
        let bs = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if bs < 0 {
            return;
        }
        let ba = addr_in(0x7f00_0001, box_port); // 127.0.0.1:box_port (box net ns)
        if libc::connect(bs, &ba as *const _ as *const libc::sockaddr, ADDR_LEN) != 0 {
            return;
        }
        // Forward the datagram that got us here, then relay both ways.
        let _ = libc::send(bs, first.as_ptr().cast(), first.len(), 0);
        pump_dgram(hs, bs);
    }
}

/// Relay whole datagrams between two connected UDP sockets until one errors. Unlike [`pump_bidir`],
/// there is no half-close: UDP has no EOF, so it runs until a socket error (e.g. an ICMP port-
/// unreachable surfaces as `ECONNREFUSED` on the connected socket) tears the relay down.
fn pump_dgram(a: i32, b: i32) {
    // UDP has no EOF, so a request/response flow (e.g. DNS) would otherwise leave this relay blocked in
    // `poll` forever, leaking a process + two sockets per client. Exit after this long with no traffic;
    // the client's parent-side dedup entry ages out on the same order, so a later datagram re-forks.
    const IDLE_MS: libc::c_int = 60_000;
    let mut buf = [0u8; 65535];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: a,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: b,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, IDLE_MS) };
        if r == 0 {
            return; // idle timeout — no traffic either way, tear the relay down
        }
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        for (i, &(from, to)) in [(a, b), (b, a)].iter().enumerate() {
            if fds[i].revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                return;
            }
            if fds[i].revents & libc::POLLIN != 0 {
                let n = unsafe { libc::recv(from, buf.as_mut_ptr().cast(), buf.len(), 0) };
                if n < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return;
                }
                // n == 0 is a legitimate zero-length datagram — forward it too.
                let _ = unsafe { libc::send(to, buf.as_ptr().cast(), n as usize, 0) };
            }
        }
    }
}

const ADDR_LEN: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

/// `sockaddr_in` for `ip` (host byte order; `0` = 0.0.0.0) and `port` (host byte order).
fn addr_in(ip: u32, port: u16) -> libc::sockaddr_in {
    let mut a: libc::sockaddr_in = unsafe { mem::zeroed() };
    a.sin_family = libc::AF_INET as libc::sa_family_t;
    a.sin_port = port.to_be();
    a.sin_addr.s_addr = ip.to_be();
    a
}

/// Bidirectional byte pump until both read sides close; each EOF half-closes the peer's write side.
fn pump_bidir(a: i32, b: i32) {
    let mut buf = [0u8; 16384];
    let (mut a_open, mut b_open) = (true, true);
    while a_open || b_open {
        let mut fds = [
            libc::pollfd {
                fd: if a_open { a } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if b_open { b } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if a_open && fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let r = unsafe { libc::read(a, buf.as_mut_ptr().cast(), buf.len()) };
            if r <= 0 {
                a_open = false;
                unsafe { libc::shutdown(b, libc::SHUT_WR) };
            } else {
                write_all(b, &buf[..r as usize]);
            }
        }
        if b_open && fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let r = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) };
            if r <= 0 {
                b_open = false;
                unsafe { libc::shutdown(a, libc::SHUT_WR) };
            } else {
                write_all(a, &buf[..r as usize]);
            }
        }
    }
}

fn write_all(fd: i32, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        data = &data[n as usize..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOOPBACK: u32 = 0x7f00_0001; // 127.0.0.1 (host order; addr_in does the to_be)

    #[test]
    fn preflight_detects_a_bound_port_and_passes_a_free_one() {
        use std::net::TcpListener;
        // An actively-listening port must be reported as taken (this is the check that stops a box
        // printing "started" while its `-p` forwarder silently fails to bind).
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = l.local_addr().unwrap().port();
        match preflight(&[(LOOPBACK, taken, 80, false)]) {
            Err((p, _)) => assert_eq!(p, taken, "reported the conflicting port"),
            Ok(()) => panic!("preflight passed a port that is actively listening"),
        }
        // A free port passes. (Grab one from the OS, release it, then check.)
        let free = {
            let t = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            t.local_addr().unwrap().port()
        };
        assert!(
            preflight(&[(LOOPBACK, free, 80, false)]).is_ok(),
            "a free port should pass"
        );
    }
}
