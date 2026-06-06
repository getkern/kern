//! Rootless TCP port publishing (`-p host:box`). A forwarder process is forked **before** the
//! sandbox `unshare`, so it stays in the HOST network + user namespace (like `kern exec`). It is
//! then told the box's PID 1 over a pipe; it binds the host port (host net ns) and, per connection,
//! forks a single-threaded connector that joins the box's user+net namespaces and connects to the
//! box's `127.0.0.1:<box_port>`, pumping bytes. No box-side proxy, no shared socket, no extra deps.
//!
//! Why fork pre-unshare: the post-unshare parent is already inside the box's (isolated) net ns, so
//! a forwarder spawned there would bind the box's loopback, not a host-reachable port. Why
//! per-connection fork (not threads): `setns(CLONE_NEWUSER)` is refused in a multithreaded process.

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

/// Fork one forwarder per `(host_port, box_port)` mapping. MUST be called BEFORE the sandbox
/// `unshare`, so each forwarder inherits the host network + user namespace. Each blocks until
/// [`activate`](PortForwarder::activate) sends the box PID 1.
pub fn fork_forwarders(ports: &[(u32, u16, u16)]) -> Vec<PortForwarder> {
    let mut out = Vec::new();
    for &(ip, hp, bp) in ports {
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
            forwarder_main(i32::from_ne_bytes(buf), ip, hp, bp)
        }
        unsafe { libc::close(rd) };
        eprintln!(
            "→ publishing {}.{}.{}.{}:{hp} → box :{bp}",
            ip >> 24 & 0xff,
            ip >> 16 & 0xff,
            ip >> 8 & 0xff,
            ip & 0xff
        );
        if ip == 0 {
            eprintln!("  warning: bound 0.0.0.0 — box port {bp} is reachable from the network");
        }
        out.push(PortForwarder { pid, activate: wr });
    }
    out
}

fn forwarder_main(box_pid1: i32, bind_ip: u32, host_port: u16, box_port: u16) -> ! {
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) }; // auto-reap connectors

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

/// Join the box's user+net namespaces (we start in the host ns, where we have the privilege to
/// enter the box's child user ns — exactly as `kern exec` does), connect to the box's loopback
/// `box_port`, and pump bytes against the accepted host connection `conn`.
fn connector_main(box_pid1: i32, box_port: u16, conn: i32) {
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
            return;
        }
        if libc::setns(user, libc::CLONE_NEWUSER) != 0 || libc::setns(net, libc::CLONE_NEWNET) != 0
        {
            return;
        }
        libc::close(user);
        libc::close(net);
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
