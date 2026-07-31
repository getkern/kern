//! Rootless TCP **and UDP** port publishing (`-p host:box[/tcp|/udp]`). A forwarder process is forked
//! **before** the sandbox `unshare`, so it stays in the HOST network + user namespace (like `kern
//! exec`). It binds the host port (host net ns) straight away, reports that bind to the parent over a
//! socketpair, and is told the box's PID 1 back over the same one; it then forks a single-threaded
//! worker per connection, which joins the box's user+net namespaces, connects to the box's
//! `127.0.0.1:<box_port>` and pumps bytes. No box-side proxy, no shared socket, no extra deps.
//!
//! - **TCP**: one worker per accepted connection (a byte pump with half-close).
//! - **UDP**: one worker per *client* - a wildcard host socket sees each client's first datagram, then
//!   a `SO_REUSEPORT` socket *connected* to that client takes over its later datagrams (the kernel
//!   routes a connected match ahead of the wildcard), relaying whole datagrams to a box-side UDP
//!   socket. Per-client workers are capped so a spoofed-source flood can't fork-bomb.
//!
//! Why fork pre-unshare: the post-unshare parent is already inside the box's (isolated) net ns, so
//! a forwarder spawned there would bind the box's loopback, not a host-reachable port. Why
//! per-connection/-client fork (not threads): `setns(CLONE_NEWUSER)` is refused in a multithreaded
//! process.
//!
//! Two ordering rules this module exists to keep:
//!
//! - **Bind BEFORE the box is declared started.** The forwarder binds its host socket the moment it
//!   is forked and reports the outcome (an `errno`) back to the parent, which refuses the box on a
//!   failure. Binding only after activation - as this did - meant a host port taken in the window
//!   between [`preflight`] and the bind left `kern box` printing "started", `kern ps` printing the
//!   mapping, and NOTHING listening; the only trace was a message on a stderr a detached box
//!   swallows. A published mapping is now a fact the parent verified, not a request it echoed.
//! - **Only publish a port the box actually owns.** With `--net`/`--network host` the box shares the
//!   HOST's net ns, so `127.0.0.1:<box_port>` is the host's and kern cannot tell the box's listener
//!   from any other process on the machine: publishing it would put a host service behind the box's
//!   name. The CLI refuses `-p` with `--net`; [`BoxNet`] is the second lock, refusing to forward if a
//!   forwarder is ever handed a box in our own net ns. (This is also where the `setns(CLONE_NEWNET)`
//!   `EPERM` came from that made the combination look merely broken.)

use std::cell::Cell;
use std::mem;
use std::ptr;

/// One published port mapping. Replaces a bare `(u32, u16, u16, bool)` - the two adjacent `u16`s
/// (host / box port) made the tuple swap-prone at every call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortMap {
    /// Host bind address in host byte order (`0` = `0.0.0.0`, all interfaces; default `127.0.0.1`).
    pub bind_ip: u32,
    /// Host-side port.
    pub host: u16,
    /// Box-side (in-namespace) port.
    pub box_port: u16,
    /// UDP when true, else TCP.
    pub udp: bool,
}

/// How a forwarder worker reaches the box's port. Decided ONCE, from the box's PID 1, right after
/// activation - not per connection.
///
/// A box that SHARES our network namespace has no port of its own: `127.0.0.1:<box_port>` there is
/// the HOST's, and nothing in the kernel distinguishes the box's listener from any other process on
/// the machine. Publishing it would put an arbitrary host service behind the box's name (measured on
/// 2026-07-31: `-p <port>:22` on a `--net` box served the host's sshd, banner for banner). So the CLI
/// refuses `-p` with `--net`, and this is the second lock on the same door: if any future path ever
/// hands a forwarder a box in our own network namespace, it serves nothing at all.
///
/// The detection itself came out of a real defect. The worker used to `setns(CLONE_NEWUSER)` into the
/// box's user ns and then `setns(CLONE_NEWNET)` into what was already our own net ns; the second call
/// is refused `EPERM`, because entering the child user ns drops the `CAP_SYS_ADMIN` the kernel demands
/// in the net ns's OWNING (initial) user ns. Every TCP connection was accepted and instantly reset and
/// every UDP datagram vanished, while the host port listened and `kern ps` showed the mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BoxNet {
    /// The box owns its net ns: join it (via its user ns) before connecting to its loopback.
    Enter,
    /// The box is in OUR net ns, so it has no port of its own: refuse every connection.
    NotTheBoxs,
}

/// A forwarder forked before the box's namespaces existed, with its host socket ALREADY bound.
/// Owned by [`Forwarders`], which activates and tears down the whole set.
struct PortForwarder {
    pid: i32,
    /// Our end of the `AF_UNIX` socketpair shared with the forwarder. The forwarder reports its bind
    /// outcome on it (an `errno`; `0` = listening), then we send the box's PID 1 back to start
    /// forwarding. Closing it without sending a pid makes the waiting forwarder exit (e.g. sandbox
    /// setup failed before the box forked). `-1` once closed - so the close happens exactly once.
    sock: Cell<i32>,
    /// The mapping this forwarder serves, so a failure can name the port it was asked to publish.
    map: PortMap,
}

impl PortForwarder {
    /// Send the box's PID 1 so the forwarder can reach the box's namespaces, then close our end.
    fn activate(&self, pid1: i32) {
        let fd = self.sock.replace(-1);
        if fd < 0 {
            return; // already activated or stopped - never write to a recycled fd
        }
        write_all(fd, &pid1.to_ne_bytes());
        unsafe { libc::close(fd) };
    }

    /// Stop the forwarder (and, via its process group membership, leave nothing listening).
    fn stop(&self) {
        let fd = self.sock.replace(-1);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        unsafe { libc::kill(self.pid, libc::SIGTERM) };
    }
}

/// A box's whole `-p` forwarder set, owned as one RAII unit: **dropping it stops every forwarder**.
///
/// That is the point. The forwarders are forked - and now bind - BEFORE the `unshare`, and roughly a
/// dozen fallible steps follow before the box exists (the uid map, the cgroup fail-closed, the pod
/// `setns`, the fork itself). Each is an early `return Err(..)`. With the old hand-written
/// `for_each(stop)` at the two SUCCESS sites, every one of those errors left a forwarder holding a
/// bound host port until the process happened to exit. Drop covers all of them.
///
/// Drop is NOT enough on its own: it cannot run when the supervisor is SIGKILLed, and the supervisor
/// sits in the BOX's cgroup, so an OOM inside the box kills it outright. Each forwarder therefore also
/// arms `PR_SET_PDEATHSIG(SIGKILL)` against the supervisor - see [`fork_forwarders`].
pub struct Forwarders(Vec<PortForwarder>);

impl Forwarders {
    /// Hand every forwarder the box's PID 1, which is what actually starts forwarding.
    pub fn activate(&self, pid1: i32) {
        for f in &self.0 {
            f.activate(pid1);
        }
    }
}

impl Drop for Forwarders {
    fn drop(&mut self) {
        for f in &self.0 {
            f.stop();
        }
    }
}

/// Pre-flight: verify every `-p` host port can actually be bound (`AF_INET`, matching the mapping's
/// TCP/UDP type) BEFORE the box is declared started. Uses `SO_REUSEADDR` only - NOT `SO_REUSEPORT` -
/// on purpose: the UDP forwarder adds `SO_REUSEPORT` (for its per-client sockets), but a REUSEPORT
/// probe here would bind happily ALONGSIDE another REUSEPORT holder and falsely pass the conflict
/// check. This is the EARLY check, and it is kept for its message: it names the conflict at the flag,
/// before any image, mount or cgroup work happens. It is no longer the only guard - `fork_forwarders`
/// now binds for real and refuses the box when that fails, which closes the window between the two -
/// but failing here is the clearer of the two failures. Returns the first conflicting
/// `(host_port, os-error)`. Best-effort: a socket-creation failure is skipped (the real bind backs it).
pub fn preflight(ports: &[PortMap]) -> Result<(), (u16, String)> {
    for p in ports {
        let ty = if p.udp {
            libc::SOCK_DGRAM
        } else {
            libc::SOCK_STREAM
        };
        let s = unsafe { libc::socket(libc::AF_INET, ty, 0) };
        if s < 0 {
            continue;
        }
        set_sock_flag(s, libc::SO_REUSEADDR); // NOT REUSEPORT - see the doc: a REUSEPORT probe here
                                              // would falsely pass alongside another REUSEPORT holder.
        let addr = addr_in(p.bind_ip, p.host);
        let r = unsafe { libc::bind(s, &addr as *const _ as *const libc::sockaddr, ADDR_LEN) };
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(s) };
        if r != 0 {
            return Err((p.host, err.to_string()));
        }
    }
    Ok(())
}

/// Fork one forwarder per `(host_port, box_port)` mapping and WAIT for each to confirm it bound its
/// host socket. MUST be called BEFORE the sandbox `unshare`, so each forwarder inherits the host
/// network + user namespace. Each then blocks until [`Forwarders::activate`] sends the box PID 1.
///
/// Returns the first `(host_port, reason)` that could not be published. Every failure is fatal to the
/// box on purpose: the alternative is what this used to do - print a line and `continue`, leaving a
/// mapping in the registry (and in `kern ps`) that no process was ever going to serve. A failure here
/// drops the [`Forwarders`] built so far, which stops the ones that DID bind, so a refused box never
/// leaves a host port held.
///
/// The forks and the confirmations are two separate passes: with a `-p 8000-8100:…` range, N ports
/// then cost one round of bind latency instead of N sequential round trips.
pub fn fork_forwarders(ports: &[PortMap]) -> Result<Forwarders, (u16, String)> {
    // Recorded BEFORE the fork so each child can tell whether we are still its parent (see the
    // PDEATHSIG arming below, which has a race the check closes).
    let supervisor = unsafe { libc::getpid() };
    let mut out = Forwarders(Vec::with_capacity(ports.len()));
    for m in ports {
        // A socketpair, not a pipe: the forwarder reports its bind outcome back on the SAME fd it
        // later receives the box's PID 1 on, so it still has to preserve exactly ONE fd across
        // `shed_inherited_fds`. CLOEXEC so the box's workload never inherits kern's control channel
        // (and so a forwarder waiting on EOF isn't held open by an unrelated exec'd process).
        let mut sv = [0i32; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        } != 0
        {
            return Err((m.host, format!("socketpair: {}", last_err())));
        }
        let (parent_end, child_end) = (sv[0], sv[1]);
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let e = last_err();
            unsafe {
                libc::close(parent_end);
                libc::close(child_end);
            }
            return Err((m.host, format!("fork: {e}")));
        }
        if pid == 0 {
            // CHILD = forwarder (still in the host ns). Bind, report, then wait for PID 1.
            unsafe { libc::close(parent_end) };
            // DIE WITH THE SUPERVISOR, enforced by the kernel rather than by a Drop.
            //
            // A forwarder holds a HOST port, and [`Forwarders`]'s Drop cannot run when the supervisor
            // is SIGKILLed - which is not hypothetical: the supervisor sits in the BOX's cgroup, so an
            // OOM inside the box kills it outright. The forwarder then survives, blocked in `accept`
            // on a port nobody can find: `kern ps` shows nothing (the registry entry is gone) and
            // `kern stop` has no box to stop. Six of these were found alive on a development machine
            // on 2026-08-01, each holding a host port for over an hour, produced by a test that
            // deliberately OOMs a 64 MB box. Reproduced on demand with `kill -9` on the supervisor.
            //
            // PDEATHSIG is per parent THREAD; this process is single-threaded by construction (the
            // sandbox fork requires it), so it fires on the supervisor's real death. It is cleared on
            // fork, so the per-connection workers do not inherit it - correct, they are bounded by
            // their own connection.
            unsafe {
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                )
            };
            // PDEATHSIG only fires on a FUTURE death, so a supervisor that died in the fork→prctl
            // window would leave exactly the orphan this is here to prevent. Detect the reparent.
            if unsafe { libc::getppid() } != supervisor {
                unsafe { libc::_exit(0) };
            }
            // Shed inherited fds (keep our socketpair end) - drops the detached box's readiness pipe
            // so it can't hang `kern box -d`, the box's scratch/registry fds, and the control fds of
            // any forwarder forked before us.
            crate::shed_inherited_fds(child_end);
            forwarder_child(child_end, *m) // -> !
        }
        unsafe { libc::close(child_end) };
        out.0.push(PortForwarder {
            pid,
            sock: Cell::new(parent_end),
            map: *m,
        });
    }
    // Second pass: nothing is announced until the kernel has actually given us the port.
    for f in &out.0 {
        let mut buf = [0u8; 4];
        if !read_exact_fd(f.sock.get(), &mut buf) {
            return Err((
                f.map.host,
                "the port forwarder died before it could bind".to_string(),
            ));
        }
        match i32::from_ne_bytes(buf) {
            0 => announce(&f.map),
            errno => {
                return Err((
                    f.map.host,
                    std::io::Error::from_raw_os_error(errno).to_string(),
                ))
            }
        }
    }
    Ok(out)
}

/// Tell the user what is now listening - AFTER the bind succeeded, never before.
fn announce(m: &PortMap) {
    let (ip, hp, bp) = (m.bind_ip, m.host, m.box_port);
    eprintln!(
        "→ publishing {}.{}.{}.{}:{hp} → box :{bp}{}",
        ip >> 24 & 0xff,
        ip >> 16 & 0xff,
        ip >> 8 & 0xff,
        ip & 0xff,
        if m.udp { "/udp" } else { "" }
    );
    if ip == 0 {
        eprintln!("  warning: bound 0.0.0.0 - box port {bp} is reachable from the network");
    }
}

/// The forwarder process. Binds its host socket FIRST and reports the outcome, so the parent can
/// refuse the box instead of declaring a mapping the kernel never granted; then waits for the box's
/// PID 1, decides how to reach the box's network ([`BoxNet`]), and forwards forever. Never returns.
fn forwarder_child(sock: i32, m: PortMap) -> ! {
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) }; // auto-reap per-connection/-client children
    let listener = match bind_host_socket(m.bind_ip, m.host, m.udp) {
        Ok(fd) => {
            write_all(sock, &0i32.to_ne_bytes());
            fd
        }
        Err(errno) => {
            write_all(sock, &errno.to_ne_bytes());
            unsafe { libc::_exit(1) };
        }
    };
    let mut buf = [0u8; 4];
    if !read_exact_fd(sock, &mut buf) {
        unsafe { libc::_exit(0) }; // parent gave up (EOF) before the box started
    }
    unsafe { libc::close(sock) };
    let box_pid1 = i32::from_ne_bytes(buf);
    // Decide the reach ONCE, here, where we still hold the host privileges the check needs. Say it
    // out loud on the refusing branch: the CLI is supposed to have rejected this combination, so
    // reaching it means something got past that check, and a silently dead port would be the same
    // "declared but not established" defect this module exists to prevent.
    let net = if same_netns(box_pid1) {
        eprintln!(
            "kern: -p {}:{}: the box shares this network namespace, so it has no port of its own - \
             refusing to forward (that would publish a HOST service under the box's name)",
            m.host, m.box_port
        );
        BoxNet::NotTheBoxs
    } else {
        BoxNet::Enter
    };
    if m.udp {
        udp_forwarder(listener, box_pid1, m.bind_ip, m.host, m.box_port, net); // -> !
    }
    tcp_forwarder(listener, box_pid1, m.box_port, net) // -> !
}

/// Create and bind the HOST-side socket for one mapping (and `listen` it, for TCP), in the host net
/// ns this process was forked into. Returns the fd, or the `errno` that stopped us - an `errno`
/// rather than a message so the child stays allocation-free and the parent formats it.
fn bind_host_socket(bind_ip: u32, host_port: u16, udp: bool) -> Result<i32, i32> {
    let ty = if udp {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
    let s = unsafe { libc::socket(libc::AF_INET, ty, 0) };
    if s < 0 {
        return Err(errno());
    }
    // UDP needs REUSEPORT too: the per-client relays bind this same host port (see `udp_forwarder`).
    if udp {
        reuse_addr_port(s);
    } else {
        set_sock_flag(s, libc::SO_REUSEADDR);
    }
    let addr = addr_in(bind_ip, host_port);
    if unsafe { libc::bind(s, &addr as *const _ as *const libc::sockaddr, ADDR_LEN) } != 0 {
        let e = errno();
        unsafe { libc::close(s) };
        return Err(e);
    }
    if !udp && unsafe { libc::listen(s, 128) } != 0 {
        let e = errno();
        unsafe { libc::close(s) };
        return Err(e);
    }
    Ok(s)
}

/// Does the box share OUR network namespace (`--net`/`--network host`)? Compared by the `(dev, ino)`
/// identity of `/proc/<pid>/ns/net` - `stat` follows the ns link to the nsfs inode, which IS the
/// kernel's namespace identity (the number `readlink` shows as `net:[…]`).
///
/// Fails CLOSED (`false` → take the `setns` path): mistaking a box's PRIVATE net ns for ours would
/// point the forwarder at `127.0.0.1:<box_port>` on the HOST and publish whatever host service
/// happens to sit there under the box's name. A wrong `true` is a security bug; a wrong `false` only
/// costs a `setns` that fails and closes the connection.
fn same_netns(box_pid1: i32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let id =
        |p: &str| -> Option<(u64, u64)> { std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino())) };
    match (
        id("/proc/self/ns/net"),
        id(&format!("/proc/{box_pid1}/ns/net")),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The current `errno`, or `EIO` if the OS somehow reported none (never `unwrap`).
fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// The current OS error as a message, for the parent-side failure paths.
fn last_err() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// Read exactly `buf.len()` bytes (EINTR-safe). `false` on EOF or error: a SHORT read of a 4-byte
/// control message is not a value, it is a dead peer - the old `read(..) != 4` treated a legal short
/// read as a protocol failure and a truncated one as data.
fn read_exact_fd(fd: i32, buf: &mut [u8]) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        let n = unsafe { libc::read(fd, buf[off..].as_mut_ptr().cast(), buf.len() - off) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if n == 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

/// TCP publish: accept on the ALREADY-bound host `listener` and fork a single-threaded connector per
/// accepted connection (fork, not threads, because `setns(CLONE_NEWUSER)` is refused in a
/// multithreaded process). The bind/listen happened in [`forwarder_child`], before the box was
/// declared started.
fn tcp_forwarder(listener: i32, box_pid1: i32, box_port: u16, net: BoxNet) -> ! {
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
            connector_main(box_pid1, box_port, conn, net);
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::close(conn) };
    }
    unsafe { libc::_exit(0) }
}

/// Join the box's user+net namespaces (we start in the host ns, where we have the privilege to enter
/// the box's child user ns - exactly as `kern exec` does). Single-threaded caller only (setns(USER)).
/// Returns `false` on any failure. After this, sockets created here live in the BOX's net ns.
///
/// ONLY valid when the box owns its net ns ([`BoxNet::Enter`]). Called for a `--net` box it fails by
/// construction: `setns(CLONE_NEWUSER)` succeeds, and the following `setns(CLONE_NEWNET)` into the
/// HOST's net ns is then refused `EPERM`, because that ns is owned by the initial user ns in which we
/// no longer hold `CAP_SYS_ADMIN`.
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

/// Reach the box's network, connect to its loopback `box_port`, and pump bytes against the accepted
/// host connection `conn`. With [`BoxNet::NotTheBoxs`] there is no box port to reach, so the
/// connection is closed rather than pointed at a host service.
fn connector_main(box_pid1: i32, box_port: u16, conn: i32, net: BoxNet) {
    if net != BoxNet::Enter || !enter_box_ns(box_pid1) {
        return;
    }
    let bs = connect_box_loopback(box_port, libc::SOCK_STREAM);
    if bs < 0 {
        return;
    }
    pump_bidir(conn, bs);
    unsafe { libc::close(bs) };
}

/// Create an `AF_INET` socket of type `ty` (`SOCK_STREAM`/`SOCK_DGRAM`) in the CURRENT net ns and
/// connect it to the box's `127.0.0.1:box_port`. Caller must already be in the box namespaces (see
/// [`enter_box_ns`]). Returns the fd, or `-1` on any failure.
fn connect_box_loopback(box_port: u16, ty: libc::c_int) -> i32 {
    unsafe {
        let s = libc::socket(libc::AF_INET, ty, 0);
        if s < 0 {
            return -1;
        }
        let addr = addr_in(0x7f00_0001, box_port); // 127.0.0.1:box_port (box net ns)
        if libc::connect(s, &addr as *const _ as *const libc::sockaddr, ADDR_LEN) != 0 {
            libc::close(s);
            return -1;
        }
        s
    }
}

/// Enable one boolean `SOL_SOCKET` option on `s` (best-effort - a failure is ignored, matching the
/// existing forwarder behaviour where these are hardening, not correctness).
fn set_sock_flag(s: i32, opt: libc::c_int) {
    let one: libc::c_int = 1;
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

/// Set `SO_REUSEADDR` + `SO_REUSEPORT` on `s`. REUSEPORT lets each per-client UDP relay bind the same
/// host port; the kernel then routes a client's datagrams to its own *connected* socket.
fn reuse_addr_port(s: i32) {
    set_sock_flag(s, libc::SO_REUSEADDR);
    set_sock_flag(s, libc::SO_REUSEPORT);
}

/// UDP publish. A wildcard host socket receives each client's FIRST datagram; a per-client child then
/// binds a `SO_REUSEPORT` socket *connected* to that client (so the kernel routes its later datagrams
/// straight to the child, not back here) and relays to a box-side UDP socket. Each relay idles out
/// (see `pump_dgram`) so a request/response client's process/sockets are freed, and the parent's
/// recent-client table is TIME-bounded (not a lifetime blacklist), so a long-lived resolver never hits
/// a cumulative ceiling and a client can reconnect after its relay dies. The group dies with the box.
fn udp_forwarder(
    sock: i32,
    box_pid1: i32,
    bind_ip: u32,
    host_port: u16,
    box_port: u16,
    net: BoxNet,
) -> ! {
    // Recently-forked clients (ip:port → when). Its ONLY job is to dedupe the ~ms race window between
    // us reading a client's first datagram and its child binding the connected socket that steals the
    // client's later datagrams. It is TIME-BOUNDED (pruned to `DEDUP_TTL`), NOT a lifetime blacklist -
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
                net,
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
    net: BoxNet,
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
        // The host socket is bound and connected FIRST, while we are still in the host net ns - the
        // order matters on the `Enter` path and is simply correct on the refusing one.
        if net != BoxNet::Enter || !enter_box_ns(box_pid1) {
            return;
        }
        let bs = connect_box_loopback(box_port, libc::SOCK_DGRAM);
        if bs < 0 {
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
            return; // idle timeout - no traffic either way, tear the relay down
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
                // n == 0 is a legitimate zero-length datagram - forward it too.
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

    /// Every test here follows the same pattern: ask the kernel for an ephemeral port, RELEASE it,
    /// then assert on who can bind that number next. Run concurrently - which is what the test
    /// harness does by default - they race each other for exactly that window, and a forwarder from
    /// one test can legitimately grab the number another just released. The result was a suite that
    /// went red roughly one run in ten on `a free port should pass`, which is the worst kind of test:
    /// it is not reporting a defect, and it teaches people to re-run instead of read.
    ///
    /// So the port tests take this lock and run one at a time. `unwrap_or_else(into_inner)` because a
    /// panic in one of them must not turn the rest into poisoning errors that hide the real failure.
    static PORT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn port_guard() -> std::sync::MutexGuard<'static, ()> {
        PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Grab a port from the OS and release it, so the number is free right now.
    fn free_port() -> u16 {
        use std::net::TcpListener;
        match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(t) => match t.local_addr() {
                Ok(a) => a.port(),
                Err(e) => panic!("local_addr: {e}"),
            },
            Err(e) => panic!("bind: {e}"),
        }
    }

    /// THE invariant this module was rewritten for: the host port is bound by the time
    /// `fork_forwarders` RETURNS - before the box is unshared, forked, or declared started. Proven
    /// the only way that isn't a restatement of the code: by racing it. A second `bind` of the same
    /// port must now fail, because a forwarder already holds it.
    #[test]
    fn the_host_port_is_bound_before_the_box_exists() {
        let _g = port_guard();
        use std::net::TcpListener;
        let port = free_port();
        let m = PortMap {
            bind_ip: LOOPBACK,
            host: port,
            box_port: 9,
            udp: false,
        };
        let fwd = match fork_forwarders(&[m]) {
            Ok(f) => f,
            Err((p, e)) => panic!("a free port {p} should publish: {e}"),
        };
        // No box has been forked and nothing was activated - yet the port is already taken.
        assert!(
            TcpListener::bind(("127.0.0.1", port)).is_err(),
            "the forwarder must already hold the host port when fork_forwarders returns"
        );
        drop(fwd); // stops the forwarder (RAII), which is the other half of the contract
    }

    /// A host port that cannot be bound is a REFUSAL naming that port, not a warning next to a
    /// started box. This is the backstop for the window `preflight` cannot cover: it runs early
    /// (before the image, mounts and cgroup work) and something can take the port in between.
    #[test]
    fn a_taken_host_port_is_reported_instead_of_published() {
        let _g = port_guard();
        use std::net::TcpListener;
        let held = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(t) => t,
            Err(e) => panic!("bind: {e}"),
        };
        let taken = match held.local_addr() {
            Ok(a) => a.port(),
            Err(e) => panic!("local_addr: {e}"),
        };
        let m = PortMap {
            bind_ip: LOOPBACK,
            host: taken,
            box_port: 9,
            udp: false,
        };
        match fork_forwarders(&[m]) {
            Err((p, why)) => {
                assert_eq!(p, taken, "the refusal must name the port that failed");
                assert!(!why.is_empty(), "the refusal must carry the OS reason");
            }
            Ok(_) => panic!("published a host port that is already bound"),
        }
        drop(held);
    }

    /// One bad port in a set refuses the whole box AND releases the ones that did bind - the RAII
    /// teardown. Without it a refused box would leave the earlier ports of a `-p` range held.
    #[test]
    fn a_failure_releases_the_ports_that_did_bind() {
        let _g = port_guard();
        use std::net::TcpListener;
        let good = free_port();
        let held = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(t) => t,
            Err(e) => panic!("bind: {e}"),
        };
        let taken = match held.local_addr() {
            Ok(a) => a.port(),
            Err(e) => panic!("local_addr: {e}"),
        };
        let maps = [
            PortMap {
                bind_ip: LOOPBACK,
                host: good,
                box_port: 9,
                udp: false,
            },
            PortMap {
                bind_ip: LOOPBACK,
                host: taken,
                box_port: 9,
                udp: false,
            },
        ];
        assert!(
            fork_forwarders(&maps).is_err(),
            "a set with an unbindable port must be refused as a whole"
        );
        // The first forwarder DID bind `good`; the refusal must have torn it down. SIGTERM is
        // asynchronous, so wait for the release rather than assuming it is instantaneous.
        let mut reclaimed = false;
        for _ in 0..200 {
            if TcpListener::bind(("127.0.0.1", good)).is_ok() {
                reclaimed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            reclaimed,
            "the already-bound port {good} was still held after the set was refused"
        );
        drop(held);
    }

    #[test]
    fn preflight_detects_a_bound_port_and_passes_a_free_one() {
        let _g = port_guard();
        use std::net::TcpListener;
        // An actively-listening port must be reported as taken (this is the check that stops a box
        // printing "started" while its `-p` forwarder silently fails to bind).
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = l.local_addr().unwrap().port();
        let pm = |host| PortMap {
            bind_ip: LOOPBACK,
            host,
            box_port: 80,
            udp: false,
        };
        match preflight(&[pm(taken)]) {
            Err((p, _)) => assert_eq!(p, taken, "reported the conflicting port"),
            Ok(()) => panic!("preflight passed a port that is actively listening"),
        }
        // A free port passes. (Grab one from the OS, release it, then check.)
        let free = {
            let t = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            t.local_addr().unwrap().port()
        };
        assert!(preflight(&[pm(free)]).is_ok(), "a free port should pass");
    }
}
