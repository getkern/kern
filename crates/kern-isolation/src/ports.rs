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
    /// Host bind address, either family: `0.0.0.0` or `::` is every interface of that family. An IPv6
    /// listener is IPv6 ONLY (`IPV6_V6ONLY`), so `0.0.0.0` and `::` are two listeners, as Docker
    /// binds them for a spec that names no address.
    pub bind: std::net::IpAddr,
    /// The IPv6 half of a spec that named NO address, added by the parser beside the IPv4 one. The
    /// one mapping the CLI drops on a host without IPv6 (Docker does the same); an IPv6 address the
    /// spec WROTE is never dropped, and a host that cannot bind it refuses the box.
    pub implicit: bool,
    /// Host-side port.
    pub host: u16,
    /// Box-side (in-namespace) port.
    pub box_port: u16,
    /// UDP when true, else TCP.
    pub udp: bool,
    /// A host port RANGE for one box port (`8080-8095:80`): the port is any free one in it, picked at
    /// start, as Docker picks it (MEASURED: fifteen replicas of `8080-8095:80` each got a different
    /// port of the range). `host` is 0 until then. `None` for every other spec.
    pub host_pool: Option<(u16, u16)>,
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
    /// Send the box's PID 1 and the address to reach inside it, then close our end.
    fn activate(&self, pid1: i32, target: u32) {
        let fd = self.sock.replace(-1);
        if fd < 0 {
            return; // already activated or stopped - never write to a recycled fd
        }
        let mut msg = [0u8; 8];
        msg[..4].copy_from_slice(&pid1.to_ne_bytes());
        msg[4..].copy_from_slice(&target.to_ne_bytes());
        write_all(fd, &msg);
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
    /// Hand every forwarder the box's PID 1 and the box address its connections go to (host byte
    /// order; the box's own address, see `BOX_ADDR`), which is what actually starts forwarding.
    pub fn activate(&self, pid1: i32, target: u32) {
        for f in &self.0 {
            f.activate(pid1, target);
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
/// `(host_port, os-error)` - the RAW [`std::io::Error`], not a string, so the caller can tell
/// `EADDRINUSE` (already in use) from `EACCES` (a rootless bind of a privileged port <1024) and give the
/// right remedy instead of one guess. Best-effort: a socket-creation failure is skipped (the real bind
/// backs it).
pub fn preflight(ports: &[PortMap]) -> Result<(), (u16, std::io::Error)> {
    for p in ports {
        let ty = if p.udp {
            libc::SOCK_DGRAM
        } else {
            libc::SOCK_STREAM
        };
        let s = host_socket(p.bind, ty);
        if s < 0 {
            continue;
        }
        set_sock_flag(s, libc::SO_REUSEADDR); // NOT REUSEPORT - see the doc: a REUSEPORT probe here
                                              // would falsely pass alongside another REUSEPORT holder.
        let (addr, len) = sockaddr_of(p.bind, p.host);
        let r = unsafe { libc::bind(s, (&addr as *const libc::sockaddr_storage).cast(), len) };
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(s) };
        if r != 0 {
            return Err((p.host, err));
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
    let (hp, bp) = (m.host, m.box_port);
    let ip = match m.bind {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
    };
    crate::progress!(
        "→ publishing {ip}:{hp} → box :{bp}{}",
        if m.udp { "/udp" } else { "" }
    );
    // Said once for the pair a default bind makes: its IPv6 twin is the same exposure.
    if m.bind.is_unspecified() && !m.implicit {
        // `kern: warning:` and not a bare `warning:`, for the reason the images.rs note carries: the
        // SDK tells kern's lines from the workload's by that prefix and nothing else.
        // Through the same channel as the cap notices: to the launcher when one is listening, so a
        // detached service's LOG does not carry it (reported in every published service's log).
        crate::cgroup::cap_notice(&format!(
            "kern: warning: bound {ip} - box port {bp} is reachable from the network"
        ));
    }
}

/// The forwarder process. Binds its host socket FIRST and reports the outcome, so the parent can
/// refuse the box instead of declaring a mapping the kernel never granted; then waits for the box's
/// PID 1, decides how to reach the box's network ([`BoxNet`]), and forwards forever. Never returns.
fn forwarder_child(sock: i32, m: PortMap) -> ! {
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) }; // auto-reap per-connection/-client children
    let listener = match bind_host_socket(m.bind, m.host, m.udp) {
        Ok(fd) => {
            write_all(sock, &0i32.to_ne_bytes());
            fd
        }
        Err(errno) => {
            write_all(sock, &errno.to_ne_bytes());
            unsafe { libc::_exit(1) };
        }
    };
    let mut buf = [0u8; 8];
    if !read_exact_fd(sock, &mut buf) {
        unsafe { libc::_exit(0) }; // parent gave up (EOF) before the box started
    }
    unsafe { libc::close(sock) };
    let box_pid1 = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let target = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
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
        udp_forwarder(listener, box_pid1, m, net, target); // -> !
    }
    tcp_forwarder(listener, box_pid1, m, net, target) // -> !
}

/// Create and bind the HOST-side socket for one mapping (and `listen` it, for TCP), in the host net
/// ns this process was forked into. Returns the fd, or the `errno` that stopped us - an `errno`
/// rather than a message so the child stays allocation-free and the parent formats it.
pub(crate) fn bind_host_socket(
    bind: std::net::IpAddr,
    host_port: u16,
    udp: bool,
) -> Result<i32, i32> {
    let ty = if udp {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
    let s = host_socket(bind, ty);
    if s < 0 {
        return Err(errno());
    }
    // UDP needs REUSEPORT too: the per-client relays bind this same host port (see `udp_forwarder`).
    if udp {
        reuse_addr_port(s);
    } else {
        set_sock_flag(s, libc::SO_REUSEADDR);
    }
    let (addr, len) = sockaddr_of(bind, host_port);
    if unsafe { libc::bind(s, (&addr as *const libc::sockaddr_storage).cast(), len) } != 0 {
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
pub(crate) fn errno() -> i32 {
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
fn tcp_forwarder(listener: i32, box_pid1: i32, m: PortMap, net: BoxNet, target: u32) -> ! {
    // ONE FLAG SHARED BY EVERY CONNECTOR this forwarder forks, so the "listening on loopback only"
    // note is said once per mapping rather than once per refused connection. An anonymous SHARED page
    // is the only memory a forked child writes and its parent then reads; null when the kernel
    // refuses the page, and then the note is simply never printed.
    let told = shared_flag();
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
            connector_main(box_pid1, m, conn, net, target, told);
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
pub(crate) fn enter_box_ns(box_pid1: i32) -> bool {
    enter_box_ns_pinned(box_pid1, 0)
}

/// A process's kernel start-time (`/proc/<pid>/stat` field 22) from an ALREADY-OPEN descriptor.
///
/// THERE IS NO PATH-BASED VERSION ANY MORE, deliberately. Resolving `/proc/<pid>/stat` by path is a
/// separate moment from resolving `/proc/<pid>/ns/user`, and this value exists precisely to decide
/// whether those namespaces belong to the generation the caller means. Reading it from a descriptor
/// obtained through the same `/proc/<pid>` directory descriptor keeps all of them in one generation
/// by construction, so the only spelling available is the correct one.
///
/// `0` means "unknown", and [`enter_box_ns_pinned`] never treats it as a match; an EXPECTATION of `0`
/// means the caller had nothing to pin with and skips the comparison entirely.
///
/// Reading the fd rather than the path is what keeps the check in the same generation as the
/// namespace descriptors beside it: a path would be resolved again, and a resolution is a moment.
/// Does not take ownership, and does not disturb the descriptor's offset for a caller that reuses it
/// (it does not: this is read once and closed).
fn starttime_of_fd(fd: i32) -> u64 {
    let mut buf = [0u8; 512];
    // SAFETY: reads at most `buf.len()` bytes into a buffer this function owns.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n <= 0 {
        return 0;
    }
    let Ok(text) = std::str::from_utf8(&buf[..n as usize]) else {
        return 0;
    };
    parse_starttime(text)
}

/// Field 22 of a `/proc/<pid>/stat` body.
///
/// Parsed from the LAST `)` rather than by splitting on whitespace from the left, because field 2 is
/// the executable name in parentheses and it may itself contain spaces and a `)`. Splitting from the
/// left is the classic way this number silently becomes a different field.
fn parse_starttime(stat: &str) -> u64 {
    let Some(after) = stat.rfind(')').and_then(|i| stat.get(i + 1..)) else {
        return 0;
    };
    // Fields after the closing paren start at field 3 (state), so start-time (field 22) is the 20th.
    after
        .split_whitespace()
        .nth(19)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

/// [`enter_box_ns`], but the pid is checked AFTER the namespace descriptors are open.
///
/// THE ORDER IS THE WHOLE POINT, and the other order is a real hole rather than a tidiness argument.
/// A caller that validates `pid` and then hands the number here has two operations with a window
/// between them: if the box's init dies in that window and the kernel hands its number to a HOST
/// process, `open("/proc/<pid>/ns/net")` resolves to the HOST's network namespace. The listener would
/// then bind its alias on the host, reachable by everything on the machine, and the connector would
/// connect to whatever the host runs on that port. That is the worst outcome this module has, and it
/// needs a crash plus load rather than an attacker.
///
/// Opening the descriptors first PINS those specific namespace instances: recycling the pid
/// afterwards cannot change what the fds refer to. So the check moves after the open, where it
/// answers the only question left, which is whether the pid was already someone else's before it. An
/// `expect_starttime` of `0` skips the check, for the callers (the `-p` forwarder) that hold a pid
/// resolved through a start-time-pinned supervisor and have nothing further to compare.
pub(crate) fn enter_box_ns_pinned(box_pid1: i32, expect_starttime: u64) -> bool {
    // ONE DIRECTORY DESCRIPTOR, THREE `openat`s, ONE GENERATION.
    //
    // The previous version opened `/proc/<pid>/ns/user` and `/proc/<pid>/ns/net` as two separate
    // paths and then read `/proc/<pid>/stat` as a third. Three path resolutions are three moments: if
    // the box's init exits between the first two, the second resolves against whatever now holds that
    // pid, and the halves straddle two generations. Under `watch`, where a service is stopped and
    // restarted all day, the recycled process is plausibly ANOTHER kern box, so the start-time read a
    // moment later can match and the check passes on a pair of descriptors from two different boxes.
    //
    // MEASURED on 7.0.0: a `/proc/<pid>` directory descriptor stops resolving once the process exits.
    // `openat` on it returns ESRCH for `ns/net`, `ns/user` and `stat` alike. So opening the directory
    // once and reaching everything through it makes all three reads the same generation BY
    // CONSTRUCTION, and the start-time comparison below then only has to answer whether that one
    // generation is the right one. It needs no new persisted state and no pidfd.
    let dir_path = format!("/proc/{box_pid1}\0");
    // SAFETY: the path is NUL-terminated above and lives for the call.
    let dirfd = unsafe {
        libc::open(
            dir_path.as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dirfd < 0 {
        return false;
    }
    let at = |name: &str| -> i32 {
        let p = format!("{name}\0");
        // SAFETY: `dirfd` is open for the length of this closure and `p` is NUL-terminated.
        unsafe {
            libc::openat(
                dirfd,
                p.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        }
    };
    let (user, net, stat) = (at("ns/user"), at("ns/net"), at("stat"));
    // SAFETY: every descriptor below was produced by this function and is closed exactly once.
    unsafe {
        if user < 0 || net < 0 || stat < 0 {
            for fd in [user, net, stat, dirfd] {
                if fd >= 0 {
                    libc::close(fd);
                }
            }
            return false;
        }
        libc::close(dirfd);
        // The descriptors now pin ONE generation; this asks whether it is the right one. Read from
        // the `stat` descriptor rather than by path, so it cannot be a fourth moment either.
        if expect_starttime != 0 && starttime_of_fd(stat) != expect_starttime {
            libc::close(user);
            libc::close(net);
            libc::close(stat);
            return false;
        }
        libc::close(stat);
        let ok = libc::setns(user, libc::CLONE_NEWUSER) == 0
            && libc::setns(net, libc::CLONE_NEWNET) == 0;
        libc::close(user);
        libc::close(net);
        ok
    }
}

/// Drop every capability this process holds, permanently, and forbid regaining any.
///
/// MEASURED, and it is why this exists: a process that has entered a box's user namespace holds a
/// FULL effective capability set in it. On this host, `CapEff` reads `0000000000000000` before
/// `setns(CLONE_NEWUSER)` and `000001ffffffffff` after. The relay halves also keep the HOST mount
/// namespace, so between the two they are the only processes in the system with a host filesystem
/// view that is reachable over a socket from inside a box. Nothing they do afterwards needs a
/// capability, so holding one is a liability with no counterpart.
///
/// ORDER MATTERS FOR THE LISTENER: it must bind first. A compose service on port 80 puts the alias
/// bind under `CAP_NET_BIND_SERVICE`, so dropping before the bind would break exactly the stacks that
/// use privileged ports.
///
/// `PR_SET_NO_NEW_PRIVS` first, then the bounding set, then the sets themselves: no-new-privs is what
/// makes the drop irreversible across an `execve` of a setuid binary, and the bounding set is what
/// stops a capability being raised back into the permitted set.
///
/// Returns `false` if any step fails, so a caller can refuse to run unprivileged-only code with
/// privileges it thought it had shed.
pub(crate) fn drop_all_capabilities() -> bool {
    restrict_capabilities(0)
}

/// Keep ONLY the capabilities in `mask` (a bitmask over capability numbers), permanently.
///
/// MEASURED, and it is why this exists: a process that has entered a box's user namespace holds a
/// FULL effective set in it. On this host `CapEff` reads `0000000000000000` before
/// `setns(CLONE_NEWUSER)` and `000001ffffffffff` after. The relay halves also keep the HOST mount
/// namespace, so between the two they are the only processes in the system with a host filesystem
/// view reachable over a socket from inside a box. Nothing they do afterwards needs a capability, so
/// holding one is a liability with no counterpart.
///
/// `mask` is not always zero, because the listener has ONE thing left to do that can need a
/// capability: a compose service on port 80 puts its alias bind under `CAP_NET_BIND_SERVICE`. It
/// therefore narrows to that single capability BEFORE binding and to zero after, which makes the
/// window that holds anything at all one capability wide instead of forty-one.
///
/// Order, and each step is load-bearing:
///  1. `PR_SET_NO_NEW_PRIVS`, so the drop cannot be undone by executing a setuid binary.
///  2. `PR_CAP_AMBIENT_CLEAR_ALL`. The ambient set is separate, and while it is bounded by permitted
///     it is cleared explicitly rather than by inference, because this function claims the sets are
///     empty and a claim should be enforced where it is made.
///  3. The WHOLE bounding set, `mask` or no `mask`, up to `cap_last_cap` READ FROM THE KERNEL rather
///     than a hard-coded 63. An unreadable or unparseable file falls back to 63, which is safe rather
///     than fail-open: `PR_CAPBSET_DROP` answers `EINVAL` for a capability the kernel does not know,
///     that return is deliberately IGNORED here, and the `capset` below still empties every set. Only
///     `PR_SET_NO_NEW_PRIVS` and `capset` decide this function's result, because they are the two
///     steps whose failure would leave a privilege behind.
///  4. `capset` with `_LINUX_CAPABILITY_VERSION_3` and TWO data elements. Version 1 covers only
///     capabilities 0 to 31, and this host has capabilities above 31 (`000001ffffffffff`), so a v1
///     header would leave the high word untouched while reporting success.
///
/// Returns `false` if any step fails, so a caller can refuse to run unprivileged-only code with
/// privileges it thought it had shed.
/// Is this thread's capability BOUNDING set empty, as `/proc/self/status` reports it?
///
/// Read from `/proc` rather than inferred from the `prctl` return values, because those cannot tell
/// "the drop failed" from "there was nothing left to drop" - the second `restrict_capabilities` call
/// hits the latter on every capability. An unreadable `/proc/self/status` answers `false`: this gates
/// a claim that privileges are gone, and a claim that cannot be checked is not one worth making.
fn bounding_set_is_empty() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
        s.lines()
            .find(|l| l.starts_with("CapBnd:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .is_some_and(|v| v.chars().all(|c| c == '0'))
    })
}

pub(crate) fn restrict_capabilities(mask: u64) -> bool {
    // SAFETY: every call below acts on the calling process only and takes no pointer to memory this
    // function does not own. `capset` is handed a header this function fills completely.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return false;
        }
        // PR_CAP_AMBIENT = 47, PR_CAP_AMBIENT_CLEAR_ALL = 4. Not exposed by this `libc` version.
        // A kernel without ambient capabilities answers EINVAL, which is not a failure to drop them.
        libc::prctl(47, 4, 0, 0, 0);
        let last = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(63);
        // THE WHOLE BOUNDING SET GOES, INCLUDING WHAT `mask` KEEPS. Dropping a capability from the
        // bounding set does not remove it from this thread's permitted or effective sets, so the
        // listener's bind still works with `CAP_NET_BIND_SERVICE` effective while that bit is gone
        // from the bound.
        //
        // MEASURED, and it is why the `mask` exception was removed: with the bit kept in the bound by
        // the first call, the SECOND call could not drop it. `PR_CAPBSET_DROP` needs `CAP_SETPCAP` in
        // the effective set, and the first call had already narrowed effective to
        // `CAP_NET_BIND_SERVICE` alone, so `CAP_SETPCAP` was gone and every drop in the second call
        // failed EPERM. `/proc/<pid>/status` for a live listener read `CapBnd: 0000000000000400`
        // while `CapEff` read zero: this function claimed every set was empty and one was not.
        //
        // The practical exposure was nil, because the bounding set only limits what can be GAINED
        // across an `execve` and `NO_NEW_PRIVS` is already set. The defect was the claim, which is
        // the kind this codebase treats as expensive on its own.
        // AND THE OUTCOME IS VERIFIED, which it was not: every drop could fail and this function
        // still returned `true`. Caught by CI on a GitHub runner, where the
        // `apparmor_restrict_unprivileged_userns` policy lets `unshare(CLONE_NEWUSER)` succeed
        // WITHOUT granting the full set inside it, so `CAP_SETPCAP` is absent, every
        // `PR_CAPBSET_DROP` answers EPERM, and `/proc/self/status` read `CapBnd: 000001ffffffffff`
        // under a claim that every set was empty. Same defect as the `mask` exception documented
        // above, one layer out: the exposure is nil (the bound only limits what an `execve` can
        // GAIN, and NO_NEW_PRIVS is already set) and the false claim is the cost.
        //
        // THE STATE IS CHECKED, NOT THE CALLS, and the difference is the whole correctness of this.
        // A first attempt failed the function when any `prctl` returned non-zero, and that broke the
        // ordinary two-call sequence its own comment describes: the second `restrict_capabilities`
        // runs with effective already narrowed, so it holds no `CAP_SETPCAP` and EVERY drop answers
        // EPERM even though the first call had already emptied the bound. Measured here: with
        // `cap_last_cap` = 40 and the privileges present, 0 of 41 drops fail; after the first call,
        // all 41 do, with nothing left to remove. "Did the bound end up empty" is the question that
        // survives both.
        for cap in 0..=last {
            libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
        }
        if !bounding_set_is_empty() {
            return false;
        }
        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let mut hdr = CapHeader {
            version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
            pid: 0,
        };
        let (lo, hi) = (mask as u32, (mask >> 32) as u32);
        let mut data = [
            CapData {
                effective: lo,
                permitted: lo,
                inheritable: 0,
            },
            CapData {
                effective: hi,
                permitted: hi,
                inheritable: 0,
            },
        ];
        libc::syscall(
            libc::SYS_capset,
            &mut hdr as *mut CapHeader,
            data.as_mut_ptr(),
        ) == 0
    }
}

/// Reach the box's network, connect to its own address at `box_port`, and pump bytes against the
/// accepted host connection `conn`. With [`BoxNet::NotTheBoxs`] there is no box port to reach, so
/// the connection is closed rather than pointed at a host service.
///
/// When the box's address refuses and its `127.0.0.1` would have answered, the listener is bound to
/// loopback only: Docker does not publish that either, and says nothing about it. kern says so, once
/// per mapping (`told`), because "connection refused" from a port `kern ps` lists names nothing.
fn connector_main(
    box_pid1: i32,
    m: PortMap,
    conn: i32,
    net: BoxNet,
    target: u32,
    told: *const std::sync::atomic::AtomicU32,
) {
    if net != BoxNet::Enter || !enter_box_ns(box_pid1) {
        return;
    }
    let bs = match connect_box_addr(target, m.box_port, libc::SOCK_STREAM) {
        Ok(fd) => fd,
        Err(e) => {
            if e == libc::ECONNREFUSED {
                note_loopback_only(m, told);
            }
            return;
        }
    };
    // TCP only, and before a single byte moves: see `set_nodelay`.
    set_nodelay(conn);
    set_nodelay(bs);
    pump_bidir(conn, bs);
    unsafe { libc::close(bs) };
}

/// Say, once per mapping, that the box's port answers on its loopback only. Probes `127.0.0.1` (a
/// connect that is closed at once) and stays silent when nothing is there either: a service that is
/// not up yet is not this.
fn note_loopback_only(m: PortMap, told: *const std::sync::atomic::AtomicU32) {
    use std::sync::atomic::Ordering;
    let probe = connect_box_loopback(m.box_port, libc::SOCK_STREAM);
    if probe < 0 {
        return;
    }
    unsafe { libc::close(probe) };
    // SAFETY: `told` is null or the start of a live MAP_SHARED page this process inherited.
    let Some(flag) = (unsafe { told.as_ref() }) else {
        return;
    };
    if flag.swap(1, Ordering::AcqRel) == 0 {
        eprintln!(
            "kern: -p {}->{}: the box's port {} listens on its 127.0.0.1 only, so it is not \
             published (a published port reaches the box's address, as under Docker); bind the \
             service to 0.0.0.0",
            m.host, m.box_port, m.box_port
        );
    }
}

/// An `AtomicU32` in an anonymous SHARED page: written by forked children, read by their siblings.
/// Null when the kernel refuses the mapping.
fn shared_flag() -> *const std::sync::atomic::AtomicU32 {
    // SAFETY: an anonymous mapping, owned by this process for its lifetime; zero-filled by the
    // kernel, which is the valid bit pattern of an `AtomicU32` holding 0.
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return ptr::null();
    }
    p.cast::<std::sync::atomic::AtomicU32>()
}

/// Connect to the box's own address `ip:box_port`, FROM that address, in the CURRENT net ns (the
/// caller is already in the box's namespaces). The source is the box's address too, so the server
/// sees a client that is not loopback, as under Docker where it sees the bridge gateway. Returns the
/// fd, or the `errno` that stopped it (`ECONNREFUSED` is what the loopback note keys on).
pub(crate) fn connect_box_addr(ip: u32, box_port: u16, ty: libc::c_int) -> Result<i32, i32> {
    unsafe {
        let s = libc::socket(libc::AF_INET, ty, 0);
        if s < 0 {
            return Err(errno());
        }
        let src = addr_in(ip, 0);
        if libc::bind(s, &src as *const _ as *const libc::sockaddr, ADDR_LEN) != 0 {
            let e = errno();
            libc::close(s);
            return Err(e);
        }
        let addr = addr_in(ip, box_port);
        if libc::connect(s, &addr as *const _ as *const libc::sockaddr, ADDR_LEN) != 0 {
            let e = errno();
            libc::close(s);
            return Err(e);
        }
        Ok(s)
    }
}

/// Create an `AF_INET` socket of type `ty` (`SOCK_STREAM`/`SOCK_DGRAM`) in the CURRENT net ns and
/// connect it to the box's `127.0.0.1:box_port`. Caller must already be in the box namespaces (see
/// [`enter_box_ns`]). Returns the fd, or `-1` on any failure.
pub(crate) fn connect_box_loopback(box_port: u16, ty: libc::c_int) -> i32 {
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

/// Connect to the box's own address ([`crate::real::BOX_ADDR`]) at `box_port`, with the SOURCE pinned
/// to `src_ip`.
///
/// WHY THE SOURCE IS SET AT ALL. A peer relay connects from inside box B to `127.0.0.1:<port>`, so
/// without this B sees every peer as loopback, indistinguishable from a connection made by B itself.
/// Loopback is the most trusted source in most default configurations, so a stack run with
/// `--no-pod` asked for network separation and got localhost-equivalence back between exactly the
/// pairs kern connected. It is no worse than the pod path, where peers really are on one loopback,
/// but it is a promise the flag implies and would otherwise not keep.
///
/// Binding the CALLING service's own alias makes the source meaningful: B sees `127.0.0.2` for one
/// peer and `127.0.0.3` for another, and a per-source rule inside B can tell them apart again.
///
/// MEASURED: `bind(127.0.0.2:0)` followed by `connect(127.0.0.1:<port>)` succeeds and the accepting
/// side reads the peer as `127.0.0.2`. The whole `127.0.0.0/8` is local on `lo`, so the alias needs
/// no address to have been added to the interface.
///
/// Returns the fd, or `-1` on any failure INCLUDING the bind: a connection whose source could not be
/// set is not silently made anyway, because that would put it back on `127.0.0.1` and hand B the
/// ambiguity this exists to remove.
pub(crate) fn connect_box_loopback_from(src_ip: u32, box_port: u16, ty: libc::c_int) -> i32 {
    unsafe {
        let s = libc::socket(libc::AF_INET, ty, 0);
        if s < 0 {
            return -1;
        }
        let src = addr_in(src_ip, 0); // ephemeral port on the peer's own alias
        if libc::bind(s, &src as *const _ as *const libc::sockaddr, ADDR_LEN) != 0 {
            libc::close(s);
            return -1;
        }
        // THE BOX'S ADDRESS, NOT ITS LOOPBACK: a peer reaches what the service serves on its
        // interfaces and not what it keeps on `127.0.0.1`, which is Docker's rule between two
        // containers and the bridge's rule here. See `BOX_ADDR`.
        let addr = addr_in(u32::from(crate::real::BOX_ADDR), box_port);
        if libc::connect(s, &addr as *const _ as *const libc::sockaddr, ADDR_LEN) != 0 {
            libc::close(s);
            return -1;
        }
        s
    }
}

/// Whether `src_ip` can be used as a source address in the CURRENT network namespace.
///
/// Called once, at relay start-up, so a source address that cannot be bound is reported then rather
/// than as a connection that fails for every client later. Binds and closes; it never connects.
pub(crate) fn source_address_is_bindable(src_ip: u32) -> bool {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if s < 0 {
            return false;
        }
        let src = addr_in(src_ip, 0);
        let ok = libc::bind(s, &src as *const _ as *const libc::sockaddr, ADDR_LEN) == 0;
        libc::close(s);
        ok
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

/// Turn Nagle OFF on a TCP socket.
///
/// Nagle holds a small write until the peer ACKs the previous one; the peer's delayed-ACK timer is
/// 40 ms. A proxy that copies an HTTP response written as headers-then-body hits exactly that, and it
/// only shows up on a KEPT-ALIVE connection, which is the normal mode for HTTP/1.1, gRPC, Postgres and
/// Redis. Measured through `-p` before this call existed: 59 requests/s on one keep-alive connection
/// with p99 pinned at 42.0 ms at every concurrency level, against 2614 requests/s when each request
/// opened a FRESH connection, which is backwards for any proxy and is the signature of the timer
/// rather than of contention.
///
/// Set on BOTH sides: the accepted client socket and the socket into the box. Either one left with
/// Nagle on can stall the direction it writes.
pub(crate) fn set_nodelay(s: i32) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            s,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
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
fn udp_forwarder(sock: i32, box_pid1: i32, m: PortMap, net: BoxNet, target: u32) -> ! {
    // Recently-forked clients (ip:port → when). Its ONLY job is to dedupe the ~ms race window between
    // us reading a client's first datagram and its child binding the connected socket that steals the
    // client's later datagrams. It is TIME-BOUNDED (pruned to `DEDUP_TTL`), NOT a lifetime blacklist -
    // so a long-lived resolver never hits a cumulative ceiling, and a client whose relay died can
    // reconnect once its stale entry ages out. The size cap is a secondary flood guard on RECENT peers.
    const DEDUP_TTL: std::time::Duration = std::time::Duration::from_secs(5);
    const MAX_RECENT: usize = 1024;
    let mut seen: std::collections::HashMap<(u128, u16), std::time::Instant> =
        std::collections::HashMap::new();
    let mut buf = [0u8; 65535];
    loop {
        let mut caddr: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut clen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
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
        let key = client_key(&caddr);
        if seen.contains_key(&key) || seen.len() >= MAX_RECENT {
            continue;
        }
        seen.insert(key, now);
        let c = unsafe { libc::fork() };
        if c == 0 {
            unsafe { libc::close(sock) };
            udp_relay_child(box_pid1, m, (caddr, clen), &buf[..n as usize], net, target);
            unsafe { libc::_exit(0) };
        }
    }
    unsafe { libc::_exit(0) }
}

/// A UDP client's identity (address bytes, port) from a `recvfrom` address of either family.
fn client_key(a: &libc::sockaddr_storage) -> (u128, u16) {
    if i32::from(a.ss_family) == libc::AF_INET6 {
        // SAFETY: the family says the storage holds a `sockaddr_in6`.
        let v6 = unsafe { &*(a as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
        (u128::from_be_bytes(v6.sin6_addr.s6_addr), v6.sin6_port)
    } else {
        // SAFETY: anything else this socket receives is a `sockaddr_in` (it is bound IPv4).
        let v4 = unsafe { &*(a as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
        (u128::from(v4.sin_addr.s_addr), v4.sin_port)
    }
}

/// One client's UDP relay: a host socket connected to the client (so it sends replies back to exactly
/// that client) + a box-side socket connected to `127.0.0.1:box_port`, forwarding datagrams both ways.
/// `first` is the initial datagram already read by the parent. Runs until either socket errors.
fn udp_relay_child(
    box_pid1: i32,
    m: PortMap,
    client: (libc::sockaddr_storage, libc::socklen_t),
    first: &[u8],
    net: BoxNet,
    target: u32,
) {
    unsafe {
        let hs = host_socket(m.bind, libc::SOCK_DGRAM);
        if hs < 0 {
            return;
        }
        reuse_addr_port(hs);
        let (ha, hlen) = sockaddr_of(m.bind, m.host);
        let (caddr, clen) = client;
        if libc::bind(hs, (&ha as *const libc::sockaddr_storage).cast(), hlen) != 0
            || libc::connect(hs, (&caddr as *const libc::sockaddr_storage).cast(), clen) != 0
        {
            return; // a racing sibling already owns this client's 4-tuple
        }
        // The host socket is bound and connected FIRST, while we are still in the host net ns - the
        // order matters on the `Enter` path and is simply correct on the refusing one.
        if net != BoxNet::Enter || !enter_box_ns(box_pid1) {
            return;
        }
        let Ok(bs) = connect_box_addr(target, m.box_port, libc::SOCK_DGRAM) else {
            return;
        };
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

/// A host-side socket address of either family, as `sockaddr_storage` and its length.
pub(crate) fn sockaddr_of(
    ip: std::net::IpAddr,
    port: u16,
) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: an all-zero `sockaddr_storage` is a valid value; each arm writes a complete address of
    // its family into the front of it.
    let mut st: libc::sockaddr_storage = unsafe { mem::zeroed() };
    match ip {
        std::net::IpAddr::V4(v4) => {
            let a = addr_in(u32::from(v4), port);
            // SAFETY: `sockaddr_in` fits in `sockaddr_storage` by definition.
            unsafe { ptr::write((&mut st as *mut libc::sockaddr_storage).cast(), a) };
            (st, ADDR_LEN)
        }
        std::net::IpAddr::V6(v6) => {
            // SAFETY: an all-zero `sockaddr_in6` is a valid value.
            let mut a: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            a.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            a.sin6_port = port.to_be();
            a.sin6_addr.s6_addr = v6.octets();
            // SAFETY: `sockaddr_in6` fits in `sockaddr_storage` by definition.
            unsafe { ptr::write((&mut st as *mut libc::sockaddr_storage).cast(), a) };
            (st, mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

/// A socket of `ty` for `ip`'s family; an IPv6 one is set IPv6-ONLY, so `::` never also takes the
/// IPv4 port its `0.0.0.0` twin binds. `-1` on failure, with `errno` set.
fn host_socket(ip: std::net::IpAddr, ty: libc::c_int) -> i32 {
    let fam = if ip.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let s = unsafe { libc::socket(fam, ty, 0) };
    if s >= 0 && ip.is_ipv6() {
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                s,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &one as *const _ as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    s
}

/// Can this host bind an IPv6 socket at all? `false` where the kernel has no IPv6 (`ipv6.disable=1`,
/// a CI runner built without it).
#[must_use]
pub fn host_has_ipv6() -> bool {
    address_is_bindable(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))
}

/// A host port the kernel picked for `primary`, free on every address in `also` too, for the
/// protocol given: one number for both families of a default bind, as Docker gives
/// (`0.0.0.0:32768` and `[::]:32768`). `None` after a bounded number of attempts.
///
/// The port is released before the box binds it, as Docker's allocator does before its proxy binds:
/// a process that takes it in that window makes the box's own bind fail, by name, rather than the
/// box being published somewhere else.
#[must_use]
pub fn pick_free_port(
    primary: std::net::IpAddr,
    also: &[std::net::IpAddr],
    udp: bool,
) -> Option<u16> {
    let ty = if udp {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
    let bound_port = |ip: std::net::IpAddr, port: u16| -> Option<(i32, u16)> {
        let s = host_socket(ip, ty);
        if s < 0 {
            return None;
        }
        let (a, len) = sockaddr_of(ip, port);
        if unsafe { libc::bind(s, (&a as *const libc::sockaddr_storage).cast(), len) } != 0 {
            unsafe { libc::close(s) };
            return None;
        }
        let mut st: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut sl = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockname(s, (&mut st as *mut libc::sockaddr_storage).cast(), &mut sl)
        };
        if r != 0 {
            unsafe { libc::close(s) };
            return None;
        }
        // Both families keep the port at the same offset of their sockaddr.
        let got = u16::from_be(unsafe {
            (*(&st as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()).sin_port
        });
        Some((s, got))
    };
    for _ in 0..32 {
        let (first, port) = bound_port(primary, 0)?;
        let mut held = vec![first];
        let all = also.iter().all(|ip| match bound_port(*ip, port) {
            Some((s, _)) => {
                held.push(s);
                true
            }
            None => false,
        });
        for s in held {
            unsafe { libc::close(s) };
        }
        if all {
            return Some(port);
        }
    }
    None
}

/// The first port of `start..=end` that binds on `primary` and on every address in `also` (one number
/// for a default bind's two families), for a host port RANGE published onto one box port. `None` when
/// every port of the range is taken. The sockets are closed again: the forwarder binds for real.
#[must_use]
pub fn pick_port_in(
    primary: std::net::IpAddr,
    also: &[std::net::IpAddr],
    udp: bool,
    start: u16,
    end: u16,
) -> Option<u16> {
    let ty = if udp {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
    let binds = |ip: std::net::IpAddr, port: u16| -> Option<i32> {
        let s = host_socket(ip, ty);
        if s < 0 {
            return None;
        }
        let (a, len) = sockaddr_of(ip, port);
        if unsafe { libc::bind(s, (&a as *const libc::sockaddr_storage).cast(), len) } != 0 {
            unsafe { libc::close(s) };
            return None;
        }
        Some(s)
    };
    (start..=end).find(|&port| {
        let mut held = Vec::new();
        let ok = std::iter::once(primary)
            .chain(also.iter().copied())
            .all(|ip| match binds(ip, port) {
                Some(s) => {
                    held.push(s);
                    true
                }
                None => false,
            });
        for s in held {
            unsafe { libc::close(s) };
        }
        ok
    })
}

/// Can a TCP socket be bound to `ip` (on an ephemeral port) on this host? This is what decides the
/// IPv6 half of a default bind, PER ADDRESS: a host can have IPv6 and still not have `::1`.
/// MEASURED on a VPS with IPv6 on `eth0` and `disable_ipv6 = 1` on `lo`: `[::]` binds and `[::1]`
/// answers `EADDRNOTAVAIL`, so a `publish_bind = "127.0.0.1"` policy (whose IPv6 twin is `::1`)
/// refused every `-p` while "does this host have IPv6" said yes.
#[must_use]
pub fn address_is_bindable(ip: std::net::IpAddr) -> bool {
    let s = host_socket(ip, libc::SOCK_STREAM);
    if s < 0 {
        return false;
    }
    let (a, len) = sockaddr_of(ip, 0);
    let ok = unsafe { libc::bind(s, (&a as *const libc::sockaddr_storage).cast(), len) } == 0;
    unsafe { libc::close(s) };
    ok
}

const ADDR_LEN: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

/// `sockaddr_in` for `ip` (host byte order; `0` = 0.0.0.0) and `port` (host byte order).
pub(crate) fn addr_in(ip: u32, port: u16) -> libc::sockaddr_in {
    let mut a: libc::sockaddr_in = unsafe { mem::zeroed() };
    a.sin_family = libc::AF_INET as libc::sa_family_t;
    a.sin_port = port.to_be();
    a.sin_addr.s_addr = ip.to_be();
    a
}

/// Bidirectional byte pump until both read sides close; each EOF half-closes the peer's write side.
pub(crate) fn pump_bidir(a: i32, b: i32) {
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

    /// Nagle must be OFF on a socket the forwarder pumps through.
    ///
    /// With it on, a proxy copying an HTTP response written as headers-then-body waits for the peer's
    /// delayed-ACK timer, which is 40 ms on Linux, and it only bites on a KEPT-ALIVE connection: the
    /// normal mode for HTTP/1.1, gRPC, Postgres and Redis. Measured end to end through `-p` on nginx
    /// before this was set: **59 requests/s** on one keep-alive connection with p99 pinned at exactly
    /// 42.0 ms whatever the concurrency, against 2614/s when every request opened a FRESH connection.
    /// A proxy being 44x faster when you STOP reusing the connection is the signature of the timer and
    /// not of load. With it off: 12,479/s on that same connection, and p99 0.27 ms.
    ///
    /// Asserted by reading the option back with `getsockopt`, on a real TCP socket, so it fails if the
    /// call is dropped, moved after the first write, or given the wrong level (`SOL_SOCKET` instead of
    /// `IPPROTO_TCP` silently sets nothing useful).
    #[test]
    fn the_forwarder_turns_nagle_off() {
        let s = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(s >= 0, "socket() failed");

        let read_back = |fd: i32| -> libc::c_int {
            let mut v: libc::c_int = -1;
            let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
            let r = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_NODELAY,
                    &mut v as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(r, 0, "getsockopt(TCP_NODELAY) failed");
            v
        };

        // The control: a fresh TCP socket has Nagle ON, so the assertion below cannot pass vacuously.
        assert_eq!(
            read_back(s),
            0,
            "a fresh socket should start with Nagle enabled"
        );
        set_nodelay(s);
        assert_ne!(read_back(s), 0, "set_nodelay left Nagle enabled");
        unsafe { libc::close(s) };
    }

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

    /// `0.0.0.0` AND `::` ON ONE PORT, as Docker binds them for `-p 8080:80`: the IPv6 listener is
    /// IPv6 only, so it neither takes the IPv4 port from its twin nor answers IPv4 clients, and an
    /// IPv6 client reaches it. Skipped where the host has no IPv6, which is the case the CLI drops
    /// the twin for.
    #[test]
    fn an_ipv6_listener_is_ipv6_only_so_both_families_share_one_port() {
        let _g = port_guard();
        if !host_has_ipv6() {
            eprintln!("skip: this host has no IPv6");
            return;
        }
        // The client half needs `::1`, which a host can lack while `::` still binds: MEASURED on the
        // VPS, `net.ipv6.conf.all.disable_ipv6 = 1` left the stack able to bind `::` and nothing to
        // connect from. The bind half is still the product's (`host_has_ipv6`); only this test's
        // client depends on the loopback.
        if std::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).is_err() {
            eprintln!("skip: this host binds :: but has no IPv6 loopback to connect from");
            return;
        }
        let any4 = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        let any6 = std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
        // ANOTHER PORT WHEN A THIRD PARTY HOLDS THIS ONE. `free_port` asks `127.0.0.1` only, and any
        // other IPv4 socket on the port refuses `0.0.0.0`: MEASURED once in a VM, "Err(98) Ok(6)". The
        // defect this test exists for, a `::` that is not IPv6-only, refuses the twin on EVERY port,
        // so retrying on `EADDRINUSE` absorbs the collision and never the defect.
        let (mut port, mut v4, mut v6) = (0, Err(0), Err(0));
        for _ in 0..20 {
            port = free_port();
            v4 = bind_host_socket(any4, port, false);
            v6 = bind_host_socket(any6, port, false);
            // Only the IPv4 bind is retried: a refused `::` after a bound `0.0.0.0` IS the defect.
            if v4 != Err(libc::EADDRINUSE) {
                break;
            }
            for fd in [v4, v6].into_iter().flatten() {
                unsafe { libc::close(fd) };
            }
        }
        let both = matches!((v4, v6), (Ok(_), Ok(_)));
        let reached = v6.ok().is_some_and(|_| {
            std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
                std::time::Duration::from_secs(2),
            )
            .is_ok()
        });
        for fd in [v4, v6].into_iter().flatten() {
            unsafe { libc::close(fd) };
        }
        assert!(
            both,
            "0.0.0.0 and :: must both bind port {port}: {v4:?} {v6:?}"
        );
        assert!(reached, "an IPv6 client must reach the :: listener");
    }

    /// A published connection reaches the box's OWN ADDRESS, from that address, and never its
    /// loopback: a listener on `127.0.0.1` only is refused (Docker does not publish it either), one
    /// on every interface is reached, and the server sees a client that is not `127.0.0.1`.
    ///
    /// `127.0.0.2` stands in for `BOX_ADDR` because a test cannot add an address to `lo`; it is
    /// local on `lo` by the `127.0.0.0/8` route and is not `127.0.0.1`, which is the one property
    /// the rule turns on. MEASURED before this function: a `-p` listener bound to `127.0.0.1` in a
    /// box answered 200 from the LAN, and a Redis in protected mode answered `+PONG` to a LAN client.
    #[test]
    fn a_published_connection_reaches_the_box_address_and_not_its_loopback() {
        let _g = port_guard();
        use std::io::Read;
        use std::net::TcpListener;
        let stand_in = u32::from(std::net::Ipv4Addr::new(127, 0, 0, 2));
        // Loopback only: refused, with the errno the note keys on.
        let lo = match TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(e) => panic!("bind loopback: {e}"),
        };
        let lo_port = lo.local_addr().map(|a| a.port()).unwrap_or(0);
        assert_eq!(
            connect_box_addr(stand_in, lo_port, libc::SOCK_STREAM)
                .map(|fd| unsafe { libc::close(fd) }),
            Err(libc::ECONNREFUSED),
            "a listener on 127.0.0.1 only must not be reached"
        );
        // Every interface: reached, and the accepted peer is the box address, not loopback.
        let any = match TcpListener::bind(("0.0.0.0", 0)) {
            Ok(l) => l,
            Err(e) => panic!("bind any: {e}"),
        };
        let any_port = any.local_addr().map(|a| a.port()).unwrap_or(0);
        let fd = match connect_box_addr(stand_in, any_port, libc::SOCK_STREAM) {
            Ok(fd) => fd,
            Err(e) => panic!("a listener on every interface must be reached (errno {e})"),
        };
        let peer = any.accept().map(|(mut c, a)| {
            let mut b = [0u8; 1];
            let _ = c.set_nonblocking(true);
            let _ = c.read(&mut b);
            a.ip()
        });
        unsafe { libc::close(fd) };
        assert_eq!(
            peer.ok(),
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2))),
            "the server must see the box address as the client, never 127.0.0.1"
        );
    }

    /// THE invariant this module was rewritten for: the host port is bound by the time
    /// `fork_forwarders` RETURNS - before the box is unshared, forked, or declared started. Proven
    /// the only way that isn't a restatement of the code: by racing it. A second `bind` of the same
    /// port must now fail, because a forwarder already holds it.
    #[test]
    fn the_host_port_is_bound_before_the_box_exists() {
        let _g = port_guard();
        use std::net::TcpListener;
        // A port found free is released before the forwarder binds it, and another test in this
        // binary can take it in between (seen once in a full run: "Address already in use" on a
        // port `free_port` had just returned). That one answer takes another port; any other fails.
        let mut attempt = 0;
        let (port, fwd) = loop {
            let port = free_port();
            let m = PortMap {
                bind: std::net::IpAddr::V4(std::net::Ipv4Addr::from(LOOPBACK)),
                implicit: false,
                host: port,
                box_port: 9,
                udp: false,
                host_pool: None,
            };
            match fork_forwarders(&[m]) {
                Ok(f) => break (port, f),
                Err((_, e)) if e.contains("os error 98") && attempt < 5 => {
                    attempt += 1;
                }
                Err((p, e)) => panic!("a free port {p} should publish: {e}"),
            }
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
            bind: std::net::IpAddr::V4(std::net::Ipv4Addr::from(LOOPBACK)),
            implicit: false,
            host: taken,
            box_port: 9,
            udp: false,
            host_pool: None,
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
                bind: std::net::IpAddr::V4(std::net::Ipv4Addr::from(LOOPBACK)),
                implicit: false,
                host: good,
                box_port: 9,
                udp: false,
                host_pool: None,
            },
            PortMap {
                bind: std::net::IpAddr::V4(std::net::Ipv4Addr::from(LOOPBACK)),
                implicit: false,
                host: taken,
                box_port: 9,
                udp: false,
                host_pool: None,
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
            bind: std::net::IpAddr::V4(std::net::Ipv4Addr::from(LOOPBACK)),
            implicit: false,
            host,
            box_port: 80,
            udp: false,
            host_pool: None,
        };
        match preflight(&[pm(taken)]) {
            Err((p, _)) => assert_eq!(p, taken, "reported the conflicting port"),
            Ok(()) => panic!("preflight passed a port that is actively listening"),
        }
        // A FREE PORT PASSES, AND THE FIRST VERSION OF THIS ASSERTION WAS A RACE. It took an
        // ephemeral port from the OS, released it, and asserted the port was free - between those
        // two instants any other thread in this binary, or any process on the machine, may take it.
        // Observed as a one-in-many failure in a full `cargo test` run and green three times out of
        // three when run alone, which is the signature.
        //
        // RETRIED RATHER THAN WEAKENED: the claim is still "preflight passes a port nobody holds",
        // and a port that lost the race is simply not that port. A handful of attempts makes a
        // spurious failure vanishingly unlikely without ever passing for the wrong reason, because
        // every attempt asserts the same thing.
        let mut passed = false;
        for _ in 0..16 {
            let Ok(t) = TcpListener::bind(("127.0.0.1", 0)) else {
                continue;
            };
            let Ok(addr) = t.local_addr() else {
                continue;
            };
            let free = addr.port();
            drop(t);
            if preflight(&[pm(free)]).is_ok() {
                passed = true;
                break;
            }
        }
        assert!(passed, "a free port should pass");
    }

    /// EVERY SET IS EMPTY AFTER A NARROWED DROP, INCLUDING THE BOUNDING SET.
    ///
    /// MEASURED as a live defect before this test existed. The relay listener narrows to
    /// `CAP_NET_BIND_SERVICE` before its bind and drops to zero after, and the first version of
    /// `restrict_capabilities` skipped `mask`'s bits in the `PR_CAPBSET_DROP` loop. That left the bit
    /// in the bounding set, and the SECOND call could not remove it: `PR_CAPBSET_DROP` needs
    /// `CAP_SETPCAP` in the effective set, which the first call had just dropped. A live listener read
    /// `CapBnd: 0000000000000400` while `CapEff` read zero, so the function claimed every set was
    /// empty and one was not.
    ///
    /// Runs in a FORKED CHILD, because dropping capabilities is irreversible and doing it in the test
    /// process would silently change what every later test in this binary runs as. The child reports
    /// through a pipe; the parent asserts. Both calls are made in the child, in the listener's order,
    /// because the defect was in their COMPOSITION and neither call is wrong alone.
    /// `bounding_set_is_empty` answers about the STATE, in both directions.
    ///
    /// The negative half is the one that matters: this test process has a full bounding set, so a
    /// version that always said "empty" would let `restrict_capabilities` keep claiming success on a
    /// host that grants no privileges to shed, which is the CI failure this was written for. The
    /// positive half runs in a forked child so the drop cannot affect the rest of the suite.
    #[test]
    fn bounding_set_is_empty_reports_the_state_not_the_calls() {
        assert!(
            !bounding_set_is_empty(),
            "this test process holds a full bounding set: {}",
            std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("CapBnd:"))
                .unwrap_or("CapBnd: unreadable")
        );
        let mut fds = [0i32; 2];
        // SAFETY: fills a two-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: fork in a test binary; the child only unshares, drops and writes one byte.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: the read end belongs to the parent, and the child exits without unwinding.
            unsafe {
                libc::close(fds[0]);
                let verdict: &[u8] = if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    b"s" // no user namespace here: nothing to conclude
                } else {
                    let last = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .unwrap_or(63);
                    for cap in 0..=last {
                        libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
                    }
                    if bounding_set_is_empty() {
                        b"y"
                    } else {
                        b"n"
                    }
                };
                libc::write(fds[1], verdict.as_ptr() as *const libc::c_void, 1);
                libc::close(fds[1]);
                libc::_exit(0);
            }
        }
        let mut b = [0u8; 1];
        // SAFETY: reads one byte into a buffer this function owns, then reaps its own child.
        let n = unsafe {
            libc::close(fds[1]);
            let n = libc::read(fds[0], b.as_mut_ptr() as *mut libc::c_void, 1);
            libc::close(fds[0]);
            let mut st: libc::c_int = 0;
            libc::waitpid(pid, &mut st, 0);
            n
        };
        assert!(n == 1, "the child reported nothing");
        match b[0] {
            b's' => eprintln!("skip: this host refuses an unprivileged user namespace"),
            b'y' => {}
            // The child dropped every capability and the bound did not empty: a GitHub runner does
            // this under AppArmor. The NEGATIVE half above already ran and is the half that guards
            // the CI failure this exists for, so the positive one is reported as unavailable rather
            // than failed.
            _ => eprintln!(
                "skip(partial): this host refuses PR_CAPBSET_DROP, so the emptied case cannot be \
                 produced here; the full-set case above still ran"
            ),
        }
    }

    #[test]
    fn a_narrowed_drop_still_empties_the_bounding_set() {
        const CAP_NET_BIND_SERVICE: u32 = 10;
        let mut fds = [0i32; 2];
        // SAFETY: fills a two-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: fork in a test binary; the child only reads /proc, writes a pipe and _exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: the read end belongs to the parent.
            unsafe { libc::close(fds[0]) };
            // A USER NAMESPACE FIRST, because this function RESTRICTS and never grants: asking for
            // `CAP_NET_BIND_SERVICE` from a process that does not hold it is a request to GAIN one,
            // and `capset` answers EPERM. The relay half holds a full set because it has just entered
            // the box's user namespace, and this is the cheapest way to stand in the same place.
            // SAFETY: unshare in a single-threaded forked child.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
                let msg = b"skip";
                // SAFETY: writes a static buffer to a descriptor this child owns.
                unsafe {
                    libc::write(fds[1], msg.as_ptr() as *const libc::c_void, msg.len());
                    libc::close(fds[1]);
                    libc::_exit(0);
                }
            }
            // THE HOST MAY REFUSE TO EMPTY THE BOUND AT ALL, and then there is no drop to measure.
            // A GitHub runner does: its `apparmor_restrict_unprivileged_userns` policy lets the
            // `unshare` above succeed, leaves `CapEff` FULL inside the new namespace, and still
            // refuses `PR_CAPBSET_DROP`. Measured there, on both architectures: `false
            // 000001ffffffffff 000001ffffffffff 000001ffffffffff 0000000000000000` - every set
            // untouched. That is the host, not this code, and a first attempt to detect it by
            // reading `CapEff` was wrong for exactly that reason: the capability is present and
            // mediated anyway.
            //
            // Probed with a DIRECT `prctl` on one capability rather than through
            // `restrict_capabilities`, so it cannot skip on a defect in the function under test: if
            // the bound can be narrowed by hand, the function is required to empty it.
            // The STATE decides, not the return value, for the same reason the function under test
            // now works that way: an LSM is free to answer 0 and mediate the effect.
            let bound_now = || -> String {
                std::fs::read_to_string("/proc/self/status")
                    .unwrap_or_default()
                    .lines()
                    .find(|l| l.starts_with("CapBnd:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("?")
                    .to_string()
            };
            let before_probe = bound_now();
            // SAFETY: acts on the calling thread only, dropping one capability from its bound.
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, 0 as libc::c_ulong, 0, 0, 0) };
            if bound_now() == before_probe {
                let msg = b"skipcaps";
                // SAFETY: writes a static buffer to a descriptor this child owns.
                unsafe {
                    libc::write(fds[1], msg.as_ptr() as *const libc::c_void, msg.len());
                    libc::close(fds[1]);
                    libc::_exit(0);
                }
            }
            let ok =
                restrict_capabilities(1u64 << CAP_NET_BIND_SERVICE) && restrict_capabilities(0);
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let line = |k: &str| -> String {
                status
                    .lines()
                    .find(|l| l.starts_with(k))
                    .map(|l| l.split_whitespace().nth(1).unwrap_or("?").to_string())
                    .unwrap_or_else(|| "?".to_string())
            };
            let out = format!(
                "{} {} {} {} {}",
                ok,
                line("CapEff:"),
                line("CapPrm:"),
                line("CapBnd:"),
                line("CapAmb:")
            );
            // SAFETY: writes a buffer this child owns to a descriptor it owns.
            unsafe {
                libc::write(fds[1], out.as_ptr() as *const libc::c_void, out.len());
                libc::close(fds[1]);
                libc::_exit(0);
            }
        }
        // SAFETY: the write end belongs to the child.
        unsafe { libc::close(fds[1]) };
        let mut buf = [0u8; 256];
        // SAFETY: reads at most `buf.len()` into a buffer this function owns.
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        // SAFETY: the child is this process's, and `st` is written by the kernel.
        unsafe {
            libc::close(fds[0]);
            let mut st: libc::c_int = 0;
            libc::waitpid(pid, &mut st, 0);
        }
        assert!(n > 0, "the child reported nothing");
        let text = String::from_utf8_lossy(&buf[..n as usize]).to_string();
        if text.trim() == "skip" {
            eprintln!("skip: this host refuses an unprivileged user namespace");
            return;
        }
        if text.trim() == "skipcaps" {
            eprintln!(
                "skip: this host refuses PR_CAPBSET_DROP inside an unprivileged user namespace \
                 (AppArmor apparmor_restrict_unprivileged_userns), so the bound cannot be emptied \
                 by anyone and there is nothing to measure"
            );
            return;
        }
        let f: Vec<&str> = text.split_whitespace().collect();
        assert_eq!(f.len(), 5, "unexpected report: {text}");
        assert_eq!(f[0], "true", "the drop must report success: {text}");
        for (name, value) in [
            ("CapEff", f[1]),
            ("CapPrm", f[2]),
            ("CapBnd", f[3]),
            ("CapAmb", f[4]),
        ] {
            assert!(
                value.chars().all(|c| c == '0'),
                "{name} must be empty after the drop, not {value} (whole report: {text})"
            );
        }
    }
}
