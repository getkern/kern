//! `--egress-allow`: a domain allowlist for a box's outbound network.
//!
//! Enforcement model (see `docs/EGRESS.md` for the full threat model): the box runs in an ISOLATED
//! network namespace (no route to the internet, a real kernel boundary), and the ONLY egress is a
//! kern-controlled HTTP proxy. Two helper processes kern owns:
//!
//!  * a **pump** joined to the box's net namespace, listening on `127.0.0.1:<port>` inside the box,
//!    relaying each connection to a host-side UNIX socket (UNIX sockets aren't namespaced, so they
//!    bridge the box netns to the host without handing the box a network route);
//!  * a **filtering proxy** in the host net namespace, on that UNIX socket, that parses each request
//!    and dials out ONLY to an allowlisted host.
//!
//! `HTTP_PROXY`/`HTTPS_PROXY` are pointed at the pump. Because the box has no other route, a workload
//! that ignores the proxy env and opens a raw socket gets `ENETUNREACH`: the proxy is the only door.
//!
//! This module's SECURITY CORE is pure and unit-tested: `host_allowed` (exact domain or subdomain, no
//! substring tricks) and the request parsers. The socket plumbing is a thin byte pump around them.

use std::io::{Read, Write};
use std::os::unix::io::FromRawFd; // for File::from_raw_fd (the pid-delivery pipe)
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt; // for Command::pre_exec

/// Is `host` covered by the allowlist? A match is an EXACT equal to an entry, or a subdomain of one
/// (`host` ends with `.<entry>`). Case-insensitive; a trailing dot is ignored. This is the whole
/// security decision, so it is deliberately strict:
///  * `pypi.org` matches `pypi.org` and `files.pypi.org`, NOT `evilpypi.org` or `pypi.org.evil.com`.
///  * an IP literal never matches a domain entry (no entry contains a bare IP unless you list it).
pub fn host_allowed(host: &str, allow: &[String]) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    allow.iter().any(|entry| {
        let e = entry
            .trim()
            .trim_end_matches('.')
            .trim_start_matches('.')
            .to_ascii_lowercase();
        if e.is_empty() {
            return false;
        }
        // exact, or a subdomain: h == e  OR  h ends with ".e" (the boundary dot prevents `evilpypi.org`
        // from matching `pypi.org`).
        h == e
            || h.len() > e.len() + 1
                && h.ends_with(&e)
                && h.as_bytes()[h.len() - e.len() - 1] == b'.'
    })
}

/// Parse the host of a `CONNECT host:port …` request line (the HTTPS proxy verb). Returns the bare host
/// (no port). `None` if the line is not a well-formed CONNECT. IPv6 literals arrive bracketed
/// (`[::1]:443`); the brackets are stripped so a bare `[::1]` never accidentally matches a domain entry.
pub fn parse_connect_host(line: &str) -> Option<String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut it = line.split_whitespace();
    if !it.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let target = it.next()?; // host:port
    host_of_authority(target)
}

/// Parse the host of a plain-HTTP proxied request: the absolute-form request-target
/// (`GET http://host/path …`) or, failing that, the `Host:` header. Returns the bare host.
pub fn parse_http_host(request_line: &str, headers: &str) -> Option<String> {
    // absolute-form: METHOD http://host[:port]/path VERSION
    if let Some(target) = request_line.split_whitespace().nth(1) {
        if let Some(rest) = target
            .strip_prefix("http://")
            .or_else(|| target.strip_prefix("https://"))
        {
            let authority = rest.split('/').next().unwrap_or(rest);
            if let Some(h) = host_of_authority(authority) {
                return Some(h);
            }
        }
    }
    // fall back to the Host header
    for h in headers.lines() {
        if let Some(v) = h
            .split_once(':')
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case("Host"))
        {
            return host_of_authority(v.1.trim());
        }
    }
    None
}

/// The bare host of an `authority` (`host`, `host:port`, `[v6]:port`), lowercased, brackets/port
/// stripped. Rejects an empty host.
fn host_of_authority(authority: &str) -> Option<String> {
    let a = authority.trim();
    let host = if let Some(rest) = a.strip_prefix('[') {
        // [v6]:port → v6
        rest.split(']').next()?
    } else {
        // host:port → host (rsplit so a bare host with no colon works too)
        a.rsplit_once(':').map(|(h, _)| h).unwrap_or(a)
    };
    let host = host.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Ports the proxy will tunnel to. A domain allowlist is about reaching a web host, not arbitrary
/// services co-located on it (`:22`, `:6379`, …), so restrict to HTTPS/HTTP. A future `host:port`
/// allowlist syntax could widen this.
fn port_allowed(port: u16) -> bool {
    port == 443 || port == 80
}

/// Resolve `host:port` and connect to the FIRST address that is a routable PUBLIC unicast IP, refusing
/// loopback / link-local / private / multicast / unspecified. Closes the SSRF where an allowlisted NAME
/// resolves to `127.0.0.1`, `169.254.169.254` (cloud metadata), or an RFC-1918 host-local service.
fn connect_vetted(host: &str, port: u16) -> std::io::Result<std::net::TcpStream> {
    use std::net::ToSocketAddrs;
    let mut last = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no public address");
    for addr in (host, port).to_socket_addrs()? {
        if !ip_is_public(addr.ip()) {
            last = std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing non-public address {}", addr.ip()),
            );
            continue;
        }
        match std::net::TcpStream::connect(addr) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Is `ip` a routable public unicast address? Rejects loopback, link-local (incl. IPv4 `169.254/16`, the
/// cloud metadata range, and IPv6 `fe80::/10`), private (RFC1918 / ULA `fc00::/7`), multicast, and
/// unspecified. Conservative: an unknown range is treated as public, but every host-local range is refused.
pub fn ip_is_public(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(a) => {
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_unspecified()
                || a.octets()[0] == 0)
        }
        std::net::IpAddr::V6(a) => {
            let hi = a.segments()[0];
            !(a.is_loopback()
                || a.is_multicast()
                || a.is_unspecified()
                || (hi & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (hi & 0xffc0) == 0xfe80) // link-local fe80::/10
        }
    }
}

// -- the running filter (socket plumbing) --------------------------------------------------------

/// A live egress filter: the filtering-proxy child (a clean re-exec), the box-netns pump pid, and the
/// box-side proxy port advertised in `HTTP_PROXY`. Dropping it kills both helpers and removes the socket.
pub struct EgressFilter {
    proxy: std::process::Child,
    pump: std::process::Child,
    sock_path: std::path::PathBuf,
}

impl Drop for EgressFilter {
    fn drop(&mut self) {
        for c in [&mut self.proxy, &mut self.pump] {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_file(&self.sock_path);
    }
}

/// Both helpers, spawned in the HOST pid namespace but not yet told the box init pid. box_run holds this
/// between spawning the helpers (before `run_in_sandbox_with`) and the `on_started` callback; calling
/// [`EgressPending::deliver`] with the box init pid writes it down the pipe to the pump and yields the
/// live [`EgressFilter`] guard.
pub struct EgressPending {
    proxy: std::process::Child,
    pump: std::process::Child,
    sock_path: std::path::PathBuf,
    pid_writer: std::fs::File,
}

impl EgressPending {
    /// Send the box init pid to the waiting pump (which then joins the box netns) and return the guard.
    /// Dropping `pid_writer` closes the pipe; the pump has already read its 4 bytes, so EOF is moot.
    pub fn deliver(mut self, box_pid1: i32) -> EgressFilter {
        let _ = self.pid_writer.write_all(&box_pid1.to_le_bytes());
        let _ = self.pid_writer.flush();
        // Partial move: `pid_writer` stays behind and drops here, closing the pipe. EgressPending has no
        // Drop, so moving the other three fields out is allowed.
        EgressFilter {
            proxy: self.proxy,
            pump: self.pump,
            sock_path: self.sock_path,
        }
    }
}

/// A `pre_exec` hook for both egress helpers (runs in the forked child, BEFORE `execve`). Two jobs, both
/// async-signal-safe:
///  1. Close every inherited fd >= 3. box_run (a foreground, multi-threaded process) forks the helper
///     with ALL its fds, including the box's OUTPUT CAPTURE PIPE. If a helper keeps that write-end open
///     in its accept loop, the box's supervisor blocks reading the pipe (never sees EOF) and box_run's
///     `waitpid` on the supervisor hangs until `--timeout`. `execve` closes O_CLOEXEC fds, but shedding
///     here is belt-and-suspenders that also drops any non-CLOEXEC copy. The helper opens everything it
///     needs (netns handle, listener, unix socket) fresh after exec.
///  2. Arm `PR_SET_PDEATHSIG(SIGKILL)` so a hard-killed box_run (SIGKILL/OOM, which skips Drop) takes
///     the helper down with it instead of orphaning.
fn helper_pre_exec() -> std::io::Result<()> {
    kern_isolation::shed_inherited_fds(-1);
    // New session + process group: the helper must NOT sit in box_run's process group, or box_run's
    // foreground supervision (which reaps / signals its own group when the box exits) would block on the
    // never-exiting helper. This is what a runtime-managed `-p` forwarder gets for free; the egress
    // helpers, spawned outside the runtime, need it explicitly. PDEATHSIG (armed AFTER setsid, since
    // setsid doesn't change the parent) still ties the helper's life to box_run.
    unsafe {
        libc::setsid();
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0);
    }
    Ok(())
}

/// Spawn the filtering proxy: call this in the HOST network namespace, BEFORE the box's netns is
/// entered/created, so the proxy has a route to a DNS server (the box's own netns is isolated and would
/// give `getaddrinfo` `EAI_AGAIN`). It is a CLEAN RE-EXEC of kern (`__egress-proxy`), not a raw fork of
/// this (multi-threaded) process, so glibc's resolver starts fresh. Returns the proxy child and the
/// UNIX socket path it binds. Pair with [`attach_pump`] once the box's init pid is known.
pub fn spawn_proxy(allow: &[String]) -> Result<(std::process::Child, std::path::PathBuf), String> {
    let uid = unsafe { libc::getuid() };
    let sock_path = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(format!("/run/user/{uid}")))
        .join(format!("kern-egress-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock_path);
    let exe = std::env::current_exe().map_err(|e| format!("egress: self exe: {e}"))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__egress-proxy").arg(&sock_path).arg(allow.join(","))
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null());
    unsafe { cmd.pre_exec(helper_pre_exec) };
    let proxy = cmd.spawn().map_err(|e| format!("egress: spawn proxy: {e}"))?;
    // Wait briefly for the proxy to bind, so the box's first request doesn't race it.
    for _ in 0..200 {
        if sock_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok((proxy, sock_path))
}

/// Spawn BOTH egress helpers, to be called from box_run in the HOST pid namespace **before**
/// `run_in_sandbox_with` (i.e. before box_run's `unshare(CLONE_NEWPID)`). This placement is
/// load-bearing, not cosmetic: after box_run unshares CLONE_NEWPID its `pid_for_children` is the BOX pid
/// namespace, so a helper forked from the `on_started` callback lands INSIDE the box pidns. On box exit
/// that helper is SIGKILL'd but lingers as a zombie box_run never reaps (box_run `wait4`s the box init
/// specifically), and the box init's own exit blocks in `zap_pid_ns_processes` waiting for that zombie to
/// be freed. The result is a three-way deadlock: the box "runs, filters correctly, then never exits."
/// Spawning here keeps both helpers in the HOST pidns, so they are ordinary box_run children the guard's
/// `Drop` reaps cleanly.
///
/// The proxy needs nothing but the allowlist. The pump needs the box init pid, which does not exist yet;
/// it is delivered later over an inherited pipe (see [`EgressPending::deliver`]). The pump is a clean
/// re-exec, so a CLOEXEC pipe fd would not survive its `execve`; the read end is therefore left
/// non-CLOEXEC and box_run closes its own copy right after the spawn so the box (forked later) can never
/// inherit it.
pub fn spawn(allow: &[String], box_port: u16) -> Result<EgressPending, String> {
    let (proxy, sock_path) = spawn_proxy(allow)?;

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        return Err(format!("egress: pipe: {}", std::io::Error::last_os_error()));
    }
    let (rfd, wfd) = (fds[0], fds[1]);
    // box_run's write end must not be inherited by the box itself.
    unsafe { libc::fcntl(wfd, libc::F_SETFD, libc::FD_CLOEXEC) };

    let exe = std::env::current_exe().map_err(|e| format!("egress: self exe: {e}"))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__egress-pump")
        .arg(rfd.to_string())
        .arg(box_port.to_string())
        .arg(&sock_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null());
    // Custom pre_exec: like `helper_pre_exec` but KEEP the pid-pipe read end (shed everything else).
    unsafe {
        cmd.pre_exec(move || {
            kern_isolation::shed_inherited_fds(rfd);
            libc::setsid();
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0);
            Ok(())
        });
    }
    let pump = match cmd.spawn() {
        Ok(p) => p,
        Err(e) => {
            unsafe {
                libc::close(rfd);
                libc::close(wfd);
            }
            return Err(format!("egress: spawn pump: {e}"));
        }
    };
    // box_run drops its read end so the box (forked later, in run_in_sandbox_with) can't inherit it.
    unsafe { libc::close(rfd) };
    let pid_writer = unsafe { std::fs::File::from_raw_fd(wfd) };
    Ok(EgressPending {
        proxy,
        pump,
        sock_path,
        pid_writer,
    })
}

/// Entry point for the re-exec'd box-netns pump (`kern __egress-pump <read_fd> <box_port> <sock>`). The
/// box init pid arrives (4 bytes, little-endian) over the inherited `read_fd` pipe from box_run; only
/// then does the pump join the box netns. Fresh process, so no inherited box capture pipes. Never returns.
pub fn pump_reexec(read_fd: i32, box_port: u16, sock_path: &str) -> ! {
    drop_signals();
    let mut buf = [0u8; 4];
    let mut got = 0usize;
    while got < buf.len() {
        let n = unsafe {
            libc::read(
                read_fd,
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - got,
            )
        };
        if n <= 0 {
            eprintln!("kern: egress pump: box pid pipe closed before delivery");
            unsafe { libc::_exit(1) };
        }
        got += n as usize;
    }
    unsafe { libc::close(read_fd) };
    let box_pid1 = i32::from_le_bytes(buf);
    pump_main(box_pid1, box_port, std::path::Path::new(sock_path));
}

/// Entry point for the re-exec'd filtering proxy (`kern __egress-proxy <sock_path> <allow-csv>`). Binds
/// the UNIX socket and runs the proxy loop with a fresh libc (so `getaddrinfo` works). Never returns.
pub fn proxy_reexec(sock_path: &str, allow_csv: &str) -> ! {
    drop_signals();
    let _ = std::fs::remove_file(sock_path);
    let listener = match UnixListener::bind(sock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kern: egress proxy: cannot bind {sock_path}: {e}");
            unsafe { libc::_exit(1) };
        }
    };
    // Owner-only (0600): the socket already lives in $XDG_RUNTIME_DIR (0700, per-user), so this is
    // belt-and-suspenders against another same-user process opening the proxy. Connect permission on a
    // UNIX socket is governed by the socket file's mode.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600));
    }
    let allow: Vec<String> = allow_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    proxy_main(listener, allow);
}

fn drop_signals() {
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
}

/// The filtering proxy: accept a UNIX connection (relayed from the box by the pump), read the request
/// head, decide via `host_allowed`, and either dial the target and pump bytes, or refuse.
fn proxy_main(listener: UnixListener, allow: Vec<String>) -> ! {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let allow = allow.clone();
        // one child per connection (cheap; keeps a slow/hostile client from blocking others)
        let c = unsafe { libc::fork() };
        if c == 0 {
            drop_signals();
            handle_client(stream, &allow);
            unsafe { libc::_exit(0) };
        }
    }
    unsafe { libc::_exit(0) }
}

fn handle_client(mut client: UnixStream, allow: &[String]) {
    // Read the request head (up to the blank line), bounded so a client can't make us buffer forever.
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while head.len() < 16 * 1024 {
        match client.read(&mut byte) {
            Ok(0) => return,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("");

    if request_line
        .split_whitespace()
        .next()
        .map(|m| m.eq_ignore_ascii_case("CONNECT"))
        == Some(true)
    {
        // HTTPS tunnel: CONNECT host:port
        let Some(host) = parse_connect_host(request_line) else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
        };
        let port = connect_port(request_line).unwrap_or(443);
        if !host_allowed(&host, allow) || !port_allowed(port) {
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return;
        }
        let upstream = match connect_vetted(&host, port) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("kern: egress proxy: CONNECT upstream {host}:{port} refused/failed: {e}");
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                return;
            }
        };
        let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
        pump_streams(client, upstream);
    } else {
        // Plain HTTP: forward the whole head we read, then splice.
        let headers = &text[request_line.len()..];
        let Some(host) = parse_http_host(request_line, headers) else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
        };
        if !host_allowed(&host, allow) {
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return;
        }
        let mut upstream = match connect_vetted(&host, 80) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("kern: egress proxy: HTTP upstream {host}:80 refused/failed: {e}");
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                return;
            }
        };
        if upstream.write_all(&head).is_err() {
            return;
        }
        pump_streams(client, upstream);
    }
}

/// The port from a `CONNECT host:port` line (default 443 handled by the caller).
fn connect_port(request_line: &str) -> Option<u16> {
    let target = request_line.split_whitespace().nth(1)?;
    let after = if target.starts_with('[') {
        target.split(']').nth(1)?.strip_prefix(':')?
    } else {
        target.rsplit_once(':')?.1
    };
    after.trim().parse().ok()
}

/// The box-netns pump: join the box's user+net ns, listen on `127.0.0.1:box_port` inside the box, and
/// relay every accepted connection to the host-side UNIX socket where the proxy listens.
fn pump_main(box_pid1: i32, box_port: u16, sock_path: &std::path::Path) -> ! {
    if !enter_box_ns(box_pid1) {
        eprintln!(
            "kern: egress pump: cannot join box netns: {}",
            std::io::Error::last_os_error()
        );
        unsafe { libc::_exit(1) };
    }
    let listener = match std::net::TcpListener::bind(("127.0.0.1", box_port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("kern: egress pump: cannot bind 127.0.0.1:{box_port} in box: {e}");
            unsafe { libc::_exit(1) };
        }
    };
    for conn in listener.incoming() {
        let Ok(client) = conn else { continue };
        let sp = sock_path.to_path_buf();
        let c = unsafe { libc::fork() };
        if c == 0 {
            drop_signals();
            // The unix socket lives in the HOST filesystem, which this process still sees (we joined
            // only user+net, not the mount ns), so this connect bridges the box netns to the host proxy.
            if let Ok(up) = UnixStream::connect(&sp) {
                pump_streams(client, up);
            }
            unsafe { libc::_exit(0) };
        }
    }
    unsafe { libc::_exit(0) }
}

/// Join the box's NETWORK namespace (and, when needed, its USER namespace first), but NEVER its PID
/// namespace. The pump binds a high port (`127.0.0.1:3128`, no capability) and connects to a host UNIX
/// socket (unix sockets aren't net-namespaced, and the pump stays in the host MOUNT ns so the socket path
/// is still reachable).
///
/// `setns(CLONE_NEWNET)` requires CAP_SYS_ADMIN over the user ns that OWNS the target net ns. In a
/// ROOTLESS box_run that capability does not exist in the host user ns, so the direct join is denied
/// (`EPERM`); we must first enter the box's USER ns, where box-root holds CAP_SYS_ADMIN over its own net
/// ns. `setns(CLONE_NEWUSER)` needs a SINGLE-THREADED caller (`EINVAL` otherwise) which is exactly why
/// the pump is a fresh re-exec and does this before spawning any relay threads. Entering the user ns does
/// NOT put the pump in the box PID ns, so it cannot become the zombie that would deadlock pidns teardown.
/// The fast direct path is kept for the privileged case (real root / `--privileged`).
fn enter_box_ns(box_pid1: i32) -> bool {
    let open_ns = |kind: &str| -> i32 {
        let p = format!("/proc/{box_pid1}/ns/{kind}\0");
        unsafe {
            libc::open(
                p.as_ptr() as *const libc::c_char,
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        }
    };
    unsafe {
        let net = open_ns("net");
        if net < 0 {
            return false;
        }
        // Fast path: already privileged over the box net ns.
        if libc::setns(net, libc::CLONE_NEWNET) == 0 {
            libc::close(net);
            return true;
        }
        // Rootless: enter the box USER ns first (single-threaded re-exec, so CLONE_NEWUSER is allowed),
        // then the net ns with the pre-opened fd. Never the PID ns.
        let user = open_ns("user");
        if user < 0 {
            libc::close(net);
            return false;
        }
        let ok = libc::setns(user, libc::CLONE_NEWUSER) == 0
            && libc::setns(net, libc::CLONE_NEWNET) == 0;
        libc::close(user);
        libc::close(net);
        ok
    }
}

/// Splice two streams bidirectionally until both close. Two threads, one per direction; each half-closes
/// its write side on EOF so the peer learns the direction ended.
fn pump_streams<A, B>(a: A, b: B)
where
    A: Read + Write + TryCloneStream + Send + 'static,
    B: Read + Write + TryCloneStream + Send + 'static,
{
    let (Ok(mut a_r), Ok(mut a_w)) = (a.try_clone_stream(), a.try_clone_stream()) else {
        return;
    };
    let (Ok(mut b_r), Ok(mut b_w)) = (b.try_clone_stream(), b.try_clone_stream()) else {
        return;
    };
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_r, &mut b_w);
        b_w.shutdown_write();
    });
    let _ = std::io::copy(&mut b_r, &mut a_w);
    a_w.shutdown_write();
    let _ = t.join();
}

/// A stream we can clone (for the two-direction pump) and half-close.
pub trait TryCloneStream: Sized {
    fn try_clone_stream(&self) -> std::io::Result<Self>;
    fn shutdown_write(&self);
}
impl TryCloneStream for std::net::TcpStream {
    fn try_clone_stream(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
    fn shutdown_write(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}
impl TryCloneStream for UnixStream {
    fn try_clone_stream(&self) -> std::io::Result<Self> {
        self.try_clone()
    }
    fn shutdown_write(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn host_allowed_exact_and_subdomain_only() {
        let a = allow(&["pypi.org", "files.pythonhosted.org"]);
        assert!(host_allowed("pypi.org", &a)); // exact
        assert!(host_allowed("files.pypi.org", &a)); // subdomain
        assert!(host_allowed("a.b.pypi.org", &a)); // deep subdomain
        assert!(host_allowed("PyPI.ORG", &a)); // case-insensitive
        assert!(host_allowed("pypi.org.", &a)); // trailing dot
        assert!(host_allowed("files.pythonhosted.org", &a));
    }

    #[test]
    fn host_allowed_rejects_lookalikes_and_suffix_tricks() {
        let a = allow(&["pypi.org"]);
        assert!(!host_allowed("evilpypi.org", &a)); // no boundary dot
        assert!(!host_allowed("pypi.org.evil.com", &a)); // suffix attack
        assert!(!host_allowed("notpypi.org", &a));
        assert!(!host_allowed("pypi.org.evil", &a));
        assert!(!host_allowed("xpypi.org", &a));
        assert!(!host_allowed("", &a));
        assert!(!host_allowed("1.2.3.4", &a)); // an IP literal never matches a domain
        assert!(!host_allowed("org", &a)); // parent of the entry is NOT allowed
    }

    #[test]
    fn empty_or_dotted_allowlist_entries_never_match() {
        assert!(!host_allowed("pypi.org", &allow(&[""])));
        assert!(!host_allowed("pypi.org", &allow(&["."])));
        assert!(!host_allowed("anything.com", &allow(&[])));
    }

    #[test]
    fn parse_connect_host_and_port() {
        assert_eq!(
            parse_connect_host("CONNECT pypi.org:443 HTTP/1.1"),
            Some("pypi.org".into())
        );
        assert_eq!(connect_port("CONNECT pypi.org:443 HTTP/1.1"), Some(443));
        assert_eq!(
            parse_connect_host("CONNECT evil.com:8080 HTTP/1.1"),
            Some("evil.com".into())
        );
        assert_eq!(connect_port("CONNECT evil.com:8080 HTTP/1.1"), Some(8080));
        // IPv6 literal is bracket-stripped so it can't masquerade as a domain.
        assert_eq!(
            parse_connect_host("CONNECT [2606:4700::1]:443 HTTP/1.1"),
            Some("2606:4700::1".into())
        );
        assert_eq!(parse_connect_host("GET / HTTP/1.1"), None);
        assert_eq!(parse_connect_host("CONNECT"), None);
    }

    #[test]
    fn ssrf_guard_rejects_host_local_ips() {
        use std::net::IpAddr;
        let bad = [
            "127.0.0.1",
            "127.5.5.5",
            "169.254.169.254", // cloud metadata
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1", // multicast
            "::1",
            "fe80::1",  // link-local
            "fc00::1",  // ULA
            "fd12::34", // ULA
        ];
        for s in bad {
            assert!(!ip_is_public(s.parse::<IpAddr>().unwrap()), "{s} must be refused");
        }
        for s in ["1.1.1.1", "8.8.8.8", "93.184.215.14", "2606:4700:4700::1111"] {
            assert!(ip_is_public(s.parse::<IpAddr>().unwrap()), "{s} must be allowed");
        }
    }

    #[test]
    fn only_http_https_ports_tunnel() {
        assert!(port_allowed(443));
        assert!(port_allowed(80));
        for p in [22u16, 25, 6379, 3306, 8080, 0, 1] {
            assert!(!port_allowed(p), "port {p} must be refused");
        }
    }

    #[test]
    fn parse_http_host_absolute_uri_then_header() {
        assert_eq!(
            parse_http_host("GET http://pypi.org/simple/ HTTP/1.1", ""),
            Some("pypi.org".into())
        );
        assert_eq!(
            parse_http_host("GET http://pypi.org:8080/x HTTP/1.1", ""),
            Some("pypi.org".into())
        );
        // origin-form request → fall back to the Host header
        assert_eq!(
            parse_http_host("GET /simple/ HTTP/1.1", "Host: files.pypi.org\r\n"),
            Some("files.pypi.org".into())
        );
        assert_eq!(parse_http_host("GET /x HTTP/1.1", "X-Foo: bar\r\n"), None);
    }
}
