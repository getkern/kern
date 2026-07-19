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
use std::os::unix::net::{UnixListener, UnixStream};

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

// -- the running filter (socket plumbing) --------------------------------------------------------

/// A live egress filter: the filtering-proxy child (a clean re-exec), the box-netns pump pid, and the
/// box-side proxy port advertised in `HTTP_PROXY`. Dropping it kills both helpers and removes the socket.
pub struct EgressFilter {
    proxy: std::process::Child,
    pump_pid: i32,
    sock_path: std::path::PathBuf,
}

impl Drop for EgressFilter {
    fn drop(&mut self) {
        let _ = self.proxy.kill();
        let _ = self.proxy.wait();
        if self.pump_pid > 0 {
            unsafe { libc::kill(self.pump_pid, libc::SIGKILL) };
        }
        let _ = std::fs::remove_file(&self.sock_path);
    }
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
    let proxy = std::process::Command::new(exe)
        .arg("__egress-proxy")
        .arg(&sock_path)
        .arg(allow.join(","))
        .spawn()
        .map_err(|e| format!("egress: spawn proxy: {e}"))?;
    // Wait briefly for the proxy to bind, so the box's first request doesn't race it.
    for _ in 0..200 {
        if sock_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok((proxy, sock_path))
}

/// Attach the box-netns pump to an already-spawned proxy, completing the filter. The pump is a plain
/// fork joined to the box's NET namespace (it does no name resolution, so a fork is safe): it listens on
/// `127.0.0.1:box_port` inside the box and relays each connection to the proxy's UNIX socket.
pub fn attach_pump(
    proxy: std::process::Child,
    sock_path: std::path::PathBuf,
    box_pid1: i32,
    box_port: u16,
) -> Result<EgressFilter, String> {
    let sp = sock_path.clone();
    let pump_pid = unsafe { libc::fork() };
    if pump_pid == 0 {
        drop_signals();
        pump_main(box_pid1, box_port, &sp); // diverges (-> !)
    }
    if pump_pid < 0 {
        return Err("could not fork egress pump".into());
    }
    Ok(EgressFilter {
        proxy,
        pump_pid,
        sock_path,
    })
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
        if !host_allowed(&host, allow) {
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return;
        }
        let upstream = match std::net::TcpStream::connect((host.as_str(), port)) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("kern: egress proxy: CONNECT upstream {host}:{port} failed: {e}");
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
        let mut upstream = match std::net::TcpStream::connect((host.as_str(), 80)) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("kern: egress proxy: HTTP upstream {host}:80 failed: {e}");
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
    // CRITICAL: this is a plain fork of the (foreground) box_run process, so it inherited every open fd,
    // including the box's stdout/stderr CAPTURE PIPES. Held open in the accept loop below they would keep
    // those pipes from ever reaching EOF, so the launcher waiting on the box's output hangs until the
    // --timeout backstop fires (a box running `true` would appear to hang for the whole timeout). Close
    // every inherited fd >= 3 first; the pump opens everything it needs (the netns handle, the listener,
    // the unix socket) fresh below.
    kern_isolation::shed_inherited_fds(-1);
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

/// Join the box's NETWORK namespace only. Unlike `kern exec`, the pump does not need to become
/// box-root: it binds a high port (`127.0.0.1:3128`, no capability needed) and connects to a host UNIX
/// socket (not namespaced). We are in the box user ns's PARENT (the host), which holds CAP_SYS_ADMIN
/// over the child net ns, so `setns(CLONE_NEWNET)` is permitted without first entering the user ns,
/// and we AVOID `setns(CLONE_NEWUSER)`, which requires a single-threaded caller (EINVAL otherwise).
fn enter_box_ns(box_pid1: i32) -> bool {
    let path = format!("/proc/{box_pid1}/ns/net\0");
    unsafe {
        let net = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDONLY | libc::O_CLOEXEC,
        );
        if net < 0 {
            return false;
        }
        let ok = libc::setns(net, libc::CLONE_NEWNET) == 0;
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
