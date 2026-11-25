//! `<service>.<project>.localhost`: a name for each compose service's published port, on this machine.
//!
//! WHY `.localhost` AND NOT `.local`. `.local` is mDNS (Bonjour/Avahi): resolving it needs a daemon,
//! and publishing a name there announces it to the whole local network. `.localhost` is reserved for
//! the machine itself (RFC 6761): Chrome, Firefox, curl and systemd-resolved already answer it with
//! the loopback address, with nothing to configure and no root. MEASURED here: `getent hosts
//! web.kl.localhost` answered `::1` on a stock Ubuntu.
//!
//! THE ROUTER. A name only gets a request to the loopback address; which service it meant is in the
//! request's `Host`. One small HTTP router per user, listening on the loopback addresses only, reads
//! that header and forwards the connection to the port the service published:
//!
//! * `<service>.<project>.localhost`: the service's box `<project>-<service>-1`; `<service>-<n>`
//!   is replica n;
//! * `<port>.<service>.<project>.localhost`: the published port of that container port;
//! * `<service>.kern.localhost`: the one running project that has that service (several: refused
//!   with the exact names).
//!
//! It reaches only ports this user's boxes published on the host, so it opens nothing that was not
//! open. Port 80 when the system lets an ordinary user bind it (`net.ipv4.ip_unprivileged_port_start`
//! at 80 or below), else 8780 or the next free one; `[kern] local_domains_port` fixes it. NOT 8080:
//! MEASURED on 2026-11-20, a router on 8080 refused a second project publishing 8080 ("held by kern"),
//! and 8080 is the port the most apps publish (Airflow, Jenkins, Keycloak). kern has no
//! daemon, and this is not one: `compose up` starts it when a service publishes a port, and it leaves
//! by itself about 3 s after the last box with a published port is gone. HTTPS too, after
//! `kern proxy trust` and only then: see `localtls`, which ends the TLS and hands the request to this
//! same router, on 443 where an ordinary user may bind it and 8443 (or the next free port) elsewhere.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

/// The state a running router publishes: `<pid> <starttime> <port>`.
fn state_path() -> std::io::Result<PathBuf> {
    Ok(crate::registry::runtime_subdir("router")?.join("state"))
}

fn lock_path() -> std::io::Result<PathBuf> {
    Ok(crate::registry::runtime_subdir("router")?.join("lock"))
}

/// The router running now: `(pid, plain port, HTTPS port)`, the last `None` when it does not answer
/// HTTPS. A state whose process is gone, or another process under that pid, is no router.
fn running() -> Option<(i32, u16, Option<u16>)> {
    let text = std::fs::read_to_string(state_path().ok()?).ok()?;
    let mut f = text.split_whitespace();
    let pid: i32 = f.next()?.parse().ok()?;
    let start: u64 = f.next()?.parse().ok()?;
    let port: u16 = f.next()?.parse().ok()?;
    // The fourth field arrived with HTTPS; a state written before it has none.
    let tls = f
        .next()
        .and_then(|t| t.parse::<u16>().ok())
        .filter(|t| *t != 0);
    (pid > 0 && start != 0 && crate::registry::proc_starttime(pid) == start)
        .then_some((pid, port, tls))
}

/// The port of the router running now, if one is.
pub fn running_port() -> Option<u16> {
    running().map(|(_, port, _)| port)
}

/// The HTTPS port of the router running now, when it answers HTTPS (`kern proxy trust`).
pub fn running_tls_port() -> Option<u16> {
    running().and_then(|(_, _, tls)| tls)
}

/// Stop the router running now and start a new one when a box still publishes a port, so a change
/// of `kern proxy trust` takes effect at once. A connection open now is cut; the next one is answered.
pub fn restart() {
    if let Some((pid, _, _)) = running() {
        // SAFETY: a pid whose start time `running` has just checked against the recorded one.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        for _ in 0..50 {
            if crate::registry::proc_starttime(pid) == 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    if crate::registry::list()
        .iter()
        .any(|b| has_tcp_port(&b.ports))
    {
        let _ = ensure();
    }
}

/// Whether `[kern] local_domains` is on (the default).
pub fn enabled() -> bool {
    crate::config::load(None)
        .ok()
        .and_then(|c| c.kern.local_domains)
        .unwrap_or(true)
}

/// Start the router unless one runs, and return its port. `None` when it could not start (said on
/// stderr by the caller) or is turned off.
pub fn ensure() -> Option<u16> {
    if !enabled() {
        return None;
    }
    if let Some(p) = running_port() {
        return Some(p);
    }
    let exe = std::env::current_exe().ok()?;
    // IN A CGROUP OF ITS OWN, NOT THE CALLER'S. Started as a child of `compose up` it landed in the
    // cgroup of whoever ran that, a terminal's scope for instance, and closing the terminal could end
    // it. Through the user manager it gets its own transient scope, the way kern's own unit does;
    // without one (WSL without systemd, CI) it starts as a plain child, in its own session.
    if kern_isolation::user_systemd_present() {
        if let Some(p) = spawn_router(&exe, true) {
            return Some(p);
        }
    }
    spawn_router(&exe, false)
}

/// Start `kern __local-router` and wait for it to publish its port. `scoped`: through
/// `systemd-run --scope`, which becomes the router itself once the scope exists.
fn spawn_router(exe: &std::path::Path, scoped: bool) -> Option<u16> {
    let mut cmd = if scoped {
        let sr = kern_isolation::trusted_helper("systemd-run")
            .unwrap_or_else(|| std::path::PathBuf::from("systemd-run"));
        let mut c = std::process::Command::new(sr);
        c.envs(kern_isolation::manager_envs())
            .args([
                kern_isolation::systemd_scope_mode(),
                "--scope",
                "--quiet",
                "--collect",
            ])
            .args(kern_isolation::manager_setenv_args())
            .arg("--")
            .arg(exe)
            .arg("__local-router");
        c
    } else {
        let mut c = std::process::Command::new(exe);
        c.arg("__local-router");
        c
    };
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: `setsid` is async-signal-safe; the router must not share the terminal's session.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
            libc::setsid();
            Ok(())
        });
    }
    // READY IS SAID, NOT POLLED FOR. The router writes one byte on this pipe once its state names
    // the port (`READY_FD`); a router that finds another one running leaves, which closes the pipe,
    // and that one's state answers. This used to read the state file every 10 ms for up to 3 s, so
    // `kern box -d -p` and `compose up` paid up to 10 ms of polling granularity on a cold router.
    let mut fds = [0i32; 2];
    // SAFETY: pipe2 writes two descriptors into `fds`.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);
    cmd.env(READY_FD, wr.to_string());
    // SAFETY: `fcntl` is async-signal-safe; it lets the write end, and only it, cross the exec.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, move || {
            libc::fcntl(wr, libc::F_SETFD, 0);
            Ok(())
        });
    }
    let spawned = cmd.spawn();
    // SAFETY: the parent's copy of the write end; the router holds its own.
    unsafe { libc::close(wr) };
    let Ok(_router) = spawned else {
        unsafe { libc::close(rd) };
        return None;
    };
    let mut pfd = libc::pollfd {
        fd: rd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one pollfd owned here; 3 s, the bound the polling loop had.
    let _ = unsafe { libc::poll(&mut pfd, 1, 3000) };
    unsafe { libc::close(rd) };
    running_port()
}

/// The variable naming the descriptor a starting router says "listening" on.
const READY_FD: &str = "KERN_ROUTER_READY_FD";

/// `kern __router-port` (hidden): the port the names answer on, for `kern.exe doctor`, which checks
/// it from the Windows side (a port Windows reserves, or one a Windows program holds, breaks the
/// names from Windows while everything works inside the distro). One line: `<port> running` for the
/// router running now, `<port> idle` for the port it would take now, `off` when the names are off.
pub fn port_verb() -> i32 {
    if !enabled() {
        println!("off");
        return 0;
    }
    if let Some(p) = running_port() {
        println!("{p} running");
        return 0;
    }
    match candidate_ports()
        .into_iter()
        .find(|p| TcpListener::bind(("127.0.0.1", *p)).is_ok())
    {
        Some(p) => {
            println!("{p} idle");
            0
        }
        None => {
            println!("none");
            1
        }
    }
}

/// The ports to try, in order.
fn candidate_ports() -> Vec<u16> {
    if let Some(p) = crate::config::load(None)
        .ok()
        .and_then(|c| c.kern.local_domains_port)
    {
        return vec![p];
    }
    let unprivileged = std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(1024);
    let mut v = Vec::new();
    if unprivileged <= 80 {
        v.push(80);
    }
    v.extend(8780..8790);
    v
}

/// The HTTPS ports to try, in order: 443 where an ordinary user may bind it, then 8443 to 8452.
fn tls_candidate_ports() -> Vec<u16> {
    let unprivileged = std::fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(1024);
    let mut v = Vec::new();
    if unprivileged <= 443 {
        v.push(443);
    }
    v.extend(8443..8453);
    v
}

/// Bind `127.0.0.1` and `::1` on the first of `ports` either answers: `(port, listeners)`.
fn bind_loopback(ports: &[u16]) -> Option<(u16, Vec<TcpListener>)> {
    for &port in ports {
        let mut ls = Vec::new();
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            ls.push(l);
        }
        if let Ok(l) = TcpListener::bind(("::1", port)) {
            ls.push(l);
        }
        if !ls.is_empty() {
            return Some((port, ls));
        }
    }
    None
}

/// `kern __local-router`: serve until no box publishes a port. Never returns.
pub fn run() -> ! {
    use std::os::unix::fs::OpenOptionsExt;
    // ONE PER USER: the lock is held for the router's life; a second one leaves at once.
    let Ok(lock) = lock_path().and_then(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(p)
    }) else {
        std::process::exit(1);
    };
    // SAFETY: flock on a descriptor we own.
    if unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(&lock),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    } != 0
    {
        std::process::exit(0);
    }
    let Some((port, listeners)) = bind_loopback(&candidate_ports()) else {
        std::process::exit(1);
    };
    // HTTPS ONLY AFTER `kern proxy trust`: without it there is no authority, and no port is opened.
    let tls = crate::localtls::server_config()
        .and_then(|config| bind_loopback(&tls_candidate_ports()).map(|b| (config, b)));
    let tls_port = tls.as_ref().map_or(0, |(_, (p, _))| *p);
    // SAFETY: getpid takes no arguments.
    let me = unsafe { libc::getpid() };
    if let Ok(p) = state_path() {
        let tmp = p.with_extension("tmp");
        let line = format!(
            "{me} {} {port} {tls_port}\n",
            crate::registry::proc_starttime(me)
        );
        if std::fs::write(&tmp, line).is_ok() {
            let _ = std::fs::rename(&tmp, &p);
        }
    }
    // Tell whoever started this that the state names the port (see `spawn_router`).
    if let Some(fd) = crate::global_env(READY_FD)
        .and_then(|v| v.into_string().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|fd| *fd > 2)
    {
        // SAFETY: one byte from a local on the descriptor the starter handed over; closed after.
        unsafe {
            libc::write(fd, b"R".as_ptr().cast(), 1);
            libc::close(fd);
        }
    }
    for l in listeners {
        std::thread::spawn(move || {
            for conn in l.incoming().flatten() {
                std::thread::spawn(move || serve(conn));
            }
        });
    }
    if let Some((config, (_, tls_listeners))) = tls {
        for l in tls_listeners {
            let config = std::sync::Arc::clone(&config);
            std::thread::spawn(move || {
                for conn in l.incoming().flatten() {
                    let config = std::sync::Arc::clone(&config);
                    std::thread::spawn(move || crate::localtls::serve(conn, config, port));
                }
            });
        }
    }
    // IT LIVES AS LONG AS THERE IS A NAME TO SERVE: any box of this user with a published TCP port,
    // from compose or `kern box -p`. Checked every second; with none for three checks in a row it
    // leaves, so a service restarting does not take the router with it and a `down` does not leave
    // it running for a minute.
    let mut idle = 0;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let any = crate::registry::list()
            .iter()
            .any(|b| has_tcp_port(&b.ports));
        idle = if any { 0 } else { idle + 1 };
        if idle >= 3 {
            if let Ok(p) = state_path() {
                let _ = std::fs::remove_file(p);
            }
            std::process::exit(0);
        }
    }
}

/// Whether a registry `ports` string publishes at least one TCP port.
pub fn has_tcp_port(ports: &str) -> bool {
    !mappings(ports).is_empty()
}

/// One published mapping of a box: `(address, host port, container port)`, TCP only.
fn mappings(ports: &str) -> Vec<(String, u16, u16)> {
    ports
        .split(',')
        .filter_map(|m| {
            let m = m.trim();
            if m.ends_with("/udp") {
                return None;
            }
            let m = m.trim_end_matches("/tcp");
            let (left, cport) = m.split_once("->")?;
            let (addr, hport) = left.rsplit_once(':')?;
            Some((addr.to_string(), hport.parse().ok()?, cport.parse().ok()?))
        })
        .collect()
}

/// Where a request for `host` goes: the loopback address and port, or the status and sentence that
/// answer instead.
fn route(host: &str) -> Result<(String, u16), (u16, String)> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let h = match h.rsplit_once(':') {
        Some((name, p)) if p.bytes().all(|b| b.is_ascii_digit()) => name.to_string(),
        _ => h,
    };
    let Some(front) = h.strip_suffix(".localhost") else {
        return Err((
            404,
            format!("{h} is not a <service>.<project>.localhost name"),
        ));
    };
    let labels: Vec<&str> = front.split('.').collect();
    let (want_port, service, project) = match labels.as_slice() {
        [s, p] => (None, *s, *p),
        [port, s, p] => match port.parse::<u16>() {
            Ok(n) => (Some(n), *s, *p),
            Err(_) => {
                return Err((
                    404,
                    format!("{h}: expected [<port>.]<service>.<project>.localhost"),
                ))
            }
        },
        _ => {
            return Err((
                404,
                format!("{h}: expected [<port>.]<service>.<project>.localhost"),
            ))
        }
    };
    if !label_ok(service) || !label_ok(project) {
        return Err((404, format!("{h}: not a service name")));
    }
    let candidates = [
        format!("{project}-{service}-1"),
        format!("{project}-{service}"),
    ];
    let mut found = candidates.iter().find_map(|n| crate::registry::find(n));
    // `<box>.kern.localhost`: a box started on its own (`kern box web -d -p ...`) is named as it is.
    if found.is_none() && project == "kern" {
        found = crate::registry::find(service).filter(|b| has_tcp_port(&b.ports));
    }
    if found.is_none() && project == "kern" {
        let suffix = format!("-{service}-1");
        let all: Vec<_> = crate::registry::list()
            .into_iter()
            .filter(|b| b.name.ends_with(&suffix) && !b.ports.is_empty())
            .collect();
        match all.len() {
            0 => {}
            1 => found = all.into_iter().next(),
            _ => {
                let names: Vec<String> = all
                    .iter()
                    .filter_map(|b| {
                        b.name
                            .strip_suffix(&suffix)
                            .map(|p| format!("{service}.{p}.localhost"))
                    })
                    .collect();
                return Err((
                    409,
                    format!(
                        "several running projects have a service '{service}': {}",
                        names.join(", ")
                    ),
                ));
            }
        }
    }
    let Some(b) = found else {
        return Err((404, format!("no running service '{service}' in a project '{project}' (kern compose ps lists them)")));
    };
    let maps = mappings(&b.ports);
    if maps.is_empty() {
        return Err((502, format!("service '{service}' publishes no TCP port: add one, e.g. ports: [\"127.0.0.1::80\"]")));
    }
    let pick = match want_port {
        Some(c) => maps.iter().find(|m| m.2 == c),
        None => [80u16, 8080, 3000, 8000, 5000]
            .iter()
            .find_map(|c| maps.iter().find(|m| m.2 == *c))
            .or_else(|| maps.first()),
    };
    let Some((addr, hport, _)) = pick else {
        return Err((
            502,
            format!(
                "service '{service}' publishes no container port {}",
                want_port.unwrap_or(0)
            ),
        ));
    };
    // A WILDCARD bind answers on loopback too; a specific address answers only there.
    let target = match addr.trim_start_matches('[').trim_end_matches(']') {
        "" | "0.0.0.0" => "127.0.0.1".to_string(),
        "::" => "::1".to_string(),
        a => a.to_string(),
    };
    Ok((target, *hport))
}

/// Answer with `status` and END THE CONNECTION, whatever else the client sent.
///
/// A REFUSED REQUEST GETS NOTHING AFTER IT. A client may pipeline a second request behind the
/// first; once the first is refused (no such name, a head this reader will not split), not one
/// byte that follows may reach a service. So: the answer, the write side shut, whatever the client
/// already sent read and dropped (closing with unread data would reset the connection and could
/// destroy the answer before the client reads it), then the socket closed.
fn refuse(c: &mut TcpStream, status: u16, msg: &str) {
    let reason = match status {
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Bad Gateway",
    };
    let body = format!("kern: {msg}\n");
    let _ = write!(
        c,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = c.flush();
    let _ = c.shutdown(std::net::Shutdown::Write);
    let _ = c.set_read_timeout(Some(std::time::Duration::from_millis(500)));
    let mut sink = [0u8; 4096];
    let mut drained = 0usize;
    while drained < 64 * 1024 {
        match c.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

/// One client connection: read the head, check its framing and its one host (the same reader the
/// egress proxy uses, `kern_common::httphead`), route by that host, forward the head and splice.
///
/// ONLY THE FIRST REQUEST IS ROUTED: what follows on a kept-alive connection goes to the same
/// service. A browser keeps one HTTP/1.1 connection per origin, so a page cannot steer a second
/// request on it to another name; routing each request is the HTTPS terminator's job (HTTP/2 does
/// share connections across names).
fn serve(mut c: TcpStream) {
    use kern_common::httphead;
    let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = httphead::head_end(&buf) {
            break i;
        }
        if buf.len() > 16 * 1024 {
            refuse(&mut c, 400, "request head too large");
            return;
        }
        match c.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = &buf[..end];
    // A HEAD THIS READER AND THE SERVICE COULD SPLIT DIFFERENTLY is refused, as the egress proxy
    // refuses it: that disagreement is how a second request is smuggled past the routing decision.
    if let Err(r) = httphead::framing(head) {
        refuse(&mut c, 400, r.reason());
        return;
    }
    let text = String::from_utf8_lossy(head);
    let (request_line, headers) = httphead::split_head(&text);
    let host = match httphead::the_host(request_line, headers) {
        Ok(h) => h,
        Err(r) => {
            refuse(&mut c, 400, r.reason());
            return;
        }
    };
    let (addr, port) = match route(&host) {
        Ok(t) => t,
        Err((status, msg)) => {
            refuse(&mut c, status, &msg);
            return;
        }
    };
    let Ok(mut up) = TcpStream::connect((addr.as_str(), port)) else {
        refuse(
            &mut c,
            502,
            &format!("the service's port {port} did not answer"),
        );
        return;
    };
    let _ = c.set_read_timeout(None);
    if up.write_all(&buf).is_err() {
        return;
    }
    let (Ok(mut c2), Ok(mut up2)) = (c.try_clone(), up.try_clone()) else {
        return;
    };
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut up2);
        let _ = up2.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut up, &mut c);
    let _ = c.shutdown(std::net::Shutdown::Write);
    let _ = t.join();
}

/// The URL of a box started on its own that publishes a TCP port, `http://<box>.kern.localhost[:port]/`,
/// starting the router; `None` when it publishes none, its name is not a host-name label, the names
/// are turned off, or the router could not start.
pub fn box_url(name: &str) -> Option<String> {
    if !label_ok(name) {
        return None;
    }
    // THE CHEAP QUESTION FIRST: most boxes publish no port, and reading the config to learn whether
    // names are on cost every `kern box -d` its parse (MEASURED: +0.13 ms per detached start).
    let inst = crate::registry::find(name)?;
    if !has_tcp_port(&inst.ports) || !enabled() {
        return None;
    }
    ensure().map(|port| url_now(name, "kern", port))
}

/// The host-name label a box is reached by: in a stack (`pod` set and the box named
/// `<pod>-<service>-<n>`) the service, or `<service>-<n>` for a replica past the first; a box on its
/// own, its name. ONE DERIVATION, used by `compose up`'s lines, `kern ps` and `inspect`, so the URL
/// one prints is the URL another prints. `(label, project)`.
pub fn name_of(name: &str, pod: &str) -> (String, String) {
    let pod = pod.trim();
    match name
        .strip_prefix(&format!("{pod}-"))
        .filter(|_| !pod.is_empty())
    {
        Some(short) => (
            short.strip_suffix("-1").unwrap_or(short).to_string(),
            pod.to_string(),
        ),
        None => (name.to_string(), "kern".to_string()),
    }
}

/// The URL a running box is reached at through the router that runs now, or `None` (no published TCP
/// port, or no router running: nothing answers the name then, so nothing is printed for it).
pub fn url_of(name: &str, pod: &str, ports: &str) -> Option<String> {
    if !has_tcp_port(ports) {
        return None;
    }
    let (label, project) = name_of(name, pod);
    // Only a URL the router routes: the same label rule as `route`.
    if !label_ok(&label) || !label_ok(&project) {
        return None;
    }
    let port = running_port()?;
    Some(url_now(&label, &project, port))
}

/// The URL to print for a name now: `https://` on the router's HTTPS port when it answers HTTPS (the
/// user ran `kern proxy trust`), else `http://` on `port`. The plain URL keeps working either way.
pub fn url_now(service: &str, project: &str, port: u16) -> String {
    match running_tls_port() {
        Some(443) => format!("https://{service}.{project}.localhost/"),
        Some(tls) => format!("https://{service}.{project}.localhost:{tls}/"),
        None => url(service, project, port),
    }
}

/// A host-name label the router answers for: 1 to 63 bytes (DNS's bound) of letters, digits, `-`
/// and `_`. ONE rule for `route`, `box_url` and `url_of`, so a printed URL is one that routes.
pub(crate) fn label_ok(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && l.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The URL a service is reached at, for the lines `compose up` prints.
pub fn url(service: &str, project: &str, port: u16) -> String {
    if port == 80 {
        format!("http://{service}.{project}.localhost/")
    } else {
        format!("http://{service}.{project}.localhost:{port}/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ports_string_gives_its_tcp_mappings() {
        assert_eq!(
            mappings("127.0.0.1:48947->80, 0.0.0.0:5353->53/udp, [::1]:9000->9000/tcp"),
            vec![
                ("127.0.0.1".to_string(), 48947, 80),
                ("[::1]".to_string(), 9000, 9000)
            ]
        );
        assert!(mappings("").is_empty());
    }

    #[test]
    fn names_that_are_not_a_service_are_refused_before_any_lookup() {
        for bad in [
            "example.com",
            "web.localhost",
            "a.b.c.d.localhost",
            "w$b.p.localhost",
            "x.web.p.localhost",
        ] {
            assert!(route(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_url_drops_port_80() {
        assert_eq!(url("web", "shop", 80), "http://web.shop.localhost/");
        assert_eq!(url("web", "shop", 8780), "http://web.shop.localhost:8780/");
    }
}
