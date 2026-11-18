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
//! at 80 or below), else 8080 or the next free one; `[kern] local_domains_port` fixes it. kern has no
//! daemon, and this is not one: `compose up` starts it when a service publishes a port, and it leaves
//! by itself a minute after the last box with a published port is gone. HTTP only: HTTPS would need
//! a TLS stack in kern and a certificate authority in the user's trust store.

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

/// The port of the router running now, if one is.
pub fn running_port() -> Option<u16> {
    let text = std::fs::read_to_string(state_path().ok()?).ok()?;
    let mut f = text.split_whitespace();
    let pid: i32 = f.next()?.parse().ok()?;
    let start: u64 = f.next()?.parse().ok()?;
    let port: u16 = f.next()?.parse().ok()?;
    (pid > 0 && start != 0 && crate::registry::proc_starttime(pid) == start).then_some(port)
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
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__local-router")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: `setsid` is async-signal-safe; the router must not share the terminal's session.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().ok()?;
    // The router writes its state once it listens; it may also find another one already running
    // and leave, which is fine: that one's state answers.
    for _ in 0..200 {
        if let Some(p) = running_port() {
            return Some(p);
        }
        if let Ok(Some(_)) = child.try_wait() {
            return running_port();
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    None
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
    v.extend(8080..8090);
    v
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
    let mut bound: Option<(u16, Vec<TcpListener>)> = None;
    for port in candidate_ports() {
        let v4 = TcpListener::bind(("127.0.0.1", port));
        let v6 = TcpListener::bind(("::1", port));
        let mut ls = Vec::new();
        if let Ok(l) = v4 {
            ls.push(l);
        }
        if let Ok(l) = v6 {
            ls.push(l);
        }
        if !ls.is_empty() {
            bound = Some((port, ls));
            break;
        }
    }
    let Some((port, listeners)) = bound else {
        std::process::exit(1);
    };
    // SAFETY: getpid takes no arguments.
    let me = unsafe { libc::getpid() };
    if let Ok(p) = state_path() {
        let tmp = p.with_extension("tmp");
        let line = format!("{me} {} {port}\n", crate::registry::proc_starttime(me));
        if std::fs::write(&tmp, line).is_ok() {
            let _ = std::fs::rename(&tmp, &p);
        }
    }
    for l in listeners {
        std::thread::spawn(move || {
            for conn in l.incoming().flatten() {
                std::thread::spawn(move || serve(conn));
            }
        });
    }
    // LEAVE WHEN NOTHING IS LEFT TO ROUTE TO: two checks a minute apart that find no box publishing
    // a port.
    let mut idle = 0;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let any = crate::registry::list()
            .iter()
            .any(|b| has_tcp_port(&b.ports));
        idle = if any { 0 } else { idle + 1 };
        if idle >= 2 {
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
    let ok_label = |l: &str| {
        !l.is_empty()
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if !ok_label(service) || !ok_label(project) {
        return Err((404, format!("{h}: not a service name")));
    }
    let candidates = [
        format!("{project}-{service}-1"),
        format!("{project}-{service}"),
    ];
    let mut found = candidates.iter().find_map(|n| crate::registry::find(n));
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

fn answer(c: &mut TcpStream, status: u16, msg: &str) {
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
}

/// One client connection: read the head, route by `Host`, forward the head and splice.
fn serve(mut c: TcpStream) {
    let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        // A head that ends in a bare `\n\n` is complete for some servers and never for this reader:
        // it is ended here so the refusal below answers at once instead of after the read timeout.
        if let Some(i) = buf.windows(2).position(|w| w == b"\n\n") {
            break i + 2;
        }
        if buf.len() > 16 * 1024 {
            answer(&mut c, 400, "request head too large");
            return;
        }
        match c.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = &buf[..head_end];
    // A BARE LF IS REFUSED, as the egress proxy refuses it: a head this reader and the service split
    // differently is how a second request is smuggled past the routing decision.
    if crate::egress::has_bare_lf(head) {
        answer(&mut c, 400, "a request line or header ends in a bare LF");
        return;
    }
    let text = String::from_utf8_lossy(head);
    let hosts: Vec<&str> = text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("host").then_some(v.trim())
        })
        .collect();
    let [host] = hosts.as_slice() else {
        answer(&mut c, 400, "a request must name exactly one Host");
        return;
    };
    let (addr, port) = match route(host) {
        Ok(t) => t,
        Err((status, msg)) => {
            answer(&mut c, status, &msg);
            return;
        }
    };
    let Ok(mut up) = TcpStream::connect((addr.as_str(), port)) else {
        answer(
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
        assert_eq!(url("web", "shop", 8080), "http://web.shop.localhost:8080/");
    }
}
