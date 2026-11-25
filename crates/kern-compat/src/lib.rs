//! `kern compat docker`: the Docker Engine API on a Unix socket, answered by kern, so a program that
//! speaks to `docker.sock` (Testcontainers, an IDE's container view, docker-py, the `docker` CLI)
//! drives kern's boxes. Linked into `kern`: `kern compat docker serve` runs it in the foreground, and
//! the `systemd --user` socket unit `kern compat docker enable` installs starts it at the first
//! connection and lets it exit when idle.
//!
//! WHAT IT IS. A translator: every request becomes a `kern` command (`box -d`, `inspect --json`,
//! `logs`, `stop`, `rm`, `pull`, `images --json`) run as this user, so every rule kern applies to a
//! box applies here too, and nothing starts a box another way. What kern refuses without a flag
//! (privileged, devices, GPUs, added capabilities) is refused here, naming the field.
//!
//! WHAT IT IS NOT. A Docker daemon: no image build, no networks, no volumes API, no Swarm.
//! An endpoint it does not translate answers 501 and says so, rather than something that looks like
//! success. It covers what Testcontainers needs (create, start, a published port, a log or exec wait,
//! stop, remove), with its reaper turned off (`TESTCONTAINERS_RYUK_DISABLED=true`): the reaper is a
//! container that mounts the socket, and a box does not get kern's control socket.
//!
//! THE SOCKET is this user's (`0600`, `$XDG_RUNTIME_DIR/kern/compat-docker.sock`), inside kern's
//! runtime root, which no box may mount; kern refuses to replace a path that is not a socket.

mod api;
mod events;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

/// The longest request head read, and the longest body.
const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 4 * 1024 * 1024;

/// One request as the API reads it.
pub(crate) struct Request {
    pub(crate) method: String,
    /// The path without the `/vX.Y` version prefix, percent-decoded per segment by the handlers.
    pub(crate) path: String,
    pub(crate) query: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    /// The client asked for the connection to be handed over (`Upgrade: tcp`), as docker clients do
    /// for an attached exec.
    pub(crate) upgrade: bool,
    /// The process on the other end of the connection, when the kernel names it.
    pub(crate) peer: Option<api::Owner>,
    /// `Connection: close`: the connection ends after the answer.
    pub(crate) close: bool,
}

impl Request {
    pub(crate) fn param(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// A boolean query parameter as Docker clients write it (`1`, `true`).
    pub(crate) fn flag(&self, key: &str) -> bool {
        matches!(self.param(key), Some("1" | "true" | "True"))
    }
}

/// `%XX` and `+` (in a query) decoded; an invalid escape is kept as written.
pub(crate) fn percent_decode(s: &str, plus_is_space: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `/v1.43/containers/json` -> `/containers/json`.
fn strip_version(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("/v") {
        if let Some(slash) = rest.find('/') {
            let ver = &rest[..slash];
            if !ver.is_empty() && ver.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
                return &rest[slash..];
            }
        }
    }
    path
}

/// What reading one request ended in.
enum Read1 {
    Request(Request),
    /// `POST /images/load`, its body left on the connection: an image archive is as large as the
    /// image, so it is streamed to `kern load` rather than read into memory under [`MAX_BODY`].
    Load(Request, Framing),
    /// The client closed between requests.
    Closed,
    /// A malformed request: answered 400, then the connection ends.
    Bad(&'static str),
}

/// How a body is framed on the connection.
#[derive(Clone, Copy)]
pub(crate) enum Framing {
    Length(u64),
    Chunked,
}

/// Copy a body framed as `f` from the connection to `w`, without holding it: the bytes copied, or
/// why the body did not arrive whole. A write that fails (the reader ended early) stops the copy
/// and is reported apart, as `Ok(Err(..))`, since the body is then not the reason.
pub(crate) fn copy_body(
    r: &mut BufReader<UnixStream>,
    f: Framing,
    w: &mut dyn Write,
) -> Result<Result<u64, std::io::Error>, &'static str> {
    let chunk = |r: &mut BufReader<UnixStream>, n: u64, w: &mut dyn Write| {
        let mut left = n;
        let mut buf = [0u8; 64 * 1024];
        while left > 0 {
            let want = buf.len().min(usize::try_from(left).unwrap_or(buf.len()));
            let got = match r.read(&mut buf[..want]) {
                Ok(0) | Err(_) => return Err("the body ends before its length"),
                Ok(g) => g,
            };
            if let Err(e) = w.write_all(&buf[..got]) {
                return Ok(Err(e));
            }
            left -= got as u64;
        }
        Ok(Ok(n))
    };
    match f {
        Framing::Length(n) => chunk(r, n, w),
        Framing::Chunked => {
            let mut total = 0u64;
            loop {
                let mut size_line = String::new();
                if r.by_ref().take(1024).read_line(&mut size_line).is_err() {
                    return Err("a chunk size line that does not parse");
                }
                let size_hex = size_line
                    .trim()
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim();
                let Ok(size) = u64::from_str_radix(size_hex, 16) else {
                    return Err("a chunk size line that does not parse");
                };
                if size == 0 {
                    loop {
                        let mut t = String::new();
                        if r.by_ref().take(8192).read_line(&mut t).is_err() {
                            return Err("the chunked body ends inside its trailers");
                        }
                        if t == "\r\n" || t.is_empty() {
                            return Ok(Ok(total));
                        }
                    }
                }
                match chunk(r, size, w)? {
                    Ok(n) => total += n,
                    Err(e) => return Ok(Err(e)),
                }
                let mut crlf = [0u8; 2];
                if r.read_exact(&mut crlf).is_err() || &crlf != b"\r\n" {
                    return Err("a chunk not ended by CRLF");
                }
            }
        }
    }
}

/// Read one request: the head up to its blank line (strictly framed), then its body by
/// `Content-Length` or `chunked`.
fn read_request(r: &mut BufReader<UnixStream>) -> Read1 {
    let mut head = Vec::with_capacity(1024);
    loop {
        let mut line = Vec::new();
        match r
            .by_ref()
            .take((MAX_HEAD - head.len()) as u64 + 1)
            .read_until(b'\n', &mut line)
        {
            Ok(0) => {
                return if head.is_empty() {
                    Read1::Closed
                } else {
                    Read1::Bad("the head ends before its blank line")
                }
            }
            Ok(_) => {}
            Err(_) => return Read1::Closed,
        }
        head.extend_from_slice(&line);
        if head.len() > MAX_HEAD {
            return Read1::Bad("the head is longer than 64 KiB");
        }
        if kern_common::httphead::head_end(&head).is_some() {
            break;
        }
    }
    if kern_common::httphead::framing(&head).is_err() {
        return Read1::Bad("the head is not framed the one way HTTP/1.1 allows");
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(_version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Read1::Bad("the request line is not METHOD TARGET VERSION");
    };
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut upgrade = false;
    let mut close = false;
    for l in lines {
        if let Some((n, v)) = l.split_once(':') {
            let n = n.trim();
            if n.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().ok();
            } else if n.eq_ignore_ascii_case("transfer-encoding") {
                chunked = v.trim().eq_ignore_ascii_case("chunked");
            } else if n.eq_ignore_ascii_case("upgrade") {
                upgrade = v.trim().eq_ignore_ascii_case("tcp");
            } else if n.eq_ignore_ascii_case("connection") {
                close = v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"));
            }
        }
    }
    let (raw_path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let streamed = method == "POST" && strip_version(raw_path) == "/images/load";
    let body = if streamed {
        Vec::new()
    } else if chunked {
        match read_chunked(r) {
            Ok(b) => b,
            Err(why) => return Read1::Bad(why),
        }
    } else {
        let n = content_length.unwrap_or(0);
        if n > MAX_BODY {
            return Read1::Bad("a body longer than 4 MiB");
        }
        let mut b = vec![0u8; n];
        if r.read_exact(&mut b).is_err() {
            return Read1::Bad("the body ends before its length");
        }
        b
    };
    let query = raw_query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (percent_decode(k, true), percent_decode(v, true))
        })
        .collect();
    let req = Request {
        method: method.to_string(),
        path: strip_version(raw_path).to_string(),
        query,
        body,
        upgrade,
        close,
        peer: None,
    };
    if streamed {
        let framing = if chunked {
            Framing::Chunked
        } else {
            Framing::Length(content_length.unwrap_or(0) as u64)
        };
        return Read1::Load(req, framing);
    }
    Read1::Request(req)
}

/// A `Transfer-Encoding: chunked` body, bounded by [`MAX_BODY`]: [`copy_body`] into memory, a
/// body over the cap said as such (MEASURED: a 7.8 MB `docker load` was answered "a chunked body
/// that does not parse", which sent the reader looking for a fault in the client).
fn read_chunked(r: &mut BufReader<UnixStream>) -> Result<Vec<u8>, &'static str> {
    struct Capped(Vec<u8>);
    impl Write for Capped {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.0.len() + b.len() > MAX_BODY {
                return Err(std::io::Error::other("over the cap"));
            }
            self.0.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut body = Capped(Vec::new());
    match copy_body(r, Framing::Chunked, &mut body)? {
        Ok(_) => Ok(body.0),
        Err(_) => Err("a body longer than 4 MiB"),
    }
}

/// What a handler answers.
pub(crate) enum Response {
    /// A whole body with its length; the connection stays open for the next request.
    Full {
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
        extra: Vec<(&'static str, String)>,
    },
    /// A stream the handler writes itself, after this head; the connection closes when it ends.
    Stream {
        status: u16,
        content_type: &'static str,
        /// Answer `101` and hand the connection over, as Docker does when the client asked for it.
        upgrade: bool,
        writer: Box<dyn FnOnce(&mut Out) + Send>,
    },
}

/// Where a stream response's body goes: the connection itself after a `101`, and otherwise in
/// HTTP/1.1 chunks, which is how Docker answers a stream (`logs`, `pull`, `wait`, an attach the client
/// did not upgrade).
///
/// CHUNKED BECAUSE A CLIENT REQUIRES IT. The body used to run unframed to the connection's close,
/// which HTTP/1.1 allows and the `docker` CLI and docker-py read. Docker.DotNet (Testcontainers for
/// .NET) does not: MEASURED on Windows through the named pipe, its `GetLogsAsync` failed with
/// `Invalid chunk header encountered: 'out-a'`, reading the first log frame as a chunk size.
///
/// ONE WRITE IS ONE CHUNK, written whole: two threads that share the connection under one lock (the
/// attach pump, one per stream) then cannot interleave inside a chunk any more than inside a frame.
pub(crate) struct Out {
    stream: UnixStream,
    chunked: bool,
    /// What the client sent past its request before this answer, already read off the
    /// connection: the first bytes of a hijacked exec's stdin, for a client that does not wait
    /// for the `101`.
    input: Vec<u8>,
}

impl Out {
    /// The connection was handed over (`101`): the answer is the raw stream, nothing follows it.
    pub(crate) fn hijacked(&self) -> bool {
        !self.chunked
    }

    /// A second handle on the same connection, framing the same way.
    pub(crate) fn try_clone(&self) -> std::io::Result<Out> {
        Ok(Out {
            stream: self.stream.try_clone()?,
            chunked: self.chunked,
            input: Vec::new(),
        })
    }

    /// The bytes already read past the request (see `input`), once.
    pub(crate) fn take_input(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.input)
    }

    /// The connection, for a handler that watches it (a client hanging up) rather than writes.
    pub(crate) fn socket(&self) -> &UnixStream {
        &self.stream
    }

    /// End the body: the empty chunk, when chunked.
    fn finish(&mut self) -> std::io::Result<()> {
        if self.chunked {
            self.stream.write_all(b"0\r\n\r\n")?;
        }
        self.stream.flush()
    }
}

/// `n` in lowercase hex, into `buf`, and the bytes written: a chunk size without an allocation.
fn hex_len(mut n: usize, buf: &mut [u8; 16]) -> &[u8] {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = DIGITS[n & 0xf];
        n >>= 4;
        if n == 0 || i == 0 {
            break;
        }
    }
    &buf[i..]
}

impl Write for Out {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            // An empty chunk is the end of the body: never written for an empty write.
            return Ok(0);
        }
        if !self.chunked {
            return self.stream.write(data);
        }
        let mut digits = [0u8; 16];
        self.stream.write_all(hex_len(data.len(), &mut digits))?;
        self.stream.write_all(b"\r\n")?;
        self.stream.write_all(data)?;
        self.stream.write_all(b"\r\n")?;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Status",
    }
}

/// Write `resp`. `false` when the connection must end after it.
/// `head_only` for a HEAD request: the head says how long the body is, and the body is not sent.
fn write_response(w: &mut UnixStream, resp: Response, head_only: bool, input: &[u8]) -> bool {
    match resp {
        Response::Full {
            status,
            content_type,
            body,
            extra,
        } => {
            let mut head = format!(
                "HTTP/1.1 {status} {}\r\nServer: kern/{}\r\nApi-Version: {}\r\n",
                reason(status),
                kern_common::VERSION,
                api::API_VERSION
            );
            if status != 204 && status != 304 {
                head.push_str(&format!(
                    "Content-Type: {content_type}\r\nContent-Length: {}\r\n",
                    body.len()
                ));
            }
            for (k, v) in extra {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
            head.push_str("\r\n");
            let body: &[u8] = if head_only { &[] } else { &body };
            w.write_all(head.as_bytes())
                .and_then(|()| w.write_all(body))
                .and_then(|()| w.flush())
                .is_ok()
        }
        Response::Stream {
            status,
            content_type,
            upgrade,
            writer,
        } => {
            let head = if upgrade {
                format!(
                    "HTTP/1.1 101 UPGRADED\r\nContent-Type: {content_type}\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nApi-Version: {}\r\n\r\n",
                    api::API_VERSION
                )
            } else {
                format!(
                "HTTP/1.1 {status} {}\r\nServer: kern/{}\r\nApi-Version: {}\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                reason(status),
                kern_common::VERSION,
                api::API_VERSION
            )
            };
            let Ok(stream) = w.try_clone() else {
                return false;
            };
            let mut out = Out {
                stream,
                chunked: !upgrade,
                input: if upgrade { input.to_vec() } else { Vec::new() },
            };
            if w.write_all(head.as_bytes()).is_ok() {
                writer(&mut out);
                let _ = out.finish();
            }
            false
        }
    }
}

/// How long a connection may sit with a request half sent, or idle between requests. A client
/// that keeps one open (an IDE) reconnects; a stream already answering is writing, not reading.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

fn serve_connection(stream: UnixStream, kern: &Path) {
    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err() {
        return;
    }
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let peer = peer_of(&stream);
    let mut w = write_half;
    let mut r = BufReader::new(stream);
    loop {
        match read_request(&mut r) {
            Read1::Closed => return,
            Read1::Bad(why) => {
                let _ = write_response(&mut w, api::error(400, why), false, &[]);
                return;
            }
            // The connection ends after a load: its body was read by the load itself, and one that
            // stopped early leaves the rest of it on the connection.
            Read1::Load(req, framing) => {
                let resp = api::image_load(&req, kern, &mut r, framing);
                let _ = write_response(&mut w, resp, false, &[]);
                return;
            }
            Read1::Request(mut req) => {
                req.peer = peer.clone();
                let resp = api::handle(&req, kern);
                if !write_response(&mut w, resp, req.method == "HEAD", r.buffer()) || req.close {
                    return;
                }
            }
        }
    }
}

/// Bind `path` as this user's socket: a stale socket there is replaced, anything else is refused.
fn bind(path: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            // A live server answers a connect; only a dead one's socket is removed.
            if UnixStream::connect(path).is_ok() {
                return Err(format!(
                    "{} is served already (another `kern compat docker serve`?)",
                    path.display()
                ));
            }
            std::fs::remove_file(path)
                .map_err(|e| format!("cannot remove the stale {}: {e}", path.display()))?;
        }
        Ok(_) => {
            return Err(format!(
                "{} exists and is not a socket: kern does not replace it",
                path.display()
            ))
        }
        Err(_) => {}
    }
    // SAFETY: umask with a constant; the socket is created owner-only, then the mode is set again.
    let old = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(path);
    // SAFETY: restoring the mask saved above.
    unsafe { libc::umask(old) };
    let l = bound.map_err(|e| format!("cannot bind {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("cannot make {} owner-only: {e}", path.display()))?;
    Ok(l)
}

/// Where the server listens.
pub enum Listen {
    /// A socket path this process binds (a stale socket there is replaced).
    Path(PathBuf),
    /// A listening socket passed by systemd's socket unit (`LISTEN_FDS`), as this fd.
    Inherited(RawFd),
}

/// Connections being served now, and when the last one ended (seconds on the monotonic clock).
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static LAST_END: AtomicU64 = AtomicU64::new(0);

fn monotonic_secs() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes the timespec it is given.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    u64::try_from(ts.tv_sec).unwrap_or(0)
}

/// Serve the Docker API until killed, or, with `idle`, until no connection has been open for that
/// long (systemd starts it again at the next one). Every request is run by the `kern` binary at
/// `kern`. `Err` says why it could not serve.
pub fn serve(listen: Listen, kern: PathBuf, idle: Option<Duration>) -> Result<(), String> {
    // ⛔ A PIPE WHOSE READER ENDED IS AN ERROR HERE, NOT THE SERVER'S DEATH. kern's `main` restores
    // SIGPIPE's default, which suits a command in a pipeline and kills a server: MEASURED,
    // `head -c 20M /dev/zero | docker exec -i c true` ended this process with SIGPIPE (exit 141) as
    // `true` left the rest of its stdin unread, and with it every attached run and session it
    // served. Ignored, a write to that pipe fails and the feeder stops. Every process this server
    // starts is kern, whose `main` restores the default again, so no workload inherits this.
    // SAFETY: setting a signal's disposition to SIG_IGN has no precondition.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let (listener, shown) = match listen {
        Listen::Path(p) => (bind(&p)?, p.display().to_string()),
        Listen::Inherited(fd) => (inherited(fd)?, format!("fd {fd} from systemd")),
    };
    eprintln!("kern: the Docker API, answered by kern, on {shown}");
    LAST_END.store(monotonic_secs(), Ordering::Release);
    loop {
        if let Some(idle) = idle {
            let mut pfd = libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one pollfd, owned here, for one second.
            let ready = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if ready == 0 {
                let quiet = monotonic_secs().saturating_sub(LAST_END.load(Ordering::Acquire));
                // Not while a test session's containers wait for their process to end: the
                // reaper that removes them lives in this process. Nor while an attached
                // `docker run` box runs: its exit code, its event and its `--rm` are done here.
                if ACTIVE.load(Ordering::Acquire) == 0
                    && !api::sessions_open()
                    && !api::runs_alive()
                    && quiet >= idle.as_secs()
                {
                    return Ok(());
                }
                continue;
            }
        }
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if idle.is_some() && e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(format!("{shown}: accept failed: {e}")),
        };
        let kern = kern.clone();
        ACTIVE.fetch_add(1, Ordering::AcqRel);
        let spawned = std::thread::Builder::new()
            .name("kern-compat-conn".into())
            .spawn(move || {
                serve_connection(stream, &kern);
                LAST_END.store(monotonic_secs(), Ordering::Release);
                ACTIVE.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            ACTIVE.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// A Windows process key as `kern.exe` writes it: `<pid>-<creation time>`, both decimal.
pub fn valid_peer_key(k: &str) -> bool {
    k.split_once('-').is_some_and(|(a, b)| {
        !a.is_empty()
            && !b.is_empty()
            && a.len() <= 10
            && b.len() <= 20
            && a.bytes().all(|c| c.is_ascii_digit())
            && b.bytes().all(|c| c.is_ascii_digit())
    })
}

/// Who a connection's test session belongs to. The process that connected (`SO_PEERCRED`, with
/// its start time so a reused pid is not it), unless it is this kern's own `__stdio` bridge: that
/// one lives for one connection, and the session is the Windows process it names
/// (`--windows-peer`), or nobody's when it names none.
fn peer_of(s: &UnixStream) -> Option<api::Owner> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into the ucred it is given.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 || cred.pid <= 0 {
        return None;
    }
    let peer = api::Peer::of(cred.pid)?;
    let exe = std::fs::read_link(format!("/proc/{}/exe", cred.pid)).ok();
    let me = std::fs::read_link("/proc/self/exe").ok();
    if exe.is_some() && exe == me {
        let cmdline = std::fs::read(format!("/proc/{}/cmdline", cred.pid)).ok()?;
        let argv: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        if argv
            .windows(3)
            .any(|w| w == [&b"compat"[..], b"docker", b"__stdio"])
        {
            let key = argv
                .windows(2)
                .find(|w| w[0] == b"--windows-peer")
                .and_then(|w| std::str::from_utf8(w[1]).ok())
                .filter(|k| valid_peer_key(k))?;
            return Some(api::Owner::Windows(key.to_string()));
        }
    }
    Some(api::Owner::Local(peer))
}

/// The listening socket systemd passed. It is made close-on-exec FIRST: systemd hands it without,
/// and every `kern box` this server runs would otherwise inherit the listening Docker socket.
fn inherited(fd: RawFd) -> Result<UnixListener, String> {
    // SAFETY: fcntl on an fd number; a bad one fails with EBADF, read below.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(format!(
            "fd {fd} from systemd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: a zeroed stat is a valid out-buffer for fstat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstat writes the stat it is given, for an fd shown open above.
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(format!("fd {fd} from systemd is not a socket"));
    }
    // SAFETY: the fd is an open socket and from here owned by the listener alone.
    Ok(unsafe { UnixListener::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::{copy_body, read_chunked, Framing};
    use std::io::{BufReader, Write};
    use std::os::unix::net::UnixStream;

    /// The far end of a connection that has `bytes` on it and is then closed for writing.
    fn conn(bytes: &[u8]) -> BufReader<UnixStream> {
        let (mut a, b) = UnixStream::pair().expect("pair");
        let owned = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = a.write_all(&owned);
            let _ = a.shutdown(std::net::Shutdown::Write);
        });
        BufReader::new(b)
    }

    /// A body is copied as framed, by length or in chunks, past any cap; a body that stops short
    /// or a chunk that does not parse is said as such; a reader that stops early is reported apart.
    #[test]
    fn a_body_is_copied_as_framed_and_its_faults_are_named() {
        let big = vec![7u8; 5 * 1024 * 1024];
        let mut out = Vec::new();
        let n = copy_body(&mut conn(&big), Framing::Length(big.len() as u64), &mut out);
        assert!(matches!(n, Ok(Ok(len)) if len == big.len() as u64) && out == big);

        let mut out = Vec::new();
        let r = copy_body(
            &mut conn(b"5\r\nhello\r\n3;x=y\r\nabc\r\n0\r\n\r\n"),
            Framing::Chunked,
            &mut out,
        );
        assert!(matches!(r, Ok(Ok(8))) && out == b"helloabc");

        let mut out = Vec::new();
        assert!(copy_body(&mut conn(b"abc"), Framing::Length(10), &mut out).is_err());
        assert!(copy_body(&mut conn(b"zz\r\n"), Framing::Chunked, &mut out).is_err());
        assert!(copy_body(&mut conn(b"3\r\nabcXY"), Framing::Chunked, &mut out).is_err());

        struct Gone;
        impl Write for Gone {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(matches!(
            copy_body(&mut conn(b"abc"), Framing::Length(3), &mut Gone),
            Ok(Err(_))
        ));
    }

    /// A chunked request body over the cap is refused AS over the cap, not as unparseable.
    #[test]
    fn a_chunked_body_over_the_cap_says_so() {
        let mut wire = Vec::new();
        for _ in 0..5 {
            wire.extend_from_slice(b"100000\r\n");
            wire.extend(std::iter::repeat_n(1u8, 0x100000));
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(
            read_chunked(&mut conn(&wire)).err(),
            Some("a body longer than 4 MiB")
        );
        assert_eq!(
            read_chunked(&mut conn(b"2\r\nok\r\n0\r\n\r\n")).ok(),
            Some(b"ok".to_vec())
        );
    }

    /// A stream body in HTTP/1.1 chunks: one write, one chunk; an empty write writes nothing (an
    /// empty chunk would END the body); `finish` writes the terminator. After a `101` the bytes go
    /// as they are.
    #[test]
    fn a_stream_body_is_chunked_unless_the_connection_was_upgraded() {
        use std::io::{Read, Write};
        for (chunked, want) in [
            (
                true,
                &b"5\r\nhello\r\n1a\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n"[..],
            ),
            (false, &b"helloabcdefghijklmnopqrstuvwxyz"[..]),
        ] {
            let Ok((a, mut b)) = UnixStream::pair() else {
                panic!("socketpair");
            };
            let mut out = Out {
                stream: a,
                chunked,
                input: Vec::new(),
            };
            assert!(out.write_all(b"hello").is_ok());
            assert!(matches!(out.write(b""), Ok(0)));
            let Ok(mut second) = out.try_clone() else {
                panic!("clone");
            };
            assert!(second.write_all(b"abcdefghijklmnopqrstuvwxyz").is_ok());
            drop(second);
            assert!(out.finish().is_ok());
            drop(out);
            let mut got = Vec::new();
            assert!(b.read_to_end(&mut got).is_ok());
            assert_eq!(
                got,
                want,
                "chunked={chunked}: {:?}",
                String::from_utf8_lossy(&got)
            );
        }
        let mut buf = [0u8; 16];
        assert_eq!(hex_len(0, &mut buf), b"0");
        assert_eq!(hex_len(255, &mut buf), b"ff");
        assert_eq!(hex_len(1 << 20, &mut buf), b"100000");
        assert_eq!(hex_len(usize::MAX, &mut buf), b"ffffffffffffffff");
    }

    use super::*;

    /// The parser takes what any client of this user sends: mutated real requests, from the shapes
    /// Testcontainers and the docker CLI send, must end in a request, a 400 or a close, never a
    /// panic or a hang, and every body read must stay under the cap. Deterministic (xorshift), so a
    /// failure names the case.
    #[test]
    fn the_parser_survives_mutated_requests() {
        let seeds: [&[u8]; 6] = [
            b"HEAD /_ping HTTP/1.1\r\nHost: docker\r\n\r\n",
            b"POST /v1.52/containers/create?name=a HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: 47\r\n\r\n{\"Image\":\"alpine\",\"Cmd\":[\"true\"],\"Env\":[\"A=1\"]}",
            b"POST /v1.52/containers/abc/attach?stderr=1&stdout=1&stream=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
            b"POST /exec/x/start HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"De\r\n9\r\ntach\":true\r\n1\r\n}\r\n0\r\n\r\n",
            b"GET /containers/json?all=1&filters=%7B%22label%22%3A%5B%22a%3Db%22%5D%7D HTTP/1.1\r\n\r\nGET /version HTTP/1.1\r\n\r\n",
            b"DELETE /containers/x?force=1&v=1 HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        ];
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut outcomes = [0usize; 3];
        for case in 0..6000 {
            let mut input = seeds[case % seeds.len()].to_vec();
            for _ in 0..(1 + next() % 8) {
                let r = next();
                let at = if input.is_empty() {
                    0
                } else {
                    (r as usize >> 8) % input.len()
                };
                match r % 6 {
                    0 if !input.is_empty() => input[at] = (r >> 32) as u8,
                    1 if !input.is_empty() => {
                        input.remove(at);
                    }
                    2 => input.insert(at, (r >> 40) as u8),
                    3 => input.splice(at..at, b"\r\n".iter().copied()).for_each(drop),
                    4 => input
                        .splice(at..at, b"Content-Length: 99999999999\r\n".iter().copied())
                        .for_each(drop),
                    _ => input.truncate(at),
                }
            }
            let Ok((client, server)) = UnixStream::pair() else {
                panic!("no socketpair")
            };
            let mut c = client;
            let writer = std::thread::spawn(move || {
                let _ = c.write_all(&input);
                let _ = c.shutdown(std::net::Shutdown::Write);
            });
            if server
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .is_err()
            {
                panic!("no read timeout")
            }
            let mut r = BufReader::new(server);
            for _ in 0..4 {
                match read_request(&mut r) {
                    Read1::Request(req) => {
                        outcomes[0] += 1;
                        assert!(req.body.len() <= MAX_BODY, "case {case}: body over the cap");
                        let _ = kern_common::json::parse(&String::from_utf8_lossy(&req.body));
                    }
                    // The server ends the connection after a load, its body read by the load.
                    Read1::Load(..) => {
                        outcomes[0] += 1;
                        break;
                    }
                    Read1::Closed => {
                        outcomes[1] += 1;
                        break;
                    }
                    Read1::Bad(_) => {
                        outcomes[2] += 1;
                        break;
                    }
                }
            }
            let _ = writer.join();
        }
        eprintln!("parser fuzz: {outcomes:?} (requests, closes, 400s)");
        // The mutations reached every outcome, so the run exercised the parser and not only its door.
        assert!(outcomes.iter().all(|n| *n > 100), "{outcomes:?}");
    }

    #[test]
    fn the_version_prefix_comes_off_and_only_it() {
        assert_eq!(strip_version("/v1.43/containers/json"), "/containers/json");
        assert_eq!(strip_version("/containers/json"), "/containers/json");
        assert_eq!(strip_version("/volumes/x"), "/volumes/x");
        assert_eq!(strip_version("/v1.43"), "/v1.43");
    }

    #[test]
    fn percent_escapes_decode_and_a_bad_one_is_kept() {
        assert_eq!(
            percent_decode("library%2Fnginx%3Aalpine", false),
            "library/nginx:alpine"
        );
        assert_eq!(percent_decode("a+b", true), "a b");
        assert_eq!(percent_decode("a+b", false), "a+b");
        assert_eq!(percent_decode("50%", true), "50%");
        assert_eq!(percent_decode("%zz", true), "%zz");
    }
}
