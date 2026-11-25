//! A transient systemd scope for THIS process, asked of the manager over D-Bus directly.
//!
//! WHY NOT `systemd-run --scope`. A box started from a session outside the user's systemd subtree (a
//! WSL `wsl.exe -u` shell, an ssh login on a server, a Jetson console) cannot move itself into the
//! delegated `kern-boxes.service`, so it asks systemd for a scope of its own. Through `systemd-run`
//! that cost a process, its own bus connection, and then kern started again inside the scope.
//! MEASURED on WSL Ubuntu with systemd (i7-9700, user `kdev`, session in `/init.scope`, medians of 30):
//! `kern box ... true` 13.84 ms from such a session against 5.29 ms from a shell already in a scope;
//! `systemd-run --user --scope true` alone 5.94 ms; the same `StartTransientUnit` asked directly,
//! from inside the process, 2.87 ms. Asked here, the scope takes this process (`PIDs`) and kern goes
//! on as it is: no `systemd-run`, no second start.
//!
//! WRITTEN FROM THE PROTOCOL, NOT A LIBRARY: the D-Bus wire format (little-endian marshaling, the
//! message header, SASL `EXTERNAL`) and one method of systemd's Manager. Two doors, the ones
//! `systemd-run` itself uses: the manager's private socket (`<runtime>/systemd/private`, peer to peer,
//! no bus daemon) and, where that refuses, the session bus (`<runtime>/bus`, `Hello` and an
//! `AddMatch` first). As root, the system manager's private socket.
//!
//! EVERY FAILURE IS AN `Err` AND NOTHING ELSE: no partial state is left that the caller must undo,
//! and the caller falls back to `systemd-run`, so the worst this module can do is cost the time it
//! took to fail. The scope is only reported made once systemd said its job is `done` AND
//! `/proc/self/cgroup` names it.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The longest the whole exchange may take before the caller falls back. A healthy manager answers
/// in a few ms; this bounds a stuck one.
const DEADLINE: Duration = Duration::from_secs(5);

/// The largest message read from the manager. systemd's signals are a few hundred bytes; a larger
/// one is not an answer to anything asked here.
const MAX_MESSAGE: usize = 1 << 20;

const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_IFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_DEST: &str = "org.freedesktop.systemd1";

/// One property of the scope, typed as systemd's D-Bus API takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prop {
    /// `t`: `MemoryMax`, `MemorySwapMax`, `TasksMax`, `CPUQuotaPerSecUSec`.
    U64(&'static str, u64),
    /// `s`: `OOMPolicy`, `CollectMode`.
    Str(&'static str, String),
    /// `ay`: `AllowedCPUs`, a bitmask, CPU `n` at bit `n % 8` of byte `n / 8`.
    Bytes(&'static str, Vec<u8>),
}

/// The typed property for one `systemd-run -p Key=Value` this crate's callers pass, or `None` for a
/// key or a value this module does not take. ONE SPELLING FOR BOTH DOORS: the caller builds the same
/// `Key=Value` strings for `systemd-run` and for here, so the two cannot ask for different scopes;
/// a string this cannot translate makes the whole request fall back rather than drop the property.
pub fn prop_of(kv: &str) -> Option<Prop> {
    let (k, v) = kv.split_once('=')?;
    let number = |v: &str| -> Option<u64> {
        if v == "infinity" {
            Some(u64::MAX)
        } else {
            v.parse().ok()
        }
    };
    Some(match k {
        "MemoryMax" => Prop::U64("MemoryMax", number(v)?),
        "MemorySwapMax" => Prop::U64("MemorySwapMax", number(v)?),
        "TasksMax" => Prop::U64("TasksMax", number(v)?),
        // `CPUQuota=50%` is half of each second: 500000 us per second.
        "CPUQuota" => {
            let pct: u64 = v.strip_suffix('%')?.parse().ok()?;
            Prop::U64("CPUQuotaPerSecUSec", pct.checked_mul(10_000)?)
        }
        "AllowedCPUs" => Prop::Bytes("AllowedCPUs", cpu_mask(v)?),
        "OOMPolicy" => Prop::Str("OOMPolicy", v.to_string()),
        _ => return None,
    })
}

/// `0-3,8` as the bitmask systemd's `AllowedCPUs` takes. `None` for a list that does not parse or
/// names a CPU past 8191.
pub fn cpu_mask(list: &str) -> Option<Vec<u8>> {
    let mut mask: Vec<u8> = Vec::new();
    for part in list.split(',') {
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (
                a.trim().parse::<usize>().ok()?,
                b.trim().parse::<usize>().ok()?,
            ),
            None => {
                let n = part.trim().parse::<usize>().ok()?;
                (n, n)
            }
        };
        if lo > hi || hi >= 8192 {
            return None;
        }
        for cpu in lo..=hi {
            if mask.len() <= cpu / 8 {
                mask.resize(cpu / 8 + 1, 0);
            }
            mask[cpu / 8] |= 1 << (cpu % 8);
        }
    }
    (!mask.is_empty()).then_some(mask)
}

/// Why no scope was made. The caller only needs to know that it was not; the text is for a reader
/// of a debug trace.
#[derive(Debug)]
pub struct ScopeError(pub String);

/// Put this process in a new transient scope `unit` (ending `.scope`) with `props`, through the
/// system manager when `system`, else the user manager reached through `runtime_dir`. Returns once
/// the scope runs and this process is in it.
pub fn start_scope_for_self(
    system: bool,
    runtime_dir: Option<&Path>,
    unit: &str,
    props: &[Prop],
) -> Result<(), ScopeError> {
    let started = Instant::now();
    let (mut conn, on_bus) = connect(system, runtime_dir)?;
    let pid = std::process::id();
    let mut serial = 0u32;
    let mut next = || {
        serial += 1;
        serial
    };
    if on_bus {
        conn.send(&method_call(
            next(),
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
            Some("org.freedesktop.DBus"),
            "",
            &[],
        ))?;
        let mut rule = Writer::default();
        rule.string(
            "type='signal',sender='org.freedesktop.systemd1',interface='org.freedesktop.systemd1.Manager',member='JobRemoved'",
        );
        conn.send(&method_call(
            next(),
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "AddMatch",
            Some("org.freedesktop.DBus"),
            "s",
            &rule.buf,
        ))?;
    }
    let dest = on_bus.then_some(SYSTEMD_DEST);
    if on_bus {
        conn.send(&method_call(
            next(),
            SYSTEMD_PATH,
            MANAGER_IFACE,
            "Subscribe",
            dest,
            "",
            &[],
        ))?;
    }
    let start_serial = next();
    conn.send(&method_call(
        start_serial,
        SYSTEMD_PATH,
        MANAGER_IFACE,
        "StartTransientUnit",
        dest,
        "ssa(sv)a(sa(sv))",
        &start_transient_body(unit, pid, props),
    ))?;
    // The job's end may come before the method's answer names the job, so ends are kept until then.
    let mut job: Option<String> = None;
    let mut ended: Vec<(String, String)> = Vec::new();
    loop {
        if started.elapsed() > DEADLINE {
            return Err(ScopeError("the manager did not answer in time".into()));
        }
        let m = conn.recv(started)?;
        match m.kind {
            KIND_ERROR if m.reply_serial == Some(start_serial) => {
                let detail = Reader::new(&m.body).string().unwrap_or_default();
                return Err(ScopeError(format!(
                    "{}: {detail}",
                    m.error_name.unwrap_or_default()
                )));
            }
            KIND_RETURN if m.reply_serial == Some(start_serial) => {
                job = Some(
                    Reader::new(&m.body)
                        .string()
                        .ok_or_else(|| ScopeError("no job in the answer".into()))?,
                );
            }
            KIND_SIGNAL if m.member.as_deref() == Some("JobRemoved") => {
                // `uoss`: id, job, unit, result.
                let mut r = Reader::new(&m.body);
                if let (Some(_), Some(j), Some(u), Some(res)) =
                    (r.u32(), r.string(), r.string(), r.string())
                {
                    if u == unit {
                        ended.push((j, res));
                    }
                }
            }
            _ => {}
        }
        if let Some(j) = &job {
            if let Some((_, result)) = ended.iter().find(|(e, _)| e == j) {
                if result != "done" {
                    return Err(ScopeError(format!("the scope's job ended '{result}'")));
                }
                break;
            }
        }
    }
    // The manager's word, checked against the kernel's: this process is in the scope.
    let here = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    if here
        .lines()
        .any(|l| l.starts_with("0::") && l.trim_end().ends_with(&format!("/{unit}")))
    {
        Ok(())
    } else {
        Err(ScopeError(format!("not in {unit} after its job ended")))
    }
}

/// A connection to the manager, and whether it goes through a bus daemon.
fn connect(system: bool, runtime_dir: Option<&Path>) -> Result<(Conn, bool), ScopeError> {
    let doors: Vec<(PathBuf, bool)> = if system {
        vec![(PathBuf::from("/run/systemd/private"), false)]
    } else {
        let rt = runtime_dir.ok_or_else(|| ScopeError("no runtime directory".into()))?;
        vec![(rt.join("systemd/private"), false), (rt.join("bus"), true)]
    };
    let mut last = String::from("no door");
    for (path, on_bus) in doors {
        match UnixStream::connect(&path) {
            Ok(s) => {
                let mut c = Conn {
                    sock: s,
                    buf: Vec::new(),
                };
                c.auth()?;
                return Ok((c, on_bus));
            }
            Err(e) => last = format!("{}: {e}", path.display()),
        }
    }
    Err(ScopeError(last))
}

const KIND_CALL: u8 = 1;
const KIND_RETURN: u8 = 2;
const KIND_ERROR: u8 = 3;
const KIND_SIGNAL: u8 = 4;

struct Conn {
    sock: UnixStream,
    buf: Vec<u8>,
}

impl Conn {
    /// SASL `EXTERNAL`: the kernel tells the manager who is on this socket, the uid in hex of its
    /// decimal digits is the claim.
    fn auth(&mut self) -> Result<(), ScopeError> {
        let io = |e: std::io::Error| ScopeError(format!("auth: {e}"));
        self.sock
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .map_err(io)?;
        // SAFETY: getuid takes no arguments and cannot fail.
        let uid = unsafe { libc::getuid() };
        let hex: String = uid
            .to_string()
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        self.sock
            .write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())
            .map_err(io)?;
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\r\n") {
            if line.len() > 512 || self.sock.read(&mut byte).map_err(io)? == 0 {
                return Err(ScopeError("auth: no answer".into()));
            }
            line.push(byte[0]);
        }
        if !line.starts_with(b"OK ") {
            return Err(ScopeError(format!(
                "auth refused: {}",
                String::from_utf8_lossy(&line).trim()
            )));
        }
        self.sock.write_all(b"BEGIN\r\n").map_err(io)
    }

    fn send(&mut self, msg: &[u8]) -> Result<(), ScopeError> {
        self.sock
            .write_all(msg)
            .map_err(|e| ScopeError(format!("send: {e}")))
    }

    /// The next whole message, read within the deadline counted from `started`.
    fn recv(&mut self, started: Instant) -> Result<Message, ScopeError> {
        loop {
            if let Some((m, used)) = parse_message(&self.buf)? {
                self.buf.drain(..used);
                return Ok(m);
            }
            let left = DEADLINE
                .checked_sub(started.elapsed())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| ScopeError("the manager did not answer in time".into()))?;
            self.sock
                .set_read_timeout(Some(left))
                .map_err(|e| ScopeError(format!("recv: {e}")))?;
            let mut chunk = [0u8; 4096];
            let n = self
                .sock
                .read(&mut chunk)
                .map_err(|e| ScopeError(format!("recv: {e}")))?;
            if n == 0 {
                return Err(ScopeError("the manager closed the connection".into()));
            }
            if self.buf.len() + n > MAX_MESSAGE {
                return Err(ScopeError("a message larger than any answer".into()));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// D-Bus marshaling, little-endian. Alignment is relative to the start of the buffer, which is the
/// start of the message for a header and of the body for a body (a body starts 8-aligned).
#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn align(&mut self, n: usize) {
        while self.buf.len() % n != 0 {
            self.buf.push(0);
        }
    }
    fn byte(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    /// `s` and `o`.
    fn string(&mut self, v: &str) {
        self.u32(u32::try_from(v.len()).unwrap_or(u32::MAX));
        self.buf.extend_from_slice(v.as_bytes());
        self.buf.push(0);
    }
    /// `g`: one length byte, at most 255.
    fn signature(&mut self, v: &str) {
        self.byte(u8::try_from(v.len()).unwrap_or(u8::MAX));
        self.buf.extend_from_slice(v.as_bytes());
        self.buf.push(0);
    }
    /// An array whose elements align to `elem_align`: the length, the padding to the first element
    /// (not counted), then the elements `fill` writes.
    fn array(&mut self, elem_align: usize, fill: impl FnOnce(&mut Writer)) {
        self.u32(0);
        let at = self.buf.len() - 4;
        self.align(elem_align);
        let start = self.buf.len();
        fill(self);
        let len = u32::try_from(self.buf.len() - start).unwrap_or(u32::MAX);
        self.buf[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }
}

/// `StartTransientUnit(name, "fail", properties, aux = [])`, the scope holding `pid`, collected once
/// it is inactive or failed (`systemd-run --collect`).
fn start_transient_body(unit: &str, pid: u32, props: &[Prop]) -> Vec<u8> {
    let mut w = Writer::default();
    w.string(unit);
    w.string("fail");
    w.array(8, |w| {
        let prop = |w: &mut Writer, name: &str, sig: &str, value: &dyn Fn(&mut Writer)| {
            w.align(8);
            w.string(name);
            w.signature(sig);
            value(w);
        };
        prop(w, "PIDs", "au", &|w| w.array(4, |w| w.u32(pid)));
        prop(w, "CollectMode", "s", &|w| w.string("inactive-or-failed"));
        for p in props {
            match p {
                Prop::U64(k, v) => prop(w, k, "t", &|w| w.u64(*v)),
                Prop::Str(k, v) => prop(w, k, "s", &|w| w.string(v)),
                Prop::Bytes(k, v) => prop(w, k, "ay", &|w| {
                    w.array(1, |w| w.buf.extend_from_slice(v));
                }),
            }
        }
    });
    w.array(8, |_| {});
    w.buf
}

/// A method call: the fixed header, the header fields (path, interface, member, destination when
/// on a bus, signature when there is a body), padding to 8, the body.
fn method_call(
    serial: u32,
    path: &str,
    iface: &str,
    member: &str,
    dest: Option<&str>,
    sig: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut w = Writer::default();
    w.byte(b'l');
    w.byte(KIND_CALL);
    w.byte(0);
    w.byte(1);
    w.u32(u32::try_from(body.len()).unwrap_or(u32::MAX));
    w.u32(serial);
    w.array(8, |w| {
        let field = |w: &mut Writer, code: u8, ty: &str, val: &str| {
            w.align(8);
            w.byte(code);
            w.signature(ty);
            if ty == "g" {
                w.signature(val);
            } else {
                w.string(val);
            }
        };
        field(w, 1, "o", path);
        field(w, 2, "s", iface);
        field(w, 3, "s", member);
        if let Some(d) = dest {
            field(w, 6, "s", d);
        }
        if !sig.is_empty() {
            field(w, 8, "g", sig);
        }
    });
    w.align(8);
    w.buf.extend_from_slice(body);
    w.buf
}

/// The parts of an incoming message this module reads.
#[derive(Debug, Default)]
struct Message {
    kind: u8,
    reply_serial: Option<u32>,
    error_name: Option<String>,
    member: Option<String>,
    body: Vec<u8>,
}

/// One message from the front of `buf`, and the bytes it took; `Ok(None)` while it is incomplete.
fn parse_message(buf: &[u8]) -> Result<Option<(Message, usize)>, ScopeError> {
    if buf.len() < 16 {
        return Ok(None);
    }
    if buf[0] != b'l' {
        return Err(ScopeError(
            "a big-endian message, which this does not read".into(),
        ));
    }
    let le = |at: usize| u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]);
    let body_len = le(4) as usize;
    let fields_len = le(12) as usize;
    let fields_end = 16usize
        .checked_add(fields_len)
        .ok_or_else(|| ScopeError("a header too long".into()))?;
    let body_at = fields_end.div_ceil(8) * 8;
    let total = body_at
        .checked_add(body_len)
        .filter(|t| *t <= MAX_MESSAGE)
        .ok_or_else(|| ScopeError("a message larger than any answer".into()))?;
    if buf.len() < total {
        return Ok(None);
    }
    let mut m = Message {
        kind: buf[1],
        body: buf[body_at..total].to_vec(),
        ..Message::default()
    };
    let mut r = Reader {
        buf: &buf[..fields_end],
        at: 16,
    };
    while r.at < fields_end {
        r.align(8);
        if r.at >= fields_end {
            break;
        }
        let code = r
            .byte()
            .ok_or_else(|| ScopeError("a header field cut short".into()))?;
        let ty = r
            .signature()
            .ok_or_else(|| ScopeError("a header field with no type".into()))?;
        match ty.as_str() {
            "u" => {
                let v = r
                    .u32()
                    .ok_or_else(|| ScopeError("a header field cut short".into()))?;
                if code == 5 {
                    m.reply_serial = Some(v);
                }
            }
            "s" | "o" => {
                let v = r
                    .string()
                    .ok_or_else(|| ScopeError("a header field cut short".into()))?;
                match code {
                    3 => m.member = Some(v),
                    4 => m.error_name = Some(v),
                    _ => {}
                }
            }
            "g" => {
                r.signature()
                    .ok_or_else(|| ScopeError("a header field cut short".into()))?;
            }
            other => {
                return Err(ScopeError(format!("a header field of type '{other}'")));
            }
        }
    }
    Ok(Some((m, total)))
}

/// Reading what [`Writer`] writes. Every read is bounded by the buffer: `None` past its end.
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }
    fn align(&mut self, n: usize) {
        self.at = self.at.div_ceil(n) * n;
    }
    fn byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.at)?;
        self.at += 1;
        Some(b)
    }
    fn u32(&mut self) -> Option<u32> {
        self.align(4);
        let b = self.buf.get(self.at..self.at + 4)?;
        self.at += 4;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let end = self.at.checked_add(len)?;
        let s = std::str::from_utf8(self.buf.get(self.at..end)?)
            .ok()?
            .to_string();
        self.at = end + 1;
        Some(s)
    }
    fn signature(&mut self) -> Option<String> {
        let len = self.byte()? as usize;
        let end = self.at.checked_add(len)?;
        let s = std::str::from_utf8(self.buf.get(self.at..end)?)
            .ok()?
            .to_string();
        self.at = end + 1;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A method call reads back through the parser with what was put in, and its fixed header is
    /// D-Bus's: little-endian, a call, version 1, the body length, the serial.
    #[test]
    fn a_method_call_round_trips_through_the_parser() {
        let body = start_transient_body(
            "kern-box-7.scope",
            7,
            &[
                Prop::U64("MemoryMax", 1 << 29),
                Prop::Bytes("AllowedCPUs", vec![0x0f]),
            ],
        );
        let msg = method_call(
            3,
            SYSTEMD_PATH,
            MANAGER_IFACE,
            "StartTransientUnit",
            None,
            "ssa(sv)a(sa(sv))",
            &body,
        );
        assert_eq!(&msg[..4], &[b'l', KIND_CALL, 0, 1]);
        assert_eq!(
            u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]) as usize,
            body.len()
        );
        assert_eq!(u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]), 3);
        let (m, used) = parse_message(&msg).unwrap().unwrap();
        assert_eq!(used, msg.len());
        assert_eq!(m.kind, KIND_CALL);
        assert_eq!(m.member.as_deref(), Some("StartTransientUnit"));
        assert_eq!(m.body, body);
        // The body itself: the unit, the mode, then the properties array.
        let mut r = Reader::new(&body);
        assert_eq!(r.string().as_deref(), Some("kern-box-7.scope"));
        assert_eq!(r.string().as_deref(), Some("fail"));
        assert!(
            parse_message(&msg[..msg.len() - 1]).unwrap().is_none(),
            "incomplete"
        );
    }

    /// The property array is laid out as the spec says: its length counts the elements and not the
    /// padding to the first, each `(sv)` 8-aligned, a `t` 8-aligned inside its variant.
    #[test]
    fn properties_are_marshaled_to_the_spec() {
        let body = start_transient_body("u.scope", 0x01020304, &[Prop::U64("TasksMax", 512)]);
        // "u.scope" (4+7+1 = 12), "fail" (4+4+1 = 9) -> 21, the array's length aligned to 24.
        let len = u32::from_le_bytes([body[24], body[25], body[26], body[27]]) as usize;
        // The first property starts at 32 (8-aligned after the length), with "PIDs".
        assert_eq!(&body[32..36], &4u32.to_le_bytes());
        assert_eq!(&body[36..41], b"PIDs\0");
        assert_eq!(&body[41..45], &[2, b'a', b'u', 0]);
        // `au`: its length 4 at 48, the pid at 52.
        assert_eq!(&body[48..52], &4u32.to_le_bytes());
        assert_eq!(&body[52..56], &0x01020304u32.to_le_bytes());
        // The last property, TasksMax=512 as `t`, ends the array exactly at 32 + len.
        assert_eq!(&body[32 + len - 8..32 + len], &512u64.to_le_bytes());
        // Then the empty aux array: its length 0, 4-aligned, and the padding to its 8-aligned
        // elements, which is there even with none.
        let aux = (32 + len).div_ceil(4) * 4;
        assert_eq!(&body[aux..aux + 4], &0u32.to_le_bytes());
        assert_eq!(body.len(), (aux + 4).div_ceil(8) * 8);
    }

    /// The `-p Key=Value` strings the callers pass to `systemd-run`, typed; a key or value this does
    /// not take is `None`, so the caller falls back instead of dropping it.
    #[test]
    fn systemd_run_properties_translate_or_refuse() {
        assert_eq!(
            prop_of("MemoryMax=536870912"),
            Some(Prop::U64("MemoryMax", 536870912))
        );
        assert_eq!(
            prop_of("MemorySwapMax=0"),
            Some(Prop::U64("MemorySwapMax", 0))
        );
        assert_eq!(
            prop_of("TasksMax=infinity"),
            Some(Prop::U64("TasksMax", u64::MAX))
        );
        assert_eq!(
            prop_of("CPUQuota=50%"),
            Some(Prop::U64("CPUQuotaPerSecUSec", 500_000))
        );
        assert_eq!(
            prop_of("AllowedCPUs=0-3,8"),
            Some(Prop::Bytes("AllowedCPUs", vec![0x0f, 0x01]))
        );
        assert_eq!(
            prop_of("OOMPolicy=continue"),
            Some(Prop::Str("OOMPolicy", "continue".into()))
        );
        for bad in [
            "MemoryMax=lots",
            "CPUQuota=50",
            "AllowedCPUs=3-1",
            "Delegate=yes",
            "nothing",
        ] {
            assert_eq!(prop_of(bad), None, "{bad}");
        }
        assert_eq!(cpu_mask("0"), Some(vec![1]));
        assert_eq!(cpu_mask("9000"), None);
    }

    /// A signal and an error from the manager parse to what the exchange reads: the member, the
    /// reply serial, the error name, the body.
    #[test]
    fn answers_from_the_manager_parse() {
        // Built with the same writer, as the manager's would be: kind and the two header fields.
        let mut w = Writer::default();
        w.byte(b'l');
        w.byte(KIND_ERROR);
        w.byte(0);
        w.byte(1);
        let mut body = Writer::default();
        body.string("Unit kern-box-1.scope already exists.");
        w.u32(body.buf.len() as u32);
        w.u32(9);
        w.array(8, |w| {
            w.align(8);
            w.byte(4);
            w.signature("s");
            w.string("org.freedesktop.systemd1.UnitExists");
            w.align(8);
            w.byte(5);
            w.signature("u");
            w.u32(4);
            w.align(8);
            w.byte(8);
            w.signature("g");
            w.signature("s");
        });
        w.align(8);
        w.buf.extend_from_slice(&body.buf);
        let (m, _) = parse_message(&w.buf).unwrap().unwrap();
        assert_eq!(m.kind, KIND_ERROR);
        assert_eq!(m.reply_serial, Some(4));
        assert_eq!(
            m.error_name.as_deref(),
            Some("org.freedesktop.systemd1.UnitExists")
        );
        assert_eq!(
            Reader::new(&m.body).string().as_deref(),
            Some("Unit kern-box-1.scope already exists.")
        );
        // A big-endian message is refused, not misread.
        let mut be = w.buf.clone();
        be[0] = b'B';
        assert!(parse_message(&be).is_err());
    }

    /// LIVE, against this machine's own manager, so `--ignored` only: the test binary runs itself
    /// again as a child (the scope takes the process that asks), which asks for a scope with a
    /// memory cap and checks the kernel applied it. On a desktop whose private socket refuses, this
    /// is the session-bus door (`Hello`, `AddMatch`, a destination).
    #[test]
    #[ignore = "asks this machine's systemd for a scope"]
    fn live_a_scope_is_made_for_the_asking_process() {
        if std::env::var_os("KERN_SDBUS_LIVE_CHILD").is_some() {
            // One thread, as kern is where it asks (its scope step is single-threaded, asserted):
            // the harness's process has two, and a fork keeps only the caller's.
            // SAFETY: the child only reads files, talks on a socket and exits; the parent waits.
            let pid = unsafe { libc::fork() };
            if pid > 0 {
                let mut status = 0;
                // SAFETY: waiting for the child just forked.
                unsafe { libc::waitpid(pid, &mut status, 0) };
                std::process::exit(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    4
                });
            }
            // `KERN_SDBUS_LIVE_BUS`: a runtime dir holding the session bus and no private socket,
            // so the bus door is the one taken.
            let rt = std::env::var_os("KERN_SDBUS_LIVE_BUS")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from));
            // SAFETY: getuid takes no arguments.
            let system = unsafe { libc::getuid() } == 0;
            let unit = format!("kern-sdbus-test-{}.scope", std::process::id());
            let t = Instant::now();
            let r = start_scope_for_self(
                system,
                rt.as_deref(),
                &unit,
                &[Prop::U64("MemoryMax", 64 << 20)],
            );
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            let cg = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
            let path = cg
                .lines()
                .find_map(|l| l.strip_prefix("0::"))
                .unwrap_or("")
                .trim()
                .to_string();
            let max = std::fs::read_to_string(format!("/sys/fs/cgroup{path}/memory.max"))
                .unwrap_or_default();
            let threads = std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("Threads:"))
                .map(|l| l.trim_start_matches("Threads:").trim().to_string())
                .unwrap_or_default();
            println!(
                "LIVE {r:?} {ms:.2} ms threads={threads} {path} memory.max={}",
                max.trim()
            );
            std::process::exit(if r.is_ok() && max.trim() == "67108864" {
                0
            } else {
                3
            });
        }
        let Ok(me) = std::env::current_exe() else {
            return;
        };
        let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) else {
            return;
        };
        let bus_only = std::env::temp_dir().join(format!("kern-sdbus-bus-{}", std::process::id()));
        let _ = std::fs::create_dir(&bus_only);
        let _ = std::os::unix::fs::symlink(rt.join("bus"), bus_only.join("bus"));
        for door in [None, Some(bus_only.clone())] {
            let mut cmd = std::process::Command::new(&me);
            if let Some(d) = &door {
                cmd.env("KERN_SDBUS_LIVE_BUS", d);
            }
            let out = cmd
                .args([
                    "--exact",
                    "sdbus::tests::live_a_scope_is_made_for_the_asking_process",
                    "--ignored",
                    "--nocapture",
                ])
                .env("KERN_SDBUS_LIVE_CHILD", "1")
                .output()
                .expect("run the child");
            let text = String::from_utf8_lossy(&out.stdout);
            for l in text.lines().filter(|l| l.starts_with("LIVE")) {
                eprintln!("{l}");
            }
            assert!(out.status.success(), "{text}");
        }
        let _ = std::fs::remove_file(bus_only.join("bus"));
        let _ = std::fs::remove_dir(&bus_only);
    }
}
