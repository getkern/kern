//! What an SDK sandbox RAN and what it PRINTED, kept beside the box history.
//!
//! WHY. The history (`history.rs`) says that a call ran, how long and how it ended, and on purpose
//! nothing more: kern sees a box from outside. The code a model sent and the output it got back are
//! known only to the SDK, and they are what a person reading an agent's work wants to see. So the SDK
//! hands them to `kern sandbox record` after each call, and `kern sandbox show` prints them.
//!
//! A SENSITIVE RECORD, TREATED AS ONE. Code and output can carry a secret, and no filter removes
//! secrets reliably, so the protection is where and how long they are kept, not what is cut out:
//!
//! * the SAME place as the history (`[kern] sandbox_history`): the runtime tmpfs by default, cleared
//!   at reboot; disk only when chosen; `off` records nothing. `[kern] sandbox_transcripts = false`
//!   turns these off alone;
//! * one file per call, mode 0600, created exclusively and never through a symlink, in a 0700
//!   directory under the history's, which a box can neither mount nor reach;
//! * bounded per call (code [`MAX_CODE`], each stream [`MAX_STREAM`], what was cut is marked) and in
//!   total (`[kern] sandbox_transcripts_max_size`, [`DEFAULT_TOTAL`]): past it the oldest go;
//! * `kern sandbox clear` removes them with the history, `kern sandbox keep` moves them with it.
//!
//! THE WIRE FORMAT is length-framed, so output may hold any byte: one line
//! `v1 <code bytes> <stdout bytes> <stderr bytes>\n`, then the three byte strings.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::history::Keep;

const DIR: &str = "transcripts";
/// The most of the code kept per call.
pub const MAX_CODE: usize = 64 * 1024;
/// The most of each output stream kept per call.
pub const MAX_STREAM: usize = 256 * 1024;
/// The total the transcripts may occupy when `[kern] sandbox_transcripts_max_size` is unset.
pub const DEFAULT_TOTAL: u64 = 16 << 20;
/// A length in a frame header past this is refused rather than read: no SDK sends that much.
const FRAME_CEILING: u64 = 1 << 30;
const FORMAT: &str = "t1";

/// One call, as kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    pub ended_ms: u64,
    pub box_name: String,
    pub language: String,
    pub exit: i32,
    pub code: Vec<u8>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Whether code, stdout, stderr were cut to their bound.
    pub truncated: [bool; 3],
}

/// Read up to `cap` bytes of a `len`-byte field from `r` and discard the rest, so the next field
/// starts where it should. `(kept, was it cut)`.
fn read_field(r: &mut impl Read, len: u64, cap: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let keep = len.min(cap as u64);
    let mut kept = Vec::with_capacity(usize::try_from(keep).unwrap_or(0));
    r.by_ref().take(keep).read_to_end(&mut kept)?;
    if (kept.len() as u64) < keep {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the record ended before its declared length",
        ));
    }
    let rest = len - keep;
    if rest > 0 {
        let skipped = std::io::copy(&mut r.by_ref().take(rest), &mut std::io::sink())?;
        if skipped < rest {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the record ended before its declared length",
            ));
        }
    }
    Ok((kept, len > keep))
}

/// Parse a frame (`v1 <a> <b> <c>\n` then the bytes) into a transcript of `box_name`.
pub fn read_frame(
    r: &mut impl Read,
    box_name: &str,
    language: &str,
    exit: i32,
    ended_ms: u64,
) -> Result<Transcript, String> {
    let mut head = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => return Err("the record has no header line".into()),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.len() > 96 {
                    return Err("the record's header line is too long".into());
                }
            }
            Err(e) => return Err(format!("reading the record: {e}")),
        }
    }
    let head = String::from_utf8_lossy(&head);
    let f: Vec<&str> = head.split_ascii_whitespace().collect();
    let lens: Option<Vec<u64>> = match f.as_slice() {
        ["v1", a, b, c] => [a, b, c]
            .iter()
            .map(|s| s.parse::<u64>().ok().filter(|n| *n <= FRAME_CEILING))
            .collect(),
        _ => None,
    };
    let Some(lens) = lens else {
        return Err(format!(
            "the record's header is {head:?}: expected `v1 <code bytes> <stdout bytes> <stderr bytes>`"
        ));
    };
    let caps = [MAX_CODE, MAX_STREAM, MAX_STREAM];
    let mut parts: Vec<(Vec<u8>, bool)> = Vec::with_capacity(3);
    for (len, cap) in lens.iter().zip(caps) {
        parts.push(read_field(r, *len, cap).map_err(|e| format!("reading the record: {e}"))?);
    }
    let mut it = parts.into_iter();
    let (code, tc) = it.next().unwrap_or_default();
    let (stdout, to) = it.next().unwrap_or_default();
    let (stderr, te) = it.next().unwrap_or_default();
    Ok(Transcript {
        ended_ms,
        box_name: box_name.to_string(),
        language: language.to_string(),
        exit,
        code,
        stdout,
        stderr,
        truncated: [tc, to, te],
    })
}

/// A language word as recorded: letters, digits, `+ - . _`, at most 32; anything else is `other`.
fn clean_language(s: &str) -> String {
    let ok = !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.' | b'_'));
    if ok {
        s.to_string()
    } else {
        "other".to_string()
    }
}

impl Transcript {
    fn header(&self) -> String {
        format!(
            "{FORMAT}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            self.ended_ms,
            self.box_name,
            clean_language(&self.language),
            self.exit,
            u8::from(self.truncated[0]),
            u8::from(self.truncated[1]),
            u8::from(self.truncated[2]),
            self.code.len(),
            self.stdout.len(),
            self.stderr.len(),
        )
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        let nl = bytes.iter().position(|b| *b == b'\n')?;
        let head = std::str::from_utf8(bytes.get(..nl)?).ok()?;
        let f: Vec<&str> = head.split('\t').collect();
        if f.len() != 11 || f[0] != FORMAT {
            return None;
        }
        let num = |i: usize| f.get(i).and_then(|s| s.parse::<u64>().ok());
        let (lc, lo, le) = (
            usize::try_from(num(8)?).ok()?,
            usize::try_from(num(9)?).ok()?,
            usize::try_from(num(10)?).ok()?,
        );
        let body = bytes.get(nl + 1..)?;
        if body.len() != lc.checked_add(lo)?.checked_add(le)? {
            return None;
        }
        Some(Self {
            ended_ms: num(1)?,
            box_name: f[2].to_string(),
            language: f[3].to_string(),
            exit: f[4].parse().ok()?,
            truncated: [f[5] == "1", f[6] == "1", f[7] == "1"],
            code: body.get(..lc)?.to_vec(),
            stdout: body.get(lc..lc + lo)?.to_vec(),
            stderr: body.get(lc + lo..)?.to_vec(),
        })
    }
}

/// Whether transcripts are kept, where, and the total bound, from one read of `kern.toml`.
fn settings() -> (bool, Keep, u64) {
    let cfg = crate::config::load(None).ok();
    let k = cfg.as_ref().map(|c| &c.kern);
    let keep = k.and_then(|k| k.sandbox_history).unwrap_or(Keep::Memory);
    let on = k.and_then(|k| k.sandbox_transcripts).unwrap_or(true) && keep != Keep::Off;
    let total = k
        .and_then(|k| k.sandbox_transcripts_max_size)
        .unwrap_or(DEFAULT_TOTAL)
        .max(crate::config::TRANSCRIPTS_MIN_BYTES);
    (on, keep, total)
}

/// The transcripts directory of a history directory, made private.
fn dir_in(history_dir: &Path) -> std::io::Result<PathBuf> {
    let d = history_dir.join(DIR);
    crate::commands::own_only_dir(&d)?;
    Ok(d)
}

/// Keep `t` where the history is kept now, then trim the oldest past the total bound. `Ok(false)`
/// when transcripts are off.
pub fn record(t: &Transcript) -> std::io::Result<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    let (on, keep, total) = settings();
    if !on {
        return Ok(false);
    }
    let d = dir_in(&crate::history::dir_for(keep)?)?;
    let mut rand = [0u8; 4];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut rand);
    }
    let name = format!(
        "{:013}-{}-{:02x}{:02x}{:02x}{:02x}",
        t.ended_ms, t.box_name, rand[0], rand[1], rand[2], rand[3]
    );
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(d.join(&name))?;
    f.write_all(t.header().as_bytes())?;
    f.write_all(&t.code)?;
    f.write_all(&t.stdout)?;
    f.write_all(&t.stderr)?;
    trim(&d, total);
    Ok(true)
}

/// The files of `d` oldest first (names start with the end time), with their sizes.
fn files_in(d: &Path) -> Vec<(PathBuf, u64)> {
    let Ok(rd) = std::fs::read_dir(d) else {
        return Vec::new();
    };
    let mut v: Vec<(PathBuf, u64)> = rd
        .flatten()
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            m.is_file().then(|| (e.path(), m.len()))
        })
        .collect();
    v.sort_by(|a, b| a.0.file_name().cmp(&b.0.file_name()));
    v
}

/// Remove the oldest files of `d` until it holds at most `total` bytes. Best effort: two writers
/// trimming at once may remove a few more than needed, never a file being written (it is the newest).
fn trim(d: &Path, total: u64) {
    let files = files_in(d);
    let mut held: u64 = files.iter().map(|(_, n)| n).sum();
    for (p, n) in files {
        if held <= total {
            break;
        }
        if std::fs::remove_file(&p).is_ok() {
            held = held.saturating_sub(n);
        }
    }
}

/// Every transcripts directory that exists: memory, and the disk one.
fn places() -> Vec<PathBuf> {
    crate::history::places_pub()
        .into_iter()
        .map(|d| d.join(DIR))
        .filter(|d| d.is_dir())
        .collect()
}

/// The newest `n` transcripts (of `box_name` when given), newest first.
pub fn read(box_name: Option<&str>, n: usize) -> Vec<Transcript> {
    let mut all: Vec<(PathBuf, u64)> = places().iter().flat_map(|d| files_in(d)).collect();
    all.sort_by(|a, b| b.0.file_name().cmp(&a.0.file_name()));
    let mut out = Vec::new();
    for (p, _) in all {
        if out.len() >= n {
            break;
        }
        let Ok(bytes) = std::fs::read(&p) else {
            continue;
        };
        if let Some(t) = Transcript::parse(&bytes) {
            if box_name.is_none_or(|b| b == t.box_name) {
                out.push(t);
            }
        }
    }
    out
}

/// Remove every transcript; returns how many there were.
pub fn clear() -> Result<usize, String> {
    let mut n = 0;
    for d in places() {
        for (p, _) in files_in(&d) {
            std::fs::remove_file(&p).map_err(|e| format!("clearing {}: {e}", p.display()))?;
            n += 1;
        }
    }
    Ok(n)
}

/// Move every transcript into the transcripts directory of `to` (a history directory), copying
/// across filesystems (tmpfs to disk). Returns how many moved.
pub fn move_to(to: &Path) -> Result<usize, String> {
    let dest = dir_in(to).map_err(|e| format!("making {}: {e}", to.display()))?;
    let mut moved = 0;
    for d in places() {
        if d == dest {
            continue;
        }
        for (p, _) in files_in(&d) {
            let Some(name) = p.file_name() else { continue };
            let target = dest.join(name);
            if std::fs::rename(&p, &target).is_err() {
                use std::os::unix::fs::OpenOptionsExt;
                let bytes =
                    std::fs::read(&p).map_err(|e| format!("reading {}: {e}", p.display()))?;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&target)
                    .map_err(|e| format!("writing {}: {e}", target.display()))?;
                f.write_all(&bytes)
                    .map_err(|e| format!("writing {}: {e}", target.display()))?;
                std::fs::remove_file(&p).map_err(|e| format!("removing {}: {e}", p.display()))?;
            }
            moved += 1;
        }
    }
    Ok(moved)
}

/// `kern sandbox record <box> [--exit N] [--language L]`: one call's transcript from stdin.
pub fn record_from_stdin(
    box_name: &str,
    language: &str,
    exit: i32,
) -> Result<(), crate::error::Error> {
    kern_common::BoxName::parse(box_name)
        .map_err(|_| crate::error::Error::Usage("sandbox record <box>: not a box name"))?;
    let mut stdin = std::io::stdin().lock();
    let t = read_frame(
        &mut stdin,
        box_name,
        language,
        exit,
        crate::history::now_ms(),
    )
    .map_err(crate::error::Error::Sandbox)?;
    record(&t).map_err(|e| crate::error::Error::Sandbox(format!("keeping the transcript: {e}")))?;
    Ok(())
}

/// The bytes of a recorded field, made safe for a terminal: control characters other than newline
/// and tab dropped, every line indented so nothing a box printed starts at column 0.
fn for_terminal(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len() + 16);
    for line in text.split('\n') {
        out.push_str("    ");
        out.extend(
            line.chars()
                .filter(|c| *c == '\t' || !kern_common::is_terminal_unsafe(*c)),
        );
        out.push('\n');
    }
    out
}

fn json_of(t: &Transcript) -> String {
    use kern_common::json_str;
    let s = |b: &[u8]| json_str(&String::from_utf8_lossy(b));
    format!(
        "{{\"schema\":1,\"ended_ms\":{},\"box\":{},\"language\":{},\"exit\":{},\"code\":{},\"stdout\":{},\"stderr\":{},\"truncated\":{{\"code\":{},\"stdout\":{},\"stderr\":{}}}}}",
        t.ended_ms,
        json_str(&t.box_name),
        json_str(&t.language),
        t.exit,
        s(&t.code),
        s(&t.stdout),
        s(&t.stderr),
        t.truncated[0],
        t.truncated[1],
        t.truncated[2],
    )
}

/// `kern sandbox show [<box>] [-n N] [--json]`.
pub fn show(box_name: Option<&str>, n: usize, json: bool) -> Result<(), crate::error::Error> {
    let rows = read(box_name, n);
    if json {
        for t in &rows {
            println!("{}", json_of(t));
        }
        return Ok(());
    }
    if rows.is_empty() {
        let (on, keep, _) = settings();
        if on {
            println!(
                "no transcript recorded{} (the SDKs record the code and output of each call; {}: {})",
                box_name.map(|b| format!(" for {b}")).unwrap_or_default(),
                keep.word(),
                keep.meaning()
            );
        } else {
            println!(
                "transcripts are off: [kern] sandbox_transcripts = false, or sandbox_history = \"off\""
            );
        }
        return Ok(());
    }
    for t in rows.iter().rev() {
        let cut = |i: usize| if t.truncated[i] { " (cut)" } else { "" };
        println!(
            "== {} {} {} exit {}",
            crate::history::local_datetime_pub(t.ended_ms),
            t.box_name,
            t.language,
            t.exit
        );
        println!("  code{}:", cut(0));
        print!("{}", for_terminal(&t.code));
        if !t.stdout.is_empty() {
            println!("  stdout{}:", cut(1));
            print!("{}", for_terminal(&t.stdout));
        }
        if !t.stderr.is_empty() {
            println!("  stderr{}:", cut(2));
            print!("{}", for_terminal(&t.stderr));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(code: &[u8], out: &[u8], err: &[u8]) -> Vec<u8> {
        let mut v = format!("v1 {} {} {}\n", code.len(), out.len(), err.len()).into_bytes();
        v.extend_from_slice(code);
        v.extend_from_slice(out);
        v.extend_from_slice(err);
        v
    }

    #[test]
    fn a_frame_reads_back_as_written_with_any_bytes_in_it() {
        let f = frame(b"print(1)\n", b"1\n\x00\x1b[2J", b"");
        let t = read_frame(&mut f.as_slice(), "pysbx-abc", "python", 0, 7);
        assert_eq!(
            t.as_ref()
                .map(|t| (t.code.as_slice(), t.stdout.as_slice(), t.truncated)),
            Ok((
                b"print(1)\n".as_slice(),
                b"1\n\x00\x1b[2J".as_slice(),
                [false; 3]
            ))
        );
        let Ok(t) = t else { return };
        let mut stored = t.header().into_bytes();
        stored.extend_from_slice(&t.code);
        stored.extend_from_slice(&t.stdout);
        stored.extend_from_slice(&t.stderr);
        assert_eq!(Transcript::parse(&stored), Some(t));
    }

    #[test]
    fn each_field_is_cut_to_its_bound_and_the_next_one_still_lines_up() {
        let big = vec![b'x'; MAX_STREAM + 10];
        let f = frame(b"c", &big, b"tail");
        let t = read_frame(&mut f.as_slice(), "b", "sh", 1, 0);
        assert_eq!(
            t.as_ref()
                .map(|t| (t.stdout.len(), t.stderr.as_slice(), t.truncated)),
            Ok((MAX_STREAM, b"tail".as_slice(), [false, true, false]))
        );
    }

    #[test]
    fn a_bad_frame_is_refused_not_guessed() {
        for bad in [
            b"".as_slice(),
            b"v2 1 1 1\nabc",
            b"v1 1 1\nab",
            b"v1 5 0 0\nab",
            b"v1 x 0 0\n",
            b"v1 2000000000 0 0\n",
        ] {
            assert!(
                read_frame(&mut &bad[..], "b", "sh", 0, 0).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_stored_file_that_does_not_add_up_is_not_read() {
        let t = Transcript {
            ended_ms: 1,
            box_name: "b".into(),
            language: "python".into(),
            exit: 0,
            code: b"abc".to_vec(),
            stdout: vec![],
            stderr: vec![],
            truncated: [false; 3],
        };
        let mut stored = t.header().into_bytes();
        stored.extend_from_slice(b"ab");
        assert_eq!(Transcript::parse(&stored), None);
    }

    #[test]
    fn output_reaches_the_terminal_without_its_escapes_and_indented() {
        let shown = for_terminal(b"ok\n\x1b[2Kerror: fake\x07");
        assert!(!shown.contains('\x1b') && !shown.contains('\x07'));
        assert!(shown.lines().all(|l| l.starts_with("    ")));
    }

    #[test]
    fn trimming_removes_the_oldest_first() {
        let dir = std::env::temp_dir().join(format!("kern-tr-trim-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        for (i, size) in [(1u64, 100usize), (2, 100), (3, 100)] {
            let _ = std::fs::write(dir.join(format!("{i:013}-b-0000")), vec![0u8; size]);
        }
        trim(&dir, 150);
        let left: Vec<String> = files_in(&dir)
            .iter()
            .filter_map(|(p, _)| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(left, vec!["0000000000003-b-0000".to_string()]);
    }
}
