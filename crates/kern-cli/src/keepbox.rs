//! Boxes that outlive their process: the store behind `kern box --keep`, `kern start` and `kern rm`.
//!
//! # Why this exists, and what it deliberately does not change
//!
//! A kern box is a process, and its writable layer is scratch under `$XDG_RUNTIME_DIR`: when the
//! process ends, both are gone. That is the documented model and it stays the default - nothing a
//! plain `kern box` runs leaves state behind. What was missing is the case a reader coming from
//! Docker expects and a Dev Containers client performs on every attach: stop a box, start it again,
//! and find the files where they were. There was no verb for it, and the one mechanism that could
//! have carried it (`--overlay-upper`, which the build uses) could be written ONCE and never reused,
//! because a used overlay workdir holds a mode-000 `work/work` that `remove_dir_all` cannot traverse
//! (measured: the second start failed with `Permission denied`).
//!
//! `--keep` is that case, asked for explicitly. It names the box's writable layer under
//! `$XDG_DATA_HOME/kern/boxes/<name>/`, which is a real filesystem rather than the runtime tmpfs, so
//! the layer survives a logout and a reboot and can hold the `user.*` attributes overlayfs needs for
//! its own markers (see `kern_isolation::mount_overlay_c`). Beside the layer sits the one thing a
//! restart cannot deduce: the command line that made the box.
//!
//! # The record is the ARGV, not a projection of it
//!
//! A box's posture is wide - mounts, caps, seccomp, AppArmor, Landlock, uid range, env file, ports,
//! pod, profiles, scratch, the workload argv. The registry already records most of it, for `kern ps`
//! and for `kern exec` to reproduce; but "most of it" is exactly the wrong amount for a restart,
//! because the one flag that is not in the record comes back as a box that is subtly not the box that
//! stopped. So the record is the argv the operator gave, verbatim and byte-for-byte (arguments are
//! not required to be UTF-8), plus the directory it was given in: `kern start` re-runs that command.
//! A flag added to `kern box` tomorrow is carried by this with no change here, which a field-by-field
//! copy could not promise.
//!
//! What a replay cannot promise is stated rather than papered over: a `-v` source that has since been
//! deleted, an `--env-file` that is gone, a `--secret` that moved. Those fail at start exactly as they
//! would have failed the first time, with kern's own message, and the box is left stopped.
//!
//! # Layout
//!
//! ```text
//! $XDG_DATA_HOME/kern/boxes/<name>/
//!   upper/        the box's writable layer (overlay upperdir); `diff` in the build's spelling
//!   work/         overlayfs's own workdir, cleared at every start
//!   box.rec       ONE record: `key=value` header (created, last_exit, image, cwd), a blank line,
//!                 then the `kern box` argv, NUL-separated, raw bytes
//! ```
//!
//! One directory per box, so `kern rm` is one removal; one record file, so a reader can never catch
//! the write half-done (see [`REC`]).

use std::io;
use std::path::{Path, PathBuf};

/// Where kept boxes live. Under `$XDG_DATA_HOME` (not the runtime dir) because the point of `--keep`
/// is a layer that is still there after a reboot; the fallbacks mirror [`crate::volume::volumes_dir`]
/// so the two kinds of persistent state sit side by side.
pub fn boxes_dir() -> PathBuf {
    if let Some(x) = crate::global_env("XDG_DATA_HOME") {
        return PathBuf::from(x).join("kern").join("boxes");
    }
    if let Some(h) = crate::global_env("HOME") {
        return PathBuf::from(h).join(".local/share/kern/boxes");
    }
    PathBuf::from(format!("/tmp/kern-boxes-{}", unsafe { libc::getuid() }))
}

/// The directory of the kept box called `name`, or `None` when the name is not one kern would accept
/// as a box name - which is also what makes it a single safe path component.
///
/// THE PREDICATE IS `BoxName::parse`, THE ONE `kern box` ITSELF USES, and it was
/// `valid_resource_name` first. Those two do not accept the same names: `valid_resource_name` caps
/// at 64 bytes where a box name may be 200, so `kern box <71-char-name> --keep` ran the box and
/// kept NOTHING, with no word said - MEASURED, and 71 bytes is not a corner case, it is the length
/// of `sentry-self-hosted-snuba-subscription-consumer-generic-metrics-counters`, the name that made
/// `BoxName::MAX_LEN` 200 in the first place. `parse` gives the same path safety: a name must start
/// with a letter, digit or `_`, so it is never `.`, `..` or a flag, and its charset has no `/`.
pub fn dir_of(name: &str) -> Option<PathBuf> {
    kern_common::BoxName::parse(name)
        .ok()
        .map(|_| boxes_dir().join(name))
}

/// Everything `kern start` needs that the argv does not carry.
#[derive(Debug, Default, Clone)]
pub struct Meta {
    /// Unix seconds when `--keep` first created this box.
    pub created: u64,
    /// The exit code of its last run, or `None` while it has never finished one.
    pub last_exit: Option<i32>,
    /// What it will run: the `--image` reference or the `--rootfs` path, DERIVED FROM THE ARGV by
    /// [`image_of`] rather than stored, so the row `kern ps -a` prints cannot disagree with the
    /// command `kern start` replays. It was a header field, and a record written by hand could then
    /// show `alpine:3.19` in `ps -a` while its argv said `--image something-else` (measured).
    pub image: String,
    /// The directory the `kern box` command was given in. A relative `-v ./data:/data` means nothing
    /// without it, and `kern start` run from elsewhere would resolve it against the wrong tree.
    pub cwd: String,
}

/// Create `dir` 0700: a box's layer holds whatever the workload wrote, and the argv can name a
/// `--secret` path or an `--env-file`.
fn mkdir_private(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Open a record file 0600, refusing to follow a symlink at the final component, so a planted
/// `box.rec` cannot redirect the write. Same rule as the build records.
fn open_private(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

/// Read a record file with a bound, refusing anything that is not a regular file and never
/// following a symlink at its name. `Ok(None)` when it is not there.
///
/// THE FLAGS ARE THE WHOLE POINT, and the first version had none of them: it was a plain
/// `File::open`, and the module's own comment claimed the build records' rule. MEASURED: a FIFO
/// planted at `box.rec` hung `kern ps -a` AND `kern start` for ever (`timeout 10` returned 124 for
/// both), because opening a FIFO for reading blocks until a writer arrives. `O_NONBLOCK` makes that
/// open return, `O_NOFOLLOW` refuses a symlink at the name, and the regular-file check on the OPEN
/// descriptor refuses the FIFO itself and anything else that is not a file. The reader is shared
/// with the build records ([`crate::openat2::read_regular_bytes`]) so there is one bounded read in
/// the crate and not three.
fn read_bounded(path: &Path, max: u64) -> io::Result<Option<Vec<u8>>> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | crate::openat2::READ_UNTRUSTED)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    crate::openat2::read_regular_bytes(&f, max).map(Some)
}

/// The most a record may hold: `ARG_MAX` is 2 MiB on Linux, nothing kern accepts is near it, and the
/// header above the argv is four short lines.
const REC_MAX: u64 = 2 * 1024 * 1024 + 64 * 1024;

/// The file both halves of the record live in, and the name of its temp.
///
/// ONE FILE, ONE `rename`, because a reader must never see HALF a record. The first version wrote
/// `box.argv` and `box.meta` in place, each truncated then filled, and both failure modes were
/// measured: 20 `kern start` of one kept box at once, and one of them answered "no kept box" -
/// it had read `box.argv` while the winner's replay was rewriting it, so the file was there and
/// empty. Two files plus two renames would fix that half and leave the other: a reader between the
/// two renames pairs a NEW argv with an OLD `cwd`, which replays the command from the wrong
/// directory. One file cannot be caught in either state.
const REC: &str = "box.rec";

/// Write (or rewrite) the argv and meta of the kept box at `dir`. The argv is NUL-separated raw
/// bytes, because an argument is not required to be UTF-8 and a lossy conversion would restart a box
/// with a different command than the one that was run.
pub fn write(dir: &Path, argv: &[std::ffi::OsString], meta: &Meta) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    mkdir_private(dir)?;
    let mut bytes = Vec::new();
    for a in argv {
        let raw = a.as_os_str().as_bytes();
        // An argument cannot contain a NUL (execve's own rule), so NUL is a separator no value can
        // forge. Stated as a check rather than assumed: a caller that built one by hand would
        // otherwise split one argument into two at start time.
        if raw.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an argument contains a NUL byte",
            ));
        }
        bytes.extend_from_slice(raw);
        bytes.push(0);
    }
    // THE HEADER, then a blank line, then the argv bytes. The header's values are `one_line`d, so
    // the separator cannot occur inside it and the split below cannot land in the middle of a
    // value; everything after it is raw and may hold any byte, including a newline.
    let mut body = format!(
        "created={}\nlast_exit={}\ncwd={}\n\n",
        meta.created,
        meta.last_exit.map_or(String::new(), |c| c.to_string()),
        one_line(&meta.cwd),
    )
    .into_bytes();
    body.extend_from_slice(&bytes);
    // Temp then `rename`, the same swap the build records use: a reader sees the old record or the
    // new one, never a truncated one, and a crash mid-write leaves the old record intact. The temp
    // is opened `O_NOFOLLOW` so a planted symlink cannot redirect the write, and the `rename`
    // replaces a symlinked `box.rec` itself rather than writing through it.
    // THE TEMP CARRIES THE WRITER'S PID, so two processes writing the same box's record (a
    // re-create and a `set_exit`, or two `kern start`s racing before one of them loses the name
    // claim) cannot interleave into one temp file and rename the mixture into place. A fixed name is
    // safe for a build record, which has exactly one writer for its whole life; a kept box's
    // directory has many writers over its life, so the pattern needed this.
    let tmp = dir.join(format!("box.rec.{}.tmp", std::process::id()));
    open_private(&tmp)?.write_all(&body)?;
    std::fs::rename(&tmp, dir.join(REC))
}

/// `\n`/`\r` out of a value, so one field cannot forge another. Same rule as the build records.
fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// The name of the lock file beside the record. Its CONTENT is only for the refusal's message; the
/// lock itself is the `flock`, which the kernel releases however the holder dies.
const LOCK: &str = "box.lock";

/// Take the kept layer at `dir` for this box, for as long as this process tree lives, or say who
/// has it.
///
/// WHY A LOCK ON THE LAYER AND NOT THE NAME CLAIM. The registry's name claim is what stops two boxes
/// sharing a NAME, and the layer is addressed by name, so it looked like enough. It is not, because
/// the registry and the layer live in different places: MEASURED, two ways, both of them things an
/// operator does.
///   * `kern box w1 --keep -d`, then `kern rename w1 w2`, then `kern start w1`: the registry entry
///     moved, the record did not, and the second box mounted the first's live layer. The kernel said
///     so itself: "overlayfs: upperdir is in-use as upperdir/workdir of another mount, accessing
///     files from both mounts will result in undefined behavior".
///   * One `$XDG_DATA_HOME`, two `$XDG_RUNTIME_DIR`s - which kern's own `ps` warning says a
///     `kern compose systemd` unit produces: two registries, one layer, same outcome. The second
///     start also clears `work/` under the live mount, because overlayfs requires an empty workdir.
///
/// `flock` AND NOT A PID FILE, because the holder of a detached box is a FORK of this process: the
/// lock belongs to the open file description, which a fork shares, so it outlives the launcher that
/// printed "started" and dies with the supervisor - including a `kill -9`, where a pid file would
/// have stayed behind and locked the layer for ever. The descriptor is leaked on purpose: closing it
/// is what releases the lock, and the lifetime that is wanted is "until this process exits".
pub fn hold_layer(dir: &Path) -> Result<(), crate::error::Error> {
    use std::io::{Read, Seek, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    mkdir_private(dir).map_err(|e| {
        crate::error::Error::Sandbox(format!("--keep: cannot use {}: {e}", dir.display()))
    })?;
    let mut f = std::fs::OpenOptions::new()
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(LOCK))
        .map_err(|e| {
            crate::error::Error::Sandbox(format!(
                "--keep: cannot open the layer lock {}: {e}",
                dir.join(LOCK).display()
            ))
        })?;
    // SAFETY: `flock` on a descriptor this function owns. `LOCK_NB` so a layer that is in use is an
    // immediate refusal and not a box that hangs.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(crate::error::Error::Sandbox(format!(
                "--keep: cannot lock the layer {}: {e}",
                dir.display()
            )));
        }
        let mut who = String::new();
        let _ = f.read_to_string(&mut who);
        let who = who.trim();
        return Err(crate::error::Error::AlreadyRunning(format!(
            "the kept layer {} is in use by another box{}, and two boxes cannot write one overlay \
             layer (the kernel calls it undefined behaviour). `kern ps` lists what is running; one \
             of the two has to stop first",
            dir.display(),
            if who.is_empty() {
                String::new()
            } else {
                format!(" (pid {who})")
            }
        )));
    }
    // For the message the NEXT caller gets. Best effort: the lock is the fact, this is the courtesy.
    let _ = f.set_len(0);
    let _ = f.seek(io::SeekFrom::Start(0));
    let _ = write!(f, "{}", std::process::id());
    let _ = f.flush();
    // LEAKED ON PURPOSE: see the note above. `into_raw_fd` keeps the descriptor open with no owner,
    // so the lock lives until this process (or the fork that supervises the box) exits.
    use std::os::unix::io::IntoRawFd;
    let _ = f.into_raw_fd();
    Ok(())
}

/// Record this run's exit code against the kept box at `dir`, leaving the argv alone. Best effort:
/// a box whose record cannot be updated is still a box the operator can start.
pub fn set_exit(dir: &Path, code: i32) {
    if let Some((argv, mut meta)) = read(dir) {
        meta.last_exit = Some(code);
        let _ = write(dir, &argv, &meta);
    }
}

/// The argv and meta of the kept box at `dir`, or `None` when there is no readable record there.
///
/// A record that is present but unreadable, oversized or missing its argv answers `None` rather than
/// a guess: `kern start` then says it cannot restart this box, which is the honest outcome for a
/// record somebody edited.
pub fn read(dir: &Path) -> Option<(Vec<std::ffi::OsString>, Meta)> {
    use std::os::unix::ffi::OsStringExt;
    let raw = read_bounded(&dir.join(REC), REC_MAX).ok()??;
    // The FIRST blank line ends the header; the argv is everything after it. A record with no
    // separator at all is one somebody truncated or wrote by hand: no argv, so no restart.
    let cut = raw.windows(2).position(|w| w == b"\n\n")?;
    let (head, tail) = raw.split_at(cut);
    let tail = tail.get(2..).unwrap_or(&[]);
    // `split` on the terminator leaves a trailing empty element; an empty argv is not a command.
    let argv: Vec<std::ffi::OsString> = tail
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| std::ffi::OsString::from_vec(a.to_vec()))
        .collect();
    if argv.is_empty() {
        return None;
    }
    let mut meta = Meta {
        image: image_of(&argv),
        ..Meta::default()
    };
    for line in String::from_utf8_lossy(head).lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "created" => meta.created = v.parse().unwrap_or(0),
            "last_exit" => meta.last_exit = v.parse().ok(),
            "cwd" => meta.cwd = v.to_string(),
            // `image=` was a header field until it was measured that a hand-written record could
            // make `ps -a` show one image and run another. It is derived below and ignored here.
            _ => {}
        }
    }
    Some((argv, meta))
}

/// One kept box, as `kern ps -a` lists it.
#[derive(Debug, Clone)]
pub struct KeptBox {
    pub name: String,
    pub meta: Meta,
    /// The workload argv, for the COMMAND column: everything after the `--` of the recorded command.
    pub command: String,
}

/// Every kept box whose NAME passes `name_ok`, which is asked before the record is opened. Order is
/// the directory's; the caller sorts.
///
/// The predicate is on the dirent, where a name is free: reading a record costs an `openat`, two
/// `read`s and a parse, and `kern ps -a --filter name=x` dropped every row it had just read.
/// MEASURED on the first version, 1000 kept boxes: a `--filter name=` that matched nothing still
/// cost 5.4 ms.
pub fn list_matching(name_ok: impl Fn(&str) -> bool) -> Vec<KeptBox> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(boxes_dir()) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name_ok(&name) {
            continue;
        }
        // The same predicate as `dir_of`, so a name kern accepted and kept is a name kern lists.
        if kern_common::BoxName::parse(&name).is_err() {
            continue; // not a name kern made
        }
        let Some((argv, meta)) = read(&e.path()) else {
            continue;
        };
        out.push(KeptBox {
            command: workload_of(&argv),
            name,
            meta,
        });
    }
    out
}

/// What the recorded command will RUN: the value of `--image` or `--rootfs`, in either spelling
/// (`--image x` and `--image=x`), empty when the argv names neither.
///
/// Read out of the argv and never stored, for the same reason [`workload_of`] is: the row a reader
/// sees in `kern ps -a` before typing `kern start` has to be a fact about the command that will run.
/// Stops at the workload separator, so `-- sh -c "--image lies"` cannot supply it.
pub fn image_of(argv: &[std::ffi::OsString]) -> String {
    let mut it = argv.iter().take_while(|a| a.as_os_str() != "--");
    while let Some(a) = it.next() {
        let Some(text) = a.to_str() else { continue };
        for flag in ["--image", "--rootfs"] {
            if text == flag {
                if let Some(v) = it.next() {
                    return v.to_string_lossy().into_owned();
                }
                return String::new();
            }
            if let Some(v) = text.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
                return v.to_string();
            }
        }
    }
    String::new()
}

/// The workload part of a recorded `kern box` argv: what follows the first bare `--`, joined with
/// spaces. Empty when the command line named none, which means the image's own entrypoint ran.
pub fn workload_of(argv: &[std::ffi::OsString]) -> String {
    let mut it = argv.iter().skip_while(|a| a.as_os_str() != "--");
    it.next(); // the `--` itself
    it.map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Remove the kept box `name`: its layer and its record, in one removal.
///
/// THE LAYER IS NOT REMOVABLE BY A PLAIN `remove_dir_all` and that is the normal case, not the odd
/// one: a used overlay workdir holds `work/work` at mode 000, and a `--uid-range` box leaves files
/// owned by subordinate uids. `remove_build_tree` chmods what it walks and retries inside an
/// id-mapped user namespace, which is the same remover `kern gc` uses on build trees.
pub fn remove(name: &str) -> Result<(), crate::error::Error> {
    let Some(dir) = dir_of(name) else {
        return Err(crate::error::Error::Sandbox(format!(
            "'{name}' is not a box name kern would have made"
        )));
    };
    // `symlink_metadata`, NOT `is_dir`: `is_dir` follows a symlink, and `remove_build_tree` chmods
    // every directory it walks to 0700 before removing it. MEASURED on the first version: with
    // `boxes/<name>` replaced by a link to another tree, `kern rm <name>` chmodded that whole tree
    // to 0700 (setgid and sticky stripped), unlinked the link, and printed "removed kept box" with
    // exit 0 - a false success that changed permissions outside the store. A kept box is a
    // DIRECTORY kern made; anything else at that name is reported, not walked.
    match std::fs::symlink_metadata(&dir) {
        Err(_) => {
            return Err(crate::error::Error::NotRunning(format!(
                "no kept box '{name}' (`kern ps -a` lists them; a box without `--keep` leaves nothing to remove)"
            )))
        }
        Ok(m) if !m.is_dir() => {
            return Err(crate::error::Error::Sandbox(format!(
                "kept box '{name}': {} is {}, not a directory kern made, so it is left alone. \
                 Remove it yourself if you put it there",
                dir.display(),
                if m.file_type().is_symlink() {
                    "a symlink"
                } else {
                    "not a directory"
                }
            )))
        }
        Ok(_) => {}
    }
    crate::commands::remove_build_tree(&dir);
    if dir.exists() {
        return Err(crate::error::Error::Sandbox(format!(
            "kept box '{name}': its directory {} could not be removed",
            dir.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// A temp `XDG_DATA_HOME` for one test, restored after it. `env_guard` serialises the tests that
    /// mutate the environment, which is the rule this repo already applies to every such test.
    fn with_tmp_home(body: impl FnOnce(PathBuf)) {
        let _g = crate::env_guard();
        let home = std::env::temp_dir().join(format!("kern-keepbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("tmp home");
        crate::set_global_env("XDG_DATA_HOME", &home);
        body(home.clone());
        crate::unset_global_env("XDG_DATA_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// THE ARGV SURVIVES BYTE FOR BYTE, including an argument that is not UTF-8 and one that holds a
    /// space, because `kern start` re-runs it: a lossy round trip would start a box with a command
    /// the operator never gave. The separator is NUL, which no argument can contain.
    #[test]
    fn the_recorded_argv_round_trips_byte_for_byte() {
        use std::os::unix::ffi::OsStringExt;
        with_tmp_home(|_| {
            let dir = dir_of("web").expect("a valid name");
            let argv = vec![
                OsString::from("box"),
                OsString::from("web"),
                OsString::from("--image"),
                OsString::from("alpine:3.19"),
                OsString::from("-v"),
                OsString::from("/tmp/a b:/data"),
                OsString::from("--"),
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from("echo hi"),
                OsString::from_vec(vec![0xff, 0xfe]),
            ];
            let meta = Meta {
                created: 1_700_000_000,
                last_exit: None,
                image: "alpine:3.19".into(),
                cwd: "/home/x/p".into(),
            };
            write(&dir, &argv, &meta).expect("write");
            let (back, m) = read(&dir).expect("read");
            assert_eq!(back, argv, "the argv came back changed");
            assert_eq!(m.created, 1_700_000_000);
            assert_eq!(m.last_exit, None);
            assert_eq!(m.image, "alpine:3.19");
            assert_eq!(m.cwd, "/home/x/p");
            // The workload is what follows the `--`, and the non-UTF-8 argument is part of it.
            assert!(workload_of(&argv).starts_with("sh -c echo hi"));
            // 0600 and 0700: the argv can name a `--secret` path, the layer holds the workload's files.
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.join(REC))
                    .expect("stat")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&dir).expect("stat").permissions().mode() & 0o777,
                0o700
            );
        });
    }

    /// AN EXIT CODE IS RECORDED WITHOUT TOUCHING THE ARGV, because the two are written by different
    /// moments: the argv at creation, the code every time a run ends.
    #[test]
    fn recording_an_exit_leaves_the_argv_alone() {
        with_tmp_home(|_| {
            let dir = dir_of("api").expect("a valid name");
            let argv = vec![OsString::from("box"), OsString::from("api")];
            write(&dir, &argv, &Meta::default()).expect("write");
            set_exit(&dir, 137);
            let (back, m) = read(&dir).expect("read");
            assert_eq!(back, argv);
            assert_eq!(m.last_exit, Some(137));
            // And again, with a different code: the field is replaced, not appended to.
            set_exit(&dir, 0);
            assert_eq!(read(&dir).expect("read").1.last_exit, Some(0));
        });
    }

    /// `kern rm` DOES NOT WALK A SYMLINK PLANTED AT A BOX'S NAME.
    ///
    /// MEASURED on the first version, which asked `is_dir()` (that follows a link) and then called
    /// `remove_build_tree`, whose job is to chmod every directory it walks to 0700 before removing
    /// it: with `boxes/<name>` replaced by a link to another tree, `kern rm <name>` chmodded that
    /// tree to 0700, unlinked the link, and printed "removed kept box" with exit 0.
    #[test]
    fn removing_a_box_whose_name_is_a_symlink_leaves_the_target_alone() {
        with_tmp_home(|home| {
            let target = home.join("not-a-kept-box");
            std::fs::create_dir_all(target.join("sub")).expect("mkdir");
            let mode = |p: &Path| {
                use std::os::unix::fs::PermissionsExt;
                std::fs::metadata(p).expect("stat").permissions().mode() & 0o777
            };
            for p in [&target, &target.join("sub")] {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            }
            let dir = dir_of("victim").expect("a valid name");
            std::fs::create_dir_all(dir.parent().expect("the store")).expect("mkdir");
            std::os::unix::fs::symlink(&target, &dir).expect("plant the link");
            let err = remove("victim").expect_err("a symlink is not a kept box");
            assert!(format!("{err}").contains("is a symlink"), "{err}");
            assert_eq!(mode(&target), 0o755, "the target's mode must not change");
            assert_eq!(mode(&target.join("sub")), 0o755, "nor its children's");
            assert!(
                std::fs::symlink_metadata(&dir).is_ok(),
                "the link itself is left where it was, for whoever put it there"
            );
        });
    }

    /// A READER NEVER CATCHES THE WRITE HALF-DONE, which is the reason the record is one file
    /// renamed into place rather than two files filled in place.
    ///
    /// MEASURED on the first version: 20 `kern start` of one kept box at once, and one of them
    /// answered "no kept box" - it had read `box.argv` while the winner's replay was rewriting it,
    /// so the file existed and was empty. This is that race at the unit: one thread rewrites the
    /// record in a loop while another reads it, and EVERY read must answer with a complete record,
    /// either the old one or the new one. With an in-place write it answers `None`.
    #[test]
    fn a_concurrent_reader_sees_a_whole_record_or_the_old_one_never_half() {
        with_tmp_home(|_| {
            let dir = dir_of("race").expect("a valid name");
            let short = vec![OsString::from("box"), OsString::from("race")];
            let long: Vec<OsString> = std::iter::once(OsString::from("box"))
                .chain(std::iter::once(OsString::from("race")))
                // A long tail, so the two records differ in SIZE: an in-place write of the short one
                // over the long one leaves a reader a valid prefix, and of the long one over the
                // short a reader catches it part-written. Both are the defect.
                .chain((0..200).map(|i| OsString::from(format!("--label=k{i}=v{i}"))))
                .collect();
            write(&dir, &long, &Meta::default()).expect("write");
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let writer = {
                let (dir, stop) = (dir.clone(), std::sync::Arc::clone(&stop));
                let (short, long) = (short.clone(), long.clone());
                std::thread::spawn(move || {
                    let mut i = 0u32;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let argv = if i % 2 == 0 { &short } else { &long };
                        let _ = write(&dir, argv, &Meta::default());
                        i = i.wrapping_add(1);
                    }
                })
            };
            let mut reads = 0u32;
            let mut half = 0u32;
            for _ in 0..4000 {
                match read(&dir) {
                    // Whatever we got must be ONE of the two records, whole: `box race` then either
                    // nothing or the full 200 labels. A prefix of the long one is a torn read.
                    Some((argv, _)) => {
                        let ok = argv == short || argv == long;
                        if !ok {
                            half += 1;
                        }
                        reads += 1;
                    }
                    // `None` means the record was not readable at all, which is the measured failure.
                    None => half += 1,
                }
            }
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = writer.join();
            assert!(
                reads > 0,
                "the reader never read anything, so this proves nothing"
            );
            assert_eq!(
                half,
                0,
                "{half} of {} reads saw a record that was neither the old one nor the new one",
                reads + half
            );
        });
    }

    /// EVERY NAME `kern box` ACCEPTS HAS A LAYER, which is not what the first version did.
    ///
    /// MEASURED: `dir_of` validated with `valid_resource_name`, which caps at 64 bytes, while a box
    /// name may be 200 - so `kern box <71-char-name> --keep` ran the box, kept nothing and said
    /// nothing. 71 bytes is the length of the compose service name that made the limit 200.
    #[test]
    fn a_name_kern_accepts_as_a_box_is_a_name_that_can_be_kept() {
        // `with_tmp_home` because `dir_of` reads the process-global `XDG_DATA_HOME`, and this
        // binary's tests run in threads: the guard in `main.rs` catches a test that reads it
        // without the lock, which is how this one was written the first time.
        with_tmp_home(|_| {
            let long = format!("s{}", "a".repeat(70));
            assert_eq!(long.len(), 71);
            for name in [
                long.as_str(),
                "web",
                "a",
                "_x",
                "web.1",
                "web-1",
                "web..1",
                &"n".repeat(200),
            ] {
                assert!(
                    kern_common::BoxName::parse(name).is_ok(),
                    "{name}: this test's own premise is wrong"
                );
                let dir = dir_of(name).unwrap_or_else(|| panic!("{name} has no layer directory"));
                // Still ONE path component under the store, which is the other half of the predicate.
                assert_eq!(dir.parent(), Some(boxes_dir().as_path()));
                assert_eq!(dir.file_name().and_then(|n| n.to_str()), Some(name));
            }
            // And what `kern box` refuses has no directory either way.
            for name in ["", ".", "..", "../escape", "-rf", "a/b", &"n".repeat(201)] {
                assert!(kern_common::BoxName::parse(name).is_err(), "{name}");
                assert!(dir_of(name).is_none(), "{name}");
            }
        });
    }

    /// A RECORD THAT IS NOT A REGULAR FILE IS REFUSED, AND REFUSED WITHOUT BLOCKING.
    ///
    /// MEASURED on the first version, which opened the record with a plain `File::open`: a FIFO
    /// planted at `box.rec` hung `kern ps -a` and `kern start` for ever (`timeout 10` returned 124
    /// for both), because opening a FIFO to read blocks until a writer arrives. A symlink there was
    /// followed, so the record could be read from anywhere the user could read.
    #[test]
    fn a_record_that_is_a_fifo_or_a_symlink_is_refused_not_followed() {
        with_tmp_home(|home| {
            let boxes = home.join("kern/boxes");
            // A FIFO at the record's name. The read must RETURN, which is what this asserts by
            // completing at all: a blocking open would hang the test.
            let fifo = boxes.join("fifo");
            std::fs::create_dir_all(&fifo).expect("mkdir");
            let path = fifo.join(REC);
            let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("cstring");
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
            assert!(read(&fifo).is_none(), "a FIFO is not a record");
            // A symlink at the record's name, pointing at a file that IS a valid record elsewhere:
            // following it would answer with that record under this box's name.
            let real = home.join("elsewhere.rec");
            std::fs::write(&real, b"created=1\n\nbox\0other\0").expect("write");
            let link = boxes.join("link");
            std::fs::create_dir_all(&link).expect("mkdir");
            std::os::unix::fs::symlink(&real, link.join(REC)).expect("symlink");
            assert!(read(&link).is_none(), "a symlink is not followed");
            // Neither appears in the listing, and a real one beside them does.
            let good = dir_of("real").expect("a valid name");
            write(
                &good,
                &[OsString::from("box"), OsString::from("real")],
                &Meta::default(),
            )
            .expect("write");
            let names: Vec<String> = list_matching(|_| true)
                .into_iter()
                .map(|k| k.name)
                .collect();
            assert_eq!(names, ["real"], "only the readable record is a row");
        });
    }

    /// A RECORD NOBODY WROTE IS NOT A BOX. An empty argv, a missing argv file and a directory whose
    /// name kern would not have made all answer `None`/skip rather than becoming a row in `kern ps -a`
    /// or something `kern start` tries to run.
    #[test]
    fn an_unreadable_or_forged_record_is_not_listed_and_not_started() {
        with_tmp_home(|home| {
            let boxes = home.join("kern/boxes");
            // No argv at all.
            std::fs::create_dir_all(boxes.join("empty")).expect("mkdir");
            assert!(read(&boxes.join("empty")).is_none());
            // An argv of nothing but separators.
            std::fs::create_dir_all(boxes.join("nulls")).expect("mkdir");
            std::fs::write(boxes.join("nulls").join(REC), b"created=1\n\n\0\0\0").expect("write");
            assert!(read(&boxes.join("nulls")).is_none());
            // A header with no blank line after it: a record somebody truncated. No argv, no start.
            std::fs::create_dir_all(boxes.join("cut")).expect("mkdir");
            std::fs::write(boxes.join("cut").join(REC), b"created=1\nimage=alpine\n")
                .expect("write");
            assert!(read(&boxes.join("cut")).is_none());
            // A ZERO-BYTE record, which is what an interrupted in-place write used to leave behind.
            std::fs::create_dir_all(boxes.join("zero")).expect("mkdir");
            std::fs::write(boxes.join("zero").join(REC), b"").expect("write");
            assert!(read(&boxes.join("zero")).is_none());
            // A name that is not a box name: not a path component kern would have made.
            assert!(dir_of("../escape").is_none());
            assert!(dir_of("").is_none());
            // One real record beside them, so the listing is not empty for an unrelated reason.
            let good = dir_of("real").expect("a valid name");
            write(
                &good,
                &[OsString::from("box"), OsString::from("real")],
                &Meta::default(),
            )
            .expect("write");
            let names: Vec<String> = list_matching(|_| true)
                .into_iter()
                .map(|b| b.name)
                .collect();
            assert_eq!(
                names,
                vec!["real".to_string()],
                "only the readable record is listed"
            );
        });
    }

    /// REMOVING ONE THAT IS NOT THERE SAYS SO, and the message names what `--keep` means rather than
    /// leaving the reader to wonder whether the box ever existed.
    #[test]
    fn removing_a_box_that_was_never_kept_names_the_reason() {
        with_tmp_home(|_| {
            let err = remove("ghost").expect_err("nothing to remove");
            let said = format!("{err}");
            assert!(said.contains("no kept box 'ghost'"), "{said}");
            assert!(said.contains("--keep"), "{said}");
            assert!(remove("../escape").is_err(), "a bad name is refused");
        });
    }

    /// THE WORKLOAD COLUMN IS WHAT FOLLOWS THE `--`, and a command line that named none says nothing
    /// rather than showing kern's own flags as if the box had run them.
    #[test]
    fn the_workload_column_is_only_what_followed_the_separator() {
        let flags_only = vec![
            OsString::from("box"),
            OsString::from("web"),
            OsString::from("--image"),
            OsString::from("nginx"),
        ];
        assert_eq!(workload_of(&flags_only), "");
        let with_cmd = vec![
            OsString::from("box"),
            OsString::from("web"),
            OsString::from("--"),
            OsString::from("nginx"),
            OsString::from("-g"),
            OsString::from("daemon off;"),
        ];
        assert_eq!(workload_of(&with_cmd), "nginx -g daemon off;");
    }
}
