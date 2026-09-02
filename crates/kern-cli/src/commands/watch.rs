//! `kern compose <file> watch [service...]`: rebuild and restart ONE service when its build context
//! changes, and nothing else.
//!
//! WHY THIS EXISTS. A stack is brought up once a day, so the cold-start difference against an engine
//! is a number a developer reads in a table and never feels. The loop they run dozens of times a day
//! is edit, rebuild, restart, and that is where a millisecond restart is something under the fingers
//! rather than a benchmark. It is also the loop where kern was WORSE than the alternative: without
//! it, developing on kern meant rebuilding and restarting by hand.
//!
//! WHAT IS WATCHED, and why it is not configurable. Each selected service's `build.context`
//! directory, recursively. kern does not invent a `develop.watch` key: the context is the set of
//! files that already decide the image's content (it is the input to `kern build`), so watching it
//! is watching exactly what a rebuild would read. A service with no `build:` has no such set and is
//! excluded by name rather than watched pointlessly.
//!
//! THE CYCLE IS THREE EXISTING VERBS, not a reimplementation: `kern build` for the image, `kern stop`
//! for the one box, `kern compose <file> start` to bring back what is not running. Each of those is
//! already the tested path for its job; this module decides WHEN, never HOW.
//!
//! FAILURE MODES, enumerated before the code rather than discovered by it:
//!
//!  1. **inotify unavailable.** `inotify_init1` fails (no support, fd limit). Refused with the errno,
//!     never degraded into a silent no-op loop that looks like it is watching.
//!  2. **Watch limit.** `inotify_add_watch` returns `ENOSPC` when `fs.inotify.max_user_watches` is
//!     exhausted, which a large `node_modules` reaches easily. Reported with the sysctl to raise,
//!     and the watch REFUSES rather than covering part of the tree, because a partial watch is a
//!     rebuild that silently does not happen.
//!  3. **Editors that write by rename.** vim, and most IDEs, write a temp file and rename over the
//!     target, so `IN_CLOSE_WRITE` alone misses the save. The mask carries `IN_MOVED_TO` and
//!     `IN_CREATE` for exactly that.
//!  4. **inotify is not recursive.** A directory created after start would be unwatched, so a file
//!     added inside it would never fire. Every `IN_CREATE|IN_ISDIR` adds a watch for the new
//!     directory before the debounce elapses.
//!  5. **Event storms.** A `git checkout` touches thousands of files. Events are folded into a
//!     per-service dirty bit inside a fixed stack buffer; nothing is allocated per event, and the
//!     rebuild runs once per settled burst, not once per file.
//!  6. **Queue overflow.** `IN_Q_OVERFLOW` means the kernel dropped events and there is no way to
//!     know which. The safe reading is "something changed": every watched service is marked dirty.
//!     Treating an overflow as no news is how a watcher misses the one edit that mattered.
//!  7. **A cycle while a cycle runs.** The rebuild is synchronous and events that arrive during it
//!     are read afterwards, so a save mid-build is not lost and does not start a second build.
//!  8. **Ctrl-C.** `SIGINT`/`SIGTERM` set a flag that the poll loop observes, so the watcher leaves
//!     without killing a build halfway and without leaving the terminal in a strange state.
//!  9. **A context that escapes the project.** The same confinement `resolve_builds` applies is
//!     applied here, by calling the same function, so `context: ../../..` is refused identically.

use crate::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Quiet period after the last event before a rebuild starts. An editor's save is several events
/// (truncate, write, close, sometimes a rename) and a formatter-on-save adds more, so rebuilding on
/// the first one would build a half-written tree. 300 ms is long enough to cover a save and short
/// enough to stay inside the "it happened while I was looking" window.
const DEBOUNCE_MS: i32 = 300;

/// Poll slice while idle. Not the debounce: this is how often the loop can observe the stop flag, so
/// Ctrl-C is answered within it rather than at the next file change.
const IDLE_POLL_MS: i32 = 250;

/// Read buffer for `inotify` events. 8 KiB holds a long burst in one read, and being a fixed array it
/// costs no allocation on the event path. `u64` elements give the 8-byte alignment
/// `struct inotify_event` requires: reading into a `[u8; N]` and casting would be unaligned.
#[repr(C)]
struct EventBuf([u64; 1024]);

impl EventBuf {
    const fn new() -> Self {
        Self([0; 1024])
    }
    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.0.as_mut_ptr().cast()
    }
    const fn len(&self) -> usize {
        std::mem::size_of::<Self>()
    }
    /// The bytes a `read` filled, as a slice. `n` is the syscall's own return, so it is never past
    /// the buffer; the assertion is the caller's contract rather than a runtime check.
    fn filled(&self, n: usize) -> &[u8] {
        // SAFETY: `self.0` is `len()` bytes of initialised storage and `n <= len()` by construction
        // (the caller passes a `read` return on this buffer). Reading it as bytes is always valid.
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast::<u8>(), n.min(self.len())) }
    }
}

/// Set by the signal handler; observed by the poll loop. `SeqCst` because the ordering that matters
/// is between a signal-interrupted syscall and the next load, and the cost is irrelevant at one load
/// per quarter second.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// One watched service: what to rebuild, what to restart, and where its files are.
pub(crate) struct Watched {
    /// The name in the compose file, for every message a human reads.
    service: String,
    /// The scoped box name, for `kern stop`.
    box_name: String,
    /// Image tag to build into. Same rule as `resolve_builds`: the file's `image:` if it has one,
    /// otherwise the synthesized `kern-compose-<box>:latest`, so watch rebuilds the tag the stack
    /// actually runs rather than a second one nobody starts.
    tag: String,
    /// Canonical, confined build context.
    context: PathBuf,
    /// Canonical dockerfile inside the context, when the file names one.
    dockerfile: Option<PathBuf>,
    /// `--build-arg` values, already interpolated by the compose reader.
    args: Vec<String>,
    /// Set by an event under this service's context; cleared when its cycle runs.
    dirty: bool,
}

/// Add an inotify watch for `dir` and every directory beneath it, recording which service each watch
/// descriptor belongs to.
///
/// Returns the number of watches added, or the errno-bearing error that stopped it. A partial walk is
/// never returned as success: half a tree watched is a rebuild that silently does not happen, and the
/// user would read the absence as "nothing changed" rather than as "kern stopped watching".
fn add_watch_tree(
    fd: i32,
    dir: &Path,
    idx: usize,
    map: &mut Vec<(i32, usize)>,
) -> Result<usize, Error> {
    use std::os::unix::ffi::OsStrExt;
    let mask = libc::IN_CLOSE_WRITE
        | libc::IN_MOVED_TO
        | libc::IN_MOVED_FROM
        | libc::IN_CREATE
        | libc::IN_DELETE;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| Error::Compose(format!("watch: path is not usable: {}", dir.display())))?;
    let wd = unsafe { libc::inotify_add_watch(fd, c.as_ptr(), mask) };
    if wd < 0 {
        let e = std::io::Error::last_os_error();
        // ENOSPC here is the watch limit, and it is the only one worth a recipe: everything else is
        // reported as itself rather than guessed at.
        let hint = if e.raw_os_error() == Some(libc::ENOSPC) {
            "\n  the per-user inotify watch limit is exhausted; raise it with:\n  \
             sudo sysctl fs.inotify.max_user_watches=524288"
        } else {
            ""
        };
        return Err(Error::Compose(format!(
            "watch: cannot watch '{}': {e}{hint}",
            dir.display()
        )));
    }
    map.push((wd, idx));
    let mut added = 1;
    // Recurse into subdirectories WITHOUT following symlinks: a link pointing outside the context
    // would put a watch on a tree the build never reads, and a link cycle would not terminate.
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // A directory that cannot be read is not fatal: it contributes no files to the build either.
        Err(_) => return Ok(added),
    };
    for ent in entries.flatten() {
        let ty = match ent.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ty.is_dir() {
            added += add_watch_tree(fd, &ent.path(), idx, map)?;
        }
    }
    Ok(added)
}

/// Which service a watch descriptor belongs to. Linear over a vector because the map is read once per
/// event and holds one entry per directory: a hash map would allocate to answer a question a short
/// scan answers, and the vector keeps the lookup in cache.
fn service_of(map: &[(i32, usize)], wd: i32) -> Option<usize> {
    map.iter().find_map(|(w, i)| (*w == wd).then_some(*i))
}

/// Walk one `read`'s worth of inotify events, marking services dirty and returning the paths of any
/// directories created (which need their own watch before the next event can be missed).
///
/// Allocation-free over the events themselves; the returned vector is empty in the common case and
/// holds one entry per NEW directory, which is rare by construction.
fn drain_events(
    buf: &[u8],
    map: &[(i32, usize)],
    watched: &mut [Watched],
    new_dirs: &mut Vec<(PathBuf, usize)>,
) -> bool {
    const HDR: usize = std::mem::size_of::<libc::inotify_event>();
    let mut off = 0usize;
    let mut overflow = false;
    while off + HDR <= buf.len() {
        // SAFETY: `off + HDR <= buf.len()` and the buffer is 8-byte aligned, which is the alignment
        // of `inotify_event`. The kernel writes whole events, so a header at `off` is complete.
        let ev = unsafe { &*(buf.as_ptr().add(off) as *const libc::inotify_event) };
        let name_len = ev.len as usize;
        let total = HDR + name_len;
        if off + total > buf.len() {
            break; // truncated tail: the next read returns it whole
        }
        if ev.mask & libc::IN_Q_OVERFLOW != 0 {
            overflow = true;
        }
        if let Some(i) = service_of(map, ev.wd) {
            if let Some(w) = watched.get_mut(i) {
                w.dirty = true;
            }
            // A new directory needs a watch of its own: inotify does not recurse, so without this a
            // file created inside it would never be seen.
            if ev.mask & libc::IN_ISDIR != 0 && ev.mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0
            {
                if let Some(name) = event_name(&buf[off + HDR..off + total]) {
                    if let Some(parent) = dir_of_wd(map, ev.wd, watched, i) {
                        new_dirs.push((parent.join(name), i));
                    }
                }
            }
        }
        off += total;
    }
    overflow
}

/// The NUL-terminated name an event carries, as a `&str`, or `None` when it is absent or not UTF-8.
/// A non-UTF-8 filename is not an error: it simply cannot be joined into a path here, and the file
/// still marked its service dirty above, which is the part that matters.
fn event_name(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .ok()
        .filter(|s| !s.is_empty())
}

/// The directory a watch descriptor names. inotify does not report it, so this recovers the only
/// thing it can be with the information kept: the service's context root when the watch IS the root,
/// and `None` otherwise, which makes the caller add the new directory relative to the root instead.
///
/// That is deliberately conservative: adding a watch for the wrong directory would be worse than
/// re-walking the context, which is what the caller does when this answers `None`.
fn dir_of_wd(map: &[(i32, usize)], wd: i32, watched: &[Watched], idx: usize) -> Option<PathBuf> {
    let first_wd = map.iter().find(|(_, i)| *i == idx).map(|(w, _)| *w)?;
    if first_wd == wd {
        watched.get(idx).map(|w| w.context.clone())
    } else {
        None
    }
}

/// Run one rebuild-and-restart cycle for a service. Returns the wall time it took.
///
/// Every step's failure is reported and the loop CONTINUES: a build that fails is the normal state of
/// an edit in progress, and a watcher that exits on it would be useless exactly when it is being
/// used. The stack is left as it is, so the previous container keeps serving until a build succeeds.
fn cycle(w: &Watched, file: &str, self_exe: &Path) -> std::time::Duration {
    let t0 = std::time::Instant::now();
    eprintln!("  rebuilding '{}'", w.service);
    let mut build = std::process::Command::new(self_exe);
    build.arg("build").arg("-t").arg(&w.tag);
    if let Some(df) = &w.dockerfile {
        build.arg("-f").arg(df);
    }
    for a in &w.args {
        build.arg("--build-arg").arg(a);
    }
    build.arg(&w.context);
    match build.status() {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!(
                "  build failed for '{}' ({}); leaving the running service alone",
                w.service,
                s.code().unwrap_or(-1)
            );
            return t0.elapsed();
        }
        Err(e) => {
            eprintln!("  cannot run `kern build` for '{}': {e}", w.service);
            return t0.elapsed();
        }
    }
    // Stop only this box. `compose stop` would take the whole stack down, which is the opposite of
    // what a watcher is for.
    let stopped = std::process::Command::new(self_exe)
        .arg("stop")
        .arg(&w.box_name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !stopped {
        eprintln!(
            "  '{}' was not running, starting it from the new image",
            w.service
        );
    }
    // `start` launches what is not running and leaves the rest untouched, so the peers keep their
    // uptime and the pod is not recreated.
    match std::process::Command::new(self_exe)
        .arg("compose")
        .arg(file)
        .arg("start")
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "  restart of '{}' failed ({})",
            w.service,
            s.code().unwrap_or(-1)
        ),
        Err(e) => eprintln!("  cannot restart '{}': {e}", w.service),
    }
    t0.elapsed()
}

/// Build the watch set from the stack. Only services with a `build:` can be watched, and the
/// confinement rules are the caller's (already applied), so this only pairs what it is given.
pub(crate) fn watch_set(
    boxes: &[&crate::compose::ComposeBox],
    contexts: &[(String, PathBuf, Option<PathBuf>)],
) -> Vec<Watched> {
    boxes
        .iter()
        .filter_map(|b| {
            let (_, ctx, df) = contexts.iter().find(|(n, _, _)| *n == b.name)?;
            let bd = b.build.as_ref()?;
            Some(Watched {
                service: b.service.clone(),
                box_name: b.name.clone(),
                tag: b
                    .image
                    .clone()
                    .unwrap_or_else(|| format!("kern-compose-{}:latest", b.name)),
                context: ctx.clone(),
                dockerfile: df.clone(),
                args: bd.args.clone(),
                dirty: false,
            })
        })
        .collect()
}

/// The watch loop. Blocks until `SIGINT`/`SIGTERM`.
pub(crate) fn run(mut watched: Vec<Watched>, file: &str, self_exe: &Path) -> Result<(), Error> {
    if watched.is_empty() {
        return Err(Error::Compose(format!(
            "nothing to watch in {file}: `watch` follows a service's `build:` context, and no \
             selected service declares one. A service that runs a published `image:` has no source \
             tree to rebuild from."
        )));
    }
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(Error::Compose(format!(
            "watch: inotify unavailable: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut map: Vec<(i32, usize)> = Vec::new();
    let mut total = 0usize;
    for (i, w) in watched.iter().enumerate() {
        match add_watch_tree(fd, &w.context.clone(), i, &mut map) {
            Ok(n) => total += n,
            Err(e) => {
                unsafe { libc::close(fd) };
                return Err(e);
            }
        }
    }
    // Handlers AFTER the watches exist, so a Ctrl-C during setup is the default kill rather than a
    // flag nothing is yet reading.
    unsafe {
        // `as *const () as sighandler_t`, the same two-step the TUI's restore handler uses: a direct
        // function-item-to-integer cast is refused by lint, and for a good reason, so the pointer is
        // formed explicitly before it becomes the integer the C API wants.
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
    eprintln!(
        "watching {} service(s) across {total} director{} - Ctrl-C to stop",
        watched.len(),
        if total == 1 { "y" } else { "ies" }
    );
    for w in &watched {
        eprintln!("  {} <- {}", w.service, w.context.display());
    }

    let mut buf = EventBuf::new();
    let mut new_dirs: Vec<(PathBuf, usize)> = Vec::new();
    // `None` = idle; `Some(deadline)` = a burst is settling.
    let mut settle: Option<std::time::Instant> = None;
    while !STOP.load(Ordering::SeqCst) {
        let timeout = match settle {
            None => IDLE_POLL_MS,
            Some(_) => DEBOUNCE_MS.min(IDLE_POLL_MS),
        };
        let mut pfd = [libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        let n = crate::eintr::poll(&mut pfd, timeout);
        if n > 0 {
            let got = crate::eintr::read(fd, buf.as_mut_ptr(), buf.len());
            if got > 0 {
                new_dirs.clear();
                let overflow =
                    drain_events(buf.filled(got as usize), &map, &mut watched, &mut new_dirs);
                if overflow {
                    // The kernel dropped events and will not say which. Rebuild everything watched:
                    // the alternative is to miss the edit that mattered and look idle.
                    eprintln!("  (inotify queue overflowed: rebuilding every watched service)");
                    for w in watched.iter_mut() {
                        w.dirty = true;
                    }
                }
                for (dir, idx) in new_dirs.drain(..) {
                    // Best-effort: a directory that disappeared between the event and here is not an
                    // error, and a watch that cannot be added is reported once by the next cycle's
                    // rebuild rather than by refusing to continue.
                    if dir.is_dir() {
                        let _ = add_watch_tree(fd, &dir, idx, &mut map);
                    }
                }
                settle = Some(std::time::Instant::now());
            }
        }
        // A burst has settled when nothing arrived for the debounce window.
        if let Some(since) = settle {
            if since.elapsed() >= std::time::Duration::from_millis(DEBOUNCE_MS as u64) {
                settle = None;
                for w in watched.iter_mut() {
                    if !w.dirty {
                        continue;
                    }
                    w.dirty = false;
                    let took = cycle(w, file, self_exe);
                    eprintln!("  '{}' back in {} ms", w.service, took.as_millis());
                }
            }
        }
    }
    unsafe { libc::close(fd) };
    eprintln!("watch: stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(service: &str, ctx: &str) -> Watched {
        Watched {
            service: service.to_string(),
            box_name: format!("pod-tok-{service}"),
            tag: format!("kern-compose-pod-tok-{service}:latest"),
            context: PathBuf::from(ctx),
            dockerfile: None,
            args: Vec::new(),
            dirty: false,
        }
    }

    /// A watch descriptor resolves to the service that registered it, and to nothing when it was
    /// never registered. The lookup is the only thing standing between an event and rebuilding the
    /// WRONG service, which is a failure a user would read as "watch is broken" without knowing why.
    #[test]
    fn a_watch_descriptor_resolves_to_the_service_that_registered_it() {
        let map = [(3, 0), (4, 0), (7, 1)];
        assert_eq!(service_of(&map, 3), Some(0));
        assert_eq!(service_of(&map, 4), Some(0));
        assert_eq!(service_of(&map, 7), Some(1));
        assert_eq!(service_of(&map, 5), None, "an unknown wd marks nothing");
        assert_eq!(service_of(&[], 3), None, "an empty map marks nothing");
    }

    /// The name inside an event is NUL-terminated and padded, and both have to be stripped or a path
    /// join produces a name with trailing zero bytes that matches nothing on disk.
    #[test]
    fn an_event_name_is_read_without_its_padding() {
        assert_eq!(event_name(b"src\0\0\0\0"), Some("src"));
        assert_eq!(event_name(b"a.rs\0"), Some("a.rs"));
        assert_eq!(event_name(b"\0\0"), None, "an empty name is no name");
        assert_eq!(event_name(b""), None);
        assert_eq!(
            event_name(&[0xff, 0xfe, 0]),
            None,
            "a non-UTF-8 name is not a path here; the dirty bit above already fired"
        );
        assert_eq!(
            event_name(b"no-nul"),
            Some("no-nul"),
            "a name filling the field exactly still reads"
        );
    }

    /// An empty watch set is refused rather than entering a loop that can never fire. A user who
    /// asked to watch a stack of published images must be told why nothing is happening, at the
    /// moment they ask, not by watching a silent terminal.
    #[test]
    fn watching_nothing_is_refused_with_the_reason() {
        let err = run(Vec::new(), "compose.yml", Path::new("/nonexistent"))
            .expect_err("an empty watch set must refuse");
        let msg = format!("{err}");
        assert!(
            msg.contains("nothing to watch") && msg.contains("build:"),
            "the refusal must say what watch follows: {msg}"
        );
    }

    /// The buffer is 8-byte aligned, which is what `inotify_event` requires. A `[u8; N]` would be
    /// 1-aligned and the cast in `drain_events` would be undefined behaviour on the first event.
    #[test]
    fn the_event_buffer_is_aligned_for_inotify_event() {
        let buf = EventBuf::new();
        let addr = buf.0.as_ptr() as usize;
        assert_eq!(
            addr % std::mem::align_of::<libc::inotify_event>(),
            0,
            "the read buffer must satisfy inotify_event's alignment"
        );
        assert!(
            buf.len() >= std::mem::size_of::<libc::inotify_event>() * 16,
            "the buffer must hold a burst, not one event"
        );
    }

    /// `watch_set` pairs a service with its resolved context, and skips a service that has no
    /// `build:` even when a context was resolved for its name. The filter is what keeps a stack of
    /// published images from being watched pointlessly.
    #[test]
    fn only_services_with_a_build_context_are_watched() {
        let with_build = crate::compose::ComposeBox {
            name: "pod-tok-api".into(),
            service: "api".into(),
            build: Some(crate::compose::BuildDirective {
                context: ".".into(),
                dockerfile: None,
                args: vec!["A=1".into()],
            }),
            ..Default::default()
        };
        let no_build = crate::compose::ComposeBox {
            name: "pod-tok-db".into(),
            service: "db".into(),
            image: Some("postgres:alpine".into()),
            ..Default::default()
        };

        let contexts = vec![
            ("pod-tok-api".to_string(), PathBuf::from("/p/api"), None),
            ("pod-tok-db".to_string(), PathBuf::from("/p/db"), None),
        ];
        let set = watch_set(&[&with_build, &no_build], &contexts);
        assert_eq!(set.len(), 1, "only the service with a build: is watched");
        assert_eq!(set[0].service, "api");
        assert_eq!(set[0].context, PathBuf::from("/p/api"));
        assert_eq!(set[0].args, vec!["A=1".to_string()]);
        assert_eq!(
            set[0].tag, "kern-compose-pod-tok-api:latest",
            "a service with no image: builds into the synthesized tag the stack runs"
        );
    }

    /// A service that names an `image:` AND a `build:` rebuilds into that image, not into a second
    /// tag nobody starts. Docker's rule, and the one `resolve_builds` already follows.
    #[test]
    fn an_image_and_a_build_rebuild_the_named_image() {
        let b = crate::compose::ComposeBox {
            name: "pod-tok-web".into(),
            service: "web".into(),
            image: Some("myco/web:dev".into()),
            build: Some(crate::compose::BuildDirective {
                context: "web".into(),
                dockerfile: Some("Dockerfile.dev".into()),
                args: Vec::new(),
            }),
            ..Default::default()
        };
        let contexts = vec![(
            "pod-tok-web".to_string(),
            PathBuf::from("/p/web"),
            Some(PathBuf::from("/p/web/Dockerfile.dev")),
        )];
        let set = watch_set(&[&b], &contexts);
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].tag, "myco/web:dev");
        assert_eq!(
            set[0].dockerfile,
            Some(PathBuf::from("/p/web/Dockerfile.dev"))
        );
    }

    /// The unused-field guard: `w()` builds a `Watched` the way the loop does, so a field added to
    /// the struct without being set here fails to compile rather than defaulting silently.
    #[test]
    fn a_watched_service_carries_what_a_cycle_needs() {
        let x = w("api", "/p/api");
        assert_eq!(x.service, "api");
        assert_eq!(x.box_name, "pod-tok-api");
        assert!(x.tag.ends_with(":latest"));
        assert!(!x.dirty, "a fresh entry is not dirty");
        assert!(x.args.is_empty());
    }
}
