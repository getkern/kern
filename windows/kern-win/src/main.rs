//! `kern.exe` - the Windows edge of kern. A THIN bridge: kern's sandbox needs a real Linux kernel
//! (namespaces + cgroups v2 + overlayfs + seccomp), and Windows already ships one - **WSL2**. This shim
//! translates Windows paths and forwards the command to `kern` INSIDE WSL2.
//!
//! HOT PATH = ONE `wsl.exe` spawn, and the forward uses `--exec` (NO shell): with plain `wsl -- cmd`
//! the args are re-joined and re-parsed by the distro's default shell - argument boundaries survive
//! only by accident, `$VAR`/globs get expanded, and a `;` in an arg becomes a second command. `--exec`
//! passes argv through untouched. kern's absolute path inside the distro is resolved ONCE (via a login
//! shell, so `~/.local/bin` installs are found) and cached next to the distro name; afterwards each
//! command is a single `wsl.exe --exec /abs/kern …` - no probe, no shell, no profile sourcing.
//!
//! "Hybrid" = ONE kern: identical CLI on native Linux and on Windows; the Windows side is only this
//! forwarder. No daemon, no Docker Desktop.

use std::env;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{exit, Command, Stdio};

/// Cache dir (`%LOCALAPPDATA%\kern`) - holds the resolved-distro cache and one-shot hint markers.
fn cache_dir() -> Option<PathBuf> {
    let base = env::var("LOCALAPPDATA").ok().filter(|s| !s.is_empty())?;
    Some(PathBuf::from(base).join("kern"))
}

/// Cache file: line 1 = distro name, line 2 = kern's absolute path inside it. Both resolved on the
/// first run only, so the hot path spends ZERO probe spawns and ZERO shell startups. NOTE the name is
/// `wsl-distro`, NOT `distro`: the installer imports the WSL image into a DIRECTORY
/// `%LOCALAPPDATA%\kern\distro\` (the ext4.vhdx), so a cache file literally named `distro` collided
/// with that dir - the write failed every time and every command re-ran the first-run probe.
fn cache_file() -> Option<PathBuf> {
    Some(cache_dir()?.join("wsl-distro"))
}

fn read_cache() -> Option<(String, Option<String>)> {
    let s = fs::read_to_string(cache_file()?).ok()?;
    let mut lines = s.lines().map(str::trim);
    let d = lines.next().filter(|d| !d.is_empty())?.to_string();
    let path = lines
        .next()
        .filter(|p| p.starts_with('/'))
        .map(str::to_string);
    Some((d, path))
}

fn write_cache(distro: &str, kern_path: &str) {
    if let Some(p) = cache_file() {
        if let Some(dir) = p.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let _ = fs::write(p, format!("{distro}\n{kern_path}\n"));
    }
}

fn clear_cache() {
    if let Some(p) = cache_file() {
        let _ = fs::remove_file(p);
    }
}

/// Why we couldn't resolve a usable distro - each maps to an actionable message.
enum ResolveErr {
    NoDistro,
    KernMissing(String),
}

/// The resolved forward target: which distro, and how to reach `kern` inside it.
struct Target {
    distro: String,
    /// kern's absolute path (cached). `None` only for a `KERN_WSL_DISTRO` env override - then the
    /// forward goes through a login-shell trampoline that resolves PATH the same way the user's
    /// interactive shell would (still ONE wsl.exe spawn).
    kern_path: Option<String>,
    /// True when `distro` came from the cache file - only then is a stale-cache retry meaningful.
    from_cache: bool,
}

/// Resolve the WSL distro + kern path. Order: `KERN_WSL_DISTRO` → cache file → first-run probe.
/// Only the first-ever run pays the probe; afterwards it's a single file read, no spawn.
fn resolve_target() -> Result<Target, ResolveErr> {
    if let Ok(d) = env::var("KERN_WSL_DISTRO") {
        if !d.trim().is_empty() {
            // Explicit override - trust it, no probe, no cache. PATH is resolved by the trampoline.
            return Ok(Target {
                distro: d.trim().to_string(),
                kern_path: None,
                from_cache: false,
            });
        }
    }
    if let Some((distro, kern_path)) = read_cache() {
        return Ok(Target {
            distro,
            kern_path,
            from_cache: true,
        });
    }
    // First run only. WSL can take several seconds to boot its utility VM - say so, never hang mute.
    eprintln!("kern: first run - locating your WSL distro (WSL itself can take a few seconds to start)...");
    let names = list_distros();
    if names.is_empty() {
        return Err(ResolveErr::NoDistro);
    }
    // Prefer kern's own pre-baked `kern` distro, then try EVERY listed distro (the default one may
    // be something like docker-desktop while kern lives one line down in Ubuntu).
    let ordered = order_candidates(&names);
    for d in &ordered {
        if let Some(path) = kern_path_in(d) {
            write_cache(d, &path);
            return Ok(Target {
                distro: (*d).clone(),
                kern_path: Some(path),
                from_cache: false,
            });
        }
    }
    // Distros exist but none has kern - report the most likely candidate (the first tried).
    //
    // `first()` AND NOT `[0]`: the index is provably in range here (`names` is non-empty above and
    // `order_candidates` partitions it, so it returns exactly as many elements) but that invariant
    // lives in two other functions. This binary is built with `panic = "abort"`, so a wrong index
    // would abort with no message at all - the forwarder would simply vanish. The fallback cannot
    // happen; if it ever does, it reports the condition instead of killing the process.
    match ordered.first() {
        Some(d) => Err(ResolveErr::KernMissing((*d).clone())),
        None => Err(ResolveErr::NoDistro),
    }
}

/// Capture the stdout of a `wsl.exe` sub-command, or `None` on spawn failure / non-zero exit. Sets
/// `WSL_UTF8=1` (2021+ WSL → plain UTF-8; older ignores it and emits UTF-16LE) and decodes both via
/// `decode_wsl`. THE one place probe spawns live - a non-success status is never parsed as output
/// (else WSL's own error text would be mistaken for a distro name / kern path).
fn wsl_query(args: &[&str]) -> Option<String> {
    let out = Command::new("wsl.exe")
        .args(args)
        .env("WSL_UTF8", "1")
        .output()
        .ok()?;
    out.status.success().then(|| decode_wsl(&out.stdout))
}

/// Candidate distros in probe order: kern's own pre-baked `kern` distro FIRST (case-insensitive),
/// then every other listed distro in order. Pure so the "try all, kern-first" rule is unit-tested
/// without spawning `wsl.exe` - the default distro may be `docker-desktop` while kern lives one line
/// down in `Ubuntu`, so probing only the first name would wrongly report kern missing.
fn order_candidates(names: &[String]) -> Vec<&String> {
    names
        .iter()
        .filter(|n| n.eq_ignore_ascii_case("kern"))
        .chain(names.iter().filter(|n| !n.eq_ignore_ascii_case("kern")))
        .collect()
}

/// First-run probe: the distro names from `wsl -l -q` (empty = no distros / WSL broken).
fn list_distros() -> Vec<String> {
    wsl_query(&["-l", "-q"])
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// One-time, cache-populating resolution of kern's ABSOLUTE path inside `distro`. A LOGIN shell
/// (`sh -lc`) on purpose: install.sh drops kern in `~/.local/bin`, which only profile-sourcing
/// shells have on PATH - probing with a bare `sh -c` (non-login) would tell users to install kern,
/// watch them do it, and then still refuse: a dead loop. Runs only when the cache is being written.
fn kern_path_in(distro: &str) -> Option<String> {
    let p = wsl_query(&["-d", distro, "--exec", "sh", "-lc", "command -v kern"])?;
    let p = p.trim();
    p.starts_with('/').then(|| p.to_string())
}

/// WSL command output decoding. With `WSL_UTF8=1` it's plain UTF-8; pre-2021 WSL ignores the var and
/// emits UTF-16LE. Detect by embedded NULs (any real UTF-16LE line has them; UTF-8 never does) and
/// decode PROPERLY via `decode_utf16` - a byte-skipping hack would truncate any non-Latin-1 distro
/// name (e.g. a CJK name) to garbage.
fn decode_wsl(bytes: &[u8]) -> String {
    if !bytes.contains(&0) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    // DESTRUCTURED, not indexed: a two-element slice pattern proves the bound to the compiler, so
    // this carries no index that could abort (`panic = "abort"` here means an out-of-range index
    // would kill the forwarder with no output at all). An odd trailing byte is DROPPED explicitly,
    // which is what `chunks_exact` did silently - half a UTF-16 code unit is not a character.
    let units: Vec<u16> = bytes
        .chunks(2)
        .filter_map(|c| match c {
            [lo, hi] => Some(u16::from_le_bytes([*lo, *hi])),
            _ => None,
        })
        .collect();
    char::decode_utf16(units.into_iter().filter(|&u| u != 0xFEFF)) // strip a BOM if present
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Translate a single arg from Windows to WSL form, leaving non-paths untouched. Handles a bare Windows
/// path (`C:\a\b`) and a mount spec whose SOURCE is a Windows path (`-v C:\a:/dst[:opts]`).
fn translate_arg(arg: &str) -> String {
    if is_win_path(arg) {
        if let Some((src, rest)) = split_mount(arg) {
            return format!("{}:{}", win_to_wsl(src), rest);
        }
        return win_to_wsl(arg);
    }
    arg.to_string()
}

/// `true` if `s` starts like a Windows path: `X:\…` or `X:/…`.
fn is_win_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// Split a mount value `C:\src:/dst[:opts]` into (`C:\src`, `/dst[:opts]`): the first `:` after the
/// drive colon that is followed by a path separator (the Linux dest always starts `:/`).
fn split_mount(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut i = 2;
    while i + 1 < bytes.len() {
        if bytes[i] == b':' && (bytes[i + 1] == b'/' || bytes[i + 1] == b'\\') {
            return Some((&s[..i], &s[i + 1..]));
        }
        i += 1;
    }
    None
}

/// `C:\Users\me\proj` → `/mnt/c/Users/me/proj`. Drive letter lowercased; backslashes → forward.
///
/// CARRIES ITS OWN GUARD INSTEAD OF TRUSTING ITS CALLER. The only production caller is
/// `translate_arg`, which calls it after `is_win_path` has already proved the first three bytes
/// exist, so the previous `b[0]` and `p[2..]` could not go out of range. But the proof lived in the
/// OTHER function: anything that ever calls this directly (a test does) would abort the whole
/// process, with no message, because this binary is built `panic = "abort"`. A path that is not a
/// drive path is now returned unchanged, which is also what the forwarder does with every other
/// argument it does not recognise.
fn win_to_wsl(p: &str) -> String {
    let mut chars = p.chars();
    let (Some(letter), Some(':')) = (chars.next(), chars.next()) else {
        return p.to_string();
    };
    if !letter.is_ascii_alphabetic() {
        return p.to_string();
    }
    let drive = letter.to_ascii_lowercase();
    let rest = chars.as_str().replace('\\', "/");
    format!(
        "/mnt/{drive}{}",
        if rest.starts_with('/') {
            rest
        } else {
            format!("/{rest}")
        }
    )
}

// ---------------------------------------------------------------------------------------------
// `kern wsl …` - the Windows edge's own commands, handled HERE and never forwarded.
//
// WHY THIS EXISTS. A field report on a Windows host found three kerns disagreeing on their version,
// one of them inside a WSL distro, "with nothing anywhere saying so". `kern doctor` now names the
// ones it can see, and it says in its own words that it CANNOT see across a WSL boundary. This is
// the other side of that boundary: from Windows you could neither SEE which distro `kern.exe` talks
// to nor CHOOSE it, except by setting `KERN_WSL_DISTRO` on every invocation or by deleting a cache
// file nothing documents. A choice that can only be made by deleting an undocumented file is not a
// choice.
//
// INTERCEPTED BEFORE `resolve_target`, deliberately: these commands are needed MOST when no distro
// has kern, which is exactly when resolving would abort with an install hint. `kern wsl list` has to
// work on a machine where nothing is installed yet.
//
// `wsl` is free as a verb: the Linux kern answers `error: unknown command 'wsl'`, so nothing is
// shadowed today, and a Windows-only concern is the one thing that belongs on the Windows edge.

/// Where the distro choice came from. `status` PRINTS this instead of implying it, because the
/// precedence matters: an env override silently beats a stored choice, and a user who ran
/// `kern wsl use` and still lands elsewhere has no way to tell why.
#[derive(Debug, PartialEq)]
enum Source {
    Env,
    Cache,
    Unresolved,
}

/// The parsed `kern wsl` sub-command. Pure, so the parse is unit-tested without a Windows host.
#[derive(Debug, PartialEq)]
enum WslCmd {
    List { probe: bool },
    Use(String),
    Status,
    Reset,
    Usage(Option<String>),
}

/// Parse `kern wsl …`. `None` means "not a wsl command, forward it" - so a future Linux-side verb
/// named `wsl` keeps working for anything this does not claim.
fn parse_wsl(args: &[String]) -> Option<WslCmd> {
    if args.first().map(String::as_str) != Some("wsl") {
        return None;
    }
    let rest = args.get(1..).unwrap_or(&[]);
    let tail = rest.get(1..).unwrap_or(&[]);
    Some(match rest.first().map(String::as_str) {
        None => WslCmd::Usage(None),

        // AN UNRECOGNISED ARGUMENT IS REFUSED, NEVER IGNORED, and every arm below says so.
        //
        // 🪤 MEASURED ON A REAL HOST, and this is the whole reason these arms are not one-liners:
        //   * `kern wsl list --prob` (a typo for `--probe`) ran a plain `list`, printed
        //     "not probed" on every row, and exited 0. The user asked to probe, was told nothing,
        //     and read an answer that looked like the probe's.
        //   * `kern wsl use kern rodlaw` stored `kern` and dropped `rodlaw` in silence, so a
        //     command with two distro names in it succeeds and the second one never happened.
        // Both are the same defect: an argument the parser does not understand, accepted. The exit
        // code is 2 (usage), which is what `use` with no name already returned.
        Some("list" | "ls") => match tail.iter().find(|a| *a != "--probe") {
            Some(bad) => WslCmd::Usage(Some(format!(
                "`kern wsl list` takes only --probe, not {}",
                short(bad)
            ))),
            None => WslCmd::List {
                probe: tail.iter().any(|a| a == "--probe"),
            },
        },

        Some("status") => no_args("status", tail, WslCmd::Status),
        Some("reset") => no_args("reset", tail, WslCmd::Reset),

        Some("use") => match (tail.first(), tail.get(1)) {
            // A name is REQUIRED and is never guessed: `use` with no argument writing the default
            // distro would persist a choice the user did not make.
            (None, _) => WslCmd::Usage(Some("kern wsl use needs a distro name".into())),
            (Some(n), _) if n.trim().is_empty() => {
                WslCmd::Usage(Some("kern wsl use needs a distro name".into()))
            }
            // ONE name, because two is ambiguous and picking the first is a guess. A WSL distro
            // name can contain a space, so the remedy named here is quoting rather than "pick one".
            (Some(_), Some(extra)) => WslCmd::Usage(Some(format!(
                "`kern wsl use` takes ONE distro name, got a second: {}. \
                 A name containing a space must be quoted",
                short(extra)
            ))),
            (Some(n), None) => WslCmd::Use(n.trim().to_string()),
        },

        Some(other) => WslCmd::Usage(Some(format!("unknown: kern wsl {}", short(other)))),
    })
}

/// A name from the command line or the cache file, made safe to put in a one-line message.
///
/// WHY EVERY ECHO OF AN UNTRUSTED NAME GOES THROUGH THIS. Measured on the test host: `kern wsl use`
/// with a 4096-character name printed all 4096 into the refusal; a name containing a newline split
/// the message across two lines so the second half read like a separate statement; and a cache file
/// holding one 70,000-character line put all of it into two different messages. None of these is a
/// privilege boundary - the cache is in the user's own `%LOCALAPPDATA%` and the argument is their own
/// shell - but a refusal is meant to be read, and the same rule is already applied to the version
/// strings `kern doctor` collects: strip the control characters, then cap the length.
fn short(s: &str) -> String {
    const MAX: usize = 48;
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    // `char_indices` and not a byte slice: cutting a multi-byte character in half would panic, and
    // a distro name can be any UTF-16 the user typed.
    match clean.char_indices().nth(MAX) {
        Some((at, _)) => format!("'{}…' ({} characters)", &clean[..at], clean.chars().count()),
        None => format!("'{clean}'"),
    }
}

const WSL_USAGE: &str = "\
kern wsl - which WSL2 distro kern.exe forwards to

  kern wsl list [--probe]   list the WSL2 distros; --probe also reports kern's version in each
                            (that STARTS every stopped distro, so it is opt-in)
  kern wsl status           the distro in use, where that choice came from, and kern's version
  kern wsl use <distro>     remember <distro> for every later command (checks kern is in it first)
  kern wsl reset            forget the stored choice; the next command detects a distro again

The order of precedence is: KERN_WSL_DISTRO, then the stored choice, then auto-detection.";

/// Which distros are RUNNING. `-l -q --running` gives bare names, one per line: no header to parse
/// (it is LOCALISED - the test host answers in Italian) and no ambiguity for a name with a space.
fn running_distros() -> Vec<String> {
    wsl_query(&["-l", "-q", "--running"])
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// kern's path AND version inside `distro`, in ONE spawn. `Some((path, version))` only when the
/// binary identifies itself as kern.
///
/// THE VERSION IS NOT ASSUMED FROM THE NAME, the same rule `doctor` follows: a file called `kern`
/// that is some other project would otherwise be reported as a kern install at an unknown version.
/// `command -v` short-circuits with `&&`, so "not installed" comes back as empty output rather than
/// as a half-filled answer.
fn kern_in(distro: &str) -> Option<KernInDistro> {
    let out = wsl_query(&[
        "-d",
        distro,
        "--exec",
        "sh",
        "-lc",
        "command -v kern && kern --version",
    ])?;
    let mut lines = out.lines().map(str::trim).filter(|l| !l.is_empty());
    let path = lines.next()?;
    let version = lines.next().unwrap_or("");
    if !path.starts_with('/') || !version.starts_with("kern ") {
        return None;
    }
    Some((path.to_string(), version.to_string()))
}

/// kern's absolute path inside a distro, and the version string it reported.
type KernInDistro = (String, String);

/// One row of a `--probe` sweep: the distro name, and what was found in it. The inner `None` is
/// "looked, no kern"; a distro ABSENT from the slice was never looked at, which is a third state and
/// the one `render_list` must not collapse into the second.
type ProbeRow = (String, Option<KernInDistro>);

/// Render `kern wsl list`. Pure: the table and every marker are unit-tested without a Windows host.
///
/// `probed` is `None` for the distros that were not probed, which is NOT the same as "kern is not
/// there" and must not read like it: an unprobed row says so.
fn render_list(
    names: &[String],
    running: &[String],
    selected: Option<&str>,
    source: &Source,
    probed: Option<&[ProbeRow]>,
) -> String {
    if names.is_empty() {
        return "kern: no WSL2 distro is registered on this machine.\n".to_string();
    }
    let mut s = String::new();
    s.push_str("  DISTRO                STATE     KERN\n");
    for n in names {
        let state = if running.iter().any(|r| r == n) {
            "running"
        } else {
            "stopped"
        };
        let mark = if Some(n.as_str()) == selected {
            "*"
        } else {
            " "
        };
        let kern = match probed.map(|p| p.iter().find(|(d, _)| d == n)) {
            // Probed and found: the version is what makes a mismatch between distros visible.
            Some(Some((_, Some((_, v))))) => v.clone(),
            Some(Some((_, None))) => "not installed".to_string(),
            // Not probed: say that, rather than leaving a blank that reads as "none".
            _ => "not probed".to_string(),
        };
        s.push_str(&format!("{mark} {n:<21} {state:<9} {kern}\n"));
    }
    let why = |source: &Source| match source {
        Source::Env => "from KERN_WSL_DISTRO",
        Source::Cache => "stored by `kern wsl use`",
        Source::Unresolved => "auto-detected",
    };
    match selected {
        // THE SELECTED DISTRO MAY NOT BE IN THE LIST, and the legend must not pretend otherwise.
        //
        // 🪤 MEASURED: with a stored choice naming a distro that has since been unregistered, this
        // printed a table where NO row carried a `*` and then a footer reading "* = in use:
        // '<name>'". A legend for a marker that is not on the page, under a list the name is absent
        // from. The forwarder recovers from this on its own (a stale cache is cleared and re-probed
        // on the next command), so the honest line is that the stored name is gone, not an error.
        Some(d) if !names.iter().any(|n| n == d) => s.push_str(&format!(
            "\nThe selected distro {} ({}) is NOT in the list above: it is no longer registered, \
             so no row is marked. The next kern command detects one again, or pick one with \
             `kern wsl use <distro>`.\n",
            short(d),
            why(source)
        )),
        Some(d) => s.push_str(&format!("\n* = in use: {} ({}).\n", short(d), why(source))),
        None => s.push_str(
            "\nNo distro is selected yet; the next kern command detects one. \
             Pick one with `kern wsl use <distro>`.\n",
        ),
    }
    s
}

/// What `kern wsl use <distro>` should do, decided separately from doing it so every branch is
/// unit-tested: the refusals are the part that matters and they are the part a Windows host makes
/// expensive to exercise.
#[derive(Debug, PartialEq)]
enum UseVerdict {
    /// Store it. `warn_env` carries the name that will WIN over what we are about to store.
    Store {
        path: String,
        version: String,
        warn_env: Option<String>,
    },
    /// Refuse: the distro is not registered. Carries the names we did see.
    NoSuchDistro(Vec<String>),
    /// Refuse: it exists, but kern is not inside it.
    NoKernInside,
}

fn use_verdict(
    want: &str,
    names: &[String],
    found: Option<KernInDistro>,
    env_override: Option<&str>,
) -> UseVerdict {
    // Case-insensitively, because WSL itself treats distro names that way and `wsl -d UBUNTU`
    // reaches `Ubuntu`. Storing the user's spelling of a distro that exists under another case
    // would work by luck and break the moment anything compares the two.
    let Some(actual) = names.iter().find(|n| n.eq_ignore_ascii_case(want)) else {
        return UseVerdict::NoSuchDistro(names.to_vec());
    };
    let Some((path, version)) = found else {
        return UseVerdict::NoKernInside;
    };
    UseVerdict::Store {
        path,
        version,
        // THE WARNING IS THE POINT. `KERN_WSL_DISTRO` beats the stored choice (see `resolve_target`),
        // so without this the command reports success and the next command goes somewhere else.
        // A stored choice that is silently ignored is worse than a refusal.
        warn_env: env_override
            .map(str::trim)
            .filter(|e| !e.is_empty() && !e.eq_ignore_ascii_case(actual))
            .map(str::to_string),
    }
}

/// Which distro is in use, and where that choice came from.
///
/// ONE SPELLING OF THE PRECEDENCE RULE, because `list` and `status` must agree about it and a second
/// copy drifts the first time the order changes. The order is `KERN_WSL_DISTRO`, then the stored
/// choice, then detection - the same order `resolve_target` forwards with, which is what makes
/// `status` able to say what the NEXT command will do rather than what this one looked up.
fn selection(
    env_distro: Option<&String>,
    cached: Option<&(String, Option<String>)>,
) -> (Option<String>, Source) {
    match (env_distro, cached) {
        (Some(d), _) => (Some(d.clone()), Source::Env),
        (None, Some((d, _))) => (Some(d.clone()), Source::Cache),
        (None, None) => (None, Source::Unresolved),
    }
}

/// A sub-command that takes no arguments: either the command, or a usage refusal naming the first
/// extra argument. Spelled once because `status` and `reset` had the same four lines, and a message
/// that exists twice is a message that will disagree with itself.
fn no_args(verb: &str, tail: &[String], cmd: WslCmd) -> WslCmd {
    match tail.first() {
        Some(bad) => WslCmd::Usage(Some(format!(
            "`kern wsl {verb}` takes no arguments, got {}",
            short(bad)
        ))),
        None => cmd,
    }
}

/// Run a `kern wsl` command. Returns the process exit code.
fn run_wsl_cmd(cmd: WslCmd) -> i32 {
    let env_distro = env::var("KERN_WSL_DISTRO")
        .ok()
        .filter(|s| !s.trim().is_empty());
    match cmd {
        WslCmd::Usage(err) => {
            if let Some(e) = err {
                eprintln!("kern: {e}\n");
                eprintln!("{WSL_USAGE}");
                return 2;
            }
            println!("{WSL_USAGE}");
            0
        }

        WslCmd::List { probe } => {
            let names = list_distros();
            let running = running_distros();
            let cached = read_cache();
            let (selected, source) = selection(env_distro.as_ref(), cached.as_ref());
            let probed = if probe && !names.is_empty() {
                // ANNOUNCED BEFORE IT HAPPENS: asking a stopped distro for a version boots it, which
                // takes seconds and leaves it running. A diagnostic must not do that silently.
                let stopped = names.iter().filter(|n| !running.contains(n)).count();
                if stopped > 0 {
                    eprintln!(
                        "kern: probing starts {stopped} stopped distro(s) and can take a few seconds each..."
                    );
                }
                Some(
                    names
                        .iter()
                        .map(|n| (n.clone(), kern_in(n)))
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            };
            print!(
                "{}",
                render_list(
                    &names,
                    &running,
                    selected.as_deref(),
                    &source,
                    probed.as_deref()
                )
            );
            if !probe && !names.is_empty() {
                println!("Run `kern wsl list --probe` to see kern's version inside each distro.");
            }
            0
        }

        WslCmd::Status => {
            let cached = read_cache();
            // THE SAME `selection` AS `list`, so the two cannot disagree about which distro is in
            // use. Only the "nothing selected yet" case differs, because `status` has a sentence to
            // print for it and `list` has a table to put it under.
            let (distro, source) = match selection(env_distro.as_ref(), cached.as_ref()) {
                (Some(d), src) => (d, src),
                (None, _) => {
                    println!(
                        "kern: no distro selected yet - the next kern command will detect one.\n\
                         Run `kern wsl list` to see what is available."
                    );
                    return 0;
                }
            };
            println!("distro:  {}", short(&distro));
            println!(
                "chosen:  {}",
                match source {
                    Source::Env => "by KERN_WSL_DISTRO (overrides the stored choice)",
                    Source::Cache => "by `kern wsl use` (stored)",
                    Source::Unresolved => "auto-detected",
                }
            );
            if source == Source::Env {
                if let Some((d, _)) = &cached {
                    if !d.eq_ignore_ascii_case(&distro) {
                        println!(
                            "stored:  {}  (NOT in use - the environment variable wins)",
                            short(d)
                        );
                    }
                }
            }
            match kern_in(&distro) {
                Some((path, version)) => {
                    println!("kern:    {version}");
                    println!("path:    {path}");
                    0
                }
                None => {
                    println!("kern:    NOT FOUND inside {}", short(&distro));
                    eprintln!(
                        "\nkern: {} is selected but has no kern. Pick another with\n\
                         `kern wsl use <distro>`, or install kern inside it:\n\n\
                         {INSTALL_HINT}",
                        short(&distro)
                    );
                    1
                }
            }
        }

        WslCmd::Use(want) => {
            let names = list_distros();
            // Probe ONLY the requested distro, and only if it exists: booting every distro to honour
            // one `use` would be a side effect nobody asked for.
            let found = names
                .iter()
                .find(|n| n.eq_ignore_ascii_case(&want))
                .and_then(|actual| kern_in(actual));
            match use_verdict(&want, &names, found, env_distro.as_deref()) {
                UseVerdict::NoSuchDistro(seen) => {
                    eprintln!("kern: no WSL2 distro named {}.", short(&want));
                    if seen.is_empty() {
                        eprintln!("No distro is registered. Install one:\n\n{INSTALL_HINT}");
                    } else {
                        eprintln!("Registered: {}", seen.join(", "));
                    }
                    1
                }
                UseVerdict::NoKernInside => {
                    // THE `wsl -d {want}` IN THE SUGGESTION IS DELIBERATELY NOT PUT THROUGH
                    // `short()`, unlike every other echo in this file: it is a command to paste,
                    // and a truncated name would make it a command that does not work. It is safe
                    // to print whole because this arm is only reachable when `want` matched a
                    // REGISTERED distro (see `use_verdict`), so its length is whatever WSL itself
                    // accepted - not, as in the cache and the argument list, whatever anything
                    // happened to write. The leading sentence still uses `short()`, so an absurd
                    // name is visible as absurd on the first line.
                    eprintln!(
                        "kern: {} exists but kern is not installed inside it, so it is NOT stored:\n\
                         a stored choice that cannot answer would break every later command.\n\n\
                         Install kern in it:  wsl -d {want} -- sh -lc 'curl -fsSL \
                         https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh'\n\
                         or re-run the Windows installer:\n\n{INSTALL_HINT}",
                        short(&want)
                    );
                    1
                }
                UseVerdict::Store {
                    path,
                    version,
                    warn_env,
                } => {
                    // The distro is stored under WSL's spelling, not the user's, so the cache never
                    // holds a name that only works by case-insensitive luck.
                    let actual = names
                        .iter()
                        .find(|n| n.eq_ignore_ascii_case(&want))
                        .cloned()
                        .unwrap_or(want);
                    write_cache(&actual, &path);
                    match read_cache() {
                        // VERIFIED, not assumed: the cache file collided with a directory once and
                        // every write failed silently, so every command re-ran the first-run probe.
                        Some((d, _)) if d == actual => {
                            println!("kern: now using {} ({version}).", short(&actual));
                        }
                        _ => {
                            eprintln!(
                                "kern: could not store the choice (is %LOCALAPPDATA% writable?).\n\
                                 Use it for this session instead:  set KERN_WSL_DISTRO={actual}"
                            );
                            return 1;
                        }
                    }
                    if let Some(e) = warn_env {
                        eprintln!(
                            "\nkern: WARNING - KERN_WSL_DISTRO is set to {env} and OVERRIDES what was\n\
                             just stored, so commands will still go there. Clear it to use {chosen}:\n\
                             \n    set KERN_WSL_DISTRO=\n",
                            env = short(&e),
                            chosen = short(&actual)
                        );
                    }
                    0
                }
            }
        }

        WslCmd::Reset => {
            let had = read_cache().map(|(d, _)| d);
            clear_cache();
            match had {
                Some(d) => println!(
                    "kern: forgot {}. The next command detects a distro again.",
                    short(&d)
                ),
                None => println!("kern: no stored choice to forget."),
            }
            if let Some(e) = env_distro {
                eprintln!(
                    "\nkern: note - KERN_WSL_DISTRO is set to {}, so detection is still bypassed.\n\
                     Clear it with:  set KERN_WSL_DISTRO=",
                    short(&e)
                );
            }
            0
        }
    }
}

/// Print the 9p perf hint ONCE per install, and only to a human: a marker file next to the cache
/// silences repeats, and a non-terminal stderr (scripted/piped use) never sees it - 200 boxes in a
/// CI loop must not emit 200 identical warnings into captured output.
fn hint_9p_once() {
    if !std::io::stderr().is_terminal() {
        return;
    }
    let Some(marker) = cache_dir().map(|d| d.join("hint-9p")) else {
        return;
    };
    if marker.exists() {
        return;
    }
    let _ = fs::write(&marker, "shown\n");
    eprintln!("kern: note - a mounted Windows path uses the WSL2 9p bridge (slower); keep hot data inside WSL for speed. (shown once)");
}

/// Build the exact `wsl.exe` argv (everything after the program name). `--exec` means argv passes
/// through to the Linux side UNTOUCHED - no default-shell re-parse, so a user arg like
/// `--env X=1;rm -rf /` or `printenv '$HOME'` reaches kern literally, never a second shell command.
/// With a cached absolute kern path we exec it directly; with an env-override distro (no cached path)
/// we exec a login-shell TRAMPOLINE whose script is a FIXED literal (`exec kern "$@"`) and whose args
/// arrive as POSITIONAL PARAMETERS - still no re-parse of user args. Pure, so the argv is unit-tested.
fn forward_argv(target: &Target, translated: &[String]) -> Vec<String> {
    let mut argv = vec!["-d".into(), target.distro.clone(), "--exec".into()];
    match &target.kern_path {
        Some(p) => argv.push(p.clone()),
        None => argv.extend(["sh", "-lc", r#"exec kern "$@""#, "sh"].map(String::from)),
    }
    argv.extend(translated.iter().cloned());
    argv
}

/// Forward the command: ONE `wsl.exe` spawn, inheriting stdio (so `-it`, Ctrl-C and piping all work).
fn forward(target: &Target, translated: &[String]) -> std::io::Result<std::process::ExitStatus> {
    Command::new("wsl.exe")
        .args(forward_argv(target, translated))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
}

/// The one-shot Windows install command - quoted in both "distro missing" messages, so the URL
/// lives in exactly one place.
const INSTALL_HINT: &str =
    "   powershell -ExecutionPolicy Bypass -Command \"irm https://raw.githubusercontent.com/getkern/kern/main/install.ps1 | iex\"";

fn main() {
    // `args_os` + lossy, NOT `env::args()`: the latter PANICS on an argument with invalid Unicode
    // (legal in NTFS names via unpaired UTF-16 surrogates) - a backtrace instead of an error.
    let args: Vec<String> = env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    // BEFORE resolving: `kern wsl …` is this shim's own, and it is needed most on a machine where
    // resolution would abort with an install hint. These never reach the Linux side.
    if let Some(cmd) = parse_wsl(&args) {
        exit(run_wsl_cmd(cmd));
    }

    // Up to 2 attempts: a stale cache (distro unregistered since it was written) is cleared and
    // re-resolved ONCE, transparently - not a permanent bare WSL error until a human deletes a file.
    for attempt in 0..2 {
        let target = match resolve_target() {
            Ok(t) => t,
            Err(ResolveErr::NoDistro) => {
                eprintln!(
                    "kern: no usable WSL2 distro found. kern runs its Linux sandbox inside WSL2. Install it once:\n\n\
                     {INSTALL_HINT}\n\n\
                     (one-time setup - far lighter than Docker Desktop)."
                );
                exit(1);
            }
            Err(ResolveErr::KernMissing(d)) => {
                eprintln!(
                    "kern: found WSL distro '{d}', but kern isn't installed inside it. Easiest fix - re-run the\n\
                     kern installer (it imports a ready-made distro with kern already inside):\n\n\
                     {INSTALL_HINT}\n\n\
                     or, if '{d}' has curl:  wsl -d {d} -- sh -lc 'curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh'"
                );
                exit(1);
            }
        };

        let translated: Vec<String> = args.iter().map(|a| translate_arg(a)).collect();

        // Best-effort perf hint: a `-v` source under /mnt/<drive> crosses WSL2's 9p bridge (~10x slower).
        if args
            .iter()
            .zip(&translated)
            .any(|(o, t)| o != t && t.starts_with("/mnt/"))
        {
            hint_9p_once();
        }

        match forward(&target, &translated) {
            // wsl.exe itself failed (code -1 = 0xFFFFFFFF - kern's own exits are 0-255): if the
            // distro came from OUR cache it may have been unregistered → clear + one fresh retry.
            Ok(s) if s.code() == Some(-1) && target.from_cache && attempt == 0 => {
                clear_cache();
                eprintln!(
                    "kern: WSL distro {} didn't start (removed or renamed?) - re-detecting...",
                    short(&target.distro)
                );
                continue;
            }
            Ok(s) => exit(s.code().unwrap_or(1)),
            Err(e) => {
                clear_cache(); // wsl.exe not even spawnable - force a fresh probe next time
                eprintln!("kern: could not invoke WSL2: {e}. Is WSL installed? Try: wsl -l -v");
                exit(1);
            }
        }
    }
    // NOT `unreachable!`. The loop cannot fall through - every arm of the match either exits or, at
    // attempt 0 only, continues - but `unreachable!` is a panic, and with `panic = "abort"` in this
    // profile that is the forwarder dying silently on a condition it could have reported. The exit
    // code is the generic failure, with a line saying which invariant broke, so if the loop is ever
    // restructured the symptom is a message and not a vanished process.
    eprintln!(
        "kern: internal error - the WSL retry loop ended without forwarding. Please report this."
    );
    exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bare_path() {
        assert_eq!(win_to_wsl(r"C:\Users\me\proj"), "/mnt/c/Users/me/proj");
        assert_eq!(win_to_wsl(r"D:/data"), "/mnt/d/data");
    }
    #[test]
    fn mount_spec_source_translated() {
        assert_eq!(translate_arg(r"C:\proj:/src:ro"), "/mnt/c/proj:/src:ro");
        assert_eq!(translate_arg(r"C:\a\b:/work"), "/mnt/c/a/b:/work");
    }
    #[test]
    fn non_paths_untouched() {
        assert_eq!(translate_arg("alpine:3.19"), "alpine:3.19");
        assert_eq!(translate_arg("--memory"), "--memory");
        assert_eq!(translate_arg("512m"), "512m");
        assert_eq!(translate_arg("vcpu:heavy"), "vcpu:heavy");
    }
    #[test]
    fn linux_paths_untouched() {
        assert_eq!(translate_arg("/src"), "/src");
        assert_eq!(translate_arg("data:/work"), "data:/work");
    }
    #[test]
    fn mount_translation_is_detectable_for_9p_hint() {
        // the perf-hint check keys on a translated mount source starting with /mnt/
        let t = translate_arg(r"C:\data:/data");
        assert_eq!(t, "/mnt/c/data:/data");
        assert!(t.starts_with("/mnt/"));
        // a Linux-only mount must NOT trip the hint
        assert!(!translate_arg("data:/work").starts_with("/mnt/"));
    }
    #[test]
    fn decode_wsl_handles_utf8_utf16_and_non_latin1() {
        // WSL_UTF8=1 path: plain UTF-8, no NULs.
        assert_eq!(decode_wsl(b"Ubuntu\nkern\n"), "Ubuntu\nkern\n");
        // Old-WSL path: UTF-16LE. Latin-1 name…
        let utf16: Vec<u8> = "kern\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_wsl(&utf16), "kern\r\n");
        // …and a non-Latin-1 name, which the old byte-skipping heuristic would have mangled.
        let cjk: Vec<u8> = "开发-Ubuntu\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_wsl(&cjk), "开发-Ubuntu\n");
        // A BOM is stripped, not leaked into the first name.
        let bom: Vec<u8> = "\u{FEFF}kern\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_wsl(&bom), "kern\n");
        // Empty output → empty string (no distros).
        assert_eq!(decode_wsl(b""), "");
    }
    #[test]
    fn order_candidates_puts_kern_first_then_keeps_order() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // kern lives one line below the default (docker-desktop) → must be tried FIRST.
        let names = s(&["docker-desktop", "Ubuntu", "kern"]);
        let ord: Vec<&str> = order_candidates(&names)
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(ord, ["kern", "docker-desktop", "Ubuntu"]);
        // Case-insensitive match on the kern distro.
        let names = s(&["Ubuntu", "KERN"]);
        assert_eq!(order_candidates(&names)[0], "KERN");
        // No kern distro → original order, all still tried.
        let names = s(&["Ubuntu", "Debian"]);
        let ord: Vec<&str> = order_candidates(&names)
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(ord, ["Ubuntu", "Debian"]);
    }
    #[test]
    fn is_win_path_only_matches_drive_paths() {
        assert!(is_win_path(r"C:\x"));
        assert!(is_win_path("D:/x"));
        // NOT drive paths: UNC, drive-relative (no separator), bare, Linux, image ref.
        assert!(!is_win_path(r"\\wsl$\Ubuntu\home")); // UNC → left untouched (kern/WSL handles it)
        assert!(!is_win_path("C:foo")); // drive-relative, no separator
        assert!(!is_win_path("C:")); // just a drive
        assert!(!is_win_path("/mnt/c")); // already Linux
        assert!(!is_win_path("alpine:3.19")); // image tag
    }
    #[test]
    fn split_mount_finds_the_linux_dest_colon() {
        // Source Windows path, Linux dest, optional opts after a SECOND colon stay in `rest`.
        assert_eq!(split_mount(r"C:\proj:/src"), Some((r"C:\proj", "/src")));
        assert_eq!(
            split_mount(r"C:\proj:/src:ro"),
            Some((r"C:\proj", "/src:ro"))
        );
        // A Windows path with no Linux dest (bare mount source alone) → no split.
        assert_eq!(split_mount(r"C:\proj"), None);
        // The drive colon at index 1 is never mistaken for the dest separator.
        assert_eq!(split_mount(r"C:/a:/b"), Some((r"C:/a", "/b")));
    }
    #[test]
    fn translate_arg_leaves_unc_and_drive_relative_untouched() {
        // We only translate real drive paths; UNC and drive-relative are forwarded verbatim
        // (kern inside WSL / the user is responsible - we never silently corrupt them).
        assert_eq!(translate_arg(r"\\wsl$\Ubuntu\home"), r"\\wsl$\Ubuntu\home");
        assert_eq!(translate_arg("C:relative"), "C:relative");
    }
    #[test]
    fn forward_argv_uses_exec_and_passes_args_verbatim() {
        // Cached absolute-path target → `wsl -d kern --exec /root/.local/bin/kern <args…>`.
        let t = Target {
            distro: "kern".into(),
            kern_path: Some("/root/.local/bin/kern".into()),
            from_cache: true,
        };
        // A shell-hostile arg must survive as ONE element - `--exec` means no shell parses it.
        let args = vec!["box".into(), "--env".into(), "X=1;rm -rf /".into()];
        assert_eq!(
            forward_argv(&t, &args),
            [
                "-d",
                "kern",
                "--exec",
                "/root/.local/bin/kern",
                "box",
                "--env",
                "X=1;rm -rf /"
            ]
        );
        // Env-override distro (no cached path) → fixed login-shell trampoline, user args positional.
        let t = Target {
            distro: "Ubuntu".into(),
            kern_path: None,
            from_cache: false,
        };
        assert_eq!(
            forward_argv(&t, &["ps".into()]),
            [
                "-d",
                "Ubuntu",
                "--exec",
                "sh",
                "-lc",
                r#"exec kern "$@""#,
                "sh",
                "ps"
            ]
        );
    }

    #[test]
    fn win_to_wsl_does_not_abort_on_a_string_that_is_not_a_drive_path() {
        // BEFORE THE GUARD THESE FOUR ABORTED THE PROCESS. `win_to_wsl` indexed `b[0]` and `p[2..]`
        // and relied on `is_win_path` having been called first, by a different function. With
        // `panic = "abort"` in this profile that is not an exception a caller can see, it is the
        // forwarder disappearing with no output. The production path is unchanged, which the
        // `translate_arg` tests above still prove; this one covers calling in directly.
        for odd in ["", "C", "C:", ":/x", "7:/x", "/mnt/c"] {
            let out = win_to_wsl(odd);
            if odd.len() < 2 || !odd.starts_with(|c: char| c.is_ascii_alphabetic()) {
                assert_eq!(
                    out, odd,
                    "a non-drive path must come back untouched: {odd:?}"
                );
            }
        }
        // And the real conversion is untouched by the guard.
        assert_eq!(win_to_wsl(r"C:\Users\me"), "/mnt/c/Users/me");
        assert_eq!(win_to_wsl("D:/data"), "/mnt/d/data");
    }

    // --- `kern wsl …`: the parse, the table and the refusals ----------------------------------
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn only_a_leading_wsl_is_claimed() {
        // Everything else forwards UNCHANGED. `wsl` in any other position is a kern argument (an
        // image tag, a box name, a path) and claiming it would break forwarding.
        assert_eq!(parse_wsl(&s(&["box", "wsl"])), None);
        assert_eq!(parse_wsl(&s(&["run", "--name", "wsl"])), None);
        assert_eq!(parse_wsl(&[]), None);
        assert_eq!(parse_wsl(&s(&["ps"])), None);
        // And a leading `wsl` IS claimed, with no sub-command meaning usage rather than an error.
        assert_eq!(parse_wsl(&s(&["wsl"])), Some(WslCmd::Usage(None)));
    }

    #[test]
    fn wsl_subcommands_parse() {
        assert_eq!(
            parse_wsl(&s(&["wsl", "list"])),
            Some(WslCmd::List { probe: false })
        );
        assert_eq!(
            parse_wsl(&s(&["wsl", "ls"])),
            Some(WslCmd::List { probe: false })
        );
        assert_eq!(
            parse_wsl(&s(&["wsl", "list", "--probe"])),
            Some(WslCmd::List { probe: true })
        );
        assert_eq!(parse_wsl(&s(&["wsl", "status"])), Some(WslCmd::Status));
        assert_eq!(parse_wsl(&s(&["wsl", "reset"])), Some(WslCmd::Reset));
        assert_eq!(
            parse_wsl(&s(&["wsl", "use", "Ubuntu"])),
            Some(WslCmd::Use("Ubuntu".into()))
        );
        // Surrounding whitespace is trimmed, because a name pasted from `wsl -l -v` carries it.
        assert_eq!(
            parse_wsl(&s(&["wsl", "use", "  kern "])),
            Some(WslCmd::Use("kern".into()))
        );
    }

    #[test]
    fn the_precedence_rule_has_one_spelling_and_the_environment_wins() {
        // THE ORDER IS THE CORRECTNESS PROPERTY, not a preference: `resolve_target` forwards with
        // the environment variable beating the stored choice, so if `selection` disagreed, `status`
        // and `list` would report a distro that commands do not go to. It used to be written twice,
        // once in each arm, which is how that disagreement would have arrived.
        let env = "rodlaw".to_string();
        let cache = ("kern".to_string(), Some("/usr/local/bin/kern".to_string()));

        assert_eq!(
            selection(Some(&env), Some(&cache)),
            (Some("rodlaw".to_string()), Source::Env),
            "the environment variable must beat the stored choice"
        );
        assert_eq!(
            selection(None, Some(&cache)),
            (Some("kern".to_string()), Source::Cache)
        );
        assert_eq!(selection(None, None), (None, Source::Unresolved));
        // An env value with no cache is still an override, not a detection.
        assert_eq!(
            selection(Some(&env), None),
            (Some("rodlaw".to_string()), Source::Env)
        );
    }

    #[test]
    fn an_argument_the_parser_does_not_understand_is_refused_not_ignored() {
        // ALL FOUR OF THESE WERE MEASURED SUCCEEDING ON A REAL HOST before this existed, which is
        // the only reason they are worth four assertions: `list --prob` ran a plain list and printed
        // "not probed" on every row, so the user who asked to probe got an answer shaped like the
        // probe's; `use kern rodlaw` stored the first and dropped the second in silence.
        for argv in [
            vec!["wsl", "list", "--prob"],
            vec!["wsl", "list", "--nonesiste"],
            vec!["wsl", "list", "extra"],
            vec!["wsl", "use", "kern", "rodlaw"],
            vec!["wsl", "status", "kern"],
            vec!["wsl", "reset", "--force"],
        ] {
            let got = parse_wsl(&s(&argv));
            assert!(
                matches!(got, Some(WslCmd::Usage(Some(_)))),
                "{argv:?} must be refused, got {got:?}"
            );
        }
        // And the forms that ARE understood still are, so the refusal did not widen.
        assert_eq!(
            parse_wsl(&s(&["wsl", "list", "--probe"])),
            Some(WslCmd::List { probe: true })
        );
        assert_eq!(
            parse_wsl(&s(&["wsl", "list"])),
            Some(WslCmd::List { probe: false })
        );
        assert_eq!(parse_wsl(&s(&["wsl", "status"])), Some(WslCmd::Status));
        assert_eq!(parse_wsl(&s(&["wsl", "reset"])), Some(WslCmd::Reset));
        assert_eq!(
            parse_wsl(&s(&["wsl", "use", "kern"])),
            Some(WslCmd::Use("kern".into()))
        );
    }

    #[test]
    fn an_echoed_name_is_bounded_and_carries_no_control_characters() {
        // MEASURED on the test host: a 4096-character name was printed in full into a refusal, a
        // name containing a newline split the message in two so the tail read as a separate
        // statement, and a cache file with one 70,000-character line put all of it into two
        // messages. A refusal is meant to be read.
        let long = "x".repeat(4096);
        let out = short(&long);
        assert!(
            out.len() < 120,
            "a 4096-char name must not be echoed whole: {} bytes",
            out.len()
        );
        assert!(out.contains("4096 characters"), "{out}");
        assert_eq!(short("a\nb"), "'a b'", "a newline must not break the line");
        assert_eq!(short("a\tb\r\n"), "'a b  '");
        // A short, ordinary name is untouched apart from the quotes.
        assert_eq!(short("kern"), "'kern'");
        // MULTI-BYTE SAFE: cutting at a byte offset inside a character would panic, and `panic =
        // "abort"` in this profile makes that a silent death rather than an error.
        let cjk = "距".repeat(100);
        let out = short(&cjk);
        assert!(out.contains("100 characters"), "{out}");
        assert!(out.starts_with('\''), "{out}");
    }

    #[test]
    fn list_does_not_print_a_legend_for_a_marker_that_is_not_there() {
        // MEASURED: a stored choice naming an unregistered distro printed a table with NO `*` on any
        // row and then "* = in use: '<name>'" underneath it.
        let names = s(&["kern", "rodlaw"]);
        let out = render_list(&names, &[], Some("gone-distro"), &Source::Cache, None);
        assert!(!out.contains('*'), "no row is marked, so no legend: {out}");
        assert!(out.contains("NOT in the list above"), "{out}");
        assert!(out.contains("no longer registered"), "{out}");
        // The normal case is unaffected.
        let out = render_list(&names, &[], Some("kern"), &Source::Cache, None);
        assert!(out.contains("* = in use: 'kern'"), "{out}");
    }

    #[test]
    fn use_without_a_name_is_refused_not_guessed() {
        // Defaulting to the current distro would persist a choice the user never made.
        let r = parse_wsl(&s(&["wsl", "use"]));
        assert!(matches!(r, Some(WslCmd::Usage(Some(_)))));
        let r = parse_wsl(&s(&["wsl", "use", "   "]));
        assert!(matches!(r, Some(WslCmd::Usage(Some(_)))));
        // An unknown sub-command says so instead of being forwarded to the Linux side, where the
        // error would name a command the user never typed.
        assert!(matches!(
            parse_wsl(&s(&["wsl", "frobnicate"])),
            Some(WslCmd::Usage(Some(_)))
        ));
    }

    #[test]
    fn list_marks_the_one_in_use_and_names_the_reason() {
        let names = s(&["kern", "rodlaw"]);
        let running = s(&["kern"]);
        let out = render_list(&names, &running, Some("kern"), &Source::Cache, None);
        assert!(out.contains("* kern"), "{out}");
        assert!(out.contains("  rodlaw"), "{out}");
        assert!(out.contains("running"), "{out}");
        assert!(out.contains("stopped"), "{out}");
        assert!(out.contains("stored by `kern wsl use`"), "{out}");
        // An env override must be named as such: it is why `use` can appear not to work.
        let out = render_list(&names, &running, Some("rodlaw"), &Source::Env, None);
        assert!(out.contains("from KERN_WSL_DISTRO"), "{out}");
    }

    #[test]
    fn unprobed_is_not_reported_as_absent() {
        // THE DISTINCTION THAT MATTERS: a blank or a "no" for a distro we never asked would make
        // `list` claim kern is missing from distros it simply did not look at.
        let names = s(&["kern", "rodlaw"]);
        let out = render_list(&names, &[], Some("kern"), &Source::Cache, None);
        assert_eq!(out.matches("not probed").count(), 2, "{out}");
        assert!(!out.contains("not installed"), "{out}");

        let probed = vec![
            (
                "kern".to_string(),
                Some((
                    "/usr/local/bin/kern".to_string(),
                    "kern v0.25.1".to_string(),
                )),
            ),
            ("rodlaw".to_string(), None),
        ];
        let out = render_list(&names, &[], Some("kern"), &Source::Cache, Some(&probed));
        assert!(out.contains("kern v0.25.1"), "{out}");
        assert!(out.contains("not installed"), "{out}");
        assert!(!out.contains("not probed"), "{out}");
    }

    #[test]
    fn list_with_no_distro_says_so_rather_than_printing_an_empty_table() {
        let out = render_list(&[], &[], None, &Source::Unresolved, None);
        assert!(out.contains("no WSL2 distro"), "{out}");
        assert!(!out.contains("DISTRO"), "{out}");
    }

    #[test]
    fn use_refuses_a_distro_that_is_not_registered() {
        let names = s(&["kern", "rodlaw"]);
        assert_eq!(
            use_verdict("Ubuntu", &names, None, None),
            UseVerdict::NoSuchDistro(names.clone())
        );
    }

    #[test]
    fn use_refuses_a_distro_without_kern_instead_of_storing_it() {
        // Storing it would make EVERY later command fail, and the failure would look like a kern
        // bug rather than the consequence of this command.
        let names = s(&["kern", "rodlaw"]);
        assert_eq!(
            use_verdict("rodlaw", &names, None, None),
            UseVerdict::NoKernInside
        );
    }

    #[test]
    fn use_matches_the_distro_name_case_insensitively() {
        // `wsl -d KERN` reaches `kern`, so refusing the user's spelling would refuse a name that
        // WSL itself accepts.
        let names = s(&["kern"]);
        let found = Some((
            "/usr/local/bin/kern".to_string(),
            "kern v0.25.1".to_string(),
        ));
        assert!(matches!(
            use_verdict("KERN", &names, found, None),
            UseVerdict::Store { .. }
        ));
    }

    #[test]
    fn use_warns_when_the_environment_will_override_what_it_stores() {
        // KERN_WSL_DISTRO beats the stored choice in `resolve_target`, so a silent success here
        // leaves the user with a choice that does nothing.
        let names = s(&["kern", "rodlaw"]);
        let found = Some((
            "/usr/local/bin/kern".to_string(),
            "kern v0.25.1".to_string(),
        ));
        let v = use_verdict("kern", &names, found.clone(), Some("rodlaw"));
        assert_eq!(
            v,
            UseVerdict::Store {
                path: "/usr/local/bin/kern".into(),
                version: "kern v0.25.1".into(),
                warn_env: Some("rodlaw".into()),
            }
        );
        // No warning when the override names the SAME distro (any case): nothing is being masked.
        for same in ["kern", "KERN", "  kern  "] {
            match use_verdict("kern", &names, found.clone(), Some(same)) {
                UseVerdict::Store { warn_env, .. } => assert_eq!(warn_env, None, "{same}"),
                other => panic!("{other:?}"),
            }
        }
        // An empty/whitespace variable is not an override - `set KERN_WSL_DISTRO=` is how you clear it.
        match use_verdict("kern", &names, found, Some("   ")) {
            UseVerdict::Store { warn_env, .. } => assert_eq!(warn_env, None),
            other => panic!("{other:?}"),
        }
    }
}
