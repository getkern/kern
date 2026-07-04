//! `kern.exe` — the Windows edge of kern. A THIN bridge: kern's sandbox needs a real Linux kernel
//! (namespaces + cgroups v2 + overlayfs + seccomp), and Windows already ships one — **WSL2**. This shim
//! translates Windows paths and forwards the command to `kern` INSIDE WSL2.
//!
//! HOT PATH = ONE `wsl.exe` spawn, and the forward uses `--exec` (NO shell): with plain `wsl -- cmd`
//! the args are re-joined and re-parsed by the distro's default shell — argument boundaries survive
//! only by accident, `$VAR`/globs get expanded, and a `;` in an arg becomes a second command. `--exec`
//! passes argv through untouched. kern's absolute path inside the distro is resolved ONCE (via a login
//! shell, so `~/.local/bin` installs are found) and cached next to the distro name; afterwards each
//! command is a single `wsl.exe --exec /abs/kern …` — no probe, no shell, no profile sourcing.
//!
//! "Hybrid" = ONE kern: identical CLI on native Linux and on Windows; the Windows side is only this
//! forwarder. No daemon, no Docker Desktop.

use std::env;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{exit, Command, Stdio};

/// Cache dir (`%LOCALAPPDATA%\kern`) — holds the resolved-distro cache and one-shot hint markers.
fn cache_dir() -> Option<PathBuf> {
    let base = env::var("LOCALAPPDATA").ok().filter(|s| !s.is_empty())?;
    Some(PathBuf::from(base).join("kern"))
}

/// Cache file: line 1 = distro name, line 2 = kern's absolute path inside it. Both resolved on the
/// first run only, so the hot path spends ZERO probe spawns and ZERO shell startups. NOTE the name is
/// `wsl-distro`, NOT `distro`: the installer imports the WSL image into a DIRECTORY
/// `%LOCALAPPDATA%\kern\distro\` (the ext4.vhdx), so a cache file literally named `distro` collided
/// with that dir — the write failed every time and every command re-ran the first-run probe.
fn cache_file() -> Option<PathBuf> {
    Some(cache_dir()?.join("wsl-distro"))
}

fn read_cache() -> Option<(String, Option<String>)> {
    let s = fs::read_to_string(cache_file()?).ok()?;
    let mut lines = s.lines().map(str::trim);
    let d = lines.next().filter(|d| !d.is_empty())?.to_string();
    let path = lines.next().filter(|p| p.starts_with('/')).map(str::to_string);
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

/// Why we couldn't resolve a usable distro — each maps to an actionable message.
enum ResolveErr {
    NoDistro,
    KernMissing(String),
}

/// The resolved forward target: which distro, and how to reach `kern` inside it.
struct Target {
    distro: String,
    /// kern's absolute path (cached). `None` only for a `KERN_WSL_DISTRO` env override — then the
    /// forward goes through a login-shell trampoline that resolves PATH the same way the user's
    /// interactive shell would (still ONE wsl.exe spawn).
    kern_path: Option<String>,
    /// True when `distro` came from the cache file — only then is a stale-cache retry meaningful.
    from_cache: bool,
}

/// Resolve the WSL distro + kern path. Order: `KERN_WSL_DISTRO` → cache file → first-run probe.
/// Only the first-ever run pays the probe; afterwards it's a single file read, no spawn.
fn resolve_target() -> Result<Target, ResolveErr> {
    if let Ok(d) = env::var("KERN_WSL_DISTRO") {
        if !d.trim().is_empty() {
            // Explicit override — trust it, no probe, no cache. PATH is resolved by the trampoline.
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
    // First run only. WSL can take several seconds to boot its utility VM — say so, never hang mute.
    eprintln!("kern: first run — locating your WSL distro (WSL itself can take a few seconds to start)…");
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
    // Distros exist but none has kern — report the most likely candidate (the first tried).
    Err(ResolveErr::KernMissing(ordered[0].clone()))
}

/// Capture the stdout of a `wsl.exe` sub-command, or `None` on spawn failure / non-zero exit. Sets
/// `WSL_UTF8=1` (2021+ WSL → plain UTF-8; older ignores it and emits UTF-16LE) and decodes both via
/// `decode_wsl`. THE one place probe spawns live — a non-success status is never parsed as output
/// (else WSL's own error text would be mistaken for a distro name / kern path).
fn wsl_query(args: &[&str]) -> Option<String> {
    let out = Command::new("wsl.exe").args(args).env("WSL_UTF8", "1").output().ok()?;
    out.status.success().then(|| decode_wsl(&out.stdout))
}

/// Candidate distros in probe order: kern's own pre-baked `kern` distro FIRST (case-insensitive),
/// then every other listed distro in order. Pure so the "try all, kern-first" rule is unit-tested
/// without spawning `wsl.exe` — the default distro may be `docker-desktop` while kern lives one line
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
/// shells have on PATH — probing with a bare `sh -c` (non-login) would tell users to install kern,
/// watch them do it, and then still refuse: a dead loop. Runs only when the cache is being written.
fn kern_path_in(distro: &str) -> Option<String> {
    let p = wsl_query(&["-d", distro, "--exec", "sh", "-lc", "command -v kern"])?;
    let p = p.trim();
    p.starts_with('/').then(|| p.to_string())
}

/// WSL command output decoding. With `WSL_UTF8=1` it's plain UTF-8; pre-2021 WSL ignores the var and
/// emits UTF-16LE. Detect by embedded NULs (any real UTF-16LE line has them; UTF-8 never does) and
/// decode PROPERLY via `decode_utf16` — a byte-skipping hack would truncate any non-Latin-1 distro
/// name (e.g. a CJK name) to garbage.
fn decode_wsl(bytes: &[u8]) -> String {
    if !bytes.contains(&0) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
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
fn win_to_wsl(p: &str) -> String {
    let b = p.as_bytes();
    let drive = (b[0] as char).to_ascii_lowercase();
    let rest = p[2..].replace('\\', "/");
    format!("/mnt/{drive}{}", if rest.starts_with('/') { rest } else { format!("/{rest}") })
}

/// Print the 9p perf hint ONCE per install, and only to a human: a marker file next to the cache
/// silences repeats, and a non-terminal stderr (scripted/piped use) never sees it — 200 boxes in a
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
    eprintln!("kern: note — a mounted Windows path uses the WSL2 9p bridge (slower); keep hot data inside WSL for speed. (shown once)");
}

/// Build the exact `wsl.exe` argv (everything after the program name). `--exec` means argv passes
/// through to the Linux side UNTOUCHED — no default-shell re-parse, so a user arg like
/// `--env X=1;rm -rf /` or `printenv '$HOME'` reaches kern literally, never a second shell command.
/// With a cached absolute kern path we exec it directly; with an env-override distro (no cached path)
/// we exec a login-shell TRAMPOLINE whose script is a FIXED literal (`exec kern "$@"`) and whose args
/// arrive as POSITIONAL PARAMETERS — still no re-parse of user args. Pure, so the argv is unit-tested.
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

/// The one-shot Windows install command — quoted in both "distro missing" messages, so the URL
/// lives in exactly one place.
const INSTALL_HINT: &str =
    "   powershell -ExecutionPolicy Bypass -Command \"irm https://raw.githubusercontent.com/getkern/kern/main/install.ps1 | iex\"";

fn main() {
    // `args_os` + lossy, NOT `env::args()`: the latter PANICS on an argument with invalid Unicode
    // (legal in NTFS names via unpaired UTF-16 surrogates) — a backtrace instead of an error.
    let args: Vec<String> = env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    // Up to 2 attempts: a stale cache (distro unregistered since it was written) is cleared and
    // re-resolved ONCE, transparently — not a permanent bare WSL error until a human deletes a file.
    for attempt in 0..2 {
        let target = match resolve_target() {
            Ok(t) => t,
            Err(ResolveErr::NoDistro) => {
                eprintln!(
                    "kern: no usable WSL2 distro found. kern runs its Linux sandbox inside WSL2. Install it once:\n\n\
                     {INSTALL_HINT}\n\n\
                     (one-time setup — far lighter than Docker Desktop)."
                );
                exit(1);
            }
            Err(ResolveErr::KernMissing(d)) => {
                eprintln!(
                    "kern: found WSL distro '{d}', but kern isn't installed inside it. Easiest fix — re-run the\n\
                     kern installer (it imports a ready-made distro with kern already inside):\n\n\
                     {INSTALL_HINT}\n\n\
                     or, if '{d}' has curl:  wsl -d {d} -- sh -lc 'curl -fsSL https://raw.githubusercontent.com/getkern/kern/main/install.sh | sh'"
                );
                exit(1);
            }
        };

        let translated: Vec<String> = args.iter().map(|a| translate_arg(a)).collect();

        // Best-effort perf hint: a `-v` source under /mnt/<drive> crosses WSL2's 9p bridge (~10x slower).
        if args.iter().zip(&translated).any(|(o, t)| o != t && t.starts_with("/mnt/")) {
            hint_9p_once();
        }

        match forward(&target, &translated) {
            // wsl.exe itself failed (code -1 = 0xFFFFFFFF — kern's own exits are 0-255): if the
            // distro came from OUR cache it may have been unregistered → clear + one fresh retry.
            Ok(s) if s.code() == Some(-1) && target.from_cache && attempt == 0 => {
                clear_cache();
                eprintln!(
                    "kern: WSL distro '{}' didn't start (removed or renamed?) — re-detecting…",
                    target.distro
                );
                continue;
            }
            Ok(s) => exit(s.code().unwrap_or(1)),
            Err(e) => {
                clear_cache(); // wsl.exe not even spawnable — force a fresh probe next time
                eprintln!("kern: could not invoke WSL2: {e}. Is WSL installed? Try: wsl -l -v");
                exit(1);
            }
        }
    }
    unreachable!("second attempt always exits");
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
        let utf16: Vec<u8> = "kern\r\n".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode_wsl(&utf16), "kern\r\n");
        // …and a non-Latin-1 name, which the old byte-skipping heuristic would have mangled.
        let cjk: Vec<u8> = "开发-Ubuntu\n".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode_wsl(&cjk), "开发-Ubuntu\n");
        // A BOM is stripped, not leaked into the first name.
        let bom: Vec<u8> = "\u{FEFF}kern\n".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode_wsl(&bom), "kern\n");
        // Empty output → empty string (no distros).
        assert_eq!(decode_wsl(b""), "");
    }
    #[test]
    fn order_candidates_puts_kern_first_then_keeps_order() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // kern lives one line below the default (docker-desktop) → must be tried FIRST.
        let names = s(&["docker-desktop", "Ubuntu", "kern"]);
        let ord: Vec<&str> = order_candidates(&names).iter().map(|s| s.as_str()).collect();
        assert_eq!(ord, ["kern", "docker-desktop", "Ubuntu"]);
        // Case-insensitive match on the kern distro.
        let names = s(&["Ubuntu", "KERN"]);
        assert_eq!(order_candidates(&names)[0], "KERN");
        // No kern distro → original order, all still tried.
        let names = s(&["Ubuntu", "Debian"]);
        let ord: Vec<&str> = order_candidates(&names).iter().map(|s| s.as_str()).collect();
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
        assert_eq!(split_mount(r"C:\proj:/src:ro"), Some((r"C:\proj", "/src:ro")));
        // A Windows path with no Linux dest (bare mount source alone) → no split.
        assert_eq!(split_mount(r"C:\proj"), None);
        // The drive colon at index 1 is never mistaken for the dest separator.
        assert_eq!(split_mount(r"C:/a:/b"), Some((r"C:/a", "/b")));
    }
    #[test]
    fn translate_arg_leaves_unc_and_drive_relative_untouched() {
        // We only translate real drive paths; UNC and drive-relative are forwarded verbatim
        // (kern inside WSL / the user is responsible — we never silently corrupt them).
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
        // A shell-hostile arg must survive as ONE element — `--exec` means no shell parses it.
        let args = vec!["box".into(), "--env".into(), "X=1;rm -rf /".into()];
        assert_eq!(
            forward_argv(&t, &args),
            ["-d", "kern", "--exec", "/root/.local/bin/kern", "box", "--env", "X=1;rm -rf /"]
        );
        // Env-override distro (no cached path) → fixed login-shell trampoline, user args positional.
        let t = Target { distro: "Ubuntu".into(), kern_path: None, from_cache: false };
        assert_eq!(
            forward_argv(&t, &["ps".into()]),
            ["-d", "Ubuntu", "--exec", "sh", "-lc", r#"exec kern "$@""#, "sh", "ps"]
        );
    }
}
