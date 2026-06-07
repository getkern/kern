//! Terminal styling: ANSI colours when stdout is a TTY and `NO_COLOR` is unset (else no-ops), the
//! `kern` wordmark, and the `kern box` status panel. Dependency-free — raw escape strings, gated
//! once. Because the colour fields are `""` when colour is off, call sites interpolate
//! unconditionally and piped/non-tty output (and the test harness) stays plain.

use std::io::IsTerminal;

/// ANSI codes, or `""` each when colour is disabled.
pub struct Palette {
    pub b: &'static str, // bold
    pub c: &'static str, // cyan
    pub d: &'static str, // dim
    pub g: &'static str, // green  — isolated / on / healthy
    pub y: &'static str, // yellow — open but deliberate (a heads-up, not an error)
    pub r: &'static str, // red    — bad / unhealthy
    pub z: &'static str, // reset
}

impl Palette {
    /// Colour on iff stdout is a terminal and `NO_COLOR` is unset (the de-facto standard).
    pub fn detect() -> Self {
        Self::for_stream(std::io::stdout().is_terminal())
    }

    /// Colour on iff stderr is a terminal and `NO_COLOR` is unset — for the box status panel, which
    /// prints to stderr so it never mixes with the box's own stdout.
    pub fn detect_stderr() -> Self {
        Self::for_stream(std::io::stderr().is_terminal())
    }

    fn for_stream(is_tty: bool) -> Self {
        if std::env::var_os("NO_COLOR").is_none() && is_tty {
            Self {
                b: "\x1b[1m",
                c: "\x1b[36m",
                d: "\x1b[2m",
                g: "\x1b[32m",
                y: "\x1b[33m",
                r: "\x1b[31m",
                z: "\x1b[0m",
            }
        } else {
            Self {
                b: "",
                c: "",
                d: "",
                g: "",
                y: "",
                r: "",
                z: "",
            }
        }
    }
}

/// The 5-line "KERN" wordmark (figlet), coloured cyan + bold by `p`.
pub fn logo(p: &Palette) -> String {
    let (b, c, z) = (p.b, p.c, p.z);
    format!(
        "{b}{c}  _  _______ ____  _   _{z}\n\
         {b}{c} | |/ / ____|  _ \\| \\ | |{z}\n\
         {b}{c} | ' /|  _| | |_) |  \\| |{z}\n\
         {b}{c} | . \\| |___|  _ <| |\\  |{z}\n\
         {b}{c} |_|\\_\\_____|_| \\_\\_| \\_|{z}"
    )
}

/// Status glyphs, with a plain-ASCII fallback when the locale isn't UTF-8 (`LANG=C`), so a box
/// banner never prints mojibake.
pub struct Glyphs {
    pub ok: &'static str,
    pub warn: &'static str,
    pub arrow: &'static str,
    pub rule: &'static str,
    pub lead: &'static str,
    pub dot: &'static str,
    pub ell: &'static str,
}

impl Glyphs {
    pub fn detect() -> Self {
        let utf8 = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .filter_map(std::env::var_os)
            .filter_map(|v| v.into_string().ok())
            .any(|v| v.to_ascii_uppercase().contains("UTF"));
        if utf8 {
            Self {
                ok: "✔",
                warn: "⚠",
                arrow: "→",
                rule: "─",
                lead: "▸",
                dot: "·",
                ell: "…",
            }
        } else {
            Self {
                ok: "+",
                warn: "!",
                arrow: "->",
                rule: "-",
                lead: ">",
                dot: "-",
                ell: "...",
            }
        }
    }
}

/// Terminal width (columns) of `fd`, via `TIOCGWINSZ`, falling back to `$COLUMNS`, then 80.
pub fn term_width(fd: i32) -> usize {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
        return ws.ws_col as usize;
    }
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&c| c > 0)
        .unwrap_or(80)
}

/// Everything the box status panel reports. Borrowed, so the call site builds it for free.
pub struct BoxStatus<'a> {
    pub name: &'a str,
    /// The image ref or rootfs path, shown in the header.
    pub source: &'a str,
    /// The effective command line the box runs (docker `ps` calls this COLUMN; we show it too).
    pub cmd: &'a str,
    pub read_only: bool,
    pub bind_rootfs: bool,
    pub share_net: bool,
    pub memory: Option<u64>,
    pub cpus: Option<f64>,
    pub volumes: usize,
    pub tty: bool,
    pub seccomp_syscalls: usize,
}

/// Human-readable byte size (`512M`, `1.5G`, `256K`, `0 B`) — the shared [`kern_common::fmt_bytes`]
/// convention, so the banner, `ps`/`stats`, `top` and volume sizes all render bytes the same way.
fn fmt_size(bytes: u64) -> String {
    kern_common::fmt_bytes(bytes)
}

/// A ONE-LINE box summary — the default for a foreground run, so a beginner who just wants their
/// command's output isn't buried under a six-line posture panel. Shows the name, source, and a green
/// "isolated" (or a yellow heads-up when a boundary is deliberately open). The full [`box_banner`] is
/// one `--verbose` away. Pure (returns the string) so it's unit-testable.
pub fn box_line(s: &BoxStatus, p: &Palette, gl: &Glyphs) -> String {
    let (b, c, d, g, y, z) = (p.b, p.c, p.d, p.g, p.y, p.z);
    let name = scrub(s.name);
    let source = scrub(s.source);
    let posture = if s.share_net {
        format!("{y}{} host network — not isolated{z}", gl.warn)
    } else if s.bind_rootfs {
        format!("{y}{} shared rootfs — writes persist{z}", gl.warn)
    } else {
        format!("{g}{} isolated{z}", gl.ok)
    };
    format!(
        "{b}{c}{} box {z}{b}{name}{z} {d}{} {source}{z}   {posture}   {d}(--verbose for detail){z}\n",
        gl.lead, gl.dot,
    )
}

/// Build the `kern box` status panel: an aligned, semantically-coloured summary of the box's
/// isolation + resource posture, with an actionable warning block for the *deliberately open*
/// choices (`--net`, `--bind-rootfs`). Pure (returns the string) so it's unit-testable; the caller
/// decides whether to print it (only when stderr is a TTY).
///
/// Colour is meaning, not decoration: green = isolated/on, yellow = open-but-chosen (a heads-up).
pub fn box_banner(s: &BoxStatus, p: &Palette, gl: &Glyphs, width: usize) -> String {
    let (b, c, d, g, y, z) = (p.b, p.c, p.d, p.g, p.y, p.z);
    let mut out = String::new();

    // Header: "▸ box <name> · <source>" on the left, "kern <ver>" dim on the right. name/source are
    // sanitized (untrusted) before they reach the terminal.
    let name = scrub(s.name);
    let source = scrub(s.source);
    let left_len = gl.lead.chars().count() + 6 + name.chars().count() + source.chars().count() + 3; // "▸ box "(6) + " · "(3)
    let right_len = "kern ".len() + kern_common::VERSION.len();
    let pad = width.saturating_sub(left_len + right_len).max(1);
    out.push_str(&format!(
        "{b}{c}{} box {z}{b}{name}{z} {d}{} {source}{z}{}{d}kern {}{z}\n",
        gl.lead,
        gl.dot,
        " ".repeat(pad),
        kern_common::VERSION,
    ));

    // A rule line under the header, clamped so it never wraps.
    let rule_w = width.clamp(20, 64).saturating_sub(2);
    out.push_str(&format!("{d}  {}{z}\n", gl.rule.repeat(rule_w)));

    // One aligned field. `mark` = "" for a neutral/info row (no glyph).
    let row = |out: &mut String, label: &str, mark: &str, mark_col: &str, value: String| {
        let m = if mark.is_empty() {
            "  ".to_string()
        } else {
            format!("{mark_col}{mark}{z} ")
        };
        out.push_str(&format!("  {d}{label:<8}{z}{m}{value}\n"));
    };

    // cmd — what the box actually runs (docker `ps` calls this COMMAND). Truncated to the width so
    // a long command never wraps the panel.
    if !s.cmd.is_empty() {
        let budget = width.clamp(20, 100).saturating_sub(12);
        let shown = scrub_truncate(s.cmd, budget, gl);
        row(&mut out, "cmd", "", "", format!("{c}{shown}{z}"));
    }

    // fs / root.
    if s.read_only {
        row(
            &mut out,
            "fs",
            gl.ok,
            g,
            format!("read-only root {d}(no writable surface){z}"),
        );
    } else if s.bind_rootfs {
        row(
            &mut out,
            "fs",
            gl.warn,
            y,
            format!("bind {d}(mutable, shared source){z}"),
        );
    } else {
        row(
            &mut out,
            "fs",
            gl.ok,
            g,
            format!("overlay {d}(image immutable, scratch discarded){z}"),
        );
    }

    // network.
    if s.share_net {
        row(
            &mut out,
            "net",
            gl.warn,
            y,
            format!("host {d}(shared — no network isolation){z}"),
        );
    } else {
        row(
            &mut out,
            "net",
            gl.ok,
            g,
            format!("isolated {d}(loopback-only){z}"),
        );
    }

    // guard line: seccomp + caps + userns, the always-on baseline.
    row(
        &mut out,
        "guard",
        gl.ok,
        g,
        format!(
            "seccomp {} syscalls {} caps dropped {} userns",
            s.seccomp_syscalls, gl.dot, gl.dot
        ),
    );

    // limits (only when set — else it's noise).
    let mut lim = Vec::new();
    if let Some(m) = s.memory {
        lim.push(format!("mem {}", fmt_size(m)));
    }
    if let Some(cpu) = s.cpus {
        lim.push(format!("cpu {}", fmt_cpus(cpu)));
    }
    if !lim.is_empty() {
        row(
            &mut out,
            "limits",
            gl.ok,
            g,
            lim.join(&format!(" {} ", gl.dot)),
        );
    }

    // volumes (only when present). Published ports are NOT shown here: the port forwarder already
    // prints each `→ publishing …` mapping (for both foreground and detached, with the real bind
    // result), so repeating them would double-report — the panel stays the single source for the
    // rest of the posture.
    if s.volumes > 0 {
        let plural = if s.volumes == 1 { "" } else { "s" };
        row(
            &mut out,
            "mounts",
            gl.arrow,
            c,
            format!("{} volume{plural}", s.volumes),
        );
    }
    if s.tty {
        row(
            &mut out,
            "tty",
            gl.ok,
            g,
            format!(
                "interactive (PTY) {d}{} Ctrl-D or `exit` to leave{z}",
                gl.dot
            ),
        );
    }

    // Warning block: the deliberately-open choices, each with a one-line fix. Dedup of the status
    // rows above — the warning *expands* the yellow row, it doesn't repeat it.
    let mut warns: Vec<(String, String)> = Vec::new();
    if s.share_net {
        warns.push((
            "--net shares the host network — the box has no network isolation".into(),
            "drop --net for an isolated, loopback-only box".into(),
        ));
    }
    if s.bind_rootfs {
        warns.push((
            "--bind-rootfs binds the source directly — it's mutable and shared".into(),
            "drop --bind-rootfs for an immutable, per-box overlay root".into(),
        ));
    }
    if !warns.is_empty() {
        out.push('\n');
        for (msg, fix) in warns {
            out.push_str(&format!("  {y}{}{z} {msg}\n", gl.warn));
            out.push_str(&format!("    {d}{} {fix}{z}\n", gl.arrow));
        }
    }

    out
}

/// Strip control / escape characters from an UNTRUSTED string before it reaches the terminal, so a
/// crafted image ref, rootfs path or command can't inject ANSI sequences into the panel (spoofing
/// the cursor, title, or clipboard). The box *name* is already charset-validated by `BoxName`;
/// `source` and `cmd` are not. Mirrors the `search`/`images` table hardening.
pub(crate) fn scrub(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Sanitize, then truncate to at most `max` characters with an ellipsis when cut. Operates on
/// `char`s so a multi-byte command is never split mid-character. Sanitizing FIRST means a control
/// char can't be smuggled past the length budget.
fn scrub_truncate(s: &str, max: usize, gl: &Glyphs) -> String {
    let clean = scrub(s);
    if clean.chars().count() <= max || max == 0 {
        return clean;
    }
    let keep = max.saturating_sub(gl.ell.chars().count());
    let head: String = clean.chars().take(keep).collect();
    format!("{head}{}", gl.ell)
}

/// A non-negative `f64` for display: `1.5`, `2`, `0.5` (drop a trailing `.0`). Shared by `--cpus`
/// here and the `kern top` profile forms.
pub(crate) fn fmt_cpus(c: f64) -> String {
    if c.fract() == 0.0 {
        format!("{}", c as u64)
    } else {
        format!("{c}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ascii_glyphs() -> Glyphs {
        Glyphs {
            ok: "+",
            warn: "!",
            arrow: "->",
            rule: "-",
            lead: ">",
            dot: "-",
            ell: "...",
        }
    }

    fn plain() -> Palette {
        Palette {
            b: "",
            c: "",
            d: "",
            g: "",
            y: "",
            r: "",
            z: "",
        }
    }

    fn base<'a>() -> BoxStatus<'a> {
        BoxStatus {
            name: "demo",
            source: "alpine",
            cmd: "/bin/sh",
            read_only: false,
            bind_rootfs: false,
            share_net: false,
            memory: None,
            cpus: None,
            volumes: 0,
            tty: false,
            seccomp_syscalls: 25,
        }
    }

    #[test]
    fn fmt_size_units() {
        assert_eq!(fmt_size(512 * 1024 * 1024), "512M");
        assert_eq!(fmt_size(1024 * 1024 * 1024), "1G");
        assert_eq!(fmt_size(1536 * 1024 * 1024), "1.5G");
        assert_eq!(fmt_size(256 * 1024), "256K");
    }

    #[test]
    fn fmt_cpus_drops_trailing_zero() {
        assert_eq!(fmt_cpus(2.0), "2");
        assert_eq!(fmt_cpus(1.5), "1.5");
        assert_eq!(fmt_cpus(0.5), "0.5");
    }

    #[test]
    fn banner_default_box_is_all_green_no_warning() {
        let s = base();
        let out = box_banner(&s, &plain(), &ascii_glyphs(), 80);
        assert!(out.contains("box demo"));
        assert!(out.contains("alpine"));
        assert!(out.contains("overlay"));
        assert!(out.contains("isolated"));
        assert!(out.contains("seccomp 25 syscalls"));
        // No deliberately-open choice → no warning block.
        assert!(!out.contains("no network isolation"));
        // Optional rows are omitted when empty.
        assert!(!out.contains("limits"));
        assert!(!out.contains("mounts"));
        assert!(!out.contains("ports"));
    }

    #[test]
    fn banner_net_emits_actionable_warning() {
        let mut s = base();
        s.share_net = true;
        let out = box_banner(&s, &plain(), &ascii_glyphs(), 80);
        assert!(out.contains("host (shared"));
        assert!(out.contains("--net shares the host network"));
        assert!(out.contains("drop --net"));
    }

    #[test]
    fn banner_shows_limits_and_mounts_when_set() {
        let mut s = base();
        s.memory = Some(512 * 1024 * 1024);
        s.cpus = Some(1.5);
        s.volumes = 2;
        let out = box_banner(&s, &plain(), &ascii_glyphs(), 80);
        assert!(out.contains("mem 512M"));
        assert!(out.contains("cpu 1.5"));
        assert!(out.contains("2 volumes"));
        // Ports are reported by the forwarder, not the panel (no double-report).
        assert!(!out.contains("ports"));
    }

    #[test]
    fn banner_shows_cmd_and_truncates_long_ones() {
        let mut s = base();
        s.cmd = "/bin/sh";
        let out = box_banner(&s, &plain(), &ascii_glyphs(), 80);
        assert!(out.contains("cmd"));
        assert!(out.contains("/bin/sh"));
        // A command longer than the width budget is cut with an ellipsis, never wrapping.
        s.cmd =
            "sh -c 'while true; do echo a-very-long-command-line-that-keeps-going-and-going; done'";
        let out = box_banner(&s, &plain(), &ascii_glyphs(), 60);
        assert!(out.contains("..."));
        assert!(out.lines().all(|l| l.chars().count() <= 60));
    }

    #[test]
    fn banner_strips_terminal_escapes_from_untrusted_fields() {
        // A crafted image ref / command must not inject ANSI into the panel (terminal spoofing).
        let mut s = base();
        s.source = "alpine\x1b]0;PWNED\x07";
        s.cmd = "sh\x1b[2J\x1b[H-c evil";
        let out = box_banner(&s, &plain(), &ascii_glyphs(), 80);
        assert!(!out.contains('\x1b'), "escape leaked into the panel");
        assert!(!out.contains('\x07'), "BEL leaked into the panel");
        assert!(out.contains("alpine"));
        assert!(out.contains("evil"));
    }

    #[test]
    fn banner_tty_shows_exit_hint() {
        let mut s = base();
        s.tty = true;
        let out = box_banner(&s, &plain(), &ascii_glyphs(), 80);
        assert!(out.contains("interactive (PTY)"));
        assert!(out.contains("Ctrl-D"));
    }

    #[test]
    fn banner_bind_rootfs_warns() {
        let mut s = base();
        s.bind_rootfs = true;
        let out = box_banner(&s, &plain(), &ascii_glyphs(), 80);
        assert!(out.contains("bind (mutable, shared source)"));
        assert!(out.contains("--bind-rootfs binds the source directly"));
    }

    #[test]
    fn line_is_one_line_and_shows_isolated() {
        let out = box_line(&base(), &plain(), &ascii_glyphs());
        assert_eq!(out.lines().count(), 1);
        assert!(out.contains("box demo"));
        assert!(out.contains("alpine"));
        assert!(out.contains("isolated"));
        assert!(out.contains("--verbose"));
    }

    #[test]
    fn line_surfaces_open_boundaries_inline() {
        let mut s = base();
        s.share_net = true;
        let out = box_line(&s, &plain(), &ascii_glyphs());
        assert!(out.contains("not isolated"));
        s.share_net = false;
        s.bind_rootfs = true;
        let out = box_line(&s, &plain(), &ascii_glyphs());
        assert!(out.contains("writes persist"));
    }

    #[test]
    fn line_strips_terminal_escapes() {
        let mut s = base();
        s.name = "x\x1b]0;PWNED\x07";
        s.source = "alpine\x1b[2J";
        let out = box_line(&s, &plain(), &ascii_glyphs());
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
    }
}
