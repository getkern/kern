//! Terminal styling: ANSI colours when stdout is a TTY and `NO_COLOR` is unset (else no-ops), plus
//! the `kern` wordmark. Dependency-free — raw escape strings, gated once. Because the fields are
//! `""` when colour is off, call sites interpolate unconditionally and piped/non-tty output (and
//! the test harness) stays plain.

use std::io::IsTerminal;

/// ANSI codes, or `""` each when colour is disabled.
pub struct Palette {
    pub b: &'static str, // bold
    pub c: &'static str, // cyan
    pub d: &'static str, // dim
    pub g: &'static str, // green
    pub z: &'static str, // reset
}

impl Palette {
    /// Colour on iff stdout is a terminal and `NO_COLOR` is unset (the de-facto standard).
    pub fn detect() -> Self {
        if std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal() {
            Self {
                b: "\x1b[1m",
                c: "\x1b[36m",
                d: "\x1b[2m",
                g: "\x1b[32m",
                z: "\x1b[0m",
            }
        } else {
            Self {
                b: "",
                c: "",
                d: "",
                g: "",
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
