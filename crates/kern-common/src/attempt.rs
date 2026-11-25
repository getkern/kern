//! A detached box's current attempt, as its supervisor records it in `<runtime>/kern/attempt/
//! <name>-<pid>` (`run <since_ms> <restarts>`, `restarting <since_ms> <code> <restarts>`): written
//! by the supervisor, read by `kern ps`/`inspect` for `Restarting` and `RestartCount`, and by kern's
//! Docker API for the `die` and `start` of each restart. One format, so the reader and the writer
//! cannot drift.

/// A box's current attempt, as its supervisor last recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// A run started at this time (Unix milliseconds), after `restarts` restarts.
    Running { since_ms: u64, restarts: u32 },
    /// The last run exited with `code` at this time, and the next one (restart number `restarts`)
    /// has not started yet.
    Restarting {
        since_ms: u64,
        code: i32,
        restarts: u32,
    },
}

impl Attempt {
    /// The record's one line, as the supervisor writes it.
    pub fn render(self) -> String {
        match self {
            Attempt::Running { since_ms, restarts } => format!("run {since_ms} {restarts}\n"),
            Attempt::Restarting {
                since_ms,
                code,
                restarts,
            } => format!("restarting {since_ms} {code} {restarts}\n"),
        }
    }

    /// A record read back; `None` for anything else.
    pub fn parse(text: &str) -> Option<Attempt> {
        let mut f = text.split_whitespace();
        let kind = f.next()?;
        let since_ms: u64 = f.next()?.parse().ok()?;
        // THE RESTART COUNT IS THE LAST FIELD AND OPTIONAL: a record from before it reads as 0.
        let a = match kind {
            "run" => Attempt::Running {
                since_ms,
                restarts: 0,
            },
            "restarting" => Attempt::Restarting {
                since_ms,
                code: f.next()?.parse().ok()?,
                restarts: 0,
            },
            _ => return None,
        };
        let restarts = match f.next() {
            Some(n) => n.parse().ok()?,
            None => 0,
        };
        let a = match a {
            Attempt::Running { since_ms, .. } => Attempt::Running { since_ms, restarts },
            Attempt::Restarting { since_ms, code, .. } => Attempt::Restarting {
                since_ms,
                code,
                restarts,
            },
        };
        f.next().is_none().then_some(a)
    }

    /// How many times the box has been restarted, as Docker's `RestartCount` counts them.
    pub fn restarts(self) -> u32 {
        match self {
            Attempt::Running { restarts, .. } | Attempt::Restarting { restarts, .. } => restarts,
        }
    }
}
