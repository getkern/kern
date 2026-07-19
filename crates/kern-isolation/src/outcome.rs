//! Sandbox execution outcome - the structured result of [`crate::Sandbox::run`].

/// Where the resource-usage figures in [`Outcome`] came from.
///
/// The public runtime reports [`Self::RusageFallback`] today: the SDK shells
/// out to the `kern` CLI and does not yet parse the box token from its output,
/// so it cannot discover the per-box cgroup path on its own and falls back to
/// `getrusage(RUSAGE_CHILDREN)`. This is honest signal to the caller that the
/// figures carry the documented caveats of getrusage (cumulative across reaped
/// children, not strictly per-sandbox).
///
/// The `resource_source` field on [`Outcome`] is therefore the public signal of
/// the precision the caller is receiving - read it before building billing on
/// top of the numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceSource {
    /// Figures sampled from the sandbox's own cgroup v2 (`memory.peak`
    /// and `cpu.stat`). Per-sandbox, accurate, suitable for billing.
    Cgroup,

    /// Figures sampled from `getrusage(RUSAGE_CHILDREN)`. **Cumulative
    /// across all reaped children of the calling process**; under
    /// `Sandbox` reuse the figures over-report. Not suitable for
    /// per-sandbox billing.
    RusageFallback,

    /// No figures available (`getrusage` failed and no cgroup was
    /// discoverable). Both `peak_memory_bytes` and `cpu_time_ms` are
    /// `None` in this case.
    Unavailable,
}

/// Result of running a command inside the sandbox.
///
/// Carries everything an AI-agent platform or scheduler needs to decide what to
/// do next: the exit code, captured stdout/stderr, truncation markers,
/// wall-clock time, and best-effort resource accounting (peak memory, CPU time).
///
/// Resource fields are `Option` because availability depends on the runtime's
/// sampling. When `None`, treat it as "unknown", not "zero".
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Numeric exit code in the range 0..=255. Signals map to `128 + signo`
    /// (POSIX shell convention).
    pub exit_code: i32,

    /// Wall-clock duration the sandbox process was alive, in milliseconds.
    pub wall_ms: u64,

    /// Bytes written to stdout by the sandboxed process. Capacity is bounded by
    /// the builder's `stdout_limit_bytes`; if the limit was hit,
    /// `stdout_truncated` is `true` and this holds exactly that many bytes.
    pub stdout: Vec<u8>,

    /// Bytes written to stderr by the sandboxed process. Same bounding
    /// semantics as `stdout`.
    pub stderr: Vec<u8>,

    /// `true` if the captured stdout reached the configured byte limit and was
    /// cut off. The remaining bytes were discarded (not stored).
    pub stdout_truncated: bool,

    /// `true` if the captured stderr reached the configured byte limit and was
    /// cut off.
    pub stderr_truncated: bool,

    /// Peak resident-set-size of the sandboxed process in bytes. `None` if the
    /// runtime did not sample it.
    ///
    /// **Check [`Self::resource_source`] before using this for billing.** When
    /// the source is [`ResourceSource::RusageFallback`] the figure comes from
    /// `getrusage(RUSAGE_CHILDREN)` and is **cumulative across all reaped
    /// children** of the calling process - it over-reports under sandbox reuse.
    pub peak_memory_bytes: Option<u64>,

    /// Total CPU time consumed by the sandboxed process across user and system
    /// mode, in milliseconds. `None` if the runtime did not sample it. Same
    /// caveat as [`Self::peak_memory_bytes`].
    pub cpu_time_ms: Option<u64>,

    /// Which sampling source produced [`Self::peak_memory_bytes`] and
    /// [`Self::cpu_time_ms`]. `Cgroup` is accurate, `RusageFallback`
    /// over-reports under sandbox reuse, `Unavailable` signals `None` figures.
    pub resource_source: ResourceSource,
}

/// View of a captured stream as UTF-8 text together with the truncation status,
/// so callers cannot silently consume incomplete output.
///
/// Returned by [`Outcome::stdout_text`] / [`Outcome::stderr_text`]. An agent
/// that acts on tool output without checking truncation may decide on partial
/// data; this view type makes both pieces impossible to drop.
#[derive(Debug, Clone, Copy)]
pub struct OutputView<'a> {
    /// The captured bytes interpreted as UTF-8. `None` if the bytes are not
    /// valid UTF-8 - callers can still read the raw `Vec<u8>` from
    /// `Outcome::stdout` / `stderr`.
    pub text: Option<&'a str>,

    /// `true` if the stream was cut off at the configured limit.
    pub truncated: bool,
}

impl<'a> OutputView<'a> {
    /// The captured text, only if it is complete (non-truncated). Returns `None`
    /// if the stream was truncated or not valid UTF-8. Use this where partial
    /// output must not be acted on.
    pub fn complete(&self) -> Option<&'a str> {
        if self.truncated {
            None
        } else {
            self.text
        }
    }
}

impl Outcome {
    /// `true` when the sandboxed command exited successfully (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    /// View stdout as `&str` if it is valid UTF-8, else `None`.
    ///
    /// # WARNING - silent truncation
    /// This helper does NOT signal truncation. If the process emitted more than
    /// `stdout_limit_bytes`, the returned string is a prefix and
    /// `stdout_truncated` is `true`. For decision paths prefer
    /// [`Self::stdout_text`], which surfaces truncation in its return value.
    pub fn stdout_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.stdout).ok()
    }

    /// View stderr as `&str` if it is valid UTF-8, else `None`. Same caveat as
    /// [`Self::stdout_str`].
    pub fn stderr_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.stderr).ok()
    }

    /// View stdout as text-plus-truncation-flag. The returned [`OutputView`]
    /// carries both the UTF-8 text (or `None`) AND the truncation status, so a
    /// caller cannot accidentally ignore truncation.
    pub fn stdout_text(&self) -> OutputView<'_> {
        OutputView {
            text: std::str::from_utf8(&self.stdout).ok(),
            truncated: self.stdout_truncated,
        }
    }

    /// View stderr as text-plus-truncation-flag. See [`Self::stdout_text`].
    pub fn stderr_text(&self) -> OutputView<'_> {
        OutputView {
            text: std::str::from_utf8(&self.stderr).ok(),
            truncated: self.stderr_truncated,
        }
    }
}
