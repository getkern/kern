//! Embeddable sandbox SDK - a fluent [`Sandbox::builder()`] over `kern box`.
//!
//! This is the library face of kern for programs that want to run untrusted or
//! semi-trusted code inside a real kernel isolation boundary (namespaces +
//! pivot_root + seccomp + cgroup v2) and get a structured [`Outcome`] back -
//! the exit code, captured stdout/stderr (with truncation flags), wall time,
//! and best-effort resource accounting.
//!
//! ```no_run
//! use kern_isolation::{Sandbox, SeccompMode};
//!
//! let out = Sandbox::builder()
//!     .rootfs("/var/lib/kern/rootfs/alpine")
//!     .no_network()          // isolated loopback-only netns (the default)
//!     .readonly_root()       // remount the root read-only after pivot
//!     .memory_limit_bytes(256 * 1024 * 1024)
//!     .cpus(0.5)             // half a core
//!     .pids_limit(128)       // fork-bomb ceiling
//!     .timeout_ms(5_000)     // SIGKILL a runaway after 5 s
//!     .env("LANG", "C")
//!     .build()
//!     .unwrap()
//!     .run("sh", &["-c", "echo hello"])
//!     .unwrap();
//!
//! assert!(out.success());
//! assert_eq!(out.stdout_str(), Some("hello\n"));
//! ```
//!
//! ## How it runs
//! The SDK shells out to the `kern` CLI as a privilege-separation layer: the
//! builder assembles a `kern box …` argument vector, spawns it with piped
//! stdio, feeds optional stdin, drains stdout/stderr concurrently (so a chatty
//! guest can't deadlock on a full pipe), and reaps the child. The `kern` binary
//! does the actual namespace/mount/cgroup setup. Locate it via `KERN_BIN`, then
//! `PATH`, then the usual install locations (see [`SandboxBuilder::build`]).
//!
//! ## Compose from a kern.toml
//! Instead of repeating resource flags, point the builder at the same
//! `kern.toml` that `kern top` / `kern config add` author and apply named
//! profiles by token:
//!
//! ```no_run
//! # use kern_isolation::Sandbox;
//! let out = Sandbox::builder()
//!     .rootfs("/var/lib/kern/rootfs/alpine")
//!     .config("./kern.toml")
//!     .profile("vcpu:small")      // CPU/memory/nice from [[vcpu]] name="small"
//!     .profile("vdisk:scratch")   // scratch disk mounted at /vdisk/scratch
//!     .build().unwrap()
//!     .run("sh", &["-c", "true"]).unwrap();
//! # let _ = out;
//! ```
//!
//! Tokens are `vcpu:`/`vgpio:`/`vdisk:` (the public set - GPU/`vgpu:` is a
//! private-runtime feature).
//!
//! ### Precedence - explicit setter over profile (no conflict, a defined override)
//! A `vcpu:` profile carries CPU/memory/cpuset (and nice); `vgpio:`/`vdisk:` add
//! devices/disks and overlap with nothing. When BOTH a `vcpu:` profile and the
//! matching explicit setter are present, the precedence is fixed and
//! deterministic: **explicit setter > profile > default** - the runtime
//! pre-seeds the caps from the explicit values and a profile fills only what is
//! still unset. So this is an intentional override, not an ambiguity:
//!
//! ```no_run
//! # use kern_isolation::Sandbox;
//! // "use vcpu:small, but bump CPU to 4 cores for this run":
//! let out = Sandbox::builder()
//!     .rootfs("/rootfs").config("./kern.toml")
//!     .profile("vcpu:small")   // e.g. cpus=1.5, memory=256m
//!     .cpus(4.0)               // WINS over the profile's 1.5; memory stays 256m
//!     .build().unwrap()
//!     .run("true", &[]).unwrap();
//! # let _ = out;
//! ```
//!
//! Only the three setters a `vcpu:` also sets can override it:
//! [`SandboxBuilder::cpus`], [`SandboxBuilder::memory_limit_bytes`],
//! [`SandboxBuilder::cpuset`]. If you want the profile's value, simply don't call
//! the matching setter.
//!
//! You never have to guess whether an override is happening: [`Sandbox::warnings`]
//! lists every such shadow (and duplicate env keys / volume targets) as a
//! human-readable advisory after `build()`. Genuine *contradictions* (two roots,
//! `bind_rootfs` + `readonly_root`, a zero limit, a malformed profile token, …)
//! are hard errors from `build()` instead - see its docs. So: contradictions
//! stop you; benign overrides are reported, never silent.
//!
//! ## Honest limits (public runtime)
//! - The public `kern box` **always** replaces the host filesystem with the
//!   given `rootfs`/`image` - there is no "share the host fs" mode, so
//!   [`SandboxBuilder::no_host_fs`] is the default and the method only affirms
//!   it. A rootfs or image is therefore **required**; [`SandboxBuilder::build`]
//!   rejects a config that sets neither.
//! - The public seccomp filter (hardened denylist) is **always on**;
//!   [`SandboxBuilder::seccomp`] is advisory - see its docs.
//! - Resource figures come from `getrusage(RUSAGE_CHILDREN)` today
//!   ([`crate::ResourceSource::RusageFallback`]); read `Outcome::resource_source`
//!   before treating them as per-sandbox-accurate.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Instant;

use crate::outcome::{Outcome, ResourceSource};

/// Errors returned by the sandbox SDK ([`Sandbox`] / [`SandboxBuilder`]).
///
/// Distinct from the crate's low-level [`crate::Error`] (raw syscall failures):
/// this type describes failures of the *embedding* API - a bad configuration,
/// a missing `kern` binary, or an I/O failure talking to the child.
#[derive(Debug)]
pub enum SandboxError {
    /// The configuration was rejected before spawning anything (e.g. no rootfs
    /// or image, or an empty command).
    InvalidConfig(String),
    /// The `kern` binary could not be located. Set `KERN_BIN` or install `kern`
    /// onto `PATH`.
    KernNotFound(String),
    /// Spawning or exec'ing the `kern` child failed.
    Spawn {
        /// The binary path we tried to run.
        command: String,
        /// Underlying OS error.
        source: std::io::Error,
    },
    /// An I/O failure while talking to the child (writing stdin, waiting).
    Io {
        /// Where the failure happened.
        context: String,
        /// Underlying OS error.
        source: std::io::Error,
    },
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::InvalidConfig(m) => write!(f, "invalid sandbox configuration: {m}"),
            SandboxError::KernNotFound(m) => write!(f, "{m}"),
            SandboxError::Spawn { command, source } => {
                write!(f, "failed to spawn {command}: {source}")
            }
            SandboxError::Io { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SandboxError::Spawn { source, .. } | SandboxError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Shorthand for `Result<T, SandboxError>` used across the SDK.
pub type SandboxResult<T> = std::result::Result<T, SandboxError>;

/// Selects the seccomp policy for the sandbox.
///
/// # Advisory on the public runtime
/// The public `kern box` installs its hardened **denylist** filter
/// unconditionally (it cannot be turned off from the SDK). This enum is kept so
/// embeddings share one API shape with the private runtime and so the intent is
/// explicit in caller code, but on the public runtime:
/// - [`Self::DenylistHardened`] is what actually runs (the default).
/// - [`Self::DenylistHardenedStrict`] and [`Self::Disabled`] are **not honored**
///   - the always-on hardened denylist applies regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeccompMode {
    /// No filter requested. **Not honored on the public runtime** - the
    /// built-in filter stays on.
    Disabled,
    /// Hardened denylist (the default, and what the public runtime always runs).
    #[default]
    DenylistHardened,
    /// Denylist with kill-on-violation. **Not honored on the public runtime** -
    /// treated as [`Self::DenylistHardened`].
    DenylistHardenedStrict,
}

/// Default output capture cap - 256 KiB per stream.
///
/// Sized to be safe under fan-out: a platform running 100 concurrent sandboxes
/// (agent grading, CI, batch) with a 16 MiB default would peak at 3.2 GiB just
/// for output buffers. 256 KiB fits typical agent output (JSON, diagnostics,
/// short reports) while a 100-box fan-out costs ~50 MiB. Raise it explicitly via
/// [`SandboxBuilder::stdout_limit_bytes`] / [`SandboxBuilder::stderr_limit_bytes`].
const DEFAULT_OUTPUT_LIMIT: usize = 256 * 1024;

/// A host directory or file to bind-mount into the sandbox (`-v src:dst[:ro]`).
#[derive(Debug, Clone)]
struct BindMount {
    source: String,
    target: String,
    read_only: bool,
}

/// A configured but not-yet-running sandbox. Create one with [`Sandbox::builder`].
#[derive(Debug, Clone)]
pub struct Sandbox {
    rootfs: Option<String>,
    image: Option<String>,
    bind_rootfs: bool,
    config: Option<String>,
    profiles: Vec<String>,
    share_net: bool,
    readonly_root: bool,
    hostname: Option<String>,
    workdir: Option<String>,
    #[allow(dead_code)] // advisory on the public runtime; see SeccompMode docs
    seccomp: SeccompMode,
    memory_limit_bytes: Option<u64>,
    memory_swap_max_bytes: Option<u64>,
    cpus: Option<f64>,
    cpuset: Option<String>,
    pids_limit: Option<u64>,
    volumes: Vec<BindMount>,
    env: Vec<(String, String)>,
    inherit_env: bool,
    timeout_ms: Option<u64>,
    // `Arc` so `run(&self)` can hand the payload to the writer thread with a cheap
    // refcount bump instead of copying the (possibly MB-scale) bytes every call.
    stdin_bytes: Option<Arc<Vec<u8>>>,
    stdout_limit_bytes: usize,
    stderr_limit_bytes: usize,
    /// Non-fatal advisories computed by [`SandboxBuilder::build`]: legal but
    /// potentially-surprising combinations (e.g. an explicit resource setter that
    /// shadows a profile's value). Surfaced via [`Sandbox::warnings`].
    warnings: Vec<String>,
}

impl Sandbox {
    /// Start configuring a new sandbox with secure-by-default values:
    /// - filesystem: isolated (the required `rootfs`/`image` is the whole view)
    /// - network: isolated loopback-only namespace
    /// - seccomp: the runtime's hardened denylist (always on)
    /// - environment: NOT inherited (only explicit [`SandboxBuilder::env`] vars)
    /// - no resource limits set
    ///
    /// You must set a [`SandboxBuilder::rootfs`] or [`SandboxBuilder::image`]
    /// before [`SandboxBuilder::build`].
    pub fn builder() -> SandboxBuilder {
        SandboxBuilder::default()
    }

    /// Non-fatal advisories about this configuration, computed at
    /// [`SandboxBuilder::build`]. Each is a legal-but-potentially-surprising
    /// combination the caller may want to surface to a human - most commonly an
    /// explicit resource setter (`.cpus`/`.memory_limit_bytes`/`.cpuset`) that
    /// **shadows** a `vcpu:` profile's value (the explicit one wins), duplicate
    /// env keys or volume targets (last wins), or multiple `vcpu:` profiles
    /// (first-to-set-a-field wins).
    ///
    /// Empty means the config has no known ambiguities. Genuine contradictions
    /// are hard errors from `build()` instead - this list is only for the cases
    /// that are well-defined but easy to misread. A CLI front-end should print
    /// these; an automated caller can log or ignore them.
    ///
    /// ```
    /// # use kern_isolation::Sandbox;
    /// let sb = Sandbox::builder()
    ///     .rootfs("/r").profile("vcpu:small").cpus(4.0)
    ///     .build().unwrap();
    /// assert!(sb.warnings().iter().any(|w| w.contains("cpus")));
    /// ```
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Execute `command` with `args` inside this sandbox configuration.
    ///
    /// Spawns `kern box …`, pipes stdio, feeds optional stdin, drains
    /// stdout/stderr concurrently, reaps the child, and returns a structured
    /// [`Outcome`].
    ///
    /// # Liveness
    /// `run()` returns once the `kern` child is reaped **and** both output pipes
    /// reach EOF. `kern box` runs the guest as PID 1 of its own PID namespace, so
    /// when that init exits the kernel tears down any surviving grandchildren and
    /// the pipe write-ends close. If you run fully untrusted code that may spawn
    /// background processes, set [`SandboxBuilder::timeout_ms`] so a wedged guest
    /// is force-killed rather than holding a pipe open.
    ///
    /// Resource figures in the returned [`Outcome`] come from
    /// `getrusage(RUSAGE_CHILDREN)`, which is **process-global**: under concurrent
    /// `run()` calls they conflate all reaped children and are unreliable per-box:
    /// check `Outcome::resource_source` (it reports
    /// [`crate::ResourceSource::RusageFallback`]).
    ///
    /// # Errors
    /// - [`SandboxError::InvalidConfig`] if `command` is empty.
    /// - [`SandboxError::KernNotFound`] if the `kern` binary can't be located.
    /// - [`SandboxError::Spawn`] if the child can't be started.
    /// - [`SandboxError::Io`] on a failure writing stdin or waiting on the child.
    pub fn run(&self, command: &str, args: &[&str]) -> SandboxResult<Outcome> {
        if command.is_empty() {
            return Err(SandboxError::InvalidConfig(
                "command must be non-empty".to_string(),
            ));
        }

        let kern_bin = resolve_kern_binary()?;
        let kern_args = self.assemble_kern_args(command, args);

        let start = Instant::now();
        let mut cmd = Command::new(&kern_bin);
        cmd.args(&kern_args);

        // Always pipe stdio so the SDK can present a structured Outcome - the
        // captured bytes are the primary product for the agent use case.
        cmd.stdin(if self.stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // The guest env is set inside the box via `--env` (see assemble). Here we
        // scope the env of the KERN CLI PROCESS itself. Unless the caller opts
        // into inheritance, clear it and forward only what kern needs to run:
        //   PATH                    - resolve the kern binary's own helpers
        //   HOME                    - locate ~/.config/kern (config + registry)
        //   XDG_RUNTIME_DIR,
        //   DBUS_SESSION_BUS_ADDRESS - cgroup v2 delegation via the user session
        //   USER, LOGNAME           - user-scope identity
        if !self.inherit_env {
            cmd.env_clear();
            for key in [
                "PATH",
                "HOME",
                "XDG_RUNTIME_DIR",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "DBUS_SESSION_BUS_ADDRESS",
                "USER",
                "LOGNAME",
            ] {
                if let Some(val) = std::env::var_os(key) {
                    cmd.env(key, val);
                }
            }
        }

        let mut child = cmd.spawn().map_err(|source| SandboxError::Spawn {
            command: kern_bin.display().to_string(),
            source,
        })?;

        // Drain both output streams concurrently to avoid a pipe-buffer deadlock:
        // a child writing >~64 KiB to one stream would block if we read serially.
        // These MUST start before we push stdin - otherwise a large stdin (the
        // main thread blocked in write_all) plus a guest that writes output
        // before consuming all of stdin deadlocks: nobody drains stdout while we
        // wait to finish feeding stdin, and the guest can't make progress.
        let stdout_handle = child.stdout.take().map(|s| {
            let limit = self.stdout_limit_bytes;
            std::thread::spawn(move || read_capped(s, limit))
        });
        let stderr_handle = child.stderr.take().map(|s| {
            let limit = self.stderr_limit_bytes;
            std::thread::spawn(move || read_capped(s, limit))
        });

        // Feed stdin on its own thread so a large payload can't block the
        // reap/drain path (and a guest that reads only a prefix and exits gives
        // us EPIPE, which we intentionally ignore). Dropping the handle at the
        // end of the closure signals EOF to the guest.
        let stdin_handle = self.stdin_bytes.clone().and_then(|bytes| {
            child.stdin.take().map(|mut sin| {
                std::thread::spawn(move || {
                    use std::io::Write as _;
                    let _ = sin.write_all(&bytes[..]);
                })
            })
        });

        let status = match child.wait() {
            Ok(s) => s,
            Err(source) => {
                // A `wait()` failure is rare (std retries EINTR), but if it happens
                // don't leave a zombie or a detached writer: kill, reap, join.
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = stdin_handle {
                    let _ = h.join();
                }
                return Err(SandboxError::Io {
                    context: "waitpid on kern child".to_string(),
                    source,
                });
            }
        };
        if let Some(h) = stdin_handle {
            let _ = h.join();
        }

        let (peak_memory_bytes, cpu_time_ms, resource_source) = sample_resource_usage();

        let (stdout, stdout_truncated) = stdout_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_else(|| (Vec::new(), false));
        let (stderr, stderr_truncated) = stderr_handle
            .and_then(|h| h.join().ok())
            .unwrap_or_else(|| (Vec::new(), false));

        let wall_ms = start.elapsed().as_millis() as u64;
        let exit_code = status.code().unwrap_or_else(|| {
            // No code → killed by signal. Match POSIX shell convention.
            use std::os::unix::process::ExitStatusExt as _;
            status.signal().map(|s| 128 + s).unwrap_or(1)
        });

        Ok(Outcome {
            exit_code,
            wall_ms,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
            peak_memory_bytes,
            cpu_time_ms,
            resource_source,
        })
    }

    /// Assemble the `kern box …` argument vector for this config. Private so the
    /// wire format stays an implementation detail.
    fn assemble_kern_args(&self, command: &str, args: &[&str]) -> Vec<String> {
        // Pre-size for the fixed flags (~24), the profile tokens, the per-volume
        // (-v VALUE) and per-env (--env VALUE) pairs, and the command + its args -
        // so a profile- or volume-heavy config doesn't realloc mid-build.
        let mut out: Vec<String> = Vec::with_capacity(
            args.len() + self.profiles.len() + self.volumes.len() * 2 + self.env.len() * 2 + 24,
        );
        out.push("box".to_string());
        // Quiet: suppress kern's own setup chatter so captured stdout/stderr are
        // exactly the guest's. (kern auto-assigns the box name.)
        out.push("-q".to_string());

        if let Some(r) = &self.rootfs {
            out.push("--rootfs".to_string());
            out.push(r.clone());
        }
        if let Some(img) = &self.image {
            out.push("--image".to_string());
            out.push(img.clone());
        }
        if self.bind_rootfs {
            out.push("--bind-rootfs".to_string());
        }
        // Compose from a kern.toml: point the box at the config, if any. The box
        // resolves the profile tokens (below) against it; explicit builder
        // setters above already emitted their flags, and the box's "explicit
        // flag wins" merge means those override any profile value.
        if let Some(cfg) = &self.config {
            out.push("--config".to_string());
            out.push(cfg.clone());
        }
        // Network: isolated (loopback-only) is the default; opt into host net.
        if self.share_net {
            out.push("--net".to_string());
        }
        if self.readonly_root {
            out.push("--read-only".to_string());
        }
        if let Some(h) = &self.hostname {
            out.push("--hostname".to_string());
            out.push(h.clone());
        }
        if let Some(d) = &self.workdir {
            out.push("--workdir".to_string());
            out.push(d.clone());
        }
        if let Some(bytes) = self.memory_limit_bytes {
            out.push("--memory".to_string());
            out.push(format!("{bytes}"));
        }
        if let Some(bytes) = self.memory_swap_max_bytes {
            out.push("--memory-swap-max".to_string());
            out.push(format!("{bytes}"));
        }
        if let Some(c) = self.cpus {
            out.push("--cpus".to_string());
            out.push(format!("{c}"));
        }
        if let Some(cs) = &self.cpuset {
            out.push("--cpuset-cpus".to_string());
            out.push(cs.clone());
        }
        if let Some(pids) = self.pids_limit {
            out.push("--pids-limit".to_string());
            out.push(format!("{pids}"));
        }
        if let Some(ms) = self.timeout_ms {
            // `--timeout` takes whole SECONDS; round sub-second up so the kill
            // still fires (0 stays 0 = no timeout).
            let secs = if ms == 0 { 0 } else { ms.div_ceil(1000).max(1) };
            out.push("--timeout".to_string());
            out.push(format!("{secs}"));
        }
        for v in &self.volumes {
            out.push("-v".to_string());
            out.push(if v.read_only {
                format!("{}:{}:ro", v.source, v.target)
            } else {
                format!("{}:{}", v.source, v.target)
            });
        }
        // Guest environment (the box starts from a clean env - pass each var in).
        for (k, val) in &self.env {
            out.push("--env".to_string());
            out.push(format!("{k}={val}"));
        }
        // Resource-profile tokens (`vcpu:`/`vgpio:`/`vdisk:`) - bare positionals the
        // box classifies as profiles (validated at build() so none can be mistaken
        // for the box name). Must sit before the `--` separator.
        for p in &self.profiles {
            out.push(p.clone());
        }

        out.push("--".to_string());
        out.push(command.to_string());
        for a in args {
            out.push((*a).to_string());
        }
        out
    }
}

/// Builder for [`Sandbox`]. Each method consumes and returns `self` for fluent
/// chaining; defaults are secure (isolated fs + net, no inherited env).
#[derive(Debug, Clone)]
pub struct SandboxBuilder {
    inner: Sandbox,
}

impl Default for SandboxBuilder {
    fn default() -> Self {
        SandboxBuilder {
            inner: Sandbox {
                rootfs: None,
                image: None,
                bind_rootfs: false,
                config: None,
                profiles: Vec::new(),
                share_net: false,
                readonly_root: false,
                hostname: None,
                workdir: None,
                seccomp: SeccompMode::default(),
                memory_limit_bytes: None,
                memory_swap_max_bytes: None,
                cpus: None,
                cpuset: None,
                pids_limit: None,
                volumes: Vec::new(),
                env: Vec::new(),
                inherit_env: false,
                timeout_ms: None,
                stdin_bytes: None,
                stdout_limit_bytes: DEFAULT_OUTPUT_LIMIT,
                stderr_limit_bytes: DEFAULT_OUTPUT_LIMIT,
                warnings: Vec::new(),
            },
        }
    }
}

impl SandboxBuilder {
    /// Use `dir` as the sandbox root filesystem (pivoted in as an overlay by
    /// default). Required unless [`Self::image`] is set.
    pub fn rootfs(mut self, dir: impl Into<String>) -> Self {
        self.inner.rootfs = Some(dir.into());
        self
    }

    /// Pull and run the given OCI image reference (e.g. `alpine`, `alpine:3.19`)
    /// as the root filesystem. Alternative to [`Self::rootfs`].
    pub fn image(mut self, reference: impl Into<String>) -> Self {
        self.inner.image = Some(reference.into());
        self
    }

    /// Bind the `rootfs` directly instead of layering an overlay - faster on
    /// kernels with slow overlayfs, at the cost of a mutable, shared root.
    /// Only valid with [`Self::rootfs`] (not [`Self::image`]) and not with
    /// [`Self::readonly_root`].
    pub fn bind_rootfs(mut self) -> Self {
        self.inner.bind_rootfs = true;
        self
    }

    /// Affirm that the host filesystem is not shared. This is the default on the
    /// public runtime (the box only ever sees its `rootfs`/`image`), so the
    /// method exists for API symmetry and to make the intent explicit.
    pub fn no_host_fs(self) -> Self {
        // No-op: the public kern box always replaces the host filesystem.
        self
    }

    /// Compose the box from a `kern.toml` config file (the same file `kern top`
    /// and `kern config add` author). Its resource **profiles** are applied by
    /// name via [`Self::profile`]. Without this, the box uses its default config
    /// path (`$KERN_CONFIG`, else `~/.config/kern/kern.toml`).
    ///
    /// Explicit builder setters (e.g. [`Self::cpus`], [`Self::memory_limit_bytes`])
    /// win over a profile's value - the runtime's "explicit flag wins" merge.
    pub fn config(mut self, path: impl Into<String>) -> Self {
        self.inner.config = Some(path.into());
        self
    }

    /// Apply a named resource profile from the `kern.toml` (see [`Self::config`]).
    /// The token is `vcpu:<name>` (CPU/memory/nice), `vgpio:<name>` (GPIO device
    /// exposure), or `vdisk:<name>` (a scratch/persistent disk mounted at
    /// `/vdisk/<name>`). Repeatable; `vgpio`/`vdisk` accumulate, a `vcpu` fills
    /// only the resources not already set explicitly.
    ///
    /// The token prefix and non-empty name are validated at [`Self::build`], so a
    /// malformed token fails fast instead of being silently taken as the box name.
    /// (GPU/`vgpu:` profiles are a private-runtime feature and are not accepted
    /// here.)
    pub fn profile(mut self, token: impl Into<String>) -> Self {
        self.inner.profiles.push(token.into());
        self
    }

    /// Isolate the network in a loopback-only namespace. This is the default;
    /// the method makes it explicit. The inverse is [`Self::share_network`].
    pub fn no_network(mut self) -> Self {
        self.inner.share_net = false;
        self
    }

    /// Share the host network namespace instead of isolating it. Opt-in - gives
    /// the box outbound networking at the cost of network isolation.
    pub fn share_network(mut self) -> Self {
        self.inner.share_net = true;
        self
    }

    /// Remount the root filesystem read-only after pivot. Not compatible with
    /// [`Self::bind_rootfs`].
    pub fn readonly_root(mut self) -> Self {
        self.inner.readonly_root = true;
        self
    }

    /// Set the sandbox UTS-namespace hostname.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.inner.hostname = Some(hostname.into());
        self
    }

    /// Set the working directory the sandboxed process is `chdir`'d into before
    /// `exec`.
    pub fn workdir(mut self, dir: impl Into<String>) -> Self {
        self.inner.workdir = Some(dir.into());
        self
    }

    /// Select the seccomp policy. **Advisory on the public runtime** - see
    /// [`SeccompMode`]. The hardened denylist is always on regardless.
    pub fn seccomp(mut self, mode: SeccompMode) -> Self {
        self.inner.seccomp = mode;
        self
    }

    /// Bind-mount a host path into the box at `target` (`-v source:target`).
    /// The primary way data crosses the sandbox boundary. Pass `read_only` to
    /// mount it `:ro`.
    pub fn volume(
        mut self,
        source: impl Into<String>,
        target: impl Into<String>,
        read_only: bool,
    ) -> Self {
        self.inner.volumes.push(BindMount {
            source: source.into(),
            target: target.into(),
            read_only,
        });
        self
    }

    /// Set a hard memory limit in bytes (cgroup v2 `memory.max`). The box is
    /// OOM-killed if it exceeds this bound.
    pub fn memory_limit_bytes(mut self, bytes: u64) -> Self {
        self.inner.memory_limit_bytes = Some(bytes);
        self
    }

    /// Set the swap allowance in bytes (cgroup v2 `memory.swap.max`). This is
    /// the v2 swap limit, NOT a combined mem+swap total.
    pub fn memory_swap_max_bytes(mut self, bytes: u64) -> Self {
        self.inner.memory_swap_max_bytes = Some(bytes);
        self
    }

    /// Cap CPU in cores (K8s semantics: `1.5` = one and a half cores) via cgroup
    /// v2 `cpu.max`. Best-effort where the CPU controller isn't delegated.
    pub fn cpus(mut self, cores: f64) -> Self {
        self.inner.cpus = Some(cores);
        self
    }

    /// Set the CPU quota per 100 ms scheduling period in microseconds, e.g.
    /// `cpu_quota_us(50_000)` = half a core. Convenience wrapper over
    /// [`Self::cpus`] for callers that think in quota-microseconds
    /// (`cores = quota_us / 100_000`).
    pub fn cpu_quota_us(self, quota_us: u64) -> Self {
        self.cpus(quota_us as f64 / 100_000.0)
    }

    /// Pin the box to a CPU set (`"0-3"`, `"0,2,4"`) via `sched_setaffinity`
    /// (and `cpuset.cpus` where delegated).
    pub fn cpuset(mut self, list: impl Into<String>) -> Self {
        self.inner.cpuset = Some(list.into());
        self
    }

    /// Cap the number of PIDs the box may create (cgroup v2 `pids.max`).
    /// Fork-bomb containment.
    pub fn pids_limit(mut self, limit: u64) -> Self {
        self.inner.pids_limit = Some(limit);
        self
    }

    /// Add an environment variable visible to the sandboxed process. Repeatable;
    /// later values override earlier ones for the same key.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner.env.push((key.into(), value.into()));
        self
    }

    /// By default the host environment is NOT inherited by the `kern` process
    /// (only a small whitelist kern needs to run, plus any [`Self::env`] vars
    /// passed to the guest). Call this to inherit the full host environment into
    /// the `kern` process. Rarely needed; prefer explicit [`Self::env`].
    pub fn inherit_env(mut self) -> Self {
        self.inner.inherit_env = true;
        self
    }

    /// Send `SIGKILL` to the box if it hasn't exited within the given duration.
    /// Rounded up to whole seconds (the runtime's granularity). `0` = no timeout.
    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.inner.timeout_ms = Some(ms);
        self
    }

    /// Pipe `bytes` into the box's stdin. If not set, stdin is `/dev/null`.
    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.inner.stdin_bytes = Some(Arc::new(bytes.into()));
        self
    }

    /// Cap stdout capture at `bytes`; excess is discarded and
    /// `Outcome::stdout_truncated` is set. Default: 256 KiB.
    pub fn stdout_limit_bytes(mut self, bytes: usize) -> Self {
        self.inner.stdout_limit_bytes = bytes;
        self
    }

    /// Cap stderr capture at `bytes`. Default: 256 KiB.
    pub fn stderr_limit_bytes(mut self, bytes: usize) -> Self {
        self.inner.stderr_limit_bytes = bytes;
        self
    }

    /// Validate the configuration and return the immutable [`Sandbox`].
    ///
    /// # Errors
    /// [`SandboxError::InvalidConfig`] if:
    /// - neither [`Self::rootfs`] nor [`Self::image`] is set (the public box has
    ///   no default root), or both are, or either is an empty string;
    /// - [`Self::bind_rootfs`] is combined with [`Self::image`] or
    ///   [`Self::readonly_root`] (a bind root is mutable-only and needs a dir);
    /// - a resource limit is nonsensical: [`Self::cpus`] not finite-and-positive,
    ///   a zero [`Self::memory_limit_bytes`] or [`Self::pids_limit`];
    /// - an [`Self::env`] key is empty or contains `=`, or an empty
    ///   [`Self::hostname`] / [`Self::workdir`] / [`Self::config`] was set;
    /// - a [`Self::profile`] token is not `vcpu:`/`vgpio:`/`vdisk:` with a
    ///   non-empty name.
    ///
    /// Validating here means a bad value fails fast with a clear message instead
    /// of surfacing later as a cryptic `kern box` usage error (or, worse, being
    /// silently dropped).
    pub fn build(self) -> SandboxResult<Sandbox> {
        let s = &self.inner;
        let bad = |m: &str| Err(SandboxError::InvalidConfig(m.to_string()));

        match (s.rootfs.is_some(), s.image.is_some()) {
            (false, false) => {
                return bad(
                    "set a rootfs (.rootfs) or an image (.image) - the sandbox has no default root",
                )
            }
            (true, true) => return bad("set either .rootfs or .image, not both"),
            _ => {}
        }
        if s.rootfs.as_deref() == Some("") {
            return bad("rootfs path must not be empty");
        }
        if s.image.as_deref() == Some("") {
            return bad("image reference must not be empty");
        }
        if s.bind_rootfs {
            if s.image.is_some() {
                return bad(
                    "bind_rootfs needs a rootfs directory; an image stays an immutable overlay",
                );
            }
            if s.readonly_root {
                return bad(
                    "bind_rootfs is writable-only; drop readonly_root to bind, or drop bind_rootfs \
                     for a read-only overlay root",
                );
            }
        }
        // Resource limits: a limit set to a nonsensical value is a caller bug, not
        // "unlimited" (that's `None`) - reject it rather than let kern do so cryptically.
        if let Some(c) = s.cpus {
            if !c.is_finite() || c <= 0.0 {
                return bad("cpus must be a finite positive number of cores (e.g. 0.5, 2.0)");
            }
        }
        if s.memory_limit_bytes == Some(0) {
            return bad("memory_limit_bytes must be > 0 (omit it for no limit)");
        }
        if s.pids_limit == Some(0) {
            return bad("pids_limit must be >= 1 (omit it for the default)");
        }
        for (k, _) in &s.env {
            if k.is_empty() || k.contains('=') {
                return bad("env keys must be non-empty and must not contain '='");
            }
        }
        if s.hostname.as_deref() == Some("") {
            return bad("hostname must not be empty");
        }
        if s.workdir.as_deref() == Some("") {
            return bad("workdir must not be empty");
        }
        if s.config.as_deref() == Some("") {
            return bad("config path must not be empty");
        }
        // Volumes: source and target must be non-empty and colon-free. The box's
        // `-v src:target[:ro]` spec is colon-delimited, so a `:` in either field
        // would shift the fields and silently mis-mount - reject it up front.
        for v in &s.volumes {
            if v.source.is_empty() || v.target.is_empty() {
                return bad("volume source and target must both be non-empty");
            }
            if v.source.contains(':') || v.target.contains(':') {
                return bad("volume source/target must not contain ':' (it delimits the -v spec)");
            }
        }
        // Profile tokens: each MUST be a recognized `<kind>:<name>` (vcpu/vgpio/
        // vdisk) with a SAFE name. This is security-relevant on two counts:
        //  (a) an unrecognized bare token would not classify as a profile and the
        //      box would silently adopt it as the box NAME; and
        //  (b) the name flows into a mount path (`/vdisk/<name>`) and a config
        //      lookup, so a `..`/`/` in it could traverse outside the intended
        //      target - reject anything but `[A-Za-z0-9._-]` (and no `..`).
        for tok in &s.profiles {
            let name = ["vcpu:", "vgpio:", "vdisk:"]
                .iter()
                .find_map(|p| tok.strip_prefix(p));
            if !name.is_some_and(is_safe_profile_name) {
                return Err(SandboxError::InvalidConfig(format!(
                    "profile token {tok:?} must be vcpu:<name>, vgpio:<name>, or vdisk:<name> \
                     with a name of [A-Za-z0-9._-] (no '/', no '..'); vgpu:/GPU profiles are \
                     private-runtime only"
                )));
            }
        }
        // Config is coherent (no contradictions). Compute the non-fatal advisories
        // - the shadowing / duplicate cases that are well-defined but easy to
        // misread - so `Sandbox::warnings()` can surface them to a human.
        let mut inner = self.inner;
        inner.warnings = compute_warnings(&inner);
        Ok(inner)
    }
}

/// A safe resource-profile name: non-empty, only `[A-Za-z0-9._-]`, and no `..`
/// (nor a lone `.`), so it can't traverse out of a mount path (`/vdisk/<name>`)
/// or a config lookup. The SDK is the caller-facing validation layer, so it
/// rejects a hostile name here rather than trust the runtime to.
fn is_safe_profile_name(n: &str) -> bool {
    !n.is_empty()
        && n != "."
        && !n.contains("..")
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Compute the non-fatal advisories for a coherent config (see [`Sandbox::warnings`]).
///
/// The SDK does not parse the `kern.toml`, so a "shadows a vcpu: profile" advisory
/// is deliberately conditional ("if that profile also sets …"): it fires whenever
/// BOTH an explicit resource setter and a `vcpu:` profile are present, because the
/// caller can't otherwise tell that the explicit value takes precedence.
fn compute_warnings(s: &Sandbox) -> Vec<String> {
    let mut w = Vec::new();
    let vcpu_count = s.profiles.iter().filter(|p| p.starts_with("vcpu:")).count();

    if vcpu_count > 0 {
        if s.cpus.is_some() {
            w.push(
                "explicit .cpus() is set together with a vcpu: profile - if that profile also \
                 sets CPU cores, your explicit .cpus() wins (drop one to remove the ambiguity)"
                    .to_string(),
            );
        }
        if s.memory_limit_bytes.is_some() {
            w.push(
                "explicit .memory_limit_bytes() is set together with a vcpu: profile - if that \
                 profile also sets memory, your explicit value wins"
                    .to_string(),
            );
        }
        if s.cpuset.is_some() {
            w.push(
                "explicit .cpuset() is set together with a vcpu: profile - if that profile also \
                 pins CPUs, your explicit value wins"
                    .to_string(),
            );
        }
    }
    if vcpu_count > 1 {
        w.push(format!(
            "{vcpu_count} vcpu: profiles applied - each resource is taken from the FIRST profile \
             that sets it; later vcpu: profiles only fill what is still unset"
        ));
    }

    // Duplicate env keys / volume targets: the last one wins (the box applies them
    // in order). `duplicated` reports each repeated value once.
    for k in duplicated(s.env.iter().map(|(k, _)| k)) {
        w.push(format!(
            "env key {k:?} is set more than once - the last value wins"
        ));
    }
    for t in duplicated(s.volumes.iter().map(|v| &v.target)) {
        w.push(format!(
            "volume target {t:?} is mounted more than once - the last source wins"
        ));
    }
    w
}

/// The values that appear more than once in `items`, each returned once, in
/// first-seen order. Used to warn about duplicate env keys / volume targets.
fn duplicated<T: PartialEq>(items: impl Iterator<Item = T>) -> Vec<T> {
    let mut seen: Vec<T> = Vec::new();
    let mut dups: Vec<T> = Vec::new();
    for it in items {
        if seen.contains(&it) {
            if !dups.contains(&it) {
                dups.push(it);
            }
        } else {
            seen.push(it);
        }
    }
    dups
}

/// Sample resource usage of the just-finished sandbox via
/// `getrusage(RUSAGE_CHILDREN)`.
///
/// Documented caveat: `ru_maxrss` is cumulative over all reaped children and may
/// over-report when one `Sandbox` is reused across many `run()` calls - hence
/// [`ResourceSource::RusageFallback`] is reported so callers know the precision.
fn sample_resource_usage() -> (Option<u64>, Option<u64>, ResourceSource) {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut ru) };
    if r != 0 {
        return (None, None, ResourceSource::Unavailable);
    }
    // ru_maxrss is in KiB on Linux; convert to bytes.
    let peak = (ru.ru_maxrss as u64).saturating_mul(1024);
    let user_ms =
        (ru.ru_utime.tv_sec as u64).saturating_mul(1_000) + (ru.ru_utime.tv_usec as u64) / 1_000;
    let sys_ms =
        (ru.ru_stime.tv_sec as u64).saturating_mul(1_000) + (ru.ru_stime.tv_usec as u64) / 1_000;
    let peak = if peak > 0 { Some(peak) } else { None };
    let cpu = Some(user_ms.saturating_add(sys_ms));
    if peak.is_none() && cpu.is_none() {
        (None, None, ResourceSource::Unavailable)
    } else {
        (peak, cpu, ResourceSource::RusageFallback)
    }
}

/// Read from `r` until EOF or `limit` bytes, whichever comes first. Returns
/// `(bytes, truncated)`. After the cap is hit we keep draining (so the child's
/// writes don't block on a full pipe) but discard the excess.
fn read_capped(mut r: impl std::io::Read, limit: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::with_capacity(limit.min(64 * 1024));
    let mut scratch = [0u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let n = match r.read(&mut scratch) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if buf.len() >= limit {
            truncated = true;
            continue;
        }
        let remaining = limit.saturating_sub(buf.len());
        let take = n.min(remaining);
        buf.extend_from_slice(&scratch[..take]);
        if take < n {
            truncated = true;
        }
    }
    (buf, truncated)
}

/// Locate the `kern` binary this SDK delegates to. Lookup order: `KERN_BIN`
/// (absolute path), then `kern` on `PATH`, then common install locations.
fn resolve_kern_binary() -> SandboxResult<PathBuf> {
    if let Some(env_path) = std::env::var_os("KERN_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("kern");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    for fallback in ["/usr/local/bin/kern", "/usr/bin/kern"] {
        let p = PathBuf::from(fallback);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        for sub in [".cargo/bin/kern", ".local/bin/kern"] {
            let p = home.join(sub);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    Err(SandboxError::KernNotFound(
        "could not locate the `kern` binary; set KERN_BIN or install kern onto PATH".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The command vector `run()` would spawn - pure, so the security-critical
    /// flag translation is testable without spawning anything.
    fn args(s: &Sandbox, cmd: &str, a: &[&str]) -> Vec<String> {
        s.assemble_kern_args(cmd, a)
    }

    #[test]
    fn build_requires_a_root() {
        let e = Sandbox::builder().build().unwrap_err();
        assert!(matches!(e, SandboxError::InvalidConfig(_)));
        // rootfs alone is fine.
        assert!(Sandbox::builder().rootfs("/r").build().is_ok());
        // image alone is fine.
        assert!(Sandbox::builder().image("alpine").build().is_ok());
        // both is rejected.
        assert!(Sandbox::builder()
            .rootfs("/r")
            .image("alpine")
            .build()
            .is_err());
    }

    #[test]
    fn build_rejects_nonsensical_limits_and_strings() {
        let b = || Sandbox::builder().rootfs("/r");
        // cpus: non-finite / non-positive rejected; positive fine.
        assert!(b().cpus(f64::NAN).build().is_err());
        assert!(b().cpus(f64::INFINITY).build().is_err());
        assert!(b().cpus(0.0).build().is_err());
        assert!(b().cpus(-1.0).build().is_err());
        assert!(b().cpus(0.5).build().is_ok());
        // zero memory / pids rejected (None = unlimited is the way to say "no cap").
        assert!(b().memory_limit_bytes(0).build().is_err());
        assert!(b().memory_limit_bytes(1).build().is_ok());
        assert!(b().pids_limit(0).build().is_err());
        assert!(b().pids_limit(1).build().is_ok());
        // swap 0 is VALID (swap off), not a bug.
        assert!(b().memory_swap_max_bytes(0).build().is_ok());
        // empty rootfs/image/hostname/workdir rejected.
        assert!(Sandbox::builder().rootfs("").build().is_err());
        assert!(Sandbox::builder().image("").build().is_err());
        assert!(b().hostname("").build().is_err());
        assert!(b().workdir("").build().is_err());
        // env key hygiene: empty or '='-containing key rejected; value is free.
        assert!(b().env("", "v").build().is_err());
        assert!(b().env("A=B", "v").build().is_err());
        assert!(b().env("OK", "any=thing you like").build().is_ok());
    }

    #[test]
    fn config_and_profiles_map_to_flags_before_the_separator() {
        let s = Sandbox::builder()
            .rootfs("/r")
            .config("/etc/kern.toml")
            .profile("vcpu:small")
            .profile("vgpio:leds")
            .profile("vdisk:scratch")
            .build()
            .unwrap();
        let a = args(&s, "sh", &["-c", "true"]);
        // --config <path> present with its value.
        let ci = a.iter().position(|x| x == "--config").unwrap();
        assert_eq!(a[ci + 1], "/etc/kern.toml");
        // Every profile token appears, and BEFORE the `--` separator (else the box
        // would treat it as the command, not a profile).
        let dd = a.iter().position(|x| x == "--").unwrap();
        for tok in ["vcpu:small", "vgpio:leds", "vdisk:scratch"] {
            let at = a.iter().position(|x| x == tok).expect("token present");
            assert!(at < dd, "{tok} must precede the -- separator");
        }
        // command still lands after the separator.
        assert_eq!(a[dd + 1], "sh");
    }

    #[test]
    fn build_rejects_malformed_or_gpu_profile_tokens() {
        let b = || Sandbox::builder().rootfs("/r");
        // Good tokens.
        assert!(b().profile("vcpu:x").build().is_ok());
        assert!(b().profile("vgpio:y").profile("vdisk:z").build().is_ok());
        // A bare token (no kind:) would be silently taken as the box NAME - reject.
        assert!(b().profile("small").build().is_err());
        // Empty name after the colon.
        assert!(b().profile("vcpu:").build().is_err());
        // Unknown / private-only kinds.
        assert!(b().profile("vgpu:big").build().is_err());
        assert!(b().profile("gpu:0").build().is_err());
        // Empty config path.
        assert!(b().config("").build().is_err());
        // A flag-looking token can't sneak through as a profile either.
        assert!(b().profile("--net").build().is_err());
        // Path-traversal / unsafe chars in the NAME are rejected (name flows into
        // /vdisk/<name> and a config lookup).
        assert!(b().profile("vdisk:../../../etc").build().is_err());
        assert!(b().profile("vcpu:a/b").build().is_err());
        assert!(b().profile("vgpio:..").build().is_err());
        assert!(b().profile("vdisk:a b").build().is_err());
        assert!(b().profile("vcpu:a\nb").build().is_err());
        // Dotted/hyphenated/underscored names are fine.
        assert!(b().profile("vdisk:scratch-1.tmp_v2").build().is_ok());
    }

    #[test]
    fn build_rejects_ambiguous_volume_specs() {
        let b = || Sandbox::builder().rootfs("/r");
        // A ':' in source/target would shift the -v src:tgt[:ro] fields.
        assert!(b().volume("/a:b", "/mnt", false).build().is_err());
        assert!(b().volume("/a", "/mn:t", false).build().is_err());
        // Empty source/target rejected.
        assert!(b().volume("", "/mnt", false).build().is_err());
        assert!(b().volume("/a", "", false).build().is_err());
        // A normal volume is fine.
        assert!(b().volume("/data", "/mnt/data", true).build().is_ok());
    }

    #[test]
    fn warnings_flag_shadowing_and_duplicates_but_not_clean_configs() {
        // A clean config with no overlaps → no warnings.
        let clean = Sandbox::builder()
            .rootfs("/r")
            .profile("vdisk:scratch")
            .cpus(2.0)
            .build()
            .unwrap();
        assert!(clean.warnings().is_empty(), "clean config must be quiet");

        // Explicit .cpus() shadowing a vcpu: profile → one warning mentioning cpus.
        let shadow = Sandbox::builder()
            .rootfs("/r")
            .profile("vcpu:small")
            .cpus(4.0)
            .build()
            .unwrap();
        assert!(shadow.warnings().iter().any(|w| w.contains("cpus")));

        // memory + cpuset shadowing too, plus multiple vcpu: profiles.
        let many = Sandbox::builder()
            .rootfs("/r")
            .profile("vcpu:a")
            .profile("vcpu:b")
            .memory_limit_bytes(1 << 20)
            .cpuset("0-1")
            .build()
            .unwrap();
        assert!(many.warnings().iter().any(|w| w.contains("memory")));
        assert!(many.warnings().iter().any(|w| w.contains("cpuset")));
        assert!(many.warnings().iter().any(|w| w.contains("vcpu: profiles")));

        // Duplicate env key and duplicate volume target each warn once.
        let dup = Sandbox::builder()
            .rootfs("/r")
            .env("K", "1")
            .env("K", "2")
            .volume("/a", "/mnt", false)
            .volume("/b", "/mnt", true)
            .build()
            .unwrap();
        assert_eq!(
            dup.warnings()
                .iter()
                .filter(|w| w.contains("env key"))
                .count(),
            1
        );
        assert!(dup.warnings().iter().any(|w| w.contains("volume target")));
        // A vdisk:/vgpio: profile alongside .cpus() is NOT a shadow (no overlap).
        let no_overlap = Sandbox::builder()
            .rootfs("/r")
            .profile("vgpio:leds")
            .cpus(1.0)
            .build()
            .unwrap();
        assert!(no_overlap.warnings().is_empty());
    }

    #[test]
    fn conflict_matrix_hard_errors_are_complete() {
        // Every genuine contradiction is rejected by build() (not a warning).
        let err = |b: SandboxBuilder| b.build().is_err();
        assert!(err(Sandbox::builder())); // no root
        assert!(err(Sandbox::builder().rootfs("/r").image("x"))); // both roots
        assert!(err(Sandbox::builder().image("x").bind_rootfs())); // bind needs a dir
        assert!(err(Sandbox::builder()
            .rootfs("/r")
            .bind_rootfs()
            .readonly_root())); // bind vs ro
        assert!(err(Sandbox::builder().rootfs("/r").cpus(0.0))); // nonsense cpus
        assert!(err(Sandbox::builder().rootfs("/r").memory_limit_bytes(0))); // zero mem
        assert!(err(Sandbox::builder().rootfs("/r").pids_limit(0))); // zero pids
        assert!(err(Sandbox::builder().rootfs("/r").profile("bogus"))); // bad token
        assert!(err(Sandbox::builder().rootfs("/r").config(""))); // empty config
                                                                  // And a fully-specified coherent config with overrides is NOT an error
                                                                  // (it's a warning) - override is a supported pattern.
        assert!(Sandbox::builder()
            .rootfs("/r")
            .config("/k.toml")
            .profile("vcpu:small")
            .profile("vdisk:scratch")
            .cpus(4.0)
            .memory_limit_bytes(1 << 28)
            .build()
            .is_ok());
    }

    #[test]
    fn build_rejects_incoherent_bind_rootfs() {
        assert!(Sandbox::builder()
            .image("alpine")
            .bind_rootfs()
            .build()
            .is_err());
        assert!(Sandbox::builder()
            .rootfs("/r")
            .bind_rootfs()
            .readonly_root()
            .build()
            .is_err());
        // bind_rootfs with a plain rootfs is fine.
        assert!(Sandbox::builder()
            .rootfs("/r")
            .bind_rootfs()
            .build()
            .is_ok());
    }

    #[test]
    fn defaults_are_secure_isolated_net_and_no_share_flags() {
        let s = Sandbox::builder().rootfs("/r").build().unwrap();
        let a = args(&s, "true", &[]);
        // Isolated by default: NO --net.
        assert!(!a.iter().any(|x| x == "--net"), "default must isolate net");
        // Quiet + rootfs + command separator present.
        assert_eq!(a[0], "box");
        assert!(a.iter().any(|x| x == "-q"));
        let ri = a.iter().position(|x| x == "--rootfs").unwrap();
        assert_eq!(a[ri + 1], "/r");
        let dd = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(a[dd + 1], "true");
    }

    #[test]
    fn every_knob_maps_to_the_right_flag() {
        let s = Sandbox::builder()
            .rootfs("/root/fs")
            .share_network()
            .readonly_root()
            .hostname("boxy")
            .workdir("/work")
            .memory_limit_bytes(268_435_456)
            .memory_swap_max_bytes(0)
            .cpus(1.5)
            .cpuset("0-3")
            .pids_limit(128)
            .timeout_ms(4200) // → 5s
            .volume("/data", "/mnt/data", true)
            .volume("/rw", "/mnt/rw", false)
            .env("LANG", "C")
            .env("FOO", "bar")
            .build()
            .unwrap();
        let a = args(&s, "sh", &["-c", "echo hi"]);
        let joined = a.join(" ");

        let flag_val = |flag: &str| -> Option<String> {
            a.iter().position(|x| x == flag).map(|i| a[i + 1].clone())
        };
        assert_eq!(flag_val("--rootfs").as_deref(), Some("/root/fs"));
        assert!(a.iter().any(|x| x == "--net"), "share_network → --net");
        assert!(a.iter().any(|x| x == "--read-only"));
        assert_eq!(flag_val("--hostname").as_deref(), Some("boxy"));
        assert_eq!(flag_val("--workdir").as_deref(), Some("/work"));
        assert_eq!(flag_val("--memory").as_deref(), Some("268435456"));
        assert_eq!(flag_val("--memory-swap-max").as_deref(), Some("0"));
        assert_eq!(flag_val("--cpus").as_deref(), Some("1.5"));
        assert_eq!(flag_val("--cpuset-cpus").as_deref(), Some("0-3"));
        assert_eq!(flag_val("--pids-limit").as_deref(), Some("128"));
        assert_eq!(flag_val("--timeout").as_deref(), Some("5")); // 4200ms rounds up
        assert!(joined.contains("-v /data:/mnt/data:ro"));
        assert!(joined.contains("-v /rw:/mnt/rw"));
        assert!(joined.contains("--env LANG=C"));
        assert!(joined.contains("--env FOO=bar"));
        // command + args after the separator, in order.
        let dd = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(&a[dd + 1..], &["sh", "-c", "echo hi"]);
    }

    #[test]
    fn cpu_quota_us_converts_to_cores() {
        let s = Sandbox::builder()
            .rootfs("/r")
            .cpu_quota_us(50_000) // half a core
            .build()
            .unwrap();
        let a = args(&s, "true", &[]);
        let i = a.iter().position(|x| x == "--cpus").unwrap();
        assert_eq!(a[i + 1], "0.5");
    }

    #[test]
    fn timeout_rounds_up_but_keeps_zero() {
        let z = Sandbox::builder()
            .rootfs("/r")
            .timeout_ms(0)
            .build()
            .unwrap();
        let a = args(&z, "true", &[]);
        assert_eq!(
            a.iter().position(|x| x == "--timeout").map(|i| &a[i + 1]),
            Some(&"0".to_string())
        );
        let one = Sandbox::builder()
            .rootfs("/r")
            .timeout_ms(1)
            .build()
            .unwrap();
        let a = args(&one, "true", &[]);
        assert_eq!(
            a.iter().position(|x| x == "--timeout").map(|i| &a[i + 1]),
            Some(&"1".to_string())
        );
    }

    #[test]
    fn no_network_is_the_default_and_can_toggle_back() {
        let s = Sandbox::builder()
            .rootfs("/r")
            .share_network()
            .no_network() // last call wins → isolated
            .build()
            .unwrap();
        assert!(!args(&s, "true", &[]).iter().any(|x| x == "--net"));
    }

    #[test]
    fn run_rejects_empty_command() {
        let s = Sandbox::builder().rootfs("/r").build().unwrap();
        let e = s.run("", &[]).unwrap_err();
        assert!(matches!(e, SandboxError::InvalidConfig(_)));
    }

    #[test]
    fn resolve_kern_binary_honors_kern_bin() {
        // Point KERN_BIN at a real file (this test binary) and confirm it wins.
        let me = std::env::current_exe().unwrap();
        // SAFETY: single-threaded test; we set then immediately read.
        unsafe { std::env::set_var("KERN_BIN", &me) };
        let got = resolve_kern_binary().unwrap();
        assert_eq!(got, me);
        unsafe { std::env::remove_var("KERN_BIN") };
    }

    #[test]
    fn read_capped_truncates_and_flags() {
        let data = vec![b'x'; 1000];
        let (buf, trunc) = read_capped(&data[..], 100);
        assert_eq!(buf.len(), 100);
        assert!(trunc);
        let (buf, trunc) = read_capped(&data[..], 4000);
        assert_eq!(buf.len(), 1000);
        assert!(!trunc);
    }

    #[test]
    fn seccomp_setter_is_accepted_and_advisory() {
        // The setter must not change the emitted args (public seccomp is always
        // on and has no CLI knob) - it's advisory, documented on SeccompMode.
        let base = Sandbox::builder().rootfs("/r").build().unwrap();
        let strict = Sandbox::builder()
            .rootfs("/r")
            .seccomp(SeccompMode::DenylistHardenedStrict)
            .build()
            .unwrap();
        assert_eq!(args(&base, "true", &[]), args(&strict, "true", &[]));
    }

    #[test]
    fn outcome_output_view_surfaces_truncation() {
        let o = Outcome {
            exit_code: 0,
            wall_ms: 1,
            stdout: b"hi".to_vec(),
            stderr: Vec::new(),
            stdout_truncated: true,
            stderr_truncated: false,
            peak_memory_bytes: None,
            cpu_time_ms: None,
            resource_source: ResourceSource::Unavailable,
        };
        assert!(o.success());
        // stdout_str hides truncation; stdout_text surfaces it.
        assert_eq!(o.stdout_str(), Some("hi"));
        assert!(o.stdout_text().truncated);
        assert_eq!(o.stdout_text().complete(), None);
    }
}
