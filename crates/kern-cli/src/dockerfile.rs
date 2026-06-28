//! A tiny, dependency-free parser for a **subset** of the Dockerfile format, used by `kern build`.
//!
//! Supported instructions: `FROM RUN COPY ADD ENV WORKDIR USER CMD ENTRYPOINT EXPOSE ARG LABEL`.
//! `VOLUME` and `HEALTHCHECK` are ACCEPTED (parsed, no build-time effect) so stock upstream Dockerfiles
//! build instead of failing; `HEALTHCHECK` nudges the user to kern's runtime `--health-cmd`.
//! Multi-stage builds are supported: `FROM … AS <name>` and `COPY --from=<stage>` are parsed here
//! (stage names tracked, `--from` validated against earlier stages via [`resolve_from`]) and executed by
//! `commands::build_multi_stage`, which builds each stage through the single-stage path and copies
//! artifacts across stages.
//! Deliberately NOT supported (rejected with a clear error, never silently ignored): `SHELL`, `ONBUILD`,
//! `STOPSIGNAL`, `ADD <url>`, and `ADD` auto-extraction. Comments (`#`), blank lines and backslash
//! line-continuations are handled; `ARG`/`ENV` values substitute into later `${VAR}`/`$VAR`.
//! BuildKit `RUN` **heredocs** (`RUN <<EOF … EOF`, incl. `<<-` tab-strip, quoted `<<'EOF'`, and the
//! interpreter form `RUN python3 <<EOF`) are parsed and reduced to a single `/bin/sh -c` argv; a COPY
//! heredoc and multiple/stacked heredocs on one instruction are rejected with a clear error.
//!
//! The parser is pure (text in, instructions out) so it is unit-testable without touching disk or
//! the network; the executor lives in `commands::build`.

use std::collections::HashMap;

/// One resolved build step. `RUN`/`CMD`/`ENTRYPOINT` are already reduced to an argv (shell form
/// `X` becomes `["/bin/sh","-c","X"]`, exec form `["a","b"]` stays as given). `ARG`/`LABEL` produce
/// no instruction (they only affect variable substitution / are ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instr {
    /// `FROM <image> [AS <name>]`. `as_name` is `Some` only in a multi-stage build; a plain single-stage
    /// `FROM` leaves it `None`, so the single-stage executor path is byte-for-byte unchanged.
    From {
        image: String,
        as_name: Option<String>,
    },
    Run(Vec<String>),
    /// `COPY [--from=<stage|image>] <srcs...> <dst>`. `from` is `Some(_)` for a `COPY --from`; a normal
    /// `COPY` from the build context leaves it `None`. The [`CopyFrom`] variant records whether the
    /// source is an earlier build STAGE or an external IMAGE, so the executor takes the right path.
    Copy {
        srcs: Vec<String>,
        dst: String,
        from: Option<CopyFrom>,
    },
    Env(String, String),
    Workdir(String),
    User(String),
    Cmd(Vec<String>),
    Entrypoint(Vec<String>),
    Expose(String),
}

/// The source of a `COPY --from=<X>`. `X` is resolved at parse time: it names an earlier build
/// [`Stage`](CopyFrom::Stage) if it matches one (by name or numeric index), otherwise — if it's a
/// syntactically valid OCI reference — it's an external [`Image`](CopyFrom::Image) to pull and copy
/// out of. A stage ALWAYS wins over an image of the same spelling (Docker's rule); anything that is
/// neither is rejected. The distinction is preserved at the type level so the executor never has to
/// re-guess which path to take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyFrom {
    /// An earlier build stage, kept as the raw `--from=<name-or-index>` token (resolved to an index by
    /// [`resolve_from`] on the executor side, exactly as the parser validated it).
    Stage(String),
    /// An external image reference (`busybox`, `nginx:alpine`, `ghcr.io/org/img:1.2`, …) to pull.
    Image(String),
}

/// Lint a parsed instruction list for common Dockerfile smells, returning a human-readable warning per
/// finding (empty = clean). These are advisory only — they never fail a build — but drive the `warn`
/// status in the build history (`kern builds`). Deliberately a small, high-signal set (the same
/// families `hadolint`/BuildKit surface most): unpinned base image, `apt-get`/`apk` without a
/// no-recommends / `--no-cache` flag, a `RUN cd` that doesn't persist, and a missing final `CMD`.
pub fn lint(instrs: &[Instr]) -> Vec<String> {
    let mut warns = Vec::new();
    for i in instrs {
        match i {
            Instr::From { image, .. } => {
                // Unpinned tag: no `:tag`/`@digest`, or the mutable `:latest` — non-reproducible builds.
                let bare = image.rsplit('/').next().unwrap_or(image);
                if !bare.contains(':') && !bare.contains('@') {
                    warns.push(format!("FROM {image}: no tag pinned (implicit ':latest' — builds aren't reproducible); pin a version"));
                } else if image.ends_with(":latest") {
                    warns.push(format!("FROM {image}: ':latest' is mutable — pin a specific version for reproducible builds"));
                }
            }
            Instr::Run(argv) => {
                let joined = argv.join(" ");
                if joined.contains("apt-get install") && !joined.contains("--no-install-recommends")
                {
                    warns.push("RUN apt-get install without --no-install-recommends (pulls extra packages, larger image)".into());
                }
                if joined.contains("apt-get")
                    && joined.contains("install")
                    && !joined.contains("rm -rf /var/lib/apt/lists")
                {
                    warns.push("RUN apt-get install without cleaning /var/lib/apt/lists (bloats the layer)".into());
                }
                if joined.contains("apk add")
                    && !joined.contains("--no-cache")
                    && !joined.contains("rm -rf /var/cache/apk")
                {
                    warns.push(
                        "RUN apk add without --no-cache (leaves the apk index in the layer)".into(),
                    );
                }
                // A `cd` in its own RUN doesn't persist to later instructions — a frequent footgun.
                let trimmed = joined.trim_start();
                if (trimmed == "cd" || trimmed.starts_with("cd "))
                    && !joined.contains("&&")
                    && !joined.contains(';')
                {
                    warns.push("RUN cd <dir>: the directory change doesn't persist to later steps — use WORKDIR".into());
                }
            }
            _ => {}
        }
    }
    if !instrs
        .iter()
        .any(|i| matches!(i, Instr::Cmd(_) | Instr::Entrypoint(_)))
    {
        warns.push("no CMD or ENTRYPOINT: the image has no default command".into());
    }
    warns
}

/// A heredoc operator (`<<WORD`, `<<-WORD`, `<<"WORD"`, `<<'WORD'`) found on a RUN/COPY opener line,
/// with its byte range in the scanned string so the opener text can be reconstructed without it.
struct HeredocOp {
    /// Byte range of the whole operator token (`<<…WORD` incl. any `-`/quotes) in the scanned string.
    start: usize,
    end: usize,
    /// The delimiter word (unquoted), e.g. `EOF`.
    delim: String,
    /// `true` for `<<-`: strip leading TABs from body lines and allow a tab-indented close.
    strip_tabs: bool,
}

/// One collected heredoc: its delimiter, the joined body (`\n`-separated, tabs already stripped for
/// `<<-`), and whether its closing delimiter was found before EOF.
struct Heredoc {
    delim: String,
    body: String,
    terminated: bool,
}

/// A folded instruction line: `text` is the opener (backslash-continuations already joined), plus any
/// heredoc bodies attached to it (RUN/COPY/ADD only). `lineno` is the 1-based line of the opener.
struct Logical {
    lineno: usize,
    text: String,
    heredocs: Vec<Heredoc>,
}

/// Scan a string for heredoc operators in order. A `<<` is only an operator when a delimiter word
/// (starting with a letter/`_`, optionally quoted, optionally `<<-`) follows — so a shell bit-shift
/// like `1<<2` (a digit follows) is NOT mistaken for one.
fn scan_heredoc_ops(s: &str) -> Vec<HeredocOp> {
    let b = s.as_bytes();
    let mut ops = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        if b[i] != b'<' || b[i + 1] != b'<' {
            i += 1;
            continue;
        }
        let start = i;
        let mut j = i + 2;
        let strip_tabs = j < b.len() && b[j] == b'-';
        if strip_tabs {
            j += 1;
        }
        let quote = if j < b.len() && (b[j] == b'"' || b[j] == b'\'') {
            let q = b[j];
            j += 1;
            Some(q)
        } else {
            None
        };
        // The delimiter word must start with a letter or `_` (rules out `1<<2`).
        if j >= b.len() || !(b[j].is_ascii_alphabetic() || b[j] == b'_') {
            i += 2;
            continue;
        }
        let ds = j;
        j += 1;
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
            j += 1;
        }
        let delim = s[ds..j].to_string();
        if let Some(q) = quote {
            if j < b.len() && b[j] == q {
                j += 1; // consume the closing quote
            }
        }
        ops.push(HeredocOp {
            start,
            end: j,
            delim,
            strip_tabs,
        });
        i = j;
    }
    ops
}

/// The heredoc operators an instruction OPENS: only RUN/COPY/ADD may open a heredoc, so a stray `<<`
/// on any other instruction (or a bit-shift) never starts consuming following lines as a body.
fn opener_heredoc_ops(text: &str) -> Vec<HeredocOp> {
    let kw = text
        .split_once(char::is_whitespace)
        .map(|(k, _)| k)
        .unwrap_or(text)
        .to_ascii_uppercase();
    if matches!(kw.as_str(), "RUN" | "COPY" | "ADD") {
        scan_heredoc_ops(text)
    } else {
        Vec::new()
    }
}

/// Build the argv for a `RUN` that opens a heredoc. `rest` is the opener minus the `RUN` keyword.
/// Two shapes. With no command before `<<`, the body IS a shell script: `["/bin/sh","-c",<body>]`
/// (BuildKit's `RUN <<EOF … EOF`, the dominant case). With a command/interpreter before `<<` (e.g.
/// `python3 <<EOF`), feed the body on that command's stdin by handing a real heredoc to `/bin/sh`:
/// `["/bin/sh","-c","<cmd> <<'DELIM'\n<body>\nDELIM"]`.
///
/// The body is kept verbatim (kern doesn't env-expand RUN bodies). Multiple heredocs on one RUN and
/// an unterminated heredoc are rejected with a clear error.
fn heredoc_run_argv(rest: &str, heredocs: &[Heredoc]) -> Result<Vec<String>, String> {
    let ops = scan_heredoc_ops(rest);
    if ops.len() > 1 {
        return Err(
            "multiple heredocs on one instruction aren't supported yet — use one `<<DELIM` per RUN"
                .to_string(),
        );
    }
    let op = &ops[0]; // caller only routes here when opener_heredoc_ops found ≥1
    let hd = &heredocs[0];
    if !hd.terminated {
        return Err(format!("unterminated heredoc `<<{}`", hd.delim));
    }
    let prefix = format!("{}{}", &rest[..op.start], &rest[op.end..]);
    let prefix = prefix.trim();
    let argv = if prefix.is_empty() {
        vec!["/bin/sh".to_string(), "-c".to_string(), hd.body.clone()]
    } else {
        let script = format!(
            "{prefix} <<'{d}'\n{body}\n{d}",
            d = hd.delim,
            body = hd.body
        );
        vec!["/bin/sh".to_string(), "-c".to_string(), script]
    };
    Ok(argv)
}

/// Parse Dockerfile `text` into an ordered instruction list. `build_args` seed the substitution
/// table (they override any in-file `ARG` default). Returns a human-readable error on the first
/// malformed or unsupported line, tagged with the 1-based line number.
pub fn parse(text: &str, build_args: &HashMap<String, String>) -> Result<Vec<Instr>, String> {
    let mut out = Vec::new();
    // Substitution table: `ARG` defaults + `--build-arg` overrides + `ENV` values, applied to later
    // instruction operands. `build_args` win over in-file `ARG` defaults (Docker semantics).
    let mut vars: HashMap<String, String> = HashMap::new();
    let mut saw_from = false;
    // Stage names in parse order (one per FROM; `None` for an unnamed stage). Used to validate a
    // `COPY --from=<name-or-index>` against EARLIER stages only (no forward-ref, no self-ref).
    let mut stage_names: Vec<Option<String>> = Vec::new();

    for ll in logical_lines(text).into_iter() {
        let Logical {
            lineno,
            text: logical,
            heredocs,
        } = ll;
        let line = logical.trim();
        if line.is_empty() {
            continue;
        }
        let (kw_raw, rest) = match line.split_once(char::is_whitespace) {
            Some((k, r)) => (k, r.trim()),
            None => (line, ""),
        };
        let kw = kw_raw.to_ascii_uppercase();
        let err = |m: &str| Err(format!("Dockerfile line {lineno}: {m}"));

        match kw.as_str() {
            "FROM" => {
                // Substitute FIRST (a `FROM $BASE AS build` must expand `$BASE`), THEN split off a
                // trailing `AS <name>` so the AS keyword/name can't come from a variable's contents.
                let expanded = subst(rest, &vars);
                let mut toks = expanded.split_whitespace();
                let image = toks.next().unwrap_or("").to_string();
                if image.is_empty() {
                    return err("FROM needs an image reference");
                }
                // Optional `AS <name>`: exactly `as <name>` (case-insensitive) after the image.
                let as_name = match (toks.next(), toks.next(), toks.next()) {
                    (None, _, _) => None,
                    (Some(kw), Some(name), None) if kw.eq_ignore_ascii_case("as") => {
                        let name = name.to_ascii_lowercase();
                        if name.is_empty()
                            || !name.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-'
                            })
                        {
                            return err("FROM … AS <name>: name allows only letters/digits/_/./-");
                        }
                        if stage_names
                            .iter()
                            .any(|n| n.as_deref() == Some(name.as_str()))
                        {
                            return err(&format!("duplicate build-stage name '{name}'"));
                        }
                        Some(name)
                    }
                    _ => return err("FROM takes '<image>' or '<image> AS <name>'"),
                };
                saw_from = true;
                stage_names.push(as_name.clone());
                out.push(Instr::From { image, as_name });
            }
            _ if !saw_from && kw != "ARG" => {
                return err("the first instruction must be FROM (ARG may precede it)");
            }
            "ARG" => {
                // `ARG K` or `ARG K=default`. A matching --build-arg overrides the default.
                let (k, def) = match rest.split_once('=') {
                    Some((k, v)) => (k.trim().to_string(), Some(subst(v.trim(), &vars))),
                    None => (rest.trim().to_string(), None),
                };
                if k.is_empty() {
                    return err("ARG needs a name");
                }
                if let Some(v) = build_args.get(&k) {
                    vars.insert(k, v.clone());
                } else if let Some(d) = def {
                    vars.insert(k, d);
                }
            }
            "ENV" => {
                for (k, v) in
                    parse_env(rest, &vars).map_err(|m| format!("Dockerfile line {lineno}: {m}"))?
                {
                    vars.insert(k.clone(), v.clone());
                    out.push(Instr::Env(k, v));
                }
            }
            "RUN" => {
                // A BuildKit heredoc (`RUN <<EOF … EOF`) is folded here: `heredocs` holds the body
                // lines the parser consumed verbatim. Reduce it to a single `/bin/sh -c` argv.
                if heredocs.is_empty() {
                    out.push(Instr::Run(cmd_argv(rest, &vars)))
                } else {
                    out.push(Instr::Run(
                        heredoc_run_argv(rest, &heredocs)
                            .map_err(|m| format!("Dockerfile line {lineno}: {m}"))?,
                    ))
                }
            }
            "CMD" => out.push(Instr::Cmd(cmd_argv(rest, &vars))),
            "ENTRYPOINT" => out.push(Instr::Entrypoint(cmd_argv(rest, &vars))),
            "WORKDIR" => {
                let d = subst(rest, &vars);
                if d.is_empty() {
                    return err("WORKDIR needs a path");
                }
                out.push(Instr::Workdir(d));
            }
            "USER" => {
                let u = subst(rest, &vars);
                if u.is_empty() {
                    return err("USER needs a name/uid");
                }
                out.push(Instr::User(u));
            }
            "COPY" | "ADD" => {
                // `COPY <<EOF <dest>` (heredoc → file) is a valid BuildKit form we don't implement
                // yet. Its body was consumed verbatim into `heredocs`, so error clearly rather than
                // mis-parsing the opener (never silently drop the body).
                if !heredocs.is_empty() {
                    return err(&format!("{kw} heredoc (`<<…`) isn't supported yet"));
                }
                let mut toks = split_ws(&subst(rest, &vars));
                // `COPY --from=<stage|image>` (multi-stage / external image) is the ONLY build flag we
                // accept; capture and drop it. Any other `--flag` (or `--from` on `ADD`) is still
                // rejected rather than ignored.
                let mut from: Option<CopyFrom> = None;
                if let Some(pos) = toks.iter().position(|t| t.starts_with("--")) {
                    let flag = toks[pos].clone();
                    if kw == "COPY" && flag.starts_with("--from=") {
                        let x = flag["--from=".len()..].to_string();
                        // Resolve `--from=<X>` at parse time. A build STAGE wins over an image of the same
                        // spelling (Docker's rule), so check stages FIRST: `upto` = index of the CURRENT
                        // stage (the last FROM pushed), which excludes it → self- and forward-references
                        // are rejected for free; a numeric `--from=N` must index an already-built stage.
                        // Otherwise, if `X` is a valid OCI reference, it's an external image to pull;
                        // anything that is neither an earlier stage nor a valid ref is an error.
                        let cur = stage_names.len().saturating_sub(1);
                        from = Some(if resolve_from(&x, &stage_names, cur).is_some() {
                            CopyFrom::Stage(x)
                        } else if x.parse::<usize>().is_ok() || !kern_oci::valid_reference(&x) {
                            // A bare NUMBER is always a stage INDEX (never an external image), so an
                            // out-of-range index is an error — as is anything that's neither a known
                            // stage nor a syntactically valid image reference.
                            return err(
                                "COPY --from must reference an earlier build stage (by name or index) \
                                 or a valid image reference (e.g. --from=busybox)",
                            );
                        } else {
                            CopyFrom::Image(x)
                        });
                        toks.remove(pos);
                    } else if flag.starts_with("--from") {
                        return err("--from is only supported on COPY (multi-stage)");
                    } else {
                        return err(&format!("{kw} flag {flag} isn't supported yet"));
                    }
                }
                if kw == "ADD"
                    && toks
                        .iter()
                        .any(|t| t.starts_with("http://") || t.starts_with("https://"))
                {
                    return err("ADD <url> isn't supported yet — use COPY with a local file");
                }
                if toks.len() < 2 {
                    return err(&format!("{kw} needs at least a source and a destination"));
                }
                let dst = toks.pop().unwrap();
                out.push(Instr::Copy {
                    srcs: toks,
                    dst,
                    from,
                });
            }
            "EXPOSE" => {
                for p in split_ws(&subst(rest, &vars)) {
                    out.push(Instr::Expose(p));
                }
            }
            "LABEL" | "MAINTAINER" => { /* metadata — parsed and ignored */ }
            // VOLUME/HEALTHCHECK are ACCEPTED (parsed, not fatal) so a real-world upstream Dockerfile that
            // uses them builds instead of exploding — they were the two commonest reasons a `kern build`
            // of a stock image failed. They carry NO build-time filesystem effect, so we emit no Instr:
            //   VOLUME    → a runtime mount point; kern mounts volumes at run via `-v`, so it's advisory
            //               at build (Docker also only *declares* it — the anonymous volume is a runtime
            //               concern). Parsed and dropped.
            //   HEALTHCHECK → maps onto kern's runtime `--health-cmd`/`--health-interval`/… flags; kern
            //               doesn't yet BAKE it into the image config, so we accept it and (once, on the
            //               first HEALTHCHECK) tell the user to pass the health flags at `kern box` time,
            //               rather than silently dropping a health contract or failing the build.
            "VOLUME" => { /* runtime mount point — advisory at build, mounted via `-v` at run */ }
            "HEALTHCHECK" => {
                // Don't fail; nudge the user to the runtime flags. `HEALTHCHECK NONE` disables — nothing to say.
                let body = subst(rest, &vars);
                if !body.trim().eq_ignore_ascii_case("none") {
                    eprintln!(
                        "kern build: HEALTHCHECK accepted but not baked into the image — add it at run \
                         with `kern box … --health-cmd '<cmd>'` (see `kern box --help`)"
                    );
                }
            }
            // Still genuinely unsupported (and rare): fail clearly rather than silently mis-build.
            "SHELL" | "ONBUILD" | "STOPSIGNAL" => {
                return err(&format!("{kw} isn't supported yet"));
            }
            other => return err(&format!("unknown instruction {other}")),
        }
    }
    if !saw_from {
        return Err("Dockerfile has no FROM instruction".to_string());
    }
    Ok(out)
}

/// Resolve a `COPY --from=<x>` reference to a 0-based stage index, considering ONLY stages `[0, upto)`
/// (i.e. stages built BEFORE the current one). A numeric `<x>` must be a valid index `< upto`; otherwise
/// `<x>` is matched (case-insensitively) against the stage names. `None` = not an earlier stage → the
/// parser rejects it, and the executor treats a `None` here as an internal error. Shared by the parser
/// (validation) and the executor (lookup) so they can't disagree on what a `--from` resolves to.
pub fn resolve_from(from: &str, stage_names: &[Option<String>], upto: usize) -> Option<usize> {
    let upto = upto.min(stage_names.len());
    if let Ok(n) = from.parse::<usize>() {
        return (n < upto).then_some(n);
    }
    let want = from.to_ascii_lowercase();
    stage_names[..upto]
        .iter()
        .position(|n| n.as_deref() == Some(want.as_str()))
}

/// Fold physical lines into logical ones: drop full-line comments, honour a trailing `\`
/// continuation, and — for a RUN/COPY/ADD line that OPENS a heredoc (`<<DELIM`) — consume the
/// following physical lines VERBATIM (no comment stripping, no continuation) as the heredoc body,
/// up to the closing delimiter (tab-indented close allowed for `<<-`). Each `Logical` carries the
/// opener text plus any attached heredoc bodies.
fn logical_lines(text: &str) -> Vec<Logical> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut idx = 0;
    while idx < lines.len() {
        // A `#` comment line (when not mid-continuation) is dropped whole.
        if lines[idx].trim_start().starts_with('#') {
            idx += 1;
            continue;
        }
        let start = idx + 1;
        // Fold backslash continuations into the opener text.
        let mut cur = String::new();
        loop {
            let raw = lines[idx];
            let trimmed_end = raw.trim_end();
            idx += 1;
            if let Some(stripped) = trimmed_end.strip_suffix('\\') {
                cur.push_str(stripped);
                cur.push(' ');
                if idx >= lines.len() {
                    break;
                }
            } else {
                cur.push_str(raw);
                break;
            }
        }
        // If this opener opens heredoc(s), consume their bodies verbatim from the following lines.
        let mut heredocs = Vec::new();
        for op in opener_heredoc_ops(&cur) {
            let mut body = Vec::new();
            let mut terminated = false;
            while idx < lines.len() {
                let raw = lines[idx];
                idx += 1;
                // Closing delimiter: the line (leading tabs stripped for `<<-`, trailing CR ignored)
                // must equal the delimiter exactly.
                let close = if op.strip_tabs {
                    raw.trim_start_matches('\t')
                } else {
                    raw
                };
                if close.strip_suffix('\r').unwrap_or(close) == op.delim {
                    terminated = true;
                    break;
                }
                // Body line: `<<-` strips leading TABs (only tabs, not spaces).
                let line = if op.strip_tabs {
                    raw.trim_start_matches('\t')
                } else {
                    raw
                };
                body.push(line.to_string());
            }
            let unterminated = !terminated;
            heredocs.push(Heredoc {
                delim: op.delim,
                body: body.join("\n"),
                terminated,
            });
            // A body that ran to EOF swallowed any later openers — stop; the RUN handler reports it.
            if unterminated {
                break;
            }
        }
        out.push(Logical {
            lineno: start,
            text: cur,
            heredocs,
        });
    }
    out
}

/// Reduce a RUN/CMD/ENTRYPOINT operand to an argv. Exec form (`["a","b"]`) is honoured literally;
/// shell form is wrapped in `/bin/sh -c`. Uses **soft** substitution: Docker doesn't env-expand
/// these three, so unknown `$VAR`/`$1`/`$$` are left verbatim for the shell (only known ARG/ENV are
/// filled) — otherwise `RUN echo $HOME` or `awk '{print $1}'` would be silently gutted.
fn cmd_argv(rest: &str, vars: &HashMap<String, String>) -> Vec<String> {
    let t = rest.trim();
    if t.starts_with('[') {
        if let Some(v) = parse_exec_array(t) {
            return v.iter().map(|s| subst_soft(s, vars)).collect();
        }
        // Fall through to shell form if the JSON array is malformed.
    }
    vec!["/bin/sh".to_string(), "-c".to_string(), subst_soft(t, vars)]
}

/// Parse a JSON-ish exec array `["a","b"]` into its string elements (escape-aware). `None` if it
/// isn't a well-formed array of strings.
fn parse_exec_array(s: &str) -> Option<Vec<String>> {
    let inner = s.strip_prefix('[')?.strip_suffix(']')?;
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut in_str, mut esc, mut seen) = (false, false, false);
    for c in inner.chars() {
        if in_str {
            if esc {
                cur.push(match c {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    other => other,
                });
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                out.push(std::mem::take(&mut cur));
                in_str = false;
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            in_str = true;
            seen = true;
        } else if c == ',' || c.is_whitespace() {
            // separators between elements
        } else {
            return None; // stray token outside a string → not a clean exec array
        }
    }
    if in_str {
        return None; // unterminated
    }
    if !seen {
        return Some(Vec::new());
    }
    Some(out)
}

/// Parse an `ENV` operand into `(key, value)` pairs. Supports `ENV K=V [K2=V2 …]` (the modern form,
/// values may be double-quoted) and the legacy `ENV KEY the rest is the value`.
fn parse_env(rest: &str, vars: &HashMap<String, String>) -> Result<Vec<(String, String)>, String> {
    let t = rest.trim();
    if t.is_empty() {
        return Err("ENV needs KEY=VALUE".to_string());
    }
    // Legacy `ENV KEY value with spaces` — no `=` in the first token.
    let first = t.split_whitespace().next().unwrap_or("");
    if !first.contains('=') {
        let (k, v) = t
            .split_once(char::is_whitespace)
            .ok_or("ENV KEY needs a value")?;
        return Ok(vec![(k.to_string(), subst(v.trim(), vars))]);
    }
    // Modern `K=V K2=V2` — split on unquoted whitespace, then each token on its first `=`.
    let mut pairs = Vec::new();
    for tok in split_ws(t) {
        let (k, v) = tok.split_once('=').ok_or("ENV expects KEY=VALUE tokens")?;
        if k.is_empty() {
            return Err("ENV key can't be empty".to_string());
        }
        pairs.push((k.to_string(), subst(v, vars)));
    }
    Ok(pairs)
}

/// Whitespace split honouring double-quotes and backslash escapes (so a quoted path with spaces
/// stays one token). Used for COPY/ADD/EXPOSE/ENV operands.
fn split_ws(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut in_q, mut esc, mut has) = (false, false, false);
    for c in s.chars() {
        if esc {
            cur.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
            has = true;
        } else if c == '"' {
            in_q = !in_q;
            has = true;
        } else if c.is_whitespace() && !in_q {
            if has {
                out.push(std::mem::take(&mut cur));
                has = false;
            }
        } else {
            cur.push(c);
            has = true;
        }
    }
    if has {
        out.push(cur);
    }
    out
}

/// **Hard** substitution (ADD/COPY/ENV/FROM/USER/WORKDIR/EXPOSE, matching Docker's env-replace
/// list): `${VAR}`/`$VAR` from `vars`, an unknown var → **empty**, `$$` → literal `$`.
fn subst(s: &str, vars: &HashMap<String, String>) -> String {
    subst_impl(s, vars, false)
}

/// **Soft** substitution for RUN/CMD/ENTRYPOINT, which Docker does NOT env-expand: known ARG/ENV are
/// filled, but an unknown `$VAR`/`${VAR}` and `$$` are left **verbatim** for the shell — so
/// `RUN echo $HOME`, `awk '{print $1}'` and `$$` (PID) keep working.
fn subst_soft(s: &str, vars: &HashMap<String, String>) -> String {
    subst_impl(s, vars, true)
}

/// Shared substitution engine; `soft` decides how unknown vars and `$$` are treated (see the two
/// wrappers above).
///
/// Accumulates BYTES (not `char`s) so multibyte UTF-8 in a value passes through intact — every byte
/// copied comes from a valid `&str`, so the final `from_utf8` never fails. The `$`/`{`/`}`/name
/// bytes we branch on are all ASCII, and every `&s[..]` slice boundary lands on one, so no panic.
fn subst_impl(s: &str, vars: &HashMap<String, String>, soft: bool) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'$' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        // `$` at end, or `$$`: soft leaves `$$` for the shell, hard collapses it to a literal `$`.
        if i + 1 >= b.len() {
            out.push(b'$');
            break;
        }
        if b[i + 1] == b'$' {
            out.extend_from_slice(if soft { b"$$" } else { b"$" });
            i += 2;
            continue;
        }
        let (name, next) = if b[i + 1] == b'{' {
            match s[i + 2..].find('}') {
                Some(rel) => (&s[i + 2..i + 2 + rel], i + 2 + rel + 1),
                None => {
                    out.push(b'$'); // unterminated `${` — emit literally
                    i += 1;
                    continue;
                }
            }
        } else {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                j += 1;
            }
            (&s[start..j], j)
        };
        if name.is_empty() {
            out.push(b'$');
            i += 1;
            continue;
        }
        match vars.get(name) {
            Some(v) => out.extend_from_slice(v.as_bytes()),
            // Soft mode leaves an unknown reference verbatim (the shell may expand it); hard mode
            // drops it (empty), as Docker does for its env-replaced instructions.
            None if soft => out.extend_from_slice(&b[i..next]),
            None => {}
        }
        i = next;
    }
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ba() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn lint_flags_unpinned_base_and_missing_cmd_but_not_clean() {
        // Unpinned FROM + no CMD → two warnings.
        let dirty = lint(&[Instr::From {
            image: "alpine".into(),
            as_name: None,
        }]);
        assert!(dirty.iter().any(|w| w.contains("no tag pinned")));
        assert!(dirty.iter().any(|w| w.contains("no CMD")));
        // A pinned base + a CMD → clean, zero warnings.
        let clean = lint(&[
            Instr::From {
                image: "alpine:3.19".into(),
                as_name: None,
            },
            Instr::Cmd(vec!["/bin/sh".into()]),
        ]);
        assert!(clean.is_empty(), "pinned + CMD must be clean: {clean:?}");
        // ':latest' is flagged as mutable even though it's "tagged".
        assert!(lint(&[Instr::From {
            image: "ubuntu:latest".into(),
            as_name: None,
        }])
        .iter()
        .any(|w| w.contains("mutable")));
        // RUN apt-get install without --no-install-recommends is flagged.
        assert!(lint(&[
            Instr::From {
                image: "debian:12".into(),
                as_name: None,
            },
            Instr::Run(vec!["apt-get install -y curl".into()]),
            Instr::Cmd(vec!["/bin/sh".into()]),
        ])
        .iter()
        .any(|w| w.contains("no-install-recommends")));
    }

    /// A plain single-stage `FROM <image>` instruction (as_name None), for terse test assertions.
    fn from(image: &str) -> Instr {
        Instr::From {
            image: image.into(),
            as_name: None,
        }
    }

    #[test]
    fn minimal_from_run_cmd() {
        let df = "FROM alpine:3.19\nRUN echo hi\nCMD [\"/bin/sh\"]\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(
            got[0],
            Instr::From {
                image: "alpine:3.19".into(),
                as_name: None
            }
        );
        assert_eq!(
            got[1],
            Instr::Run(vec!["/bin/sh".into(), "-c".into(), "echo hi".into()])
        );
        assert_eq!(got[2], Instr::Cmd(vec!["/bin/sh".into()]));
    }

    #[test]
    fn comments_blanks_and_continuations() {
        let df = "# a comment\nFROM alpine\n\nRUN apk add \\\n  curl \\\n  bash\n";
        let got = parse(df, &ba()).unwrap();
        // Continuations join into one RUN; exact inter-token spacing is irrelevant (the shell
        // collapses it), so assert on the collapsed form.
        let Instr::Run(argv) = &got[1] else {
            panic!("expected RUN")
        };
        assert_eq!(argv[0], "/bin/sh");
        assert_eq!(argv[1], "-c");
        assert_eq!(
            argv[2].split_whitespace().collect::<Vec<_>>(),
            ["apk", "add", "curl", "bash"]
        );
    }

    #[test]
    fn env_forms_and_substitution() {
        let df =
            "FROM alpine\nENV A=1 B=two\nENV C hello world\nWORKDIR /app/${A}\nRUN echo $B$C\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(got[1], Instr::Env("A".into(), "1".into()));
        assert_eq!(got[2], Instr::Env("B".into(), "two".into()));
        assert_eq!(got[3], Instr::Env("C".into(), "hello world".into()));
        assert_eq!(got[4], Instr::Workdir("/app/1".into()));
        assert_eq!(
            got[5],
            Instr::Run(vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo twohello world".into()
            ])
        );
    }

    #[test]
    fn arg_default_and_build_arg_override() {
        let mut ba = HashMap::new();
        ba.insert("VER".to_string(), "9".to_string());
        let df = "ARG VER=1\nARG NAME=box\nFROM alpine\nRUN echo $VER-$NAME\n";
        let got = parse(df, &ba).unwrap();
        // --build-arg VER=9 wins over the ARG default; NAME uses its default.
        assert_eq!(
            got[1],
            Instr::Run(vec!["/bin/sh".into(), "-c".into(), "echo 9-box".into()])
        );
    }

    #[test]
    fn copy_multiple_srcs_and_dst() {
        let df = "FROM alpine\nCOPY a.txt b.txt /dst/\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(
            got[1],
            Instr::Copy {
                srcs: vec!["a.txt".into(), "b.txt".into()],
                dst: "/dst/".into(),
                from: None,
            }
        );
    }

    #[test]
    fn dollar_dollar_is_literal() {
        assert_eq!(subst("a$$b", &ba()), "a$b");
        assert_eq!(subst("${X}y", &ba()), "y"); // unknown → empty
    }

    #[test]
    fn run_uses_soft_subst_keeps_shell_syntax() {
        // RUN/CMD/ENTRYPOINT: known ARG/ENV fill in, but unknown `$VAR`/`$1`/`$$` survive for the
        // shell (Docker doesn't env-expand these three).
        let mut v = HashMap::new();
        v.insert("VER".to_string(), "9".to_string());
        let df = "FROM alpine\nARG VER\nRUN echo $VER $HOME $$ && awk '{print $1}'\n";
        let got = parse(df, &v).unwrap();
        assert_eq!(
            got[1],
            Instr::Run(vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo 9 $HOME $$ && awk '{print $1}'".into()
            ])
        );
        // But WORKDIR (hard subst) drops an unknown var to empty, Docker-style.
        assert_eq!(
            parse("FROM a\nWORKDIR /x/$NOPE/y\n", &HashMap::new()).unwrap()[1],
            Instr::Workdir("/x//y".into())
        );
    }

    #[test]
    fn subst_preserves_multibyte_utf8() {
        // Bytes are copied verbatim, so multibyte chars around a substitution stay intact (and it
        // never panics on a non-char-boundary slice).
        let mut v = HashMap::new();
        v.insert("N".to_string(), "café".to_string());
        assert_eq!(subst("日本 ${N} €", &v), "日本 café €");
        assert_eq!(subst("ünïcödé$$", &ba()), "ünïcödé$");
    }

    #[test]
    fn rejects_unsupported_and_malformed() {
        // `COPY --from=<garbage>` (neither an earlier stage nor a valid image ref) is rejected — an
        // uppercase repo is not a legal OCI reference. (A bare lowercase `nope` IS a valid ref now, so
        // it's accepted as an external image — see `copy_from_external_image_ref`.)
        assert!(parse("FROM a\nCOPY --from=NOPE /a /b\n", &ba())
            .unwrap_err()
            .contains("earlier build stage"));
        // SHELL/ONBUILD/STOPSIGNAL are still genuinely unsupported → clear error.
        assert!(parse("FROM a\nONBUILD RUN x\n", &ba())
            .unwrap_err()
            .contains("ONBUILD"));
        assert!(parse("RUN echo hi\n", &ba())
            .unwrap_err()
            .contains("must be FROM"));
        assert!(parse("FROM a\nADD https://x/y /z\n", &ba())
            .unwrap_err()
            .contains("url"));
        assert!(parse("FROM a\nBOGUS x\n", &ba())
            .unwrap_err()
            .contains("unknown instruction"));
        assert!(parse("RUN x", &ba()).is_err());
        assert!(parse("# only a comment\n", &ba())
            .unwrap_err()
            .contains("no FROM"));
    }

    #[test]
    fn arg_may_precede_from() {
        let df = "ARG BASE=alpine\nFROM $BASE\n";
        assert_eq!(parse(df, &ba()).unwrap()[0], from("alpine"));
    }

    #[test]
    fn volume_and_healthcheck_are_accepted_not_fatal() {
        // A stock upstream Dockerfile with VOLUME/HEALTHCHECK must BUILD, not explode. They carry no
        // build-time filesystem effect, so they produce no instruction — the FROM/RUN around them do.
        let df = "FROM alpine\nVOLUME /data\nHEALTHCHECK --interval=30s CMD curl -f localhost || exit 1\nRUN echo hi\n";
        let got = parse(df, &ba()).expect("VOLUME/HEALTHCHECK must not fail the build");
        // Only FROM + RUN survive as instructions; VOLUME/HEALTHCHECK emit none.
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], from("alpine"));
        assert!(matches!(got[1], Instr::Run(_)));
        // `HEALTHCHECK NONE` is also fine (disables — nothing to nudge).
        assert!(parse("FROM alpine\nHEALTHCHECK NONE\n", &ba()).is_ok());
    }

    #[test]
    fn from_as_names_stages() {
        let df = "FROM golang AS build\nRUN go build\nFROM alpine\nCOPY --from=build /app /app\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(
            got[0],
            Instr::From {
                image: "golang".into(),
                as_name: Some("build".into())
            }
        );
        assert_eq!(got[2], from("alpine"));
        assert_eq!(
            got[3],
            Instr::Copy {
                srcs: vec!["/app".into()],
                dst: "/app".into(),
                from: Some(CopyFrom::Stage("build".into())),
            }
        );
    }

    #[test]
    fn copy_from_by_index_and_name() {
        // Numeric --from=0 references the first stage; a $BASE in FROM still substitutes before AS-split.
        let df = "FROM alpine AS base\nFROM alpine\nCOPY --from=0 /a /a\nCOPY --from=base /b /b\n";
        let got = parse(df, &ba()).unwrap();
        assert!(matches!(&got[2], Instr::Copy { from: Some(CopyFrom::Stage(f)), .. } if f == "0"));
        assert!(
            matches!(&got[3], Instr::Copy { from: Some(CopyFrom::Stage(f)), .. } if f == "base")
        );
    }

    #[test]
    fn multi_stage_reference_rules() {
        // forward-ref (a stage defined LATER) → not an earlier stage. With a name that ISN'T a valid
        // image ref (uppercase), it's rejected rather than silently treated as an image.
        assert!(parse(
            "FROM alpine\nCOPY --from=Later /a /a\nFROM alpine AS later\n",
            &ba()
        )
        .unwrap_err()
        .contains("earlier build stage"));
        // self-ref (the current stage's own name, upper-cased so it's not a valid ref) → rejected
        // (upto excludes the current stage, and `Me` is not a legal image reference).
        assert!(parse("FROM alpine AS me\nCOPY --from=Me /a /a\n", &ba())
            .unwrap_err()
            .contains("earlier build stage"));
        // numeric out-of-range → rejected (a bare number is a stage index, never an external image).
        assert!(parse("FROM alpine\nCOPY --from=5 /a /a\n", &ba())
            .unwrap_err()
            .contains("earlier build stage"));
        // duplicate stage name → rejected.
        assert!(parse("FROM alpine AS x\nFROM alpine AS x\n", &ba())
            .unwrap_err()
            .contains("duplicate build-stage name"));
        // `--from` on ADD → rejected.
        assert!(parse("FROM a AS s\nFROM a\nADD --from=s /x /y\n", &ba())
            .unwrap_err()
            .contains("--from is only supported on COPY"));
    }

    #[test]
    fn copy_from_external_image_ref() {
        // A `--from=<image>` that names no earlier stage but IS a valid OCI reference is accepted as an
        // external image to pull (BuildKit's `COPY --from=nginx:alpine …`).
        let df = "FROM alpine\nCOPY --from=busybox /bin/busybox /bb\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(
            got[1],
            Instr::Copy {
                srcs: vec!["/bin/busybox".into()],
                dst: "/bb".into(),
                from: Some(CopyFrom::Image("busybox".into())),
            }
        );
        // A tagged/registry-qualified ref is fine too.
        assert!(matches!(
            &parse("FROM alpine\nCOPY --from=nginx:alpine /etc/nginx/nginx.conf /\n", &ba()).unwrap()[1],
            Instr::Copy { from: Some(CopyFrom::Image(i)), .. } if i == "nginx:alpine"
        ));
        assert!(matches!(
            &parse("FROM alpine\nCOPY --from=ghcr.io/org/img:1.2 /a /a\n", &ba()).unwrap()[1],
            Instr::Copy { from: Some(CopyFrom::Image(i)), .. } if i == "ghcr.io/org/img:1.2"
        ));
        // Garbage (an uppercase repo isn't a legal ref, nor an earlier stage) is still rejected.
        assert!(parse("FROM alpine\nCOPY --from=Bad_Ref /a /b\n", &ba())
            .unwrap_err()
            .contains("earlier build stage"));
    }

    #[test]
    fn copy_from_stage_wins_over_same_named_image() {
        // `busybox` is both a real image AND an earlier stage name here → the STAGE must win (Docker's
        // rule), so `--from=busybox` resolves to the Stage, not an external Image pull.
        let df = "FROM alpine AS busybox\nRUN true\nFROM alpine\nCOPY --from=busybox /a /a\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(
            got[3],
            Instr::Copy {
                srcs: vec!["/a".into()],
                dst: "/a".into(),
                from: Some(CopyFrom::Stage("busybox".into())),
            }
        );
    }

    #[test]
    fn resolve_from_numeric_and_named() {
        let names = vec![Some("build".to_string()), None, Some("final".to_string())];
        // upto excludes the current stage; only earlier stages resolve.
        assert_eq!(resolve_from("build", &names, 3), Some(0));
        assert_eq!(resolve_from("final", &names, 3), Some(2));
        assert_eq!(resolve_from("0", &names, 3), Some(0));
        assert_eq!(resolve_from("2", &names, 3), Some(2));
        // out of `upto` range → None (forward/self reference).
        assert_eq!(resolve_from("final", &names, 2), None); // final is index 2, not < upto=2
        assert_eq!(resolve_from("3", &names, 3), None); // no such index
        assert_eq!(resolve_from("nope", &names, 3), None);
    }

    /// Pull the shell script out of a `RUN` reduced to `["/bin/sh","-c",<script>]`.
    fn run_script(instr: &Instr) -> &str {
        match instr {
            Instr::Run(a) if a.len() == 3 && a[0] == "/bin/sh" && a[1] == "-c" => &a[2],
            other => panic!("expected shell-form RUN, got {other:?}"),
        }
    }

    #[test]
    fn scan_heredoc_ops_detects_forms_and_ignores_bitshift() {
        // Bare, tab-strip, and both quote styles are recognised (delimiter word only).
        assert_eq!(scan_heredoc_ops("<<EOF").len(), 1);
        let dash = &scan_heredoc_ops("cat <<-END x")[0];
        assert_eq!(dash.delim, "END");
        assert!(dash.strip_tabs);
        assert_eq!(scan_heredoc_ops("python3 <<'PY'")[0].delim, "PY");
        assert_eq!(scan_heredoc_ops("sh <<\"SH\"")[0].delim, "SH");
        // A shell bit-shift (digit after `<<`) is NOT a heredoc.
        assert!(scan_heredoc_ops("echo $((1<<2))").is_empty());
        // Two openers on one line are both found (RUN handler then rejects the pair).
        assert_eq!(scan_heredoc_ops("<<A <<B").len(), 2);
    }

    #[test]
    fn run_heredoc_basic_body_runs_as_shell_script() {
        // The two body lines become ONE `/bin/sh -c` script (newline-joined), the dominant case.
        let df =
            "FROM alpine\nRUN <<EOF\necho line1\necho line2 > /tmp/x\nEOF\nCMD [\"/bin/sh\"]\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(
            got[1],
            Instr::Run(vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo line1\necho line2 > /tmp/x".into()
            ])
        );
        // The delimiter line is consumed, not parsed as an instruction: FROM, RUN, CMD only.
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn run_heredoc_dash_strips_leading_tabs() {
        // `<<-` strips leading TABs from body lines and allows a tab-indented close; spaces are kept.
        let df = "FROM alpine\nRUN <<-EOF\n\techo hi\n\t  spaced\n\tEOF\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(run_script(&got[1]), "echo hi\n  spaced");
    }

    #[test]
    fn run_heredoc_quoted_delimiter_body_verbatim() {
        // A quoted delimiter matches the unquoted word; the body is kept verbatim.
        let df = "FROM alpine\nRUN <<'EOF'\necho ${NOT_EXPANDED}\nEOF\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(run_script(&got[1]), "echo ${NOT_EXPANDED}");
    }

    #[test]
    fn run_heredoc_interpreter_form_feeds_stdin() {
        // A command before `<<` (here `cat`) gets the body on stdin via a real shell heredoc.
        let df = "FROM alpine\nRUN cat <<EOF\nhello\nworld\nEOF\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(run_script(&got[1]), "cat <<'EOF'\nhello\nworld\nEOF");
        // A body containing single quotes survives (the batcher single-quote-escapes when combining).
        let py = "FROM alpine\nRUN python3 <<EOF\nprint('hi')\nEOF\n";
        assert_eq!(
            run_script(&parse(py, &ba()).unwrap()[1]),
            "python3 <<'EOF'\nprint('hi')\nEOF"
        );
    }

    #[test]
    fn run_heredoc_bitshift_is_not_a_heredoc() {
        // `RUN echo $((1<<2))` is an ordinary single-line RUN, never a heredoc opener.
        let got = parse("FROM alpine\nRUN echo $((1<<2))\n", &ba()).unwrap();
        assert_eq!(run_script(&got[1]), "echo $((1<<2))");
    }

    #[test]
    fn run_heredoc_unterminated_errors() {
        // Delimiter never reappears before EOF → a clear "unterminated heredoc" error, no panic.
        let err = parse("FROM alpine\nRUN <<EOF\necho hi\n", &ba()).unwrap_err();
        assert!(err.contains("unterminated heredoc"), "{err}");
        assert!(err.contains("EOF"), "{err}");
    }

    #[test]
    fn run_multiple_heredocs_rejected() {
        // Stacked heredocs on one instruction are detected and rejected, not mis-parsed.
        let err = parse("FROM alpine\nRUN <<A <<B\nx\nA\ny\nB\n", &ba()).unwrap_err();
        assert!(err.contains("multiple heredocs"), "{err}");
    }

    #[test]
    fn copy_heredoc_errors_clearly() {
        // COPY heredoc isn't implemented; error clearly rather than silently dropping the body.
        let err = parse("FROM alpine\nCOPY <<EOF /app/x\nhello\nEOF\n", &ba()).unwrap_err();
        assert!(err.contains("heredoc"), "{err}");
    }
}
