//! A tiny, dependency-free parser for a **subset** of the Dockerfile format, used by `kern build`.
//!
//! Supported instructions: `FROM RUN COPY ADD ENV WORKDIR USER CMD ENTRYPOINT EXPOSE ARG LABEL`.
//! Deliberately NOT supported (and rejected with a clear error, never silently ignored):
//! multi-stage builds (`FROM … AS`, `COPY --from`), `VOLUME`, `HEALTHCHECK`, `SHELL`, `ONBUILD`,
//! `STOPSIGNAL`, `ADD <url>`, and `ADD` auto-extraction. Comments (`#`), blank lines and backslash
//! line-continuations are handled; `ARG`/`ENV` values substitute into later `${VAR}`/`$VAR`.
//!
//! The parser is pure (text in, instructions out) so it is unit-testable without touching disk or
//! the network; the executor lives in `commands::build`.

use std::collections::HashMap;

/// One resolved build step. `RUN`/`CMD`/`ENTRYPOINT` are already reduced to an argv (shell form
/// `X` becomes `["/bin/sh","-c","X"]`, exec form `["a","b"]` stays as given). `ARG`/`LABEL` produce
/// no instruction (they only affect variable substitution / are ignored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instr {
    From(String),
    Run(Vec<String>),
    Copy { srcs: Vec<String>, dst: String },
    Env(String, String),
    Workdir(String),
    User(String),
    Cmd(Vec<String>),
    Entrypoint(Vec<String>),
    Expose(String),
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

    for (lineno, logical) in logical_lines(text).into_iter() {
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

        // Reject the multi-stage marker explicitly wherever it can appear.
        if kw == "FROM"
            && rest
                .split_whitespace()
                .any(|t| t.eq_ignore_ascii_case("as"))
        {
            return err("multi-stage builds (FROM … AS) aren't supported yet");
        }

        match kw.as_str() {
            "FROM" => {
                if saw_from {
                    return err("multi-stage builds (multiple FROM) aren't supported yet");
                }
                let image = subst(rest, &vars);
                if image.is_empty() {
                    return err("FROM needs an image reference");
                }
                saw_from = true;
                out.push(Instr::From(image));
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
            "RUN" => out.push(Instr::Run(cmd_argv(rest, &vars))),
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
                let mut toks = split_ws(&subst(rest, &vars));
                // Reject build-only flags we don't implement rather than silently ignore them.
                if let Some(f) = toks.iter().find(|t| t.starts_with("--")) {
                    if f.starts_with("--from") {
                        return err("COPY --from (multi-stage) isn't supported yet");
                    }
                    return err(&format!("{kw} flag {f} isn't supported yet"));
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
                out.push(Instr::Copy { srcs: toks, dst });
            }
            "EXPOSE" => {
                for p in split_ws(&subst(rest, &vars)) {
                    out.push(Instr::Expose(p));
                }
            }
            "LABEL" | "MAINTAINER" => { /* metadata — parsed and ignored */ }
            "VOLUME" | "HEALTHCHECK" | "SHELL" | "ONBUILD" | "STOPSIGNAL" => {
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

/// Fold physical lines into logical ones: drop full-line comments, honour a trailing `\`
/// continuation. Returns `(first_physical_lineno, joined_text)` per logical line.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut start = 0usize;
    let mut continuing = false;
    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;
        // A `#` comment line is only a comment when NOT continuing a previous line.
        if !continuing && raw.trim_start().starts_with('#') {
            continue;
        }
        if !continuing {
            start = lineno;
        }
        let trimmed_end = raw.trim_end();
        if let Some(stripped) = trimmed_end.strip_suffix('\\') {
            cur.push_str(stripped);
            cur.push(' ');
            continuing = true;
        } else {
            cur.push_str(raw);
            out.push((start, std::mem::take(&mut cur)));
            continuing = false;
        }
    }
    if !cur.is_empty() {
        out.push((start, cur));
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
    fn minimal_from_run_cmd() {
        let df = "FROM alpine:3.19\nRUN echo hi\nCMD [\"/bin/sh\"]\n";
        let got = parse(df, &ba()).unwrap();
        assert_eq!(got[0], Instr::From("alpine:3.19".into()));
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
                dst: "/dst/".into()
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
        assert!(parse("FROM alpine AS build\n", &ba())
            .unwrap_err()
            .contains("multi-stage"));
        assert!(parse("FROM a\nCOPY --from=x /a /b\n", &ba())
            .unwrap_err()
            .contains("multi-stage"));
        assert!(parse("FROM a\nVOLUME /data\n", &ba())
            .unwrap_err()
            .contains("VOLUME"));
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
        assert_eq!(parse(df, &ba()).unwrap()[0], Instr::From("alpine".into()));
    }
}
