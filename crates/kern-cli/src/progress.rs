//! `--progress auto|tty|plain|json|quiet` for `kern build` and `kern compose`: the mode, and the
//! events and live view built on it. The mode itself lives in `kern_common` (`ProgressMode`), where
//! the `progress!` narrator reads it; this module takes the flag off the command line, emits the
//! events, and draws the live view.

use kern_common::ProgressMode;

/// Compose verbs after which `--progress` is still kern's: they take flags and service names, never
/// a command of their own. After `run` or `exec` the rest is the box's command line, and a
/// `--progress` there (`npm --progress=false`) belongs to it.
const COMPOSE_VERBS_WITH_PROGRESS: [&str; 6] =
    ["up", "build", "pull", "create", "start", "restart"];

/// Take `--progress <mode>` (or `--progress=<mode>`) off a `kern build` / `kern compose` command line,
/// put the mode in force for this process and for every kern it starts (`KERN_PROGRESS`), and return
/// the rest. Other commands are returned unchanged. An unknown mode is refused.
pub fn take_progress_flag(args: &[String]) -> Result<Vec<String>, crate::error::Error> {
    let first = args.first().map(String::as_str);
    if !matches!(first, Some("build" | "compose")) {
        return Ok(args.to_vec());
    }
    let compose = first == Some("compose");
    let verbs: Vec<&str> = crate::commands::COMPOSE_VERBS
        .iter()
        .map(|(n, _)| *n)
        .collect();
    let mut out: Vec<String> = Vec::with_capacity(args.len());
    let mut mode: Option<ProgressMode> = None;
    let mut verb: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            out.extend(args[i..].iter().cloned());
            break;
        }
        if compose && verb.is_none() && i > 0 && verbs.contains(&a) {
            verb = Some(a);
        }
        let ours = !compose || verb.is_none_or(|v| COMPOSE_VERBS_WITH_PROGRESS.contains(&v));
        let value = if !ours {
            None
        } else if a == "--progress" {
            i += 1;
            Some(args.get(i).map(String::as_str).unwrap_or(""))
        } else {
            a.strip_prefix("--progress=")
        };
        match value {
            Some(v) => {
                mode = Some(ProgressMode::parse(v).ok_or(crate::error::Error::Usage(
                    "--progress auto|tty|plain|json|quiet",
                ))?);
            }
            None => out.push(args[i].clone()),
        }
        i += 1;
    }
    if let Some(m) = mode {
        kern_common::set_progress_mode(m);
        crate::set_global_env("KERN_PROGRESS", m.word());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn progress_is_taken_where_it_is_kerns_and_left_where_it_is_the_boxes() {
        let _g = crate::env_guard();
        let cases: [(&[&str], &[&str]); 6] = [
            (
                &["build", "--progress", "plain", "-t", "x", "."],
                &["build", "-t", "x", "."],
            ),
            (
                &["compose", "--progress=quiet", "up", "-d"],
                &["compose", "up", "-d"],
            ),
            (
                &["compose", "f.yml", "up", "--progress", "json"],
                &["compose", "f.yml", "up"],
            ),
            (
                &["compose", "run", "app", "npm", "--progress=false"],
                &["compose", "run", "app", "npm", "--progress=false"],
            ),
            (
                &["compose", "exec", "app", "x", "--progress", "plain"],
                &["compose", "exec", "app", "x", "--progress", "plain"],
            ),
            (
                &["box", "x", "--progress", "plain"],
                &["box", "x", "--progress", "plain"],
            ),
        ];
        for (input, want) in cases {
            let got = take_progress_flag(&v(input)).ok();
            assert_eq!(got, Some(v(want)), "{input:?}");
        }
        assert!(take_progress_flag(&v(&["build", "--progress", "loud"])).is_err());
        assert!(take_progress_flag(&v(&["build", "--progress"])).is_err());
        kern_common::set_progress_mode(ProgressMode::Auto);
        crate::unset_global_env("KERN_PROGRESS");
    }
}
