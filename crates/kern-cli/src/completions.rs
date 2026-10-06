//! `kern completions <bash|zsh|fish>` - print a shell-completion script to stdout.
//!
//! kern uses a hand-rolled parser (no clap), so the scripts are hand-written: they complete the verb
//! set and, for the box-management verbs, the names of currently-running boxes via `kern ps`. Install
//! with e.g. `kern completions bash | sudo tee /etc/bash_completion.d/kern`.

use crate::error::Error;

/// The top-level verbs.
///
/// This list and the `COMMANDS:` block of `kern --help` are two descriptions of one parser, so they
/// drifted: nine verbs the reference documents (`commit`, `rmi`, `rename`, `update`, `wait`, `diff`,
/// `events`, `up`, `uninstall`) could not be tab-completed, and two the parser accepts (`killall`,
/// `logout`) appeared only here. Neither direction is harmless: the first hides working commands
/// from the discovery path most people use, the second offers commands the reference never
/// explains. `the_completions_and_the_reference_agree` compares the two lists now.
const VERBS: &[&str] = &[
    "box",
    "run",
    "exec",
    "attach",
    "cp",
    "logs",
    "ps",
    "top",
    "stats",
    "inspect",
    "pause",
    "unpause",
    "stop",
    "kill",
    "killall",
    "pull",
    "push",
    "tag",
    "build",
    "network",
    "pod",
    "search",
    "images",
    "image",
    "builds",
    "save",
    "load",
    "compose",
    "volume",
    "config",
    "validate",
    "examples",
    "doctor",
    "probe",
    "info",
    "bench",
    "history",
    "recover",
    "login",
    "logout",
    "gc",
    "prune",
    "completions",
    "version",
    "help",
    // Documented in the reference and missing here until 0.6.39.
    "commit",
    "rmi",
    "rename",
    "update",
    "wait",
    "diff",
    "events",
    "up",
    "down",
    "uninstall",
    "port",
    // `kern box --keep` gave these two something to act on; they were documented and uncompletable
    // until `the_completions_and_the_reference_agree` said so.
    "start",
    "rm",
];

/// Verbs whose first argument is a running box's name (so completion can offer `kern ps` names).
const NAME_VERBS: &[&str] = &[
    "exec", "attach", "logs", "inspect", "pause", "unpause", "stop", "kill", "port",
];

/// Verbs whose first argument is a KEPT box's name, which is a different set from the one above:
/// `kern start` and `kern rm` act on a box that is NOT running, so offering the running names would
/// complete to exactly the names both verbs refuse. The source is `ps -a -q --filter status=kept`,
/// one line per name, which is the query that means "what `kern start` can run".
const KEPT_VERBS: &[&str] = &["start", "rm"];

/// The shell command each script runs to list kept names. One spelling, so the three scripts cannot
/// drift from each other or from the filter the CLI accepts.
const KEPT_NAMES_CMD: &str = "kern ps -a -q --filter status=kept 2>/dev/null";

pub fn completions(shell: &str) -> Result<(), Error> {
    match shell {
        "bash" => print!("{}", bash()),
        "zsh" => print!("{}", zsh()),
        "fish" => print!("{}", fish()),
        _ => return Err(Error::Usage("completions <bash|zsh|fish>")),
    }
    Ok(())
}

fn bash() -> String {
    let verbs = VERBS.join(" ");
    let name_verbs = NAME_VERBS.join("|");
    let kept_verbs = KEPT_VERBS.join("|");
    let kept_cmd = KEPT_NAMES_CMD;
    format!(
        r#"# kern bash completion - install: kern completions bash | sudo tee /etc/bash_completion.d/kern
_kern() {{
    local cur prev verbs
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    verbs="{verbs}"
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$verbs" -- "$cur") )
        return
    fi
    case "$prev" in
        {name_verbs})
            local names
            names=$(kern ps 2>/dev/null | awk 'NR>1{{print $1}}')
            COMPREPLY=( $(compgen -W "$names" -- "$cur") )
            return ;;
        {kept_verbs})
            local kept
            kept=$({kept_cmd})
            COMPREPLY=( $(compgen -W "$kept" -- "$cur") )
            return ;;
    esac
    COMPREPLY=( $(compgen -f -- "$cur") )
}}
complete -F _kern kern
"#
    )
}

fn zsh() -> String {
    let verbs = VERBS.join(" ");
    let name_verbs = NAME_VERBS.join(" ");
    let kept_verbs = KEPT_VERBS.join(" ");
    let kept_cmd = KEPT_NAMES_CMD;
    format!(
        r#"#compdef kern
# kern zsh completion - install: kern completions zsh > "${{fpath[1]}}/_kern"
_kern() {{
    local -a verbs name_verbs kept_verbs
    verbs=({verbs})
    name_verbs=({name_verbs})
    kept_verbs=({kept_verbs})
    if (( CURRENT == 2 )); then
        _describe 'command' verbs
        return
    fi
    if (( ${{name_verbs[(I)${{words[2]}}]}} )); then
        local -a names
        names=(${{(f)"$(kern ps 2>/dev/null | awk 'NR>1{{print $1}}')"}})
        _describe 'box' names
        return
    fi
    if (( ${{kept_verbs[(I)${{words[2]}}]}} )); then
        local -a kept
        kept=(${{(f)"$({kept_cmd})"}})
        _describe 'kept box' kept
        return
    fi
    _files
}}
_kern "$@"
"#
    )
}

fn fish() -> String {
    let mut out = String::from("# kern fish completion - install: kern completions fish > ~/.config/fish/completions/kern.fish\n");
    // Verb completions (only at the first position).
    for v in VERBS {
        out.push_str(&format!(
            "complete -c kern -n '__fish_use_subcommand' -a '{v}'\n"
        ));
    }
    // Running-box-name completion for the name verbs.
    let cond = NAME_VERBS
        .iter()
        .map(|v| format!("__fish_seen_subcommand_from {v}"))
        .collect::<Vec<_>>()
        .join("; or ");
    out.push_str(&format!(
        "complete -c kern -n '{cond}' -a '(kern ps 2>/dev/null | awk \"NR>1{{print \\$1}}\")'\n"
    ));
    // Kept-box-name completion for `start` and `rm`, which act on a box that is not running.
    let kept_cond = KEPT_VERBS
        .iter()
        .map(|v| format!("__fish_seen_subcommand_from {v}"))
        .collect::<Vec<_>>()
        .join("; or ");
    out.push_str(&format!(
        "complete -c kern -n '{kept_cond}' -a '({KEPT_NAMES_CMD})'\n"
    ));
    out
}
