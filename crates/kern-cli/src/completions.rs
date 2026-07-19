//! `kern completions <bash|zsh|fish>` - print a shell-completion script to stdout.
//!
//! kern uses a hand-rolled parser (no clap), so the scripts are hand-written: they complete the verb
//! set and, for the box-management verbs, the names of currently-running boxes via `kern ps`. Install
//! with e.g. `kern completions bash | sudo tee /etc/bash_completion.d/kern`.

use crate::error::Error;

/// The top-level verbs, kept in one place so all three shells stay in sync.
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
    "pod",
    "search",
    "images",
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
];

/// Verbs whose first argument is a running box's name (so completion can offer `kern ps` names).
const NAME_VERBS: &[&str] = &[
    "exec", "attach", "logs", "inspect", "pause", "unpause", "stop", "kill",
];

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
    format!(
        r#"#compdef kern
# kern zsh completion - install: kern completions zsh > "${{fpath[1]}}/_kern"
_kern() {{
    local -a verbs name_verbs
    verbs=({verbs})
    name_verbs=({name_verbs})
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
    out
}
