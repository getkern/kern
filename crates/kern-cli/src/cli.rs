//! Command parsing and dispatch.
//!
//! A tiny hand-rolled parser keeps the binary dependency-free. The roadmap target is a
//! `clap`-derive command enum + `match` dispatch (same shape, see ARCHITECTURE.md).

use crate::commands;
use crate::error::Error;

/// Global runtime options that apply to any command.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GlobalOpts {
    /// `--no-gpu`: never load any GPU driver interposer. Decouples the sandbox trust decision
    /// from the driver-interposition trust decision; any GPU support is opt-in and off by
    /// default. The runtime itself is GPU-free.
    pub no_gpu: bool,
}

/// The parsed subcommand.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Version,
    Help,
    /// `kern box <name> --plan`: print the ordered isolation step sequence (no privileges).
    BoxPlan {
        name: String,
    },
    /// A runtime subcommand recognised but not yet implemented in this 0.x scaffold.
    Pending(&'static str),
}

/// Split argv into global options and a subcommand.
pub fn parse(args: &[String]) -> Result<(GlobalOpts, Command), Error> {
    let mut opts = GlobalOpts::default();
    let mut rest: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "--no-gpu" => opts.no_gpu = true,
            other => rest.push(other),
        }
    }
    let cmd = match rest.first().copied() {
        None | Some("--help" | "-h" | "help") => Command::Help,
        Some("--version" | "-V" | "version") => Command::Version,
        // `box <name> --plan` prints the isolation sequence (0.2); real `box` exec is 0.3.
        Some("box") => {
            let plan = rest.contains(&"--plan");
            let name = rest.iter().skip(1).find(|a| !a.starts_with("--"));
            match (plan, name) {
                (true, Some(n)) => Command::BoxPlan {
                    name: (*n).to_string(),
                },
                _ => Command::Pending("box"),
            }
        }
        // Recognised runtime verbs — implemented across the 0.x roadmap.
        Some("run") => Command::Pending("run"),
        Some("pull") => Command::Pending("pull"),
        Some("compose") => Command::Pending("compose"),
        Some(other) => return Err(Error::UnknownCommand(other.to_string())),
    };
    Ok((opts, cmd))
}

/// Parse and run.
pub fn run(args: &[String]) -> Result<(), Error> {
    let (opts, cmd) = parse(args)?;
    match cmd {
        Command::Version => commands::version(),
        Command::Help => commands::help(),
        Command::BoxPlan { name } => commands::box_plan(&name),
        Command::Pending(name) => commands::pending(name, &opts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_gpu_flag_is_parsed_and_default_off() {
        let (o, _) = parse(&["box".into()]).unwrap();
        assert!(!o.no_gpu, "GPU interposition is off by default");
        let (o, c) = parse(&["--no-gpu".into(), "box".into()]).unwrap();
        assert!(o.no_gpu);
        assert_eq!(c, Command::Pending("box"));
    }

    #[test]
    fn version_and_help_resolve() {
        assert_eq!(parse(&["--version".into()]).unwrap().1, Command::Version);
        assert_eq!(parse(&[]).unwrap().1, Command::Help);
    }

    #[test]
    fn box_plan_needs_both_name_and_flag() {
        // `box <name> --plan` → BoxPlan; missing either → Pending (real exec lands at 0.3).
        let plan = parse(&["box".into(), "web".into(), "--plan".into()])
            .unwrap()
            .1;
        assert_eq!(plan, Command::BoxPlan { name: "web".into() });
        // order-independent: flag before name
        let plan2 = parse(&["box".into(), "--plan".into(), "api".into()])
            .unwrap()
            .1;
        assert_eq!(plan2, Command::BoxPlan { name: "api".into() });
        // name without --plan, or --plan without a name → still Pending
        assert_eq!(
            parse(&["box".into(), "web".into()]).unwrap().1,
            Command::Pending("box")
        );
        assert_eq!(
            parse(&["box".into(), "--plan".into()]).unwrap().1,
            Command::Pending("box")
        );
    }

    #[test]
    fn unknown_command_errors() {
        assert!(matches!(
            parse(&["frobnicate".into()]),
            Err(Error::UnknownCommand(_))
        ));
    }
}
