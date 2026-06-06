//! `kern login` / `kern logout` — store or remove registry credentials used by the OCI pull path
//! for private images. Credentials live in the owner-only (`0600`) file managed by
//! [`kern_common::registry_auth`]; the password is read from the terminal with echo off (or from
//! stdin when piped, so it stays out of shell history and `argv`).

use crate::error::Error;

/// Docker Hub's token service host — the default registry when none is given, matching the OCI
/// pull path's `DEFAULT_REGISTRY`.
const DEFAULT_REGISTRY: &str = "registry-1.docker.io";

/// `kern login [registry] [--username U]` — prompt for (or take) a username, read a password without
/// echo, and store the credentials for `registry` (default: Docker Hub).
pub fn login(registry: Option<&str>, username: Option<&str>) -> Result<(), Error> {
    let registry = registry.unwrap_or(DEFAULT_REGISTRY);
    let user = match username {
        Some(u) => u.to_string(),
        None => prompt(&format!("Username for {registry}: "))?,
    };
    if user.is_empty() {
        return Err(Error::Usage("login: username must not be empty"));
    }
    let pass = read_password(&format!("Password for {user}@{registry}: "))?;
    if pass.is_empty() {
        return Err(Error::Usage("login: password must not be empty"));
    }
    kern_common::registry_auth::store(registry, &user, &pass)
        .map_err(|e| Error::Sandbox(format!("storing credentials: {e}")))?;
    println!("logged in to {registry} as {user}");
    Ok(())
}

/// `kern logout [registry]` — remove the stored credentials for `registry` (default: Docker Hub).
pub fn logout(registry: Option<&str>) -> Result<(), Error> {
    let registry = registry.unwrap_or(DEFAULT_REGISTRY);
    let removed = kern_common::registry_auth::remove(registry)
        .map_err(|e| Error::Sandbox(format!("removing credentials: {e}")))?;
    if removed {
        println!("logged out of {registry}");
    } else {
        println!("not logged in to {registry}");
    }
    Ok(())
}

/// Print `prompt` to stderr (so it doesn't pollute piped stdout) and read a line from stdin.
fn prompt(prompt: &str) -> Result<String, Error> {
    use std::io::{BufRead, Write};
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Error::Sandbox(format!("reading input: {e}")))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Read a password without echoing it. Turns off terminal `ECHO` for the read when stdin is a tty;
/// when stdin is piped (not a tty) it just reads a line, so CI/scripts can `printf pass | kern login`.
fn read_password(prompt_text: &str) -> Result<String, Error> {
    use std::io::{BufRead, Write};
    let is_tty = unsafe { libc::isatty(0) } == 1;
    eprint!("{prompt_text}");
    let _ = std::io::stderr().flush();

    // Save termios, clear ECHO, read, restore — best-effort and panic-safe (restored on every path).
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let echo_off = is_tty && unsafe { libc::tcgetattr(0, &mut saved) } == 0;
    if echo_off {
        let mut raw = saved;
        raw.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) };
    }
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if echo_off {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &saved) };
        eprintln!(); // the user's Enter wasn't echoed — move to a fresh line
    }
    read.map_err(|e| Error::Sandbox(format!("reading password: {e}")))?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}
