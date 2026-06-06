//! `kern pod` — a **pod** is a set of boxes that share ONE loopback network, so services reach each
//! other by name on `127.0.0.1` (like a Kubernetes pod). A hidden **holder** process (`kern
//! __pod-holder`, [`kern_isolation::run_pod_holder`]) owns the pod's user+net namespace; each
//! `kern box --pod <name>` box `setns`es into it. A shared `/etc/hosts` (bind-mounted into every pod
//! box) maps each member name → `127.0.0.1`, updated as members join. Pod members are co-trusted
//! (they share the user+net ns); the pod is the network trust unit.
//!
//! **Outbound** is OPTIONAL: if `pasta` (passt) is installed, `create` attaches it to the pod net ns
//! for rootless NAT'd internet access + DNS (unless `--no-outbound`); without pasta the pod is
//! loopback-only (inter-service only; publish to the host with `-p` on a box). kern itself needs no
//! extra dependency to run — pasta only unlocks pod egress.

use crate::error::Error;
use std::io::{BufRead, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;

/// `<XDG_RUNTIME_DIR|/run/user/uid>/kern/pods`.
fn pods_root() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })));
    base.join("kern/pods")
}

/// A pod's private directory (`…/pods/<name>`): holds the `holder` pid file and the shared `hosts`.
fn pod_dir(name: &str) -> PathBuf {
    pods_root().join(name)
}

/// Path of a pod's shared `/etc/hosts` (bind-mounted into every member box).
pub fn hosts_path(name: &str) -> PathBuf {
    pod_dir(name).join("hosts")
}

/// Path of a pod's `/etc/resolv.conf` — present only when the pod has OUTBOUND (a `pasta` NAT was
/// set up); bind-mounted into member boxes so DNS works. `None`/absent → loopback-only pod.
pub fn resolv_path(name: &str) -> PathBuf {
    pod_dir(name).join("resolv.conf")
}

/// The inode of `/proc/<pid>/ns/<kind>` — a namespace's stable identity. Used to detect PID reuse:
/// a recorded holder PID is only trusted if its net ns inode still matches the one from create time.
fn ns_inode(pid: i32, kind: &str) -> Option<u64> {
    std::fs::metadata(format!("/proc/{pid}/ns/{kind}"))
        .ok()
        .map(|m| std::os::unix::fs::MetadataExt::ino(&m))
}

/// The holder PID for pod `name` if the pod exists, its holder is still alive, AND its net ns is the
/// SAME one recorded at create (guards against the PID being reused by an unrelated process after the
/// holder died — otherwise a box could `setns` into a stranger's namespace). Else `None`.
pub fn holder_pid(name: &str) -> Option<i32> {
    let dir = pod_dir(name);
    let pid: i32 = std::fs::read_to_string(dir.join("holder"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if unsafe { libc::kill(pid, 0) } != 0 {
        return None; // holder gone
    }
    // Verify the net ns identity matches what we recorded — reject a reused PID.
    let want: u64 = std::fs::read_to_string(dir.join("netns"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if ns_inode(pid, "net") == Some(want) {
        Some(pid)
    } else {
        None
    }
}

/// Is a concurrent `pod create` still mid-startup for this dir? True iff the `starting` marker names
/// a live PID **whose kernel start-time still matches** — so a stale marker whose pid was reused by an
/// unrelated process reads as dead, not as a live starter. Used only to make two racing
/// `pod create <same>` safe: the mkdir loser must not reclaim the dir while the winner's holder is
/// still coming up (its `holder` pid isn't written yet).
fn starter_alive(dir: &std::path::Path) -> bool {
    let Ok(marker) = std::fs::read_to_string(dir.join("starting")) else {
        return false;
    };
    let marker = marker.trim();
    // `pid:starttime` (new) or a bare `pid` (older marker) — parse whichever is present.
    let (pid_s, want_start) = marker.split_once(':').unwrap_or((marker, ""));
    let Ok(pid) = pid_s.parse::<i32>() else {
        return false;
    };
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false; // no such live process
    }
    match want_start.parse::<u64>() {
        Ok(s) => crate::registry::proc_starttime(pid) == s, // reject a reused pid
        Err(_) => true, // bare-pid marker: liveness only (back-compat)
    }
}

/// `kern pod create <name> [--no-outbound]` — spawn the pod's namespace holder + seed its hosts, and
/// (unless `--no-outbound`, and if pasta is installed) attach pasta for internet egress. Publish a
/// service with `-p` on its member box.
pub fn create(name: &str, want_outbound: bool) -> Result<(), Error> {
    validate_name(name)?;
    let dir = pod_dir(name);
    let _ = std::fs::create_dir_all(pods_root()); // ensure the parent exists (recursive)

    // ATOMICALLY claim the pod by a NON-recursive 0700 mkdir: two concurrent `pod create <same>`
    // can't both proceed (the loser gets AlreadyExists). Private (0700): another local user must not
    // read/alter a pod's hosts or holder pid. A leftover dead pod dir (holder gone) is reclaimed.
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            // A live holder means a real, running pod. A live `starting` marker means a CONCURRENT
            // `pod create` is mid-startup (it won the mkdir but hasn't written its holder pid yet).
            // In BOTH cases refuse: never stomp an in-progress claim, or we'd orphan the winner's
            // holder. Only a genuinely dead leftover (no holder AND no live starter) is reclaimed.
            //
            // The winner writes its `starting` marker microseconds after winning the mkdir — but on a
            // slow host that gap widens to milliseconds, so a naive single check here can race in and
            // see neither holder nor starter *before* the winner marks itself. Poll briefly (bounded)
            // before concluding the dir is dead: a live winner appears within a few ms; a genuinely
            // dead leftover (creator crashed pre-marker) stays empty and is reclaimed after the wait.
            let claimed = || holder_pid(name).is_some() || starter_alive(&dir);
            let mut alive = claimed();
            for _ in 0..20 {
                if alive {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                alive = claimed();
            }
            if alive {
                return Err(Error::Sandbox(format!("pod '{name}' already exists")));
            }
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|e| Error::Sandbox(format!("pod dir: {e}")))?;
        } else {
            return Err(Error::Sandbox(format!("pod dir: {e}")));
        }
    }
    // Mark this claim as in-progress with OUR `pid:starttime`, BEFORE the (slow) holder startup, so a
    // concurrent loser above sees a live starter and backs off instead of reclaiming a half-built pod.
    // The start-time pins the pid's identity (as the registry does for supervisors) so a stale marker
    // whose pid was later reused by an unrelated process can't wedge `pod create` shut.
    let me = unsafe { libc::getpid() };
    let _ = std::fs::write(
        dir.join("starting"),
        format!("{me}:{}", crate::registry::proc_starttime(me)),
    );
    // Seed the shared /etc/hosts. Every member box bind-mounts this; members are appended on join.
    std::fs::write(
        hosts_path(name),
        "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n",
    )
    .map_err(|e| Error::Sandbox(format!("pod hosts: {e}")))?;

    // Spawn the holder: a detached `kern __pod-holder` that unshares + holds the pod user+net ns and
    // prints `pod-ready` once its namespaces are set up. We read that line, then record its PID.
    let self_exe = std::env::current_exe()
        .map_err(|e| Error::Sandbox(format!("cannot locate the kern binary: {e}")))?;
    let mut child = std::process::Command::new(self_exe)
        .arg("__pod-holder")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .process_group(0) // its own session/group so it survives this command exiting
        .spawn()
        .map_err(|e| Error::Sandbox(format!("pod holder: {e}")))?;
    let pid = child.id() as i32;
    let ready = child
        .stdout
        .take()
        .map(|mut out| {
            let mut line = String::new();
            std::io::BufReader::new(&mut out).read_line(&mut line).ok();
            line.trim() == "pod-ready"
        })
        .unwrap_or(false);
    if !ready {
        let _ = child.kill();
        let _ = std::fs::remove_dir_all(&dir); // also drops the `starting` marker
        return Err(Error::Sandbox(
            "pod holder failed to start (unprivileged user namespaces may be unavailable)".into(),
        ));
    }
    // Record the holder PID + its net ns inode (identity, to reject a later PID reuse). Write the
    // inode FIRST so a concurrent lookup never sees a holder pid without its verifier.
    if let Some(ino) = ns_inode(pid, "net") {
        let _ = std::fs::write(dir.join("netns"), ino.to_string());
    }
    std::fs::write(dir.join("holder"), pid.to_string())
        .map_err(|e| Error::Sandbox(format!("pod holder pid: {e}")))?;
    let _ = std::fs::remove_file(dir.join("starting")); // claim complete: holder pid is now recorded
                                                        // The holder is detached (own process group, reparented to init on our exit) and runs until
                                                        // `kern pod rm`. `forget` just drops our `Child` handle without any wait/kill (std never reaps or
                                                        // signals on drop) — the stdout pipe was already `.take()`n, so nothing leaks.
    std::mem::forget(child);
    // OUTBOUND (default, opt-out with `--no-outbound`): if `pasta` (passt) is installed, attach it to
    // the pod net ns for NAT'd internet egress + DNS. Best-effort: absent/failed → loopback-only.
    let outbound = want_outbound && setup_outbound(name, pid);
    println!("created pod '{name}'");
    println!(
        "  add boxes: kern box <name> --pod {name} -d -- …  (publish a service with -p on its box)"
    );
    if outbound {
        println!("  network: services reach each other by name + outbound to the internet (pasta)");
    } else if !want_outbound {
        println!("  network: loopback-only (--no-outbound) — services reach each other; no egress");
    } else {
        println!("  network: loopback-only — services reach each other; NO outbound (install `passt`/`pasta` for egress)");
    }
    Ok(())
}

/// Attach `pasta` (passt) to the pod's net ns for NAT'd outbound + DNS, and seed the pod's
/// `resolv.conf`. Returns `true` only when outbound AND DNS are actually up (so `create`'s message
/// is honest). Best-effort: no pasta / any failure → `false` (the pod stays loopback-only). pasta
/// backgrounds itself and exits automatically when the net ns is freed (at `pod rm`).
fn setup_outbound(name: &str, holder: i32) -> bool {
    let Some(pasta) = which_pasta() else {
        return false;
    };
    let dir = pod_dir(name);
    // `--config-net` copies the host's addresses/routes into the ns tap and NATs outbound; pasta then
    // daemonizes (the spawned process exits once setup is done). `-q` quiets it, `-P` records its PID.
    let ok = std::process::Command::new(pasta)
        .arg("--config-net")
        .arg("-q")
        .arg("-P")
        .arg(dir.join("pasta.pid"))
        .arg("--userns")
        .arg(format!("/proc/{holder}/ns/user"))
        .arg("--netns")
        .arg(format!("/proc/{holder}/ns/net"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        return false;
    }
    // Seed the pod resolv.conf with the host's real (non-loopback) nameservers — reachable through
    // the NAT, so split-horizon/LAN DNS keeps working. Only if the host has NONE that are usable from
    // the ns (e.g. systemd-resolved's 127.0.0.53 stub) do we fall back to a public resolver.
    let mut resolv = String::new();
    if let Ok(host) = std::fs::read_to_string("/etc/resolv.conf") {
        for l in host.lines() {
            if let Some(ns) = l.strip_prefix("nameserver ") {
                // A resolv.conf value is a single token; take it and drop any trailing comment.
                let ns = ns.split_whitespace().next().unwrap_or("");
                if !ns.starts_with("127.") && !ns.is_empty() {
                    resolv.push_str(&format!("nameserver {ns}\n"));
                }
            }
        }
    }
    if resolv.is_empty() {
        resolv.push_str("nameserver 1.1.1.1\n"); // host has only a local stub → public fallback
    }
    // DNS is only "up" if we actually wrote the resolv.conf the box will bind — else don't claim it.
    std::fs::write(resolv_path(name), resolv).is_ok()
}

/// Locate the `pasta` binary (part of passt), or `None` if it isn't installed.
fn which_pasta() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("pasta"))
            .find(|p| p.is_file())
    })
}

/// Append a member to a pod's shared `/etc/hosts` (name → `127.0.0.1`) if not already present, so
/// every member box can resolve it. Idempotent.
pub fn add_member(name: &str, member: &str) -> Result<(), Error> {
    let hp = hosts_path(name);
    let body = std::fs::read_to_string(&hp).unwrap_or_default();
    let line = format!("127.0.0.1\t{member}\n");
    if body.lines().any(|l| {
        let mut it = l.split_whitespace();
        it.next() == Some("127.0.0.1") && it.next() == Some(member)
    }) {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&hp)
        .map_err(|e| Error::Sandbox(format!("pod hosts: {e}")))?;
    f.write_all(line.as_bytes())
        .map_err(|e| Error::Sandbox(format!("pod hosts: {e}")))?;
    Ok(())
}

/// `kern pod ls` — list pods (name, member count, alive/dead holder).
pub fn list() -> Result<(), Error> {
    let root = pods_root();
    let mut rows: Vec<(String, usize, bool)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&root) {
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let alive = holder_pid(&name).is_some();
            // Members = shared-hosts lines beyond the two localhost seeds.
            let members = std::fs::read_to_string(hosts_path(&name))
                .map(|b| {
                    b.lines()
                        .filter(|l| l.contains('\t'))
                        .count()
                        .saturating_sub(2)
                })
                .unwrap_or(0);
            rows.push((name, members, alive));
        }
    }
    rows.sort();
    if rows.is_empty() {
        println!("no pods — create one with `kern pod create <name>`");
        return Ok(());
    }
    let p = crate::ui::Palette::detect();
    println!(
        "{d}{:<24} {:>7}  STATUS{z}",
        "POD",
        "BOXES",
        d = p.d,
        z = p.z
    );
    for (name, members, alive) in &rows {
        let status = if *alive { "up" } else { "dead" };
        println!("{}{}{:<24}{} {:>7}  {status}", p.b, p.c, name, p.z, members);
    }
    Ok(())
}

/// Does this `/proc/<pid>/comm` belong to the `pasta`/`passt` family? passt re-execs into an
/// ISA-optimized variant, so `comm` is `pasta.avx2` (or `passt.avx512`, …) — never the bare `pasta`.
/// Matching by family prefix is what keeps the teardown's PID-reuse check from silently leaking the
/// NAT daemon (the bug where `comm == "pasta"` never matched → pasta survived every `pod rm`).
fn is_pasta_comm(comm: &str) -> bool {
    comm.starts_with("pasta") || comm.starts_with("passt")
}

/// Tear a pod down: kill its pasta NAT daemon (verified by PID + `comm` family prefix), then its holder, then wipe
/// its state dir. Returns `(existed, member_count)`. Silent — callers do the messaging so `pod rm`
/// and `compose down` can each say the right thing. Member boxes keep their own (already-joined)
/// namespaces until they exit; only the holder is freed.
pub fn teardown(name: &str) -> (bool, usize) {
    let dir = pod_dir(name);
    if !dir.is_dir() {
        return (false, 0);
    }
    // Kill pasta FIRST, while the holder still owns the net ns — so its recorded PID is unambiguously
    // pasta (killing the holder frees the ns → pasta auto-exits → PID-reuse window). Verify via comm
    // (pasta runs in the HOST net ns, so the holder's ns-inode guard can't cover it).
    let holder = holder_pid(name);
    if holder.is_some() {
        if let Ok(pp) = std::fs::read_to_string(dir.join("pasta.pid")) {
            if let Ok(pp) = pp.trim().parse::<i32>() {
                let is_pasta = std::fs::read_to_string(format!("/proc/{pp}/comm"))
                    .map(|c| is_pasta_comm(c.trim()))
                    .unwrap_or(false);
                if is_pasta {
                    unsafe { libc::kill(pp, libc::SIGTERM) };
                }
            }
        }
    }
    if let Some(pid) = holder {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    // Members = shared-hosts entries beyond the two localhost seeds.
    let members = std::fs::read_to_string(hosts_path(name))
        .map(|b| {
            b.lines()
                .filter(|l| l.contains('\t'))
                .count()
                .saturating_sub(2)
        })
        .unwrap_or(0);
    let _ = std::fs::remove_dir_all(&dir);
    (true, members)
}

/// `kern pod rm <name>` — tear the pod down; still-running member boxes keep going until they exit.
pub fn remove(names: &[String]) -> Result<(), Error> {
    if names.is_empty() {
        return Err(Error::Usage("pod rm <name>..."));
    }
    for name in names {
        let (existed, members) = teardown(name);
        if !existed {
            eprintln!("kern: no pod named '{name}'");
            continue;
        }
        println!("removed pod '{name}'");
        if members > 0 {
            println!("  ({members} member box(es) keep running until they exit; `kern stop` them)");
        }
    }
    Ok(())
}

/// `kern __pod-holder` (hidden): become the pod's namespace holder — never returns.
pub fn run_holder() -> ! {
    kern_isolation::run_pod_holder()
}

/// Pod names share the box-name charset (used as a directory + hostnames): `[A-Za-z0-9_.-]`, ≤64,
/// no traversal. Rejects anything that could escape `pods/` or corrupt `/etc/hosts`.
fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        || name.starts_with('.')
    {
        return Err(Error::Sandbox(format!(
            "invalid pod name '{name}' (use letters, digits, '_', '-', '.'; max 64)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_names_reject_traversal_and_bad_chars() {
        for ok in ["web", "my-app", "db_1", "v1.2"] {
            assert!(validate_name(ok).is_ok(), "{ok} should be valid");
        }
        for bad in [
            "",
            "../evil",
            "a/b",
            ".hidden",
            "has space",
            &"x".repeat(65),
        ] {
            assert!(validate_name(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn pasta_comm_matches_isa_variants_not_strangers() {
        // Regression: the teardown once compared `comm == "pasta"` and never matched the real
        // `pasta.avx2`, so the NAT daemon leaked on every `pod rm` / `compose down`.
        for ok in [
            "pasta",
            "passt",
            "pasta.avx2",
            "passt.avx512",
            "pasta.avx2\n".trim(),
        ] {
            assert!(is_pasta_comm(ok), "{ok} should match the pasta family");
        }
        for no in ["bash", "sleep", "kern", "past", "asta", "", "pas"] {
            assert!(!is_pasta_comm(no), "{no} must NOT match");
        }
    }

    #[test]
    fn starter_alive_false_for_dead_or_absent() {
        // A cleaned-up temp dir with no `starting` marker → not alive.
        let dir = std::env::temp_dir().join(format!("kern-pod-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        assert!(!starter_alive(&dir), "no marker → not alive");
        // A marker naming an impossible pid → not alive (kill(pid,0) fails).
        std::fs::write(dir.join("starting"), "2147483646").unwrap();
        assert!(!starter_alive(&dir), "dead/absent pid → not alive");
        // Our own live pid, bare (back-compat marker) → alive.
        let me = std::process::id();
        std::fs::write(dir.join("starting"), me.to_string()).unwrap();
        assert!(starter_alive(&dir), "our live bare pid → alive");
        // `pid:starttime` with the CORRECT start-time → alive (the winner's real marker).
        let st = crate::registry::proc_starttime(me as i32);
        std::fs::write(dir.join("starting"), format!("{me}:{st}")).unwrap();
        assert!(
            starter_alive(&dir),
            "live pid + matching start-time → alive"
        );
        // Same live pid but a WRONG start-time → treated as a reused pid → not a live starter.
        std::fs::write(dir.join("starting"), format!("{me}:{}", st.wrapping_add(1))).unwrap();
        assert!(
            !starter_alive(&dir),
            "start-time mismatch → reused pid → not alive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
