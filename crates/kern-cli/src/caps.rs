//! `--cap-add` / `--cap-drop` - resolve capability names to a [`kern_isolation::CapSpec`].
//!
//! kern always drops a baseline of never-needed dangerous caps (module load, raw I/O, BPF, …). These
//! flags layer on top, Docker-style: `--cap-drop CAP` drops one more (or `ALL` for everything),
//! `--cap-add CAP` keeps one that would otherwise be dropped (add wins over drop). Names are matched
//! case-insensitively with or without the `CAP_` prefix; an unknown name is a hard error (so a typo
//! can't silently leave a cap in place).

use crate::error::Error;

/// The standard Linux capability names → kernel-stable numbers (`<linux/capability.h>`, 0..=40).
const CAP_TABLE: &[(&str, u32)] = &[
    ("CHOWN", 0),
    ("DAC_OVERRIDE", 1),
    ("DAC_READ_SEARCH", 2),
    ("FOWNER", 3),
    ("FSETID", 4),
    ("KILL", 5),
    ("SETGID", 6),
    ("SETUID", 7),
    ("SETPCAP", 8),
    ("LINUX_IMMUTABLE", 9),
    ("NET_BIND_SERVICE", 10),
    ("NET_BROADCAST", 11),
    ("NET_ADMIN", 12),
    ("NET_RAW", 13),
    ("IPC_LOCK", 14),
    ("IPC_OWNER", 15),
    ("SYS_MODULE", 16),
    ("SYS_RAWIO", 17),
    ("SYS_CHROOT", 18),
    ("SYS_PTRACE", 19),
    ("SYS_PACCT", 20),
    ("SYS_ADMIN", 21),
    ("SYS_BOOT", 22),
    ("SYS_NICE", 23),
    ("SYS_RESOURCE", 24),
    ("SYS_TIME", 25),
    ("SYS_TTY_CONFIG", 26),
    ("MKNOD", 27),
    ("LEASE", 28),
    ("AUDIT_WRITE", 29),
    ("AUDIT_CONTROL", 30),
    ("SETFCAP", 31),
    ("MAC_OVERRIDE", 32),
    ("MAC_ADMIN", 33),
    ("SYSLOG", 34),
    ("WAKE_ALARM", 35),
    ("BLOCK_SUSPEND", 36),
    ("AUDIT_READ", 37),
    ("PERFMON", 38),
    ("BPF", 39),
    ("CHECKPOINT_RESTORE", 40),
];

/// The highest cap number in [`CAP_TABLE`] - used to expand `--cap-add ALL`.
const CAP_MAX: u32 = 40;

/// Resolve one capability name (case-insensitive, optional `CAP_` prefix) to its number.
fn cap_num(name: &str) -> Option<u32> {
    let n = name.trim();
    let n = n
        .strip_prefix("CAP_")
        .or_else(|| n.strip_prefix("cap_"))
        .unwrap_or(n);
    CAP_TABLE
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(n))
        .map(|(_, v)| *v)
}

fn unknown(kind: &str, name: &str) -> Error {
    Error::Sandbox(format!(
        "unknown capability '{name}' in --cap-{kind} (e.g. NET_ADMIN, SYS_PTRACE, or ALL)"
    ))
}

/// Build a [`kern_isolation::CapSpec`] from the raw `--cap-add`/`--cap-drop` strings. `ALL` is
/// accepted in either (`--cap-drop ALL` drops everything; `--cap-add ALL` keeps everything). An
/// unknown name is rejected. Returns the default spec (drop only the dangerous baseline) when both
/// lists are empty.
pub fn resolve(adds: &[String], drops: &[String]) -> Result<kern_isolation::CapSpec, Error> {
    let mut spec = kern_isolation::CapSpec::default();
    for d in drops {
        if d.eq_ignore_ascii_case("ALL") {
            spec.drop_all = true;
        } else {
            spec.drops
                .push(cap_num(d).ok_or_else(|| unknown("drop", d))?);
        }
    }
    for a in adds {
        if a.eq_ignore_ascii_case("ALL") {
            spec.adds.extend(0..=CAP_MAX); // keep every known cap
        } else {
            spec.adds.push(cap_num(a).ok_or_else(|| unknown("add", a))?);
        }
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_resolve_case_and_prefix_insensitive() {
        assert_eq!(cap_num("NET_ADMIN"), Some(12));
        assert_eq!(cap_num("cap_net_admin"), Some(12));
        assert_eq!(cap_num("Sys_Ptrace"), Some(19));
        assert_eq!(cap_num("nope"), None);
    }

    #[test]
    fn resolve_add_drop_and_all() {
        let s = resolve(&["NET_ADMIN".into()], &["SYS_PTRACE".into()]).unwrap();
        assert!(!s.drop_all);
        assert_eq!(s.drops, vec![19]);
        assert_eq!(s.adds, vec![12]);

        let s = resolve(&[], &["ALL".into()]).unwrap();
        assert!(s.drop_all);

        let s = resolve(&["ALL".into()], &[]).unwrap();
        assert_eq!(s.adds, (0..=CAP_MAX).collect::<Vec<_>>());
    }

    #[test]
    fn unknown_name_is_rejected() {
        assert!(resolve(&[], &["FLUX_CAPACITOR".into()]).is_err());
        assert!(resolve(&["WARP_DRIVE".into()], &[]).is_err());
    }
}
