//! Unit tests for `commands`, moved out of `mod.rs` so the module that implements every verb is
//! not also the file that holds their tests. Nothing here changed in the move except `crate::commands::`,
//! which now names one level further out (`crate::commands`) because the parent of these modules
//! is this file rather than `mod.rs`.
//!
//! A child module still reaches its ancestors' private items, so the tests assert on exactly the
//! internals they did before, without widening one item's visibility.

#[cfg(test)]
mod image_user_resolution_tests {
    use crate::commands::*;

    /// A box's `config.User` given by NAME (e.g. memcached's `USER memcache`) must resolve to the image's
    /// own uid/gid the way Docker does - reading the rootfs's `/etc/passwd`/`/etc/group` - not silently
    /// run as box root. This is the fix for the class that killed memcached, unprivileged nginx, etc.
    #[test]
    fn resolves_user_name_uid_gid_group_and_numerics_from_the_image() {
        let root = std::env::temp_dir().join(format!("kern-usr-{}", std::process::id()));
        let etc = root.join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(
            etc.join("passwd"),
            "root:x:0:0:root:/root:/bin/sh\nmemcache:x:11211:11211:Memcached:/:/sbin/nologin\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("group"),
            "root:x:0:\nstaff:x:50:\nmemcache:x:11211:\n",
        )
        .unwrap();
        let lower = root.to_string_lossy();

        // bare NAME -> uid AND its passwd primary gid (Docker's rule).
        assert_eq!(resolve_image_user("memcache", &lower), Some((11211, 11211)));
        // NAME:groupname -> uid from passwd, gid from group (overrides the passwd gid).
        assert_eq!(
            resolve_image_user("memcache:staff", &lower),
            Some((11211, 50))
        );
        // NAME:numericgid, and a fully-numeric spec, both parse without the files.
        assert_eq!(resolve_image_user("memcache:99", &lower), Some((11211, 99)));
        assert_eq!(resolve_image_user("root", &lower), Some((0, 0)));
        assert_eq!(resolve_image_user("1000:1000", &lower), Some((1000, 1000)));
        // A name the image does NOT define -> None, so the caller keeps box-root with an honest note.
        assert_eq!(resolve_image_user("ghost", &lower), None);
        assert_eq!(resolve_image_user("memcache:nogroup", &lower), None);
        // No account files at all (a scratch image) -> None, never a wrong uid.
        let empty = std::env::temp_dir().join(format!("kern-usr-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(
            resolve_image_user("memcache", &empty.to_string_lossy()),
            None
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// The lookup walks an overlay `top:…:base` chain and the TOP-most layer that carries the file wins,
    /// the way the merged rootfs would present it.
    #[test]
    fn top_layer_of_an_overlay_chain_wins() {
        let base = std::env::temp_dir().join(format!("kern-usr-base-{}", std::process::id()));
        let top = std::env::temp_dir().join(format!("kern-usr-top-{}", std::process::id()));
        std::fs::create_dir_all(base.join("etc")).unwrap();
        std::fs::create_dir_all(top.join("etc")).unwrap();
        std::fs::write(base.join("etc/passwd"), "app:x:1000:1000::/:/bin/sh\n").unwrap();
        std::fs::write(top.join("etc/passwd"), "app:x:2000:2000::/:/bin/sh\n").unwrap();
        // chain is "top:base"; top's entry (2000) is authoritative.
        let chain = format!("{}:{}", top.to_string_lossy(), base.to_string_lossy());
        assert_eq!(resolve_image_user("app", &chain), Some((2000, 2000)));

        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&top);
    }

    /// A hostile image whose account file is a symlink OUT of the rootfs must NOT resolve against host
    /// paths - `image_account_field` reads pre-pivot on the host, so an unconfined read would follow the
    /// link. Confinement returns `None` (caller keeps box-root), even though the escape target defines the
    /// name.
    #[test]
    fn a_passwd_symlink_escaping_the_rootfs_does_not_resolve() {
        let root = std::env::temp_dir().join(format!("kern-usr-esc-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("kern-usr-esc-target-{}", std::process::id()));
        std::fs::create_dir_all(root.join("etc")).unwrap();
        // The victim account lives OUTSIDE the rootfs; the image's /etc/passwd is a symlink to it.
        std::fs::write(&outside, "victim:x:1234:1234::/:/bin/sh\n").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("etc/passwd")).unwrap();
        // Unconfined this would return Some((1234, 1234)); confined it must be None.
        assert_eq!(resolve_image_user("victim", &root.to_string_lossy()), None);

        // An IN-rootfs symlink (a real distro layout) still resolves - its target stays under the layer.
        std::fs::remove_file(root.join("etc/passwd")).unwrap();
        std::fs::write(root.join("etc/passwd.real"), "app:x:777:777::/:/bin/sh\n").unwrap();
        std::os::unix::fs::symlink("passwd.real", root.join("etc/passwd")).unwrap();
        assert_eq!(
            resolve_image_user("app", &root.to_string_lossy()),
            Some((777, 777))
        );

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside);
    }
}

#[cfg(test)]
mod scope_ceiling_tests {
    use crate::commands::*;

    /// The scope's ceiling is always ABOVE the box's own, and never wraps.
    ///
    /// Equal ceilings would silently undo the reason the box has an inner cgroup at all: the outer one
    /// is reached first, by the supervisor's share, so the box dies of the SCOPE's OOM - which kills
    /// the supervisor too and leaves `kern wait` with nothing to report. That was the measured defect
    /// on all three ARM boards. A `--memory` near `u64::MAX` must saturate, not wrap: wrapping would
    /// hand systemd a tiny `MemoryMax` and OOM every box instantly.
    #[test]
    fn the_scope_ceiling_is_above_the_boxs_own_and_saturates() {
        let head = kern_isolation::SCOPE_SUPERVISOR_HEADROOM;
        assert!(head > 0, "a zero headroom is the equal-ceilings bug");
        for asked in [1, 4096, 64 * 1024 * 1024, 8 * 1024 * 1024 * 1024] {
            assert_eq!(
                scope_memory_max(Some(asked)),
                asked + head,
                "the scope must clear the box's own cap by exactly the headroom"
            );
        }
        assert_eq!(
            scope_memory_max(None),
            SCOPE_MEMORY_MAX_BYTES + head,
            "a box with no --memory takes the default cap, plus the same headroom"
        );
        assert_eq!(
            scope_memory_max(Some(u64::MAX)),
            u64::MAX,
            "an absurd --memory must saturate at the ceiling, never wrap to a tiny one"
        );
        assert!(
            scope_memory_max(Some(u64::MAX - 1)) >= u64::MAX - 1,
            "saturation must never LOWER the ceiling below what was asked"
        );
    }
}

#[cfg(test)]
mod strip_ansi_tests {
    /// `strip_ansi` must remove the whole escape sequence, not just its ESC byte.
    ///
    /// This is the test that was missing, and its absence cost a shipped feature. `kern <verb>
    /// --help` filters the reference by matching on de-coloured lines; the first implementation
    /// called `ui::scrub` and then `replace`d the palette strings, but scrub removes the ESC first,
    /// so `[1m` survived as printable text and every `replace` searched for a sequence that was no
    /// longer present. Nothing matched, the filter fell back to the full 161-line page, and a
    /// terminal user got exactly the wall the feature existed to remove.
    ///
    /// The integration test could not see it: `Command::output()` captures stdout, stdout is then
    /// not a tty, the palette is empty, and with an empty palette the broken code is correct. So the
    /// assertion lives here, on the function, with the colour codes written out.
    #[test]
    fn strip_ansi_removes_whole_sequences_not_just_the_escape_byte() {
        let e = '\u{1b}';
        let cases: [(String, &str); 6] = [
            (format!("{e}[1mOPTIONS for box:{e}[0m"), "OPTIONS for box:"),
            (format!("    {e}[36mbox{e}[0m <name>"), "    box <name>"),
            (format!("{e}[38;5;208mtruecolor{e}[0m"), "truecolor"),
            ("no escapes at all".to_string(), "no escapes at all"),
            (format!("{e}(Bplain"), "plain"),
            ("tab\there".to_string(), "tabhere"),
        ];
        for (input, want) in cases {
            let got = crate::commands::strip_ansi(&input);
            assert_eq!(
                got, want,
                "strip_ansi({input:?}) gave {got:?}; a leftover `[1m` is indistinguishable from \
                 content and makes every match fail"
            );
            assert!(
                !got.contains('['),
                "strip_ansi left a `[` behind in {got:?}: the sequence was cut at the ESC only"
            );
        }
    }
}

#[cfg(test)]
mod ps_exited_tests {
    use crate::commands::*;

    fn dead(name: &str, code: i32, pod: &str) -> registry::ExitedBox {
        registry::ExitedBox {
            name: name.to_string(),
            pid: 42,
            starttime: 1000,
            code,
            pod: pod.to_string(),
            command: "python app.py".to_string(),
            exited_ago: 5,
        }
    }

    /// An exited box renders through the SAME `--format` engine as a live one: `.Status` is
    /// `exited (<code>)` and `.RunningFor` is "how long ago", so `kern ps -a --format` is complete.
    #[test]
    fn exited_box_renders_through_ps_format() {
        let e = dead("web", 7, "stack");
        assert_eq!(
            render_ps_format("{{.Names}} {{.Status}} {{.Pod}} {{.RunningFor}}", &e, 0).unwrap(),
            "web exited (7) stack 5s ago"
        );
        // No live rootfs/ports on a dead box - they render empty, not a stale value.
        assert_eq!(
            render_ps_format("[{{.Image}}{{.Ports}}]", &e, 0).unwrap(),
            "[]"
        );
    }

    /// The exited filter mirrors `ps_matches`: `status=exited|dead` accept it, `status=running`
    /// rejects it, `name` is a substring, `pod` is exact, and `label=` (not retained) matches nothing.
    #[test]
    fn exited_matches_honours_the_filter_keys() {
        let e = dead("mystack-db", 1, "mystack");
        assert!(exited_matches(&e, &[("status".into(), "exited".into())]));
        // kern has no `dead` state, so `status=dead` matches nothing (like `created`/`running`).
        assert!(!exited_matches(&e, &[("status".into(), "dead".into())]));
        assert!(!exited_matches(&e, &[("status".into(), "running".into())]));
        assert!(exited_matches(&e, &[("pod".into(), "mystack".into())]));
        assert!(!exited_matches(&e, &[("pod".into(), "mystac".into())]));
        assert!(exited_matches(&e, &[("name".into(), "db".into())]));
        assert!(exited_matches(&e, &[("id".into(), "42".into())]));
        assert!(!exited_matches(&e, &[("label".into(), "k=v".into())]));
        // AND semantics: one non-matching clause fails the whole filter.
        assert!(!exited_matches(
            &e,
            &[
                ("pod".into(), "mystack".into()),
                ("name".into(), "web".into())
            ]
        ));
    }
}

#[cfg(test)]
mod seccomp_resolution_tests {
    use crate::commands::{resolve_seccomp_mode, SecurityProfile};
    use crate::error::Error;
    use kern_isolation::SeccompFilter;
    use std::ffi::OsStr;

    fn ok(env: Option<&OsStr>, p: Option<SecurityProfile>) -> SeccompFilter {
        resolve_seccomp_mode(env, p).expect("resolve should succeed")
    }

    #[test]
    fn explicit_env_wins_then_profile_then_default_no_env_mutation() {
        // No env, no profile: the shipped default is the ALLOWLIST (deny-by-default). Pinned to the
        // concrete variant, not `SeccompFilter::default()`, so an accidental flip of the default is
        // caught here instead of passing tautologically.
        assert_eq!(ok(None, None), SeccompFilter::Allowlist);
        // Profile untrusted, no env: allowlist.
        assert_eq!(
            ok(None, Some(SecurityProfile::Untrusted)),
            SeccompFilter::Allowlist
        );
        // Explicit env WINS over the profile, even to weaken it (the documented precedence).
        assert_eq!(
            ok(
                Some(OsStr::new("denylist")),
                Some(SecurityProfile::Untrusted)
            ),
            SeccompFilter::Denylist
        );
        // Explicit `allowlist-audit` (LESS strict than the profile's allowlist: it logs-and-runs) also
        // wins - "explicit wins" is unconditional, by design.
        assert_eq!(
            ok(
                Some(OsStr::new("allowlist-audit")),
                Some(SecurityProfile::Untrusted)
            ),
            SeccompFilter::AllowlistAudit
        );
        assert_eq!(
            ok(Some(OsStr::new("allowlist")), None),
            SeccompFilter::Allowlist
        );
        // Exported-but-blank counts as unset, so it falls through to the profile.
        assert_eq!(
            ok(Some(OsStr::new("")), Some(SecurityProfile::Untrusted)),
            SeccompFilter::Allowlist
        );
    }

    #[test]
    fn a_malformed_explicit_value_fails_loud_it_does_not_downgrade_the_profile() {
        // A SET-but-unrecognised `KERN_SECCOMP` is a usage error, NOT a silent fall to the default that
        // would downgrade a `--security-profile untrusted` box from allowlist to denylist while it still
        // advertises `untrusted`. With and without the profile, the outcome is an error naming the var.
        for p in [None, Some(SecurityProfile::Untrusted)] {
            let err = resolve_seccomp_mode(Some(OsStr::new("allowlist-audi")), p).unwrap_err();
            assert!(
                matches!(&err, Error::Usage(m) if m.contains("KERN_SECCOMP")),
                "a typo'd KERN_SECCOMP must be a usage error naming the var, got {err:?}"
            );
        }
        assert!(resolve_seccomp_mode(Some(OsStr::new("bogus")), None).is_err());
    }

    #[test]
    fn a_non_utf8_value_fails_loud_it_does_not_silently_default() {
        // A non-UTF-8 `KERN_SECCOMP` cannot be a valid token, so it must be a usage error, NOT a silent
        // fall to the default that (under `--security-profile untrusted`) would downgrade the box while
        // it still advertises `untrusted`. `to_str()` returns None for invalid UTF-8, and the fail-loud
        // branch catches it exactly like a typo'd ASCII value - same class, verified here.
        use std::os::unix::ffi::OsStrExt;
        let bad = OsStr::from_bytes(b"\xff\xfe\x00nope"); // invalid UTF-8, non-empty
        for p in [None, Some(SecurityProfile::Untrusted)] {
            let err = resolve_seccomp_mode(Some(bad), p).unwrap_err();
            assert!(
                matches!(&err, Error::Usage(m) if m.contains("KERN_SECCOMP")),
                "a non-UTF-8 KERN_SECCOMP must be a usage error, got {err:?}"
            );
        }
    }
}

#[cfg(test)]
mod limit_policy_tests {
    use crate::commands::resolve_limit_policy;
    use crate::error::Error;

    #[test]
    fn require_and_allow_resolve_from_flag_or_env_and_conflict_on_resolved_values() {
        // Neither: best-effort, no conflict.
        assert_eq!(
            resolve_limit_policy(false, false, false, false).ok(),
            Some((false, false))
        );
        // require via flag; via env; both - all resolve to (true, false).
        assert_eq!(
            resolve_limit_policy(true, false, false, false).ok(),
            Some((true, false))
        );
        assert_eq!(
            resolve_limit_policy(false, true, false, false).ok(),
            Some((true, false))
        );
        assert_eq!(
            resolve_limit_policy(true, true, false, false).ok(),
            Some((true, false))
        );
        // allow via flag; via env.
        assert_eq!(
            resolve_limit_policy(false, false, true, false).ok(),
            Some((false, true))
        );
        assert_eq!(
            resolve_limit_policy(false, false, false, true).ok(),
            Some((false, true))
        );

        // The four contradictory combinations a flag-only parse check would MISS: flag+flag,
        // flag(require)+env(allow), env(require)+flag(allow), env+env. Every one must be rejected.
        for (rf, re, af, ae) in [
            (true, false, true, false),
            (true, false, false, true),
            (false, true, true, false),
            (false, true, false, true),
        ] {
            let err = resolve_limit_policy(rf, re, af, ae).unwrap_err();
            assert!(
                matches!(&err, Error::Usage(m)
                    if m.contains("mutually exclusive") && m.contains("KERN_")),
                "combination ({rf},{re},{af},{ae}) must be a usage error naming the env vars, got {err:?}"
            );
        }
    }
}

#[cfg(test)]
mod scope_ready_fd_tests {
    use crate::commands::ready_fd_to_signal;
    use std::ffi::OsStr;

    #[test]
    fn honours_a_real_fd_only_as_the_genuine_scope_reexec() {
        // A legitimate scope re-exec: KERN_SCOPE set + a real non-std fd.
        assert_eq!(ready_fd_to_signal(true, Some(OsStr::new("7"))), Some(7));
        assert_eq!(ready_fd_to_signal(true, Some(OsStr::new("  9 "))), Some(9));
        // trimmed
    }

    #[test]
    fn refuses_the_marker_without_the_scope_reexec() {
        // KERN_SCOPE NOT set: a `KERN_SCOPE_READY_FD` planted in the environment by any caller is
        // ignored, so kern never writes to / closes an fd on an env var's say-so alone.
        assert_eq!(ready_fd_to_signal(false, Some(OsStr::new("7"))), None);
        assert_eq!(ready_fd_to_signal(false, Some(OsStr::new("1"))), None);
        assert_eq!(ready_fd_to_signal(false, None), None);
    }

    #[test]
    fn never_touches_the_std_streams_or_a_malformed_value() {
        // fds 0/1/2 (stdin/stdout/stderr) are refused even under a genuine re-exec: writing a stray byte
        // to or closing kern's own std streams would corrupt its output. Malformed / out-of-range values
        // are refused too, never defaulting to some fd.
        for bad in [
            "0",
            "1",
            "2",
            "-1",
            "abc",
            "",
            "  ",
            "99999999999999999999",
            "7x",
            "0x7",
        ] {
            assert_eq!(
                ready_fd_to_signal(true, Some(OsStr::new(bad))),
                None,
                "value {bad:?} must not resolve to a signalable fd"
            );
        }
        // non-UTF-8 value: refused, not a panic.
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(
            ready_fd_to_signal(true, Some(OsStr::from_bytes(b"\xff\x37"))),
            None
        );
        assert_eq!(ready_fd_to_signal(true, None), None);
    }
}

#[cfg(test)]
mod uncapped_notice_tests {
    /// The uncapped-host notice fires exactly ONCE per host, and keeps firing when it cannot record
    /// that it fired.
    ///
    /// A `Once` is per PROCESS and every box is a new process, so the per-process guard alone put
    /// this line on every single box start. That noise is why the warning was gated on an explicit
    /// `--memory` instead, which in turn left a DEFAULT box on a non-delegating host running with
    /// unbounded RAM in silence. The marker is what lets the notice be both quiet and honest.
    #[test]
    fn the_uncapped_host_notice_is_claimed_once() {
        let dir = std::env::temp_dir().join(format!("kern-notice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("uncapped-notice");

        // First call creates the parent chain and claims it; every later call declines.
        assert!(
            crate::commands::claim_notice_at(&path),
            "the first call did not claim the notice, so a host would never be told"
        );
        assert!(
            path.exists(),
            "the marker was not written, so the claim cannot be remembered across processes"
        );
        for i in 0..5 {
            assert!(
                !crate::commands::claim_notice_at(&path),
                "call {} claimed the notice again: the line would repeat on every box start",
                i + 2
            );
        }

        // Unwritable location: fail LOUD. An unbounded box is worth a repeated line more than it is
        // worth silence, so a path that can never be created must keep returning true.
        let refused = std::path::Path::new("/proc/self/cannot-create-here/marker");
        assert!(
            crate::commands::claim_notice_at(refused) && crate::commands::claim_notice_at(refused),
            "an unwritable marker silenced the notice instead of repeating it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod ps_format_tests {
    use crate::commands::push_unescaped;

    #[test]
    fn unescape_t_n_and_keep_others() {
        let mut o = String::new();
        push_unescaped(&mut o, "a\\tb\\nc");
        assert_eq!(o, "a\tb\nc");
        let mut o = String::new();
        push_unescaped(&mut o, "plain text");
        assert_eq!(o, "plain text");
        let mut o = String::new();
        push_unescaped(&mut o, "trailing\\");
        assert_eq!(o, "trailing\\");
        let mut o = String::new();
        push_unescaped(&mut o, "\\x kept");
        assert_eq!(o, "\\x kept");
    }
}

#[cfg(test)]
mod image_size_is_memoised {
    use crate::commands::{dir_size, dir_size_cached};

    /// `kern images` walked every byte of the cache on every call: 43 ms on a 2.6 GB cache of 53
    /// images, for a number that cannot have changed, since an extracted image is immutable once its
    /// `.ok` sentinel is written. Memoised against that sentinel's mtime it is 2.2 ms.
    ///
    /// The test asserts the two things that make the cache safe rather than merely fast: it returns
    /// the SAME value as the walk, and a changed stamp makes it recompute instead of serving a stale
    /// total. A cache that is only checked for speed is how a wrong size ships.
    #[test]
    fn memoised_size_matches_the_walk_and_reacts_to_a_new_stamp() {
        let root = std::env::temp_dir().join(format!("kern-sz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("img");
        std::fs::create_dir_all(dir.join("sub")).expect("mkdir");
        std::fs::write(dir.join("a"), vec![0u8; 1000]).expect("write");
        std::fs::write(dir.join("sub/b"), vec![0u8; 2000]).expect("write");
        let stamp = root.join("img.ok");
        std::fs::write(&stamp, b"ref").expect("stamp");

        let walked = dir_size(&dir);
        assert_eq!(walked, 3000, "the walk itself must be right first");
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            walked,
            "cold read matches the walk"
        );
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            walked,
            "warm read matches too"
        );

        // Grow the tree WITHOUT touching the stamp file: the cache is entitled to keep serving the old
        // total. This is the INVARIANT the function documents - nothing writes into an image
        // directory after its sentinel exists - and the test pins it rather than pretending the cache
        // can detect a change it is not keyed on.
        std::fs::write(dir.join("c"), vec![0u8; 500]).expect("write");
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            walked,
            "same stamp, same answer: the cache is keyed on the stamp, not on a guess"
        );

        // A sentinel rewritten to a DIFFERENT LENGTH inside the same second must still invalidate:
        // mtime alone left `kern rmi x && kern pull x` able to serve the old image's size.
        std::fs::write(&stamp, b"a-longer-reference").expect("restamp same second");
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            3500,
            "a sentinel of a different size must force a recompute even within one second"
        );

        // Rewrite the stamp, as a re-pull does, and the size must be recomputed.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::write(&stamp, b"ref2").expect("restamp");
        assert_eq!(
            dir_size_cached(&dir, &stamp),
            3500,
            "a new stamp must force a recompute"
        );

        let _ = crate::commands::remove_tree_forced(&root);
    }
}

#[cfg(test)]
mod gc_clears_read_only_image_dirs {
    use crate::commands::remove_tree_forced;

    /// An extracted OCI image ships read-only directories with their original modes, and unlinking a
    /// child needs WRITE on its parent, so `std::fs::remove_dir_all` stops at the first one with
    /// EACCES. `rm -rf` leaves the tree too, but reports it and exits 1. That is why `kern gc --images` had never cleared
    /// a cache containing alpine (whose `/proc` is `r-xr-xr-x`): 62 such directories sat in the one on
    /// this machine. Asserted BOTH ways, so the test cannot pass for the wrong reason if the fix is
    /// reverted: the standard call must FAIL on this fixture first.
    #[test]
    fn forced_removal_deletes_what_remove_dir_all_cannot() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("kern-rtf-{}", std::process::id()));
        let _ = crate::commands::remove_tree_forced(&root);
        let ro = root.join("img/proc");
        std::fs::create_dir_all(&ro).expect("mkdir");
        std::fs::write(ro.join("kmsg"), b"x").expect("write");
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).expect("chmod");

        assert!(
            std::fs::remove_dir_all(root.join("img")).is_err(),
            "remove_dir_all unexpectedly succeeded - the fixture no longer reproduces the bug"
        );

        remove_tree_forced(&root).expect("forced removal");
        assert!(!root.exists(), "the tree must be gone");
    }
}

#[cfg(test)]
mod logs_tail_tests {
    use crate::commands::tail_lines;

    #[test]
    fn tail_lines_counts_and_boundaries() {
        assert_eq!(tail_lines(b"a\nb\nc\n", 2), b"b\nc\n");
        assert_eq!(tail_lines(b"a\nb\nc\n", 1), b"c\n");
        assert_eq!(tail_lines(b"a\nb\nc", 2), b"b\nc"); // no trailing newline
        assert_eq!(tail_lines(b"a\nb\nc\n", 5), b"a\nb\nc\n"); // fewer lines than n
        assert_eq!(tail_lines(b"only\n", 3), b"only\n");
    }

    #[test]
    fn tail_lines_edge_cases() {
        assert_eq!(tail_lines(b"", 3), b"");
        assert_eq!(tail_lines(b"a\nb\n", 0), b"");
        assert_eq!(tail_lines(b"no newline", 1), b"no newline");
        assert_eq!(tail_lines(b"x\n", 1), b"x\n");
    }

    // The bounded backward-seek reader must return exactly what `tail_lines` would over the whole
    // file, including across multiple 8 KiB chunks, without a trailing newline, and on an empty file.
    #[test]
    fn tail_file_matches_tail_lines() {
        use crate::commands::tail_file;
        let path = std::env::temp_dir().join(format!("kern-tailfile-{}", std::process::id()));
        let check = |content: &[u8], n: usize| {
            std::fs::write(&path, content).unwrap();
            let mut f = std::fs::File::open(&path).unwrap();
            assert_eq!(
                tail_file(&mut f, n).unwrap(),
                tail_lines(content, n),
                "len={} n={n}",
                content.len()
            );
        };
        // Multi-chunk (> 8192 B) so the backward loop runs several iterations, trailing newline.
        let mut big = Vec::new();
        for i in 0..5000 {
            big.extend_from_slice(format!("line {i}\n").as_bytes());
        }
        for &n in &[0usize, 1, 3, 50, 5000, 9999, usize::MAX] {
            check(&big, n);
        }
        // Multi-chunk WITHOUT a trailing newline (the `> n` trailing-nl edge across chunk seams).
        let mut big_no_nl = big.clone();
        assert_eq!(big_no_nl.pop(), Some(b'\n'));
        for &n in &[1usize, 3, 5000, usize::MAX] {
            check(&big_no_nl, n);
        }
        check(
            &{
                let mut e = vec![b'x'; 8191];
                e.push(b'\n');
                e
            },
            1,
        ); // exactly one CHUNK (8192 B): last backward read lands on pos == 0
        check(b"\n\n\n", 2); // only newlines
        check(b"\n\n\n", usize::MAX);
        check(b"alpha\nbeta\ngamma", 2); // single chunk, no trailing nl
        check(b"", 3); // empty
        check(b"solo", 1); // one line, no newline
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod commit_tests {
    use crate::commands::*;

    #[test]
    fn unescape_mountinfo_decodes_octal_and_leaves_plain_paths() {
        // Plain paths (the common case) pass through untouched.
        assert_eq!(unescape_mountinfo("/proc"), "/proc");
        assert_eq!(unescape_mountinfo("/mnt/vol"), "/mnt/vol");
        assert_eq!(unescape_mountinfo("/"), "/");
        // mountinfo octal-escapes space (\040), tab (\011), newline (\012), backslash (\134).
        assert_eq!(unescape_mountinfo("/mnt/my\\040vol"), "/mnt/my vol");
        assert_eq!(unescape_mountinfo("/a\\134b"), "/a\\b");
        // A lone backslash not starting a 3-octal escape is preserved verbatim (never panics).
        assert_eq!(unescape_mountinfo("/a\\b"), "/a\\b");
        assert_eq!(unescape_mountinfo("/end\\"), "/end\\");
    }
}

#[cfg(test)]
mod net_resource_tests {
    use crate::commands::*;

    fn inst(name: &str, pid: i32, pod: &str) -> registry::Instance {
        registry::Instance {
            name: name.to_string(),
            pid,
            pid1: 0,
            rootfs: String::new(),
            command: String::new(),
            started: 0,
            starttime: 0,
            ports: String::new(),
            volumes: String::new(),
            pod: pod.to_string(),
            workdir: String::new(),
            egress: String::new(),
            landlock_rw: String::new(),
            memory_max: None,
            pids_max: None,
            labels: String::new(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: String::new(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        }
    }

    #[test]
    fn ref_matches_name_pid_and_pod_with_name_winning() {
        let web = inst("web", 100, "myapp");
        let db = inst("db", 101, "myapp");
        let live: std::collections::HashSet<String> =
            ["web", "db"].into_iter().map(String::from).collect();
        // by exact NAME
        assert!(ref_matches(&web, "web", &live));
        assert!(!ref_matches(&db, "web", &live));
        // by POD name - selects every member of the pod
        assert!(ref_matches(&web, "myapp", &live));
        assert!(ref_matches(&db, "myapp", &live));
        // by PID (as a string) when no live box bears that exact name
        assert!(ref_matches(&web, "100", &live));
        assert!(!ref_matches(&web, "101", &live));
        // NAME WINS: a ref equal to a live box name never falls through to the pid/pod branch - so a
        // box literally named "web" can't sweep a same-named pod, and a numeric name isn't shadowed.
        let numname = inst("100", 999, "grp");
        let live2: std::collections::HashSet<String> =
            ["100"].into_iter().map(String::from).collect();
        assert!(ref_matches(&numname, "100", &live2)); // matches by its NAME…
        let other = inst("x", 100, "grp"); // …and NOT by a coincidental pid == that name
        assert!(!ref_matches(&other, "100", &live2));
    }

    #[test]
    fn ref_matches_empty_ref_never_sweeps_standalone_boxes() {
        // A standalone box has pod == "". An empty ref (`kern stop ""`) must NOT match it via the pod
        // branch - otherwise one stray empty argument would stop/pause every standalone box at once.
        let empty = std::collections::HashSet::new();
        let solo = inst("solo", 7, "");
        assert!(!ref_matches(&solo, "", &empty));
        // …and an empty ref also can't match a real pod member (there's no pod named "").
        let member = inst("m", 8, "realpod");
        assert!(!ref_matches(&member, "", &empty));
    }

    #[test]
    fn matching_refs_dedups_a_box_selected_by_both_its_name_and_pod() {
        // `kern stop web mypod` where box `web` is a member of `mypod`: the box matches TWO refs but
        // must appear once (else stop would kill -SIGKILL a pid twice / double-print).
        let running = vec![inst("web", 10, "mypod"), inst("db", 11, "mypod")];
        let sel = boxes_matching_refs(running, &["web".into(), "mypod".into()]);
        assert_eq!(
            sel.len(),
            2,
            "web selected by name AND pod must not duplicate"
        );
        let names: Vec<&str> = sel.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["web", "db"]);
    }

    #[test]
    fn a_box_named_like_a_pod_wins_over_the_pod_members() {
        // NAME-wins across the whole ref: a standalone box literally named `web` coexisting with a pod
        // also named `web` → `kern stop web` selects ONLY the standalone box, never the pod's members
        // (the pod branch is gated off whenever a live box bears that exact name).
        let running = vec![
            inst("web", 20, ""),      // standalone box literally named "web"
            inst("api", 21, "web"),   // a DIFFERENT box that belongs to a pod named "web"
            inst("cache", 22, "web"), // another member of pod "web"
        ];
        let sel = boxes_matching_refs(running, &["web".into()]);
        let names: Vec<&str> = sel.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["web"], "name wins; pod members are not swept");
    }

    #[test]
    fn matching_refs_selects_two_pods_and_a_loose_name_together() {
        // `kern stop p1 p2 loner` sweeps every member of both pods plus the standalone - one pass,
        // stable order, no cross-contamination between pods.
        let running = vec![
            inst("a1", 30, "p1"),
            inst("b1", 31, "p2"),
            inst("a2", 32, "p1"),
            inst("loner", 33, ""),
            inst("c", 34, "p3"), // untouched
        ];
        let sel = boxes_matching_refs(running, &["p1".into(), "p2".into(), "loner".into()]);
        let mut names: Vec<&str> = sel.iter().map(|b| b.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["a1", "a2", "b1", "loner"]);
    }

    #[test]
    fn brackets_outside_quotes_ignores_strings() {
        // Deep validate audit: a `[`/`]` inside a string value must NOT count toward the multi-line
        // array balance - else `name = "has ] bracket"` would spuriously open/close an array and make
        // the validator silently skip the following lines.
        assert_eq!(brackets_outside_quotes("pins = [1, 2, 3]"), (1, 1)); // real array
        assert_eq!(brackets_outside_quotes(r#"name = "has ] bracket""#), (0, 0)); // ] in string
        assert_eq!(brackets_outside_quotes(r#"x = "[ open only""#), (0, 0)); // [ in string
        assert_eq!(brackets_outside_quotes("pins = ["), (1, 0)); // multi-line array open
        assert_eq!(brackets_outside_quotes("]"), (0, 1)); // multi-line array close
        assert_eq!(brackets_outside_quotes(r#"a = '][' single"#), (0, 0)); // single-quoted
    }

    #[test]
    fn run_leading_dashdash_is_not_reclassified_as_a_profile() {
        // Hacker-mode regression: `kern run -- vcpu:heavy prog` - the `--` end-of-options contract means
        // `vcpu:heavy` is the literal command, NOT a profile to peel. peel_run_profiles must skip the
        // leading `--` and return start=1 without applying any profile.
        fn empty() -> AppliedProfiles {
            AppliedProfiles {
                memory: None,
                cpus: None,
                cpuset: None,
                nice: None,
                vgpio: Vec::new(),
                vdisk: Vec::new(),
            }
        }
        let cmd = vec![
            "--".to_string(),
            "vcpu:heavy".to_string(),
            "prog".to_string(),
        ];
        let mut out = empty();
        // Must NOT error on a (possibly non-existent) profile name, and must start the command at 1
        // (right after the `--`), leaving `vcpu:heavy prog` as the literal argv.
        let start = peel_run_profiles(&cmd, None, &mut out).unwrap();
        assert_eq!(start, 1);
        assert!(out.cpuset.is_none() && out.cpus.is_none() && out.memory.is_none());
        assert_eq!(&cmd[start..], ["vcpu:heavy", "prog"]);
    }

    #[test]
    fn parse_volumes_guards_targets() {
        // `parse_volumes` resolves the registry root from the process-global `XDG_RUNTIME_DIR`; hold
        // `TEST_ENV_LOCK` so a sibling test flipping that var under /tmp can't make `/tmp` look like an
        // ancestor of the (relocated) registry root and spuriously refuse a valid `-v`.
        let _env = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Bad targets are rejected before any mount.
        for bad in [
            "data:mnt",        // relative
            "data:/../escape", // traversal
            "data:/proc",      // shadows the box's proc
            "data:/sys",
            "data:/dev",
            "data:/",      // over the whole rootfs
            "data:/./x",   // dot component
            "data://proc", // leading-double-slash bypass - resolves to /proc at mount time
            "data://sys",
            "data://dev",
            "data:///dev", // triple slash too
            "data://dev/", // trailing slash after the bypass
        ] {
            assert!(
                parse_volumes(&[bad.into()]).is_err(),
                "should reject -v {bad}"
            );
        }
        // A subpath of an essential mount is allowed (use an existing host source to stay hermetic).
        assert!(
            parse_volumes(&["/tmp:/dev/foo".into()]).is_ok(),
            "a subpath like /dev/foo must be allowed"
        );
        assert!(parse_volumes(&["/tmp:/data".into()]).is_ok());
    }

    #[test]
    fn a_volume_source_that_resolves_onto_the_registry_is_refused_in_every_form() {
        // The anti-forgery gate canonicalizes the source BEFORE the overlap check, so every path form
        // that RESOLVES onto a trust-bearing registry dir - trailing slash, `.`/`..`, a symlink, or the
        // PARENT that contains it - must be refused, not just the exact literal. A test on the literal
        // alone would leave the equivalent forms unproven (adversarial review, final round). Each must
        // fail with the OVERLAP message, not a source-not-found error, so the dirs are materialized
        // first.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-forgegate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // Canonicalize the base so a symlinked `/tmp` (rare, but real on some systems) can't make the
        // PARENT-form comparison inconsistent with what `parse_volumes` canonicalizes.
        let tmp = std::fs::canonicalize(&tmp).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);

        // Materialize instances/claims/exit so `canonicalize` of the forms below succeeds. Production
        // resolves the identity set non-creatingly, so the test must create the dirs explicitly.
        crate::registry::materialize_authoritative_dirs_for_test();
        assert!(
            !crate::registry::trusted_state_dirs().is_empty(),
            "registry state dirs were created"
        );
        let kern = tmp.join("kern");
        std::os::unix::fs::symlink(&kern, tmp.join("link")).unwrap();
        std::fs::create_dir_all(tmp.join("kern-other")).unwrap();

        let refused = |src: String| -> bool {
            parse_volumes(&[format!("{src}:/r")])
                .err()
                .map(|e| {
                    e.to_string()
                        .contains("refusing to mount the kern registry")
                })
                .unwrap_or(false)
        };
        let t = tmp.to_string_lossy().into_owned();
        for form in [
            format!("{t}/kern"),              // the exact dir
            format!("{t}/kern/"),             // trailing slash
            format!("{t}/./kern"),            // a `.` component
            format!("{t}/kern/../kern"),      // a `..` round-trip
            format!("{t}/kern/instances/.."), // `..` out of a subdir
            format!("{t}/kern/instances"),    // a trust-bearing subdir directly
            format!("{t}/kern/claims"),       // and another
            format!("{t}/kern/waitexit"), // the `ps -a` breadcrumb dir (forgeable exited records)
            format!("{t}/link"),          // a symlink resolving onto the registry
            t.clone(),                    // the PARENT that contains kern/
        ] {
            assert!(refused(form.clone()), "must refuse -v source {form}");
        }
        // PARAMETRIZED on the production list: every dir `trusted_state_dirs()` protects must be refused
        // directly. So a dir added there (as `waitexit/` was) is auto-covered here instead of needing a
        // new literal above - the literal list drifting from production is the exact gap that let
        // `waitexit/` ship unprotected.
        for d in crate::registry::trusted_state_dirs() {
            assert!(
                refused(d.to_string_lossy().into_owned()),
                "must refuse trusted state dir {d:?}"
            );
        }
        // A sibling that merely shares a name prefix stays mountable.
        assert!(
            parse_volumes(&[format!("{t}/kern-other:/r")]).is_ok(),
            "a sibling of the registry must stay mountable"
        );

        std::env::remove_var("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn cp_save_write_guard_follows_a_symlink_into_the_registry() {
        // `kern cp box:/x <dst>` / `kern save -o <dst>` write via `File::create`, which FOLLOWS a symlink
        // at `dst`. A parent-only check let a symlink final component (in a safe dir, pointing at the
        // registry) redirect the write onto a peer's posture record - a real forgery bypass. The guard
        // must follow the link to where the write LANDS. Covers a direct link, a link to a not-yet-existing
        // registry path, and a two-hop chain; a link to a safe target stays writable.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-wguard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let tmp = std::fs::canonicalize(&tmp).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &tmp);
        crate::registry::materialize_authoritative_dirs_for_test();

        let safe = tmp.join("safe");
        std::fs::create_dir_all(&safe).unwrap();
        let instances = tmp.join("kern/instances");
        std::fs::write(instances.join("rec"), b"posture").unwrap();

        let g =
            |p: &std::path::Path| crate::secret::guard_host_write_path(&p.to_string_lossy(), "cp");
        // direct symlink onto an existing registry record
        let l1 = safe.join("l1");
        std::os::unix::fs::symlink(instances.join("rec"), &l1).unwrap();
        assert!(
            g(&l1).is_err(),
            "symlink onto a registry record must be refused"
        );
        // symlink onto a NOT-yet-existing registry path (write would CREATE it)
        let l2 = safe.join("l2");
        std::os::unix::fs::symlink(instances.join("newrec"), &l2).unwrap();
        assert!(
            g(&l2).is_err(),
            "symlink onto a new registry path must be refused"
        );
        // two-hop chain -> record
        let l3 = safe.join("l3");
        std::os::unix::fs::symlink(&l1, &l3).unwrap();
        assert!(
            g(&l3).is_err(),
            "a symlink chain into the registry must be refused"
        );
        // a symlink onto a SAFE target stays writable (target in `safe/`, NOT the runtime dir root -
        // that dir is an ANCESTOR of the registry and refused by design), and a plain safe path too
        let good = safe.join("good");
        std::os::unix::fs::symlink(safe.join("target.txt"), &good).unwrap();
        assert!(
            g(&good).is_ok(),
            "a symlink to a safe target must stay writable"
        );
        assert!(
            g(&safe.join("plain.txt")).is_ok(),
            "an ordinary path must stay writable"
        );

        std::env::remove_var("XDG_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn parse_tmpfs_guards_hardened_mounts_incl_double_slash() {
        for bad in [
            "/proc",
            "/sys",
            "/dev",      // exact hardened roots
            "/proc/foo", // under a hardened root
            "//proc",
            "//sys",
            "//dev", // leading-double-slash bypass
            "///dev/x",
        ] {
            assert!(
                parse_tmpfs(&[bad.into()]).is_err(),
                "should reject --tmpfs {bad}"
            );
        }
        // A normal tmpfs path is fine.
        assert!(parse_tmpfs(&["/scratch".into()]).is_ok());
        assert!(parse_tmpfs(&["/var/cache:64m".into()]).is_ok());
    }

    #[test]
    fn image_command_resolution() {
        let img = kern_oci::ImageConfig {
            entrypoint: vec!["docker-entrypoint.sh".into()],
            cmd: vec!["redis-server".into()],
            ..Default::default()
        };
        // No user command → entrypoint + image Cmd.
        assert_eq!(
            resolve_image_command(&[], false, &img),
            vec!["docker-entrypoint.sh", "redis-server"]
        );
        // User command → entrypoint + user command (image Cmd dropped, docker-style).
        assert_eq!(
            resolve_image_command(&["redis-cli".into()], false, &img),
            vec!["docker-entrypoint.sh", "redis-cli"]
        );
        // --ssh + no command → keep-alive, ignore the image command.
        assert_eq!(
            resolve_image_command(&[], true, &img),
            vec!["sleep", "infinity"]
        );
        // No image config + no command → a shell (the --rootfs / bare case).
        let empty = kern_oci::ImageConfig::default();
        assert_eq!(
            resolve_image_command(&[], false, &empty),
            vec![DEFAULT_SHELL]
        );
        // No image config + user command → the user command unchanged.
        assert_eq!(
            resolve_image_command(&["echo".into(), "hi".into()], false, &empty),
            vec!["echo", "hi"]
        );
    }

    #[test]
    fn restart_policy_parses_docker_names_only() {
        assert_eq!(RestartPolicy::parse("no"), Some(RestartPolicy::No));
        assert_eq!(
            RestartPolicy::parse("on-failure"),
            Some(RestartPolicy::OnFailure)
        );
        assert_eq!(RestartPolicy::parse("always"), Some(RestartPolicy::Always));
        assert_eq!(
            RestartPolicy::parse("unless-stopped"),
            Some(RestartPolicy::UnlessStopped)
        );
        // Unknown tokens don't parse - so a bare `--restart` won't swallow the next arg/command.
        assert_eq!(RestartPolicy::parse("sh"), None);
        assert_eq!(RestartPolicy::parse("--memory"), None);
        assert_eq!(RestartPolicy::parse(""), None);
        // Only always/unless-stopped are reboot-persistent (→ a systemd unit).
        assert!(RestartPolicy::Always.persistent() && RestartPolicy::UnlessStopped.persistent());
        assert!(!RestartPolicy::OnFailure.persistent() && !RestartPolicy::No.persistent());
    }

    #[test]
    fn systemd_quote_neutralizes_expansion_and_quoting() {
        // Plain arg is just wrapped.
        assert_eq!(systemd_quote("alpine"), "\"alpine\"");
        // `$` and `%` (systemd env/specifier expansion) are doubled so they stay literal.
        assert_eq!(systemd_quote("echo $(date +%s)"), "\"echo $$(date +%%s)\"");
        // Embedded quotes/backslashes are C-escaped so the ExecStart line stays parseable.
        assert_eq!(systemd_quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    /// `WORKDIR /app` + `COPY . .` is the shape most application Dockerfiles have, and joining the
    /// relative dot destination onto the workdir built `/app/.`, which `cp` cannot create. The
    /// neighbours that DID work are pinned too, because they are why the bug survived: `COPY . /app`
    /// and `COPY main.py .` both went down other paths.
    ///
    /// `..` must come out UNTOUCHED. Resolving it here would silently convert an escape that
    /// `sanitize_rootfs_rel` rejects into one it never sees.
    #[test]
    fn a_dot_destination_collapses_but_dotdot_survives_for_the_guard() {
        assert_eq!(collapse_dot_segments("/app/."), "/app");
        assert_eq!(collapse_dot_segments("/a/b/c/."), "/a/b/c");
        assert_eq!(collapse_dot_segments("/app/./sub"), "/app/sub");
        assert_eq!(collapse_dot_segments("//app//sub//"), "/app/sub");
        assert_eq!(collapse_dot_segments("/app"), "/app");
        // A destination that reduces to nothing is the rootfs itself, not the empty string.
        assert_eq!(collapse_dot_segments("/."), "/");
        assert_eq!(collapse_dot_segments("/"), "/");
        // Left for the guard to refuse, never resolved here.
        assert_eq!(collapse_dot_segments("/app/.."), "/app/..");
        assert_eq!(collapse_dot_segments("/../../etc"), "/../../etc");
        assert!(sanitize_rootfs_rel("..", &collapse_dot_segments("/app/..")[1..]).is_err());
    }

    #[test]
    fn sanitize_ref_is_traversal_free_and_collision_free() {
        // No `.`/`/`/`:` survive → a `..` ref can't build a `cache/..` traversal.
        for r in ["..", ".", "../../etc", "a/../b"] {
            let s = sanitize_ref(r);
            assert!(
                !s.contains('/') && s != ".." && s != "." && !s.split('-').any(|p| p == ".."),
                "{r} → {s} still looks traversal-ish"
            );
        }
        // Distinct refs that used to collapse together now differ (the hash suffix).
        assert_ne!(sanitize_ref("foo/bar"), sanitize_ref("foo_bar"));
        assert_ne!(sanitize_ref("alpine:3.19"), sanitize_ref("alpine:3_19"));
        // Same ref → same key (stable cache).
        assert_eq!(sanitize_ref("redis:alpine"), sanitize_ref("redis:alpine"));
    }

    #[test]
    fn layer_cache_key_helpers() {
        // Deterministic + chained: same inputs → same key; a changed repr OR a changed parent key
        // → different key (so a change busts this layer and everything after it).
        let k0 = layer_key("base", "RUN a");
        assert_eq!(k0, layer_key("base", "RUN a"));
        assert_ne!(k0, layer_key("base", "RUN b")); // repr changed
        assert_ne!(k0, layer_key("other", "RUN a")); // parent key changed
        assert_eq!(k0.len(), 32); // 128-bit hex
                                  // chain_lower stacks top (last) first, base (first) last - overlayfs shadow order.
        assert_eq!(
            chain_lower(&["base".into(), "l1".into(), "l2".into()]),
            "l2:l1:base"
        );
    }

    #[test]
    fn content_hash_changes_with_content() {
        let d = format!("/tmp/.kern-ch-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(format!("{d}/a"), b"one").unwrap();
        let p = std::path::Path::new(&d);
        let h1 = content_hash(p, p, None);
        assert_eq!(h1, content_hash(p, p, None)); // stable
        std::fs::write(format!("{d}/a"), b"two").unwrap();
        assert_ne!(h1, content_hash(p, p, None)); // content changed
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn content_hash_respects_dockerignore() {
        // An ignored file must NOT contribute to the key (mirrors what COPY actually keeps): editing
        // `secret.env` when `.dockerignore` excludes it leaves the key unchanged, and a real file does
        // change it. Guards the cache-correctness + don't-hash-ignored-bytes fix.
        let d = format!("/tmp/.kern-chi-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(format!("{d}/.dockerignore"), b"secret.env\nnode_modules\n").unwrap();
        std::fs::write(format!("{d}/app.txt"), b"code").unwrap();
        std::fs::write(format!("{d}/secret.env"), b"KEY=1").unwrap();
        std::fs::create_dir_all(format!("{d}/node_modules/x")).unwrap();
        std::fs::write(format!("{d}/node_modules/x/big"), b"junk").unwrap();
        let p = std::path::Path::new(&d);
        let ig = crate::dockerignore::DockerIgnore::load(p);
        assert!(ig.is_some(), "the .dockerignore should load");
        let base = content_hash(p, p, ig.as_ref());
        // Changing an IGNORED file leaves the key unchanged.
        std::fs::write(format!("{d}/secret.env"), b"KEY=changed").unwrap();
        std::fs::write(format!("{d}/node_modules/x/big"), b"junk-changed").unwrap();
        assert_eq!(
            base,
            content_hash(p, p, ig.as_ref()),
            "ignored change must not bust"
        );
        // Changing a KEPT file does bust the key.
        std::fs::write(format!("{d}/app.txt"), b"code2").unwrap();
        assert_ne!(
            base,
            content_hash(p, p, ig.as_ref()),
            "kept change must bust"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn clamp_cpuset_narrows_overwide_pins() {
        // Host CPU count (same source as the fn) - the test is host-agnostic.
        let host = std::fs::read_to_string("/proc/cpuinfo")
            .map(|t| t.lines().filter(|l| l.starts_with("processor")).count())
            .unwrap_or(1)
            .max(1);
        let max = host - 1;
        // An over-wide range is capped to the host's max CPU (never a raw `0-9999`).
        let want = if max == 0 {
            "0".to_string()
        } else {
            format!("0-{max}")
        };
        assert_eq!(
            clamp_cpuset(Some("0-9999".into()))
                .ok()
                .flatten()
                .as_deref(),
            Some(want.as_str())
        );
        // An in-range single is untouched; `None` passes through.
        assert_eq!(
            clamp_cpuset(Some("0".into())).ok().flatten().as_deref(),
            Some("0")
        );
        assert!(clamp_cpuset(None).ok().flatten().is_none());
        // Nothing in the list exists here → REFUSED, not passed through. This used to return the
        // original on the reasoning that the backend would reject it loudly; measured on a 28-CPU
        // machine, `--cpuset-cpus 28` reached systemd, applied nothing, printed nothing and exited 0
        // with the process free to use every CPU. A cap that cannot be applied must not silently
        // become no cap.
        let err = clamp_cpuset(Some("9999".into())).expect_err("an impossible pin must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("9999"),
            "the message must quote the request, got {msg}"
        );
        assert!(
            msg.contains("Refusing"),
            "the message must say it refused, got {msg}"
        );
        // The off-by-one is the case that actually mattered: one past the last CPU.
        assert!(
            clamp_cpuset(Some(host.to_string())).is_err(),
            "CPU index {host} does not exist on a {host}-CPU host and must be refused"
        );
        // ... while the last real CPU is accepted untouched, so the refusal is not over-broad.
        assert_eq!(
            clamp_cpuset(Some(max.to_string()))
                .ok()
                .flatten()
                .as_deref(),
            Some(max.to_string().as_str())
        );
        // A partially-valid list still clamps to the valid part rather than refusing.
        assert_eq!(
            clamp_cpuset(Some(format!("0,{host}")))
                .ok()
                .flatten()
                .as_deref(),
            Some("0")
        );
    }

    #[test]
    fn flat_image_key_is_content_addressed_and_ignore_aware() {
        // Guards the flat-build cache key: content-addressed (a changed Dockerfile / copied file busts
        // it → never a stale image) yet ignore-aware (an ignored file's change does NOT bust it).
        use crate::dockerfile::Instr;
        let d = format!("/tmp/.kern-fk-{}", std::process::id());
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(format!("{d}/node_modules")).unwrap();
        std::fs::write(format!("{d}/app.txt"), b"v1").unwrap();
        std::fs::write(format!("{d}/secret.env"), b"S").unwrap();
        std::fs::write(format!("{d}/node_modules/big"), b"junk").unwrap();
        std::fs::write(format!("{d}/.dockerignore"), b"node_modules\nsecret.env\n").unwrap();
        let ctx = std::path::Path::new(&d);
        let ig = crate::dockerignore::DockerIgnore::load(ctx);
        let instrs = vec![
            Instr::From {
                image: "scratch".into(),
                as_name: None,
            },
            Instr::Copy {
                srcs: vec![".".into()],
                dst: "/app".into(),
                from: None,
                chmod: None,
            },
        ];
        let key = |c: &std::path::Path| flat_image_key("base", &instrs, c, c, ig.as_ref());
        let k0 = key(ctx);
        assert_eq!(k0, key(ctx), "stable across calls");
        // Changing an IGNORED file must NOT move the key.
        std::fs::write(format!("{d}/secret.env"), b"CHANGED").unwrap();
        std::fs::write(format!("{d}/node_modules/big"), b"CHANGED").unwrap();
        assert_eq!(k0, key(ctx), "ignored change must not move the key");
        // Changing a KEPT file MUST move the key.
        std::fs::write(format!("{d}/app.txt"), b"v2").unwrap();
        assert_ne!(k0, key(ctx), "kept change must move the key");
        // A different instruction set (different dst) MUST move the key even with identical files.
        let instrs2 = vec![
            Instr::From {
                image: "scratch".into(),
                as_name: None,
            },
            Instr::Copy {
                srcs: vec![".".into()],
                dst: "/other".into(),
                from: None,
                chmod: None,
            },
        ];
        assert_ne!(
            key(ctx),
            flat_image_key("base", &instrs2, ctx, ctx, ig.as_ref()),
            "different instructions → different key"
        );
        // A different base lower MUST move the key.
        assert_ne!(
            key(ctx),
            flat_image_key("base2", &instrs, ctx, ctx, ig.as_ref()),
            "different base → different key"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn compose_pod_name_is_stable_unique_and_safe() {
        let ok = |n: &str| {
            !n.is_empty()
                && !n.starts_with('.')
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        // Stable for the same path (so `up` and `down` agree) and always a valid pod name.
        let n = compose_pod_name("/srv/myapp/compose.yaml");
        assert_eq!(n, compose_pod_name("/srv/myapp/compose.yaml"));
        assert!(ok(&n) && n.starts_with("myapp-"), "dir-based + valid: {n}");
        // Two same-named compose files in DIFFERENT dirs → DIFFERENT pods (no cross-stack collision).
        assert_ne!(
            compose_pod_name("/srv/a/compose.yaml"),
            compose_pod_name("/srv/b/compose.yaml")
        );
        // Odd/empty stems still produce a valid name (base falls back, hash suffix appended).
        assert!(ok(&compose_pod_name("compose.yaml")));
        assert!(ok(&compose_pod_name("....")));
    }

    #[test]
    fn run_batching_helpers() {
        // Only the shell form is batchable.
        assert_eq!(
            run_shell_script(&["/bin/sh".into(), "-c".into(), "echo hi".into()]),
            Some("echo hi")
        );
        assert_eq!(run_shell_script(&["node".into(), "app.js".into()]), None);
        // Single quoting is `'\''`-safe.
        assert_eq!(shell_quote_single("a'b"), "'a'\\''b'");
        // A single script isn't re-wrapped.
        assert_eq!(
            combine_run_scripts(&["echo hi"]),
            vec!["/bin/sh", "-c", "echo hi"]
        );
        // Multiple scripts → each in its own subshell, `&&`-chained (fail-fast) and quoting-safe.
        assert_eq!(
            combine_run_scripts(&["a", "it's b"]),
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "/bin/sh -c 'a' && /bin/sh -c 'it'\\''s b'".to_string(),
            ]
        );
    }

    #[test]
    fn image_config_sidecar_round_trips() {
        let c = kern_oci::ImageConfig {
            entrypoint: vec!["/entry".into()],
            cmd: vec!["-c".into(), "run".into()],
            env: vec!["A=1".into(), "B=2".into()],
            workdir: Some("/app".into()),
            user: Some("1000:1000".into()),
            exposed_ports: vec![(80, false), (53, true)],
        };
        let dir = std::env::temp_dir().join(format!("kern-imgcfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("x.image");
        write_image_config(&f, &c).expect("write the config sidecar");
        // A write that cannot happen must be reported, not discarded. The sidecar used to be written
        // with `let _ =`, so an image could be cached and announced ready with no entrypoint, no env
        // and no user, and the box silently fell back to a shell. Forced here with a path whose
        // parent does not exist, which fails on every filesystem.
        assert!(
            write_image_config(&dir.join("no-such-dir").join("x.image"), &c).is_err(),
            "an unwritable config sidecar must be an error, not a silent no-op"
        );
        let r = read_image_config(&f);
        assert_eq!(r.entrypoint, c.entrypoint);
        assert_eq!(r.cmd, c.cmd);
        assert_eq!(r.env, c.env);
        assert_eq!(r.workdir, c.workdir);
        assert_eq!(r.user, c.user);
        assert_eq!(
            r.exposed_ports, c.exposed_ports,
            "the image's EXPOSE (used by the pod port-collision warning) must survive the sidecar"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostname_validation() {
        assert_eq!(validate_hostname(None).unwrap(), None);
        assert_eq!(
            validate_hostname(Some("my-box.1")).unwrap().as_deref(),
            Some("my-box.1")
        );
        for bad in [
            "-lead",
            "trail-",
            ".dot",
            "has/slash",
            "sp ace",
            &"x".repeat(65),
        ] {
            assert!(
                validate_hostname(Some(bad)).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn tmpfs_parse_and_blocked_mounts() {
        assert_eq!(
            parse_tmpfs(&["/scratch:64M".into()]).unwrap(),
            vec![("/scratch".to_string(), "64m".to_string())]
        );
        // No size → empty (kernel default).
        assert_eq!(
            parse_tmpfs(&["/cache".into()]).unwrap(),
            vec![("/cache".to_string(), String::new())]
        );
        // Hardened mounts and their subpaths are refused; so are relative/`..` paths and bad sizes.
        for bad in [
            "/proc",
            "/sys/kernel",
            "/dev",
            "/dev/shm",
            "relative",
            "/a/../b",
            "/x:huge",
        ] {
            assert!(
                parse_tmpfs(&[bad.to_string()]).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn user_parse() {
        assert_eq!(parse_user(None).unwrap(), None);
        assert_eq!(parse_user(Some("1000")).unwrap(), Some((1000, 1000)));
        assert_eq!(parse_user(Some("1000:2000")).unwrap(), Some((1000, 2000)));
        for bad in ["alice", "1000:bob", ":5", "1000:"] {
            assert!(parse_user(Some(bad)).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn tag_ref_cannot_escape_the_cache() {
        // `tag`'s path safety rests entirely on `sanitize_ref`: a traversal ref must map to a key with
        // no `/` and no `..`, so `cache.join(key)` can never land outside the cache. Lock that here so a
        // future edit to sanitize_ref can't silently reopen a `tag ../../etc/x` escape.
        for evil in [
            "../../etc/passwd",
            "/etc/shadow",
            "a/../../b",
            "..",
            ".",
            "foo:../bar",
        ] {
            let key = sanitize_ref(evil);
            assert!(
                !key.contains('/'),
                "key for {evil:?} has a separator: {key}"
            );
            assert!(!key.contains(".."), "key for {evil:?} has `..`: {key}");
            // The join stays inside the cache root (no parent-dir component escapes it).
            let joined = std::path::Path::new("/cache/kern").join(&key);
            assert!(
                joined.starts_with("/cache/kern"),
                "{evil:?} → {joined:?} escaped the cache"
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn merged_view_honours_opaque_no_secret_resurrection() {
        // REGRESSION for the opaque-dir leak: two stacked layers where an UPPER layer made `/app` opaque
        // (`rm -rf /app && mkdir /app`, marked by `user.overlay.opaque`) and a LOWER layer holds a secret
        // `/app/token`. Reading the merged view (`merged_view_extract`) must NOT resurrect the secret -
        // the kernel applies the opaque, so `/app/token` is gone and only the upper's `marker` remains.
        // A naive raw-layer walk (the old fast-path) leaked the secret here.
        let base = std::env::temp_dir().join(format!("kern-mvbase-{}", std::process::id()));
        let top = std::env::temp_dir().join(format!("kern-mvtop-{}", std::process::id()));
        let out = std::env::temp_dir().join(format!("kern-mvout-{}", std::process::id()));
        for d in [&base, &top, &out] {
            let _ = std::fs::remove_dir_all(d);
        }
        std::fs::create_dir_all(base.join("app")).unwrap();
        std::fs::write(base.join("app/token"), b"SECRET_MUST_NOT_RESURFACE").unwrap();
        std::fs::create_dir_all(top.join("app")).unwrap();
        std::fs::write(top.join("app/marker"), b"public").unwrap();
        std::fs::create_dir_all(&out).unwrap();
        // Mark the top's `/app` opaque. In a userns-owned overlay kern mounts WITHOUT `userxattr`, so the
        // kernel reads `trusted.overlay.opaque`; but a plain test process can only set `user.overlay.*`.
        // We therefore skip if we can't establish the opaque (CI without the privilege) rather than pass
        // vacuously - the real guarantee is exercised end-to-end by the build tests.
        let set_trusted = std::process::Command::new("setfattr")
            .args(["-n", "trusted.overlay.opaque", "-v", "y"])
            .arg(top.join("app"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !set_trusted {
            let _ = std::fs::remove_dir_all(&base);
            let _ = std::fs::remove_dir_all(&top);
            let _ = std::fs::remove_dir_all(&out);
            eprintln!(
                "skip: cannot set trusted.overlay.opaque (needs privilege); covered by build e2e"
            );
            return;
        }
        // chain is top-first: [top, base].
        let chain = vec![
            top.to_string_lossy().into_owned(),
            base.to_string_lossy().into_owned(),
        ];
        let r = merged_view_extract(&chain, Some("/app"), &out);
        // The copy of `/app` must succeed and contain ONLY `marker` - never the opaque-hidden `token`.
        assert!(r.is_ok(), "merged_view_extract failed: {r:?}");
        assert!(
            out.join("app/marker").exists(),
            "public marker should be copied"
        );
        assert!(
            !out.join("app/token").exists(),
            "SECRET RESURRECTED: the opaque-hidden token must not appear in the merged copy"
        );
        for d in [&base, &top, &out] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    #[test]
    fn copy_from_stage_cannot_escape_the_source_stage() {
        // The `COPY --from` security guard: a source that resolves (via `..` or a planted symlink)
        // OUTSIDE the source stage's rootfs must be rejected, exactly like a hostile context COPY. We
        // build a fake stage rootfs with a symlink to `/` and confirm a copy THROUGH it is refused.
        let stage = std::env::temp_dir().join(format!("kern-fromtest-{}", std::process::id()));
        let dest = std::env::temp_dir().join(format!("kern-fromdest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(stage.join("etc")).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(stage.join("etc/ok.txt"), b"in-stage").unwrap();
        // A legit in-stage copy succeeds.
        assert!(copy_from_stage_rootfs(&stage, "/etc/ok.txt", &dest).is_ok());
        assert!(dest.join("ok.txt").exists());
        // A `..` escape and a symlink-to-root escape are both refused (canonicalize + starts_with).
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/", stage.join("rootlink")).unwrap();
            let via_symlink = copy_from_stage_rootfs(&stage, "/rootlink/etc/hostname", &dest);
            assert!(
                via_symlink.is_err(),
                "a symlink-to-/ in the stage must not let a COPY --from escape"
            );
        }
        let via_dotdot = copy_from_stage_rootfs(&stage, "/etc/../../../../etc/passwd", &dest);
        assert!(via_dotdot.is_err(), "a `..` escape must be refused");
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    #[cfg(unix)]
    fn copy_from_stage_preserves_inner_symlinks_no_follow() {
        // The double-copy escape class (reviewer 2a): copying a DIR out of a stage that CONTAINS an
        // absolute symlink to a host file must PRESERVE the symlink (cp -a no-follow), never dereference
        // it and copy the host file's bytes at build time. The symlink resolves only later, inside the
        // box, against the box's own rootfs - so a `→ /etc/passwd` reads the box's passwd, not the host's.
        let stage = std::env::temp_dir().join(format!("kern-sym-{}", std::process::id()));
        let dest = std::env::temp_dir().join(format!("kern-symdst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(stage.join("app")).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(stage.join("app/real.txt"), b"real").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", stage.join("app/evil")).unwrap();
        // Copy the whole `app` dir out - succeeds, and `evil` arrives as a SYMLINK, not the host file.
        assert!(copy_from_stage_rootfs(&stage, "/app", &dest).is_ok());
        let copied = dest.join("app/evil");
        let meta = std::fs::symlink_metadata(&copied).expect("evil should exist");
        assert!(
            meta.file_type().is_symlink(),
            "the inner symlink must be preserved as a symlink, not dereferenced to the host file"
        );
        assert_eq!(
            std::fs::read_link(&copied).unwrap(),
            std::path::Path::new("/etc/passwd"),
            "the symlink target must be verbatim, resolved only inside the box at run"
        );
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    #[cfg(unix)]
    fn copy_from_stage_preserves_relative_symlink_no_host_read() {
        // Reviewer 2a residual vector: a RELATIVE symlink inside a copied dir whose target ESCAPES the
        // stage rootfs (many `..` → a host file). It must arrive as a verbatim symlink, its host target
        // NEVER read at build time (canary check), and stay dangling once inside the box. This is the
        // one case the absolute-symlink test didn't exercise; `cp -a` is no-follow so it's preserved.
        let stage = std::env::temp_dir().join(format!("kern-rel-{}", std::process::id()));
        let dest = std::env::temp_dir().join(format!("kern-reldst-{}", std::process::id()));
        let canary = std::env::temp_dir().join(format!("kern-rel-canary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(stage.join("sub")).unwrap();
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(&canary, b"HOST-SECRET-DO-NOT-LEAK").unwrap();
        // A relative symlink with enough `..` to reach the canary if it were ever followed.
        let rel_target = format!("../../../../../../../../..{}", canary.display());
        std::os::unix::fs::symlink(&rel_target, stage.join("sub/rellink")).unwrap();
        assert!(copy_from_stage_rootfs(&stage, "/sub", &dest).is_ok());
        let copied = dest.join("sub/rellink");
        let meta = std::fs::symlink_metadata(&copied).expect("rellink should exist");
        assert!(
            meta.file_type().is_symlink(),
            "the relative symlink must be preserved, not dereferenced"
        );
        // The link target is verbatim (relative), and the canary's CONTENT never entered the copy tree.
        assert_eq!(
            std::fs::read_link(&copied).unwrap().to_string_lossy(),
            rel_target
        );
        // Walk the whole copied tree: no file may contain the host secret's bytes (nothing dereferenced).
        fn contains_secret(p: &std::path::Path) -> bool {
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    let ep = e.path();
                    let ft = match std::fs::symlink_metadata(&ep) {
                        Ok(m) => m.file_type(),
                        Err(_) => continue,
                    };
                    if ft.is_symlink() {
                        continue; // never follow - the whole point
                    } else if ft.is_dir() {
                        if contains_secret(&ep) {
                            return true;
                        }
                    } else if let Ok(b) = std::fs::read(&ep) {
                        if b.windows(11).any(|w| w == b"HOST-SECRET") {
                            return true;
                        }
                    }
                }
            }
            false
        }
        assert!(
            !contains_secret(&dest),
            "the host canary's bytes must NEVER appear in the copied tree (no build-time deref)"
        );
        let _ = std::fs::remove_dir_all(&stage);
        let _ = std::fs::remove_dir_all(&dest);
        let _ = std::fs::remove_file(&canary);
    }
}

#[cfg(test)]
mod scratch_tests {
    use crate::commands::{fs_magic_of, OVERLAYFS_SUPER_MAGIC};

    #[test]
    fn fs_magic_probes_the_deepest_existing_ancestor() {
        // /tmp exists → Some(magic), and on a dev host it is never overlayfs.
        let m = fs_magic_of(std::path::Path::new("/tmp")).expect("statfs /tmp");
        assert_ne!(
            m, OVERLAYFS_SUPER_MAGIC,
            "/tmp must not read as overlayfs on a host"
        );
        // A path that does not exist yet resolves via its ancestors (same magic as /tmp itself).
        let ghost = std::path::Path::new("/tmp/kern-test-does-not-exist-xyz/scratch/deeper");
        assert_eq!(fs_magic_of(ghost), Some(m));
    }
}

#[cfg(test)]
mod glob_tests {
    use crate::commands::{expand_copy_srcs, glob_expand_ctx, glob_match_component, has_glob_meta};

    fn m(p: &str, n: &str) -> bool {
        glob_match_component(p.as_bytes(), n.as_bytes())
    }

    #[test]
    fn glob_component_matcher() {
        assert!(m("*.txt", "a.txt") && m("*.txt", "f.txt") && !m("*.txt", "a.md"));
        assert!(m("?.txt", "a.txt") && !m("?.txt", "ab.txt"));
        assert!(m("[fg].txt", "f.txt") && m("[fg].txt", "g.txt") && !m("[fg].txt", "h.txt"));
        assert!(m("[!f].txt", "g.txt") && !m("[!f].txt", "f.txt"));
        assert!(m("[a-z]1", "b1") && !m("[a-z]1", "B1"));
        assert!(m("*", "anything.at.all") && m("abc", "abc") && !m("abc", "abd"));
        // `*` does not span a component (matcher is per-component), and matches an empty run.
        assert!(m("a*", "a") && m("*z", "z"));
        assert!(has_glob_meta("*.txt") && has_glob_meta("a?b") && !has_glob_meta("plain.txt"));
    }

    #[test]
    fn expand_against_a_context() {
        let dir = std::env::temp_dir().join(format!("kern-glob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("d")).unwrap();
        for f in ["f.txt", "g.txt", "h.md"] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        std::fs::write(dir.join("d/a.txt"), b"x").unwrap();
        let mut got = glob_expand_ctx(&dir, "*.txt");
        got.sort();
        assert_eq!(got, vec!["f.txt".to_string(), "g.txt".to_string()]);
        assert_eq!(
            glob_expand_ctx(&dir, "d/*.txt"),
            vec!["d/a.txt".to_string()]
        );
        // A literal source passes through expand_copy_srcs; an unmatched glob is an error.
        assert_eq!(
            expand_copy_srcs(&dir, &["f.txt".to_string()]).unwrap(),
            vec!["f.txt".to_string()]
        );
        assert!(expand_copy_srcs(&dir, &["*.zzz".to_string()]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod add_url_tests {
    use crate::commands::{add_url_basename, apply_chmod};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn apply_chmod_sets_the_mode_and_rejects_garbage() {
        let dir = std::env::temp_dir().join(format!("kern-chmod-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("f");
        std::fs::write(&f, b"x").unwrap();
        // None → leave as-is (no error).
        assert!(apply_chmod(&f, None).is_ok());
        // Octal forms: 755, 0755, 0o755 all → rwxr-xr-x (0o755).
        for m in ["755", "0755", "0o755"] {
            apply_chmod(&f, Some(m)).unwrap();
            assert_eq!(
                std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
                0o755,
                "mode {m}"
            );
        }
        apply_chmod(&f, Some("644")).unwrap();
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o644
        );
        // A non-octal mode is a clear error, not a silent no-op.
        assert!(apply_chmod(&f, Some("rwx")).is_err());
        assert!(apply_chmod(&f, Some("999")).is_err()); // 9 isn't an octal digit
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_url_basename_is_a_safe_filename() {
        // Normal cases: the last path segment, query/fragment stripped.
        assert_eq!(
            add_url_basename("https://x.io/dl/tool-1.2.3.tar.gz"),
            "tool-1.2.3.tar.gz"
        );
        assert_eq!(add_url_basename("https://x.io/f?token=abc"), "f");
        assert_eq!(add_url_basename("https://x.io/f#frag"), "f");
        // Traversal / degenerate segments must NOT escape the scratch dir → fixed safe name.
        assert_eq!(add_url_basename("https://x.io/.."), "download");
        assert_eq!(add_url_basename("https://x.io/."), "download");
        assert_eq!(add_url_basename("https://x.io/"), "download");
        // A bare host with no path segment yields the host as a (harmless, non-escaping) name.
        assert_eq!(add_url_basename("https://x.io"), "x.io");
        // A separator or NUL smuggled into the last segment (defensive) → safe name.
        assert_eq!(add_url_basename("https://x.io/a\\b"), "download");
        assert_eq!(add_url_basename("https://x.io/a\0b"), "download");
    }
}

#[cfg(test)]
mod save_tag_tests {
    use crate::commands::*;

    #[test]
    fn ensure_repo_tag_appends_latest_only_when_untagged() {
        // a bare repo → :latest (so `docker load` doesn't reject "invalid tag")
        assert_eq!(ensure_repo_tag("alpine"), "alpine:latest");
        assert_eq!(ensure_repo_tag("library/nginx"), "library/nginx:latest");
        // an explicit tag is preserved
        assert_eq!(ensure_repo_tag("alpine:3.19"), "alpine:3.19");
        // a registry PORT is not a tag (it's before the last '/')
        assert_eq!(
            ensure_repo_tag("localhost:5000/app"),
            "localhost:5000/app:latest"
        );
        assert_eq!(
            ensure_repo_tag("localhost:5000/app:v2"),
            "localhost:5000/app:v2"
        );
    }
}

#[cfg(test)]
mod image_rm_tests {
    use crate::commands::*;

    // Build a fake pulled-image entry in `cache`: a `<stem>.ok` sentinel (content = ref) + a `<stem>/`
    // payload dir with one file of `bytes` bytes.
    fn fake_image(cache: &std::path::Path, stem: &str, refname: &str, bytes: usize) {
        std::fs::write(cache.join(format!("{stem}.ok")), refname).unwrap();
        let dir = cache.join(stem);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blob"), vec![0u8; bytes]).unwrap();
    }

    /// A layer can carry a directory with no owner write bit (`dr-xr-xr-x` is ordinary in
    /// Fedora-based images). Unlinking a file needs write on its PARENT, so a plain `remove_dir_all`
    /// stops at the first one and leaves the rest on disk while `rmi` reports the size it measured
    /// beforehand. Measured on `quay.io/podman/stable`: "freed 600.5M", **456 MB still there**.
    /// On an SD-card board that is the difference between a full disk and an empty one.
    #[test]
    fn a_read_only_directory_does_not_survive_the_delete() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("kern-ro-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let deep = base.join("a/bloccata/dentro");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("file"), b"x").unwrap();
        // Take the write bit off the directory that HOLDS the file, which is what blocks the unlink.
        let ro = base.join("a/bloccata");
        let mut p = std::fs::metadata(&ro).unwrap().permissions();
        p.set_mode(0o555);
        std::fs::set_permissions(&ro, p).unwrap();
        // The plain call is expected to fail here - that is the bug being pinned.
        assert!(
            std::fs::remove_dir_all(&base).is_err(),
            "fixture is wrong: the plain remove succeeded, so it proves nothing"
        );
        force_remove_dir_all(&base);
        assert!(
            !base.exists(),
            "the tree survived the delete: rmi would report bytes it never freed"
        );
    }

    #[test]
    fn rmi_removes_only_the_named_image_and_reports_freed() {
        // Process-global env (XDG_CACHE_HOME) - serialize with every other env-mutating test.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmitest-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&cache).unwrap();
        std::env::set_var("XDG_CACHE_HOME", &tmp);

        fake_image(&cache, "alpine_3_19-aaaa", "alpine:3.19", 4096);
        fake_image(&cache, "alpine_3_20-bbbb", "alpine:3.20", 4096);

        // Resolve BY REF (as shown in `kern images`) and delete just that one.
        let freed = remove_image(&cache, "alpine:3.19").expect("image should be found by ref");
        assert!(
            freed >= 4096,
            "freed should include the payload dir, got {freed}"
        );
        assert!(
            !cache.join("alpine_3_19-aaaa.ok").exists() && !cache.join("alpine_3_19-aaaa").exists(),
            "the removed image's sentinel and payload are both gone"
        );
        // The OTHER image is untouched (no over-broad sweep).
        assert!(
            cache.join("alpine_3_20-bbbb.ok").exists() && cache.join("alpine_3_20-bbbb").is_dir(),
            "an unrelated image must survive a targeted rmi"
        );
        // Also resolvable BY STEM, and a miss returns None (→ "no such image", never a silent success).
        assert!(
            remove_image(&cache, "alpine_3_20-bbbb").is_some(),
            "stem resolves too"
        );
        assert!(remove_image(&cache, "ghost:1").is_none(), "a miss is None");

        std::env::remove_var("XDG_CACHE_HOME");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rmi_rejects_a_planted_dotdot_stem_and_cannot_escape_the_cache() {
        // A file literally named `...ok` has file_stem() == ".."; unchecked, cache.join("..") would let
        // a `remove_dir_all` wipe the cache's PARENT. `is_safe_stem` must reject it - a delete never
        // escapes the images dir, whatever a planted sentinel is named.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmiesc-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&cache).unwrap();
        // A canary living in the cache's PARENT (`kern/`) - it must survive no matter what.
        let canary = tmp.join("kern/CANARY");
        std::fs::write(&canary, b"do-not-delete").unwrap();
        // Plant the hostile sentinel: `...ok` (stem "..") with an arbitrary ref content.
        std::fs::write(cache.join("...ok"), "evil:1").unwrap();

        assert!(is_safe_stem("alpine_3_19-aaaa"));
        assert!(!is_safe_stem("..") && !is_safe_stem(".") && !is_safe_stem(""));
        // Neither the stem `..` nor the ref content can resolve to a deletion.
        assert!(
            remove_image(&cache, "..").is_none(),
            "a `..` stem is never a target"
        );
        assert!(
            remove_image(&cache, "evil:1").is_none(),
            "a planted sentinel's ref is inert"
        );
        assert!(canary.exists(), "the cache-parent canary must be untouched");
        assert!(cache.exists(), "the cache dir itself must be untouched");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rmi_removes_the_base_and_image_sidecars_too() {
        // rmi must delete ALL sidecar forms (via the shared drop_image_artifacts) - a leaked `.base`
        // would otherwise misclassify a later same-name pull.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmiside-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&cache).unwrap();
        std::env::set_var("XDG_CACHE_HOME", &tmp);

        let stem = "myapp-cccc";
        std::fs::write(cache.join(format!("{stem}.ok")), "myapp:latest").unwrap();
        std::fs::write(cache.join(format!("{stem}.base")), "alpine").unwrap();
        std::fs::write(cache.join(format!("{stem}.image")), "{}").unwrap();
        std::fs::create_dir_all(cache.join(format!("{stem}.diff"))).unwrap();

        assert!(remove_image(&cache, "myapp:latest").is_some());
        for suffix in [".ok", ".base", ".image", ".diff"] {
            assert!(
                !cache.join(format!("{stem}{suffix}")).exists(),
                "rmi must remove the {suffix} sidecar"
            );
        }

        std::env::remove_var("XDG_CACHE_HOME");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rmi_never_follows_a_symlinked_payload_dir() {
        // If the payload `<stem>/` is a SYMLINK to a dir outside the cache, deleting the image must NOT
        // reach through it - remove_dir_all unlinks the symlink, never the target's contents.
        use std::os::unix::fs::symlink;
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmisym-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&cache).unwrap();
        // A victim dir OUTSIDE the cache with a canary the delete must never touch.
        let victim = tmp.join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("keep"), b"precious").unwrap();
        // Plant an image whose payload dir is a symlink to the victim.
        let stem = "evil-dddd";
        std::fs::write(cache.join(format!("{stem}.ok")), "evil:latest").unwrap();
        symlink(&victim, cache.join(stem)).unwrap();

        assert!(
            remove_image(&cache, "evil:latest").is_some(),
            "the sentinel resolves"
        );
        assert!(
            !cache.join(format!("{stem}.ok")).exists(),
            "the .ok sentinel is removed"
        );
        // The crucial invariant: the symlink TARGET (outside the cache) is untouched.
        assert!(
            victim.join("keep").exists(),
            "a symlinked payload's target must survive rmi"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rmi_keeps_a_layer_still_referenced_by_another_image() {
        // A shared L/ layer named by TWO images' manifests must survive rmi of the first, and only be
        // reclaimed once its last referrer is removed - the fail-closed sweep, end to end.
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("kern-rmilayer-{}", std::process::id()));
        let cache = tmp.join("kern/images");
        let lc = cache.join("L");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&lc).unwrap();
        std::env::set_var("XDG_CACHE_HOME", &tmp);

        let key = "0123456789abcdef0123456789abcdef"; // 32 hex
        std::fs::create_dir_all(lc.join(key)).unwrap();
        std::fs::write(lc.join(key).join("blob"), vec![0u8; 2048]).unwrap();
        for (stem, refn) in [("app1-1111", "app1:latest"), ("app2-2222", "app2:latest")] {
            std::fs::write(cache.join(format!("{stem}.ok")), refn).unwrap();
            std::fs::write(
                cache.join(format!("{stem}.layers")),
                format!("base\n{key}\n"),
            )
            .unwrap();
        }

        assert!(remove_image(&cache, "app1:latest").is_some());
        assert!(
            lc.join(key).is_dir(),
            "a layer still referenced by another image must survive rmi"
        );
        assert!(remove_image(&cache, "app2:latest").is_some());
        assert!(
            !lc.join(key).exists(),
            "an orphaned layer is reclaimed once its last referrer is gone"
        );

        std::env::remove_var("XDG_CACHE_HOME");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn image_stat_flags_missing_layers_not_empty_builds() {
        // The honesty fix behind `kern images`: image_stat returns (size, dangling) in one pass, and
        // distinguishes a broken image (layers gone → would fail to run) from a legitimately EMPTY build
        // (a present but 0-byte layer → size 0 but NOT dangling).
        let tmp = std::env::temp_dir().join(format!("kern-dangling-{}", std::process::id()));
        let cache = tmp.join("images");
        let lc = cache.join("L");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&lc).unwrap();

        // Present but empty layer → size 0, NOT dangling (a valid empty build).
        std::fs::create_dir_all(lc.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).unwrap();
        std::fs::write(
            cache.join("empty-1.layers"),
            "base\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .unwrap();
        assert_eq!(
            image_stat(&cache, "empty-1"),
            (0, false),
            "a present (0-byte) layer is a valid empty build: size 0, not dangling"
        );
        // Missing layer → dangling.
        std::fs::write(
            cache.join("broken-2.layers"),
            "base\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();
        assert!(
            image_stat(&cache, "broken-2").1,
            "a manifest naming a missing L/ layer is dangling"
        );
        // A flat pulled image (dir present) → never dangling.
        std::fs::create_dir_all(cache.join("pulled-3")).unwrap();
        assert!(
            !image_stat(&cache, "pulled-3").1,
            "a present flat rootfs is intact"
        );
        // A bare sentinel with no payload at all → dangling.
        assert!(
            image_stat(&cache, "orphan-4").1,
            "no flat/diff/layers → nothing to run"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn kill_box_reaps_a_foreground_sigterm_ignoring_init() {
        // Reproduces the reported bug: a FOREGROUND box's init is NOT a process-group leader, so the
        // historical `kill(-pid)` misses it, and a workload that ignores SIGTERM never dies. `kill_box`
        // must reach it by signalling `pid1` directly (SIGKILL, unignorable) and CONFIRM the exit.
        // Skip gracefully where pidfd_open is unavailable (kernel < 5.3); target boards are 5.15+.
        let self_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id() as i32, 0) };
        if self_fd < 0 {
            eprintln!("skip: pidfd_open unsupported on this kernel");
            return;
        }
        unsafe { libc::close(self_fd as i32) };

        // Fork a child that ignores SIGTERM and does NOT `setsid` (it stays in our process group, like
        // a foreground box's init), then busy-loops. Only async-signal-safe calls before it spins.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
            loop {
                std::hint::spin_loop();
            }
        }

        unsafe { libc::usleep(50_000) }; // let it install the handler and start spinning
        assert_eq!(
            unsafe { libc::kill(child, 0) },
            0,
            "child should be running"
        );
        // The OLD mechanism alone can't touch it: it's not a group leader, so no group has id `child`
        // - `kill(-child, SIGTERM)` is a harmless ESRCH, and SIGTERM is ignored regardless.
        unsafe { libc::kill(-child, libc::SIGTERM) };
        unsafe { libc::usleep(50_000) };
        assert_eq!(
            unsafe { libc::kill(child, 0) },
            0,
            "the process-group SIGTERM must NOT reach a foreground, SIGTERM-ignoring init"
        );

        // The fix: `kill_box` signals pid1 directly and confirms the exit before returning.
        assert!(
            kill_box_graceful(child, child, libc::SIGTERM, 0).confirmed(),
            "kill_box must confirm the foreground box is gone"
        );
        // Reap the zombie (kill_box confirms via the pidfd BEFORE the process is reaped).
        crate::eintr::reap(child);
        assert_ne!(
            unsafe { libc::kill(child, 0) },
            0,
            "child must be dead after kill_box"
        );
    }

    /// `stop` records what the box's exit code REALLY was, and the only place that fact survives is
    /// the unreaped zombie: `/proc/<pid>/stat` field 52. A clean shutdown (`trap ... exit 0`) and a
    /// SIGKILL are the two shapes this has to tell apart - reading them as the same 137 is exactly
    /// the bug this exists to prevent.
    ///
    /// The live-process case is the discriminant: it proves the function reads a real status rather
    /// than answering from the pid, and that a not-yet-dead init can never be recorded as exited.
    /// The child is held on a pipe until that check has run - asserting it against a child racing us
    /// to `_exit` made THIS TEST flaky (seen once in five full-suite runs), which is the same defect
    /// class it was written to catch, just on the test's side of the line.
    #[test]
    fn zombie_exit_code_tells_a_clean_exit_from_a_kill() {
        // (what the child does, what `waitpid` semantics say the code is)
        for (want, kill_self) in [(7, false), (0, false), (128 + libc::SIGKILL, true)] {
            let mut fds = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
            let (rd, wr) = (fds[0], fds[1]);
            let child = unsafe { libc::fork() };
            assert!(child >= 0, "fork");
            if child == 0 {
                // Async-signal-safe only: no allocation, no Rust runtime, between fork and _exit.
                unsafe { libc::close(wr) };
                let mut byte = 0u8;
                // Block until the parent has taken its live reading. EOF (parent died) releases too,
                // so a failing test cannot leave this child behind.
                while unsafe { libc::read(rd, std::ptr::addr_of_mut!(byte).cast(), 1) } < 0 {}
                if kill_self {
                    unsafe { libc::raise(libc::SIGKILL) };
                }
                unsafe { libc::_exit(want) };
            }
            unsafe { libc::close(rd) };
            // Live, not yet dead: there is no status to read and none must be invented.
            assert_eq!(
                zombie_exit_code(child),
                None,
                "a live process has no exit status to report"
            );
            // Let it go, and drop our end so an early failure above still releases it.
            unsafe { libc::write(wr, b"g".as_ptr().cast(), 1) };
            unsafe { libc::close(wr) };
            // Wait for the zombie WITHOUT reaping it - that is the window `stop` reads in.
            let mut seen = None;
            for _ in 0..2000 {
                if let Some(code) = zombie_exit_code(child) {
                    seen = Some(code);
                    break;
                }
                unsafe { libc::usleep(1_000) };
            }
            crate::eintr::reap(child);
            assert_eq!(
                seen,
                Some(want),
                "the zombie's recorded status must decode to the code the child really exited with"
            );
        }
    }

    /// The grace a box is left with, as an arithmetic fact rather than a race between two timers.
    ///
    /// The end-to-end version of this - a workload flushing for 1.5 s under a 2 s timeout - proves
    /// the number reaches the poll, but it can only ever have a sub-second margin, because a
    /// sub-second truncation is only visible to a flush that falls between `floor(T)` and `T`. On
    /// WSL2 that margin is gone: the same 1.5 s flush MEASURED 1723 ms there, and a 0.5 s one 1007 ms,
    /// so the platform's own overhead eats it. This test is the invariant; that one is the wiring.
    #[test]
    fn remaining_grace_keeps_the_milliseconds_it_was_given() {
        use std::time::Duration;
        // Nothing spent yet: the box's own grace, in full and in milliseconds.
        assert_eq!(remaining_grace_ms(3, Duration::ZERO), 3000);
        // Part spent since the phase-1 signal: the REST of its own grace, to the millisecond. A
        // whole-second truncation here spent up to 999 ms of what the caller asked for.
        assert_eq!(remaining_grace_ms(3, Duration::from_millis(1)), 2999);
        assert_eq!(remaining_grace_ms(3, Duration::from_millis(1500)), 1500);
        // Its own grace is an UPPER bound: once spent, this box is SIGKILLed even if a longer-lived
        // member of the same stack is still inside its own. Measured before this: a service asking
        // 1 s in a stack whose longest ask was 4 s was killed at 5154 ms.
        assert_eq!(remaining_grace_ms(1, Duration::from_millis(4000)), 0);
        assert_eq!(remaining_grace_ms(3, Duration::from_millis(3000)), 0);
        // Configured with no grace at all: straight to the SIGKILL, whatever the clock says.
        assert_eq!(remaining_grace_ms(0, Duration::ZERO), 0);
        assert_eq!(remaining_grace_ms(0, Duration::from_millis(500)), 0);
        // Degenerate inputs saturate instead of wrapping into a short wait or a long one.
        assert_eq!(remaining_grace_ms(u64::MAX, Duration::ZERO), u64::MAX);
        assert_eq!(remaining_grace_ms(3, Duration::MAX), 0);
    }

    /// The mapping from a teardown to the recorded code: only a status we actually READ is reported
    /// as the box's own. Everything else stays 137, the historical "we tore it down" value.
    #[test]
    fn teardown_reports_a_read_status_and_falls_back_to_137() {
        assert_eq!(Teardown::Gone(Some(0)).exit_code(), 0);
        assert_eq!(Teardown::Gone(Some(7)).exit_code(), 7);
        assert_eq!(Teardown::Gone(Some(137)).exit_code(), 137);
        assert_eq!(Teardown::Gone(None).exit_code(), 137);
        assert_eq!(Teardown::Unconfirmed.exit_code(), 137);
        assert!(Teardown::Gone(None).confirmed());
        assert!(!Teardown::Unconfirmed.confirmed());
    }
}

#[cfg(test)]
mod relative_bind_tests {
    use crate::commands::*;

    fn one(spec: &str, dir: &std::path::Path) -> Result<String, Error> {
        let mut b = vec![crate::compose::ComposeBox {
            name: "a".into(),
            volumes: vec![spec.to_string()],
            ..Default::default()
        }];
        let f = dir.join("docker-compose.yml");
        resolve_relative_binds(&mut b, &f.to_string_lossy())?;
        Ok(b.remove(0).volumes.remove(0))
    }

    #[test]
    fn bare_dot_is_a_path_not_a_volume_name() {
        // `.:/app` (mount the project root) is the single most common bind there is. The rule "no
        // slash means named volume" sent it to the volume-name validator, which refused `.`.
        let tmp = std::env::temp_dir().join(format!("kern-bind-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let got = one(".:/app", &tmp).expect("`.` resolves");
        let want = std::fs::canonicalize(&tmp).unwrap_or_else(|_| tmp.clone());
        assert_eq!(got, format!("{}:/app", want.to_string_lossy()));
        // Options after the target survive the rewrite.
        assert!(one(".:/app:ro", &tmp).expect("ro").ends_with(":/app:ro"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_real_volume_name_is_still_left_alone() {
        // Only `.`/`..` change meaning: a bare name is still a named volume, untouched.
        let tmp = std::env::temp_dir().join(format!("kern-bind2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        assert_eq!(one("dati:/app", &tmp).expect("named"), "dati:/app");
        assert_eq!(one("/abs:/app", &tmp).expect("abs"), "/abs:/app");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_missing_bind_source_is_created_under_the_project() {
        // Docker creates it, and refusing broke the most ordinary workflow there is: clone a repo
        // whose compose file says `./data:/var/lib/mysql` and `up` failed because `./data` is not in
        // the tree yet.
        let tmp = std::env::temp_dir().join(format!("kern-bind4-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let got = one("./nuovo:/app", &tmp).expect("missing source is created");
        assert!(
            tmp.join("nuovo").is_dir(),
            "the directory now exists: {got}"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn an_escaping_source_is_refused_without_creating_anything() {
        // Containment is decided LEXICALLY, before any mkdir: `canonicalize` needs the path to exist,
        // so checking after creating would let the very input we reject leave a directory behind
        // OUTSIDE the project.
        let tmp = std::env::temp_dir().join(format!("kern-bind5-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let outside = tmp.parent().map(|p| p.join("kern-bind5-escape"));
        for spec in ["../kern-bind5-escape:/m", "./a/../../kern-bind5-escape:/m"] {
            assert!(one(spec, &tmp).is_err(), "{spec} must be refused");
        }
        if let Some(o) = &outside {
            assert!(!o.exists(), "nothing may be created outside the project");
        }
        // A `..` that stays INSIDE is still fine.
        assert!(one("a/b/../c:/m", &tmp).is_ok());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn dotdot_still_cannot_escape_the_project_directory() {
        // The traversal guard is a deliberate divergence from Docker and must survive this change.
        let tmp = std::env::temp_dir().join(format!("kern-bind3-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        assert!(
            one("..:/app", &tmp).is_err(),
            "`..` escapes the compose dir"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

#[cfg(test)]
mod compose_action_tests {
    use crate::commands::*;

    #[test]
    fn every_documented_verb_parses() {
        // The help text and the parser must not drift: every verb kern advertises has to resolve.
        for (word, want) in [
            ("up", ComposeAction::Up),
            ("down", ComposeAction::Down),
            ("stop", ComposeAction::Stop),
            ("start", ComposeAction::Start),
            ("restart", ComposeAction::Restart),
            ("ps", ComposeAction::Ps),
            ("logs", ComposeAction::Logs),
            ("build", ComposeAction::Build),
            ("pull", ComposeAction::Pull),
            ("config", ComposeAction::Config),
        ] {
            assert_eq!(ComposeAction::from_verb(word), Some(want), "verb {word}");
        }
    }

    #[test]
    fn unknown_verb_is_none_not_a_guess() {
        // A typo must NOT silently resolve to something (the caller turns `None` into a message that
        // lists the real verbs); `stop` must not be reachable from `stopp`.
        for word in ["", "pippo", "stopp", "UP", "Down", "--up", "up "] {
            assert_eq!(ComposeAction::from_verb(word), None, "{word:?}");
        }
    }

    #[test]
    fn only_up_start_and_restart_launch_anything() {
        // The dispatch returns early for every other verb. If a new verb is added and forgotten here,
        // this test states the intended contract rather than letting it silently start a stack.
        for a in [
            ComposeAction::Down,
            ComposeAction::Stop,
            ComposeAction::Ps,
            ComposeAction::Logs,
            ComposeAction::Build,
            ComposeAction::Pull,
            ComposeAction::Config,
        ] {
            assert!(
                !matches!(
                    a,
                    ComposeAction::Up | ComposeAction::Start | ComposeAction::Restart
                ),
                "{a:?} must not be a launching verb"
            );
        }
    }
}

#[cfg(test)]
mod label_filter_tests {
    use crate::commands::*;

    fn inst_with(labels: &str) -> registry::Instance {
        registry::Instance {
            name: "b".into(),
            pid: 1,
            pid1: 0,
            rootfs: String::new(),
            command: String::new(),
            started: 0,
            starttime: 0,
            ports: String::new(),
            volumes: String::new(),
            pod: String::new(),
            workdir: String::new(),
            egress: String::new(),
            landlock_rw: String::new(),
            memory_max: None,
            pids_max: None,
            labels: labels.into(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: String::new(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        }
    }

    fn f(k: &str, v: &str) -> Vec<(String, String)> {
        vec![(k.to_string(), v.to_string())]
    }

    #[test]
    fn exact_pair_matches() {
        let b = inst_with("app=web,tier=front");
        assert!(ps_matches(&b, &f("label", "app=web")));
        assert!(ps_matches(&b, &f("label", "tier=front")));
        assert!(!ps_matches(&b, &f("label", "app=api")));
    }

    #[test]
    fn bare_key_matches_any_value() {
        let b = inst_with("app=web");
        assert!(ps_matches(&b, &f("label", "app")));
        assert!(!ps_matches(&b, &f("label", "tier")));
    }

    #[test]
    fn bare_key_is_not_a_substring_match() {
        // `app` must NOT match `apple=1`: a prefix is a different key, and a filter that quietly
        // over-matches would select boxes the operator did not mean to touch.
        let b = inst_with("apple=1");
        assert!(!ps_matches(&b, &f("label", "app")));
        assert!(ps_matches(&b, &f("label", "apple")));
    }

    #[test]
    fn no_labels_matches_nothing() {
        let b = inst_with("");
        assert!(!ps_matches(&b, &f("label", "app")));
        assert!(!ps_matches(&b, &f("label", "app=web")));
    }

    #[test]
    fn value_containing_equals_is_matched_whole() {
        // A value may itself contain '=', e.g. a base64 or a query string. The pair is compared as a
        // whole, so this must match exactly and not be split at the second '='.
        let b = inst_with("cfg=a=b");
        assert!(ps_matches(&b, &f("label", "cfg=a=b")));
        assert!(ps_matches(&b, &f("label", "cfg")));
        assert!(!ps_matches(&b, &f("label", "cfg=a")));
    }
}

#[cfg(test)]
mod bring_up_check_tests {
    use crate::commands::*;

    #[test]
    fn only_an_awaited_completion_may_have_exited() {
        // The exit sidecar is written ONLY for a service some peer awaits with
        // `service_completed_successfully`, so the presence of a clean exit IS the declared intention:
        // a migration task that finished passes, and a long-running service that exited 0 by mistake
        // (a wrong command that printed help and returned 0, a config that made it terminate cleanly)
        // does NOT, because nobody declared it was allowed to end.
        //
        // A reviewer read the simplified rule as "any exit 0 is legitimate", which would have left
        // exactly that case silent. It does not, and this test pins the distinction so a future
        // simplification cannot quietly widen it.
        let pod = "p";
        let token = "t";
        let awaited = exit_key(pod, token, "migrate");
        registry::set_exit(&awaited, 0);
        assert_eq!(
            registry::exit_of(&awaited),
            Some(0),
            "awaited: clean end recorded"
        );
        // A service nobody awaits has no sidecar at all, which is not `Some(0)` and therefore counts
        // as a death - the check `settle_and_collect_dead` performs.
        assert_eq!(registry::exit_of(&exit_key(pod, token, "web")), None);
        registry::clear_exit(&awaited);
    }
}

#[cfg(test)]
mod drift_tests {
    use crate::commands::*;

    fn svc(name: &str) -> crate::compose::ComposeBox {
        crate::compose::ComposeBox {
            name: name.to_string(),
            image: Some("alpine".into()),
            ..Default::default()
        }
    }
    fn inst(hash: &str) -> registry::Instance {
        registry::Instance {
            name: "a".into(),
            pid: 1,
            pid1: 0,
            rootfs: String::new(),
            command: String::new(),
            started: 0,
            starttime: 0,
            ports: String::new(),
            volumes: String::new(),
            pod: String::new(),
            workdir: String::new(),
            egress: String::new(),
            landlock_rw: String::new(),
            memory_max: None,
            pids_max: None,
            labels: String::new(),
            stop_signal: 0,
            stop_grace: 0,
            def_hash: hash.into(),
            cap_drop_all: false,
            cap_drops: String::new(),
            cap_adds: String::new(),
            seccomp_mode: kern_isolation::SeccompFilter::Denylist,
            apparmor: String::new(),
            cap_recorded: true,
            aa_recorded: true,
            seccomp_recorded: true,
            posture_corrupt: false,
            cgroup: String::new(),
            cgroup_id: None,
            orphaned: false,
        }
    }

    #[test]
    fn the_hash_is_stable_and_field_order_independent() {
        // Two readings of the same definition must agree, or `up` would recreate the whole stack on
        // every invocation.
        let a = svc("x");
        assert_eq!(definition_hash(&a), definition_hash(&a));
        // Same content, and the hash is derived from the emitted argv, so it does not depend on how
        // the file happened to be written.
        let b = svc("x");
        assert_eq!(definition_hash(&a), definition_hash(&b));
    }

    #[test]
    fn every_field_that_changes_the_box_changes_the_hash() {
        let base = definition_hash(&svc("x"));
        let mut env = svc("x");
        env.env = vec!["V=1".into()];
        let mut ports = svc("x");
        ports.ports = vec!["1:1".into()];
        let mut img = svc("x");
        img.image = Some("busybox".into());
        let mut cmd = svc("x");
        cmd.command = vec!["echo".into(), "hi".into()];
        let mut mem = svc("x");
        mem.memory = Some("64m".into());
        for (what, h) in [
            ("environment", definition_hash(&env)),
            ("ports", definition_hash(&ports)),
            ("image", definition_hash(&img)),
            ("command", definition_hash(&cmd)),
            ("mem_limit", definition_hash(&mem)),
        ] {
            assert_ne!(h, base, "changing {what} must change the fingerprint");
        }
    }

    #[test]
    fn argv_boundaries_are_hashed_not_just_bytes() {
        // `["ab","c"]` must not hash like `["a","bc"]`: without a separator a concatenation of two
        // different definitions would collide and a real change would be missed.
        let mut a = svc("x");
        a.env = vec!["AB=".into(), "C=".into()];
        let mut b = svc("x");
        b.env = vec!["A=".into(), "BC=".into()];
        assert_ne!(definition_hash(&a), definition_hash(&b));
    }

    #[test]
    fn an_unchanged_service_is_left_alone_and_a_changed_one_is_recreated() {
        let want = definition_hash(&svc("x"));
        assert_eq!(reconcile_decision(&inst(&want), &want), Reconcile::UpToDate);
        assert_eq!(
            reconcile_decision(&inst("deadbeef"), &want),
            Reconcile::Recreate
        );
    }

    #[test]
    fn a_box_without_a_fingerprint_is_not_recreated_forever() {
        // Registered by an older kern, or started outside compose. Treating it as changed would
        // recreate it on EVERY `up`; treating it as current costs at most one missed recreate, after
        // which it carries a fingerprint and behaves normally.
        assert_eq!(
            reconcile_decision(&inst(""), "anything"),
            Reconcile::UpToDate
        );
    }
}

#[cfg(test)]
mod pod_global_tests {
    use crate::commands::*;

    fn svc(name: &str) -> crate::compose::ComposeBox {
        crate::compose::ComposeBox {
            name: name.to_string(),
            ..Default::default()
        }
    }
    fn err(boxes: &[crate::compose::ComposeBox]) -> String {
        match check_pod_global_conflicts(boxes, false) {
            Err(Error::Compose(m)) => m,
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    /// `expose:` joins the same space as `port:` and `ports:`. Without it, a real
    /// `docker-compose.yml` using the Compose spelling stayed outside the preflight and collided at
    /// runtime.
    #[test]
    fn expose_shares_the_port_space_with_port_and_ports() {
        // expose against a declared port.
        let mut a = svc("api");
        a.expose = vec![(3000, false)];
        let mut b = svc("admin");
        b.port = Some(3000);
        assert!(err(&[a, b]).contains("3000/tcp"));

        // expose contro una mappatura pubblicata.
        let mut c = svc("api");
        c.expose = vec![(3000, false)];
        let mut d = svc("admin");
        d.ports = vec!["9000:3000".into()];
        assert!(err(&[c, d]).contains("3000/tcp"));

        // expose contro expose.
        let mut e = svc("api");
        e.expose = vec![(3000, false)];
        let mut f = svc("admin");
        f.expose = vec![(3000, false)];
        assert!(err(&[e, f]).contains("3000/tcp"));

        // The protocol matters: udp and tcp on the same number are different sockets.
        let mut g = svc("api");
        g.expose = vec![(53, true)];
        let mut h = svc("dns");
        h.expose = vec![(53, false)];
        assert!(
            check_pod_global_conflicts(&[g, h], false).is_ok(),
            "udp and tcp do not collide"
        );

        // A service declaring the same port in two spellings states one fact twice.
        let mut solo = svc("api");
        solo.port = Some(3000);
        solo.expose = vec![(3000, false)];
        solo.ports = vec!["8080:3000".into()];
        assert!(
            check_pod_global_conflicts(&[solo], false).is_ok(),
            "un servizio non collide con se stesso"
        );

        // Piu' porte esposte: collide solo quella davvero condivisa.
        let mut m = svc("api");
        m.expose = vec![(3000, false), (9090, false)];
        let mut n = svc("metrics");
        n.expose = vec![(9090, false)];
        let msg = err(&[m, n]);
        assert!(msg.contains("9090/tcp") && !msg.contains("3000"), "{msg}");
    }

    /// A DECLARED `port` is what makes an internal-only service visible to this check at all. The
    /// conflict was derived from `ports:` mappings alone, so two services that publish nothing and
    /// talk to each other by name could both claim `:3000`: the preflight saw neither, both boxes
    /// started, one died with EADDRINUSE, and the stack was half up.
    #[test]
    fn a_declared_port_makes_an_unpublished_service_visible_to_the_preflight() {
        let mut a = svc("api");
        a.port = Some(3000);
        let mut b = svc("admin");
        b.port = Some(3000);
        let m = err(&[a, b]);
        assert!(m.contains("container port 3000/tcp"), "{m}");
        assert!(
            m.contains("api") && m.contains("admin"),
            "both services named: {m}"
        );
        // The message must offer the way out the field exists for.
        assert!(m.contains("port:"), "the remedy names the field: {m}");
    }

    /// A declared port and a published mapping are the same claim, so they must collide across
    /// services and must NOT collide with themselves.
    #[test]
    fn declared_and_published_ports_share_one_space_without_self_conflict() {
        // Same service declaring 3000 and publishing 8080:3000 states one fact twice: not a conflict.
        let mut solo = svc("api");
        solo.port = Some(3000);
        solo.ports = vec!["8080:3000".into()];
        assert!(
            check_pod_global_conflicts(&[solo], false).is_ok(),
            "a service must not conflict with itself"
        );

        // One declares, the other publishes the same internal port: a real conflict.
        let mut a = svc("api");
        a.port = Some(3000);
        let mut b = svc("admin");
        b.ports = vec!["3002:3000".into()];
        assert!(err(&[a, b]).contains("3000/tcp"));

        // Different internal ports are exactly the way out, and must pass.
        let mut c = svc("api");
        c.port = Some(3000);
        let mut d = svc("admin");
        d.port = Some(3100);
        assert!(
            check_pod_global_conflicts(&[c, d], false).is_ok(),
            "distinct ports must be allowed"
        );
    }

    /// A declared TCP port must not be confused with a UDP publication of the same number: they are
    /// different sockets and both can bind.
    #[test]
    fn a_declared_port_is_tcp_and_does_not_collide_with_udp() {
        let mut a = svc("api");
        a.port = Some(3000);
        let mut b = svc("metrics");
        b.ports = vec!["3000:3000/udp".into()];
        assert!(
            check_pod_global_conflicts(&[a, b], false).is_ok(),
            "tcp/3000 and udp/3000 are different sockets"
        );
    }

    #[test]
    fn same_container_port_is_a_conflict_even_with_different_host_ports() {
        // The case a reviewer's premise said was rare: two DIFFERENT services on the same INTERNAL
        // port, published on different host ports. Common by default, because every framework has one
        // canonical port. Before this, both boxes started, one died with EADDRINUSE, and `up` exited 0.
        let mut a = svc("api");
        a.ports = vec!["3001:3000".into()];
        let mut b = svc("admin");
        b.ports = vec!["3002:3000".into()];
        let m = err(&[a, b]);
        assert!(m.contains("container port 3000/tcp"), "{m}");
        assert!(m.contains("'api'") && m.contains("'admin'"), "{m}");
        // The message must offer the way out, not just the diagnosis.
        assert!(
            m.contains("--no-pod") || m.contains("different container ports"),
            "{m}"
        );
    }

    #[test]
    fn different_container_ports_are_fine_and_so_is_one_service_alone() {
        let mut a = svc("api");
        a.ports = vec!["3001:3000".into()];
        let mut b = svc("web");
        b.ports = vec!["3002:8080".into()];
        assert!(check_pod_global_conflicts(&[a, b], false).is_ok());
        // A single service publishing the same port twice is a HOST-port problem, caught elsewhere.
        let mut solo = svc("solo");
        solo.ports = vec!["1:3000".into(), "2:3000".into()];
        assert!(check_pod_global_conflicts(&[solo], false).is_ok());
    }

    #[test]
    fn tcp_and_udp_on_the_same_number_do_not_conflict() {
        let mut a = svc("a");
        a.ports = vec!["1:53".into()];
        let mut b = svc("b");
        b.ports = vec!["2:53/udp".into()];
        assert!(check_pod_global_conflicts(&[a, b], false).is_ok());
    }

    #[test]
    fn same_net_sysctl_with_different_values_is_a_conflict() {
        // The knob belongs to the shared namespace: the last service to start would decide, and the
        // file does not say which that is.
        let mut a = svc("a");
        a.sysctls = vec!["net.core.somaxconn=1024".into()];
        let mut b = svc("b");
        b.sysctls = vec!["net.core.somaxconn=2048".into()];
        assert!(err(&[a, b]).contains("different values"));
        // The SAME value from two services is consistent, not a conflict.
        let mut d = svc("d");
        d.sysctls = vec!["net.core.somaxconn=1024".into()];
        let mut e = svc("e");
        e.sysctls = vec!["net.core.somaxconn=1024".into()];
        assert!(check_pod_global_conflicts(&[d, e], false).is_ok());
    }

    #[test]
    fn non_net_sysctls_are_not_pod_global() {
        // `kernel.*`/`fs.*` are not namespaced by the network namespace: two services may differ.
        let mut a = svc("a");
        a.sysctls = vec!["kernel.msgmax=1".into()];
        let mut b = svc("b");
        b.sysctls = vec!["kernel.msgmax=2".into()];
        assert!(check_pod_global_conflicts(&[a, b], false).is_ok());
    }

    #[test]
    fn extra_hosts_shadowing_a_service_name_is_a_conflict() {
        // Both write the pod's shared /etc/hosts, so the winner would be decided by write order, and
        // a service silently resolving elsewhere is the worst kind of wrong.
        let db = svc("db");
        let mut app = svc("app");
        app.add_host = vec!["db:9.9.9.9".into()];
        assert!(err(&[db, app]).contains("same name as a service"));
        // An unrelated host entry is fine.
        let mut ok_app = svc("app");
        ok_app.add_host = vec!["esterno:9.9.9.9".into()];
        assert!(check_pod_global_conflicts(&[svc("db"), ok_app], false).is_ok());
    }

    /// The gate lives INSIDE the function, and this test is why it stays there.
    ///
    /// It used to be restated at every call site, and the sites drifted: `up` applied it, `systemd`
    /// ran with no gate at all, and `config`, the verb that answers "does this file come up?", never
    /// called the check, so it declared healthy a stack that `up` refused. Moving the gate back out,
    /// into one of the three sites, would reopen that divergence.
    #[test]
    fn the_gate_is_inside_so_no_caller_can_restate_it_differently() {
        // `ComposeBox` is not Clone, so the pair is rebuilt for each assertion.
        let pair = || {
            let (mut a, mut b) = (svc("a"), svc("b"));
            a.port = Some(3100);
            b.port = Some(3100);
            [a, b]
        };
        // Positive control: the collision is really there, otherwise the assertions below would be
        // measuring the absence of a conflict rather than the gate.
        assert!(err(&pair()).contains("3100"));
        // `--no-pod`: each service gets its own namespace, so the collision no longer exists.
        assert!(check_pod_global_conflicts(&pair(), true).is_ok());
        // A lone service shares with nobody, whatever the flag says.
        let [solo, _] = pair();
        assert!(check_pod_global_conflicts(&[solo], false).is_ok());
    }
}

#[cfg(test)]
mod port_collision_tests {
    use crate::commands::*;

    // A ComposeBox with just a name + published ports - every other field is its Default. Enough to
    // drive `check_port_collisions`, which only reads `.name` and `.ports`.
    fn svc(name: &str, ports: &[&str]) -> crate::compose::ComposeBox {
        crate::compose::ComposeBox {
            name: name.to_string(),
            ports: ports.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    // Assert a collision was reported AND that the message names both offenders (a silent or vague
    // rejection would be a regression - the whole point is a loud, actionable pre-flight error).
    fn assert_collides(boxes: &[crate::compose::ComposeBox], needles: &[&str]) {
        match check_port_collisions(boxes) {
            Err(Error::Compose(msg)) => {
                for n in needles {
                    assert!(msg.contains(n), "message {msg:?} should mention {n:?}");
                }
            }
            other => panic!("expected a compose collision error, got {other:?}"),
        }
    }

    #[test]
    fn distinct_host_ports_are_fine() {
        let boxes = [svc("web", &["8080:80"]), svc("api", &["8081:80"])];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn same_host_port_two_services_collides() {
        let boxes = [svc("a", &["9500:80"]), svc("b", &["9500:81"])];
        assert_collides(&boxes, &["'a'", "'b'", "9500/tcp"]);
    }

    #[test]
    fn different_protocol_same_port_is_fine() {
        // tcp/9000 and udp/9000 are independent bindings - NOT a collision.
        //
        // CONTRACT-level, not compose-reachable today: the compose parser strips `/tcp` and drops
        // non-TCP entries before they get here, so a `/udp` spec never reaches this function from a
        // real file (verified e2e - two `/udp` services start with NOTHING published). This covers the
        // function's own contract so the protocol dimension stays correct if kern gains UDP publish.
        let boxes = [svc("a", &["9000:80"]), svc("b", &["9000:80/udp"])];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn wildcard_bind_subsumes_specific_ip() {
        // 0.0.0.0:9700 and 127.0.0.1:9700 both want the loopback port - overlap.
        let boxes = [
            svc("x", &["0.0.0.0:9700:80"]),
            svc("y", &["127.0.0.1:9700:81"]),
        ];
        assert_collides(&boxes, &["'x'", "'y'", "9700/tcp"]);
    }

    #[test]
    fn distinct_specific_ips_same_port_are_fine() {
        // Two DIFFERENT concrete addresses can both hold port 9800 - no overlap, no error.
        let boxes = [
            svc("x", &["127.0.0.1:9800:80"]),
            svc("y", &["192.168.1.5:9800:81"]),
        ];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn intra_service_duplicate_is_caught() {
        // One service publishing the same host port twice would also fail at bind time - catch it here.
        let boxes = [svc("solo", &["9500:80", "9500:81"])];
        assert_collides(&boxes, &["'solo'", "more than once", "9500/tcp"]);
    }

    #[test]
    fn range_publish_overlap_is_caught() {
        // `8000-8002:8000-8002` expands to host ports 8000,8001,8002; a peer on 8001 collides on the
        // shared port even though the two specs aren't textually equal.
        let boxes = [
            svc("range", &["8000-8002:8000-8002"]),
            svc("peer", &["8001:81"]),
        ];
        assert_collides(&boxes, &["'range'", "'peer'", "8001/tcp"]);
    }

    #[test]
    fn unparseable_spec_is_left_for_the_per_box_path() {
        // A spec `ports::parse` rejects must NOT be treated as a collision here (that would mask the
        // real "invalid port" error the per-box start reports). No panic, no false positive.
        let boxes = [svc("bad", &["not-a-port"]), svc("ok", &["8080:80"])];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    // ---- extreme / adversarial edge cases ----------------------------------------------------

    #[test]
    fn nothing_to_check_is_ok() {
        // No services at all, and services with an empty `ports:` list. Must not panic or false-positive.
        assert!(check_port_collisions(&[]).is_ok());
        let boxes = [svc("quiet", &[]), svc("also_quiet", &[])];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn partially_overlapping_ranges_collide_on_the_shared_port() {
        // 8000-8005 and 8003-8008 share 8003..8005. The specs are textually different and neither is a
        // subset of the other - only real expansion catches this.
        let boxes = [
            svc("lo", &["8000-8005:8000-8005"]),
            svc("hi", &["8003-8008:8003-8008"]),
        ];
        assert_collides(&boxes, &["'lo'", "'hi'"]);
    }

    #[test]
    fn adjacent_ranges_do_not_collide() {
        // Off-by-one boundary in the OTHER direction: 8000-8004 then 8005-8009 touch but never overlap.
        let boxes = [
            svc("lo", &["8000-8004:8000-8004"]),
            svc("hi", &["8005-8009:8005-8009"]),
        ];
        assert!(check_port_collisions(&boxes).is_ok());
    }

    #[test]
    fn max_range_boundary() {
        // `ports::parse` caps a single spec at MAX_RANGE (1024). At the cap the spec expands and a peer
        // inside it collides; one PAST the cap is rejected by the parser, so we must stay silent and let
        // the per-box path report it - NOT invent a collision from a spec that will never bind.
        let at_cap = [svc("big", &["1-1024:1-1024"]), svc("peer", &["512:80"])];
        assert_collides(&at_cap, &["'big'", "'peer'", "512/tcp"]);
        let past_cap = [svc("huge", &["1-1025:1-1025"]), svc("peer", &["512:80"])];
        assert!(check_port_collisions(&past_cap).is_ok());
    }

    #[test]
    fn port_number_boundaries() {
        // The extremes of the valid range (1 and 65535) are ordinary ports to the checker.
        assert_collides(
            &[svc("a", &["1:1"]), svc("b", &["1:2"])],
            &["1/tcp", "'a'", "'b'"],
        );
        assert_collides(
            &[svc("a", &["65535:1"]), svc("b", &["65535:2"])],
            &["65535/tcp", "'a'", "'b'"],
        );
        // Adjacent extremes don't collide.
        assert!(check_port_collisions(&[svc("a", &["65534:1"]), svc("b", &["65535:1"])]).is_ok());
    }

    #[test]
    fn explicit_tcp_equals_default_tcp() {
        // `8080:80` and `8080:80/tcp` are the SAME protocol - a spelling difference must not hide the clash.
        let boxes = [svc("a", &["8080:80"]), svc("b", &["8080:81/tcp"])];
        assert_collides(&boxes, &["8080/tcp", "'a'", "'b'"]);
    }

    #[test]
    fn protocol_suffix_is_case_insensitive() {
        // `ports::parse` accepts `/UDP`; two udp mappings spelled differently still collide, and a
        // `/UDP` mapping still does NOT collide with tcp on the same port. CONTRACT-level like
        // `different_protocol_same_port_is_fine` - compose strips the proto before this point.
        assert_collides(
            &[svc("a", &["9000:80/udp"]), svc("b", &["9000:81/UDP"])],
            &["9000/udp"],
        );
        assert!(
            check_port_collisions(&[svc("a", &["9000:80/UDP"]), svc("b", &["9000:81"])]).is_ok()
        );
    }

    #[test]
    fn wildcard_twice_collides() {
        // Two services BOTH on 0.0.0.0 for the same port - the wildcard-vs-wildcard branch.
        let boxes = [
            svc("a", &["0.0.0.0:9100:80"]),
            svc("b", &["0.0.0.0:9100:81"]),
        ];
        assert_collides(&boxes, &["9100/tcp", "'a'", "'b'"]);
    }

    #[test]
    fn wildcard_arriving_second_still_collides() {
        // Order matters to the implementation (the wildcard may be inserted before OR after the specific
        // address), so cover both directions: specific-then-wildcard, and wildcard-then-specific.
        assert_collides(
            &[
                svc("spec", &["127.0.0.1:9200:80"]),
                svc("wild", &["0.0.0.0:9200:81"]),
            ],
            &["9200/tcp", "'spec'", "'wild'"],
        );
        assert_collides(
            &[
                svc("wild", &["0.0.0.0:9300:80"]),
                svc("spec", &["127.0.0.1:9300:81"]),
            ],
            &["9300/tcp", "'wild'", "'spec'"],
        );
    }

    #[test]
    fn wildcard_collides_with_a_far_away_specific_address() {
        // 0.0.0.0 subsumes EVERY address, not just loopback: a LAN-bound peer conflicts too.
        let boxes = [
            svc("lan", &["192.168.1.5:9400:80"]),
            svc("wild", &["0.0.0.0:9400:81"]),
        ];
        assert_collides(&boxes, &["'lan'", "'wild'"]);
    }

    #[test]
    fn default_bind_is_loopback_so_bare_and_explicit_loopback_collide() {
        // A bare `9500:80` defaults to 127.0.0.1 (kern is loopback-default). It MUST clash with an
        // explicit `127.0.0.1:9500:81` - otherwise the checker would disagree with the real bind.
        let boxes = [
            svc("bare", &["9500:80"]),
            svc("explicit", &["127.0.0.1:9500:81"]),
        ];
        assert_collides(&boxes, &["'bare'", "'explicit'", "9500/tcp"]);
    }

    #[test]
    fn intra_service_wildcard_duplicate_names_the_service_once() {
        // Same service, same wildcard port twice: the message must say "more than once" (not name the
        // service twice as if there were two culprits).
        let boxes = [svc("solo", &["0.0.0.0:9600:80", "0.0.0.0:9600:81"])];
        match check_port_collisions(&boxes) {
            Err(Error::Compose(m)) => {
                assert!(m.contains("more than once"), "got {m:?}");
                assert!(
                    !m.contains("and 'solo'"),
                    "should not read as two services: {m:?}"
                );
            }
            other => panic!("expected a collision, got {other:?}"),
        }
    }

    #[test]
    fn many_services_no_collision_is_linear_not_quadratic() {
        // REGRESSION GUARD. A single `-p` may expand to 1024 ports, so a legal stack of ranges reaches
        // tens of thousands of mappings. The pairwise version of this check measured 10.5 s on exactly
        // this shape (40 services) before any box started; bucketing makes it milliseconds. Distinct
        // bind IPs mean there is NO collision, so the scan cannot exit early - the worst case.
        let boxes: Vec<_> = (0..40)
            .map(|i| {
                svc(
                    &format!("s{i}"),
                    &[&format!("10.0.{}.{}:1-1024:1-1024", i / 256, i % 256)],
                )
            })
            .collect();
        let t0 = std::time::Instant::now();
        assert!(
            check_port_collisions(&boxes).is_ok(),
            "distinct IPs never collide"
        );
        let dt = t0.elapsed();
        // Generous ceiling (the quadratic form took ~10.5 s here, ~260x this bound) so the test is a
        // real signal on slow CI rather than a flake.
        assert!(
            dt < std::time::Duration::from_secs(2),
            "41k-mapping check should be milliseconds, took {dt:?} - did the pairwise scan come back?"
        );
    }

    #[test]
    fn collision_is_reported_deterministically() {
        // HashMap iteration order is randomized per process, but the SCAN walks services and specs in
        // file order, so the reported pair must be stable - a flaky error message would be a UX bug and
        // would make the e2e tests non-reproducible. Same input, same message, every time.
        let boxes = [
            svc("first", &["7000:80"]),
            svc("second", &["7000:81"]),
            svc("third", &["7000:82"]),
        ];
        let msg = match check_port_collisions(&boxes) {
            Err(Error::Compose(m)) => m,
            other => panic!("expected a collision, got {other:?}"),
        };
        for _ in 0..64 {
            match check_port_collisions(&boxes) {
                Err(Error::Compose(m)) => assert_eq!(m, msg, "message must be stable"),
                other => panic!("expected a collision, got {other:?}"),
            }
        }
        // And it names the FIRST conflicting pair in file order, not an arbitrary one.
        assert!(
            msg.contains("'first'") && msg.contains("'second'") && !msg.contains("'third'"),
            "should report the earliest pair: {msg:?}"
        );
    }

    #[test]
    fn every_spec_of_a_service_is_checked_not_just_the_first() {
        // A service's LAST port must be checked too (an early-exit bug would pass the first spec only).
        let boxes = [
            svc("multi", &["7100:80", "7101:81", "7102:82"]),
            svc("late", &["7102:83"]),
        ];
        assert_collides(&boxes, &["'multi'", "'late'", "7102/tcp"]);
    }

    #[test]
    fn a_malformed_spec_does_not_stop_the_scan() {
        // The `continue` on an unparseable spec must skip only THAT spec: a real collision after it is
        // still caught (a `return` there would silently disable the whole check).
        let boxes = [
            svc("a", &["bogus:spec:here:too", "7200:80"]),
            svc("b", &["7200:81"]),
        ];
        assert_collides(&boxes, &["'a'", "'b'", "7200/tcp"]);
    }
}

/// `kern stop --all` used to delete EVERY `kern-*.service` in the user's unit directory, because it
/// identified its own persistent boxes by file name. A unit the user wrote by hand was removed by an
/// unrelated `stop --all` - including the one `kern compose … systemd` tells them to write, which is
/// named exactly that way. Ownership is now read from the file, and these tests pin both marks.
#[cfg(test)]
mod managed_unit_ownership {
    use crate::commands::*;

    fn write(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).expect("test fixture");
        p
    }

    #[test]
    fn the_managed_systemd_unit_disables_systemds_start_rate_limit() {
        // REGRESSION: a persistent box's generated unit sets `Restart=always` + `RestartSec=1`. It MUST
        // also set `StartLimitIntervalSec=0`, or systemd's default (`StartLimitBurst=5` in 10s) leaves
        // the unit `failed` after a fast crash-loop - which with `RestartSec=1` happens in ~5s - and
        // `--restart always` then SILENTLY stops restarting, breaking the "restart on any exit,
        // indefinitely" contract and the up-for-days reliability this path exists for. Asserted on the
        // source because the unit is written to a FILE (a side effect), not returned, so there is no
        // value to assert without a `systemd` on the runner. Needle built via `concat!` so this test's
        // own text is not what it counts. Reads `start.rs`, where the unit writer lives: when the verbs
        // moved out of `mod.rs` this test FAILED with the needle missing rather than passing on an
        // empty search, which is the property a source-reading contract has to have.
        let src = include_str!("start.rs");
        let needle = concat!("StartLimitIntervalSec", "=0\\n\\n");
        assert!(
            src.contains(needle),
            "the managed systemd unit must carry StartLimitIntervalSec=0 before the [Service] section"
        );
    }

    #[test]
    fn persistent_supervision_falls_back_to_in_process_without_systemd() {
        use crate::commands::persistent_supervision;
        // (detached, persistent, has_pod, systemd_present) -> (use_systemd_unit, in_process_restart_always)
        // Standalone persistent + a systemd --user manager: systemd supervises (reboot-survival).
        assert_eq!(
            persistent_supervision(true, true, false, true),
            (true, false)
        );
        // Standalone persistent + NO systemd: THE FIX - fall back to the in-process supervisor so the box
        // still runs and restarts on any exit. Before this it errored on the unit install and never ran.
        assert_eq!(
            persistent_supervision(true, true, false, false),
            (false, true)
        );
        // A pod member is ALWAYS in-process, regardless of systemd (it needs the holder's namespace).
        assert_eq!(
            persistent_supervision(true, true, true, true),
            (false, true)
        );
        assert_eq!(
            persistent_supervision(true, true, true, false),
            (false, true)
        );
        // Not persistent (`on-failure`/`no`): neither always-path (on-failure is its own capped loop).
        assert_eq!(
            persistent_supervision(true, false, false, false),
            (false, false)
        );
        // Foreground persistent (rejected upstream): no systemd unit, no in-process always here either.
        assert_eq!(
            persistent_supervision(false, true, false, true),
            (false, false)
        );
    }

    #[test]
    fn only_units_kern_wrote_are_claimed() {
        let dir = std::env::temp_dir().join(format!("kern-unit-own-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("test fixture");

        // Written by kern today: carries the explicit marker.
        let marked = write(
            &dir,
            "kern-api.service",
            "[Unit]\nDescription=kern box api\nX-KernManagedBox=api\n[Service]\nExecStart=/bin/true\n",
        );
        assert!(is_kern_managed_unit(&marked));

        // Written by an OLDER kern: no marker, but the description kern has always used. It must stay
        // claimable, or upgrading would strand every already-installed persistent box.
        let legacy = write(
            &dir,
            "kern-old.service",
            "[Unit]\nDescription=kern box old\n[Service]\nExecStart=/bin/true\n",
        );
        assert!(is_kern_managed_unit(&legacy));

        // The unit `kern compose … systemd` emits: same NAME shape, not kern's to delete.
        let stack = write(
            &dir,
            "kern-web.service",
            "[Unit]\nDescription=kern compose stack web\n[Service]\nExecStart=/usr/bin/kern compose /srv/x.yml up\n",
        );
        assert!(
            !is_kern_managed_unit(&stack),
            "a stack unit is the user's file"
        );

        // Someone else's unit that happens to start with `kern-`.
        let stranger = write(
            &dir,
            "kern-backup.service",
            "[Unit]\nDescription=nightly backup\n[Service]\nExecStart=/usr/local/bin/backup\n",
        );
        assert!(!is_kern_managed_unit(&stranger));

        // Unreadable or absent: not ours. Never delete what cannot be verified.
        assert!(!is_kern_managed_unit(&dir.join("does-not-exist.service")));

        // Binary rubbish under a kern-ish name: not ours, and no panic.
        let binary = dir.join("kern-bin.service");
        std::fs::write(&binary, [0xff_u8, 0xfe, 0x00, 0x01]).expect("test fixture");
        assert!(!is_kern_managed_unit(&binary));

        // A marker buried in a huge file is still found up to the read cap, and beyond it the answer
        // is the safe one rather than a long read.
        let big = dir.join("kern-big.service");
        let mut body = String::from("[Unit]\nX-KernManagedBox=big\n");
        body.push_str(&"# padding\n".repeat(200));
        std::fs::write(&big, &body).expect("test fixture");
        assert!(is_kern_managed_unit(&big));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A verb the parser accepts but that neither the help nor the usage message names is a verb that
/// does not exist for the reader. `systemd` was exactly that, because the list was written by hand
/// in three places. There is one list now, and these tests anchor it from both sides.
#[cfg(test)]
mod compose_verbs_are_one_list {
    use crate::commands::*;

    #[test]
    fn every_listed_verb_parses_and_every_parsed_verb_is_listed() {
        let help = compose_verbs_help();
        for (name, action) in COMPOSE_VERBS {
            assert_eq!(
                ComposeAction::from_verb(name),
                Some(*action),
                "'{name}' e' in elenco ma il parser non lo accetta"
            );
            assert!(
                help.split('|').any(|v| v == *name),
                "'{name}' is accepted but does not appear in the help text: {help}"
            );
        }
        // The text must not announce anything the parser refuses.
        for v in help.split('|') {
            assert!(
                ComposeAction::from_verb(v).is_some(),
                "the help text announces '{v}', which the parser does not accept"
            );
        }
        // No duplicates: two entries with the same name would make the second unreachable.
        let mut names: Vec<&str> = COMPOSE_VERBS.iter().map(|(n, _)| *n).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            total,
            "un verbo compare due volte in COMPOSE_VERBS"
        );
    }

    #[test]
    fn an_unknown_verb_is_refused_rather_than_guessed() {
        for bad in ["", "UP", "upp", "systemctl", "--up", "up "] {
            assert!(
                ComposeAction::from_verb(bad).is_none(),
                "'{bad}' non deve essere interpretato come un verbo"
            );
        }
    }
}

/// The graceful stop waited out the whole grace period even when the box's init could not receive
/// the signal: a namespace PID 1 discards signals it has no handler for, so a `sleep` never dies of
/// SIGTERM. `kern stop` took 9013 ms instead of 2, and a `compose down` of four services would have
/// been 36 seconds.
#[cfg(test)]
mod stop_does_not_wait_for_the_impossible {
    use crate::commands::*;

    #[test]
    fn a_signal_the_init_cannot_catch_is_not_waited_for() {
        // This test process has a real SigCgt mask: whatever it holds, the function must read it
        // without panicking and answer consistently with /proc.
        let me = std::process::id() as i32;
        let status = std::fs::read_to_string(format!("/proc/{me}/status")).unwrap_or_default();
        let mask = status
            .lines()
            .find_map(|l| l.strip_prefix("SigCgt:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .unwrap_or(0);
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGUSR1] {
            let expected = mask & (1u64 << (sig - 1)) != 0;
            assert_eq!(
                init_catches_signal(me, sig),
                expected,
                "the verdict for signal {sig} must match SigCgt in /proc"
            );
        }
    }

    #[test]
    fn an_unknown_process_stays_on_the_patient_path() {
        // Not knowing must mean WAIT, not kill early: erring that way costs a wait, erring the
        // other way would cut a real shutdown in half.
        assert!(init_catches_signal(0, libc::SIGTERM), "invalid pid");
        assert!(init_catches_signal(-1, libc::SIGTERM), "negative pid");
        assert!(
            init_catches_signal(i32::MAX, libc::SIGTERM),
            "pid that does not exist: /proc unreadable, so we wait"
        );
        // A signal number out of range must not shift the bit past the mask.
        let me = std::process::id() as i32;
        assert!(init_catches_signal(me, 0));
        assert!(init_catches_signal(me, 65));
        assert!(init_catches_signal(me, -5));
    }
}

#[cfg(test)]
mod uninstall_only_removes_what_kern_installed {
    use crate::commands::*;

    #[test]
    fn only_the_file_an_installer_placed_is_this_verbs_to_delete() {
        // Identity, not path text: these need to be REAL files, which is the point. The previous version
        // of this test passed paths that did not exist and passed against string comparison, which is
        // exactly what let a symlinked install go unremoved.
        let base = std::env::temp_dir().join(format!("kern-inst-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        std::fs::create_dir_all(home.join(".local/bin")).unwrap();
        std::fs::create_dir_all(base.join("pkg")).unwrap();
        std::fs::create_dir_all(base.join("src/target/release")).unwrap();

        // 1. What an installer produces: a real binary at the install path.
        let installed = home.join(".local/bin/kern");
        std::fs::write(&installed, b"#!/bin/sh\n").unwrap();
        assert!(
            is_installed_binary(&installed, &home),
            "a binary at the install path must be removable"
        );

        // 2. A PACKAGED install: the install path is a symlink into a library directory, and
        // `current_exe()` hands us the resolved target. String comparison answered false here and
        // refused to remove a legitimate install; identity answers true.
        let real = base.join("pkg/kern");
        std::fs::write(&real, b"#!/bin/sh\n").unwrap();
        std::fs::remove_file(&installed).unwrap();
        std::os::unix::fs::symlink(&real, &installed).unwrap();
        assert!(
            is_installed_binary(&real, &home),
            "a symlinked install must still be recognised through its target"
        );

        // 3. What nobody asked us to touch: a build in a source tree, and a copy somebody placed by hand.
        let build = base.join("src/target/release/kern");
        std::fs::write(&build, b"#!/bin/sh\n").unwrap();
        assert!(
            !is_installed_binary(&build, &home),
            "a source-tree build must survive uninstall run from that tree"
        );
        let opt = base.join("pkg/kern-copy");
        std::fs::write(&opt, b"#!/bin/sh\n").unwrap();
        assert!(
            !is_installed_binary(&opt, &home),
            "a hand-placed copy is not an installation"
        );

        // 4. Another user's home is not this home.
        let other = base.join("other-home");
        std::fs::create_dir_all(other.join(".local/bin")).unwrap();
        let theirs = other.join(".local/bin/kern");
        std::fs::write(&theirs, b"#!/bin/sh\n").unwrap();
        assert!(
            !is_installed_binary(&theirs, &home),
            "another user's install is not ours to delete"
        );

        // 5. A path that does not exist cannot be identified, so it is not removable.
        assert!(!is_installed_binary(&base.join("gone"), &home));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_hardlinked_blob_is_counted_once_and_a_symlink_is_never_followed_out_of_the_tree() {
        let base = std::env::temp_dir().join(format!("kern-uninst-sz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("sub")).unwrap();
        std::fs::write(base.join("blob"), vec![0u8; 65536]).unwrap();
        let one = dir_bytes(&base);
        assert!(
            one >= 65536,
            "a 64 KiB file must account for at least its bytes, got {one}"
        );

        // The layer store hardlinks a blob shared between two images. Removing the tree frees those
        // blocks ONCE, so counting them twice would overstate what the user gets back - which is
        // exactly what this reported on a real cache before the fix (5.22 GiB claimed, 3.38 freed).
        std::fs::hard_link(base.join("blob"), base.join("sub/same-blob")).unwrap();
        assert_eq!(
            dir_bytes(&base),
            one,
            "a second link to the same inode must add nothing"
        );

        // A symlink pointing anywhere contributes 0: removal does not follow it either.
        std::os::unix::fs::symlink("/usr", base.join("link")).unwrap();
        assert_eq!(dir_bytes(&base), one, "a symlink must not be counted");

        // An unreadable or absent subtree contributes 0 rather than aborting the whole plan.
        assert_eq!(dir_bytes(&base.join("does-not-exist")), 0);
        let _ = std::fs::remove_dir_all(&base);
    }
}

#[cfg(test)]
mod config_verbs_are_defined_in_one_place {
    use crate::commands::*;

    #[test]
    fn a_verb_the_dispatch_does_not_know_is_an_error_not_a_silent_listing() {
        // The parser refuses an unknown verb first, so this is defence in depth against the two lists
        // drifting: a verb added there without a case here must fail loudly, because listing the
        // profiles and exiting 0 is indistinguishable from success.
        for stranger in ["show", "inspect", "ls", "", "LIST"] {
            let e = config_cmd(stranger, false, false);
            assert!(
                matches!(e, Err(Error::Usage(u)) if u == CONFIG_USAGE),
                "config_cmd({stranger:?}) must be a usage error, got {e:?}"
            );
        }
    }

    #[test]
    fn the_usage_string_names_every_verb_the_parser_accepts() {
        // The one place the verb set is written must actually list what works, or the error message
        // sends the reader to a verb that does not exist (or hides one that does).
        for verb in ["list", "add", "rm", "edit", "setup", "probe", "clear"] {
            assert!(
                CONFIG_USAGE.contains(verb),
                "the usage string does not mention `{verb}`: {CONFIG_USAGE}"
            );
        }
    }
}

/// `--plan` must preview every kind of profile a box can carry, not the one that was implemented
/// first.
///
/// It reported `vgpio:` device grants and nothing else, so a box attached to a CPU cap, a device and
/// a scratch disk previewed one of the three. The comment justifying the vgpio case said it exactly:
/// a preview that lists three mounts while saying nothing about `/dev/i2c-5` is not a preview of what
/// will be created. A 256M ceiling and a 48M disk are no different.
///
/// Asserted on the FUNCTION BODY rather than on behaviour because the output goes to stdout and the
/// resolvers need a config file on disk; the shape is what regresses when a fourth kind is added or
/// a third is dropped. Scoped to the body so this test's own text cannot satisfy it.
#[cfg(test)]
mod the_plan_previews_every_profile_kind {
    #[test]
    fn all_three_kinds_are_picked_and_resolved() {
        // `start.rs`, where `box_plan` lives since the verbs moved out of `mod.rs`. That move made this
        // test panic on the `else` below rather than silently pass, which is why it is written that way.
        let src = include_str!("start.rs");
        let Some(start) = src.find("pub fn box_plan") else {
            panic!("box_plan is gone; this contract test cannot find what it guards");
        };
        let body = &src[start..];
        let Some(end) = body.find("\n}\n") else {
            panic!("cannot find the end of box_plan");
        };
        let body = &body[..end];

        for kind in ["vcpu:", "vgpio:", "vdisk:"] {
            assert!(
                body.contains(&format!("pick(\"{kind}\")")),
                "box_plan no longer picks {kind} profiles out of the attached list, so a box \
                 carrying one previews without it"
            );
        }
        for resolver in ["resolve_vcpu", "resolve_vgpio", "resolve_vdisk"] {
            assert!(
                body.contains(resolver),
                "box_plan no longer calls {resolver}, so that kind is either unreported or \
                 reported from the raw config instead of the resolved values the launch uses"
            );
        }
        // Each kind must also report a failure to attach HERE rather than at launch, which is the
        // whole reason the plan resolves instead of printing the profile names back.
        // The FORMAT string, not the phrase: the doc comment above the function also contains
        // "cannot attach", and counting that made the first version of this assertion read 4.
        assert_eq!(
            body.matches("cannot attach: {e}").count(),
            3,
            "every kind must say why it cannot attach at PLAN time rather than at launch; found a \
             different number of Err arms that print it"
        );
    }
}
