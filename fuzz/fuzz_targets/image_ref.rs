#![no_main]
//! Fuzz the image-reference normalizer that every cache key, sidecar name and lookup now goes
//! through. A reference is attacker-influenced input: it arrives from a `docker-compose.yml`, a
//! `FROM` line, or a `--image` flag, and downstream it becomes a FILE NAME. The properties below are
//! the ones the rest of the code relies on, so a counter-example here is a real defect, not a
//! curiosity.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let n = kern_oci::normalize_ref(s);

    // 1. Idempotent. `sanitize_ref` calls it, and so may a caller that already did: applying it
    //    twice must not append a second `:latest`, which would split one image into two keys again.
    assert_eq!(kern_oci::normalize_ref(&n), n, "not idempotent for {s:?}");

    // 2. It only ever APPENDS the default tag. It must never drop, reorder or rewrite what the user
    //    wrote: the reference still has to name the same image at the registry.
    assert!(
        n == s || n == format!("{s}:{}", kern_oci::DEFAULT_TAG),
        "rewrote {s:?} into {n:?}"
    );

    // 3. No new path separator, and no new `..`. The result is fed to `sanitize_ref`, whose whole
    //    job is producing a single traversal-free path component; a normalizer that could introduce
    //    either would be attacking the very guard that runs after it.
    assert!(
        n.matches('/').count() == s.matches('/').count(),
        "changed the slash count of {s:?}"
    );
    assert!(
        n.matches("..").count() == s.matches("..").count(),
        "introduced '..' into {s:?}"
    );

    // 4. Normalizing must not change how the reference RESOLVES. If the two disagree, kern would
    //    cache under one identity and download another.
    if !s.is_empty() {
        assert_eq!(
            kern_oci::__fuzz::parse_ref_pub(s).ok(),
            kern_oci::__fuzz::parse_ref_pub(&n).ok(),
            "normalizing {s:?} changed how it resolves"
        );
    }
});
