#![no_main]
//! Fuzz the tar-member-path escape check with a *property*: whenever kern deems a path safe to
//! extract, an independent lexical normalization must agree it cannot escape the rootfs. kern being
//! stricter (rejecting a path that wouldn't escape) is fine; the dangerous direction - kern passing
//! a path that DOES escape - panics the target, which libFuzzer records as a crash.
use libfuzzer_sys::fuzz_target;
use std::path::{Component, Path};

/// Independent check: does joining `p` onto a rootfs escape it? Absolute paths and any leading
/// `..` (a component that pops above the root) escape; `a/../b` stays inside and does not.
fn escapes_root(p: &str) -> bool {
    let path = Path::new(p);
    if path.is_absolute() {
        return true;
    }
    let mut depth: i32 = 0;
    for c in path.components() {
        match c {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return true,
        }
    }
    false
}

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = std::str::from_utf8(data) {
        let flagged_unsafe = kern_oci::__fuzz::unsafe_member_path(p);
        if !flagged_unsafe && escapes_root(p) {
            panic!("unsafe_member_path passed an escaping path: {p:?}");
        }
    }
});
