#![no_main]
//! Fuzz the dependency-free registry-JSON string scanner. A registry can return any bytes, so the
//! scanner must never panic - in particular it must never slice a `&str` at a non-char boundary.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The scanner works on `&str`; feed it any input that is valid UTF-8 (the lossy path can't
    // produce boundary panics the strict path wouldn't).
    if let Ok(s) = std::str::from_utf8(data) {
        kern_oci::__fuzz::json_walk(s);
    }
});
