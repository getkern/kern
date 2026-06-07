#![no_main]
//! Fuzz the in-process tar-header vetter (`check_layer_safe`'s core). It parses UNTRUSTED, already-
//! decompressed layer bytes at fixed offsets (name/prefix/linkname/size/typeflag, plus GNU L/K and
//! PAX overrides) to decide what may be extracted. It must never panic — no out-of-bounds slice, no
//! unbounded read/alloc — no matter how malformed or adversarial the bytes are.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kern_oci::__fuzz::tar_vet(data);
});
