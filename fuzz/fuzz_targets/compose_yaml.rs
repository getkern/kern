#![no_main]
//! Fuzz the compose-file parser. A `docker-compose.yml` (or kern TOML compose) is UNTRUSTED input —
//! it comes straight out of a third-party repo the user just cloned. The hand-rolled YAML-lite/TOML
//! parser walks bytes, slices `&str`, tracks an indentation stack and inline-table/list nesting, and
//! interpolates `${VAR}` — all of which must NEVER panic (no out-of-bounds slice, no non-char-boundary
//! cut, no stack overflow from pathological nesting, no unbounded alloc) no matter how malformed or
//! adversarial the bytes are. On success there is a second invariant: the parse output must be a
//! well-formed graph, so `topo_order` (the other pure fn that runs on it before anything is spawned)
//! must not panic either — at worst it returns an `Err` (a dependency cycle).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser works on `&str`; feed it any valid UTF-8. A parse failure is a normal outcome
    // (the file is garbage) — only a panic is a bug.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(boxes) = kern_compose::parse(s) {
            // Second invariant: a successfully-parsed stack must always be topo-orderable-or-cycle,
            // never a panic — this runs before any box is started.
            let _ = kern_compose::topo_order(&boxes);
        }
    }
});
