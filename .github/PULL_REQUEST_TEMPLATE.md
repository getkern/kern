## What & why


## Checklist

Everything CI runs, in the order it runs it. A green local box is the point: the `docs` step used to
be absent from this list and a contributor could tick every line and still be reddened by it.

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --all-targets --all-features` clean (CI builds with `-D warnings`)
- [ ] `cargo test --all` green (HW-gated tests skip gracefully, with the reason)
- [ ] `python3 scripts/no-ai-slop.py`
- [ ] `python3 scripts/stale-numbers.py` (a re-measured figure has to be updated in EVERY file)
- [ ] `python3 scripts/test-count.py` (the README states the count of all three suites)
- [ ] `cargo deny check` and `cargo audit`
- [ ] No em-dash (U+2014) anywhere. Check under `LC_ALL=C.UTF-8`: under `LC_ALL=C` the grep errors
      to stderr and reports zero, which is a false green
- [ ] Sandbox/OCI change? characterization stays green + real-syscall test added/kept
- [ ] Security fixtures are synthetic, minimal, self-contained (no private paths/payloads)
- [ ] CHANGELOG updated
- [ ] I agree to the CLA (CLA.md)
