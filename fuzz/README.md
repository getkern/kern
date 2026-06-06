# Fuzzing

Coverage-guided fuzzing of the code that parses **untrusted input from a container registry** — the
OCI-extraction attack surface. Built with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
(libFuzzer). This is its own workspace, so the nightly + sanitizer toolchain never touches the normal
build or CI.

## Targets

| target | what it checks |
|--------|----------------|
| `oci_json` | The dependency-free registry-JSON string scanner never panics on arbitrary bytes (no non-char-boundary `&str` slice, no unbounded read). |
| `tar_member_path` | **Property:** whenever the layer-extraction guard deems a tar member path safe, an independent lexical normalization agrees it cannot escape the rootfs. A path that escapes but is passed is a crash. |

## Run

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

# fuzz one target (Ctrl-C to stop)
cargo +nightly fuzz run oci_json
cargo +nightly fuzz run tar_member_path

# time-boxed (what CI/regression uses)
cargo +nightly fuzz run oci_json -- -max_total_time=60
```

A crash is written to `fuzz/artifacts/<target>/`; reproduce it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>`.

The fuzzing surface is `kern_oci::__fuzz` (`#[doc(hidden)]`, not part of the public API).
