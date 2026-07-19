# Fuzzing

Coverage-guided fuzzing of the code that parses **untrusted input**: a container registry's
OCI-extraction surface, and the compose file a user just cloned from a third-party repo. Built with
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). This is its own workspace, so the
nightly + sanitizer toolchain never touches the normal build or CI.

## Targets

| target | what it checks |
|--------|----------------|
| `oci_json` | The dependency-free registry-JSON string scanner never panics on arbitrary bytes (no non-char-boundary `&str` slice, no unbounded read). |
| `tar_member_path` | **Property:** whenever the layer-extraction guard deems a tar member path safe, an independent lexical normalization agrees it cannot escape the rootfs. A path that escapes but is passed is a crash. |
| `tar_vet` | The in-process tar-header vetter (`check_layer_safe`'s core) never panics on arbitrary decompressed layer bytes, no OOB slice, no unbounded read/alloc, however malformed the ustar/GNU-long/PAX headers are. |
| `compose_yaml` | The hand-rolled compose parser (`kern_compose::parse`, YAML-lite + kern TOML) never panics on an arbitrary `docker-compose.yml`, no OOB/non-char-boundary slice, no stack overflow from pathological nesting, no unbounded alloc. **Property:** a successful parse is always topo-orderable-or-cycle, so `topo_order` never panics either. |

## Run

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

# fuzz one target (Ctrl-C to stop)
cargo +nightly fuzz run oci_json
cargo +nightly fuzz run compose_yaml

# time-boxed (what CI/regression uses)
cargo +nightly fuzz run oci_json -- -max_total_time=60
```

A crash is written to `fuzz/artifacts/<target>/`; reproduce it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>`.

The OCI fuzzing surface is `kern_oci::__fuzz` (`#[doc(hidden)]`, not part of the public API);
`compose_yaml` fuzzes the ordinary public entry points `kern_compose::{parse, topo_order}`.
