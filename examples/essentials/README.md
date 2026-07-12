# Essential workflows

The everyday container tasks — a throwaway box, a service on a port, your code
in a clean image, hard resource caps — daemonless, rootless, in one ~1.5 MB binary.

| Task | kern |
|---|---|
| Run a one-off command in a clean image | `kern box demo --image alpine -- echo hi` |
| An interactive, throwaway shell | `kern box dev --image alpine -it -- sh` |
| A service published to the host | `kern box web -d -p 8080:80 …` |
| Run against your own code, clean image | `kern box ci --image node -v "$PWD:/src" -w /src -- npm test` |
| Hard CPU / memory caps | `kern box … --memory 512m --cpus 1.5` |
| Observe & manage | `kern ps` · `exec` · `logs` · `stop` |
| A multi-box stack | `kern compose stack.toml up` |

## Runnable scripts

| Script | What it runs |
|---|---|
| [run.sh](run.sh) | A one-off command in a throwaway box |
| [service.sh](service.sh) | A service published to the host |
| [mount-and-test.sh](mount-and-test.sh) | A command against your files in a clean image |
| [limits.sh](limits.sh) | A box under kernel-enforced CPU / memory caps |

```sh
cargo build --release            # then: export PATH="$PWD/target/release:$PATH"
sh examples/essentials/run.sh
```

kern runs OCI images; build them with your usual image builder, then `kern box --image`.

Trust model: [../../SECURITY.md](../../SECURITY.md) · timings: [../../BENCHMARKS.md](../../BENCHMARKS.md).
