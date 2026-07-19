# What the type system buys you for kernel security

*How kern turns a class of sandbox-escape ordering bug into a compile error.*

Sandboxes are made of ordering. You unshare namespaces, mount a new root, `pivot_root` into it,
drop capabilities, seal the filesystem, and `exec` the workload. Get the *set* of operations right
but the *order* wrong and the box still "works" in every test you run, until the one arrangement
of steps that leaves a seam something can slip through.

One of those orderings in [kern](https://github.com/getkern/kern) is the read-only root. `kern box
--read-only` runs a workload on a root filesystem it cannot write to. Under the hood that's three
steps, and they have to happen in this order:

1. **mount** the new root (an overlay, a bind, or a tmpfs),
2. **pivot_root** into it (kern makes an `.old_root`, pivots, and unmounts the old world),
3. **remount** the root **read-only**.

Step 3 has to be last. The root must be writable while kern sets it up, creating `.old_root`,
wiring `/dev`, mounting volumes, and it must be the *pivoted* root that gets sealed, not some
earlier mount. Remount read-only too early and you either break setup or seal the wrong thing: a
weaker boundary that still passes a happy-path test.

The usual way you defend an ordering like this is discipline: write the steps in the right order,
leave a comment, maybe add a test that asserts the recorded sequence. That's a test *you hope you
wrote*, and that the next contributor hopes they didn't break. It's exactly the kind of invariant
that rots.

## Make the illegal state unrepresentable

kern encodes the ordering in the type system instead. The rootfs is a value parameterized by *what
has happened to it so far*:

```rust
pub struct Mounted;       // root is mounted, not yet pivoted
pub struct OldRootReady;  // pivoted in
pub struct ReadOnly;      // sealed, terminal

pub struct Rootfs<S> {
    root: String,
    _state: PhantomData<S>,
}
```

Each step *consumes* the current state and returns the next one:

```rust
impl Rootfs<Mounted> {
    // step 1, mount the new root
    pub fn mount<M: MountOps>(ops: &mut M, mode: MountMode, root: &str)
        -> Result<Rootfs<Mounted>, Error> { /* ops.mount(...) */ }

    // step 2, consumes Mounted, yields OldRootReady
    pub fn create_old_root<M: MountOps>(self, ops: &mut M)
        -> Result<Rootfs<OldRootReady>, Error> { /* ops.pivot(...) */ }
}

impl Rootfs<OldRootReady> {
    // step 3, exists ONLY on OldRootReady
    pub fn into_readonly<M: MountOps>(self, ops: &mut M)
        -> Result<Rootfs<ReadOnly>, Error> { /* ops.remount_ro("/") */ }
}
```

`into_readonly` is implemented on `Rootfs<OldRootReady>` and nowhere else. There is no
`into_readonly` on `Rootfs<Mounted>`. So "remount read-only before the pivot" isn't a bug you catch. It's a sentence you can't write:

```rust
// does NOT compile, there is no `into_readonly` on Rootfs<Mounted>
Rootfs::mount(&mut ops, MountMode::Bind, "/r")?
    .into_readonly(&mut ops);
//   ^^^^^^^^^^^^ error[E0599]: no method named `into_readonly` found for
//               struct `Rootfs<Mounted>` in the current scope
```

The legal order is the only one that typechecks:

```rust
Rootfs::mount(&mut ops, MountMode::Overlay, root)?
    .create_old_root(&mut ops)?   // pivot first
    .into_readonly(&mut ops)?;    // seal last
```

An entire class of ordering bug moves from "hope the test exists" to "the code doesn't build."

## Proving the guarantee can't quietly decay

A typestate is only worth something if it can't rot, someone adds a convenience
`impl Rootfs<Mounted> { fn into_readonly … }` and the door's open again. So the guarantee itself is
a test. kern ships a `compile_fail` doctest:

```rust
/// ```compile_fail
/// use kern_isolation::{MountMode, Recorder, Rootfs};
/// let mut ops = Recorder::default();
/// let _ = Rootfs::mount(&mut ops, MountMode::Bind, "/r")
///     .unwrap()
///     .into_readonly(&mut ops);   // must NOT compile
/// ```
```

`cargo test` asserts that this snippet *fails to compile*. If a future change ever makes the
read-only step reachable before the pivot, the snippet starts compiling and the test goes red. The
invariant is enforced by CI, not by anyone's memory.

## The same code drives tests and production

One more move makes this cheap. The steps don't call the mount syscalls directly, they call a
trait:

```rust
pub trait MountOps {
    fn mount(&mut self, src: &str, dst: &str, fstype: &str, flags: u64) -> Result<(), Error>;
    fn pivot(&mut self, new_root: &str, old_root: &str) -> Result<(), Error>;
    fn remount_ro(&mut self, target: &str) -> Result<(), Error>;
}
```

Two implementations. `RealMounts` performs the actual syscalls. `Recorder` just appends a string
per call. Production runs the typestate chain over `RealMounts`; the test suite runs the *same
chain* over `Recorder` and asserts the recorded sequence byte-for-byte:

```
mount(overlay,/root,overlay,0x0)
pivot(/root,/root/.old_root)
remount_ro(/)
```

So the ordering the type system enforces and the ordering that actually hits the kernel are the
same code path, not a model of it. The guarantee isn't decorative.

## Being honest about what it buys

Here's the part worth saying plainly, because it's the first thing a skeptic should ask: **the
typestate enforces the *order* of the steps, not the *correctness* of each step.**
`RealMounts::remount_ro` still has to pass the right flags; the seccomp filter still has to be
right; the whole thing still rides on the host kernel, and a kernel privilege-escalation bug is
still an escape. The type system doesn't make kern a hypervisor, and it doesn't turn a shared-kernel
sandbox into a microVM. (kern is explicit about that boundary: it's the right tool for your own or
semi-trusted code, CI, dev, edge, your own agents' code, not actively hostile multi-tenant
workloads, where you want a microVM.)

What it *does* buy is specific and real: one category of "the steps ran in the wrong order" bug,
the kind that survives review and slips past happy-path tests, is gone at compile time, and stays
gone because CI proves it. For security-critical sequencing, that's a good trade: a few marker
structs and a `PhantomData` in exchange for an invariant you cannot forget to check.

The lesson isn't "use typestates everywhere." It's this: when the *order* of a sequence is
load-bearing for safety, the order is something the type system can hold for you, so a reviewer,
and every future contributor, doesn't have to.

---

*kern is a fast, daemonless Linux sandbox & virtual-resource runtime, one ~1.6 MB static binary,
one Rust dependency (`libc`). The mount-ordering typestate is `Rootfs<S>` in the `kern-isolation`
crate. Code, benchmarks, and an honest account of the security boundary:
[github.com/getkern/kern](https://github.com/getkern/kern).*
