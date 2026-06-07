# kern-side issue: `kern stop` does not reliably kill a CPU-bound box (kills the pgid, not the pidns PID 1)

**Severity:** medium (correctness / resource leak; also weakens any density claim under stress)
**Found by:** the Python binding (`kern_sandbox`) — a timed-out CPU-bound box survived `kern stop`.

## Summary

`kern stop` signals the **supervisor's process group** (`kill(-b.pid, SIGKILL)`), not the box's
**PID-namespace init**. When the box's PID 1 is not in that process group — e.g. a foreground
`kern box` launched by another process (the binding), where the layout differs from the detached
`setsid`-ed supervisor the code assumes — the SIGKILL does not reach the workload, and a CPU-bound
box (`while True: pass`) keeps running. `kern stop` still prints `stopped '<name>'`, so it **reports
success while the box is alive**.

## Where

`crates/kern-cli/src/commands/mod.rs`, in `stop()`:

```rust
// Otherwise: the supervisor `setsid`-ed, so its pgid == its pid.
if !stop_managed_unit(&b.name) {
    unsafe { libc::kill(-b.pid, libc::SIGKILL) };   // <-- kills the pgid of b.pid
}
```

The assumption "the supervisor setsid-ed, so pgid == pid" does not hold for every launch shape. The
registry entry already carries `inst.pid1` (the box's PID-namespace init), and the `--timeout`
watchdog path already does the right thing (`signal_box(pidfd, pid1, SIGKILL)` at
`mod.rs:~1893/1993`) — `stop` just doesn't use it.

## Fix

Kill the box's **PID-namespace init** directly. The kernel guarantees that the death of a
PID-namespace's PID 1 tears down the *entire* namespace: no process in it can survive, and none can
escape by `setsid` (`setsid` changes the session/process-group, not the PID namespace). So:

```rust
if !stop_managed_unit(&b.name) {
    // SIGKILL the box's PID-namespace init — the kernel reaps the whole namespace. Prefer a pidfd
    // (race-free) as the watchdog path already does; fall back to the recorded pid1.
    let pid1 = if b.pid1 > 0 { b.pid1 } else { /* child_of(b.pid) */ };
    unsafe { libc::kill(pid1, libc::SIGKILL) };
    // (optionally still kill(-b.pid) to sweep the supervisor/pgroup)
}
```

This closes the `setsid` + ignore-SIGTERM survival case at the root, and lets a caller (the binding)
rely on `kern stop` as a reliable teardown instead of a best-effort multi-step dance.

## Binding-side mitigation until then (already shipped)

`kern_sandbox` tears a timed-out box down defensively — `kern stop` → `killpg(SIGKILL)` →
`proc.kill()` — with a **bounded** reader-join so the call never hangs. A box that survives all three
lingers at most `timeout_s + 5` (kern's own `--timeout` backstop reaps it), so the leak is *bounded*,
not unbounded. This kern-side fix removes the need for the dance and the bounded leak.
