//! THE COST OF ACCOUNTING, measured rather than asserted.
//!
//! The quota sits on the path of every device allocation a workload makes. An inference server
//! serving several models from one card makes a great many of them, so the number that matters is
//! not "is it fast" but "how many nanoseconds does one reservation add, and does that number stay
//! where it was". This file answers both: it prints the measurement so a reader sees the actual cost
//! on their machine, and it fails if the cost has moved by an order of magnitude.
//!
//! WHY THE CEILING IS LOOSE AND NOT TIGHT
//!     A tight bound on a timing test is a promise the machine cannot keep. CI runners are shared,
//!     boards are slow, and a test that fails when the host is busy gets muted, which is worse than
//!     no test. The bound here is set to catch the failure that actually happens to code like this:
//!     somebody adds a lock, a heap allocation or a syscall to the hot path, and the cost jumps from
//!     tens of nanoseconds to microseconds. Anything in between is noise this file refuses to
//!     pretend it can resolve.
//!
//! WHAT A NUMBER FROM THIS FILE IS NOT
//!     It is not the cost of a GPU allocation. `cuMemAlloc` on real hardware is microseconds at
//!     best. This measures only the accounting kern adds in front of it, which is the only part kern
//!     is responsible for and the only part that could be made slow by a bad edit here.

use kern_cuda::Quota;
use std::sync::Arc;
use std::time::Instant;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Anything above this and something structural has been added to the hot path.
///
/// Chosen against the measurement rather than the other way round: the uncontended pair costs tens of
/// nanoseconds on an x86 desktop, and a single uncontended mutex lock/unlock is around 20 ns while a
/// contended one, a heap allocation or a syscall is hundreds to thousands. 2000 ns leaves two orders
/// of magnitude of headroom for a slow board under load and still cannot be reached by a
/// lock-free, allocation-free pair.
const CEILING_NS: f64 = 2000.0;

/// Defeat the optimiser without a benchmark harness.
///
/// The measured code is a few atomic operations whose results are discarded, and a release build is
/// entitled to notice that and delete the loop. `std::hint::black_box` is the stable, documented way
/// to tell the compiler a value must be considered used. It is not a fence and does not perturb the
/// timing measurably; it only removes the compiler's licence to remove the work.
#[inline(always)]
fn keep<T>(v: T) -> T {
    std::hint::black_box(v)
}

/// Median of the per-round means, not the mean of everything.
///
/// One round in a set will occasionally include a scheduler preemption or a migration between cores,
/// and a mean carries that into the reported figure while a median discards it. This is the same
/// protocol `kern doctor` uses for the systemd scope toll, and for the same reason: the first sample
/// and the unlucky sample are measuring the machine, not the thing.
fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if xs.is_empty() {
        return f64::INFINITY;
    }
    xs[xs.len() / 2]
}

#[test]
fn an_uncontended_reserve_and_release_costs_nanoseconds() {
    const ROUNDS: usize = 9;
    const ITERS: usize = 200_000;
    let q = Quota::new(GIB);

    // One warm round, thrown away. It pays for the first touch of every cache line in the struct and
    // for the branch predictor having seen nothing yet, and quoting it would overstate the cost the
    // same way a cold `systemd-run` overstates the scope toll by 3.6x elsewhere in this project.
    for _ in 0..ITERS {
        let _ = keep(q.reserve(keep(4096)));
        q.release(keep(4096));
    }

    let mut per_round = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let t0 = Instant::now();
        for _ in 0..ITERS {
            let _ = keep(q.reserve(keep(4096)));
            q.release(keep(4096));
        }
        per_round.push(t0.elapsed().as_nanos() as f64 / ITERS as f64);
    }
    let ns = median(per_round);

    println!("reserve+release, uncontended: {ns:.1} ns per pair");
    assert_eq!(q.held(), 0, "the benchmark must leave the quota balanced");
    assert!(
        ns < CEILING_NS,
        "the accounting pair costs {ns:.1} ns, over the {CEILING_NS} ns ceiling. That is not a \
         slow machine, it is a lock, an allocation or a syscall on the hot path."
    );
}

/// The refusal path is on the hot path too, and on a workload that is sitting against its cap it is
/// the ONLY path. A cap that made the failing case expensive would punish exactly the tenant who is
/// already constrained.
#[test]
fn a_refusal_costs_nanoseconds_too() {
    const ROUNDS: usize = 9;
    const ITERS: usize = 200_000;
    let q = Quota::new(MIB);
    let _ = q.reserve(MIB); // full, so every reservation below is refused

    for _ in 0..ITERS {
        let _ = keep(q.reserve(keep(4096)));
    }

    let mut per_round = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let t0 = Instant::now();
        for _ in 0..ITERS {
            let _ = keep(q.reserve(keep(4096)));
        }
        per_round.push(t0.elapsed().as_nanos() as f64 / ITERS as f64);
    }
    let ns = median(per_round);

    println!("refused reservation:         {ns:.1} ns each");
    assert_eq!(q.held(), MIB, "a refusal must not move the counter");
    assert!(
        ns < CEILING_NS,
        "a refused reservation costs {ns:.1} ns, over the {CEILING_NS} ns ceiling"
    );
}

/// A zero-byte allocation is legal in CUDA and takes the early return, so it must be cheaper than a
/// real one. Asserted as an ORDERING between two measurements on the same machine in the same run,
/// which is a claim a loaded host cannot break, rather than as an absolute number, which it could.
#[test]
fn the_zero_byte_early_return_is_cheaper_than_a_real_reservation() {
    const ITERS: usize = 400_000;
    let q = Quota::new(GIB);

    for _ in 0..ITERS {
        let _ = keep(q.reserve(keep(0)));
        let _ = keep(q.reserve(keep(4096)));
        q.release(keep(4096));
    }

    let t0 = Instant::now();
    for _ in 0..ITERS {
        let _ = keep(q.reserve(keep(0)));
    }
    let zero_ns = t0.elapsed().as_nanos() as f64 / ITERS as f64;

    let t1 = Instant::now();
    for _ in 0..ITERS {
        let _ = keep(q.reserve(keep(4096)));
        q.release(keep(4096));
    }
    let real_ns = t1.elapsed().as_nanos() as f64 / ITERS as f64;

    println!("zero-byte reservation:       {zero_ns:.1} ns  (real pair: {real_ns:.1} ns)");
    assert!(
        zero_ns < real_ns,
        "the zero-byte early return ({zero_ns:.1} ns) is not cheaper than a real reservation \
         ({real_ns:.1} ns), so it is not an early return any more"
    );
}

/// Contention is where a lock-free design earns its keep, and where it can still be slow: a CAS loop
/// under heavy contention retries, and retries cost. Measured on every core the machine has, and
/// reported per operation so the number is comparable with the uncontended one above.
///
/// The assertion is deliberately about the ORDER OF MAGNITUDE and not about scaling. A CAS loop on
/// one cache line does not scale linearly with cores and is not supposed to: what must hold is that
/// contention degrades it, rather than converting it into something that blocks.
#[test]
fn contended_reservations_stay_within_an_order_of_magnitude() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    const ITERS: usize = 100_000;
    let q = Arc::new(Quota::new(GIB));

    let t0 = Instant::now();
    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let q = Arc::clone(&q);
        handles.push(std::thread::spawn(move || {
            for _ in 0..ITERS {
                if keep(q.reserve(keep(4096))).is_ok() {
                    q.release(keep(4096));
                }
            }
        }));
    }
    for h in handles {
        // No `unwrap`: a thread that panicked is a test failure, reported as one rather than as a
        // second panic inside the harness.
        assert!(h.join().is_ok(), "a worker thread panicked");
    }
    let total_ops = (threads * ITERS) as f64;
    let ns = t0.elapsed().as_nanos() as f64 / total_ops;

    println!("reserve+release, {threads} threads:  {ns:.1} ns per pair (wall / total ops)");
    assert_eq!(q.held(), 0, "contended run must leave the quota balanced");
    assert!(
        ns < CEILING_NS,
        "under {threads}-way contention a pair costs {ns:.1} ns, over the {CEILING_NS} ns ceiling"
    );
}

/// THE MEASUREMENT THAT JUSTIFIES THE LAYOUT. The struct puts `held` on its own cache line so that
/// the write every reservation makes cannot invalidate the line holding `quota`, which every
/// reservation reads. This does not attempt to prove the separation helps by a specific percentage,
/// which would be a benchmark of the host's cache hierarchy; it proves the weaker claim that
/// survives on any machine: a read-mostly field can be read by many threads while another thread
/// hammers the hot field, without the readers being starved.
#[test]
fn readers_of_the_cold_fields_are_not_starved_by_the_hot_one() {
    let q = Arc::new(Quota::new(GIB));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let writer = {
        let q = Arc::clone(&q);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if q.reserve(4096).is_ok() {
                    q.release(4096);
                }
            }
        })
    };

    const ITERS: usize = 200_000;
    let t0 = Instant::now();
    for _ in 0..ITERS {
        let _ = keep(q.limit());
    }
    let ns = t0.elapsed().as_nanos() as f64 / ITERS as f64;

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(writer.join().is_ok(), "the writer thread panicked");

    println!("limit() read while another thread writes held: {ns:.1} ns");
    assert!(
        ns < CEILING_NS,
        "reading the ceiling while the hot field is written costs {ns:.1} ns, over {CEILING_NS} ns"
    );
}

// ── the cross-process path ───────────────────────────────────────────────────────────────────────
//
// The shared total is a second hot path and a more expensive one: a reservation touches a word every
// other tenant on the host is also writing, so the CAS contends across processes rather than across
// threads of one. Measured here over a plain `Vec`, which is the same code the mapping runs, so the
// number is the ALGORITHM's cost with the page-fault and syscall costs of the mapping excluded. Those
// are paid once at attach, not per reservation, and measuring them here would hide the thing this
// file exists to watch.

use core::sync::atomic::AtomicU64;
use kern_cuda::shared::{self, Liveness, Shared};

struct AllAlive;
impl Liveness for AllAlive {
    fn alive(&self, _pid: u64, _start: u64) -> bool {
        true
    }
}

fn segment(slots: usize) -> Vec<AtomicU64> {
    (0..shared::words_for(slots))
        .map(|_| AtomicU64::new(0))
        .collect()
}

#[test]
fn a_shared_reserve_and_release_costs_nanoseconds() {
    const ROUNDS: usize = 9;
    const ITERS: usize = 200_000;
    let seg = segment(4);
    assert_eq!(shared::init(&seg, 4), Ok(()));
    let s = Shared::attach(&seg, 1, 1, &AllAlive).expect("attach");

    for _ in 0..ITERS {
        let _ = keep(s.reserve(keep(4096), GIB));
        s.release(keep(4096));
    }

    let mut per_round = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let t0 = Instant::now();
        for _ in 0..ITERS {
            let _ = keep(s.reserve(keep(4096), GIB));
            s.release(keep(4096));
        }
        per_round.push(t0.elapsed().as_nanos() as f64 / ITERS as f64);
    }
    let ns = median(per_round);

    println!("shared reserve+release:      {ns:.1} ns per pair (uncontended)");
    assert_eq!(
        s.total(),
        0,
        "the benchmark must leave the segment balanced"
    );
    assert_eq!(s.held(), 0, "and the slot with it");
    assert!(
        ns < CEILING_NS,
        "a shared pair costs {ns:.1} ns, over the {CEILING_NS} ns ceiling"
    );
}

/// Several tenants hammering ONE shared word, which is the worst case the design has: unlike the
/// per-process quota, this line cannot be split up, because a single total is the entire point.
#[test]
fn shared_reservations_stay_within_an_order_of_magnitude_under_contention() {
    let tenants = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    const ITERS: usize = 100_000;
    let seg = Arc::new(segment(16));
    assert_eq!(shared::init(&seg, 16), Ok(()));

    let t0 = Instant::now();
    let mut handles = Vec::with_capacity(tenants);
    for i in 0..tenants {
        let seg = Arc::clone(&seg);
        handles.push(std::thread::spawn(move || {
            let pid = i as u64 + 1;
            let Ok(s) = Shared::attach(&seg, pid, pid, &AllAlive) else {
                return;
            };
            for _ in 0..ITERS {
                if keep(s.reserve(keep(4096), GIB)).is_ok() {
                    s.release(keep(4096));
                }
            }
        }));
    }
    for h in handles {
        assert!(h.join().is_ok(), "a tenant thread panicked");
    }
    let ns = t0.elapsed().as_nanos() as f64 / (tenants * ITERS) as f64;

    println!("shared pair, {tenants} tenants:      {ns:.1} ns per pair (wall / total ops)");
    assert!(
        ns < CEILING_NS,
        "under {tenants}-way contention a shared pair costs {ns:.1} ns, over {CEILING_NS} ns"
    );
}
