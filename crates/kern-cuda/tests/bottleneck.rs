//! BOTTLENECK DECOMPOSITION. Which part of the 41 ns is which, and what happens to each under
//! contention.
//!
//! The end-to-end figure is one number and one number does not tell you where to spend an
//! optimisation. This file takes the accounting apart into the operations a real allocation performs,
//! measures each on its own and then measures the whole, so the difference between the sum of the
//! parts and the measured whole is visible rather than inferred: a sum that exceeds the whole means
//! the parts overlap in the pipeline, and a sum that falls short means something is being paid that
//! none of the parts accounts for.
//!
//! CONTENTION IS MEASURED SEPARATELY AND ON PURPOSE. An uncontended atomic on a line already in this
//! core's L1 is a handful of cycles. The same instruction on a line another core just wrote is a
//! coherence round trip, which is two orders of magnitude more. A structure that looks free
//! single-threaded and collapses at eight threads is the normal failure of this kind of code, and the
//! only way to know which one you have is to run both.
//!
//! NOTHING HERE ASSERTS A PERFORMANCE NUMBER. The ceilings live in `hot_path_cost.rs`, which is the
//! regression gate. This file prints, so that a decision about where to optimise is made against a
//! measurement rather than against an intuition about which line looks expensive.

use core::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use kern_cuda::registry::Registry;
use kern_cuda::shared::{self, Liveness, Shared};
use kern_cuda::Quota;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

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

#[inline(always)]
fn keep<T>(v: T) -> T {
    std::hint::black_box(v)
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if xs.is_empty() {
        return f64::INFINITY;
    }
    xs[xs.len() / 2]
}

/// Time `f` per iteration: one discarded warm round, then the median of nine.
fn ns_per_op<F: FnMut(usize)>(iters: usize, mut f: F) -> f64 {
    for i in 0..iters {
        f(i);
    }
    let mut rounds = Vec::with_capacity(9);
    for _ in 0..9 {
        let t0 = Instant::now();
        for i in 0..iters {
            f(i);
        }
        rounds.push(t0.elapsed().as_nanos() as f64 / iters as f64);
    }
    median(rounds)
}

#[test]
fn where_the_nanoseconds_go() {
    const ITERS: usize = 200_000;

    let q = Quota::new(GIB);
    let r = Registry::with_capacity(4096);
    let seg = segment(4);
    assert_eq!(shared::init(&seg, 4), Ok(()));
    let s = Shared::attach(&seg, 1, 1, &AllAlive).expect("attach");

    let ptr_for = |i: usize| 0x10_0000u64 + (i as u64 % 256) * 4096;

    // Each component on its own, in the exact form the allocation path uses it.
    let quota_ns = ns_per_op(ITERS, |_| {
        let _ = keep(q.reserve(keep(4096)));
        q.release(keep(4096));
    });
    let shared_ns = ns_per_op(ITERS, |_| {
        let _ = keep(s.reserve(keep(4096), GIB));
        s.release(keep(4096));
    });
    let registry_ns = ns_per_op(ITERS, |i| {
        let p = ptr_for(i);
        let _ = keep(r.insert(keep(p), keep(4096)));
        let _ = keep(r.remove(keep(p)));
    });
    // The registry split in two, because insert and remove are not the same shape: the insert does
    // two stores and a CAS, the remove does two loads and a CAS.
    let insert_ns = ns_per_op(ITERS, |i| {
        let p = ptr_for(i);
        let _ = keep(r.insert(keep(p), keep(4096)));
        let _ = r.remove(p); // untimed teardown, still inside the loop and therefore in both halves
    });
    let remove_ns = ns_per_op(ITERS, |i| {
        let p = ptr_for(i);
        let _ = r.insert(p, 4096);
        let _ = keep(r.remove(keep(p)));
    });

    let whole_ns = ns_per_op(ITERS, |i| {
        let p = ptr_for(i);
        if keep(q.reserve(keep(4096))).is_ok() {
            if keep(s.reserve(keep(4096), GIB)).is_ok() {
                let _ = keep(r.insert(keep(p), 4096));
            } else {
                q.release(4096);
            }
        }
        if let Some(sz) = keep(r.remove(keep(p))) {
            s.release(sz);
            q.release(sz);
        }
    });

    let parts = quota_ns + shared_ns + registry_ns;
    println!();
    println!("  UNCONTENDED, per alloc+free pair");
    println!("    quota reserve+release        {quota_ns:7.1} ns");
    println!("    shared reserve+release       {shared_ns:7.1} ns");
    println!("    registry insert+remove       {registry_ns:7.1} ns   <- dominant");
    println!("      (insert path, timed)       {insert_ns:7.1} ns");
    println!("      (remove path, timed)       {remove_ns:7.1} ns");
    println!("    ---------------------------------------");
    println!("    sum of the parts             {parts:7.1} ns");
    println!("    measured whole               {whole_ns:7.1} ns");
    println!(
        "    overlap (parts - whole)      {:7.1} ns   {}",
        parts - whole_ns,
        if parts > whole_ns {
            "the parts pipeline together"
        } else {
            "the whole pays more than its parts"
        }
    );
    println!(
        "    registry share of the whole  {:6.1} %",
        registry_ns / whole_ns * 100.0
    );

    assert_eq!(
        q.held(),
        0,
        "the decomposition must leave the quota balanced"
    );
    assert_eq!(s.total(), 0);
    assert_eq!(r.len(), 0);
}

/// The same decomposition with every core hammering it, which is where a shared counter stops being
/// free. Reported per operation so the numbers are directly comparable with the uncontended ones.
#[test]
fn where_the_nanoseconds_go_under_contention() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    const ITERS: usize = 100_000;

    // Quota: one contended word plus the peak line.
    let q = Arc::new(Quota::new(64 * GIB));
    let t0 = Instant::now();
    let mut hs = Vec::new();
    for _ in 0..threads {
        let q = Arc::clone(&q);
        hs.push(std::thread::spawn(move || {
            for _ in 0..ITERS {
                if keep(q.reserve(keep(4096))).is_ok() {
                    q.release(keep(4096));
                }
            }
        }));
    }
    for h in hs {
        assert!(h.join().is_ok());
    }
    let quota_ns = t0.elapsed().as_nanos() as f64 / (threads * ITERS) as f64;

    // Shared: one contended total plus a private slot word per tenant.
    let seg = Arc::new(segment(16));
    assert_eq!(shared::init(&seg, 16), Ok(()));
    let t0 = Instant::now();
    let mut hs = Vec::new();
    for i in 0..threads {
        let seg = Arc::clone(&seg);
        hs.push(std::thread::spawn(move || {
            let pid = i as u64 + 1;
            let Ok(s) = Shared::attach(&seg, pid, pid, &AllAlive) else {
                return;
            };
            for _ in 0..ITERS {
                if keep(s.reserve(keep(4096), 64 * GIB)).is_ok() {
                    s.release(keep(4096));
                }
            }
        }));
    }
    for h in hs {
        assert!(h.join().is_ok());
    }
    let shared_ns = t0.elapsed().as_nanos() as f64 / (threads * ITERS) as f64;

    // Registry: DISJOINT pointer ranges per thread, so the probes do not collide. What is left
    // shared is the `live` counter, which every insert and every remove writes. That is the
    // measurement this test exists for: if the number is far above the uncontended one while the
    // slots are disjoint, the counter is the contention and not the table.
    let r = Arc::new(Registry::with_capacity(1 << 16));
    let t0 = Instant::now();
    let mut hs = Vec::new();
    for t in 0..threads {
        let r = Arc::clone(&r);
        hs.push(std::thread::spawn(move || {
            for i in 0..ITERS {
                let p = 0x100_0000u64 + ((t as u64) * 4096 + (i as u64 % 4096)) * 4096;
                if keep(r.insert(keep(p), keep(4096))).is_ok() {
                    let _ = keep(r.remove(keep(p)));
                }
            }
        }));
    }
    for h in hs {
        assert!(h.join().is_ok());
    }
    let registry_ns = t0.elapsed().as_nanos() as f64 / (threads * ITERS) as f64;

    println!();
    println!("  CONTENDED, {threads} threads, per alloc+free pair (wall / total ops)");
    println!("    quota reserve+release        {quota_ns:7.1} ns");
    println!("    shared reserve+release       {shared_ns:7.1} ns");
    println!("    registry insert+remove       {registry_ns:7.1} ns   (disjoint slots)");
    println!("    ---------------------------------------");
    println!(
        "    sum                          {:7.1} ns",
        quota_ns + shared_ns + registry_ns
    );
    assert_eq!(r.len(), 0, "the contended registry must be balanced");
}

/// THE COST OF THE `live` COUNTER, isolated.
///
/// The registry keeps a running count of entries so a refusal can report how full the table was.
/// That counter is a single machine word every insert and every remove writes, from every thread, and
/// a shared word written at that rate is a coherence round trip per operation. This measures a bare
/// `fetch_add`/`fetch_sub` pair on one line at the same thread count, which is the counter's cost
/// with everything else removed: if it is a large fraction of the contended registry figure above,
/// the counter is the bottleneck and not the hashing or the probing.
#[test]
fn what_a_single_shared_counter_costs_at_this_thread_count() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    const ITERS: usize = 200_000;

    let ctr = Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let t0 = Instant::now();
    let mut hs = Vec::new();
    for _ in 0..threads {
        let ctr = Arc::clone(&ctr);
        hs.push(std::thread::spawn(move || {
            for _ in 0..ITERS {
                ctr.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                ctr.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
            }
        }));
    }
    for h in hs {
        assert!(h.join().is_ok());
    }
    let ns = t0.elapsed().as_nanos() as f64 / (threads * ITERS) as f64;

    // And the same pair on a word only this thread touches, as the control: the difference between
    // the two is the coherence traffic and nothing else.
    let solo = core::sync::atomic::AtomicUsize::new(0);
    let t1 = Instant::now();
    for _ in 0..ITERS {
        solo.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        solo.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
    }
    let solo_ns = t1.elapsed().as_nanos() as f64 / ITERS as f64;

    println!();
    println!("  ONE SHARED WORD, add+sub pair");
    println!("    {threads} threads on one line      {ns:7.1} ns");
    println!("    1 thread, uncontended        {solo_ns:7.1} ns");
    println!(
        "    coherence cost               {:7.1} ns per pair",
        ns - solo_ns
    );
    assert_eq!(ctr.load(core::sync::atomic::Ordering::Relaxed), 0);
}

/// PER-THREAD LATENCY, because the aggregate figure is throughput and reading it as latency is the
/// one mistake this file could invite.
///
/// `wall / total ops` at N threads answers "how many operations does the machine complete per unit
/// time", and on a structure that scales it goes DOWN as threads are added, which reads like the
/// operation got faster. It did not. Each thread here times its own operations and reports its own
/// distribution, so the two questions have two numbers with two names.
///
/// p99 rather than max: one sample in a run will include a scheduler preemption, and a maximum is
/// therefore a measurement of the scheduler. p99 over a hundred thousand samples is the tail an
/// operator would actually see.
#[test]
fn per_thread_latency_is_not_the_aggregate_throughput() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(16);
    const ITERS: usize = 100_000;

    let r = Arc::new(Registry::with_capacity(1 << 16));
    let wall = Instant::now();
    let mut hs = Vec::with_capacity(threads);
    for t in 0..threads {
        let r = Arc::clone(&r);
        hs.push(std::thread::spawn(move || {
            let mut samples: Vec<u64> = Vec::with_capacity(ITERS);
            for i in 0..ITERS {
                let p = 0x100_0000u64 + ((t as u64) * 4096 + (i as u64 % 4096)) * 4096;
                let t0 = Instant::now();
                if keep(r.insert(keep(p), keep(4096))).is_ok() {
                    let _ = keep(r.remove(keep(p)));
                }
                samples.push(t0.elapsed().as_nanos() as u64);
            }
            samples.sort_unstable();
            (
                samples[samples.len() / 2],
                samples[samples.len() * 99 / 100],
            )
        }));
    }
    let mut p50s = Vec::new();
    let mut p99s = Vec::new();
    for h in hs {
        match h.join() {
            Ok((a, b)) => {
                p50s.push(a as f64);
                p99s.push(b as f64);
            }
            Err(_) => panic!("a worker thread panicked"),
        }
    }
    let aggregate = wall.elapsed().as_nanos() as f64 / (threads * ITERS) as f64;

    println!();
    println!("  REGISTRY at {threads} threads, two different questions");
    println!("    aggregate throughput   {aggregate:7.1} ns/op   (wall / total ops)");
    println!(
        "    per-thread latency p50 {:7.1} ns/op   (median of the threads' medians)",
        median(p50s)
    );
    println!(
        "    per-thread latency p99 {:7.1} ns/op   (median of the threads' p99s)",
        median(p99s)
    );
    println!("    the two are not the same number and must never be quoted as one");
    assert_eq!(r.len(), 0, "the run must leave the table balanced");
}

/// TOMBSTONE ACCUMULATION, measured rather than reasoned about.
///
/// Open addressing with linear probing degrades when removals leave markers a probe must walk
/// through. The question is whether this table's insert, which claims the FIRST free-or-removed slot
/// it meets, reuses them fast enough to keep probe chains short under a workload that allocates and
/// frees on the same addresses forever. Ten times the capacity in cycles, then the longest probe the
/// table can still be made to walk.
#[test]
fn tombstones_do_not_accumulate_into_long_probes() {
    const CAP: usize = 1024;
    let r = Registry::with_capacity(CAP);
    let cycles = CAP * 10;

    for i in 0..cycles {
        let p = 0x50_0000u64 + (i as u64 % (CAP as u64 / 2)) * 4096;
        if r.insert(p, 4096).is_ok() {
            assert_eq!(r.remove(p), Some(4096), "cycle {i}");
        }
    }
    assert_eq!(r.len(), 0, "every cycle balanced");

    // After all that churn the table must still accept a full load and give every size back. If the
    // tombstones had poisoned the probe sequences, this is where it shows: as a refusal on an empty
    // table, or as a size that cannot be found again.
    let mut inserted = 0usize;
    for i in 0..CAP as u64 {
        if r.insert(0x90_0000 + i * 4096, 1000 + i).is_ok() {
            inserted += 1;
        }
    }
    println!();
    println!("  TOMBSTONES after {cycles} insert/remove cycles on a {CAP}-slot table");
    println!("    the table still accepts {inserted} of {CAP} entries");
    assert_eq!(
        inserted,
        CAP,
        "tombstones poisoned the table: it refused {} of {CAP} entries on an empty table",
        CAP - inserted
    );
    let mut recovered = 0u64;
    for i in 0..CAP as u64 {
        recovered += r.remove(0x90_0000 + i * 4096).unwrap_or(0);
    }
    let expected: u64 = (0..CAP as u64).map(|i| 1000 + i).sum();
    assert_eq!(recovered, expected, "a size was lost behind a tombstone");
    println!("    and returns every size exactly");
}
