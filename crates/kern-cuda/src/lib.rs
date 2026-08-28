//! COOPERATIVE VRAM QUOTA, the accounting engine.
//!
//! One question, answered without allocating and without taking a lock: *may this allocation of
//! `size` bytes proceed under the quota this process was given?* Everything else about GPU slicing
//! sits on top of this, and nothing here knows what a GPU is.
//!
//! WHAT THIS IS NOT
//!     A boundary. A quota implemented in userspace is bypassed by any tenant that reaches the driver
//!     without going through the library the quota lives in, and `pentest/pentest-gpu-claims.sh`
//!     demonstrates exactly that on every machine this project can reach. What a cooperative quota IS
//!     worth is density, fairness, accidental-overcommit accounting and the ability to pack several of
//!     your own models onto one card. Those are real and they are what this engine serves.
//!     [`SECURITY.md`](../../../SECURITY.md) states the distinction before any claim.
//!
//! WHY IT HAS TO BE THIS FAST
//!     A reservation happens on every device allocation a workload makes, and an inference server
//!     makes a great many. If the accounting cost were microseconds it would show up in a token rate.
//!     The design constraint is therefore an upper bound in NANOSECONDS on the uncontended path, and
//!     the bound is measured in `tests/` rather than asserted here.
//!
//! HOW THE COST IS KEPT THERE
//!     No allocation: the whole state is three `u64`-sized atomics in a struct the caller owns.
//!     No lock: reservation is a compare-and-swap loop, so a thread that loses a race retries rather
//!     than blocks, and a thread that is descheduled mid-operation blocks nobody.
//!     No syscall: nothing here reads a file, a clock or the environment.
//!
//! THE ONE THING A CAS LOOP MUST GET RIGHT
//!     The check and the commit have to be the SAME atomic step. Reading the total, deciding it fits,
//!     and then adding is a race with a window: two threads each read 1 GiB used against a 2 GiB
//!     quota, each decide their 512 MiB fits, and both commit, leaving 2 GiB used from a 1 GiB start.
//!     `compare_exchange` closes that by making the commit fail when the value moved, which sends the
//!     loser back to re-read and re-decide against the new total.

// `deny` and not `forbid`, and the difference is one module. The accounting is unsafe-free and stays
// that way; turning a `mmap`ed region into a `&[AtomicU64]` cannot be, and `forbid` cannot be lifted
// even locally. So the rule is denied crate-wide, and `map` carries the single documented exception
// with the safety argument written where the code is.
#![deny(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub mod map;
pub mod shared;

/// Why a reservation was refused.
///
/// Distinct variants rather than a `bool`, because the caller has to tell them apart: a quota refusal
/// is the normal, expected answer that a workload should see as an out-of-memory condition, while an
/// overflow refusal means the caller handed over a size that cannot be real and is worth surfacing as
/// a defect rather than as a full GPU.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// The reservation would take the total past the quota. The ordinary case.
    OverQuota {
        /// What is held right now, including everything reserved before this call.
        held: u64,
        /// The ceiling that was applied, quota plus any oversubscription allowance.
        limit: u64,
    },
    /// `held + size` does not fit in a `u64`. Not reachable with real device memory; reachable with a
    /// size that came from a corrupted or hostile caller, and refused rather than wrapped.
    WouldOverflow,
    /// The quota is draining: no new reservation is accepted, existing ones are still released. Used
    /// when a slice is being torn down and a late allocation must not re-populate it.
    Draining,
}

/// One cache line, so that a field written on the hot path cannot invalidate a field merely read on
/// it.
///
/// 64 bytes is the line size on every architecture kern targets (x86_64 and the aarch64 parts in the
/// boards it runs on). Being wrong in the low direction would cost correctness of the OPTIMISATION,
/// never of the result: on a machine with 128-byte lines two of these could share one line and the
/// separation would simply stop helping. Being wrong in the high direction costs padding on a struct
/// there is one of. So 64 is the safe end of the guess, and it is a guess about hardware rather than
/// a fact about it, which is why it says so here.
#[repr(align(64))]
#[derive(Debug)]
struct Line<T>(T);

/// A per-process cooperative VRAM quota.
///
/// `Sync` and usable from any number of threads through a shared reference. There is no interior
/// mutability beyond the atomics, and no `Drop` work, so a `'static` instance is the expected shape.
///
/// LAYOUT IS PART OF THE DESIGN, not an afterthought, and the grouping is by WRITE FREQUENCY rather
/// than by meaning. A cache line is invalidated on every core that holds it when any byte of it is
/// written. `held` is written by every reservation on every thread; `quota` is read by every
/// reservation and written almost never. Putting them in one line would make each reservation's write
/// steal the line back from every core that was about to read the ceiling, turning a read-mostly value
/// into a contended one. Three groups:
///
///   1. `held`, alone. Written by every operation, by every thread.
///   2. `peak` and `refusals`. Written on the hot path but only when the outcome is unusual: a new
///      high-water mark, or a refusal.
///   3. `quota`, `allowance`, `draining`. Read by every reservation, written when an operator resizes
///      a slice or tears it down.
#[derive(Debug)]
pub struct Quota {
    /// Bytes currently reserved. The only value that moves on every operation, hence its own line.
    held: Line<AtomicU64>,
    /// Highest value `held` has ever reached. Never decreases.
    peak: Line<AtomicU64>,
    /// Total reservations refused, all reasons. A counter an operator reads to tell "the cap is
    /// sized right" from "the workload has been hitting it all afternoon".
    ///
    /// Shares a line with `peak` on purpose: both are written only on the uncommon branch of a
    /// reservation, and a reservation writes at most one of them, so they cannot contend with each
    /// other within a single call.
    refusals: AtomicU64,
    /// The quota proper, in bytes. Read-mostly, hence the third line.
    quota: Line<AtomicU64>,
    /// Extra bytes tolerated above `quota`.
    ///
    /// Separate from `quota` rather than folded into it, because the two are decided by different
    /// people: the quota is what an operator asked for, the allowance is what the runtime is willing
    /// to tolerate before it starts refusing. Keeping them apart means a `stats()` reader can tell an
    /// operator's 2 GiB with a 10% allowance from an operator's 2.2 GiB.
    allowance: AtomicU64,
    /// When set, every reservation is refused and releases still work.
    draining: AtomicBool,
}

/// A snapshot of a quota, taken without stopping it.
///
/// The fields are read with separate atomic loads, so they are individually correct and not
/// guaranteed to be consistent with each other: `held` may move between the read of `held` and the
/// read of `peak`. That is stated rather than fixed, because fixing it means a lock on the hot path
/// to make a diagnostic read prettier, which is the wrong trade. Nothing in kern makes a decision
/// from a snapshot; they are printed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Stats {
    pub held: u64,
    pub quota: u64,
    pub allowance: u64,
    pub peak: u64,
    pub refusals: u64,
    pub draining: bool,
}

impl Quota {
    /// A quota of `bytes`, with nothing held and no oversubscription allowance.
    pub const fn new(bytes: u64) -> Self {
        Self {
            held: Line(AtomicU64::new(0)),
            peak: Line(AtomicU64::new(0)),
            refusals: AtomicU64::new(0),
            quota: Line(AtomicU64::new(bytes)),
            allowance: AtomicU64::new(0),
            draining: AtomicBool::new(false),
        }
    }

    /// An unlimited quota: accounts everything, refuses nothing.
    ///
    /// The engine still runs, which is the point. A workload with no cap gets the same accounting,
    /// the same peak and the same statistics as one with a cap, so an operator can size a quota by
    /// running uncapped first. A quota of `u64::MAX` also means the only refusal a caller can see
    /// here is [`Refused::WouldOverflow`], which cannot happen with real device memory.
    pub const fn unlimited() -> Self {
        Self::new(u64::MAX)
    }

    /// Reserve `size` bytes, or say why not.
    ///
    /// THE HOT PATH. A zero-byte reservation is accepted without touching the atomics at all, which
    /// is not a micro-optimisation: CUDA allows a zero-sized allocation and a workload that makes
    /// many of them would otherwise pay a full CAS for accounting that cannot change anything.
    ///
    /// ORDERINGS, stated because they are load-bearing and a reviewer should not have to infer them.
    /// The success ordering is `AcqRel`: `Release` so that whatever the caller did before reserving
    /// is visible to a thread that later observes this value, `Acquire` so this thread sees the work
    /// of whoever set the value it is replacing. The failure ordering is `Acquire`, which is the
    /// minimum that lets the retry read a value it can trust. `quota` and `allowance` are read
    /// `Relaxed`: they change when an operator resizes a slice, and a reservation racing that resize
    /// may use either the old or the new ceiling, which is inherent to resizing under load and not a
    /// property a stronger ordering would fix.
    pub fn reserve(&self, size: u64) -> Result<(), Refused> {
        if size == 0 {
            return Ok(());
        }
        if self.draining.load(Ordering::Relaxed) {
            self.refusals.fetch_add(1, Ordering::Relaxed);
            return Err(Refused::Draining);
        }
        let limit = self
            .quota
            .0
            .load(Ordering::Relaxed)
            .saturating_add(self.allowance.load(Ordering::Relaxed));

        let mut held = self.held.0.load(Ordering::Relaxed);
        loop {
            let Some(total) = held.checked_add(size) else {
                self.refusals.fetch_add(1, Ordering::Relaxed);
                return Err(Refused::WouldOverflow);
            };
            if total > limit {
                self.refusals.fetch_add(1, Ordering::Relaxed);
                return Err(Refused::OverQuota { held, limit });
            }
            match self.held.0.compare_exchange_weak(
                held,
                total,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // THE SECOND ATOMIC, paid only when it can change something. `fetch_max` is a
                    // read-modify-write: it locks the line and costs about what the reservation CAS
                    // itself costs, and the overwhelming majority of reservations do not set a new
                    // high-water mark. A plain `Relaxed` load first turns that into a load plus a
                    // predictable, almost-never-taken branch.
                    //
                    // Still `fetch_max` inside the branch, not a store, and that is the part a
                    // reader should check rather than trust: between the load and the write another
                    // thread may have raised the peak past `total`, and a store would lose it.
                    // `fetch_max` cannot, so the guard is a fast path in front of a correct
                    // operation and never a replacement for one. Skipping when `total <= observed`
                    // is safe because the peak only ever grows: a value that is not above what has
                    // already been recorded cannot become the maximum later.
                    if total > self.peak.0.load(Ordering::Relaxed) {
                        self.peak.0.fetch_max(total, Ordering::Relaxed);
                    }
                    return Ok(());
                }
                // `compare_exchange_weak` may fail spuriously on LL/SC machines, which is exactly why
                // it is the cheap one to use inside a loop: the retry costs a re-read, and `e` is
                // the current value, so the loop does not need a second load to make progress.
                Err(e) => held = e,
            }
        }
    }

    /// Release `size` bytes.
    ///
    /// SATURATING, and the choice is deliberate. A release larger than what is held means the caller
    /// has double-freed or lost track of a size, and there are two ways to react: wrap the counter,
    /// which silently reports a quota with billions of exabytes free and disables the cap for the
    /// rest of the process's life, or clamp at zero, which under-reports until the accounting is
    /// re-synchronised. Under-reporting is recoverable and wrapping is not, so it clamps.
    ///
    /// `Ordering::AcqRel` for the same reason as [`Self::reserve`]: the release publishes the
    /// caller's preceding work, and the loop's retry needs to see the value it is replacing.
    pub fn release(&self, size: u64) {
        if size == 0 {
            return;
        }
        let mut held = self.held.0.load(Ordering::Relaxed);
        loop {
            let next = held.saturating_sub(size);
            match self
                .held
                .0
                .compare_exchange_weak(held, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(e) => held = e,
            }
        }
    }

    /// Bytes currently reserved.
    pub fn held(&self) -> u64 {
        self.held.0.load(Ordering::Relaxed)
    }

    /// The ceiling in force: quota plus allowance, saturating.
    pub fn limit(&self) -> u64 {
        self.quota
            .0
            .load(Ordering::Relaxed)
            .saturating_add(self.allowance.load(Ordering::Relaxed))
    }

    /// Resize the quota. Takes effect on the next reservation; nothing already reserved is revoked.
    ///
    /// A quota lowered below what is already held is accepted and leaves the engine over its ceiling
    /// until enough is released. The alternative, refusing the resize, would mean an operator cannot
    /// shrink a slice that is currently full, which is the moment they most want to. Reservations are
    /// refused until `held` falls back under the new limit, which is the correct behaviour and is
    /// pinned by a test.
    pub fn set_quota(&self, bytes: u64) {
        self.quota.0.store(bytes, Ordering::Relaxed);
    }

    /// Set the oversubscription allowance, in bytes above the quota.
    pub fn set_allowance(&self, bytes: u64) {
        self.allowance.store(bytes, Ordering::Relaxed);
    }

    /// Refuse every further reservation. Releases keep working, and this cannot be undone.
    ///
    /// One-way on purpose. Draining is what a slice does while it is being torn down, and a quota
    /// that could be un-drained would let a late allocation land in a slice whose device context is
    /// already gone.
    pub fn drain(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    /// Whether [`Self::drain`] has been called.
    pub fn draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// A snapshot for reporting. See [`Stats`] on why the fields are not mutually consistent.
    pub fn stats(&self) -> Stats {
        Stats {
            held: self.held.0.load(Ordering::Relaxed),
            quota: self.quota.0.load(Ordering::Relaxed),
            allowance: self.allowance.load(Ordering::Relaxed),
            peak: self.peak.0.load(Ordering::Relaxed),
            refusals: self.refusals.load(Ordering::Relaxed),
            draining: self.draining.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    #[test]
    fn a_reservation_that_fits_is_accounted() {
        let q = Quota::new(2 * GIB);
        assert_eq!(q.reserve(512 * MIB), Ok(()));
        assert_eq!(q.held(), 512 * MIB);
        assert_eq!(q.stats().peak, 512 * MIB);
        assert_eq!(q.stats().refusals, 0);
    }

    #[test]
    fn a_reservation_past_the_quota_is_refused_and_changes_nothing() {
        let q = Quota::new(2 * GIB);
        assert_eq!(q.reserve(2 * GIB), Ok(()));
        assert_eq!(
            q.reserve(1),
            Err(Refused::OverQuota {
                held: 2 * GIB,
                limit: 2 * GIB
            })
        );
        assert_eq!(q.held(), 2 * GIB, "a refused reservation must not be held");
        assert_eq!(q.stats().refusals, 1);
    }

    #[test]
    fn exactly_the_quota_fits_and_one_byte_more_does_not() {
        let q = Quota::new(1000);
        assert_eq!(q.reserve(1000), Ok(()));
        assert!(q.reserve(1).is_err());
        q.release(1);
        assert_eq!(q.held(), 999);
        assert_eq!(q.reserve(1), Ok(()));
    }

    #[test]
    fn the_allowance_is_added_to_the_quota_and_reported_apart_from_it() {
        let q = Quota::new(GIB);
        q.set_allowance(256 * MIB);
        assert_eq!(q.limit(), GIB + 256 * MIB);
        assert_eq!(q.reserve(GIB + 256 * MIB), Ok(()));
        assert!(q.reserve(1).is_err());
        let s = q.stats();
        assert_eq!((s.quota, s.allowance), (GIB, 256 * MIB));
    }

    /// A zero-byte allocation is legal in CUDA and must not be turned into a refusal, nor cost a CAS.
    #[test]
    fn a_zero_byte_reservation_is_free_and_accepted() {
        let q = Quota::new(0);
        assert_eq!(q.reserve(0), Ok(()));
        assert_eq!(q.held(), 0);
        assert_eq!(q.stats().refusals, 0);
        q.release(0);
        assert_eq!(q.held(), 0);
    }

    /// A quota of zero refuses everything except the zero-byte case above.
    #[test]
    fn a_zero_quota_refuses_every_real_allocation() {
        let q = Quota::new(0);
        assert_eq!(q.reserve(1), Err(Refused::OverQuota { held: 0, limit: 0 }));
    }

    /// The size that cannot be real. Refused rather than wrapped, and the two are told apart because
    /// a caller must be able to distinguish "your GPU is full" from "you passed me nonsense".
    #[test]
    fn an_overflowing_size_is_refused_and_not_wrapped() {
        let q = Quota::unlimited();
        assert_eq!(q.reserve(u64::MAX), Ok(()));
        assert_eq!(q.reserve(1), Err(Refused::WouldOverflow));
        assert_eq!(q.held(), u64::MAX, "the failed add must not have wrapped");
    }

    /// A release bigger than what is held clamps at zero. Wrapping here would report an empty quota
    /// with 18 exabytes free and switch the cap off for the life of the process.
    #[test]
    fn an_oversized_release_clamps_instead_of_wrapping() {
        let q = Quota::new(GIB);
        assert_eq!(q.reserve(MIB), Ok(()));
        q.release(4 * GIB);
        assert_eq!(q.held(), 0, "a double free must not wrap the counter");
        assert_eq!(q.reserve(GIB), Ok(()), "and the quota must still hold");
        assert!(q.reserve(1).is_err());
    }

    #[test]
    fn draining_refuses_new_work_and_still_lets_the_old_go() {
        let q = Quota::new(GIB);
        assert_eq!(q.reserve(512 * MIB), Ok(()));
        q.drain();
        assert!(q.draining());
        assert_eq!(q.reserve(1), Err(Refused::Draining));
        q.release(512 * MIB);
        assert_eq!(q.held(), 0);
        assert_eq!(q.reserve(1), Err(Refused::Draining), "draining is one-way");
    }

    /// Shrinking a quota under what is held is allowed, because an operator wants to shrink a slice
    /// precisely when it is full. The engine sits over its ceiling and refuses until it drops back.
    #[test]
    fn a_quota_shrunk_below_what_is_held_refuses_until_it_drains_back() {
        let q = Quota::new(2 * GIB);
        assert_eq!(q.reserve(2 * GIB), Ok(()));
        q.set_quota(GIB);
        assert_eq!(q.held(), 2 * GIB, "nothing already reserved is revoked");
        assert!(q.reserve(1).is_err());
        q.release(GIB + 1);
        assert_eq!(q.reserve(1), Ok(()));
    }

    #[test]
    fn peak_never_falls() {
        let q = Quota::new(GIB);
        assert_eq!(q.reserve(512 * MIB), Ok(()));
        assert_eq!(q.stats().peak, 512 * MIB);
        q.release(512 * MIB);
        assert_eq!(q.held(), 0);
        assert_eq!(q.stats().peak, 512 * MIB, "peak is a high-water mark");
        assert_eq!(q.reserve(64 * MIB), Ok(()));
        assert_eq!(q.stats().peak, 512 * MIB);
    }

    /// THE RACE THE CAS EXISTS TO CLOSE. Sixteen threads, each trying to reserve one slot of a quota
    /// sized to hold exactly half of them. With a read-then-add the count would exceed the quota;
    /// with the compare-and-swap it cannot, on any interleaving.
    ///
    /// Asserted on the INVARIANT rather than on a fixed number of winners, because the number of
    /// winners is deterministic here (the quota admits exactly 8) while the identity of the winners
    /// is not. A test that pinned the identity would be testing the scheduler.
    #[test]
    fn concurrent_reservations_never_exceed_the_quota() {
        const THREADS: usize = 16;
        const SLOT: u64 = 64 * MIB;
        let q = Arc::new(Quota::new(SLOT * (THREADS as u64 / 2)));
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let q = Arc::clone(&q);
            handles.push(thread::spawn(move || q.reserve(SLOT).is_ok()));
        }
        // `map` then `filter`, not `filter` alone: `join` consumes the handle and `filter` only
        // lends it. The first attempt at removing a leftover predicate here produced exactly that
        // borrow error, which is the compiler catching a careless edit rather than a design problem.
        let won = handles
            .into_iter()
            .map(|h| h.join().unwrap_or(false))
            .filter(|ok| *ok)
            .count();
        assert_eq!(
            won,
            THREADS / 2,
            "the quota admits exactly half the threads"
        );
        assert_eq!(q.held(), SLOT * (THREADS as u64 / 2));
        assert!(
            q.held() <= q.limit(),
            "the invariant, on every interleaving"
        );
        assert_eq!(q.stats().refusals, (THREADS / 2) as u64);
    }

    /// Reserve and release from many threads at once and land exactly back at zero. A lost update in
    /// either direction shows up here as a non-zero residue.
    #[test]
    fn reserve_and_release_are_balanced_under_contention() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 2000;
        let q = Arc::new(Quota::new(GIB));
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let q = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                for _ in 0..ROUNDS {
                    if q.reserve(MIB).is_ok() {
                        q.release(MIB);
                    }
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        assert_eq!(q.held(), 0, "every reservation was released exactly once");
        assert!(q.stats().peak <= GIB);
    }

    /// The peak must be the true high-water mark under contention, not whatever the last thread saw.
    #[test]
    fn peak_survives_concurrent_growth() {
        const THREADS: usize = 8;
        const SLOT: u64 = 16 * MIB;
        let q = Arc::new(Quota::new(GIB));
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let q = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                assert_eq!(q.reserve(SLOT), Ok(()));
            }));
        }
        for h in handles {
            let _ = h.join();
        }
        assert_eq!(q.held(), SLOT * THREADS as u64);
        assert_eq!(
            q.stats().peak,
            SLOT * THREADS as u64,
            "fetch_max, not load-compare-store"
        );
    }

    /// `Quota` is shared across threads by reference, so this is a compile-time claim worth pinning:
    /// if a field ever gains interior mutability that is not `Sync`, this stops building.
    #[test]
    fn the_quota_is_shareable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Quota>();
        assert_send_sync::<Stats>();
    }
}
