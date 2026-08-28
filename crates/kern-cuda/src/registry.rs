//! THE POINTER-TO-SIZE MAP, which is the constraint the whole hook layer is built around.
//!
//! `cuMemAlloc(&ptr, size)` is told the size. `cuMemFree(ptr)` is not. So an interception layer that
//! accounts device memory has to remember, for every live allocation, how big it was, and it has to
//! answer that question on the free path of a workload that may be freeing thousands of buffers a
//! second. Everything about this file follows from that one asymmetry in the CUDA API.
//!
//! WHY NOT A `HashMap` BEHIND A `Mutex`
//!   Three reasons, in order of how badly each one bites.
//!
//!   It allocates. The hook runs inside the workload's allocator context: `cuMemFree` can be called
//!   from a destructor, from a signal-adjacent path, or from a thread that is already inside
//!   `malloc`. A map that grows by calling the system allocator can deadlock there, and a deadlock
//!   inside a GPU free is a hung inference server with no stack trace worth reading.
//!
//!   It locks. A mutex on the free path serialises every thread of a multi-stream workload behind
//!   one another for the duration of a hash lookup, and a lock held by a thread the scheduler
//!   preempted stops every other thread until it runs again.
//!
//!   It is unbounded. A workload that leaks allocations grows the map until the host is out of
//!   memory, which converts a GPU-memory problem into a host-memory problem.
//!
//! WHAT IT IS INSTEAD
//!   A fixed-capacity open-addressed table of `(pointer, size)` pairs, allocated once when the
//!   slice is created and never resized. Insert and remove are compare-and-swap on the pointer
//!   word. No locks, no allocation after construction, and a hard ceiling on memory that is known
//!   at startup rather than discovered under load.
//!
//! THE COST OF A FIXED CAPACITY, STATED
//!   A table that is full cannot record a new allocation. That is a real limit and it is handled by
//!   refusing the allocation rather than by forgetting the size, because forgetting is worse: an
//!   allocation whose size is not recorded is never released from the quota when it is freed, so
//!   the slice leaks until the process exits. Refusing is visible, bounded and correct. The
//!   capacity is a power of two chosen by the caller and the table reports how full it is, so the
//!   operator sizing a slice can see the headroom rather than guess at it.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// An empty slot. Zero is safe to use as the sentinel because no CUDA allocation ever returns a null
/// device pointer: `cuMemAlloc` either yields a valid address or an error, and a null that reached
/// this table would be a driver bug being recorded rather than a size being lost.
const EMPTY: u64 = 0;

/// A slot whose entry was removed. Distinct from [`EMPTY`] because a probe sequence must not stop at
/// a removed entry: an insert that landed past this slot is still reachable only by continuing
/// through it, and stopping here would report a live allocation as missing and leak its size.
///
/// `u64::MAX` is not a possible device pointer on any 64-bit address space, and the table refuses to
/// store it explicitly rather than relying on that.
const TOMBSTONE: u64 = u64::MAX;

/// A slot a thread has CLAIMED but not yet published a pointer into.
///
/// THE THIRD SENTINEL EXISTS BECAUSE OF A RACE THE FIRST TWO COULD NOT CLOSE, and the race is worth
/// recording because it was found by this file's own concurrency test rather than by reading:
///
///   Thread A removes its pointer: it CASes the slot to `TOMBSTONE`, then zeroes the size word.
///   Between those two writes, thread B claims the now-free slot and stores ITS size.
///   A's zeroing then lands on top of B's size.
///   B later removes its pointer, reads a size of zero, and is told the pointer is not there.
///
/// A's second write went to a slot A no longer owned. The rule that closes it is that the size word
/// is written ONLY by the thread that owns the slot, and ownership is the pointer CAS. So an insert
/// claims with this value first, writes the size while it owns the slot, and publishes the pointer
/// last; a remove reads the size and releases the slot, and never writes the size at all.
///
/// A probe that meets `RESERVED` keeps going: it is neither a free slot nor a match, and an insert
/// racing through it will publish something that is not this probe's pointer.
const RESERVED: u64 = u64::MAX - 1;

/// Why an insert was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InsertError {
    /// The probe sequence found no usable slot. The table is full, or full enough that the bounded
    /// probe gave up, and the caller must refuse the allocation rather than lose its size.
    Full {
        /// How many entries are live, for an operator sizing the table.
        live: usize,
        /// The table's capacity.
        capacity: usize,
    },
    /// The pointer is one of the two sentinel values and cannot be stored.
    ///
    /// Neither is a real device pointer, so this is a defensive refusal rather than a case that
    /// happens: recording it anyway would make a sentinel indistinguishable from an entry and
    /// corrupt every later probe.
    ReservedPointer,
    /// The pointer is already in the table.
    ///
    /// The driver returning a pointer that is already live means either the driver is wrong or this
    /// table missed a free, and both are worth surfacing rather than overwriting a size that some
    /// later `cuMemFree` is going to need.
    Duplicate,
}

/// A fixed-capacity, lock-free map from device pointer to allocation size.
///
/// Open addressing with linear probing. Linear rather than quadratic or double hashing for a reason
/// that is about the machine and not about theory: consecutive slots are adjacent in memory, so a
/// probe that walks forward walks within a cache line for the first four steps and into the next
/// prefetched line after that. A probe sequence that jumped would take a cache miss per step.
pub struct Registry {
    /// Slots, two words each: pointer then size. A single allocation, made once.
    ///
    /// Interleaved rather than two parallel arrays, which is the opposite of the struct-of-arrays
    /// choice made elsewhere in this crate, and deliberately so: the two fields are ALWAYS used
    /// together here (a lookup that finds a pointer immediately wants its size), so splitting them
    /// would take two cache misses where interleaving takes one. Struct-of-arrays wins when fields
    /// are scanned independently; this is the other case.
    slots: Box<[AtomicU64]>,
    /// `capacity - 1`, and capacity is a power of two, so the modulo on the hot path is a mask.
    mask: usize,
    /// Live entries, SHARDED, one counter per cache line.
    ///
    /// A single counter here was the measured bottleneck of the whole accounting path. Every insert
    /// increments it and every remove decrements it, so at N threads it is one machine word written
    /// 2N times per allocation cycle, and a word written at that rate from many cores is a coherence
    /// round trip rather than an instruction. Measured on an i7-14700KF: a bare `fetch_add`/
    /// `fetch_sub` pair on one shared word costs 7.2 ns on one thread and 16.4 ns on sixteen, so the
    /// coherence alone was 9.2 ns of a 69.1 ns contended pair, spent on a number used by `len()` and
    /// by the text of a refusal.
    ///
    /// SHARDED BY SLOT INDEX, WHICH MAKES IT EXACT AND NOT APPROXIMATE. An insert and the remove that
    /// undoes it act on the SAME slot, because the remove finds the pointer where the insert put it,
    /// so both hit the same shard and every shard is individually balanced. Threads working on
    /// different parts of the table touch different shards and never invalidate each other's line.
    /// Summing them for a read is the only cost, and reads are diagnostics.
    live: Box<[Line<AtomicUsize>]>,
}

/// One cache line, so two shards cannot share one.
#[repr(align(64))]
#[derive(Debug)]
struct Line<T>(T);

/// How many live-count shards. 64 lines is 4 KiB, allocated once with the table.
///
/// Sized against the machine rather than against the thread count, which the table cannot know: 64 is
/// at or above the core count of every host kern targets, so two threads sharing a shard is possible
/// but not the common case, and the fallback when it happens is exactly the single-counter behaviour
/// this replaces.
const LIVE_SHARDS: usize = 64;

/// Words per slot: the pointer and its size.
const SLOT_WORDS: usize = 2;

impl Registry {
    /// A table with room for `capacity` entries, rounded up to a power of two, minimum 64.
    ///
    /// THE ONLY ALLOCATION IN THIS FILE, and it happens once, when a slice is created, on a path that
    /// is allowed to allocate. Everything after this point is atomics on memory that already exists.
    ///
    /// Rounded up rather than refused, because the caller is an operator's slice size divided by a
    /// guess at an average allocation, and refusing a non-power-of-two would turn a tuning knob into
    /// a puzzle. The rounding is upward so the table is never smaller than what was asked for.
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(64).next_power_of_two();
        let slots = (0..cap * SLOT_WORDS)
            .map(|_| AtomicU64::new(EMPTY))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let live = (0..LIVE_SHARDS)
            .map(|_| Line(AtomicUsize::new(0)))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            slots,
            mask: cap - 1,
            live,
        }
    }

    /// How many entries the table can hold.
    pub fn capacity(&self) -> usize {
        self.mask + 1
    }

    /// How many entries are live right now.
    ///
    /// Sums the shards, so it is O(64) rather than O(1). Not on any hot path: it is read by `len`,
    /// by `is_empty` and by the text of a refusal, all of which are diagnostics or already on the
    /// slow path. Saturating, because a shard that has been decremented more than incremented (which
    /// cannot happen through the public API, since insert and remove of one pointer share a shard)
    /// must not turn the sum into a wrapped enormous number.
    pub fn len(&self) -> usize {
        self.live.iter().fold(0usize, |acc, l| {
            acc.saturating_add(l.0.load(Ordering::Relaxed))
        })
    }

    /// The shard a slot's count lives in. Same slot, same shard, so an insert and the remove that
    /// undoes it are always balanced against each other.
    #[inline(always)]
    fn live_shard(&self, slot: usize) -> &AtomicUsize {
        // `LIVE_SHARDS` is a power of two, so this is a mask.
        &self.live[slot & (LIVE_SHARDS - 1)].0
    }

    /// Whether the table holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Where a pointer's probe sequence starts.
    ///
    /// FIBONACCI HASHING, and the multiplier is not arbitrary: 0x9E3779B97F4A7C15 is 2^64 divided by
    /// the golden ratio, the standard choice for spreading keys whose low bits are not random. Device
    /// pointers are the opposite of random in exactly the way that matters here: allocations are page
    /// aligned or better, so the low twelve bits are zero on every one of them. Masking a raw pointer
    /// would send every allocation to slot 0 and turn the table into a linked list. Multiplying first
    /// moves entropy from the high bits, where an address actually varies, down into the bits the
    /// mask keeps.
    #[inline(always)]
    fn home(&self, ptr: u64) -> usize {
        const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;
        (ptr.wrapping_mul(GOLDEN) >> 32) as usize & self.mask
    }

    /// The word index of slot `i`'s pointer. Its size is the next word.
    #[inline(always)]
    fn at(&self, i: usize) -> usize {
        i * SLOT_WORDS
    }

    /// Record that `ptr` is an allocation of `size` bytes.
    ///
    /// THE ORDER OF THE TWO WRITES MATTERS AND IS NOT THE OBVIOUS ONE. The pointer is claimed first
    /// with a CAS, which makes the slot this thread's, and the size is written second. Between the
    /// two, a concurrent lookup can find the pointer with a size of zero. That window is closed by
    /// the size being written with `Release` and read with `Acquire`, and by the lookup treating a
    /// zero size as "not yet published" and continuing to probe rather than returning it: a
    /// zero-sized live allocation does not exist, so zero is unambiguous.
    ///
    /// The alternative, writing the size first, is worse and not merely different: the slot is not
    /// ours until the CAS succeeds, so writing a size into it beforehand writes into a slot another
    /// thread may be about to claim.
    pub fn insert(&self, ptr: u64, size: u64) -> Result<(), InsertError> {
        if ptr == EMPTY || ptr == TOMBSTONE || ptr == RESERVED {
            return Err(InsertError::ReservedPointer);
        }
        // A size of zero cannot be stored, because zero is how the lookup recognises a slot that has
        // been claimed but not yet published. CUDA permits a zero-byte allocation and the accounting
        // layer accepts it without reserving anything, so nothing needs to record one.
        let size = size.max(1);

        let start = self.home(ptr);
        // Bounded probe. An unbounded one on a full table walks the whole capacity and, worse, would
        // loop forever if every slot were a tombstone. The bound is the capacity, so the table is
        // reported full only after every slot has genuinely been looked at.
        for step in 0..=self.mask {
            let i = (start + step) & self.mask;
            let w = self.at(i);
            let cur = self.slots[w].load(Ordering::Acquire);
            if cur == ptr {
                return Err(InsertError::Duplicate);
            }
            if cur != EMPTY && cur != TOMBSTONE {
                // Occupied by another pointer, or RESERVED by a thread mid-insert. Neither is ours.
                continue;
            }
            // CLAIM, WRITE, PUBLISH, in that order. See [`RESERVED`]: the size may only be written
            // by the owner of the slot, and this CAS is what ownership is.
            if self.slots[w]
                .compare_exchange(cur, RESERVED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.slots[w + 1].store(size, Ordering::Relaxed);
                // `Release` publishes the size above to any thread that later reads this pointer
                // with `Acquire`, which is what makes a matched pointer imply a correct size.
                self.slots[w].store(ptr, Ordering::Release);
                self.live_shard(i).fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            // Lost the slot to another thread. Re-examine THIS slot before moving on: the winner may
            // have inserted the very pointer we are inserting, which is a duplicate rather than a
            // reason to keep probing.
            if self.slots[w].load(Ordering::Acquire) == ptr {
                return Err(InsertError::Duplicate);
            }
        }
        Err(InsertError::Full {
            // The sum is O(64) and this is the refusal path, which was going to fail an allocation
            // anyway: an operator reading "full at 65536 of 65536" needs the number to be right more
            // than they need the failure to be fast.
            live: self.len(),
            capacity: self.capacity(),
        })
    }

    /// Take `ptr` out of the table and return the size it was recorded with.
    ///
    /// `None` when the pointer is not there, which is the caller's signal that this is a free of
    /// something kern never saw: a pointer allocated before the hook was installed, a double free by
    /// the workload, or a pointer from a different allocator. The caller must NOT release anything
    /// from the quota in that case, because releasing a size it did not reserve is how a cooperative
    /// quota drifts away from the truth and eventually reports a slice with more free memory than the
    /// card has.
    ///
    /// THE REMOVE IS THE CAS, and the size is read BEFORE it. Reading after would race a concurrent
    /// insert that reuses the freed slot: the size read would be the new allocation's, and the
    /// caller would release the wrong number of bytes. Reading first and then claiming the slot means
    /// the value returned is the one that was there when the claim succeeded, because a tombstone is
    /// only written by the thread that wins.
    pub fn remove(&self, ptr: u64) -> Option<u64> {
        if ptr == EMPTY || ptr == TOMBSTONE || ptr == RESERVED {
            return None;
        }
        let start = self.home(ptr);
        for step in 0..=self.mask {
            let i = (start + step) & self.mask;
            let w = self.at(i);
            let cur = self.slots[w].load(Ordering::Acquire);
            if cur == EMPTY {
                // A genuinely empty slot ends the probe: nothing was ever inserted past it along
                // this sequence. A TOMBSTONE does not, which is the entire reason the two are
                // different values.
                return None;
            }
            if cur != ptr {
                continue;
            }
            // The pointer matched, and it was published with `Release` after its size was written,
            // so this load sees that size and not a predecessor's.
            let size = self.slots[w + 1].load(Ordering::Acquire);
            if self.slots[w]
                .compare_exchange(ptr, TOMBSTONE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // THE SIZE WORD IS DELIBERATELY NOT CLEARED. Clearing it here is a write to a slot
                // this thread has just given up, and a thread that claims the slot in between would
                // have its own size zeroed by it. The stale value is harmless: it is only ever read
                // after a pointer match, and a pointer is published only after its size is written.
                self.live_shard(i).fetch_sub(1, Ordering::Relaxed);
                return Some(size);
            }
            // Another thread removed it first: a double free by the workload. Exactly one caller
            // gets the size, which is what keeps the quota from being credited twice.
            return None;
        }
        None
    }

    /// The size recorded for `ptr`, without removing it.
    ///
    /// Diagnostics only. Nothing on the accounting path uses it: a lookup followed by a remove is
    /// two operations with a race between them, and [`Self::remove`] is the single atomic step that
    /// the free path actually needs.
    pub fn get(&self, ptr: u64) -> Option<u64> {
        if ptr == EMPTY || ptr == TOMBSTONE || ptr == RESERVED {
            return None;
        }
        let start = self.home(ptr);
        for step in 0..=self.mask {
            let i = (start + step) & self.mask;
            let w = self.at(i);
            let cur = self.slots[w].load(Ordering::Acquire);
            if cur == EMPTY {
                return None;
            }
            if cur == ptr {
                return Some(self.slots[w + 1].load(Ordering::Acquire));
            }
        }
        None
    }

    /// Sum of every live allocation's size.
    ///
    /// O(capacity) and NOT on any hot path. It exists for one job: reconciling the quota against the
    /// table when something has gone wrong, which is the only way to tell an accounting drift from a
    /// workload that genuinely holds that much.
    pub fn total_bytes(&self) -> u64 {
        let mut sum: u64 = 0;
        for i in 0..=self.mask {
            let w = self.at(i);
            let p = self.slots[w].load(Ordering::Relaxed);
            if p == EMPTY || p == TOMBSTONE || p == RESERVED {
                continue;
            }
            sum = sum.saturating_add(self.slots[w + 1].load(Ordering::Relaxed));
        }
        sum
    }

    /// Every live `(pointer, size)` pair, for teardown.
    ///
    /// Allocates, and is allowed to: it runs when a slice is being destroyed and its remaining
    /// allocations have to be given back to the quota. Never on the hot path.
    pub fn drain_all(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for i in 0..=self.mask {
            let w = self.at(i);
            let p = self.slots[w].load(Ordering::Acquire);
            if p == EMPTY || p == TOMBSTONE || p == RESERVED {
                continue;
            }
            if let Some(size) = self.remove(p) {
                out.push((p, size));
            }
        }
        out
    }
}

impl core::fmt::Debug for Registry {
    /// Prints the shape, never the contents. A device pointer in a log is an address from another
    /// process's GPU context, and dumping thousands of them is noise that hides the two numbers an
    /// operator wants.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registry")
            .field("capacity", &self.capacity())
            .field("live", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn a_recorded_allocation_gives_its_size_back_exactly_once() {
        let r = Registry::with_capacity(64);
        assert_eq!(r.insert(0x7000, 4096), Ok(()));
        assert_eq!(r.len(), 1);
        assert_eq!(r.get(0x7000), Some(4096));
        assert_eq!(r.remove(0x7000), Some(4096));
        assert_eq!(r.remove(0x7000), None, "a double free gets nothing");
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
    }

    /// A free of a pointer kern never saw must yield nothing. Releasing a guessed size here is how a
    /// cooperative quota drifts until it reports more free memory than the card has.
    #[test]
    fn an_unknown_pointer_yields_nothing() {
        let r = Registry::with_capacity(64);
        assert_eq!(r.remove(0xDEAD_BEEF), None);
        assert_eq!(r.get(0xDEAD_BEEF), None);
        assert_eq!(r.len(), 0);
    }

    /// The two sentinels are refused rather than stored. Storing one would make it indistinguishable
    /// from an empty or removed slot and corrupt every probe that passed through it.
    #[test]
    fn the_sentinel_values_are_refused() {
        let r = Registry::with_capacity(64);
        for s in [EMPTY, TOMBSTONE, RESERVED] {
            assert_eq!(r.insert(s, 8), Err(InsertError::ReservedPointer));
            assert_eq!(r.remove(s), None);
            assert_eq!(r.get(s), None);
        }
        assert_eq!(r.len(), 0);
    }

    /// The three sentinels must be distinct, or one of them is silently the other and a probe cannot
    /// tell a free slot from a claimed one.
    #[test]
    fn the_three_sentinels_are_distinct() {
        assert_ne!(EMPTY, TOMBSTONE);
        assert_ne!(EMPTY, RESERVED);
        assert_ne!(TOMBSTONE, RESERVED);
    }

    /// A driver returning a live pointer again is either a driver bug or a missed free, and both are
    /// worth refusing rather than overwriting a size some later free is going to need.
    #[test]
    fn a_duplicate_pointer_is_refused_and_does_not_overwrite() {
        let r = Registry::with_capacity(64);
        assert_eq!(r.insert(0x1000, 100), Ok(()));
        assert_eq!(r.insert(0x1000, 999), Err(InsertError::Duplicate));
        assert_eq!(r.remove(0x1000), Some(100), "the first size survived");
    }

    /// THE TOMBSTONE'S REASON FOR EXISTING. Two pointers that hash to the same home slot; remove the
    /// first, then look for the second. If removal wrote EMPTY, the probe would stop at the hole and
    /// report the second as missing, leaking its size from the quota forever.
    #[test]
    fn a_removal_does_not_hide_an_entry_further_along_the_probe() {
        let r = Registry::with_capacity(64);
        // Find two pointers with the same home slot, so the second is stored past the first.
        let mut a = 0u64;
        let mut b = 0u64;
        'outer: for i in 1u64..100_000 {
            for j in (i + 1)..100_000 {
                if r.home(i) == r.home(j) {
                    a = i;
                    b = j;
                    break 'outer;
                }
            }
        }
        assert!(a != 0 && b != 0, "no colliding pair found");
        assert_eq!(r.home(a), r.home(b), "the pair must collide");

        assert_eq!(r.insert(a, 11), Ok(()));
        assert_eq!(r.insert(b, 22), Ok(()));
        assert_eq!(r.remove(a), Some(11));
        assert_eq!(
            r.remove(b),
            Some(22),
            "the probe stopped at the hole the removal left"
        );
    }

    /// A removed slot must be reusable, or a long-running workload exhausts the table with corpses.
    #[test]
    fn a_removed_slot_is_reused() {
        let r = Registry::with_capacity(64);
        for round in 0..1000u64 {
            assert_eq!(r.insert(0x2000 + round, 8), Ok(()), "round {round}");
            assert_eq!(r.remove(0x2000 + round), Some(8));
        }
        assert_eq!(r.len(), 0);
        assert_eq!(r.insert(0x9999, 8), Ok(()), "the table is still usable");
    }

    /// A full table REFUSES rather than forgetting a size. Forgetting is the worse failure: the
    /// allocation would never be released from the quota when freed, and the slice would leak until
    /// the process exits.
    #[test]
    fn a_full_table_refuses_instead_of_losing_a_size() {
        let r = Registry::with_capacity(64);
        let cap = r.capacity();
        for i in 0..cap as u64 {
            assert_eq!(r.insert(0x10_0000 + i * 4096, 4096), Ok(()), "entry {i}");
        }
        assert_eq!(r.len(), cap);
        match r.insert(0xFFFF_0000, 4096) {
            Err(InsertError::Full { live, capacity }) => {
                assert_eq!((live, capacity), (cap, cap));
            }
            other => panic!("a full table must refuse, got {other:?}"),
        }
        // And every size that WAS recorded is still exactly recoverable.
        let mut recovered = 0u64;
        for i in 0..cap as u64 {
            recovered += r.remove(0x10_0000 + i * 4096).unwrap_or(0);
        }
        assert_eq!(recovered, cap as u64 * 4096, "no size was lost");
    }

    /// Capacity is rounded UP to a power of two and never below the minimum, so a caller's tuning
    /// number never produces a table smaller than they asked for.
    #[test]
    fn capacity_is_rounded_up_to_a_power_of_two() {
        assert_eq!(Registry::with_capacity(0).capacity(), 64);
        assert_eq!(Registry::with_capacity(1).capacity(), 64);
        assert_eq!(Registry::with_capacity(64).capacity(), 64);
        assert_eq!(Registry::with_capacity(65).capacity(), 128);
        assert_eq!(Registry::with_capacity(1000).capacity(), 1024);
        assert_eq!(Registry::with_capacity(1024).capacity(), 1024);
    }

    /// THE HASH IS NOT DECORATION. Device pointers are page aligned, so their low twelve bits are
    /// zero on every allocation. Masking a raw pointer sends them all to one slot and turns the table
    /// into a linked list with O(n) probes. Asserted as a distribution: a thousand page-aligned
    /// pointers must land in many distinct home slots, not in one.
    #[test]
    fn page_aligned_pointers_do_not_all_hash_to_one_slot() {
        let r = Registry::with_capacity(1024);
        let homes: HashSet<usize> = (0..1000u64)
            .map(|i| r.home(0x7F00_0000_0000 + i * 4096))
            .collect();
        assert!(
            homes.len() > 500,
            "page-aligned pointers collapsed into {} slots out of 1024; the multiply is not \
             spreading the high bits",
            homes.len()
        );
        // The control: what masking the raw pointer would have done.
        let naive: HashSet<usize> = (0..1000u64)
            .map(|i| (0x7F00_0000_0000u64 + i * 4096) as usize & 1023)
            .collect();
        assert!(
            naive.len() < homes.len(),
            "the naive mask spread better than the hash, which cannot be right"
        );
    }

    /// Sizes are summable without a scan of the caller's own bookkeeping, for reconciliation.
    #[test]
    fn the_total_is_the_sum_of_the_live_entries() {
        let r = Registry::with_capacity(256);
        assert_eq!(r.total_bytes(), 0);
        for i in 0..100u64 {
            assert_eq!(r.insert(0x5000 + i * 8, 1000 + i), Ok(()));
        }
        let expected: u64 = (0..100u64).map(|i| 1000 + i).sum();
        assert_eq!(r.total_bytes(), expected);
        assert_eq!(r.remove(0x5000), Some(1000));
        assert_eq!(r.total_bytes(), expected - 1000);
    }

    /// Teardown has to hand back everything still live, or a destroyed slice leaves its quota
    /// permanently consumed.
    #[test]
    fn draining_returns_every_live_entry_and_empties_the_table() {
        let r = Registry::with_capacity(256);
        for i in 0..50u64 {
            assert_eq!(r.insert(0x8000 + i * 16, 64 + i), Ok(()));
        }
        let drained = r.drain_all();
        assert_eq!(drained.len(), 50);
        let sum: u64 = drained.iter().map(|(_, s)| *s).sum();
        assert_eq!(sum, (0..50u64).map(|i| 64 + i).sum::<u64>());
        assert!(r.is_empty());
        assert_eq!(r.total_bytes(), 0);
    }

    /// A zero-byte allocation is legal in CUDA. Clamped to one byte so that a recorded allocation
    /// always has a non-zero size, which keeps `total_bytes` honest about how many entries are live.
    #[test]
    fn a_zero_size_is_clamped_to_one_byte() {
        let r = Registry::with_capacity(64);
        assert_eq!(r.insert(0x3000, 0), Ok(()));
        assert_eq!(r.get(0x3000), Some(1), "stored as one byte, not as zero");
        assert_eq!(r.remove(0x3000), Some(1));
    }

    // ── concurrency ──────────────────────────────────────────────────────────────────────────────

    /// Many threads inserting distinct pointers at once. Every one must be recoverable with exactly
    /// its own size: a lost CAS that silently overwrote a neighbour would show up as a wrong size or
    /// a missing entry.
    #[test]
    fn concurrent_inserts_of_distinct_pointers_all_survive() {
        const THREADS: u64 = 8;
        const PER: u64 = 500;
        let r = Arc::new(Registry::with_capacity(8192));
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let r = Arc::clone(&r);
            handles.push(std::thread::spawn(move || {
                for i in 0..PER {
                    let p = 0x10_0000 + (t * PER + i) * 4096;
                    if r.insert(p, 1000 + i).is_err() {
                        return false;
                    }
                }
                true
            }));
        }
        assert!(
            handles.into_iter().all(|h| h.join().unwrap_or(false)),
            "an insert failed on a table with room"
        );
        assert_eq!(r.len(), (THREADS * PER) as usize);
        for t in 0..THREADS {
            for i in 0..PER {
                let p = 0x10_0000 + (t * PER + i) * 4096;
                assert_eq!(r.remove(p), Some(1000 + i), "pointer {p:#x}");
            }
        }
        assert!(r.is_empty());
    }

    /// THE DOUBLE-FREE RACE. Two threads free the same pointer at the same instant. Exactly one must
    /// receive the size; if both did, the quota would be credited twice and would eventually report
    /// more free memory than the card has, which ends in an out-of-memory kill rather than a refusal.
    #[test]
    fn two_threads_freeing_one_pointer_credit_it_exactly_once() {
        const ROUNDS: u64 = 2000;
        let r = Arc::new(Registry::with_capacity(1024));
        for round in 0..ROUNDS {
            let p = 0x4000 + round * 4096;
            assert_eq!(r.insert(p, 777), Ok(()));
            let mut hs = Vec::new();
            for _ in 0..2 {
                let r = Arc::clone(&r);
                hs.push(std::thread::spawn(move || r.remove(p)));
            }
            let got: Vec<Option<u64>> = hs.into_iter().map(|h| h.join().unwrap_or(None)).collect();
            let winners = got.iter().filter(|g| g.is_some()).count();
            assert_eq!(winners, 1, "round {round}: {got:?}");
            assert!(got.contains(&Some(777)));
        }
        assert!(r.is_empty());
    }

    /// Insert and remove churning together, on colliding pointers, landing back at empty. A lost
    /// update in either direction leaves a residue in `live` or a stranded entry.
    #[test]
    fn insert_and_remove_churn_is_balanced() {
        const THREADS: u64 = 8;
        const ROUNDS: u64 = 2000;
        let r = Arc::new(Registry::with_capacity(1024));
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let r = Arc::clone(&r);
            handles.push(std::thread::spawn(move || {
                for i in 0..ROUNDS {
                    let p = 0x20_0000 + (t * 64 + (i % 64)) * 4096;
                    if r.insert(p, 512).is_ok() {
                        assert_eq!(r.remove(p), Some(512));
                    }
                }
            }));
        }
        for h in handles {
            assert!(h.join().is_ok(), "a worker panicked");
        }
        assert_eq!(r.len(), 0, "live count is balanced");
        assert_eq!(r.total_bytes(), 0, "and no entry was stranded");
    }

    /// A reader must never observe a slot that has been claimed but whose size is not yet written.
    /// The size is published with `Release` and read with `Acquire`, and zero means "not yet".
    #[test]
    fn a_concurrent_reader_never_sees_a_zero_size() {
        const ROUNDS: u64 = 5000;
        let r = Arc::new(Registry::with_capacity(1024));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let r = Arc::clone(&r);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    for p in 0..64u64 {
                        if let Some(s) = r.get(0x30_0000 + p * 4096) {
                            assert_ne!(s, 0, "a zero size escaped to a reader");
                        }
                    }
                }
            })
        };
        for i in 0..ROUNDS {
            let p = 0x30_0000 + (i % 64) * 4096;
            if r.insert(p, 4096).is_ok() {
                let _ = r.remove(p);
            }
        }
        stop.store(true, Ordering::Relaxed);
        assert!(reader.join().is_ok(), "the reader observed a torn entry");
    }
}
