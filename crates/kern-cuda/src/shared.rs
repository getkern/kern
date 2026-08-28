//! CROSS-PROCESS VRAM ACCOUNTING, as an algorithm over a slice of atomics.
//!
//! [`crate::Quota`] answers "does this fit in MY slice". This answers the question that only exists
//! once there are two tenants: "does this fit in the CARD". Two boxes each given an 8 GiB quota on a
//! 12 GiB card both pass their own check and together overcommit the device by 4 GiB, so a shared
//! total is not an optimisation, it is the difference between a quota that means something across a
//! host and one that means something only inside a process.
//!
//! NO SHARED MEMORY IN THIS FILE, AND NO `unsafe`. Everything here operates on a `&[AtomicU64]` the
//! caller supplies. In production that slice is a `mmap`ed file shared between processes, which
//! [`crate::map`] provides in about twenty audited lines; in tests it is a `Vec`, which is why every
//! property below can be proved without spawning a process or touching the filesystem. The mapping
//! and the algorithm fail in completely different ways, and separating them means neither test has to
//! reason about the other's failure modes.
//!
//! THE HARD PROBLEM IS NOT THE COUNTER, IT IS THE CRASH
//!     A process that dies holding a reservation leaks it. The total stays high, every later tenant
//!     sees less of the card than exists, and nothing ever gives it back. That is the failure that
//!     makes naive shared counters unusable in production, and the whole slot design exists for it:
//!     the total is authoritative and fast, and each process ALSO records its own contribution in a
//!     slot it alone writes, so a survivor can work out exactly how much a corpse was holding and
//!     subtract precisely that.
//!
//! PID REUSE IS THE TRAP UNDER THE TRAP
//!     Liveness by pid alone is wrong: pid 1234 dies, the kernel hands 1234 to an unrelated process,
//!     and the reaper concludes the slot's owner is alive. The leak then becomes permanent. A slot
//!     therefore records the owner's process START TIME as well, and a pid whose start time no longer
//!     matches is a different process wearing a dead one's number.
//!
//! WHAT THIS IS NOT
//!     A boundary, and less of one than [`crate::Quota`] even is. The segment is writable by every
//!     participant by construction: a tenant that wants to defeat the accounting can map it and store
//!     zero into the total. That is inherent to a shared counter between mutually distrusting
//!     processes without a kernel to arbitrate, it is why the tier model calls this `TIER-SOFT`, and
//!     it is stated here rather than left for a reader to work out.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::Refused;

/// Header magic: the ASCII bytes `KERNVRAM`, little-endian, so a hexdump of a live segment is
/// readable and a segment written by something else is rejected rather than misread.
pub const MAGIC: u64 = u64::from_le_bytes(*b"KERNVRAM");

/// Layout version. Bumped whenever the word indices below change meaning.
///
/// Two kern builds with different layouts must never share a segment: the older one would read a
/// slot's `held` out of the newer one's padding and subtract a garbage number from the total. The
/// version is checked on attach and a mismatch is refused, which is the only safe answer, because
/// there is nothing sensible to do with a segment written by a stranger.
pub const VERSION: u64 = 1;

// ── Word layout ──────────────────────────────────────────────────────────────────────────────────
//
// Indices into the `&[AtomicU64]`, not byte offsets into a `repr(C)` struct, and deliberately so.
// A struct shared between processes has to be laid out identically by both, which makes it a
// promise about the compiler; a slice of `u64` is laid out identically by definition. The cost is
// naming the fields here instead of in a type, which is one table.
//
// Everything on the hot path gets a cache line to itself. The total is written by every reservation
// on every process, so anything sharing its line would be invalidated at that rate for no reason.

/// `MAGIC`.
const W_MAGIC: usize = 0;
/// `VERSION`.
const W_VERSION: usize = 1;
/// Number of slots the segment was created with.
const W_SLOTS: usize = 2;

/// Bytes reserved across all live processes. The hot word, alone on its line (byte offset 64).
const W_TOTAL: usize = 8;

/// Incremented every time a dead slot is reclaimed. Diagnostics only: a non-zero value on a healthy
/// host says processes have been dying with allocations outstanding, which an operator wants to know.
const W_GENERATION: usize = 16;

/// First slot word (byte offset 192).
const SLOT_BASE: usize = 24;
/// Words per slot: 8, so each slot occupies exactly one 64-byte cache line and two processes writing
/// their own slots never contend.
const SLOT_WORDS: usize = 8;

/// Slot field: owning pid, or 0 when the slot is free. The word a reaper CASes to claim a corpse.
const S_PID: usize = 0;
/// Slot field: the owner's process start time, the guard against pid reuse.
const S_START: usize = 1;
/// Slot field: bytes this owner has reserved. Written only by the owner, read by reapers.
const S_HELD: usize = 2;

// ── Layout invariants, checked by the COMPILER ───────────────────────────────────────────────────
//
// These were a unit test until clippy pointed out that asserting on constants at runtime is the wrong
// place for it, and clippy was right in a way worth recording: a layout invariant that only fails when
// somebody runs the tests is an invariant that can be broken and shipped. As `const` assertions they
// fail the BUILD, on every target, before anything is linked.
//
// `u64` words per 64-byte cache line.
const LINE_WORDS: usize = 64 / core::mem::size_of::<u64>();

// The hot total must START a cache line, or the header words above it share the line every
// reservation on the host invalidates.
const _: () = assert!(W_TOTAL % LINE_WORDS == 0);
const _: () = assert!(W_GENERATION % LINE_WORDS == 0);
// Slots must start a line, and each must occupy exactly one, or two tenants writing their own slots
// contend with each other for no reason.
const _: () = assert!(SLOT_BASE % LINE_WORDS == 0);
const _: () = assert!(SLOT_WORDS == LINE_WORDS);
// The read-mostly header must sit below the hot word, not beside it.
const _: () = assert!(W_MAGIC < W_TOTAL);
const _: () = assert!(W_VERSION < W_TOTAL);
const _: () = assert!(W_SLOTS < W_TOTAL);
// Slot fields must fit inside a slot, or one slot's `held` is the next slot's pid.
const _: () = assert!(S_PID < SLOT_WORDS);
const _: () = assert!(S_START < SLOT_WORDS);
const _: () = assert!(S_HELD < SLOT_WORDS);
// The generation word must not land inside the slot area.
const _: () = assert!(W_GENERATION < SLOT_BASE);

/// How many `u64` words a segment with `slots` slots needs.
///
/// `const fn` so a caller can size a mapping at compile time when the slot count is fixed.
pub const fn words_for(slots: usize) -> usize {
    SLOT_BASE + slots * SLOT_WORDS
}

/// Why attaching to a segment failed.
///
/// Every variant is a refusal to proceed, never a silent repair. A segment kern does not understand
/// is a segment some other program owns, and writing into it would be worse than not starting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttachError {
    /// The slice is shorter than the header plus the slots it claims to have.
    TooSmall {
        /// Words the slice actually has.
        have: usize,
        /// Words the layout needs.
        need: usize,
    },
    /// The first word is not [`MAGIC`]. Not a kern segment.
    NotOurs {
        /// What was found instead, so an operator can see whose it is.
        found: u64,
    },
    /// The layout version does not match [`VERSION`].
    Version {
        /// The version written in the segment.
        found: u64,
        /// The version this build speaks.
        expected: u64,
    },
    /// Every slot is taken by a live process.
    NoFreeSlot {
        /// How many slots the segment has, all of them occupied.
        slots: usize,
    },
    /// A slot count of zero, which no segment can be initialised with.
    NoSlots,
}

/// Is the process that owns a slot still running?
///
/// A trait rather than a direct `/proc` read, for one reason that matters: liveness is the only part
/// of this file that touches the operating system, and every property worth testing (a corpse is
/// reclaimed, a reused pid is not mistaken for its predecessor, two reapers do not double-subtract)
/// needs liveness to be a thing the test decides. With a trait those tests are deterministic and take
/// microseconds; without one they would need real processes, real crashes and real pid reuse, and
/// would therefore not exist.
pub trait Liveness {
    /// `true` if pid `pid` is running AND was started at `start_time`.
    ///
    /// Both halves are required. A pid that exists with a different start time is a NEW process that
    /// inherited a dead one's number, and treating it as the owner is how a leak becomes permanent.
    fn alive(&self, pid: u64, start_time: u64) -> bool;
}

/// This host's `/proc`, the production implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcLiveness;

impl Liveness for ProcLiveness {
    fn alive(&self, pid: u64, start_time: u64) -> bool {
        match read_start_time(pid) {
            Some(t) => t == start_time,
            None => false,
        }
    }
}

/// The start time of `pid` in clock ticks since boot, from field 22 of `/proc/<pid>/stat`.
///
/// PARSED FROM THE LAST `)`, WHICH IS THE ONLY CORRECT WAY. Field 2 of that file is the executable's
/// name in parentheses, and it is neither escaped nor length-limited: a process named `foo bar)baz`
/// produces a line that splitting on whitespace, or scanning for the first `)`, gets wrong. A parser
/// that gets it wrong reads some other field as the start time, concludes every owner is a reused pid
/// and reclaims live slots, which is strictly worse than the leak this whole mechanism exists to
/// prevent. After the LAST `)` the remaining tokens are fields 3 onward, so field 22 is the 20th.
///
/// Returns `None` for every failure: no such process, unreadable file, malformed line. The caller
/// resolves `None` to "not alive", which for a missing `/proc` entry is exactly right and for an
/// unreadable one is the fail-safe direction, since the alternative is refusing to ever reclaim.
pub fn read_start_time(pid: u64) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_time(&text)
}

/// The parser half of [`read_start_time`], split out so it can be tested against the hostile process
/// names that make this hard, without needing a process actually called `foo) bar`.
pub fn parse_start_time(stat_line: &str) -> Option<u64> {
    let after = &stat_line[stat_line.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// One process's view of a shared segment.
///
/// Holds the slice and the index of the slot this process owns. Not `Clone`: a second copy would be
/// a second owner of one slot, and the two would race each other's `held` in a way no reaper could
/// untangle.
#[derive(Debug)]
pub struct Shared<'a> {
    words: &'a [AtomicU64],
    slots: usize,
    slot: usize,
}

/// Lay out a fresh segment.
///
/// Writes the header and zeroes every slot. The caller guarantees it is the only writer at this
/// moment, which in production means it created the backing file with `O_EXCL` and has not published
/// it yet. Calling this on a segment other processes are already using would zero their slots and
/// strand their reservations in the total forever, so it is deliberately a free function rather than
/// a method: there is no `Shared` in existence to call it on.
///
/// The magic is written LAST, and that ordering is the point. A reader that sees the magic must see
/// a fully formed header behind it, so magic is the publication of everything written before it, with
/// a `Release` store paired against the `Acquire` load in [`Shared::attach`].
pub fn init(words: &[AtomicU64], slots: usize) -> Result<(), AttachError> {
    if slots == 0 {
        return Err(AttachError::NoSlots);
    }
    let need = words_for(slots);
    if words.len() < need {
        return Err(AttachError::TooSmall {
            have: words.len(),
            need,
        });
    }
    for w in words.iter().take(need) {
        w.store(0, Ordering::Relaxed);
    }
    words[W_VERSION].store(VERSION, Ordering::Relaxed);
    words[W_SLOTS].store(slots as u64, Ordering::Relaxed);
    words[W_MAGIC].store(MAGIC, Ordering::Release);
    Ok(())
}

impl<'a> Shared<'a> {
    /// Validate a segment, reclaim anything a dead process left in it, and take a slot.
    ///
    /// The reap happens BEFORE the slot search and not after, because the two are the same problem:
    /// a segment whose slots are all held by corpses has no free slot until somebody reaps, and an
    /// attach that failed with [`AttachError::NoFreeSlot`] on a host where every owner is dead would
    /// be reporting an exhausted resource that is entirely idle.
    pub fn attach<L: Liveness>(
        words: &'a [AtomicU64],
        pid: u64,
        start_time: u64,
        liveness: &L,
    ) -> Result<Self, AttachError> {
        if words.len() <= W_SLOTS {
            return Err(AttachError::TooSmall {
                have: words.len(),
                need: words_for(1),
            });
        }
        let magic = words[W_MAGIC].load(Ordering::Acquire);
        if magic != MAGIC {
            return Err(AttachError::NotOurs { found: magic });
        }
        let version = words[W_VERSION].load(Ordering::Relaxed);
        if version != VERSION {
            return Err(AttachError::Version {
                found: version,
                expected: VERSION,
            });
        }
        let slots = words[W_SLOTS].load(Ordering::Relaxed) as usize;
        if slots == 0 {
            return Err(AttachError::NoSlots);
        }
        let need = words_for(slots);
        if words.len() < need {
            return Err(AttachError::TooSmall {
                have: words.len(),
                need,
            });
        }

        let probe = Shared {
            words,
            slots,
            slot: 0,
        };
        probe.reap_with(liveness);

        for i in 0..slots {
            let pid_word = &words[SLOT_BASE + i * SLOT_WORDS + S_PID];
            if pid_word.load(Ordering::Relaxed) != 0 {
                continue;
            }
            // Claim by CAS, so two processes attaching at the same instant cannot both take slot i.
            // The loser sees a non-zero pid and moves on to the next slot.
            if pid_word
                .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Zero the accounting BEFORE publishing the start time. A slot claimed but not yet
                // described has pid set and start time 0, which no live process matches, so a reaper
                // racing this attach would see the owner as dead and reclaim it. Writing `held`
                // first bounds that to reclaiming zero bytes, which is harmless; the reverse order
                // would let it reclaim a stale `held` left by the slot's previous owner.
                words[SLOT_BASE + i * SLOT_WORDS + S_HELD].store(0, Ordering::Relaxed);
                words[SLOT_BASE + i * SLOT_WORDS + S_START].store(start_time, Ordering::Release);
                return Ok(Shared {
                    words,
                    slots,
                    slot: i,
                });
            }
        }
        Err(AttachError::NoFreeSlot { slots })
    }

    /// Reserve `size` bytes against the physical capacity of the device.
    ///
    /// THE ORDER OF THE TWO WRITES IS A CRASH-CONSISTENCY DECISION, not a style one. The total is
    /// updated first and the slot second, so a process killed between them leaves bytes in the total
    /// that no slot claims. A reaper cannot give those back, so they leak: the card looks smaller
    /// than it is until the segment is recreated. The other order would leave a slot claiming bytes
    /// the total never received, and the reaper would subtract them from an unrelated tenant's usage,
    /// under-reporting the total and letting the card be overcommitted.
    ///
    /// Leaking is bounded by one in-flight allocation per crash and errs toward refusing work.
    /// Under-reporting is unbounded and errs toward accepting work that does not fit. The direction
    /// is chosen; it is not an accident of how the lines happened to be written.
    pub fn reserve(&self, size: u64, physical: u64) -> Result<(), Refused> {
        if size == 0 {
            return Ok(());
        }
        let total = &self.words[W_TOTAL];
        let mut held = total.load(Ordering::Relaxed);
        loop {
            let Some(next) = held.checked_add(size) else {
                return Err(Refused::WouldOverflow);
            };
            if next > physical {
                return Err(Refused::OverQuota {
                    held,
                    limit: physical,
                });
            }
            match total.compare_exchange_weak(held, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(e) => held = e,
            }
        }
        // Uncontended: this word is written by this process alone, and it has a cache line to
        // itself, so this is a local add and not a second point of contention.
        let mine = &self.words[SLOT_BASE + self.slot * SLOT_WORDS + S_HELD];
        mine.store(
            mine.load(Ordering::Relaxed).saturating_add(size),
            Ordering::Relaxed,
        );
        Ok(())
    }

    /// Release `size` bytes.
    ///
    /// Slot first, total second: the mirror of [`Self::reserve`], and for the same reason. A crash
    /// between them leaves the bytes in the total with no slot claiming them, which leaks. The
    /// reverse would remove them from the total while the slot still claims them, so a later reap
    /// would subtract them a second time and drive the total below the truth.
    ///
    /// Both subtractions saturate. A release larger than what is held means the caller lost track of
    /// a size, and wrapping the total would report a card with eighteen exabytes free.
    pub fn release(&self, size: u64) {
        if size == 0 {
            return;
        }
        let mine = &self.words[SLOT_BASE + self.slot * SLOT_WORDS + S_HELD];
        mine.store(
            mine.load(Ordering::Relaxed).saturating_sub(size),
            Ordering::Relaxed,
        );
        let total = &self.words[W_TOTAL];
        let mut held = total.load(Ordering::Relaxed);
        loop {
            let next = held.saturating_sub(size);
            match total.compare_exchange_weak(held, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return,
                Err(e) => held = e,
            }
        }
    }

    /// Reclaim every slot whose owner is gone. Returns how many slots were reclaimed.
    ///
    /// NOT ON THE HOT PATH, and that is a constraint rather than an observation: [`Liveness`] reads
    /// `/proc` in production, which is a syscall per slot. It is called on attach, and by the caller
    /// when a reservation has already failed, which is precisely when a stale reservation is worth
    /// paying a scan to find and is a moment that was going to be slow anyway.
    ///
    /// THE DOUBLE-SUBTRACT RACE, closed by a CAS. Two survivors can notice the same corpse at the
    /// same time; if both subtracted its `held` from the total, the total would fall below the truth
    /// and the card would be overcommitted, which is the direction that causes an out-of-memory kill
    /// rather than a refusal. The pid word is therefore the claim: read `held` first, then CAS the
    /// pid from the dead value to 0, and subtract only if the CAS is won. The corpse cannot be
    /// writing its own slot, so the value read before the claim is the value at the moment of death.
    pub fn reap_with<L: Liveness>(&self, liveness: &L) -> usize {
        let mut reclaimed = 0;
        for i in 0..self.slots {
            let base = SLOT_BASE + i * SLOT_WORDS;
            let owner = self.words[base + S_PID].load(Ordering::Relaxed);
            if owner == 0 {
                continue;
            }
            let start = self.words[base + S_START].load(Ordering::Acquire);
            if liveness.alive(owner, start) {
                continue;
            }
            let held = self.words[base + S_HELD].load(Ordering::Relaxed);
            if self.words[base + S_PID]
                .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                continue; // another survivor claimed this corpse
            }
            self.words[base + S_HELD].store(0, Ordering::Relaxed);
            self.words[base + S_START].store(0, Ordering::Relaxed);
            if held > 0 {
                let total = &self.words[W_TOTAL];
                let mut cur = total.load(Ordering::Relaxed);
                loop {
                    let next = cur.saturating_sub(held);
                    match total.compare_exchange_weak(
                        cur,
                        next,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break,
                        Err(e) => cur = e,
                    }
                }
            }
            self.words[W_GENERATION].fetch_add(1, Ordering::Relaxed);
            reclaimed += 1;
        }
        reclaimed
    }

    /// Give this process's slot back, subtracting whatever it still holds.
    ///
    /// The orderly counterpart of being reaped, for a process that is exiting normally. Not a `Drop`
    /// impl: `Drop` runs on unwind, and a `Shared` dropped while a panic is in flight would release
    /// a slot whose owner is about to abort anyway, which is at best pointless and at worst hides
    /// the crash-consistency behaviour this design is built around. Detaching is a decision.
    pub fn detach(self) {
        let base = SLOT_BASE + self.slot * SLOT_WORDS;
        let held = self.words[base + S_HELD].load(Ordering::Relaxed);
        if held > 0 {
            self.release(held);
        }
        self.words[base + S_START].store(0, Ordering::Relaxed);
        self.words[base + S_PID].store(0, Ordering::Release);
    }

    /// Bytes reserved across every live process.
    pub fn total(&self) -> u64 {
        self.words[W_TOTAL].load(Ordering::Relaxed)
    }

    /// Bytes this process has reserved.
    pub fn held(&self) -> u64 {
        self.words[SLOT_BASE + self.slot * SLOT_WORDS + S_HELD].load(Ordering::Relaxed)
    }

    /// How many slots have been reclaimed from dead owners since the segment was created.
    ///
    /// Non-zero means processes have been dying with device memory outstanding. Worth surfacing:
    /// it is the difference between "the card is full" and "the card looks full because three
    /// crashed tenants are still counted".
    pub fn reclaimed_total(&self) -> u64 {
        self.words[W_GENERATION].load(Ordering::Relaxed)
    }

    /// The slot index this process owns.
    pub fn slot(&self) -> usize {
        self.slot
    }

    /// How many slots the segment has.
    pub fn slots(&self) -> usize {
        self.slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    fn segment(slots: usize) -> Vec<AtomicU64> {
        (0..words_for(slots)).map(|_| AtomicU64::new(0)).collect()
    }

    /// Liveness the test decides, which is the whole reason [`Liveness`] is a trait.
    #[derive(Default)]
    struct Fake {
        live: HashSet<(u64, u64)>,
    }
    impl Fake {
        fn with(pairs: &[(u64, u64)]) -> Self {
            Self {
                live: pairs.iter().copied().collect(),
            }
        }
    }
    impl Liveness for Fake {
        fn alive(&self, pid: u64, start_time: u64) -> bool {
            self.live.contains(&(pid, start_time))
        }
    }

    /// Nothing is alive. Used where a reap must reclaim everything it finds.
    struct NothingAlive;
    impl Liveness for NothingAlive {
        fn alive(&self, _pid: u64, _start: u64) -> bool {
            false
        }
    }

    /// Everything is alive. Used where a reap must reclaim nothing.
    struct AllAlive;
    impl Liveness for AllAlive {
        fn alive(&self, _pid: u64, _start: u64) -> bool {
            true
        }
    }

    // ── the /proc parser, where the trap is ──────────────────────────────────────────────────────

    /// A real line from this machine, and the field that must come out of it.
    #[test]
    fn the_start_time_is_field_22_of_a_real_stat_line() {
        let line = "319623 (cat) R 319615 319623 319615 0 -1 4194304 131 0 0 0 0 0 0 0 20 0 1 0 \
                    1259808 6422528 374 18446744073709551615 959";
        assert_eq!(parse_start_time(line), Some(1_259_808));
    }

    /// THE TRAP. `comm` is field 2, it is the executable name, it is wrapped in parentheses, and it
    /// is neither escaped nor sanitised: a process may legally be called `evil) 1 2 3 (x`. A parser
    /// that splits on whitespace, or scans to the FIRST `)`, reads some other field as the start
    /// time. It would then decide every owner is a reused pid and reclaim live slots, which is worse
    /// than the leak this mechanism exists to prevent.
    #[test]
    fn a_process_name_with_spaces_and_parens_does_not_move_the_field() {
        let hostile =
            "1234 (evil) 1 2 3 (name) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777777 0 0 0";
        assert_eq!(
            parse_start_time(hostile),
            Some(777_777),
            "parsed from the FIRST paren instead of the last"
        );
        let spaces = "1234 (my prog) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 424242 0 0";
        assert_eq!(parse_start_time(spaces), Some(424_242));
    }

    /// Every malformed shape yields `None`, which the caller reads as "not alive". No panic, no
    /// index out of range, no silently wrong number.
    #[test]
    fn a_malformed_stat_line_is_none_and_never_a_panic() {
        for bad in [
            "",
            "no parens here at all",
            "1234 (cat)",
            "1234 (cat) R 1 2 3",
            "1234 (cat) R a b c d e f g h i j k l m n o p q r s",
            ")",
        ] {
            assert_eq!(parse_start_time(bad), None, "input {bad:?}");
        }
    }

    /// The production reader against this very process, which is by definition alive and whose start
    /// time must therefore be readable and stable across two calls.
    #[test]
    fn the_real_proc_reader_agrees_with_itself_on_this_process() {
        let pid = std::process::id() as u64;
        let Some(t) = read_start_time(pid) else {
            // A host without /proc is not a failure of this parser; it is a host this test cannot
            // ask. Named rather than silently passing.
            println!("SKIP: /proc/{pid}/stat is not readable here");
            return;
        };
        assert!(
            t > 0,
            "a start time of 0 would match a freshly claimed slot"
        );
        assert_eq!(read_start_time(pid), Some(t), "not stable across calls");
        assert!(
            ProcLiveness.alive(pid, t),
            "this process must be alive to itself"
        );
        assert!(
            !ProcLiveness.alive(pid, t.wrapping_add(1)),
            "a different start time on the same pid is a DIFFERENT process"
        );
    }

    // ── header validation ────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_fresh_segment_attaches_and_a_foreign_one_does_not() {
        let seg = segment(4);
        assert_eq!(init(&seg, 4), Ok(()));
        let s = Shared::attach(&seg, 100, 7, &AllAlive).expect("attach");
        assert_eq!((s.slots(), s.slot(), s.total()), (4, 0, 0));

        let foreign = segment(4);
        foreign[W_MAGIC].store(0xDEAD_BEEF, Ordering::Relaxed);
        assert_eq!(
            Shared::attach(&foreign, 1, 1, &AllAlive).err(),
            Some(AttachError::NotOurs { found: 0xDEAD_BEEF })
        );
    }

    #[test]
    fn a_segment_from_a_different_layout_version_is_refused() {
        let seg = segment(2);
        assert_eq!(init(&seg, 2), Ok(()));
        seg[W_VERSION].store(VERSION + 1, Ordering::Relaxed);
        assert_eq!(
            Shared::attach(&seg, 1, 1, &AllAlive).err(),
            Some(AttachError::Version {
                found: VERSION + 1,
                expected: VERSION,
            })
        );
    }

    /// A slice too short for the slots the header claims must be refused before anything is read out
    /// of it. This is the shape that would otherwise index past the end.
    #[test]
    fn a_slice_shorter_than_the_header_claims_is_refused() {
        let seg = segment(8);
        assert_eq!(init(&seg, 8), Ok(()));
        let truncated = &seg[..words_for(8) - 1];
        assert_eq!(
            Shared::attach(truncated, 1, 1, &AllAlive).err(),
            Some(AttachError::TooSmall {
                have: words_for(8) - 1,
                need: words_for(8),
            })
        );
        assert_eq!(
            Shared::attach(&seg[..2], 1, 1, &AllAlive).err(),
            Some(AttachError::TooSmall {
                have: 2,
                need: words_for(1),
            })
        );
        assert_eq!(
            init(&seg[..4], 8),
            Err(AttachError::TooSmall {
                have: 4,
                need: words_for(8)
            })
        );
        assert_eq!(init(&seg, 0), Err(AttachError::NoSlots));
    }

    // ── the shared total ─────────────────────────────────────────────────────────────────────────

    /// THE REASON THIS FILE EXISTS. Two tenants each under their own quota, together over the card.
    /// Without the shared total both allocations succeed and the device is overcommitted.
    #[test]
    fn two_tenants_under_their_own_quotas_cannot_together_exceed_the_card() {
        const CARD: u64 = 12 * GIB;
        let seg = segment(4);
        assert_eq!(init(&seg, 4), Ok(()));
        let a = Shared::attach(&seg, 1, 1, &AllAlive).expect("attach a");
        let b = Shared::attach(&seg, 2, 2, &AllAlive).expect("attach b");
        assert_ne!(a.slot(), b.slot(), "two processes must not share a slot");

        assert_eq!(a.reserve(8 * GIB, CARD), Ok(()));
        assert_eq!(
            b.reserve(8 * GIB, CARD).err(),
            Some(Refused::OverQuota {
                held: 8 * GIB,
                limit: CARD
            }),
            "the second 8 GiB would put a 12 GiB card at 16"
        );
        assert_eq!(b.reserve(4 * GIB, CARD), Ok(()), "what fits still fits");
        assert_eq!(a.total(), CARD);
        assert_eq!((a.held(), b.held()), (8 * GIB, 4 * GIB));
    }

    #[test]
    fn a_release_returns_capacity_to_the_other_tenant() {
        const CARD: u64 = 2 * GIB;
        let seg = segment(2);
        assert_eq!(init(&seg, 2), Ok(()));
        let a = Shared::attach(&seg, 1, 1, &AllAlive).expect("a");
        let b = Shared::attach(&seg, 2, 2, &AllAlive).expect("b");
        assert_eq!(a.reserve(2 * GIB, CARD), Ok(()));
        assert!(b.reserve(1, CARD).is_err());
        a.release(GIB);
        assert_eq!(b.reserve(GIB, CARD), Ok(()));
        assert_eq!(a.total(), 2 * GIB);
    }

    #[test]
    fn an_overflowing_reservation_is_refused_and_not_wrapped() {
        let seg = segment(1);
        assert_eq!(init(&seg, 1), Ok(()));
        let s = Shared::attach(&seg, 1, 1, &AllAlive).expect("attach");
        assert_eq!(s.reserve(u64::MAX, u64::MAX), Ok(()));
        assert_eq!(s.reserve(1, u64::MAX), Err(Refused::WouldOverflow));
        assert_eq!(s.total(), u64::MAX);
    }

    #[test]
    fn an_oversized_release_clamps_the_total_and_the_slot() {
        let seg = segment(1);
        assert_eq!(init(&seg, 1), Ok(()));
        let s = Shared::attach(&seg, 1, 1, &AllAlive).expect("attach");
        assert_eq!(s.reserve(MIB, GIB), Ok(()));
        s.release(4 * GIB);
        assert_eq!((s.total(), s.held()), (0, 0), "a double free must not wrap");
        assert_eq!(s.reserve(GIB, GIB), Ok(()));
    }

    #[test]
    fn a_zero_byte_reservation_touches_nothing() {
        let seg = segment(1);
        assert_eq!(init(&seg, 1), Ok(()));
        let s = Shared::attach(&seg, 1, 1, &AllAlive).expect("attach");
        assert_eq!(s.reserve(0, 0), Ok(()));
        s.release(0);
        assert_eq!((s.total(), s.held()), (0, 0));
    }

    // ── crash recovery, the hard part ────────────────────────────────────────────────────────────

    /// A process dies holding 6 GiB. Without a reaper that 6 GiB is gone for the life of the
    /// segment, and the card permanently looks half its size.
    #[test]
    fn a_dead_tenants_reservation_is_reclaimed_exactly() {
        const CARD: u64 = 12 * GIB;
        let seg = segment(4);
        assert_eq!(init(&seg, 4), Ok(()));
        let dead = Shared::attach(&seg, 111, 900, &Fake::with(&[(111, 900)])).expect("dead");
        assert_eq!(dead.reserve(6 * GIB, CARD), Ok(()));
        let live =
            Shared::attach(&seg, 222, 901, &Fake::with(&[(111, 900), (222, 901)])).expect("live");
        assert_eq!(live.reserve(4 * GIB, CARD), Ok(()));
        assert_eq!(live.total(), 10 * GIB);
        assert!(live.reserve(4 * GIB, CARD).is_err(), "card is nearly full");

        // 111 dies. Only 222 is alive now.
        let after = Fake::with(&[(222, 901)]);
        assert_eq!(live.reap_with(&after), 1, "exactly one corpse");
        assert_eq!(
            live.total(),
            4 * GIB,
            "exactly the dead tenant's 6 GiB came back, not more and not less"
        );
        assert_eq!(
            live.held(),
            4 * GIB,
            "the survivor's own accounting is untouched"
        );
        assert_eq!(live.reclaimed_total(), 1);
        assert_eq!(
            live.reserve(8 * GIB, CARD),
            Ok(()),
            "the card is usable again"
        );
    }

    /// PID REUSE. The slot's owner died and the kernel handed its number to something else. Liveness
    /// by pid alone says "alive" and the leak becomes permanent; the start time says otherwise.
    #[test]
    fn a_reused_pid_does_not_protect_a_dead_owners_slot() {
        let seg = segment(2);
        assert_eq!(init(&seg, 2), Ok(()));
        let dead = Shared::attach(&seg, 555, 1000, &Fake::with(&[(555, 1000)])).expect("dead");
        assert_eq!(dead.reserve(GIB, 4 * GIB), Ok(()));

        // pid 555 exists again, started later: a different process wearing the same number.
        let reused = Fake::with(&[(555, 2000)]);
        let probe = Shared::attach(&seg, 777, 1500, &reused).expect("probe");
        assert_eq!(
            probe.total(),
            0,
            "the slot was reclaimed despite its pid being live"
        );
        assert_eq!(probe.reclaimed_total(), 1);
    }

    /// The other direction, and the one a careless start-time check would break: an owner that is
    /// genuinely alive must never be reaped, or a running tenant's accounting is silently zeroed
    /// while it still holds the memory.
    #[test]
    fn a_live_owner_is_never_reclaimed() {
        let seg = segment(2);
        assert_eq!(init(&seg, 2), Ok(()));
        let a = Shared::attach(&seg, 10, 99, &AllAlive).expect("a");
        assert_eq!(a.reserve(GIB, 4 * GIB), Ok(()));
        assert_eq!(a.reap_with(&Fake::with(&[(10, 99)])), 0);
        assert_eq!((a.total(), a.held()), (GIB, GIB));
    }

    /// THE DOUBLE-SUBTRACT RACE. Two survivors notice the same corpse. If both subtracted, the total
    /// would fall below the truth and the card would be overcommitted, which ends in an
    /// out-of-memory kill rather than an honest refusal. The pid CAS makes exactly one of them win.
    #[test]
    fn two_reapers_racing_one_corpse_subtract_it_once() {
        const CARD: u64 = 8 * GIB;
        let seg = Arc::new(segment(4));
        assert_eq!(init(&seg, 4), Ok(()));
        {
            let dead = Shared::attach(&seg, 1, 1, &Fake::with(&[(1, 1)])).expect("dead");
            assert_eq!(dead.reserve(2 * GIB, CARD), Ok(()));
            let keeper = Shared::attach(&seg, 2, 2, &Fake::with(&[(1, 1), (2, 2)])).expect("keep");
            assert_eq!(keeper.reserve(GIB, CARD), Ok(()));
        }
        assert_eq!(seg[W_TOTAL].load(Ordering::Relaxed), 3 * GIB);

        // Only pid 2 is alive. Two threads reap concurrently.
        let mut handles = Vec::new();
        for _ in 0..2 {
            let seg = Arc::clone(&seg);
            handles.push(std::thread::spawn(move || {
                let live = Fake::with(&[(2, 2)]);
                let view = Shared {
                    words: &seg,
                    slots: 4,
                    slot: 1,
                };
                view.reap_with(&live)
            }));
        }
        let reclaimed: usize = handles.into_iter().map(|h| h.join().unwrap_or(0)).sum();
        assert_eq!(reclaimed, 1, "the corpse was claimed exactly once");
        assert_eq!(
            seg[W_TOTAL].load(Ordering::Relaxed),
            GIB,
            "2 GiB subtracted once, not twice"
        );
    }

    /// A slot freed by a corpse is reusable, and the new owner does not inherit the dead one's
    /// accounting. This is the shape that would silently start a fresh tenant at 6 GiB held.
    #[test]
    fn a_reclaimed_slot_is_reused_with_zeroed_accounting() {
        let seg = segment(1);
        assert_eq!(init(&seg, 1), Ok(()));
        let dead = Shared::attach(&seg, 1, 1, &Fake::with(&[(1, 1)])).expect("dead");
        assert_eq!(dead.reserve(3 * GIB, 8 * GIB), Ok(()));
        let fresh = Shared::attach(&seg, 2, 2, &Fake::with(&[(2, 2)])).expect("fresh");
        assert_eq!(fresh.slot(), 0, "the only slot, reused");
        assert_eq!(fresh.held(), 0, "a new tenant starts at zero");
        assert_eq!(fresh.total(), 0, "and the corpse's bytes came back");
    }

    /// Attach reaps BEFORE looking for a slot, so a segment full of corpses is not reported as an
    /// exhausted resource. Without that ordering this returns `NoFreeSlot` on a completely idle host.
    #[test]
    fn a_segment_full_of_corpses_still_admits_a_new_tenant() {
        let seg = segment(2);
        assert_eq!(init(&seg, 2), Ok(()));
        let live = Fake::with(&[(1, 1), (2, 2)]);
        let a = Shared::attach(&seg, 1, 1, &live).expect("a");
        let b = Shared::attach(&seg, 2, 2, &live).expect("b");
        assert_eq!(a.reserve(GIB, 8 * GIB), Ok(()));
        assert_eq!(b.reserve(GIB, 8 * GIB), Ok(()));
        assert!(
            Shared::attach(&seg, 3, 3, &live).is_err(),
            "both slots are held by live owners"
        );
        let c = Shared::attach(&seg, 3, 3, &NothingAlive).expect("both owners died");
        assert_eq!(c.total(), 0, "and their 2 GiB came back");
    }

    #[test]
    fn slots_are_exhausted_deterministically_and_never_shared() {
        let seg = segment(2);
        assert_eq!(init(&seg, 2), Ok(()));
        let a = Shared::attach(&seg, 1, 1, &AllAlive).expect("a");
        let b = Shared::attach(&seg, 2, 2, &AllAlive).expect("b");
        assert_ne!(a.slot(), b.slot());
        assert_eq!(
            Shared::attach(&seg, 3, 3, &AllAlive).err(),
            Some(AttachError::NoFreeSlot { slots: 2 })
        );
    }

    /// An orderly exit gives back both the slot and whatever it still held.
    #[test]
    fn detach_returns_the_slot_and_the_bytes() {
        let seg = segment(1);
        assert_eq!(init(&seg, 1), Ok(()));
        let s = Shared::attach(&seg, 1, 1, &AllAlive).expect("attach");
        assert_eq!(s.reserve(2 * GIB, 8 * GIB), Ok(()));
        s.detach();
        assert_eq!(seg[W_TOTAL].load(Ordering::Relaxed), 0);
        let next = Shared::attach(&seg, 2, 2, &AllAlive).expect("slot is free again");
        assert_eq!(next.slot(), 0);
        assert_eq!(next.reclaimed_total(), 0, "an orderly exit is not a reap");
    }

    // ── concurrency ──────────────────────────────────────────────────────────────────────────────

    /// The shared total is the physical ceiling, so the invariant is the same as the per-process one
    /// and must hold on every interleaving: sixteen threads, a card sized for eight.
    #[test]
    fn concurrent_tenants_never_exceed_the_card() {
        const TENANTS: usize = 16;
        const SLOT: u64 = 512 * MIB;
        let seg = Arc::new(segment(TENANTS));
        assert_eq!(init(&seg, TENANTS), Ok(()));
        let card = SLOT * (TENANTS as u64 / 2);

        let mut handles = Vec::with_capacity(TENANTS);
        for i in 0..TENANTS {
            let seg = Arc::clone(&seg);
            handles.push(std::thread::spawn(move || {
                let pid = i as u64 + 1;
                let live = AllAlive;
                let s = match Shared::attach(&seg, pid, pid, &live) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                s.reserve(SLOT, card).is_ok()
            }));
        }
        let won = handles
            .into_iter()
            .map(|h| h.join().unwrap_or(false))
            .filter(|ok| *ok)
            .count();
        assert_eq!(won, TENANTS / 2, "the card admits exactly half");
        let total = seg[W_TOTAL].load(Ordering::Relaxed);
        assert_eq!(total, card);
        assert!(total <= card, "the invariant, on every interleaving");
    }

    /// Reserve and release from many tenants at once and land exactly back at zero, with every slot
    /// also at zero. A lost update in either the total or a slot shows up here as a residue.
    #[test]
    fn reserve_and_release_are_balanced_across_tenants() {
        const TENANTS: usize = 8;
        const ROUNDS: usize = 2000;
        let seg = Arc::new(segment(TENANTS));
        assert_eq!(init(&seg, TENANTS), Ok(()));

        let mut handles = Vec::with_capacity(TENANTS);
        for i in 0..TENANTS {
            let seg = Arc::clone(&seg);
            handles.push(std::thread::spawn(move || {
                let pid = i as u64 + 1;
                let Ok(s) = Shared::attach(&seg, pid, pid, &AllAlive) else {
                    return;
                };
                for _ in 0..ROUNDS {
                    if s.reserve(MIB, GIB).is_ok() {
                        s.release(MIB);
                    }
                }
            }));
        }
        for h in handles {
            assert!(h.join().is_ok(), "a tenant thread panicked");
        }
        assert_eq!(
            seg[W_TOTAL].load(Ordering::Relaxed),
            0,
            "the total is balanced"
        );
        for i in 0..TENANTS {
            assert_eq!(
                seg[SLOT_BASE + i * SLOT_WORDS + S_HELD].load(Ordering::Relaxed),
                0,
                "slot {i} is balanced"
            );
        }
    }

    /// Attaching concurrently must give every process its own slot. A CAS-free claim would hand two
    /// processes the same one, and their `held` values would then overwrite each other, leaving a
    /// reaper unable to reclaim either correctly.
    #[test]
    fn concurrent_attach_never_hands_out_one_slot_twice() {
        const N: usize = 16;
        let seg = Arc::new(segment(N));
        assert_eq!(init(&seg, N), Ok(()));
        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let seg = Arc::clone(&seg);
            handles.push(std::thread::spawn(move || {
                let pid = i as u64 + 1;
                Shared::attach(&seg, pid, pid, &AllAlive)
                    .map(|s| s.slot())
                    .ok()
            }));
        }
        let slots: Vec<usize> = handles
            .into_iter()
            .filter_map(|h| h.join().unwrap_or(None))
            .collect();
        assert_eq!(slots.len(), N, "every attach succeeded");
        let unique: HashSet<usize> = slots.iter().copied().collect();
        assert_eq!(unique.len(), N, "every process got a distinct slot");
    }

    /// The cache-line invariants are `const` assertions above and fail the build, so what is left to
    /// check at runtime is the one thing that is a function rather than a constant: that the size
    /// computation matches the layout the constants describe. A `words_for` that disagreed with
    /// `SLOT_BASE` and `SLOT_WORDS` would size every mapping wrongly.
    #[test]
    fn the_size_computation_matches_the_layout() {
        assert_eq!(words_for(0), SLOT_BASE, "a slotless segment is header only");
        assert_eq!(words_for(1), SLOT_BASE + SLOT_WORDS);
        assert_eq!(words_for(3), SLOT_BASE + 3 * SLOT_WORDS);
        // The last word of the last slot must lie inside the size that was asked for. An off-by-one
        // here is an index past the end of the mapping on the busiest slot.
        let slots = 5;
        let last = SLOT_BASE + (slots - 1) * SLOT_WORDS + S_HELD;
        assert!(
            last < words_for(slots),
            "the last slot field is inside the segment"
        );
    }
}
