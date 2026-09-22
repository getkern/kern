//! One spelling for "how much of this list does the caller actually need".
//!
//! THE RULE, WHICH IS A MEASUREMENT AND NOT A STYLE: a list's LENGTH and a list's CONTENTS have
//! wildly different costs, and the TUI needs them at different rates. Every frame of `kern top`
//! prints a count for each tab in the tab bar, so every list must be *enumerated* on every frame.
//! Only the tab actually on screen prints rows, so only one list's *records* are needed, and
//! reading records is one `open` apiece.
//!
//! Measured on a host with 316 cached images and 921 build records: the first frame issued 2186
//! `open` calls, of which 921 were build `meta` files and 889 were image sidecars for tabs that
//! were not being drawn. Splitting the two halves took the first frame from 74.9 ms to 7.9 ms.
//!
//! A collector that can skip its per-record work takes a [`Detail`] and returns a [`Listing`]. The
//! point of returning both halves together is that `total` stays correct in BOTH modes: deriving
//! the count from `records.len()` makes the number depend on the caller's `Detail`, so a tab bar
//! would show the true count while its own tab is open and zero everywhere else.
//!
//! Not every collector fits: [`crate::volume::entries_with`] has a different axis, because reading
//! a volume's `meta.json` is what IDENTIFIES it as a volume (and yields its quota) rather than
//! being an extra. It cannot skip the read without miscounting, so it parameterises the recursive
//! size walk instead and says so at its own definition.

/// Does the caller need this list's records, or only how many there are?
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Detail {
    /// Open and parse every record.
    Read,
    /// Enumerate and stop, opening nothing per record.
    Skip,
}

/// The records a caller asked for, plus how many exist either way.
///
/// `total` is counted in the one traversal the collector already makes, so `Detail::Skip` costs a
/// single `read_dir` and nothing else. It is the count of entries that are WELL-FORMED ENOUGH TO
/// EXIST - a record whose body fails to parse is counted and not listed, which is a true statement
/// about the store rather than a discrepancy.
pub(crate) struct Listing<T> {
    pub records: Vec<T>,
    pub total: usize,
}
