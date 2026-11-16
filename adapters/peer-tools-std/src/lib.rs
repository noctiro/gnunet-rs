//! Current installed GNUnet HELLO/PILS PROGRAM utilities. No obsolete peerinfo
//! protocol/command, local key file, C wrapper or transport owner is substituted.
#![forbid(unsafe_code)]
mod lifecycle;
mod program;
mod stdio;
pub use program::run;
/// Current official installed program, independent of stale peerinfo manuals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tool {
    /// Export/import/dump official signed public HELLOs.
    Hello,
    /// Observe public local identity from the real PILS MQ.
    Pils,
}
