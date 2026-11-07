//! Original two-round native DKG flow and standard final aggregation.
//! Generally usable FAIR and full unchanged-C interoperability remain open;
//! private stage material has a unique owner.
#![forbid(unsafe_code)]
mod admission;
/// Actual receiver closure, original-index selection and bounded aggregation.
pub mod finalize;
mod generation;
/// Actual original-roster reveal construction and checked signature attachment.
pub mod own;
mod owner;
pub use generation::{Generation, GenerationProgress, GenerationReport};
/// Original second-round own/remote flow with honest source evidence.
pub mod round2;
mod types;
pub use gnunet_consensus_client_host::Bounds;
pub use gnunet_pils::client::Instance;
pub use owner::Round1;
pub use types::{
    CompletedRound1, Error, Limits, PeerCommitment, PilsLoss, Progress, Rejection, Report, Request,
    SigningSession, Sources, Transcript, TranscriptParts,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod handoff_tests;
