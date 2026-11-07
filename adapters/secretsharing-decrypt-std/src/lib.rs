//! Actual original-share781 decryption: verified local quorum for threshold one,
//! and cooperative PILS/CONSENSUS otherwise. General multi-peer generation,
//! qualified DKG and fair-proof production remain separate unfinished work.
#![forbid(unsafe_code)]
mod owner;
mod types;
pub use gnunet_consensus_client_host::Bounds;
pub use gnunet_wire::official::secretsharing::IndexOrder;
pub use owner::Decrypt;
pub use types::*;
