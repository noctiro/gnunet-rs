//! Native local FS block storage and streaming file/directory operations.
//! Protocol artifacts and authenticated tree ownership remain in gnunet-fs;
//! this adapter supplies blocking filesystem I/O for a host worker or CLI.
#![cfg(unix)]
#![forbid(unsafe_code)]

mod directory;
#[cfg(feature = "service")]
pub mod durable;
mod error;
/// Bounded local metadata and keyword extraction with no network runtime.
#[cfg(feature = "extraction")]
pub mod extraction;
mod files;
#[cfg(feature = "server")]
pub mod index;
/// Descriptor-root source identity and bounded enumeration, independent of services.
#[cfg(feature = "extraction")]
pub mod input_tree;
#[cfg(feature = "service")]
pub mod ipc;
#[cfg(feature = "network")]
pub mod jobs;
#[cfg(feature = "network")]
pub mod namespace;
#[cfg(feature = "service")]
pub mod network;
mod output;
#[cfg(feature = "service")]
pub mod probe_task;
#[cfg(feature = "network")]
pub mod publication;
#[cfg(feature = "network")]
pub mod unindex_task;

/// Optional bounded directory-change coordinator using actual FS publication tasks.
#[cfg(feature = "auto-share")]
pub mod auto_share;
#[cfg(feature = "service")]
pub mod search;
#[cfg(feature = "server")]
pub mod server;
mod store;
pub use error::{Error, Result};
pub use files::{Buffers, Control, Limits, Progress, Published, ReadFile, open_input};
use gnunet_fs::content::{EncodedNode, NodeRef};
pub use output::{
    ArtifactFailure, ArtifactReport, CommitStage, DirectoryStage, FileIdentity, OWNER_MARKER_NAME,
    ObservedFailure, OutputDir, OwnedDirectoryFailure, RevalidateFailure, RevalidateStage,
    RevalidatedFile,
};
#[cfg(feature = "service")]
pub use output::{RevalidateRangeFailure, RevalidatedRange};
pub use store::{Insert, Repository};

/// Block retrieval port. Returned bytes remain untrusted until the file reader
/// authenticates their actual size, query, AEAD tag and plaintext hash.
pub trait BlockSource {
    /// Copy one exact requested ciphertext block into caller storage.
    fn read_block(&mut self, request: NodeRef, output: &mut [u8]) -> Result<usize>;
}
/// Local/network storage boundary for actual encoded GNUnet blocks.
pub trait BlockSink {
    /// Retain this real encoded block; success reports its storage disposition.
    fn insert_block(&mut self, encoded: EncodedNode<'_>) -> Result<Insert>;
}
pub(crate) fn resize<T: Clone>(buffer: &mut Vec<T>, length: usize, fill: T) -> Result<()> {
    buffer
        .try_reserve_exact(length.saturating_sub(buffer.len()))
        .map_err(|_| Error::Limit)?;
    buffer.resize(length, fill);
    Ok(())
}
