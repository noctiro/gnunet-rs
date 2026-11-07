//! Immutable, bounded standard FS publication artifacts and their payload plans.
//! These local coordinates and body hashes add no GNUnet wire fields.
mod file;
pub mod indexed;
mod records;
#[cfg(test)]
mod tests;
pub mod tree;
use crate::{Buffers, Control, Progress, ReadFile, Repository};
pub use file::{file_budget, prepare_file};
use gnunet_fs::{Content, Uri, metadata, ublock};
pub use records::{prepare_keywords, prepare_namespace};
use std::{fmt, mem::size_of};

/// Local payload identity, separate from the actual DATASTORE lookup key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Payload {
    /// SHA-512 of the exact immutable raw payload bytes.
    pub hash: [u8; 64],
    /// Exact payload length, not physical disk allocation.
    pub bytes: usize,
}
/// Local checked geometry coordinate, never a network request identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Position {
    /// Canonical data/index level in the actual file tree.
    pub level: u8,
    /// Canonical ordinal within that level.
    pub index: u64,
}
/// One ordered standard PUT. Duplicate keys remain separate weighted operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Put {
    /// Official DATASTORE block type: DBLOCK1, IBLOCK2 or UBLOCK9.
    pub kind: u32,
    /// Exact actual DATASTORE lookup key.
    pub key: [u8; 64],
    /// Independently content-addressed local payload.
    pub payload: Payload,
    /// Present only for real file data/index nodes.
    pub position: Option<Position>,
}
/// Original immutable publication intent. Namespace secrets are never retained.
#[derive(Clone, Debug)]
pub enum Artifact {
    /// Full D/I file, including its genuine prepared CHK and original length.
    File(Content),
    /// Real on-demand leaves whose original named source remains required.
    IndexedFile {
        /// Original real CHK.
        content: Content,
        /// Original canonical source and complete plaintext hash.
        source: indexed::Source,
    },
    /// Authenticated postorder full or indexed recursive publication.
    Tree(tree::TreePlan),
    /// Ordered original KSK terms and exact selected target/metadata.
    Keywords {
        /// Complete original canonical KSK bytes, preserving repeated terms.
        query_uri: Vec<u8>,
        /// Complete canonical target URI of any supported official variant.
        target_uri: Vec<u8>,
        /// Exact selected official v2 metadata artifact; None preserves absence.
        metadata: Option<Vec<u8>>,
    },
    /// One already signed namespace record, with no seed or private key bytes.
    Namespace {
        /// Original public namespace identity.
        public: [u8; 32],
        /// Literal current identifier, without a terminator.
        identifier: Vec<u8>,
        /// Literal wire update; empty does not distinguish None from Some(empty).
        update: Vec<u8>,
        /// Complete canonical target URI of any supported official variant.
        target_uri: Vec<u8>,
        /// Exact selected official v2 metadata artifact.
        metadata: Option<Vec<u8>>,
    },
}
/// A prepared artifact plus every actual intended ordered weighted PUT.
#[derive(Clone, Debug)]
pub struct Plan {
    /// Original complete artifact intent; decoded fields do not authenticate it.
    pub artifact: Artifact,
    /// Complete ordered operations, including duplicate payloads/keys.
    pub puts: Vec<Put>,
}
/// Explicit local plan, object, work and artifact bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum ordered operations, including identical repeated terms/nodes.
    pub max_puts: usize,
    /// Logical owned plan bytes; WAL framing and verification workspace have separate bounds.
    pub max_plan_bytes: usize,
    /// Maximum single raw payload, also capped by the official DATASTORE frame.
    pub max_payload_bytes: usize,
    /// Planned actual PUT payload total, counting duplicate weighted operations.
    pub max_stored_bytes: u128,
    /// Original file size and computed ciphertext bounds.
    pub file: crate::Limits,
    /// Actual signed-block, URI and strict metadata parsing bounds.
    pub ublock: ublock::Limits,
    /// Complete recursive source, directory artifact and work bounds.
    pub tree: crate::network::tree_publish::TreeLimits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_puts: 16_384,
            max_plan_bytes: 8 * 1024 * 1024,
            max_payload_bytes: 65_535,
            max_stored_bytes: 1024 * 1024 * 1024,
            file: crate::Limits::default(),
            ublock: ublock::Limits::default(),
            tree: crate::network::tree_publish::TreeLimits::default(),
        }
    }
}
/// Original preparation or verification refusal, with no fabricated receipt.
#[derive(Debug)]
pub enum Error {
    /// Original immutable repository, source, cancellation or file-reader refusal.
    Host(crate::Error),
    /// Actual official geometry/URI or checked representation refusal.
    Protocol(gnunet_types::Error),
    /// Actual signed-block, strict metadata or context refusal.
    Artifact(ublock::Error),
    /// Original selected key-file authority refusal.
    Key(crate::namespace::key::Error),
    /// Original typed recursive source, directory planning or global budget refusal.
    Tree(Box<crate::network::tree_publish::TreePublishCause>),
    /// Original standard extractor/caller cause, including original descriptor
    /// restoration failure. This remains a host-only metadata producer boundary.
    Extraction(Box<crate::extraction::Error>),
    /// An explicit plan/object/work bound was exceeded.
    Limit,
    /// Plan fields or payloads differ from the original authenticated artifact.
    Binding,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Artifact(e) => e.fmt(f),
            Self::Key(e) => e.fmt(f),
            Self::Tree(e) => e.fmt(f),
            Self::Extraction(e) => e.fmt(f),
            Self::Limit => f.write_str("FS publication plan limit exceeded"),
            Self::Binding => {
                f.write_str("FS publication plan does not match its authenticated artifact")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Host(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Artifact(e) => Some(e),
            Self::Key(e) => Some(e),
            Self::Tree(e) => Some(e.as_ref()),
            Self::Extraction(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        Self::Host(e)
    }
}
impl From<crate::extraction::Error> for Error {
    fn from(error: crate::extraction::Error) -> Self {
        Self::Extraction(Box::new(error))
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Host(e.into())
    }
}
impl From<gnunet_types::Error> for Error {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<ublock::Error> for Error {
    fn from(e: ublock::Error) -> Self {
        Self::Artifact(e)
    }
}
impl From<metadata::Error> for Error {
    fn from(e: metadata::Error) -> Self {
        Self::Artifact(ublock::Error::Metadata(e))
    }
}
impl From<crate::namespace::key::Error> for Error {
    fn from(e: crate::namespace::key::Error) -> Self {
        Self::Key(e)
    }
}
impl From<crate::network::tree_publish::TreePublishCause> for Error {
    fn from(e: crate::network::tree_publish::TreePublishCause) -> Self {
        Self::Tree(Box::new(e))
    }
}
/// Fresh verification facts obtained from the actual immutable payloads.
#[derive(Debug)]
pub struct VerifiedPlan {
    file: Option<ReadFile>,
    tree: Option<tree::VerifiedTree>,
    puts: usize,
    bytes: u128,
}
impl VerifiedPlan {
    /// Genuine core reader receipt for file plans; no field projection can mint one.
    #[must_use]
    pub const fn file(&self) -> Option<ReadFile> {
        self.file
    }
    /// Fresh complete parent membership and whole-tree payload verification.
    #[must_use]
    pub const fn tree(&self) -> Option<tree::VerifiedTree> {
        self.tree
    }
    /// Number of exact planned PUTs checked, including duplicates.
    #[must_use]
    pub const fn puts(&self) -> usize {
        self.puts
    }
    /// Actual checked planned payload bytes, including duplicates.
    #[must_use]
    pub const fn bytes(&self) -> u128 {
        self.bytes
    }
}
impl Plan {
    /// Exact ordered named sources whose real FS registrations are required.
    #[must_use]
    pub fn index_sources(&self) -> &[indexed::Source] {
        match &self.artifact {
            Artifact::IndexedFile { source, .. } => std::slice::from_ref(source),
            Artifact::Tree(tree) => &tree.sources,
            _ => &[],
        }
    }
    /// Original on-demand source for one exact ordered PUT, when needed.
    #[must_use]
    pub fn source_for_put(&self, index: usize) -> Option<&indexed::Source> {
        match &self.artifact {
            Artifact::IndexedFile { source, .. } if index < self.puts.len() => Some(source),
            Artifact::Tree(tree) => tree.source_for_put(index),
            _ => None,
        }
    }
    /// Logical owned plan storage, excluding reusable validation scratch and WAL copies.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let mut total = size_of::<Self>()
            .checked_add(
                self.puts
                    .len()
                    .checked_mul(size_of::<Put>())
                    .ok_or(Error::Limit)?,
            )
            .ok_or(Error::Limit)?;
        let mut add = |n: usize| -> Result<(), Error> {
            total = total.checked_add(n).ok_or(Error::Limit)?;
            Ok(())
        };
        match &self.artifact {
            Artifact::File(_) => {}
            Artifact::IndexedFile { source, .. } => add(source.path.len())?,
            Artifact::Tree(tree) => {
                add(tree
                    .objects
                    .len()
                    .checked_mul(size_of::<tree::TreeObject>())
                    .ok_or(Error::Limit)?)?;
                add(tree
                    .sources
                    .len()
                    .checked_mul(size_of::<indexed::Source>())
                    .ok_or(Error::Limit)?)?;
                for object in &tree.objects {
                    add(object.path.len())?;
                }
                for source in &tree.sources {
                    add(source.path.len())?;
                }
            }
            Artifact::Keywords {
                query_uri,
                target_uri,
                metadata,
            } => {
                add(query_uri.len())?;
                add(target_uri.len())?;
                if let Some(m) = metadata {
                    add(m.len())?;
                }
            }
            Artifact::Namespace {
                identifier,
                update,
                target_uri,
                metadata,
                ..
            } => {
                add(identifier.len())?;
                add(update.len())?;
                add(target_uri.len())?;
                if let Some(m) = metadata {
                    add(m.len())?;
                }
            }
        }
        Ok(total)
    }
    /// Complete selected PUT payload total; this is not physical disk usage or replication.
    pub fn stored_bytes(&self) -> Result<u128, Error> {
        self.puts.iter().try_fold(0u128, |n, row| {
            n.checked_add(row.payload.bytes as u128).ok_or(Error::Limit)
        })
    }
    /// Validate geometry, URI, exact order/bindings and resource policy without
    /// reading payloads. This does not manufacture an authenticated file receipt.
    pub fn validate(&self, limits: Limits) -> Result<(), Error> {
        if self.puts.is_empty()
            || self.puts.len() > limits.max_puts
            || self.retained_bytes()? > limits.max_plan_bytes
            || self.stored_bytes()? > limits.max_stored_bytes
        {
            return Err(Error::Limit);
        }
        for put in &self.puts {
            if put.payload.bytes == 0
                || put.payload.bytes > limits.max_payload_bytes
                || put.payload.bytes > gnunet_wire::official::datastore::MAX_VALUE_BYTES
            {
                return Err(Error::Limit);
            }
        }
        match &self.artifact {
            Artifact::File(content) => file::validate(self, *content, limits),
            Artifact::IndexedFile { content, source } => {
                indexed::validate(source, *content, &self.puts, limits)
            }
            Artifact::Tree(tree) => tree::validate(tree, &self.puts, limits),
            _ => records::validate(self, limits),
        }
    }
    /// Reauthenticate all payloads through the real FileReader or original UBLOCK
    /// context. Historical metadata, row count, size or CRC alone never suffice.
    pub fn verify(
        &self,
        repo: &mut Repository,
        buffers: &mut Buffers,
        limits: Limits,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<VerifiedPlan, Error> {
        self.validate(limits)?;
        let mut tree_proof = None;
        let file = match &self.artifact {
            Artifact::File(content) => Some(file::verify(
                self,
                *content,
                repo,
                buffers,
                limits,
                &mut control,
            )?),
            Artifact::IndexedFile { content, source } => Some(indexed::verify(
                source,
                *content,
                &self.puts,
                repo,
                buffers,
                limits,
                &mut control,
            )?),
            Artifact::Tree(tree) => {
                let (root, proof) =
                    tree::verify(tree, &self.puts, repo, buffers, limits, &mut control)?;
                tree_proof = Some(proof);
                Some(root)
            }
            _ => {
                records::verify(self, repo, limits, &mut control)?;
                None
            }
        };
        Ok(VerifiedPlan {
            file,
            tree: tree_proof,
            puts: self.puts.len(),
            bytes: self.stored_bytes()?,
        })
    }
}
fn owned(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len()).map_err(|_| Error::Limit)?;
    v.extend_from_slice(bytes);
    Ok(v)
}
fn uri_bytes(uri: Uri<'_>, limits: Limits) -> Result<Vec<u8>, Error> {
    let n = uri.encoded_len()?;
    if n > limits.ublock.uri.max_input_bytes || n > limits.max_plan_bytes {
        return Err(Error::Limit);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Error::Limit)?;
    out.resize(n, 0);
    uri.encode(&mut out)?;
    Ok(out)
}
fn selected_metadata(
    plan: Option<&metadata::Plan<'_>>,
    limits: Limits,
) -> Result<Option<Vec<u8>>, Error> {
    plan.map(|plan| {
        let n = plan.report().wire_bytes;
        if n > limits.ublock.metadata.max_coded_bytes || n > limits.max_plan_bytes {
            return Err(Error::Limit);
        }
        let mut out = Vec::new();
        out.try_reserve_exact(n).map_err(|_| Error::Limit)?;
        out.resize(n, 0);
        plan.write(&mut out)?;
        Ok(out)
    })
    .transpose()
}
