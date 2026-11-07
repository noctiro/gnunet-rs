//! Acknowledged keyword and namespace publication over official DATASTORE IPC.
//!
//! A KSK is an ordered list: every term, including repeated decoded labels,
//! produces its own weighted PUT as the pinned C publisher does. Mandatory flags
//! affect search interpretation only. No namespace key, task, Resolver, remote
//! propagation or update graph is implicitly created by these operations.
use super::{
    BlockOptions, Error as TransferError, TimeLimit,
    publish::{accepted_put, execute, refused},
};
use crate::{Buffers, Control};
use gnunet_crypto::gns::EdkeySecret;
use gnunet_datastore_host::Client;
use gnunet_fs::{
    Keyword, Keywords, KeywordsIter, Uri, metadata,
    ublock::{self, Publisher},
};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::datastore::{DATA_LEN, Data, Request, Response};
use std::fmt;

/// Publication policy with one source-clock target for every actual PUT.
#[derive(Clone, Copy, Debug)]
pub struct UblockOptions {
    /// Original absolute target in the supplied DATASTORE client's clock.
    pub deadline: AbsoluteTime,
    /// Exact official priority, anonymity, replication and expiration fields.
    pub blocks: BlockOptions,
    /// Explicit label/wire/URI bounds. Metadata selection is supplied as a Plan.
    pub limits: ublock::Limits,
    /// Maximum input KSK terms, including repeated decoded labels.
    pub max_keywords: usize,
}
impl UblockOptions {
    /// Default bounded UBLOCK artifacts with caller-selected storage metadata.
    #[must_use]
    pub fn new(deadline: AbsoluteTime, blocks: BlockOptions) -> Self {
        Self {
            deadline,
            blocks,
            limits: ublock::Limits::default(),
            max_keywords: 256,
        }
    }
}
/// Only actual uninterrupted STATUS1 replies contribute to this prefix.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UblockProgress {
    /// Acknowledged input terms in order, not a count of new backend identities.
    pub accepted: usize,
    /// Complete sealed bytes in those acknowledged PUTs, including duplicates.
    pub wire_bytes: u128,
    /// Actual derived lookup key of the last acknowledged term.
    pub last_query: Option<[u8; 64]>,
}
/// Original local/remote dependency or artifact refusal.
#[derive(Debug)]
pub enum FailureCause {
    /// Actual DATASTORE reply/outcome, source deadline, native or resource cause.
    Transfer(TransferError),
    /// Real URI/metadata/signature/encryption derivation or artifact refusal.
    Artifact(ublock::Error),
    /// Explicit caller ownership, label-count or checked representation refusal.
    Protocol(ProtocolError),
    /// Caller stopped between acknowledged operations; no later term was submitted.
    Cancelled,
}
impl fmt::Display for FailureCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transfer(e) => e.fmt(f),
            Self::Artifact(e) => e.fmt(f),
            Self::Protocol(e) => write!(f, "FS UBLOCK publication: {e}"),
            Self::Cancelled => f.write_str("FS UBLOCK publication cancelled"),
        }
    }
}
impl std::error::Error for FailureCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transfer(e) => Some(e),
            Self::Artifact(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Cancelled => None,
        }
    }
}
impl From<TransferError> for FailureCause {
    fn from(e: TransferError) -> Self {
        Self::Transfer(e)
    }
}
impl From<ublock::Error> for FailureCause {
    fn from(e: ublock::Error) -> Self {
        Self::Artifact(e)
    }
}
impl From<ProtocolError> for FailureCause {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

/// Complete actual local acceptance, without durability or remote-copy claims.
pub struct PublishedUblocks {
    /// Exact acknowledged ordered prefix, which equals the complete input length.
    pub progress: UblockProgress,
    /// Explicit caller plan's full/partial/compression report; None means absent.
    pub metadata_selection: Option<metadata::Report>,
    /// Physical retirement trouble after all actual PUT acknowledgements.
    pub cleanup: Option<gnunet_client_host::ConnectError>,
    last_response: Option<OwnedFrame>,
}
impl PublishedUblocks {
    /// Last actual accepted STATUS bytes, retained without another allocation.
    #[must_use]
    pub fn last_response_bytes(&self) -> Option<&[u8]> {
        self.last_response.as_ref().map(OwnedFrame::bytes)
    }
    /// Decode the last actual accepted STATUS including its native diagnostics.
    pub fn last_response(&self) -> Result<Option<Response<'_>>, ProtocolError> {
        self.last_response_bytes().map(Response::decode).transpose()
    }
}
impl fmt::Debug for PublishedUblocks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedUblocks")
            .field("progress", &self.progress)
            .field("metadata_selection", &self.metadata_selection)
            .field("cleanup", &self.cleanup)
            .field(
                "last_response_bytes",
                &self.last_response.as_ref().map(OwnedFrame::len),
            )
            .finish()
    }
}
/// Failure preserves all known acceptance and the failed original operation.
/// An exposed weighted PUT is never retried, and prior accepted terms remain.
pub struct UblockFailure {
    /// Only the known acknowledged prefix; an uncertain term is not counted here.
    pub progress: UblockProgress,
    /// Zero-based input term which failed or was not submitted after cancellation.
    /// Count equals the input length only for a late local completion refusal.
    pub failed_index: usize,
    /// Exact current term's derived key, if derivation completed before refusal.
    pub query: Option<[u8; 64]>,
    /// Actual original artifact, protocol, native, deadline or store outcome.
    pub cause: FailureCause,
    /// Independent actual physical retirement error, not a replacement cause.
    pub retirement_error: Option<gnunet_client_host::ConnectError>,
    /// Local caller plan's selection, not a statement of remote acceptance.
    pub metadata_selection: Option<metadata::Report>,
    last_response: Option<OwnedFrame>,
}
impl UblockFailure {
    /// Last known accepted STATUS before this failure. The failed operation's
    /// actual response/certainty remains inside cause's StoreFailure, if any.
    pub fn last_response(&self) -> Result<Option<Response<'_>>, ProtocolError> {
        self.last_response
            .as_ref()
            .map(|f| Response::decode(f.bytes()))
            .transpose()
    }
}
impl fmt::Debug for UblockFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UblockFailure")
            .field("progress", &self.progress)
            .field("failed_index", &self.failed_index)
            .field("query", &self.query)
            .field("cause", &self.cause)
            .field("retirement_error", &self.retirement_error)
            .field("metadata_selection", &self.metadata_selection)
            .field(
                "last_response_bytes",
                &self.last_response.as_ref().map(OwnedFrame::len),
            )
            .finish()
    }
}
impl fmt::Display for UblockFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FS UBLOCK term {} after {} accepted: {}",
            self.failed_index, self.progress.accepted, self.cause
        )
    }
}
impl std::error::Error for UblockFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Clone, Copy)]
enum Labels<'a> {
    Keyword(&'a [u8]),
    Keywords(Keywords<'a>),
    Namespace {
        secret: &'a EdkeySecret,
        label: &'a [u8],
        update: &'a [u8],
    },
}
#[derive(Clone, Copy)]
enum Term<'a> {
    Keyword(&'a [u8]),
    Decoded(Keyword<'a>),
    Namespace {
        secret: &'a EdkeySecret,
        label: &'a [u8],
        update: &'a [u8],
    },
}
enum Terms<'a> {
    Single(Option<Term<'a>>),
    Keywords(KeywordsIter<'a>),
}
impl<'a> Iterator for Terms<'a> {
    type Item = Term<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Single(t) => t.take(),
            Self::Keywords(k) => k.next().map(Term::Decoded),
        }
    }
}
impl<'a> Labels<'a> {
    fn count(self) -> usize {
        match self {
            Self::Keywords(k) => k.len(),
            _ => 1,
        }
    }
    fn iter(self) -> Terms<'a> {
        match self {
            Self::Keyword(label) => Terms::Single(Some(Term::Keyword(label))),
            Self::Keywords(k) => Terms::Keywords(k.iter()),
            Self::Namespace {
                secret,
                label,
                update,
            } => Terms::Single(Some(Term::Namespace {
                secret,
                label,
                update,
            })),
        }
    }
}
impl<'a> Term<'a> {
    fn label_len(self) -> usize {
        match self {
            Self::Keyword(b) | Self::Namespace { label: b, .. } => b.len(),
            Self::Decoded(k) => k.len(),
        }
    }
    fn update(self) -> &'a [u8] {
        match self {
            Self::Namespace { update, .. } => update,
            _ => b"",
        }
    }
    fn validate(self, limits: ublock::Limits) -> Result<(), FailureCause> {
        if self.label_len() > limits.max_label_bytes {
            return Err(ublock::Error::Limit.into());
        }
        if matches!(self,Self::Keyword(b)|Self::Namespace{label:b,..} if b.contains(&0)) {
            return Err(ublock::Error::Label.into());
        }
        if self.update().contains(&0) {
            return Err(ublock::Error::Update.into());
        }
        Ok(())
    }
    fn publisher<'s>(
        &'s self,
        scratch: &'s mut [u8],
        limits: ublock::Limits,
    ) -> Result<Publisher<'s>, FailureCause> {
        match *self {
            Self::Keyword(label) => Publisher::keyword(label, limits).map_err(Into::into),
            Self::Decoded(keyword) => {
                let n = keyword.write(scratch)?;
                Publisher::keyword(&scratch[..n], limits).map_err(Into::into)
            }
            Self::Namespace { secret, label, .. } => {
                Publisher::namespace(secret, label, limits).map_err(Into::into)
            }
        }
    }
}

impl Buffers {
    /// Publish one exact raw keyword through one actual type9 PUT. The URI and
    /// metadata plan are explicit; no keyword extraction or normalization runs.
    pub async fn store_keyword<'id>(
        &mut self,
        store: Client<'id, '_, '_>,
        label: &[u8],
        uri: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        options: UblockOptions,
        control: impl FnMut(UblockProgress) -> Control,
    ) -> Result<PublishedUblocks, Box<UblockFailure>> {
        self.store_ublocks(
            store,
            Labels::Keyword(label),
            uri,
            metadata,
            options,
            control,
        )
        .await
    }
    /// Publish every decoded KSK term in order, including duplicates. Mandatory
    /// markers are removed only as defined by Keywords::iter/Keyword::bytes.
    /// Repeated labels intentionally add backend priority/replication again.
    pub async fn store_keywords<'id>(
        &mut self,
        store: Client<'id, '_, '_>,
        keywords: Keywords<'_>,
        uri: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        options: UblockOptions,
        control: impl FnMut(UblockProgress) -> Control,
    ) -> Result<PublishedUblocks, Box<UblockFailure>> {
        self.store_ublocks(
            store,
            Labels::Keywords(keywords),
            uri,
            metadata,
            options,
            control,
        )
        .await
    }
    /// Publish one caller-owned namespace identifier and exact optional update
    /// label through one actual type9 PUT. This does not create or persist an
    /// update graph, rotate the namespace key, or recursively publish children.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep namespace key, label, update, URI, metadata and actual store policy explicit"
    )]
    pub async fn store_namespace<'id>(
        &mut self,
        store: Client<'id, '_, '_>,
        secret: &EdkeySecret,
        label: &[u8],
        update: &[u8],
        uri: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        options: UblockOptions,
        control: impl FnMut(UblockProgress) -> Control,
    ) -> Result<PublishedUblocks, Box<UblockFailure>> {
        self.store_ublocks(
            store,
            Labels::Namespace {
                secret,
                label,
                update,
            },
            uri,
            metadata,
            options,
            control,
        )
        .await
    }

    async fn store_ublocks<'id>(
        &mut self,
        mut store: Client<'id, '_, '_>,
        labels: Labels<'_>,
        uri: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        options: UblockOptions,
        mut control: impl FnMut(UblockProgress) -> Control,
    ) -> Result<PublishedUblocks, Box<UblockFailure>> {
        let mut progress = UblockProgress::default();
        let mut failed_index = 0;
        let mut query = None;
        let mut last_response = None;
        let metadata_selection = metadata.map(metadata::Plan::report);
        let result: Result<(), FailureCause> = async {
            if store.pending() != 0 || store.retained_replies() != (0, 0) {
                return Err(ProtocolError::NotReady.into());
            }
            if options.max_keywords == 0 || labels.count() > options.max_keywords {
                return Err(ProtocolError::Capacity.into());
            }
            let mut limits = options.limits;
            limits.max_wire_bytes = limits.max_wire_bytes.min(
                store
                    .protocol_limits()
                    .max_frame_bytes
                    .checked_sub(DATA_LEN)
                    .ok_or(ProtocolError::Capacity)?,
            );
            let mut longest = 0;
            for (index, term) in labels.iter().enumerate() {
                failed_index = index;
                term.validate(limits)?;
                longest = longest.max(term.label_len());
            }
            failed_index = 0;
            crate::resize(&mut self.metadata_plain, longest, 0)
                .map_err(|e| FailureCause::Transfer(e.into()))?;
            // Every term has the same update/URI/metadata shape (namespace is
            // single-term). Preflight that exact shape before the first PUT.
            let first = labels.iter().next().ok_or(ProtocolError::InvalidInput)?;
            let publisher = first.publisher(&mut self.metadata_plain, limits)?;
            let budget = publisher.metadata_budget(first.update(), uri)?;
            let md_bytes = metadata_selection.map_or(0, |r| r.wire_bytes);
            if md_bytes > budget {
                return Err(ublock::Error::Limit.into());
            }
            drop(publisher);
            let uri_bytes = uri.encoded_len().map_err(ublock::Error::Uri)?;
            let wire_bytes = ublock::HEADER_BYTES
                .checked_add(first.update().len())
                .and_then(|n| n.checked_add(2))
                .and_then(|n| n.checked_add(uri_bytes))
                .and_then(|n| n.checked_add(md_bytes))
                .and_then(|n| n.checked_add(ublock::TAG_BYTES))
                .ok_or(ProtocolError::Overflow)?;
            crate::resize(&mut self.record, wire_bytes, 0)
                .map_err(|e| FailureCause::Transfer(e.into()))?;
            let mut time = TimeLimit::new(store.clock(), options.deadline)?;
            for (index, term) in labels.iter().enumerate() {
                failed_index = index;
                query = None;
                time.during(std::future::ready(())).await?;
                if control(progress) == Control::Cancel {
                    return Err(FailureCause::Cancelled);
                }
                let publisher = term.publisher(&mut self.metadata_plain, limits)?;
                let sealed = publisher.seal(term.update(), uri, metadata, &mut self.record)?;
                let key = *sealed.query();
                query = Some(key);
                let next = UblockProgress {
                    accepted: progress
                        .accepted
                        .checked_add(1)
                        .ok_or(ProtocolError::Overflow)?,
                    wire_bytes: progress
                        .wire_bytes
                        .checked_add(sealed.bytes().len() as u128)
                        .ok_or(ProtocolError::Overflow)?,
                    last_query: Some(key),
                };
                let answer = execute(
                    &mut store,
                    &mut time,
                    Request::Put(Data {
                        reservation: 0,
                        kind: 9,
                        priority: options.blocks.priority,
                        anonymity: options.blocks.anonymity,
                        replication: options.blocks.replication,
                        uid: 0,
                        expiration: options.blocks.expiration,
                        key: &key,
                        value: sealed.bytes(),
                    }),
                    None,
                    Some(key),
                )
                .await?;
                if !accepted_put(&answer) {
                    return Err(refused(answer, Some(key)).into());
                }
                progress = next;
                last_response = answer.taken.into_frame();
            }
            Ok(())
        }
        .await;
        // Closure cannot revoke an actual prior ACK. All failure exits preserve
        // the original operation and never automatically repeat a weighted PUT.
        let retirement_error = store.close().err();
        match result {
            Ok(()) => Ok(PublishedUblocks {
                progress,
                metadata_selection,
                cleanup: retirement_error,
                last_response,
            }),
            Err(cause) => Err(Box::new(UblockFailure {
                progress,
                failed_index,
                query,
                cause,
                retirement_error,
                metadata_selection,
                last_response,
            })),
        }
    }
}
