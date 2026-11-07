//! Native availability observations of one root-authenticated data leaf.
//!
//! A probe uses the ordinary FS lookup owner and its original absolute deadline.
//! It fetches only the selected leaf and necessary authenticated index path,
//! discards plaintext, and neither reads nor populates a local cache. A receipt
//! proves this particular range was retrieved; it proves neither the rest of the
//! file nor future network availability. An elapsed deadline is inconclusive.

use super::{DownloadOptions, Error, Lookup};
use crate::{Buffers, Control, Progress};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{
    Content,
    content::{BLOCK_BYTES, BlockKey, Layout, RangeReader, TAG_BYTES, VerifiedRange},
};
use gnunet_types::{AbsoluteTime, Duration, Error as ProtocolError};
use gnunet_wire::official::fs::{BlockType, Response};
use std::{fmt, ops::Range};

/// Caller policy for a native probe of one explicitly selected leaf ordinal.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Ordinary official FS search policy, including the original absolute
    /// deadline, anonymity, verified LOC target and explicit loopback choice.
    /// Its whole-tree limits are superseded by the path limits below.
    pub transfer: DownloadOptions,
    /// Largest file size admitted by caller policy, independent of path work.
    pub max_file_bytes: u64,
    /// Maximum authenticated blocks on the selected leaf-to-root path.
    pub max_path_blocks: u64,
    /// Maximum exact ciphertext bytes on that path, including every AEAD tag.
    pub max_encoded_bytes: u128,
}
impl Options {
    /// Ordinary anonymous discovery, admitting the maximum eight-level path.
    #[must_use]
    pub fn new(deadline: AbsoluteTime) -> Self {
        Self::from(DownloadOptions::new(deadline))
    }
}
impl From<DownloadOptions> for Options {
    fn from(transfer: DownloadOptions) -> Self {
        Self {
            max_file_bytes: transfer.limits.max_file_bytes,
            transfer,
            max_path_blocks: 8,
            max_encoded_bytes: 8 * (BLOCK_BYTES + TAG_BYTES) as u128,
        }
    }
}

/// Uniformly select one actual data-leaf ordinal, including a partial tail.
/// Empty content has one real empty-root leaf. Rejection sampling avoids modulo
/// bias and is bounded to 64 entropy reads; entropy failure yields no selection.
/// This is local caller policy and adds no field or flag to an FS message.
pub fn sample_leaf(
    content: Content,
    entropy: &mut impl gnunet_crypto::Entropy,
) -> Result<u64, ProtocolError> {
    let count = Layout::new(content.size).leaf_count();
    if count == 1 {
        return Ok(0);
    }
    let threshold = count.wrapping_neg() % count;
    for _ in 0..64 {
        let mut bytes = [0; 8];
        entropy.fill(&mut bytes)?;
        let value = u64::from_be_bytes(bytes);
        if value >= threshold {
            return Ok(value % count);
        }
    }
    Err(ProtocolError::Entropy)
}

/// Actual native run together with its original matching selected-path replies.
/// Only `Buffers::probe_recorded` constructs this wrapper. The raw frames are
/// original authenticated-prefix observations; replay independently checks them
/// before treating them as historical crypto evidence. No whole-file or freshness
/// receipt can be projected from these public observations.
#[derive(Debug)]
pub struct Recorded {
    result: Result<Observed, Failure>,
    frames: Vec<Vec<u8>>,
}
impl Recorded {
    /// Borrow the original actual proof or complete typed failure.
    #[must_use]
    pub const fn result(&self) -> &Result<Observed, Failure> {
        &self.result
    }
    /// Original matching complete responses in selected root-to-leaf order.
    /// Only frames accepted by the original range reader are retained here.
    /// Rejected or fetched-but-unaccepted final replies remain separately in
    /// Failure.last_response; no unrelated delayed frame enters this prefix.
    #[must_use]
    pub fn frames(&self) -> &[Vec<u8>] {
        &self.frames
    }
    /// Consume the actual wrapper into its original result and retained frames.
    /// The frames can be persisted as history, but cannot reconstruct Observed.
    pub fn into_parts(self) -> (Result<Observed, Failure>, Vec<Vec<u8>>) {
        (self.result, self.frames)
    }
}

#[derive(Default)]
struct Recording {
    frames: Vec<Vec<u8>>,
    used: usize,
}
impl Recording {
    fn prepare(&mut self, layout: Layout, leaf: u64) -> Result<(), Error> {
        // Reserve and initialize the exact legal frame length of each real
        // selected path node before native work. Native recording then performs
        // only checked copies: an allocator refusal cannot erase an I/O result.
        self.frames
            .try_reserve_exact(usize::from(layout.levels()))
            .map_err(|_| crate::Error::Limit)?;
        let mut node = layout.leaf(leaf)?;
        loop {
            let length = super::CLIENT_PUT_PREFIX + node.plaintext_bytes() + TAG_BYTES;
            let mut frame = Vec::new();
            frame
                .try_reserve_exact(length)
                .map_err(|_| crate::Error::Limit)?;
            frame.resize(length, 0);
            self.frames.push(frame);
            let Some(parent) = node.parent() else { break };
            node = parent;
        }
        self.frames.reverse();
        Ok(())
    }
    fn capture(&mut self, lookup: &Lookup) -> Result<(), Error> {
        let frame = lookup
            .channel
            .framing()
            .and_then(|framed| framed.frame())
            .ok_or(ProtocolError::NotReady)?;
        let slot = self
            .frames
            .get_mut(self.used)
            .ok_or(ProtocolError::Capacity)?;
        if frame.len() != slot.len() {
            return Err(ProtocolError::Malformed.into());
        }
        slot.copy_from_slice(frame);
        self.used += 1;
        Ok(())
    }
    fn finish(mut self) -> Vec<Vec<u8>> {
        self.frames.truncate(self.used);
        self.frames
    }
}

/// Reauthenticate one complete historical selected path from original FS frames.
/// This checks exact frame count/order/type, size, CHK query, AEAD and plaintext
/// keys through the same root-bound range reader. Stored expiration/transmission
/// metadata does not establish current retention or reachability, and this pure
/// operation can mint only VerifiedRange, never a native Observed or VerifiedFile.
pub fn revalidate(
    content: Content,
    leaf: u64,
    frames: &[Vec<u8>],
    buffers: &mut Buffers,
) -> Result<VerifiedRange, Error> {
    let (_, completion) = revalidate_prefix(content, leaf, frames, buffers)?;
    completion.ok_or(ProtocolError::Malformed.into())
}

/// Reauthenticate an exact original selected-path prefix using reusable buffers.
/// Returns only actual authenticated work and an optional completed historical
/// range proof. Empty or incomplete prefixes produce no completion. A complete
/// prefix from an interrupted run does not turn that native failure into success;
/// neither this result nor stored timing metadata can reconstruct Observed.
pub fn revalidate_prefix(
    content: Content,
    leaf: u64,
    frames: &[Vec<u8>],
    buffers: &mut Buffers,
) -> Result<(Progress, Option<VerifiedRange>), Error> {
    let layout = Layout::new(content.size);
    let range = layout.leaf(leaf)?.range();
    if frames.len() > usize::from(layout.levels()) {
        return Err(ProtocolError::Malformed.into());
    }
    crate::resize(
        &mut buffers.keys,
        layout.required_keys(),
        BlockKey::default(),
    )?;
    let mut reader = RangeReader::new(content, range, &mut buffers.keys)?;
    let mut progress = Progress::default();
    for frame in frames {
        let request = reader.next().ok_or(ProtocolError::Malformed)?;
        let Response::Put(put) = Response::decode(frame)? else {
            return Err(ProtocolError::Malformed.into());
        };
        let expected = if request.node().level() == 0 {
            BlockType::DBLOCK
        } else {
            BlockType::IBLOCK
        };
        if put.block_type != expected
            || put.block.len() != request.node().plaintext_bytes() + TAG_BYTES
        {
            return Err(ProtocolError::Authentication.into());
        }
        // The original pending NodeRef validates query, size, tag and plaintext
        // key before it authenticates the child references or selected data.
        if let Some(chunk) = reader.open_next(put.block, &mut buffers.plain)? {
            progress.plaintext_bytes += chunk.bytes().len() as u64;
        }
        progress.blocks += 1;
        progress.encoded_bytes += put.block.len() as u128;
    }
    Ok((progress, reader.completion()))
}

#[derive(Debug)]
struct Snapshot {
    content: Content,
    leaf: u64,
    range: Option<Range<u64>>,
    policy: DownloadOptions,
    progress: Progress,
    started: Option<AbsoluteTime>,
    last_checked: Option<AbsoluteTime>,
    queries_written: u64,
    response: Vec<u8>,
    retired: bool,
}
impl Snapshot {
    fn new(content: Content, leaf: u64, options: Options) -> Self {
        Self {
            content,
            leaf,
            range: None,
            policy: options.transfer,
            progress: Progress::default(),
            started: None,
            last_checked: None,
            queries_written: 0,
            response: Vec::new(),
            retired: false,
        }
    }
    fn capture(&mut self, lookup: &Lookup) {
        self.last_checked = Some(lookup.time.now);
        self.queries_written = lookup.queries_written;
        if let Some(frame) = lookup.channel.framing().and_then(|framed| framed.frame()) {
            // Capacity for the largest admitted raw response was reserved before
            // constructing the native owner. Preserve actual bytes, not a
            // reconstructed response or an interpretation of a partial frame.
            self.response.clear();
            self.response.extend_from_slice(frame);
        }
    }
    fn refuse(self, cause: Error) -> Failure {
        Failure {
            detail: Box::new(FailureDetail {
                cause,
                snapshot: self,
            }),
        }
    }
}

/// Successful observation minted only by this actual native range retrieval.
/// Private fields prevent a local block-reader receipt from being presented as
/// a native observation. No whole-file receipt is constructed by this operation.
#[derive(Debug)]
pub struct Observed {
    verified: VerifiedRange,
    started: AbsoluteTime,
    finished: AbsoluteTime,
    snapshot: Snapshot,
}
impl Observed {
    /// Root-authenticated range obtained from actual service replies.
    #[must_use]
    pub const fn verified(&self) -> VerifiedRange {
        self.verified
    }
    /// Actual authenticated work, including every necessary index block.
    #[must_use]
    pub const fn progress(&self) -> Progress {
        self.snapshot.progress
    }
    /// Explicitly selected canonical data-leaf ordinal.
    #[must_use]
    pub const fn leaf(&self) -> u64 {
        self.snapshot.leaf
    }
    /// Exact authenticated interval, clipping a tail leaf to the file length.
    #[must_use]
    pub fn range(&self) -> Range<u64> {
        self.verified.range()
    }
    /// Original source-clock sample at native-owner construction.
    #[must_use]
    pub const fn started(&self) -> AbsoluteTime {
        self.started
    }
    /// Source-clock sample at the final successful deadline checkpoint.
    #[must_use]
    pub const fn finished(&self) -> AbsoluteTime {
        self.finished
    }
    /// Checked interval between accepted logical source-clock observations.
    /// Forward clock adjustment affects this value; it is not native elapsed
    /// time or the official client's active queue-time metric.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        Duration(self.finished.as_micros() - self.started.as_micros())
    }
    /// Actual completely written SEARCH frames, including any reconnect retry.
    #[must_use]
    pub const fn queries_written(&self) -> u64 {
        self.snapshot.queries_written
    }
    /// Original most recently retained complete FS response. The owner retains
    /// one bounded frame; unrelated delayed replies are routed by Lookup.
    #[must_use]
    pub fn last_response(&self) -> &[u8] {
        &self.snapshot.response
    }
    /// Actual official search policy used for this observation.
    #[must_use]
    pub const fn policy(&self) -> DownloadOptions {
        self.snapshot.policy
    }
    /// The original native channel and clock subscription were explicitly closed.
    #[must_use]
    pub const fn retired(&self) -> bool {
        self.snapshot.retired
    }
}

#[derive(Debug)]
struct FailureDetail {
    cause: Error,
    snapshot: Snapshot,
}
/// Refused or interrupted observation with its original cause and actual work.
/// A deadline is not proof of absence; setup refusal, cancellation, clock loss
/// and malformed replies remain separately inspectable through the original
/// error. No completion receipt is available on this type.
#[derive(Debug)]
pub struct Failure {
    detail: Box<FailureDetail>,
}
impl Failure {
    /// Original setup, local resource, transport, clock or authentication error.
    #[must_use]
    pub fn cause(&self) -> &Error {
        &self.detail.cause
    }
    /// Consume diagnostics and recover the original error without conversion.
    #[must_use]
    pub fn into_cause(self) -> Error {
        self.detail.cause
    }
    /// Original selected content identity, retaining its size-bound CHK.
    #[must_use]
    pub fn content(&self) -> Content {
        self.detail.snapshot.content
    }
    /// Explicit requested leaf ordinal, including an out-of-range refusal.
    #[must_use]
    pub fn leaf(&self) -> u64 {
        self.detail.snapshot.leaf
    }
    /// Checked selected range, absent when the leaf ordinal was invalid.
    #[must_use]
    pub fn range(&self) -> Option<Range<u64>> {
        self.detail.snapshot.range.clone()
    }
    /// Authenticated blocks and plaintext processed before refusal/interruption.
    #[must_use]
    pub fn progress(&self) -> Progress {
        self.detail.snapshot.progress
    }
    /// Native-owner start, absent for setup refusals before owner construction.
    #[must_use]
    pub fn started(&self) -> Option<AbsoluteTime> {
        self.detail.snapshot.started
    }
    /// Last accepted monotonic source-clock sample. On a clock refusal this
    /// deliberately does not claim a known completion/retirement timestamp.
    #[must_use]
    pub fn last_checked(&self) -> Option<AbsoluteTime> {
        self.detail.snapshot.last_checked
    }
    /// Completely written actual SEARCH frames; zero distinguishes a refusal
    /// before any complete native request from an attempted quiet lookup.
    #[must_use]
    pub fn queries_written(&self) -> u64 {
        self.detail.snapshot.queries_written
    }
    /// Most recently retained original complete response, including a complete
    /// rejected response if present. Partial bytes never masquerade as a reply.
    #[must_use]
    pub fn last_response(&self) -> &[u8] {
        &self.detail.snapshot.response
    }
    /// Original official lookup policy, unchanged by retries or cancellation.
    #[must_use]
    pub fn policy(&self) -> DownloadOptions {
        self.detail.snapshot.policy
    }
    /// Whether an original native owner existed and was explicitly closed.
    /// Channel closure is infallible; no cleanup error is synthesized.
    #[must_use]
    pub fn retired(&self) -> bool {
        self.detail.snapshot.retired
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.detail.cause.fmt(f)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.detail.cause)
    }
}

fn path(
    content: Content,
    leaf: u64,
    options: Options,
    selected: &mut Option<Range<u64>>,
) -> Result<(Layout, Range<u64>), Error> {
    let layout = Layout::new(content.size);
    let mut node = layout.leaf(leaf)?;
    let range = node.range();
    *selected = Some(range.clone());
    let mut blocks = 0u64;
    let mut encoded = 0u128;
    loop {
        blocks += 1;
        encoded += (node.plaintext_bytes() + TAG_BYTES) as u128;
        let Some(parent) = node.parent() else {
            break;
        };
        node = parent;
    }
    if content.size > options.max_file_bytes
        || blocks > options.max_path_blocks
        || encoded > options.max_encoded_bytes
    {
        return Err(crate::Error::Limit.into());
    }
    Ok((layout, range))
}

impl Buffers {
    /// Retrieve and authenticate one explicitly selected canonical data leaf and
    /// only its necessary index ancestors through the ordinary native FS pipe.
    ///
    /// The caller chooses a valid leaf ordinal (uniform sampling is separate
    /// caller policy). A tail is clipped exactly. Explicit leaf0 for empty
    /// content authenticates its actual empty encrypted root; a zero-byte receipt
    /// is not a claim that nonempty file data was observed. No cache or output is
    /// involved. The transfer policy preserves caller anonymity, signed LOC
    /// placement and explicit local-only choice without adding probe wire flags.
    /// Dropping this future closes its original owner through Channel's Drop.
    pub async fn probe(
        &mut self,
        source: EndpointSource,
        content: Content,
        leaf: u64,
        options: Options,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<Observed, Failure> {
        self.probe_inner(source, content, leaf, options, control, None)
            .await
    }

    /// Retrieve the same actual native range while retaining its complete
    /// matching path replies. All transcript storage is reserved before native
    /// work and bounded by the selected path, at most eight protocol frames.
    /// Regular `probe` does not allocate this additional transcript. A failure
    /// returns its original typed result and only its actually authenticated
    /// prefix frames. Historical replay must independently check those frames.
    pub async fn probe_recorded(
        &mut self,
        source: EndpointSource,
        content: Content,
        leaf: u64,
        options: Options,
        control: impl FnMut(Progress) -> Control,
    ) -> Recorded {
        let mut recording = Recording::default();
        let result = self
            .probe_inner(
                source,
                content,
                leaf,
                options,
                control,
                Some(&mut recording),
            )
            .await;
        Recorded {
            result,
            frames: recording.finish(),
        }
    }

    async fn probe_inner(
        &mut self,
        source: EndpointSource,
        content: Content,
        leaf: u64,
        options: Options,
        mut control: impl FnMut(Progress) -> Control,
        mut recording: Option<&mut Recording>,
    ) -> Result<Observed, Failure> {
        let mut snapshot = Snapshot::new(content, leaf, options);
        let (layout, range) = match path(content, leaf, options, &mut snapshot.range) {
            Ok(plan) => plan,
            Err(cause) => return Err(snapshot.refuse(cause)),
        };
        if let Some(recording) = recording.as_deref_mut()
            && let Err(cause) = recording.prepare(layout, leaf)
        {
            return Err(snapshot.refuse(cause));
        }
        if let Err(cause) =
            crate::resize(&mut self.keys, layout.required_keys(), BlockKey::default())
        {
            return Err(snapshot.refuse(cause.into()));
        }
        if snapshot
            .response
            .try_reserve_exact(super::CLIENT_PUT_PREFIX + BLOCK_BYTES + TAG_BYTES)
            .is_err()
        {
            return Err(snapshot.refuse(crate::Error::Limit.into()));
        }
        let mut reader = match RangeReader::new(content, range, &mut self.keys) {
            Ok(reader) => reader,
            Err(cause) => return Err(snapshot.refuse(cause.into())),
        };
        let mut lookup = match Lookup::new(source, options.transfer) {
            Ok(lookup) => lookup,
            Err(cause) => return Err(snapshot.refuse(cause)),
        };
        let started = lookup.time.now;
        snapshot.started = Some(started);
        let result = async {
            while let Some(request) = reader.next() {
                lookup.during(std::future::ready(())).await?;
                if control(snapshot.progress) == Control::Cancel {
                    return Err(Error::Cancelled(snapshot.progress));
                }
                let result = lookup
                    .fetch_controlled(request, snapshot.progress, &mut control)
                    .await;
                snapshot.capture(&lookup);
                result?;
                if control(snapshot.progress) == Control::Cancel {
                    return Err(Error::Cancelled(snapshot.progress));
                }
                let bytes = lookup.block()?;
                let length = bytes.len();
                if let Some(chunk) = reader.open_next(bytes, &mut self.plain)? {
                    snapshot.progress.plaintext_bytes += chunk.bytes().len() as u64;
                }
                snapshot.progress.blocks += 1;
                snapshot.progress.encoded_bytes += length as u128;
                if let Some(recording) = recording.as_deref_mut() {
                    recording.capture(&lookup)?;
                }
                lookup.release();
            }
            if control(snapshot.progress) == Control::Cancel {
                return Err(Error::Cancelled(snapshot.progress));
            }
            lookup.during(std::future::ready(())).await?;
            reader.completion().ok_or(ProtocolError::NotReady.into())
        }
        .await;
        snapshot.capture(&lookup);
        let finished = lookup.time.now;
        // Close this exact owner, rather than leave a lookup running in the
        // background or invent an independent cleanup/protocol acknowledgment.
        lookup.channel.close();
        snapshot.retired = true;
        match result {
            Ok(verified) => Ok(Observed {
                verified,
                started,
                finished,
                snapshot,
            }),
            Err(cause) => Err(snapshot.refuse(cause)),
        }
    }
}
