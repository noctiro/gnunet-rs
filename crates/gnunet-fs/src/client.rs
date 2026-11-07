//! Bounded owners for the official local FS service MQ.
//!
//! Each owner has one logical operation and a dedicated physical connection.
//! FS has no request ID, cancel frame, search-end or negative lookup reply.
//! Hosts retain each original frame through partial I/O, and close the physical
//! MQ before calling `retire`. A successful block lookup authenticates that
//! block; a `content::FileReader` must still authenticate/decrypt the file tree.
use crate::{Content, Location};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, hash512};
use gnunet_types::{AbsoluteTime, Error};
use gnunet_wire::official::fs::{
    BlockType, ClientPut, MAX_SEEN_PER_FRAME, Request, Response, Search,
};
use subtle::ConstantTimeEq;

/// Identity storage borrowed exclusively while this operation or its tokens exist.
#[derive(Debug, Default)]
pub struct Instance {
    _private: u8,
}
impl Instance {
    /// New local owner identity; never encoded on the wire.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: 0 }
    }
}

/// Original physical service connection. The diagnostic number is not authority.
#[derive(Clone, Copy, Debug)]
pub struct Epoch<'a> {
    owner: &'a Instance,
    serial: u64,
}
impl PartialEq for Epoch<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.owner, other.owner) && self.serial == other.serial
    }
}
impl Eq for Epoch<'_> {}
impl Epoch<'_> {
    /// Local diagnostic generation, with no FS wire representation.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}

/// Copyable opaque identity of one original outbound frame. A native host can
/// retain it alongside its owned copy of the exact bytes without a self-reference.
/// It carries no FS wire extension and cannot authorize a later frame or MQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transmission<'a> {
    epoch: Epoch<'a>,
    sequence: u64,
}
impl<'a> Transmission<'a> {
    /// Original physical MQ for host callback and retirement correlation.
    #[must_use]
    pub const fn epoch(self) -> Epoch<'a> {
        self.epoch
    }
}

/// Immutable original frame lease. Dropping it requires retirement of its MQ;
/// it does not permit preparing another request on the same byte stream.
#[must_use = "retain the original frame until its full write or MQ retirement"]
pub struct Prepared<'a, 'buf> {
    epoch: Epoch<'a>,
    bytes: &'buf [u8],
    sequence: u64,
}
impl<'a> Prepared<'a, '_> {
    /// The original physical MQ identity.
    #[must_use]
    pub const fn epoch(&self) -> Epoch<'a> {
        self.epoch
    }
    /// Opaque completion tag to retain with an owned copy of these exact bytes.
    #[must_use]
    pub const fn tag(&self) -> Transmission<'a> {
        Transmission {
            epoch: self.epoch,
            sequence: self.sequence,
        }
    }
    /// Exact original frame bytes; the host tracks any partial write offset.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

/// How the original whole-block seen set is replayed on a fresh service MQ.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SeenReplay {
    /// Send the newest hashes fitting one frame and keep the entire bounded
    /// local set for exact deduplication. This works around the v0.29.1 service's
    /// unequal-query continuation merge condition without private wire changes.
    #[default]
    RecentWindow,
    /// Send every known digest across official CONTINUED frames. The host must
    /// select this only for a service whose same-query merge works correctly.
    /// The pinned v0.29.1 source does not satisfy that condition; no runtime
    /// negotiation or conformance result is implied by selecting this policy.
    Continued,
}

/// Caller resource and LOC identity policy, not extra wire fields.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum returned block bytes accepted before hashing/signature work.
    pub max_block_bytes: usize,
    /// Optional expected placement signer. None returns any valid signed claim.
    pub expected_loc_peer: Option<[u8; 32]>,
    /// Wire replay policy; the complete known set always remains local.
    pub seen_replay: SeenReplay,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_block_bytes: crate::ublock::DEFAULT_WIRE_BYTES,
            expected_loc_peer: None,
            seen_replay: SeenReplay::RecentWindow,
        }
    }
}

/// Terminal failure preserves the triggering error and any uncertain effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Original loss, cancellation, timeout, framing or authentication cause.
    pub cause: Error,
    /// OutcomeUnknown if an index/unindex request may have been processed.
    pub outcome: Error,
}

/// A borrowed result of one complete service frame. An IndexStarted/Unindexed
/// reply acknowledges that service operation, not durable DATASTORE publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'frame> {
    /// Unknown well-framed messages or an already accepted duplicate block.
    Ignored,
    /// Query-bound D/I ciphertext or a signature-verified UBLOCK, still encrypted.
    /// Its expiry is returned unchanged; this client owner makes no UTC validity claim.
    Block(ClientPut<'frame>),
    /// A verified, request-bound LOC signature; current validity is caller policy.
    Location(Location),
    /// The FS service acknowledged adding the indexed file.
    IndexStarted,
    /// The service rejected indexing; its exact diagnostic excludes final NUL.
    IndexFailed(&'frame [u8]),
    /// One exact indexed-file listing record; paths are not authorization to open.
    IndexEntry {
        /// Service-reported plaintext file hash.
        file_id: [u8; 64],
        /// Exact service filename, excluding final NUL.
        filename: &'frame [u8],
    },
    /// Explicit official index-list end. Search has no equivalent.
    IndexEnd,
    /// The FS service acknowledged removing the file from its index.
    Unindexed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    NeedConnection,
    NeedRequest,
    Leased,
    Waiting,
    Completed,
    Failed,
}

/// One allocation-free operation with KNOWN slots for whole-block seen digests.
/// Searches reconnect using their original query and accepted result digests.
/// No scheduler, socket, clock sampling or automatic index mutation retry exists.
///
/// The full known set is bounded by KNOWN, independently of frame size. A
/// RecentWindow replays its newest fitting hashes and filters all duplicates
/// locally. Continued replays every hash across individually leased official
/// frames, for a service with working same-query continuation merge semantics.
pub struct Client<'id, 'request, const KNOWN: usize> {
    identity: &'id Instance,
    request: Request<'request>,
    limits: Limits,
    deadline: AbsoluteTime,
    last_now: AbsoluteTime,
    serial: u64,
    epoch: Option<Epoch<'id>>,
    phase: Phase,
    failure: Option<Failure>,
    known: [[u8; 64]; KNOWN],
    known_len: usize,
    send_offset: usize,
    lease_sequence: u64,
    leased_end: usize,
    leased_more: bool,
}
impl<'id, 'request, const KNOWN: usize> Client<'id, 'request, KNOWN> {
    /// Validate without connecting. Initial seen digests are caller-supplied
    /// prior results; subsequent entries are added only after actual validation.
    /// No request bytes or owner state escape on a failed admission.
    pub fn new(
        identity: &'id mut Instance,
        request: Request<'request>,
        limits: Limits,
        now: AbsoluteTime,
        deadline: AbsoluteTime,
    ) -> Result<Self, Error> {
        Self::new_with_known(identity, request, limits, now, deadline, &[])
    }

    /// Admit additional whole-block hashes from a caller's prior validated
    /// results. They may exceed one wire frame; they never become wire IDs.
    /// Duplicate hashes occupy one slot, and any failed admission drops only
    /// this not-yet-connected owner. Only searches may supply known results.
    pub fn new_with_known(
        identity: &'id mut Instance,
        request: Request<'request>,
        limits: Limits,
        now: AbsoluteTime,
        deadline: AbsoluteTime,
        prior_results: &[[u8; 64]],
    ) -> Result<Self, Error> {
        request.encoded_len()?;
        if deadline <= now {
            return Err(Error::Deadline);
        }
        if let Request::Search(search) = request {
            if search.options & gnunet_wire::official::fs::SEARCH_CONTINUED != 0 {
                return Err(Error::InvalidInput);
            }
            if !supported(search.block_type) {
                return Err(Error::Unsupported);
            }
        } else if !prior_results.is_empty() {
            return Err(Error::InvalidInput);
        }
        let mut client = Self {
            identity,
            request,
            limits,
            deadline,
            last_now: now,
            serial: 0,
            epoch: None,
            phase: Phase::NeedConnection,
            failure: None,
            known: [[0; 64]; KNOWN],
            known_len: 0,
            send_offset: 0,
            lease_sequence: 0,
            leased_end: 0,
            leased_more: false,
        };
        if let Request::Search(search) = request {
            for digest in search.seen.as_chunks::<64>().0 {
                client.remember(*digest)?;
            }
        }
        for digest in prior_results {
            client.remember(*digest)?;
        }
        Ok(client)
    }

    /// Whether the host may attach a fresh physical service MQ.
    #[must_use]
    pub fn connection_needed(&self) -> bool {
        self.phase == Phase::NeedConnection && self.epoch.is_none()
    }
    /// Whether the next original request fragment may be prepared on this MQ.
    #[must_use]
    pub fn request_needed(&self) -> bool {
        self.phase == Phase::NeedRequest && self.epoch.is_some()
    }
    /// Whether cancellation/completion/failure requires closing the original MQ.
    #[must_use]
    pub fn retirement_needed(&self) -> bool {
        self.epoch.is_some() && matches!(self.phase, Phase::Completed | Phase::Failed)
    }
    /// Locally completed operation (a streaming search never completes by silence).
    #[must_use]
    pub fn completed(&self) -> bool {
        self.phase == Phase::Completed
    }
    /// Terminal failure and its original cause, retained through physical retire.
    #[must_use]
    pub const fn failure(&self) -> Option<Failure> {
        self.failure
    }
    /// Exact accepted whole-block digests, suitable for original-plugin filtering.
    #[must_use]
    pub fn known_results(&self) -> &[[u8; 64]] {
        &self.known[..self.known_len]
    }

    /// Attach a fresh physical connection. No FS INIT handshake is invented.
    pub fn begin_connection(&mut self, now: AbsoluteTime) -> Result<Epoch<'id>, Error> {
        self.observe(now)?;
        if !self.connection_needed() {
            return Err(Error::NotReady);
        }
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let epoch = Epoch {
            owner: self.identity,
            serial,
        };
        self.serial = serial;
        self.epoch = Some(epoch);
        self.phase = Phase::NeedRequest;
        self.send_offset = 0;
        Ok(epoch)
    }

    /// Encode the next original request frame into caller-owned storage. Capacity
    /// rejection leaves output and request state unchanged. Hosts must reserve
    /// their outbound queue before preparing this non-repeatable lease.
    pub fn prepare<'buf>(
        &mut self,
        epoch: Epoch<'id>,
        now: AbsoluteTime,
        output: &'buf mut [u8],
    ) -> Result<Prepared<'id, 'buf>, Error> {
        self.check_epoch(epoch)?;
        self.observe(now)?;
        if self.phase != Phase::NeedRequest {
            return Err(Error::NotReady);
        }
        let sequence = self.lease_sequence.checked_add(1).ok_or(Error::Overflow)?;
        let mut next_offset = 0;
        let mut more = false;
        let request = match self.request {
            Request::Search(search) => {
                let available = output
                    .len()
                    .checked_sub(gnunet_wire::official::fs::SEARCH_PREFIX)
                    .ok_or(Error::Capacity)?;
                let slots = (available / 64).min(MAX_SEEN_PER_FRAME);
                let (start, end) = match self.limits.seen_replay {
                    SeenReplay::RecentWindow => {
                        (self.known_len.saturating_sub(slots), self.known_len)
                    }
                    SeenReplay::Continued => {
                        if slots == 0 && self.send_offset < self.known_len {
                            return Err(Error::Capacity);
                        }
                        let end = self.send_offset + slots.min(self.known_len - self.send_offset);
                        more = end < self.known_len;
                        (self.send_offset, end)
                    }
                };
                next_offset = end;
                Request::Search(Search {
                    options: search.options
                        | if more {
                            gnunet_wire::official::fs::SEARCH_CONTINUED
                        } else {
                            0
                        },
                    seen: self.known[start..end].as_flattened(),
                    ..search
                })
            }
            other => other,
        };
        let len = request.encode(output)?;
        self.lease_sequence = sequence;
        self.leased_end = next_offset;
        self.leased_more = more;
        self.phase = Phase::Leased;
        Ok(Prepared {
            epoch,
            bytes: &output[..len],
            sequence,
        })
    }

    /// Report full physical write of the original lease. This is stream progress,
    /// not service processing or an acknowledgement of a business operation.
    pub fn written(&mut self, frame: &Prepared<'id, '_>, now: AbsoluteTime) -> Result<(), Error> {
        self.written_tag(frame.tag(), now)
    }

    /// Report a native queue's full write of the original frame tagged at
    /// preparation. The host must retain the exact bytes through partial I/O;
    /// copying this tag does not permit replay, replacing bytes or early ACKs.
    pub fn written_tag(&mut self, tag: Transmission<'id>, now: AbsoluteTime) -> Result<(), Error> {
        self.check_epoch(tag.epoch)?;
        self.observe(now)?;
        if self.phase != Phase::Leased || tag.sequence != self.lease_sequence {
            return Err(Error::Stale);
        }
        self.send_offset = self.leased_end;
        self.phase = if self.leased_more {
            Phase::NeedRequest
        } else {
            Phase::Waiting
        };
        Ok(())
    }

    /// Fail after the native queue removed this exact frame without writing any
    /// byte (for example, Framed::remove_unwritten returned it successfully).
    /// The host must actually remove it before this call: a merely pending or
    /// canceled write does not establish zero bytes. Current epoch, lease sequence
    /// and Leased state are all checked before changing the owner.
    ///
    /// This closing path preserves the supplied actual cause, including after
    /// the deadline; it admits no work and does not extend that deadline. Even
    /// INDEX/UNINDEX have a known no-effect outcome for this unsent frame. The
    /// original physical MQ still requires retirement before dropping its I/O.
    pub fn cancel_unwritten(
        &mut self,
        tag: Transmission<'id>,
        now: AbsoluteTime,
        cause: Error,
    ) -> Result<(), Error> {
        self.check_epoch(tag.epoch)?;
        if self.phase != Phase::Leased || tag.sequence != self.lease_sequence {
            return Err(Error::Stale);
        }
        // Nothing can resume from Failed. Preserve the host's original cause
        // rather than allowing a later clock/deadline observation to replace it.
        self.last_now = self.last_now.max(now);
        self.failure = Some(Failure {
            cause,
            outcome: cause,
        });
        self.phase = Phase::Failed;
        Ok(())
    }

    /// Receive one complete frame from this original physical MQ. Known malformed
    /// or mismatched results poison it; Capacity does not consume a result or
    /// mutate the seen set, so callers can retain input and decide how to stop.
    pub fn receive<'frame>(
        &mut self,
        epoch: Epoch<'id>,
        now: AbsoluteTime,
        input: &'frame [u8],
    ) -> Result<Event<'frame>, Error> {
        self.check_epoch(epoch)?;
        self.observe(now)?;
        if self.phase != Phase::Waiting {
            return Err(Error::NotReady);
        }
        let response = match Response::decode(input) {
            Ok(response) => response,
            Err(cause) => return Err(self.fail(cause)),
        };
        match self.process(response) {
            Ok(event) => Ok(event),
            Err(Error::Capacity) => Err(Error::Capacity),
            Err(cause) => Err(self.fail(cause)),
        }
    }

    fn process<'frame>(&mut self, response: Response<'frame>) -> Result<Event<'frame>, Error> {
        if let Response::Unknown(_) = response {
            return Ok(Event::Ignored);
        }
        match (self.request, response) {
            (Request::Search(search), Response::Put(result)) => self.block(search, result),
            (
                Request::LocSign {
                    expiration: requested,
                    key,
                    query,
                    file_length,
                },
                Response::LocSignature {
                    expiration,
                    signature,
                    peer,
                },
            ) => {
                let rounded = requested.as_micros() / 1_000_000 * 1_000_000;
                if expiration.as_micros() != rounded
                    || self
                        .limits
                        .expected_loc_peer
                        .is_some_and(|expected| expected != peer)
                {
                    return Err(Error::Authentication);
                }
                let location = Location::from_signed(
                    Content {
                        key,
                        query,
                        size: file_length,
                    },
                    EddsaPublicKey::from_bytes(peer),
                    EddsaSignature::from_bytes(signature),
                    expiration,
                )?;
                self.phase = Phase::Completed;
                Ok(Event::Location(location))
            }
            (Request::IndexStart { .. }, Response::IndexStarted) => {
                self.phase = Phase::Completed;
                Ok(Event::IndexStarted)
            }
            (Request::IndexStart { .. }, Response::IndexFailed { message }) => {
                self.phase = Phase::Completed;
                Ok(Event::IndexFailed(message))
            }
            (Request::IndexList, Response::IndexEntry { file_id, filename }) => {
                Ok(Event::IndexEntry { file_id, filename })
            }
            (Request::IndexList, Response::IndexEnd) => {
                self.phase = Phase::Completed;
                Ok(Event::IndexEnd)
            }
            (Request::Unindex { .. }, Response::Unindexed) => {
                self.phase = Phase::Completed;
                Ok(Event::Unindexed)
            }
            _ => Err(Error::Malformed),
        }
    }

    fn block<'frame>(
        &mut self,
        search: Search<'_>,
        result: ClientPut<'frame>,
    ) -> Result<Event<'frame>, Error> {
        if result.block.len() > self.limits.max_block_bytes {
            return Err(Error::TooLarge);
        }
        if !supported(result.block_type)
            || result.block_type == BlockType::ANY
            || (search.block_type != BlockType::ANY && result.block_type != search.block_type)
        {
            return Err(Error::Authentication);
        }
        let digest = hash512(result.block);
        if result.block_type == BlockType::UBLOCK {
            crate::ublock::verify_block(result.block, &search.query, self.limits.max_block_bytes)
                .map_err(|error| match error {
                crate::ublock::Error::Crypto(cause) => cause,
                crate::ublock::Error::Framing => Error::Malformed,
                crate::ublock::Error::Limit => Error::TooLarge,
                _ => Error::Authentication,
            })?;
        } else if !bool::from(digest.ct_eq(&search.query)) {
            return Err(Error::Authentication);
        }
        // D/I replies are terminal even if a caller's initial seen list contains
        // the digest. The plugin ignores seen filters for these single results.
        if search.block_type == BlockType::DBLOCK || search.block_type == BlockType::IBLOCK {
            self.phase = Phase::Completed;
            return Ok(Event::Block(result));
        }
        // UBLOCK lookup key hashes its verification key, while the seen filter
        // hashes the entire signed block. Never substitute URI or CHK hashes.
        if self.contains(&digest) {
            return Ok(Event::Ignored);
        }
        if result.block_type == BlockType::UBLOCK || search.block_type == BlockType::ANY {
            self.remember(digest)?;
        }
        Ok(Event::Block(result))
    }

    fn remember(&mut self, digest: [u8; 64]) -> Result<(), Error> {
        if !self.contains(&digest) {
            let slot = self.known.get_mut(self.known_len).ok_or(Error::Capacity)?;
            *slot = digest;
            self.known_len += 1;
        }
        Ok(())
    }
    fn contains(&self, digest: &[u8; 64]) -> bool {
        self.known[..self.known_len]
            .iter()
            .any(|seen| seen == digest)
    }
    fn check_epoch(&self, epoch: Epoch<'id>) -> Result<(), Error> {
        if self.epoch == Some(epoch) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    fn observe(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        if let Some(failure) = self.failure {
            return Err(failure.outcome);
        }
        if self.phase == Phase::Completed {
            return Err(Error::Stale);
        }
        if now < self.last_now {
            return Err(self.fail(Error::TimeUncertain));
        }
        self.last_now = now;
        if now >= self.deadline {
            return Err(self.fail(Error::Deadline));
        }
        Ok(())
    }
    fn fail(&mut self, cause: Error) -> Error {
        let uncertain = matches!(
            self.request,
            Request::IndexStart { .. } | Request::Unindex { .. }
        ) && matches!(self.phase, Phase::Leased | Phase::Waiting);
        let outcome = if uncertain {
            Error::OutcomeUnknown
        } else {
            cause
        };
        self.failure = Some(Failure { cause, outcome });
        self.phase = Phase::Failed;
        outcome
    }

    /// Request cancellation. The host must still close the dedicated MQ and
    /// report retirement before discarding pending I/O. There is no cancel frame.
    pub fn cancel(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        self.abort(now, Error::Cancelled)
    }
    /// Stop with the native host's original EOF, protocol, clock, cancellation
    /// or physical I/O cause. This closing path admits no new work and preserves
    /// that cause even when a deadline or clock observation is reported later.
    /// A leased or fully written index mutation remains OutcomeUnknown unless
    /// the host used cancel_unwritten with a successful zero-byte queue removal.
    /// The host must still close and retire the original physical MQ.
    pub fn abort(&mut self, now: AbsoluteTime, cause: Error) -> Result<(), Error> {
        if let Some(failure) = self.failure {
            return Err(failure.outcome);
        }
        if self.phase == Phase::Completed {
            return Err(Error::Stale);
        }
        self.last_now = self.last_now.max(now);
        self.fail(cause);
        Ok(())
    }
    /// Poll the original source-time deadline without inventing an FS timeout reply.
    pub fn poll(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        self.observe(now)
    }

    /// Report that this exact physical MQ is closed and no callback/write/read
    /// can still target it. Loss of an active search permits a fresh connection
    /// with the original deadline and seen set. A partially sent index mutation
    /// remains OutcomeUnknown; no automatic replay is permitted.
    pub fn retire(&mut self, epoch: Epoch<'id>, now: AbsoluteTime) -> Result<(), Error> {
        self.check_epoch(epoch)?;
        if !matches!(self.phase, Phase::Completed | Phase::Failed) && self.observe(now).is_ok() {
            if matches!(self.request, Request::Search(_)) || self.phase == Phase::NeedRequest {
                self.phase = Phase::NeedConnection;
            } else {
                self.fail(Error::Io);
            }
        }
        self.epoch = None;
        Ok(())
    }
}

fn supported(kind: BlockType) -> bool {
    matches!(
        kind,
        BlockType::ANY | BlockType::DBLOCK | BlockType::IBLOCK | BlockType::UBLOCK
    )
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Fallible owner regressions assert protocol and state boundaries"
    )]
    use super::*;
    use gnunet_wire::official::{
        AbsoluteTime,
        fs::{SEARCH_LOOPBACK_ONLY, SEARCH_NONE},
    };

    fn search<'a>(kind: BlockType, query: [u8; 64], seen: &'a [u8]) -> Request<'a> {
        Request::Search(Search {
            options: SEARCH_NONE,
            block_type: kind,
            anonymity: 1,
            target: [0; 32],
            query,
            seen,
        })
    }
    fn put<'a>(kind: BlockType, block: &'a [u8]) -> Response<'a> {
        Response::Put(ClientPut {
            block_type: kind,
            expiration: AbsoluteTime::from_micros(123),
            last_transmission: AbsoluteTime::NEVER,
            num_transmissions: 3,
            respect_offered: 4,
            block,
        })
    }

    #[test]
    fn original_partial_lease_retirement_and_epoch_isolation() -> Result<(), Error> {
        let mut identity = Instance::new();
        let mut client = Client::<2>::new(
            &mut identity,
            search(BlockType::UBLOCK, [1; 64], &[]),
            Limits::default(),
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(100),
        )?;
        let first = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut small = [0x55; 111];
        assert!(matches!(
            client.prepare(first, AbsoluteTime::from_micros(2), &mut small),
            Err(Error::Capacity)
        ));
        assert_eq!(small, [0x55; 111]);
        let mut bytes = [0; 112];
        let original = client.prepare(first, AbsoluteTime::from_micros(2), &mut bytes)?;
        assert!(matches!(
            client.prepare(first, AbsoluteTime::from_micros(2), &mut small),
            Err(Error::NotReady)
        ));
        // A host may have partially written original. It must retire that MQ.
        assert_eq!(
            client.begin_connection(AbsoluteTime::from_micros(3)),
            Err(Error::NotReady)
        );
        client.retire(first, AbsoluteTime::from_micros(3))?;
        let replacement = client.begin_connection(AbsoluteTime::from_micros(4))?;
        assert_eq!(
            client.written(&original, AbsoluteTime::from_micros(5)),
            Err(Error::Stale)
        );
        assert_eq!(
            client.receive(first, AbsoluteTime::from_micros(5), &[]),
            Err(Error::Stale)
        );
        assert_ne!(first, replacement);
        client.cancel(AbsoluteTime::from_micros(6))?;
        assert!(client.retirement_needed());
        client.retire(replacement, AbsoluteTime::from_micros(6))?;
        assert_eq!(
            client.failure().ok_or(Error::InvalidInput)?.outcome,
            Error::Cancelled
        );
        Ok(())
    }

    #[test]
    fn authenticated_block_completes_get_but_local_search_silence_does_not() -> Result<(), Error> {
        let body = b"actual ciphertext bytes";
        let query = hash512(body);
        let mut identity = Instance::new();
        // A raw caller-supplied seen digest must not swallow the sole D result.
        let mut client = Client::<1>::new(
            &mut identity,
            search(BlockType::DBLOCK, query, &query),
            Limits::default(),
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(20),
        )?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut tx = [0; 112];
        let prepared = client.prepare(epoch, AbsoluteTime::from_micros(2), &mut tx)?;
        client.written(&prepared, AbsoluteTime::from_micros(2))?;
        let mut rx = [0; 100];
        let len = put(BlockType::DBLOCK, body).encode(&mut rx)?;
        assert!(matches!(
            client.receive(epoch, AbsoluteTime::from_micros(3), &rx[..len]),
            Ok(Event::Block(_))
        ));
        assert!(client.completed());
        assert!(client.retirement_needed());
        client.retire(epoch, AbsoluteTime::from_micros(4))?;

        let mut other = Instance::new();
        let Request::Search(mut request) = search(BlockType::UBLOCK, [1; 64], &[]) else {
            return Err(Error::InvalidInput);
        };
        request.options = SEARCH_LOOPBACK_ONLY;
        let mut search = Client::<1>::new(
            &mut other,
            Request::Search(request),
            Limits::default(),
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(20),
        )?;
        let epoch = search.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut tx = [0; 112];
        let prepared = search.prepare(epoch, AbsoluteTime::from_micros(2), &mut tx)?;
        search.written(&prepared, AbsoluteTime::from_micros(2))?;
        assert!(!search.completed());
        assert_eq!(
            search.poll(AbsoluteTime::from_micros(20)),
            Err(Error::Deadline)
        );
        search.retire(epoch, AbsoluteTime::from_micros(20))?;
        assert!(!search.connection_needed());
        Ok(())
    }

    #[test]
    fn admin_partial_mutation_unknown_and_request_bound_location() -> Result<(), Error> {
        let mut identity = Instance::new();
        let mut client = Client::<0>::new(
            &mut identity,
            Request::Unindex { file_id: [7; 64] },
            Limits::default(),
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(20),
        )?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut tx = [0; 72];
        let frame = client.prepare(epoch, AbsoluteTime::from_micros(2), &mut tx)?;
        client.written(&frame, AbsoluteTime::from_micros(2))?;
        client.cancel(AbsoluteTime::from_micros(3))?;
        assert_eq!(
            client.failure(),
            Some(Failure {
                cause: Error::Cancelled,
                outcome: Error::OutcomeUnknown
            })
        );
        assert!(client.retirement_needed());
        client.retire(epoch, AbsoluteTime::from_micros(3))?;

        let content = Content {
            key: [2; 64],
            query: [3; 64],
            size: 9,
        };
        let key = gnunet_crypto::EddsaPrivateKey::from_seed([8; 32]);
        let location = Location::sign(content, &key, AbsoluteTime::from_micros(2_345_678))?;
        let mut identity = Instance::new();
        let mut client = Client::<0>::new(
            &mut identity,
            Request::LocSign {
                expiration: AbsoluteTime::from_micros(2_345_678),
                key: content.key,
                query: content.query,
                file_length: content.size,
            },
            Limits {
                expected_loc_peer: Some(*key.public_key().as_bytes()),
                ..Limits::default()
            },
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(20),
        )?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut tx = [0; 152];
        let frame = client.prepare(epoch, AbsoluteTime::from_micros(2), &mut tx)?;
        client.written(&frame, AbsoluteTime::from_micros(2))?;
        let mut rx = [0; 112];
        Response::LocSignature {
            expiration: location.expiration(),
            signature: *location.signature().as_bytes(),
            peer: *location.peer().as_bytes(),
        }
        .encode(&mut rx)?;
        assert_eq!(
            client.receive(epoch, AbsoluteTime::from_micros(3), &rx),
            Ok(Event::Location(location))
        );
        assert!(client.completed());
        Ok(())
    }

    fn distinct_prior<const N: usize>() -> [[u8; 64]; N] {
        core::array::from_fn(|index| {
            let mut digest = [0; 64];
            digest[..8].copy_from_slice(&(index as u64).to_be_bytes());
            digest
        })
    }

    #[test]
    fn continued_fragments_advance_only_original_full_writes_and_restart_on_new_mq()
    -> Result<(), Error> {
        let prior = distinct_prior::<1023>();
        let mut identity = Instance::new();
        let mut client = Client::<1023>::new_with_known(
            &mut identity,
            search(BlockType::UBLOCK, [3; 64], &[]),
            Limits {
                seen_replay: SeenReplay::Continued,
                ..Limits::default()
            },
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(20),
            &prior,
        )?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut first_bytes = [0; 112 + 512 * 64];
        let first = client.prepare(epoch, AbsoluteTime::from_micros(2), &mut first_bytes)?;
        let Request::Search(frame) = Request::decode(first.bytes())? else {
            return Err(Error::InvalidInput);
        };
        assert_eq!(frame.options, gnunet_wire::official::fs::SEARCH_CONTINUED);
        assert_eq!(frame.seen, prior[..512].as_flattened());
        let first_tag = first.tag();
        client.written_tag(first_tag, AbsoluteTime::from_micros(3))?;
        assert!(client.request_needed());
        let mut second_bytes = [0; 112 + 512 * 64];
        let second = client.prepare(epoch, AbsoluteTime::from_micros(4), &mut second_bytes)?;
        let Request::Search(frame) = Request::decode(second.bytes())? else {
            return Err(Error::InvalidInput);
        };
        assert_eq!(frame.seen, prior[512..1024.min(prior.len())].as_flattened());
        // 1023 prior entries means the second frame has 511 and is final.
        assert_eq!(frame.options, 0);
        assert_eq!(
            client.written_tag(first_tag, AbsoluteTime::from_micros(5)),
            Err(Error::Stale)
        );
        assert_eq!(
            client.cancel_unwritten(first_tag, AbsoluteTime::from_micros(5), Error::Cancelled),
            Err(Error::Stale)
        );
        client.written(&second, AbsoluteTime::from_micros(5))?;
        assert!(!client.request_needed());
        assert!(!client.completed());
        client.retire(epoch, AbsoluteTime::from_micros(6))?;
        let replacement = client.begin_connection(AbsoluteTime::from_micros(7))?;
        let mut replay_bytes = [0; 112 + 512 * 64];
        let replay =
            client.prepare(replacement, AbsoluteTime::from_micros(8), &mut replay_bytes)?;
        let Request::Search(frame) = Request::decode(replay.bytes())? else {
            return Err(Error::InvalidInput);
        };
        assert_eq!(frame.seen, prior[..512].as_flattened());
        assert_eq!(
            client.written(&second, AbsoluteTime::from_micros(8)),
            Err(Error::Stale)
        );
        assert_eq!(
            client.poll(AbsoluteTime::from_micros(20)),
            Err(Error::Deadline)
        );
        client.retire(replacement, AbsoluteTime::from_micros(20))?;
        assert!(!client.connection_needed());
        Ok(())
    }

    #[test]
    fn recent_window_bounds_wire_without_losing_the_complete_local_seen_set() -> Result<(), Error> {
        let prior = distinct_prior::<1023>();
        let mut identity = Instance::new();
        let mut client = Client::<1023>::new_with_known(
            &mut identity,
            search(BlockType::UBLOCK, [4; 64], &[]),
            Limits::default(),
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(20),
            &prior,
        )?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut bytes = [0; 112 + MAX_SEEN_PER_FRAME * 64];
        let original = client.prepare(epoch, AbsoluteTime::from_micros(2), &mut bytes)?;
        let Request::Search(frame) = Request::decode(original.bytes())? else {
            return Err(Error::InvalidInput);
        };
        assert_eq!(frame.options, 0);
        assert_eq!(frame.seen, prior[1..].as_flattened());
        assert_eq!(client.known_results(), &prior);
        client.written(&original, AbsoluteTime::from_micros(3))?;
        client.retire(epoch, AbsoluteTime::from_micros(4))?;
        let replacement = client.begin_connection(AbsoluteTime::from_micros(5))?;
        // A small host buffer can replay no remote hashes while retaining exact
        // deduplication of all prior results locally.
        let mut small = [0; 112];
        let original = client.prepare(replacement, AbsoluteTime::from_micros(6), &mut small)?;
        let Request::Search(frame) = Request::decode(original.bytes())? else {
            return Err(Error::InvalidInput);
        };
        assert!(frame.seen.is_empty());
        assert_eq!(client.known_results(), &prior);
        Ok(())
    }
    // Insert this one test in client.rs's existing cfg(test) module, or include it
    // as a child test module of client. It needs no std, heap, fixtures or sockets.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions verify a real signed UBLOCK and original connection replay"
    )]
    fn signed_ublock_uses_whole_block_seen_and_replays_it_after_reconnect()
    -> Result<(), gnunet_types::Error> {
        use super::{Client, Event, Instance, Limits};
        use crate::{Content, ublock};
        use gnunet_crypto::hash512;
        use gnunet_types::{AbsoluteTime, Error};
        use gnunet_wire::official::fs::{
            BlockType, ClientPut, Request, Response, SEARCH_NONE, Search,
        };

        // Seal a real anonymous keyword block. Its lookup query hashes the derived
        // signing key, whereas the service's seen filter hashes this entire block.
        let publisher = ublock::Publisher::keyword(b"owner-seen", ublock::Limits::default())
            .map_err(|_| Error::InvalidInput)?;
        let lookup = ublock::Context::keyword(b"owner-seen", ublock::Limits::default())
            .map_err(|_| Error::InvalidInput)?;
        let mut block_buffer = [0; 1024];
        let sealed = publisher
            .seal(
                b"",
                Content {
                    key: [1; 64],
                    query: [2; 64],
                    size: 41,
                }
                .uri(),
                None,
                &mut block_buffer,
            )
            .map_err(|_| Error::Authentication)?;
        assert_eq!(sealed.query(), lookup.query());
        let whole_block_digest = hash512(sealed.bytes());
        assert_ne!(&whole_block_digest, lookup.query());

        let mut identity = Instance::new();
        let mut client = Client::<2>::new(
            &mut identity,
            Request::Search(Search {
                options: SEARCH_NONE,
                block_type: BlockType::UBLOCK,
                anonymity: 1,
                target: [0; 32],
                query: *lookup.query(),
                seen: &[],
            }),
            Limits::default(),
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(100),
        )?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut initial_bytes = [0; 112];
        let initial = client.prepare(epoch, AbsoluteTime::from_micros(2), &mut initial_bytes)?;
        let Request::Search(first_search) = Request::decode(initial.bytes())? else {
            return Err(Error::Malformed);
        };
        assert!(first_search.seen.is_empty());
        client.written(&initial, AbsoluteTime::from_micros(2))?;

        let mut result_bytes = [0; 2048];
        let result_len = Response::Put(ClientPut {
            block_type: BlockType::UBLOCK,
            expiration: AbsoluteTime::from_micros(1_000_000),
            last_transmission: AbsoluteTime::NEVER,
            num_transmissions: 2,
            respect_offered: 3,
            block: sealed.bytes(),
        })
        .encode(&mut result_bytes)?;
        let result = &result_bytes[..result_len];
        assert!(matches!(
            client.receive(epoch, AbsoluteTime::from_micros(3), result)?,
            Event::Block(block) if block.block == sealed.bytes()
                && block.block_type == BlockType::UBLOCK
        ));
        assert_eq!(client.known_results(), &[whole_block_digest]);
        assert_eq!(
            client.receive(epoch, AbsoluteTime::from_micros(4), result)?,
            Event::Ignored
        );
        assert_eq!(client.known_results(), &[whole_block_digest]);
        assert!(!client.completed());

        // The host reports the old physical connection closed before obtaining a
        // replacement. The replay uses the complete block digest and same query.
        client.retire(epoch, AbsoluteTime::from_micros(5))?;
        assert!(client.connection_needed());
        let replacement = client.begin_connection(AbsoluteTime::from_micros(6))?;
        assert_ne!(epoch, replacement);
        let mut replay_bytes = [0; 176];
        let replay =
            client.prepare(replacement, AbsoluteTime::from_micros(7), &mut replay_bytes)?;
        let Request::Search(replayed_search) = Request::decode(replay.bytes())? else {
            return Err(Error::Malformed);
        };
        assert_eq!(replayed_search.query, *lookup.query());
        assert_eq!(replayed_search.seen, whole_block_digest.as_slice());
        assert_eq!(replayed_search.options, SEARCH_NONE);
        client.written(&replay, AbsoluteTime::from_micros(7))?;
        assert_eq!(
            client.receive(epoch, AbsoluteTime::from_micros(8), result),
            Err(Error::Stale)
        );
        assert_eq!(
            client.receive(replacement, AbsoluteTime::from_micros(8), result)?,
            Event::Ignored
        );
        assert_eq!(client.known_results(), &[whole_block_digest]);
        client.cancel(AbsoluteTime::from_micros(9))?;
        assert!(client.retirement_needed());
        client.retire(replacement, AbsoluteTime::from_micros(9))?;
        assert!(
            client
                .failure()
                .is_some_and(|failure| failure.cause == Error::Cancelled)
        );
        Ok(())
    }

    #[test]
    fn confirmed_unsent_mutation_keeps_actual_cause_but_written_tag_cannot_downgrade()
    -> Result<(), Error> {
        let mut identity = Instance::new();
        let mut client = Client::<0>::new(
            &mut identity,
            Request::Unindex { file_id: [7; 64] },
            Limits::default(),
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(20),
        )?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut bytes = [0; 72];
        let original = client.prepare(epoch, AbsoluteTime::from_micros(2), &mut bytes)?;
        let tag = original.tag();
        // Native Framed owns an exact copy and successfully removes the frame
        // with zero bytes written. The transport's original Io cause is kept,
        // even if the host reports that removal after the operation deadline.
        client.cancel_unwritten(tag, AbsoluteTime::from_micros(30), Error::Io)?;
        assert_eq!(
            client.failure(),
            Some(Failure {
                cause: Error::Io,
                outcome: Error::Io
            })
        );
        assert!(client.retirement_needed());
        assert!(!client.connection_needed());
        assert_eq!(
            client.written_tag(tag, AbsoluteTime::from_micros(30)),
            Err(Error::Io)
        );
        client.retire(epoch, AbsoluteTime::from_micros(30))?;
        assert_eq!(
            client.cancel_unwritten(tag, AbsoluteTime::from_micros(30), Error::Cancelled),
            Err(Error::Stale)
        );
        assert_eq!(
            client.failure(),
            Some(Failure {
                cause: Error::Io,
                outcome: Error::Io
            })
        );

        let mut identity = Instance::new();
        let mut client = Client::<0>::new(
            &mut identity,
            Request::IndexStart {
                device: 0,
                inode: 0,
                file_id: [8; 64],
                filename: b"/tmp/index",
            },
            Limits::default(),
            AbsoluteTime::from_micros(0),
            AbsoluteTime::from_micros(20),
        )?;
        let epoch = client.begin_connection(AbsoluteTime::from_micros(1))?;
        let mut bytes = [0; 128];
        let original = client.prepare(epoch, AbsoluteTime::from_micros(2), &mut bytes)?;
        let tag = original.tag();
        client.written_tag(tag, AbsoluteTime::from_micros(3))?;
        assert_eq!(
            client.cancel_unwritten(tag, AbsoluteTime::from_micros(4), Error::Io),
            Err(Error::Stale)
        );
        assert_eq!(client.failure(), None);
        // Once bytes were written, native loss remains uncertain and retains
        // its original cause, even if a later cancellation is reported.
        client.abort(AbsoluteTime::from_micros(4), Error::Io)?;
        let failure = Some(Failure {
            cause: Error::Io,
            outcome: Error::OutcomeUnknown,
        });
        assert_eq!(client.failure(), failure);
        assert_eq!(
            client.abort(AbsoluteTime::from_micros(5), Error::Cancelled),
            Err(Error::OutcomeUnknown)
        );
        assert_eq!(client.failure(), failure);
        client.retire(epoch, AbsoluteTime::from_micros(5))?;
        Ok(())
    }
}
