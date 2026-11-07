//! Shared Job/Flow/reliability packet attempts. These are local branded leases,
//! not new wire messages, a second Flow, or proof constructors.
use super::*;
mod cancel;
pub use cancel::{StagedSend, TransferCancellation};

#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod order_tests;

/// Original Engine-installed current eligible virtual path generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathId {
    source: Source,
    serial: u64,
}
/// One original common-transmit inner packet attempt. It is moved into actual
/// Actor J; retries of a remote ACK create a new attempt with the same inner
/// UUID/span, and must obtain a fresh actual BOX nonce.
#[derive(Debug)]
pub struct VirtualAttempt {
    source: Source,
    serial: u64,
    claim: u64,
}
/// Read-only identity does not release the original actor/Engine debt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualId {
    source: Source,
    serial: u64,
}
impl VirtualAttempt {
    /// Exact original typed local attempt identity.
    pub fn id(&self) -> VirtualId {
        VirtualId {
            source: self.source.clone(),
            serial: self.serial,
        }
    }
}
/// Original common-transmit packet, borrowed until actual Actor admission.
pub struct VirtualPacket<'a> {
    /// Exact local attempt identity, not a wire RID.
    pub id: VirtualId,
    /// Same actual path generation preflighted by the original Job.
    pub path: PathId,
    /// Original final peer Flow identity.
    pub target: PeerId,
    /// Original local submitter, distinct from the DV source and remote peer.
    /// This opaque identity is preserved after the first CORE credit returns.
    pub origin: Option<&'a ClientId>,
    /// Complete existing Fragment/Reliable/Flow/application frame.
    pub bytes: &'a [u8],
    /// Existing original control-window policy.
    pub without_fc: bool,
    /// Original scheduling deadline in Engine coordinates.
    pub until: MonoInstant,
}
/// Original actor output carried by a common direct Job, possibly fragmented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferId {
    source: Source,
    serial: u64,
}
/// Original local transfer disposition. Whole original logical bytes may span
/// several real fragments; Written describes successful local communicator
/// SEND_ACK1210 callbacks for all of them, not remote delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferOutcome {
    /// Every original byte span received a successful local communicator
    /// SEND_ACK1210 callback. This is not a remote acknowledgement.
    Written,
    /// The original common Job ended before any actual native queue admission.
    Unsent,
    /// The original Job retired without sending the complete logical message.
    /// Every chunk that actually existed has a known local disposition; the
    /// original physical MQ remains usable. This is not complete delivery.
    Incomplete,
    /// An original local SEND_ACK1210 callback reported this failure code.
    Failed(u32),
    /// The original physical MQ closed before all spans had a known result.
    SourceLost,
}
/// Actual original common-Job/native facts, never remote processing assurance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferState {
    /// At least one original1209 fragment actually entered its physical MQ.
    pub queued: bool,
    /// Actual positive bytes on the original physical IPC source.
    pub exposed: bool,
    /// Original terminal local disposition. Unknown native chunks retain None.
    pub outcome: Option<TransferOutcome>,
    /// Original reliable Job still owns retries/ACK debt after local full write.
    pub job_pending: bool,
}
/// Read-only labels of an original retained common Job. A serial is diagnostic
/// metadata and cannot recreate a Job, native callback or submission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobDiagnostic {
    /// Original Engine-local common Job serial.
    pub serial: u64,
    /// Original immutable message extent in bytes, excluding carrier headers.
    pub bytes: usize,
    /// Bytes already staged on their first pass; this is not write coverage.
    pub fresh_offset: usize,
    /// The original unfragmented body was staged on its first pass.
    pub whole_sent: bool,
    /// Original monotonic expiry in Engine microseconds, never recomputed here.
    pub expires: u64,
    /// Retained original preflight refusal, if any.
    pub deferred: Option<Error>,
}
/// Current records of the exact original physical queue generation, if retained.
/// These observations neither reserve a packet grant nor revalidate a route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueDiagnostic {
    /// Remaining original local packet grant; unlimited is reported separately.
    pub available: u64,
    /// This queue actually advertised an unlimited packet grant.
    pub unlimited: bool,
    /// Original local attempts still counted in flight on this generation.
    pub inflight: u64,
    /// Advertised complete network-frame extent in bytes.
    pub mtu: u32,
    /// Original validated-route expiry in Engine monotonic microseconds.
    pub valid_until: u64,
}
/// Current per-peer FLOW counters, without granting or consuming window space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowDiagnostic {
    /// Current stored network-byte charge on the peer's outbound window.
    pub used: u64,
    /// Current stored outbound-window ceiling in bytes; it may be the
    /// initial or reset default rather than a received FLOW update.
    pub window: u64,
}
/// Fixed metadata copied from one exact original transfer. It contains no
/// message body, clock sample, mutable owner or reusable capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferDiagnostic {
    /// Original physical next-hop peer, not an inferred ultimate BOX sender.
    pub peer: PeerId,
    /// Original Engine-local communicator client serial, diagnostic only.
    pub client_serial: u64,
    /// Original communicator-local queue number.
    pub queue: u32,
    /// Original Engine-local queue-generation serial, diagnostic only.
    pub route: u64,
    /// The exact original physical client remains in the Engine's client table.
    pub client_live: bool,
    /// The exact original queue generation remains, with its current counters.
    pub queue_state: Option<QueueDiagnostic>,
    /// Current original transfer admission/exposure/local-result facts.
    pub state: TransferState,
    /// Original output bypasses peer FLOW charging, independently of queue grants.
    pub bypass: bool,
    /// Original message bytes covered by actual successful local1210 callbacks.
    pub covered_bytes: usize,
    /// Complete original message extent that those callbacks must cover.
    pub total_bytes: usize,
    /// Original parent chunk rows still awaiting local packet/source disposition.
    pub live_chunks: usize,
    /// Original common Job serial, including after that Job already ended.
    pub job_serial: u64,
    /// Original Job if still retained; staging progress is distinct from coverage.
    pub job: Option<JobDiagnostic>,
    /// Current counters of the original physical next-hop peer, if retained.
    pub flow: Option<FlowDiagnostic>,
    /// Already committed Engine monotonic coordinate; no clock is sampled here.
    pub last_monotonic: MonoInstant,
    /// Global local attempts currently retained by this Engine.
    pub attempts: usize,
    /// Global domain output frames awaiting their host, excluding native FIFOs.
    pub outputs: usize,
    /// Original ordinary message/attempt limit.
    pub message_limit: usize,
    /// Original additional control message/attempt slots.
    pub control_message_reserve: usize,
}
struct Path {
    id: PathId,
    mtu: usize,
    until: u64,
}
struct VirtualRow {
    id: VirtualId,
    path: PathId,
    job: u64,
    mid: [u8; 8],
    peer: PeerId,
    origin: Option<ClientId>,
    bytes: Option<Zeroizing<Vec<u8>>>,
    expires: u64,
    control: bool,
    remote: Option<u64>,
    claimed: bool,
    claim: Option<u64>,
    admitted: bool,
    canceled: bool,
}
impl VirtualRow {
    fn packet(&self) -> VirtualPacket<'_> {
        VirtualPacket {
            id: self.id.clone(),
            path: self.path.clone(),
            target: self.peer,
            origin: self.origin.as_ref(),
            bytes: self.bytes.as_deref().map_or(&[], |bytes| bytes.as_slice()),
            without_fc: self.control,
            until: MonoInstant(self.expires),
        }
    }
}
pub(super) struct Transfer {
    pub(super) id: TransferId,
    pub(super) job: u64,
    pub(super) queue: DirectQueue,
    pub(super) written: Coverage,
    pub(super) state: TransferState,
    pub(super) bypass: bool,
    pub(super) packet_observed: bool,
    // Only actual non-normal Job retirement sets this fact. Normal fresh-byte
    // completion must retain unknown chunk callbacks as native debt.
    pub(super) job_retired: bool,
}
pub(super) struct TxBook {
    paths: Vec<(PeerId, Path)>,
    virtuals: Vec<VirtualRow>,
    pub(super) transfers: Vec<Transfer>,
}
impl TxBook {
    pub(super) fn new(limits: Limits) -> Result<Self, Error> {
        let mut paths = Vec::new();
        let mut virtuals = Vec::new();
        let mut transfers = Vec::new();
        paths
            .try_reserve_exact(limits.peers)
            .map_err(|_| Error::Capacity)?;
        virtuals
            .try_reserve_exact(limits.messages)
            .map_err(|_| Error::Capacity)?;
        transfers
            .try_reserve_exact(limits.messages)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            paths,
            virtuals,
            transfers,
        })
    }
    fn can_claim_virtual(&self, candidate: &VirtualRow, now: u64) -> bool {
        if candidate.claimed
            || candidate.admitted
            || candidate.canceled
            || candidate.bytes.is_none()
            || now >= candidate.expires
        {
            return false;
        }
        // Physical Vec slots may move on retirement. Only the original serial
        // orders one submitter's ordinary packets to one peer. A claimed but
        // not admitted predecessor still owns its place; remote ACK debt does
        // not, and neither canceled nor expired work can hold the stream.
        candidate.control
            || !self.virtuals.iter().any(|older| {
                !older.control
                    && !older.admitted
                    && !older.canceled
                    && older.bytes.is_some()
                    && now < older.expires
                    && older.id.source == candidate.id.source
                    && older.origin == candidate.origin
                    && older.peer == candidate.peer
                    && older.id.serial < candidate.id.serial
            })
    }
}
impl Book {
    pub(in crate::engine) fn virtual_path(
        &self,
        peer: PeerId,
        now: u64,
    ) -> Option<(PathId, usize)> {
        self.tx
            .paths
            .iter()
            .find(|(p, v)| {
                *p == peer && v.until > now && self.source.as_ref() == Some(&v.id.source)
            })
            .map(|(_, v)| (v.id.clone(), v.mtu))
    }
    pub(super) fn retire_tx_source(&mut self, source: &Source) {
        self.tx.paths.retain(|(_, p)| &p.id.source != source);
        for v in &mut self.tx.virtuals {
            if &v.id.source == source {
                v.canceled = true;
            }
        }
    }
    pub(super) fn tx_debts(&self, source: &Source) -> usize {
        self.tx
            .virtuals
            .iter()
            .filter(|v| &v.id.source == source)
            .count()
            + self
                .tx
                .transfers
                .iter()
                .filter(|t| &t.id.source == source)
                .count()
    }
    pub(in crate::engine) fn external_bypass(&self, job: u64) -> bool {
        self.tx.transfers.iter().any(|r| r.job == job && r.bypass)
    }
    pub(in crate::engine) fn external(&self, job: u64) -> Option<TransferId> {
        self.tx
            .transfers
            .iter()
            .find(|r| r.job == job)
            .map(|r| r.id.clone())
    }
    pub(in crate::engine) fn virtual_room(&self, limit: usize) -> bool {
        self.tx.virtuals.len() < limit
    }
    fn transfer_completion(&self, transfer: &Transfer) -> Option<TransferOutcome> {
        if transfer.state.job_pending
            || self.sends.iter().any(|row| {
                row.parent
                    .as_ref()
                    .is_some_and(|(id, _)| id == &transfer.id)
            })
        {
            None
        } else {
            transfer.state.outcome
        }
    }
    pub(in crate::engine) fn job_finished(&mut self, job: u64) {
        if let Some(t) = self.tx.transfers.iter_mut().find(|t| t.job == job) {
            t.state.job_pending = false;
        }
    }
    pub(in crate::engine) fn job_retired(&mut self, job: u64) {
        let parent = self
            .tx
            .transfers
            .iter_mut()
            .find(|t| t.job == job)
            .map(|t| {
                t.state.job_pending = false;
                t.job_retired = true;
                t.id.clone()
            });
        for v in &mut self.tx.virtuals {
            if v.job == job {
                v.canceled = true;
            }
        }
        if let Some(parent) = parent {
            self.settle_retired_transfer(&parent);
        }
    }
    /// A retired logical suffix is not unknown native debt once every actual
    /// chunk has ended. Call only after removing the chunk's original SendRow;
    /// its real failure/source result has already taken precedence.
    pub(super) fn settle_retired_transfer(&mut self, parent: &TransferId) {
        if self
            .sends
            .iter()
            .any(|row| row.parent.as_ref().is_some_and(|(id, _)| id == parent))
        {
            return;
        }
        if let Some(t) = self.tx.transfers.iter_mut().find(|t| &t.id == parent)
            && t.job_retired
            && t.state.outcome.is_none()
            && !t.written.complete()
        {
            t.state.outcome = Some(if t.state.queued || t.state.exposed || t.packet_observed {
                TransferOutcome::Incomplete
            } else {
                TransferOutcome::Unsent
            });
        }
    }
    pub(super) fn transfer_packet(&mut self, parent: &TransferId, span: Span, state: SendState) {
        if let Some(t) = self.tx.transfers.iter_mut().find(|t| &t.id == parent) {
            t.packet_observed |= state.packet.is_some();
            t.state.exposed |= state.ipc_exposed;
            if t.state.outcome.is_none() {
                match state.packet {
                    Some(PacketOutcome::Written) => {
                        t.written.mark(span);
                        if t.written.complete() {
                            t.state.outcome = Some(TransferOutcome::Written);
                        }
                    }
                    Some(PacketOutcome::Failed(code)) => {
                        t.state.outcome = Some(TransferOutcome::Failed(code))
                    }
                    Some(PacketOutcome::SourceLost) => {
                        t.state.outcome = Some(TransferOutcome::SourceLost)
                    }
                    None => {}
                }
            }
        }
    }
}
impl Engine {
    /// Actual host installs only the observed current eligible Actor path, using its
    /// original fixed native deadline translated after this Times sample.
    /// Replacing the same peer is atomic: its connection/Jobs survive while
    /// old path attempts retain their exact canceled original callback debt.
    pub fn dv_install_path(
        &mut self,
        source: &Source,
        peer: PeerId,
        mtu: usize,
        remaining: Duration,
        times: Times,
    ) -> Result<PathId, Error> {
        self.dv_check_source(source)?;
        if !(4..=65535).contains(&mtu) {
            return Err(Error::InvalidInput);
        }
        if self.dv_bridge.tx.paths.len() == self.limits.peers
            && !self.dv_bridge.tx.paths.iter().any(|(p, _)| *p == peer)
        {
            return Err(Error::Capacity);
        }
        // Preflight the generation before publishing reachability. A failed
        // replacement must leave the original path and its visibility intact.
        let serial = self
            .dv_bridge
            .serial
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let previous = self
            .dv_bridge
            .tx
            .paths
            .iter()
            .find(|(p, _)| *p == peer)
            .map(|(_, path)| path.id.clone());
        self.dv_virtual_peer(source, peer, remaining, times)?;
        let until = times
            .monotonic()
            .0
            .checked_add(remaining.0)
            .ok_or(Error::Overflow)?;
        let id = PathId {
            source: source.clone(),
            serial,
        };
        let path = Path {
            id: id.clone(),
            mtu,
            until,
        };
        if let Some(i) = self.dv_bridge.tx.paths.iter().position(|(p, _)| *p == peer) {
            self.dv_bridge.tx.paths[i] = (peer, path);
        } else {
            self.dv_bridge.tx.paths.push((peer, path));
        }
        self.dv_bridge.serial = serial;
        if let Some(previous) = previous {
            // New reachability is already installed. Retire only old staging
            // and original claims; never disconnect or erase same-peer Jobs.
            for original in &mut self.dv_bridge.tx.virtuals {
                if original.path == previous {
                    original.canceled = true;
                }
            }
        }
        Ok(id)
    }
    /// Withdraw only that source/path. Admitted old attempts keep their original
    /// callback debt; a replacement cannot inherit their private lease.
    pub fn dv_withdraw_path(&mut self, id: &PathId) -> Result<(), Error> {
        self.dv_check_source(&id.source)?;
        let i = self
            .dv_bridge
            .tx
            .paths
            .iter()
            .position(|(_, p)| p.id == *id)
            .ok_or(Error::Stale)?;
        let peer = self.dv_bridge.tx.paths[i].0;
        let virtual_live = self.dv_bridge.virtuals.iter().any(|v| {
            v.peer == peer
                && v.source != id.source
                && v.until > self.last_monotonic
                && self.dv_bridge.source.as_ref() == Some(&v.source)
        });
        let routes = virtual_live || self.routes.iter().any(|q| q.description.peer == peer);
        let live = virtual_live
            || self
                .routes
                .iter()
                .any(|q| q.description.peer == peer && q.valid_until > self.last_monotonic);
        let needed = self.refresh_outputs(peer, routes, live)?;
        if self
            .output
            .len()
            .checked_add(needed)
            .is_none_or(|n| n > self.limits.messages + self.limits.control_messages)
        {
            return Err(Error::WouldBlock);
        }
        self.dv_bridge.tx.paths.swap_remove(i);
        self.dv_bridge
            .virtuals
            .retain(|v| v.source != id.source || v.peer != peer);
        for v in &mut self.dv_bridge.tx.virtuals {
            if v.path == *id {
                v.canceled = true;
            }
        }
        // No other producer turns an authenticated inbound BOX into return
        // reachability. A withdrawn final path must close the CORE/payload gate
        // now, while admitted original Actor claims keep their own callbacks.
        self.refresh(peer)
    }
    /// Next immutable original packet in its stable submitter/peer order.
    /// Explicit controls remain eligible ahead of ordinary blocked work.
    pub fn dv_virtual_packet(&self) -> Option<VirtualPacket<'_>> {
        self.dv_virtual_packet_where(|_| true)
    }
    /// Select a currently claimable packet accepted by the caller's bounded
    /// admission policy. A blocked peer need not hold unrelated peers or local
    /// submitters. The predicate cannot bypass an original stream predecessor;
    /// `dv_claim_virtual` independently enforces the same boundary.
    pub fn dv_virtual_packet_where(
        &self,
        mut eligible: impl FnMut(&VirtualPacket<'_>) -> bool,
    ) -> Option<VirtualPacket<'_>> {
        if self.dv_bridge.retiring {
            return None;
        }
        self.dv_bridge
            .tx
            .virtuals
            .iter()
            .filter(|v| {
                self.dv_bridge.source.as_ref() == Some(&v.id.source)
                    && self.dv_bridge.tx.can_claim_virtual(v, self.last_monotonic)
            })
            .filter(|v| eligible(&v.packet()))
            .min_by_key(|v| (!v.control, v.id.serial))
            .map(VirtualRow::packet)
    }
    /// Reserve original lease before actual fallible Actor copy. Native caller
    /// returns it with dv_reject_virtual on zero-admission refusal.
    pub fn dv_claim_virtual(&mut self, id: &VirtualId) -> Result<VirtualAttempt, Error> {
        self.dv_check_source(&id.source)?;
        let i = self
            .dv_bridge
            .tx
            .virtuals
            .iter()
            .position(|v| v.id == *id)
            .ok_or(Error::Stale)?;
        let v = &self.dv_bridge.tx.virtuals[i];
        if !self.dv_bridge.tx.can_claim_virtual(v, self.last_monotonic) {
            return Err(Error::NotReady);
        }
        let claim = self.dv_bridge.next()?;
        let v = &mut self.dv_bridge.tx.virtuals[i];
        v.claimed = true;
        v.claim = Some(claim);
        Ok(VirtualAttempt {
            source: id.source.clone(),
            serial: id.serial,
            claim,
        })
    }
    /// Zero-admission refusal preserves the exact bytes/UUID/span and targets.
    pub fn dv_reject_virtual(
        &mut self,
        original: VirtualAttempt,
    ) -> Result<(), Rejected<VirtualAttempt>> {
        let id = original.id();
        let Some(v) =
            self.dv_bridge.tx.virtuals.iter_mut().find(|v| {
                v.id == id && v.claimed && !v.admitted && v.claim == Some(original.claim)
            })
        else {
            return Err(Rejected {
                reason: Error::Stale,
                value: original,
            });
        };
        v.claimed = false;
        v.claim = None;
        Ok(())
    }
    /// Actual Actor copy/admission occurred; release only its former staging
    /// bytes, keeping original Job/span/local MID/remote ACK association.
    pub fn dv_virtual_queued(&mut self, id: &VirtualId) -> Result<(), Error> {
        let v = self
            .dv_bridge
            .tx
            .virtuals
            .iter_mut()
            .find(|v| v.id == *id && v.claimed && !v.admitted)
            .ok_or(Error::Stale)?;
        v.admitted = true;
        if let Some(bytes) = v.bytes.take() {
            self.buffered -= bytes.len();
        }
        Ok(())
    }
    /// Actual source/path/task retirement observed by the coordinator.
    pub fn dv_virtual_canceled(&self, id: &VirtualId) -> bool {
        self.dv_bridge
            .tx
            .virtuals
            .iter()
            .find(|v| v.id == *id)
            .is_none_or(|v| v.canceled || self.dv_bridge.source.as_ref() != Some(&v.id.source))
    }
    /// Return exact original Actor output metadata after its real local write or
    /// terminal failure. This only unlocks the existing remote-ACK retry record;
    /// it never marks remote coverage or regenerates the old BOX nonce.
    pub fn dv_finish_virtual(
        &mut self,
        original: VirtualAttempt,
    ) -> Result<(), Rejected<VirtualAttempt>> {
        let id = original.id();
        let Some(i) = self
            .dv_bridge
            .tx
            .virtuals
            .iter()
            .position(|v| v.id == id && v.admitted && v.claim == Some(original.claim))
        else {
            return Err(Rejected {
                reason: Error::Stale,
                value: original,
            });
        };
        let v = self.dv_bridge.tx.virtuals.swap_remove(i);
        if let Some(bytes) = v.bytes {
            self.buffered -= bytes.len();
        }
        if let Some(record) = v.remote {
            self.remote_acks.local_done(record, v.mid);
        }
        if v.canceled
            && let Some(peer) = self.peers.iter_mut().find(|p| p.id == v.peer)
        {
            // A retired parent may have burned the ultimate peer's historical
            // FLOW charge before its BOX reached native admission. Preserve
            // that history and let a real FLOW exchange recover the window.
            peer.flow_dirty = true;
            peer.flow_next = peer.flow_next.min(self.last_monotonic);
        }
        Ok(())
    }
    /// Admit an actual Actor immutable output as one original existing direct
    /// Job. Common transmit_job selects fragments/reliability and actual queue
    /// grants. This alone is NOT actual native MQ admission.
    pub fn dv_enqueue_transfer(
        &mut self,
        source: &Source,
        queue: &DirectQueue,
        input: &[u8],
        bypass: bool,
        remaining: Duration,
        times: Times,
    ) -> Result<TransferId, Error> {
        self.dv_check_source(source)?;
        self.dv_queue_index(queue, times.monotonic().0)?;
        if self.dv_bridge.tx.transfers.len() == self.limits.messages {
            return Err(Error::Capacity);
        }
        if !matches!(
            Frame::decode(input)?.header().message_type().value(),
            dv::LEARN_TYPE | dv::BOX_TYPE
        ) {
            return Err(Error::Unsupported);
        }
        let written = Coverage::new(input.len(), 0)?;
        let until = times
            .monotonic()
            .0
            .checked_add(remaining.0)
            .filter(|n| *n != u64::MAX && remaining.0 > 0)
            .ok_or(Error::Deadline)?;
        let id = TransferId {
            source: source.clone(),
            serial: self.dv_bridge.next()?,
        };
        self.enqueue(Some(queue.route), queue.peer, input, None, false)?;
        let job = self.jobs.back_mut().ok_or(Error::Stale)?;
        job.expires = until;
        self.dv_bridge.tx.transfers.push(Transfer {
            id: id.clone(),
            job: job.id,
            queue: queue.clone(),
            written,
            state: TransferState {
                queued: false,
                exposed: false,
                outcome: None,
                job_pending: true,
            },
            bypass,
            packet_observed: false,
            job_retired: false,
        });
        Ok(id)
    }
    /// Actual immutable chunk1209 admission, reported synchronously before any
    /// physical write. Returns its original whole-packet parent if present.
    pub fn dv_chunk_queued(&mut self, id: &SendId) -> Result<Option<TransferId>, Error> {
        let i = self.dv_send_index(id)?;
        let Some((parent, _)) = &self.dv_bridge.sends[i].parent else {
            return Ok(None);
        };
        let parent = parent.clone();
        let t = self
            .dv_bridge
            .tx
            .transfers
            .iter_mut()
            .find(|t| t.id == parent)
            .ok_or(Error::Stale)?;
        t.state.queued = true;
        Ok(Some(parent))
    }
    /// Exact current whole output parent of an original native chunk.
    pub fn dv_chunk_parent(&self, id: &SendId) -> Option<TransferId> {
        self.dv_bridge
            .sends
            .iter()
            .find(|r| r.id == *id)
            .and_then(|r| r.parent.as_ref().map(|(id, _)| id.clone()))
    }
    /// Recognize only an already-minted original common-transmit1209 record.
    pub fn dv_frame_tag(&self, owner: &ClientId, frame: &[u8]) -> Option<SendId> {
        if Frame::decode(frame).ok()?.header().message_type().value() != 1209 || frame.len() < 48 {
            return None;
        }
        let mid: [u8; 8] = frame.get(8..16)?.try_into().ok()?;
        self.dv_bridge
            .sends
            .iter()
            .find(|r| r.queue.owner == *owner && r.id.mid == mid)
            .map(|r| r.id.clone())
    }
    /// Actual native/job state; no polling generates a receipt.
    pub fn dv_transfer_state(&self, id: &TransferId) -> Result<TransferState, Error> {
        self.dv_bridge
            .tx
            .transfers
            .iter()
            .find(|r| r.id == *id)
            .map(|r| r.state)
            .ok_or(Error::Stale)
    }
    /// Actual terminal local disposition only after the original common Job
    /// ended and every original native chunk has a known disposition. A local
    /// Written result alone cannot release an active Job's remote-ACK debt.
    /// This read-only business query neither retires nor advances any owner.
    pub fn dv_transfer_completion(
        &self,
        id: &TransferId,
    ) -> Result<Option<TransferOutcome>, Error> {
        self.dv_bridge
            .tx
            .transfers
            .iter()
            .find(|transfer| transfer.id == *id)
            .map(|transfer| self.dv_bridge.transfer_completion(transfer))
            .ok_or(Error::Stale)
    }
    /// Copy bounded facts from the same original transfer and retained records.
    /// Missing/foreign/retired IDs return None; no budget, preflight, queue or
    /// clock is advanced, and the copied labels cannot authorize any operation.
    pub fn dv_transfer_diagnostic(&self, id: &TransferId) -> Option<TransferDiagnostic> {
        let transfer = self
            .dv_bridge
            .tx
            .transfers
            .iter()
            .find(|row| row.id == *id)?;
        let queue = &transfer.queue;
        let queue_state = self
            .routes
            .iter()
            .find(|route| {
                route.serial == queue.route
                    && route.owner == queue.owner
                    && route.description.peer == queue.peer
                    && route.description.id == queue.queue
            })
            .map(|route| QueueDiagnostic {
                available: route.available,
                unlimited: route.unlimited,
                inflight: route.inflight,
                mtu: route.description.mtu,
                valid_until: route.valid_until,
            });
        Some(TransferDiagnostic {
            peer: queue.peer,
            client_serial: queue.owner.serial,
            queue: queue.queue,
            route: queue.route,
            client_live: self.clients.iter().any(|client| client.id == queue.owner),
            queue_state,
            state: transfer.state,
            bypass: transfer.bypass,
            covered_bytes: transfer.written.covered_bytes(),
            total_bytes: transfer.written.total_bytes(),
            live_chunks: self
                .dv_bridge
                .sends
                .iter()
                .filter(|chunk| {
                    chunk
                        .parent
                        .as_ref()
                        .is_some_and(|(parent, _)| parent == id)
                })
                .count(),
            job_serial: transfer.job,
            job: self
                .jobs
                .iter()
                .find(|job| job.id == transfer.job)
                .map(|job| JobDiagnostic {
                    serial: job.id,
                    bytes: job.message.len(),
                    fresh_offset: job.fresh_offset(),
                    whole_sent: job.whole_sent,
                    expires: job.expires,
                    deferred: job.deferred,
                }),
            flow: self
                .peers
                .iter()
                .find(|peer| peer.id == queue.peer)
                .map(|peer| FlowDiagnostic {
                    used: peer.outbound_used,
                    window: peer.outbound_window,
                }),
            last_monotonic: MonoInstant(self.last_monotonic),
            attempts: self.attempts.len(),
            outputs: self.output.len(),
            message_limit: self.limits.messages,
            control_message_reserve: self.limits.control_messages,
        })
    }
    /// Original physical owner remains available for actual partial retirement.
    pub fn dv_transfer_owner(&self, id: &TransferId) -> Result<&ClientId, Error> {
        self.dv_bridge
            .tx
            .transfers
            .iter()
            .find(|r| r.id == *id)
            .map(|r| r.queue.owner())
            .ok_or(Error::Stale)
    }
    /// Cancel only the original unsent suffix/Job. Unknown native chunks still
    /// require actual same-MQ drain/close. Already settled incomplete work does
    /// not acquire a source-loss fact; normal completed Jobs are not retired.
    pub fn dv_cancel_transfer(&mut self, id: &TransferId) -> Result<(), Error> {
        let t = self
            .dv_bridge
            .tx
            .transfers
            .iter()
            .find(|r| r.id == *id)
            .ok_or(Error::Stale)?;
        let job = t.job;
        if let Some(i) = self.jobs.iter().position(|j| j.id == job) {
            let j = self.jobs.remove(i).ok_or(Error::Stale)?;
            self.buffered -= j.charge();
            self.remote_acks.remove_job(job);
            self.dv_bridge.job_retired(job);
        }
        Ok(())
    }
    /// Retire metadata only after actual packet/source fact AND original common
    /// Job ended. No live unexpired nonce, packet or ACK debt is silently evicted.
    pub fn dv_take_transfer(
        &mut self,
        id: TransferId,
    ) -> Result<TransferState, Rejected<TransferId>> {
        let Some(i) = self.dv_bridge.tx.transfers.iter().position(|t| t.id == id) else {
            return Err(Rejected {
                reason: Error::Stale,
                value: id,
            });
        };
        if self
            .dv_bridge
            .transfer_completion(&self.dv_bridge.tx.transfers[i])
            .is_none()
        {
            return Err(Rejected {
                reason: Error::NotReady,
                value: id,
            });
        }
        Ok(self.dv_bridge.tx.transfers.swap_remove(i).state)
    }
}
pub(in crate::engine) struct VirtualPlan {
    pub(in crate::engine) path: PathId,
    pub(in crate::engine) job: u64,
    pub(in crate::engine) peer: PeerId,
    pub(in crate::engine) origin: Option<ClientId>,
    pub(in crate::engine) mid: [u8; 8],
    pub(in crate::engine) remote: Option<u64>,
    pub(in crate::engine) expires: u64,
    pub(in crate::engine) control: bool,
}
pub(in crate::engine) struct VirtualPrepared {
    id: VirtualId,
    plan: VirtualPlan,
}
pub(in crate::engine) struct Chunk(SendRow);
impl Book {
    pub(in crate::engine) fn prepare_virtual(
        &mut self,
        plan: VirtualPlan,
    ) -> Result<VirtualPrepared, Error> {
        if self.source.as_ref() != Some(&plan.path.source) {
            return Err(Error::Stale);
        }
        let id = VirtualId {
            source: plan.path.source.clone(),
            serial: self.next()?,
        };
        Ok(VirtualPrepared { id, plan })
    }
    pub(in crate::engine) fn commit_virtual(&mut self, p: VirtualPrepared, packet: Vec<u8>) {
        let VirtualPlan {
            path,
            job,
            peer,
            origin,
            mid,
            remote,
            expires,
            control,
        } = p.plan;
        self.tx.virtuals.push(VirtualRow {
            id: p.id,
            path,
            job,
            mid,
            peer,
            origin,
            bytes: Some(Zeroizing::new(packet)),
            expires,
            control,
            remote,
            claimed: false,
            claim: None,
            admitted: false,
            canceled: false,
        });
    }
    pub(in crate::engine) fn commit_chunk(&mut self, chunk: Chunk) {
        self.sends.push(chunk.0);
    }
}
impl Engine {
    pub(in crate::engine) fn dv_prepare_chunk(
        &self,
        job: u64,
        q: usize,
        mid: [u8; 8],
        span: Span,
    ) -> Result<Option<Chunk>, Error> {
        let Some(parent) = self.dv_bridge.external(job) else {
            return Ok(None);
        };
        if self.dv_bridge.sends.len() == self.limits.messages {
            return Err(Error::WouldBlock);
        }
        let route = &self.routes[q];
        Ok(Some(Chunk(SendRow {
            parent: Some((parent, span)),
            id: SendId {
                instance: self.instance.clone(),
                mid,
            },
            queue: DirectQueue {
                owner: route.owner.clone(),
                peer: route.description.peer,
                queue: route.description.id,
                route: route.serial,
            },
            debit: 0,
            queue_debit: !route.unlimited,
            state: SendState {
                ipc_exposed: false,
                ipc_written: false,
                packet: None,
            },
        })))
    }
}
impl Engine {
    /// Actual zero-admission generic-J refusal. Invalidates this claim so a
    /// retained old refusal cannot later release a newly admitted actor's debt.
    pub fn dv_unclaim_virtual(&mut self, id: &VirtualId) -> Result<(), Error> {
        let v = self
            .dv_bridge
            .tx
            .virtuals
            .iter_mut()
            .find(|v| v.id == *id && v.claimed && !v.admitted)
            .ok_or(Error::Stale)?;
        v.claimed = false;
        v.claim = None;
        Ok(())
    }
    /// Exact retained original packet, including while its actual admission
    /// closure holds the non-clone lease. No bytes/nonce are regenerated.
    pub fn dv_virtual_get(&self, id: &VirtualId) -> Result<VirtualPacket<'_>, Error> {
        let v = self
            .dv_bridge
            .tx
            .virtuals
            .iter()
            .find(|v| v.id == *id && !v.canceled)
            .ok_or(Error::Stale)?;
        v.bytes.as_ref().ok_or(Error::NotReady)?;
        Ok(v.packet())
    }
    /// Drop only an original never-admitted attempt after source/path retirement.
    /// This releases local staging, not remote coverage or a fabricated ACK.
    pub fn dv_discard_unadmitted(&mut self, id: &VirtualId) -> Result<(), Error> {
        let i = self
            .dv_bridge
            .tx
            .virtuals
            .iter()
            .position(|v| v.id == *id && !v.admitted && !v.claimed)
            .ok_or(Error::Stale)?;
        let v = self.dv_bridge.tx.virtuals.swap_remove(i);
        if let Some(bytes) = v.bytes {
            self.buffered -= bytes.len();
        }
        if let Some(record) = v.remote {
            self.remote_acks.local_done(record, v.mid);
        }
        Ok(())
    }
    /// Local expired/source-retired staging work, no native authority.
    pub fn dv_unadmitted_retired(&self, times: Times) -> Option<VirtualId> {
        self.dv_bridge
            .tx
            .virtuals
            .iter()
            .find(|v| {
                !v.admitted
                    && !v.claimed
                    && (v.canceled
                        || times.monotonic().0 >= v.expires
                        || self.dv_bridge.source.as_ref() != Some(&v.id.source))
            })
            .map(|v| v.id.clone())
    }
}
impl Engine {
    /// Clock-free old-source staging cleanup. Admitted Actor origins remain
    /// untouched and must return through their real original completion path.
    pub fn dv_discard_virtual_source(&mut self, source: &Source) -> Result<bool, Error> {
        if self.dv_bridge.source.as_ref() != Some(source) || !self.dv_bridge.retiring {
            return Err(Error::NotReady);
        }
        let Some(id) = self
            .dv_bridge
            .tx
            .virtuals
            .iter()
            .find(|v| &v.id.source == source && !v.admitted && !v.claimed)
            .map(|v| v.id.clone())
        else {
            return Ok(false);
        };
        self.dv_discard_unadmitted(&id)?;
        Ok(true)
    }
}
