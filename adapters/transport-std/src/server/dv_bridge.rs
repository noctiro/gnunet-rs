//! Physical DV ports. No crypto, actor or persistence owner is hidden in Server.
use super::*;
use gnunet_transport::dv_bridge::{self as dv, DirectQueue, Ingress, IngressId, SendId, Source};

#[derive(Clone, PartialEq, Eq)]
enum Debt {
    Single(SendId),
    Transfer(dv::TransferId),
}
pub(super) struct Deadline {
    id: Debt,
    owner: ClientId,
    hard: Instant,
}
/// Complete actual RX remains held on refusal, retaining its first-byte target.
pub struct InputRefused<E> {
    /// Same non-clone Engine debt supplied to the admission closure.
    pub original: Ingress,
    /// Actual actor/provider/admission refusal, without formatting payload bytes.
    pub error: E,
}
/// Actual original input budget. No operation restarts its first-byte timeout.
#[derive(Clone, Copy, Debug)]
pub struct InputBudget {
    /// Native immutable original first-byte/source target.
    pub hard: Instant,
    /// Logical target derived once from the same sample and remaining native time.
    pub until: AbsoluteTime,
}
/// Original queue cause and independent rollback cause remain distinct.
#[derive(Debug)]
pub struct QueueError {
    /// Original allocation/source/admission cause.
    pub cause: Error,
    /// Independent failure rolling back a never-admitted exact SEND debit.
    pub cleanup: Option<Error>,
}
impl From<Error> for QueueError {
    fn from(cause: Error) -> Self {
        Self {
            cause,
            cleanup: None,
        }
    }
}
impl core::fmt::Display for QueueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DV queue: {:?}; cleanup={:?}", self.cause, self.cleanup)
    }
}
impl std::error::Error for QueueError {}
/// Identify only actual communicator1202 carrying complete1218/1219. It does not
/// classify unrelated malformed IPC as a DV operation.
pub(super) fn is_dv(input: &[u8]) -> bool {
    matches!(gnunet_transport::communicator::Request::decode(input), Ok(gnunet_transport::communicator::Request::Incoming { message, .. }) if gnunet_wire::official::Frame::decode(message).is_ok_and(|f| matches!(f.header().message_type().value(), gnunet_transport::dv::LEARN_TYPE | gnunet_transport::dv::BOX_TYPE)))
}
impl Server {
    /// Whether this original source remains attached as a retirement barrier.
    /// External native/FC and worker debts still require their real outcomes.
    pub fn dv_source_active(&self) -> bool {
        self.engine.dv_source_active()
    }

    /// Actual business admission, separate from source-active retirement gate.
    pub fn dv_source_accepting(&self) -> bool {
        self.engine.dv_source_accepting()
    }
    /// Whether the current native input boundary permits one new Actor source.
    /// Partial ordinary input is not yet classifiable; complete DV input still
    /// belongs to its original source. Reading this state starts no IO, captures
    /// no deadline, and grants no source capability.
    pub fn dv_source_attach_ready(&self) -> bool {
        !self
            .clients
            .iter()
            .any(|c| c.input.is_some() || c.io.frame().is_some_and(is_dv))
    }
    /// Actual Engine-minted source, after the real ready actor identity check.
    pub fn dv_attach_source(&mut self, peer: PeerId) -> Result<Source, Error> {
        if !self.dv_source_attach_ready() {
            return Err(Error::NotReady);
        }
        self.engine.dv_attach_source(peer)
    }
    /// Actor/source is physically closed. Begin retirement without releasing
    /// Owner's original source-active gate or inventing cleanup completion.
    pub fn dv_begin_retire_source(&mut self, source: &Source) -> Result<(), Error> {
        self.engine.dv_begin_retire_source(source)
    }
    /// Retained original Engine obligations, independent of durable worker join.
    pub fn dv_source_debts(&self, source: &Source) -> usize {
        self.engine.dv_source_debts(source)
    }
    /// No clock required. Actor source was physically closed before this call.
    pub fn dv_retire_source(&mut self, source: &Source) -> Result<(), Error> {
        // Partial/held old-source bytes cannot be handed to a replacement
        // actor. Close their original physical MQ before source retirement;
        // other clients/complete ordinary frames keep their own ownership.
        let mut first = None;
        while let Some(i) = self.clients.iter().position(|c| {
            c.dv_rx_source.as_ref() == Some(source)
                && (c.input.is_some() || c.io.frame().is_some_and(is_dv))
        }) {
            if let Err(error) = self.close(i) {
                first.get_or_insert(error);
            }
        }
        if let Err(error) = self.engine.dv_retire_source(source) {
            first.get_or_insert(error);
        }
        first.map_or(Ok(()), Err)
    }
    /// Current eligible direct queue leases, without allocating a snapshot.
    pub fn dv_direct_queues(&self, times: Times) -> impl Iterator<Item = DirectQueue> + '_ {
        self.engine.dv_direct_queues(times)
    }
    /// Next retained DV input in fair actual-client order. This performs no IO.
    pub fn dv_next_input(&self, cursor: &mut usize) -> Option<ClientId> {
        if self.clients.is_empty() {
            return None;
        }
        for _ in 0..self.clients.len() {
            let i = *cursor % self.clients.len();
            *cursor = cursor.wrapping_add(1);
            if self.clients[i].io.frame().is_some_and(is_dv) {
                return Some(self.clients[i].id.clone());
            }
        }
        None
    }
    /// Synchronous actual actor admission of one original complete RX. All
    /// fallible copy/resource work happens inside accept before RX is released.
    /// A refusal removes only the unadmitted metadata reservation and leaves the
    /// same original RX/cursor/deadline. Caller must poll its actual capacity source.
    pub fn dv_try_input<T, E>(
        &mut self,
        source: &Source,
        owner: &ClientId,
        times: Times,
        accept: impl FnOnce(DirectQueue, Ingress, &[u8], InputBudget) -> Result<T, InputRefused<E>>,
    ) -> Result<Option<Result<T, E>>, Error> {
        let i = self
            .clients
            .iter()
            .position(|c| c.id == *owner)
            .ok_or(Error::Stale)?;
        if self.clients[i].dv_rx_source.as_ref() != Some(source) {
            return Err(Error::Stale);
        }
        let now = Instant::now();
        let hard = self.clients[i]
            .input
            .unwrap_or(self.clients[i].lease)
            .min(self.clients[i].lease);
        if now >= hard {
            self.close(i)?;
            return Err(Error::Deadline);
        }
        let remaining =
            u64::try_from(hard.duration_since(now).as_micros()).map_err(|_| Error::Overflow)?;
        let until =
            times.absolute_after(gnunet_wire::official::RelativeTime::from_micros(remaining))?;
        let Some(frame) = self.clients[i].io.frame() else {
            return Ok(None);
        };
        if !is_dv(frame) {
            return Ok(None);
        }
        let original = self
            .engine
            .dv_prepare_incoming(source, owner, frame, times)?;
        let original_id = original.origin.id();
        let result = accept(
            original.queue,
            original.origin,
            original.message,
            InputBudget { hard, until },
        );
        match result {
            Ok(token) => {
                self.engine.dv_input_admitted(&original_id)?;
                self.clients[i].io.release();
                self.clients[i].input = None;
                self.clients[i].dv_rx_source = None;
                Ok(Some(Ok(token)))
            }
            Err(InputRefused { original, error }) => {
                self.engine
                    .dv_abort_incoming(original)
                    .map_err(|r| r.reason)?;
                Ok(Some(Err(error)))
            }
        }
    }
    /// Actual generic actor-J admission. Refusal E retains its original opaque
    /// metadata; only a never-admitted local reservation is rolled back.
    pub fn dv_try_input_generic<T, E>(
        &mut self,
        source: &Source,
        owner: &ClientId,
        times: Times,
        accept: impl FnOnce(DirectQueue, Ingress, &[u8], InputBudget) -> Result<T, E>,
    ) -> Result<Option<Result<T, E>>, Error> {
        let i = self
            .clients
            .iter()
            .position(|c| c.id == *owner)
            .ok_or(Error::Stale)?;
        if self.clients[i].dv_rx_source.as_ref() != Some(source) {
            return Err(Error::Stale);
        }
        let now = Instant::now();
        let hard = self.clients[i]
            .input
            .unwrap_or(self.clients[i].lease)
            .min(self.clients[i].lease);
        if now >= hard {
            self.close(i)?;
            return Err(Error::Deadline);
        }
        let remaining =
            u64::try_from(hard.duration_since(now).as_micros()).map_err(|_| Error::Overflow)?;
        let until =
            times.absolute_after(gnunet_wire::official::RelativeTime::from_micros(remaining))?;
        let Some(frame) = self.clients[i].io.frame() else {
            return Ok(None);
        };
        if !is_dv(frame) {
            return Ok(None);
        }
        let original = self
            .engine
            .dv_prepare_incoming(source, owner, frame, times)?;
        let original_id = original.origin.id();
        let result = accept(
            original.queue,
            original.origin,
            original.message,
            InputBudget { hard, until },
        );
        match result {
            Ok(token) => {
                self.engine.dv_input_admitted(&original_id)?;
                self.clients[i].io.release();
                self.clients[i].input = None;
                self.clients[i].dv_rx_source = None;
                Ok(Some(Ok(token)))
            }
            Err(error) => {
                self.engine.dv_abort_prepared(&original_id)?;
                Ok(Some(Err(error)))
            }
        }
    }
    /// Real actor returned the original debt. Original source loss is distinct
    /// from a successful queued1203. Refusal returns the SAME non-clone value.
    pub fn dv_finish_input(
        &mut self,
        original: Ingress,
    ) -> Result<dv::IngressEnd, gnunet_types::Rejected<Ingress>> {
        self.engine.dv_finish_incoming(original)
    }
    /// Actual private-grant bridge uses this explicit trusted host port. Neither
    /// bytes nor this method alone proves cryptographic or durable authenticity.
    /// Receiving authenticated bytes does not establish a usable return route;
    /// only existing route installation/validation owns that separate authority.
    pub fn dv_deliver(
        &mut self,
        original: &IngressId,
        peer: PeerId,
        bytes: &[u8],
        times: Times,
        signer: &mut impl Signer,
    ) -> Result<dv::Delivery, Error> {
        self.engine.dv_deliver(original, peer, bytes, times, signer)
    }
    /// Prepare/reserve/commit and ACTUALLY enqueue one immutable1209 on its
    /// selected current direct MQ. No await occurs between commit and enqueue.
    /// Returned SendId is local native admission, not full IPC/packet/remote ACK.
    pub fn dv_queue_packet(
        &mut self,
        queue: &DirectQueue,
        bytes: &[u8],
        without_fc: bool,
        hard: Instant,
        times: Times,
    ) -> Result<SendId, QueueError> {
        let i = self
            .clients
            .iter()
            .position(|c| c.id == *queue.owner())
            .ok_or(Error::Stale)?;
        let now = Instant::now();
        let hard = hard.min(self.clients[i].lease);
        if now >= hard {
            return Err(Error::Deadline.into());
        }
        let remaining = gnunet_types::Duration(
            u64::try_from(hard.duration_since(now).as_micros()).map_err(|_| Error::Overflow)?,
        );
        let prepared = self
            .engine
            .dv_prepare_send(queue, bytes, without_fc, remaining, times)?;
        self.clients[i].io.reserve_tagged(prepared.len())?;
        self.dv_deadlines
            .try_reserve(1)
            .map_err(|_| Error::Capacity)?;
        if Instant::now() >= hard {
            return Err(Error::Deadline.into());
        }
        let (id, owner, bytes) = self
            .engine
            .dv_commit_send(prepared, times)
            .map_err(|r| r.reason)?;
        if let Err(rejected) = self.clients[i]
            .io
            .queue_tagged(OwnedFrame::new(bytes), Some(id.clone()))
        {
            let cleanup = self.engine.dv_unsent(id).err();
            return Err(QueueError {
                cause: rejected.reason,
                cleanup,
            });
        }
        self.dv_deadlines.push(Deadline {
            id: Debt::Single(id.clone()),
            owner,
            hard,
        });
        self.clients[i].output = Some(self.clients[i].output.map_or(hard, |at| at.min(hard)));
        Ok(id)
    }
    /// Exact accumulated IPC/communicator facts. Partial IPC does not report a
    /// complete packet. The owning Bridge consumes only a terminal original row.
    pub fn dv_send_state(&self, id: &SendId) -> Result<dv::SendState, Error> {
        self.engine.dv_send_state(id)
    }
    /// Retire only a real terminal original packet/source fact.
    pub fn dv_take_send(
        &mut self,
        id: SendId,
    ) -> Result<dv::SendState, gnunet_types::Rejected<SendId>> {
        let result = self.engine.dv_take_send(id.clone());
        if result.is_ok() {
            self.dv_deadlines
                .retain(|d| d.id != Debt::Single(id.clone()));
        }
        result
    }
    /// Partial/unknown output cancellation physically closes its ORIGINAL MQ.
    /// This can retire other queues sharing that MQ; it does not invent a safe
    /// per-packet wire CANCEL that the official protocol does not contain.
    pub fn dv_retire_send(&mut self, id: &SendId) -> Result<(), Error> {
        let owner = self.engine.dv_send_owner(id)?.clone();
        if self.clients.iter().any(|c| c.id == owner) {
            self.close_client(&owner)?;
        }
        Ok(())
    }
    fn dv_debt_pending(&self, id: &Debt) -> bool {
        match id {
            Debt::Single(id) => self
                .engine
                .dv_send_state(id)
                .is_ok_and(|s| s.packet.is_none()),
            Debt::Transfer(id) => self
                .engine
                .dv_transfer_completion(id)
                .is_ok_and(|done| done.is_none()),
        }
    }
    /// Admit the immutable actual actor output to the EXISTING common Job path.
    /// This is deliberately not a native queued callback. The actual observed
    /// poll port supplies queued only after a real first1209 chunk admission.
    pub fn dv_enqueue_output(
        &mut self,
        source: &Source,
        queue: &DirectQueue,
        bytes: &[u8],
        bypass: bool,
        hard: Instant,
        times: Times,
    ) -> Result<dv::TransferId, Error> {
        let i = self
            .clients
            .iter()
            .position(|c| c.id == *queue.owner())
            .ok_or(Error::Stale)?;
        let hard = hard.min(self.clients[i].lease);
        let now = Instant::now();
        if now >= hard {
            return Err(Error::Deadline);
        }
        self.dv_deadlines
            .try_reserve(1)
            .map_err(|_| Error::Capacity)?;
        let left = gnunet_types::Duration(
            u64::try_from(hard.duration_since(now).as_micros()).map_err(|_| Error::Overflow)?,
        );
        let id = self
            .engine
            .dv_enqueue_transfer(source, queue, bytes, bypass, left, times)?;
        self.dv_deadlines.push(Deadline {
            id: Debt::Transfer(id.clone()),
            owner: queue.owner().clone(),
            hard,
        });
        Ok(id)
    }
    /// Actual original common-Job/native result; does not create an ACK.
    pub fn dv_transfer_state(&self, id: &dv::TransferId) -> Result<dv::TransferState, Error> {
        self.engine.dv_transfer_state(id)
    }
    /// Read original Engine transfer facts without native IO, clock sampling,
    /// queue admission or interpreting copied metadata as a callback/permit.
    pub fn dv_transfer_diagnostic(&self, id: &dv::TransferId) -> Option<dv::TransferDiagnostic> {
        self.engine.dv_transfer_diagnostic(id)
    }
    /// Atomically reclaim an original parent whose chunks are all still owned
    /// locally before native admission. No frame is removed from Framed and no
    /// physical or remote write/ACK is inferred from a successful cancellation.
    pub fn dv_cancel_transfer_pre_native(
        &mut self,
        id: &dv::TransferId,
    ) -> Result<dv::TransferCancellation, Error> {
        let owner = self.engine.dv_transfer_owner(id)?;
        if self
            .clients
            .iter()
            .filter(|client| client.id == *owner)
            .any(|client| {
                client.io.tagged_sends().any(|send| {
                    self.engine.dv_send_state(send).is_err()
                        || self.engine.dv_chunk_parent(send).as_ref() == Some(id)
                })
            })
        {
            return Ok(dv::TransferCancellation::NeedsRetirement);
        }
        let pending_send = self
            .pending_frame
            .as_ref()
            .and_then(|(owner, frame)| self.engine.dv_frame_tag(owner, frame.bytes()));
        // An unclassified DV packet in the original client's staging slot is
        // not proof that this parent has no escaped chunk.
        if self.pending_frame.as_ref().is_some_and(|(client, frame)| {
            client == owner
                && pending_send.is_none()
                && gnunet_wire::official::Frame::decode(frame.bytes()).is_ok_and(|f| {
                    f.header().message_type().value() == 1209
                        && frame.bytes().get(48..).is_some_and(|body| {
                            gnunet_wire::official::Frame::decode(body).is_ok_and(|f| {
                                matches!(f.header().message_type().value(), 1218 | 1219)
                            })
                        })
                })
        }) {
            return Ok(dv::TransferCancellation::NeedsRetirement);
        }
        let pending =
            self.pending_frame
                .as_ref()
                .zip(pending_send.as_ref())
                .map(|((owner, frame), send)| dv::StagedSend {
                    owner,
                    send,
                    bytes: frame.bytes(),
                });
        let result = self.engine.dv_cancel_pre_native_transfer(id, pending)?;
        if let dv::TransferCancellation::Unsent { pending } = result {
            if pending {
                drop(self.pending_frame.take());
            }
            self.dv_deadlines
                .retain(|deadline| deadline.id != Debt::Transfer(id.clone()));
        }
        Ok(result)
    }
    /// Remove only this original deadline after the Engine proved that its
    /// Job and all actual chunks ended, retaining the original local outcome.
    pub(super) fn dv_finish_settled_transfer(
        &mut self,
        id: &dv::TransferId,
    ) -> Result<Option<dv::TransferOutcome>, Error> {
        let outcome = self.engine.dv_transfer_completion(id)?;
        if outcome.is_some() {
            self.dv_deadlines
                .retain(|d| d.id != Debt::Transfer(id.clone()));
        }
        Ok(outcome)
    }
    /// Reclaim a fully local original parent atomically. A Job whose actual
    /// chunks and logical ownership all ended has no remaining native debt,
    /// regardless of its terminal local outcome. Only native/unknown chunks
    /// require original MQ closure; no wire CANCEL or peer ACK is invented.
    pub fn dv_retire_transfer(&mut self, id: &dv::TransferId) -> Result<(), Error> {
        if self.dv_finish_settled_transfer(id)?.is_some() {
            return Ok(());
        }
        if matches!(
            self.dv_cancel_transfer_pre_native(id)?,
            dv::TransferCancellation::Unsent { .. }
        ) {
            return Ok(());
        }
        let owner = self.engine.dv_transfer_owner(id)?.clone();
        let state = self.engine.dv_transfer_state(id)?;
        let mut first = self.engine.dv_cancel_transfer(id).err();
        // Actual logical cancellation ends only the original suffix/retry Job.
        // If all native chunks already ended, preserve their local outcome/MQ.
        if self.dv_finish_settled_transfer(id)?.is_some() {
            return first.map_or(Ok(()), Err);
        }
        if let Some(index) = self.clients.iter().position(|c| c.id == owner)
            && let Err(e) = self.close_observed(
                index,
                RetirementCause::DvTransferCancellation {
                    id: id.clone(),
                    state,
                },
            )
        {
            first.get_or_insert(e);
        }
        first.map_or(Ok(()), Err)
    }
    /// Real original ACK/packet/source debt ended; metadata can now be reclaimed.
    pub fn dv_take_transfer(
        &mut self,
        id: dv::TransferId,
    ) -> Result<dv::TransferState, gnunet_types::Rejected<dv::TransferId>> {
        let result = self.engine.dv_take_transfer(id.clone());
        if result.is_ok() {
            self.dv_deadlines
                .retain(|d| d.id != Debt::Transfer(id.clone()));
        }
        result
    }
    pub(super) fn dv_expired(&self, now: Instant) -> Option<(ClientId, RetirementCause)> {
        self.dv_deadlines
            .iter()
            .find(|d| {
                now >= d.hard
                    && self.clients.iter().any(|c| c.id == d.owner)
                    && self.dv_debt_pending(&d.id)
            })
            .and_then(|d| {
                let work = match &d.id {
                    Debt::Single(id) => DvRetirementWork::Packet {
                        id: id.clone(),
                        state: self.engine.dv_send_state(id).ok()?,
                    },
                    Debt::Transfer(id) => DvRetirementWork::Transfer {
                        id: id.clone(),
                        state: self.engine.dv_transfer_state(id).ok()?,
                    },
                };
                Some((
                    d.owner.clone(),
                    RetirementCause::DvDeadline { work, hard: d.hard },
                ))
            })
    }
    pub(super) fn dv_next_deadline(&self) -> Option<Instant> {
        self.dv_deadlines
            .iter()
            .filter(|d| self.clients.iter().any(|c| c.id == d.owner) && self.dv_debt_pending(&d.id))
            .map(|d| d.hard)
            .min()
    }
}
/// Exact original native admission decision, separate from physical progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAdmission {
    /// The real observer checked this same Actor/source and immutable output.
    /// The caller may now admit this original frame to its physical queue.
    Admit,
    /// Retain this original frame and its fixed targets while other permitted
    /// source/control work progresses. No native admission was authorized.
    Deferred,
    /// The observer requested retirement of this same original parent. Yield
    /// immediately before further native IO so its real transaction can run.
    Retiring,
}
/// Actual synchronous observer of already-minted common-transmit parents.
/// Caller implementation must use its original actor/token mapping, not raw PIDs.
pub trait NativeObserver {
    /// Synchronously project only this same actual Actor/source. A standard
    /// non-DV owner has no DV paths; an active DV source requires its real port.
    fn links(
        &mut self,
        engine: &Engine,
        _peer: PeerId,
    ) -> Result<gnunet_transport::monitor::Links, Error> {
        if engine.dv_source_active() {
            Err(Error::NotReady)
        } else {
            Ok(gnunet_transport::monitor::Links::direct())
        }
    }
    /// Preflight the exact original actor/source before native queue admission.
    /// Deferral and original retirement have distinct scheduling consequences;
    /// neither decision authorizes writing or creates a replacement retry.
    fn ready(&mut self, parent: &dv::TransferId, engine: &Engine)
    -> Result<NativeAdmission, Error>;
    /// Actual1209 admission happened; called before any physical write.
    fn queued(&mut self, parent: &dv::TransferId) -> Result<(), Error>;
    /// Actual positive native bytes happened for this original parent.
    fn exposed(&mut self, parent: &dv::TransferId, bytes: usize) -> Result<(), Error>;
    /// Independent actual physical cleanup failure after a triggering error.
    fn cleanup(&mut self, _error: Error) {}
}
pub(super) struct NoObserver;
impl NativeObserver for NoObserver {
    fn ready(&mut self, _: &dv::TransferId, _: &Engine) -> Result<NativeAdmission, Error> {
        Ok(NativeAdmission::Deferred)
    }
    fn queued(&mut self, _: &dv::TransferId) -> Result<(), Error> {
        Err(Error::NotReady)
    }
    fn exposed(&mut self, _: &dv::TransferId, _: usize) -> Result<(), Error> {
        Err(Error::NotReady)
    }
}
/// Original explicit actual providers; grouping adds no implicit provider/task.
pub struct Ports<'a, S: Signer, E: Entropy, A: AddressStore> {
    /// Actual original identity signing provider.
    pub signer: &'a mut S,
    /// Explicit actual entropy provider.
    pub entropy: &'a mut E,
    /// Actual original address persistence provider.
    pub store: &'a mut A,
}
/// Generic actual Actor refusal retains its same non-clone outbound origin.
pub struct VirtualRefused<E> {
    /// Original common Job attempt, never a new request or verified constructor.
    pub original: dv::VirtualAttempt,
    /// Actual original actor/resource/source error.
    pub error: E,
}
impl Server {
    /// Read actual next common-transmit staged packet, without copying payload.
    pub fn dv_virtual_packet(&self) -> Option<dv::VirtualPacket<'_>> {
        self.engine.dv_virtual_packet()
    }
    /// Select an eligible original stream head without copying its body.
    /// A caller's local refusal cannot authorize a later packet in that stream.
    pub fn dv_virtual_packet_where(
        &self,
        eligible: impl FnMut(&dv::VirtualPacket<'_>) -> bool,
    ) -> Option<dv::VirtualPacket<'_>> {
        self.engine.dv_virtual_packet_where(eligible)
    }
    /// Actual eligible route installation/replacement by the concrete Actor bridge.
    pub fn dv_install_path(
        &mut self,
        source: &Source,
        peer: PeerId,
        mtu: usize,
        remaining: gnunet_types::Duration,
        times: Times,
    ) -> Result<dv::PathId, Error> {
        self.engine
            .dv_install_path(source, peer, mtu, remaining, times)
    }
    /// Actual original route loss; new same-peer paths have distinct IDs.
    pub fn dv_withdraw_path(&mut self, path: &dv::PathId) -> Result<(), Error> {
        self.engine.dv_withdraw_path(path)
    }
    /// Actual generic Actor admission with original immutable packet/lease. The
    /// concrete bridge supplies the real result; no queue or network ACK implied.
    pub fn dv_try_virtual<T, E>(
        &mut self,
        id: &dv::VirtualId,
        accept: impl FnOnce(dv::VirtualAttempt, &[u8]) -> Result<T, VirtualRefused<E>>,
    ) -> Result<Result<T, E>, Error> {
        let original = self.engine.dv_claim_virtual(id)?;
        let packet = self.engine.dv_virtual_get(id)?;
        let result = accept(original, packet.bytes);
        match result {
            Ok(token) => {
                self.engine.dv_virtual_queued(id)?;
                Ok(Ok(token))
            }
            Err(VirtualRefused { original, error }) => {
                self.engine
                    .dv_reject_virtual(original)
                    .map_err(|r| r.reason)?;
                Ok(Err(error))
            }
        }
    }
    /// Concrete generic-J actor port; a refused old claim is invalidated before
    /// the same immutable original packet becomes available for admission again.
    pub fn dv_try_virtual_generic<T, E>(
        &mut self,
        id: &dv::VirtualId,
        accept: impl FnOnce(dv::VirtualAttempt, &[u8]) -> Result<T, E>,
    ) -> Result<Result<T, E>, Error> {
        let original = self.engine.dv_claim_virtual(id)?;
        let packet = self.engine.dv_virtual_get(id)?;
        match accept(original, packet.bytes) {
            Ok(token) => {
                self.engine.dv_virtual_queued(id)?;
                Ok(Ok(token))
            }
            Err(error) => {
                self.engine.dv_unclaim_virtual(id)?;
                Ok(Err(error))
            }
        }
    }
    /// Final actual original Actor attempt outcome releases only local ACK gate.
    pub fn dv_finish_virtual(
        &mut self,
        original: dv::VirtualAttempt,
    ) -> Result<(), gnunet_types::Rejected<dv::VirtualAttempt>> {
        self.engine.dv_finish_virtual(original)
    }
    /// Actual original request/source cancellation, without reassigning a token.
    pub fn dv_virtual_canceled(&self, id: &dv::VirtualId) -> bool {
        self.engine.dv_virtual_canceled(id)
    }
    /// Local never-admitted retired staging. No crypto/store work is replayed.
    pub fn dv_discard_retired(&mut self, times: Times) -> Result<bool, Error> {
        let Some(id) = self.engine.dv_unadmitted_retired(times) else {
            return Ok(false);
        };
        self.engine.dv_discard_unadmitted(&id)?;
        Ok(true)
    }
}
impl Server {
    /// Actually drop this SAME retained complete remote DV frame after permanent
    /// pre-admission refusal. Queue only its original physical FC response; no
    /// application authentication, Actor success or network ACK is invented.
    pub fn dv_discard_original_input(
        &mut self,
        source: &Source,
        owner: &ClientId,
        times: Times,
    ) -> Result<dv::IngressEnd, Error> {
        let i = self
            .clients
            .iter()
            .position(|c| c.id == *owner)
            .ok_or(Error::Stale)?;
        let frame = self.clients[i].io.frame().ok_or(Error::NotReady)?;
        let input = self
            .engine
            .dv_prepare_incoming(source, owner, frame, times)?;
        match self.engine.dv_finish_incoming(input.origin) {
            Ok(end) => {
                self.clients[i].io.release();
                self.clients[i].input = None;
                self.clients[i].dv_rx_source = None;
                Ok(end)
            }
            Err(r) => {
                let cause = r.reason;
                self.engine
                    .dv_abort_incoming(r.value)
                    .map_err(|r| r.reason)?;
                Err(cause)
            }
        }
    }
}
/// Zero-admission inbox refusal retains its actual error and the replacement
/// local reservation ID of THAT same physical input after fair queue rotation.
pub struct InboxRefusal<E> {
    /// Actual zero-admission Actor error/opaque original metadata.
    pub original: E,
    /// Same immutable physical input under a fresh local admission brand.
    pub current: dv::IngressId,
}
impl Server {
    /// Actual complete outer-reassembled DV frame, not a verified sender result.
    pub fn dv_inbox(&self) -> Option<dv::InboxPacket<'_>> {
        self.engine.dv_inbox()
    }
    /// Exact original unadmitted scheduling target; native epoch is supplied by
    /// the same actual Owner Clock, never projected from a fresh UTC sample.
    pub fn dv_inbox_deadline(&self) -> Option<gnunet_types::MonoInstant> {
        self.engine.dv_inbox_deadline()
    }
    /// Actual generic Actor admission of a complete existing reassembly. Refusal
    /// retains SAME immutable body/source/deadline but invalidates the old local
    /// claim brand so a late refused origin cannot affect its newer admission.
    pub fn dv_try_inbox_generic<T, E>(
        &mut self,
        id: &dv::IngressId,
        accept: impl FnOnce(DirectQueue, Ingress, &[u8]) -> Result<T, E>,
    ) -> Result<Result<T, InboxRefusal<E>>, Error> {
        let origin = self.engine.dv_claim_inbox(id)?;
        let frame = self.engine.dv_inbox_get(id)?;
        let result = accept(frame.queue.clone(), origin, frame.bytes);
        match result {
            Ok(value) => {
                self.engine.dv_inbox_admitted(id)?;
                Ok(Ok(value))
            }
            Err(error) => {
                let current = self.engine.dv_reset_inbox(id)?;
                Ok(Err(InboxRefusal {
                    original: error,
                    current,
                }))
            }
        }
    }
    /// Permanent remote pre-admission refusal or original expiry. Actual local
    /// physical FC disposition is returned; no crypto/application success.
    pub fn dv_discard_inbox(&mut self, id: &dv::IngressId) -> Result<dv::IngressEnd, Error> {
        self.engine.dv_drop_inbox(id)
    }
    /// Clock-free retiring-source cleanup: first close the exact original MQ,
    /// then discard only never-admitted held/inbox bytes and their FC records.
    pub fn dv_discard_unadmitted_source(&mut self, source: &Source) -> Result<bool, Error> {
        let mut progress = false;
        let mut first = None;
        if let Some(owner) = self.engine.dv_unadmitted_owner(source)
            && self.clients.iter().any(|c| c.id == owner)
        {
            if let Err(e) = self.close_client(&owner) {
                first.get_or_insert(e);
            }
            progress = true;
        }
        match self.engine.dv_drop_retired_held(source) {
            Ok(changed) => progress |= changed,
            Err(e) => {
                first.get_or_insert(e);
            }
        }
        match self.engine.dv_discard_inbox_source(source) {
            Ok(changed) => progress |= changed,
            Err(e) => {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(progress), Err)
    }
}
impl Server {
    /// Actual old-source staging cleanup, never a new clock-dependent request.
    pub fn dv_discard_virtual_source(&mut self, source: &Source) -> Result<bool, Error> {
        self.engine.dv_discard_virtual_source(source)
    }
}
impl Server {
    /// Native guard for original unadmitted deadlines, with no canonical sample.
    pub fn dv_expire_inbox_native(
        &mut self,
        source: &Source,
        through: gnunet_types::MonoInstant,
    ) -> Result<bool, Error> {
        self.engine.dv_expire_inbox_native(source, through)
    }
}

#[cfg(test)]
mod delivery_boundary_tests {
    use super::*;
    use gnunet_crypto::EddsaPrivateKey;
    use gnunet_transport::p2p::{Challenge, Flow, Validation};
    use gnunet_wire::official::{
        Frame,
        communicator::{Characteristics, Queue, Request},
    };

    struct Key(EddsaPrivateKey);
    impl Signer for Key {
        fn identity(&self) -> PeerId {
            PeerId(*self.0.public_key().as_bytes())
        }
        fn sign_validation(&mut self, bytes: &[u8; 48]) -> Result<[u8; 64], Error> {
            Ok(*self.0.sign(35, bytes)?.as_bytes())
        }
    }
    struct FixtureEntropy(u8);
    impl Entropy for FixtureEntropy {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
            self.0 = self.0.wrapping_add(1);
            bytes.fill(self.0);
            Ok(())
        }
    }
    fn check(value: bool) -> Result<(), Error> {
        if value { Ok(()) } else { Err(Error::Conflict) }
    }
    fn wire(request: Request<'_>) -> Result<Vec<u8>, Error> {
        let mut bytes = vec![0; request.encoded_len()?];
        request.encode(&mut bytes)?;
        Ok(bytes)
    }
    fn times(now: u64) -> Times {
        Times::new(MonoInstant(now), AbsoluteTime::from_micros(1_000_000 + now))
    }
    struct Harness {
        server: Server,
        comm: ClientId,
        carrier: PeerId,
        source: Source,
        local: Key,
    }
    impl Harness {
        fn new() -> Result<Self, Error> {
            let mut local = Key(EddsaPrivateKey::from_seed([11; 32]));
            let mut carrier = Key(EddsaPrivateKey::from_seed([12; 32]));
            let mut entropy = FixtureEntropy(0);
            let mut engine = Engine::new(local.identity(), gnunet_transport::Limits::default())?;
            let comm = engine.accept()?;
            engine.receive(
                &comm,
                &wire(Request::Register {
                    characteristics: Characteristics::Reliable,
                    can_burst: false,
                    prefix: b"unix",
                })?,
                10,
                &mut local,
                &mut entropy,
            )?;
            engine.receive(
                &comm,
                &wire(Request::QueueSetup(
                    Queue {
                        id: 1,
                        peer: carrier.identity().0,
                        network: 1,
                        mtu: 1024,
                        length: u64::MAX,
                        priority: 0,
                        status: 0,
                    },
                    b"unix-/private/server-delivery-boundary",
                ))?,
                10,
                &mut local,
                &mut entropy,
            )?;
            let mut challenge = None;
            while let Some(output) = engine.output() {
                if let Output::Frame { bytes, .. } = output
                    && Frame::decode(&bytes)?.header().message_type().value() == 1209
                {
                    let inner = bytes.get(48..).ok_or(Error::Truncated)?;
                    if Frame::decode(inner)?.header().message_type().value() == 1303 {
                        challenge = Some(Challenge::decode(inner)?);
                    }
                }
            }
            let challenge = challenge.ok_or(Error::NotFound)?;
            let validity = 1_000_000;
            let signed = Validation {
                signature: carrier
                    .sign_validation(&Validation::signed_region(&challenge.nonce, validity))?,
                nonce: challenge.nonce,
                origin: challenge.origin,
                validity,
            }
            .encode();
            engine.receive(
                &comm,
                &wire(Request::Incoming {
                    flow_control: false,
                    flow_id: [0; 8],
                    validity,
                    peer: carrier.identity().0,
                    neighbour: [0; 32],
                    message: &signed,
                })?,
                10,
                &mut local,
                &mut entropy,
            )?;
            check(engine.snapshot().connected == 1)?;
            let mut server = Server::new(engine, 2, 65535)?;
            let source = server.dv_attach_source(local.identity())?;
            Ok(Self {
                server,
                comm,
                carrier: carrier.identity(),
                source,
                local,
            })
        }
        fn deliver(&mut self, sender: PeerId, bytes: &[u8]) -> Result<dv::Delivery, Error> {
            // This test invokes the production Server trusted-host port. The
            // header reserves only an Engine ingress, assuming the caller's
            // separate authentication; it is not an AEAD/BOX success fixture.
            let kind = gnunet_transport::dv::BOX_TYPE.to_be_bytes();
            let marker = [0, 4, kind[0], kind[1]];
            let incoming = wire(Request::Incoming {
                flow_control: false,
                flow_id: [0; 8],
                validity: 1_000_000,
                peer: self.carrier.0,
                neighbour: [0; 32],
                message: &marker,
            })?;
            let original = self
                .server
                .engine
                .dv_prepare_incoming(&self.source, &self.comm, &incoming, times(20))?
                .origin;
            let id = original.id();
            self.server.engine.dv_input_admitted(&id)?;
            let result = self
                .server
                .dv_deliver(&id, sender, bytes, times(20), &mut self.local);
            self.server
                .dv_finish_input(original)
                .map_err(|refused| refused.reason)?;
            result
        }
    }

    #[test]
    fn trusted_server_control_never_creates_a_payload_return_route() -> Result<(), Error> {
        let mut h = Harness::new()?;
        let sender = PeerId(*EddsaPrivateKey::from_seed([13; 32]).public_key().as_bytes());
        let flow = Flow {
            sequence: 1,
            inbound_window: gnunet_transport::p2p::DEFAULT_WINDOW,
            outbound_sent: 0,
            outbound_window: gnunet_transport::p2p::DEFAULT_WINDOW,
            sender_time: 20,
            rtt: 0,
            sync_ready: false,
        }
        .encode();
        check(h.deliver(sender, &flow)? == dv::Delivery::Accepted)?;
        // Only the independently signature-validated physical carrier is up.
        check(h.server.engine().snapshot().connected == 1)?;
        check(matches!(
            h.deliver(sender, &[0, 4, 0, 64]),
            Err(Error::NotReady)
        ))?;
        check(h.server.engine().snapshot().connected == 1)?;
        check(h.server.dv_source_debts(&h.source) == 0)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn partial_registration_finishes_on_original_mq_before_dv_source_handoff()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        struct Store;
        impl AddressStore for Store {
            fn validated(&mut self, _: PeerId, _: &[u8], _: u64) -> Result<(), Error> {
                Err(Error::Conflict)
            }
        }
        let mut signer = Key(EddsaPrivateKey::from_seed([14; 32]));
        let mut entropy = FixtureEntropy(0);
        let mut server = Server::new(
            Engine::new(signer.identity(), gnunet_transport::Limits::default())?,
            1,
            65535,
        )?;
        let (socket, mut communicator) = tokio::net::UnixStream::pair()?;
        let client = server.admit(gnunet_service_runtime::connection::Connection::from_unix(
            socket,
        ))?;
        let lease = server.clients[0].lease;
        let registration = wire(Request::Register {
            characteristics: Characteristics::Reliable,
            can_burst: false,
            prefix: b"unix",
        })?;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            communicator.write_all(&registration[..1]).await?;
            server
                .step(None, 10, &mut signer, &mut entropy, &mut Store)
                .await?;
            let original = server.clients[0].input.ok_or(Error::NotReady)?;
            check(!server.dv_source_attach_ready() && !server.dv_source_active())?;
            // Native progress continues on the same accepted MQ and first-byte
            // target. It is not an Actor admission or a discarded/replayed frame.
            communicator.write_all(&registration[1..2]).await?;
            server
                .step(None, 10, &mut signer, &mut entropy, &mut Store)
                .await?;
            check(server.clients[0].input == Some(original) && server.clients[0].lease == lease)?;
            check(!server.dv_source_attach_ready())?;
            communicator.write_all(&registration[2..]).await?;
            while server.clients[0].io.frame().is_none() {
                server
                    .step(None, 10, &mut signer, &mut entropy, &mut Store)
                    .await?;
            }
            check(server.dv_source_attach_ready() && server.clients[0].id == client)?;
            // A complete ordinary registration needs no Actor ownership. The
            // exact trusted-host port can now mint its source once, then consume
            // that original complete frame without closing or retagging its MQ.
            let source = server.dv_attach_source(signer.identity())?;
            server
                .step(None, 10, &mut signer, &mut entropy, &mut Store)
                .await?;
            check(server.clients[0].io.frame().is_none() && server.clients[0].input.is_none())?;
            check(server.clients[0].id == client && server.clients[0].lease == lease)?;
            check(server.dv_source_active() && server.take_native_retirement().is_none())?;
            server.dv_begin_retire_source(&source)?;
            server.dv_retire_source(&source)?;
            server.shutdown()?;
            let mut byte = [0; 1];
            check(communicator.read(&mut byte).await? == 0)?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await??;
        Ok(())
    }
}
