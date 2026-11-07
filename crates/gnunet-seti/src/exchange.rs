//! Actual GNUnet Bloom reduction, fragment assembly and original output effects.
use crate::*;
use gnunet_block::{BlockType, bloom::BloomGroup};
use gnunet_crypto::Entropy;
use gnunet_types::Error;
use gnunet_wire::official::seti as wire;
/// Exact integer k choice from ceil(log2(remote/local)), clamped safely at one.
/// Length uses the official sender's byte formula with an integer approximation
/// to 1/ln(2), avoiding floating conversion UB at zero/extreme cardinalities.
/// Length is informational on the wire; peers use the actual advertised bytes.
pub fn bloom_parameters(local: u32, remote: u32) -> Result<(usize, u32), Error> {
    if local == 0 {
        return Ok((8, 1));
    }
    let k = if remote <= local {
        if remote == 0 || u64::from(local) >= u64::from(remote) * 2 {
            1
        } else {
            2
        }
    } else {
        let mut scale = u64::from(local);
        let mut n = 0;
        while scale < u64::from(remote) {
            scale *= 2;
            n += 1
        }
        2 + n
    };
    let n = u128::from(local) * u128::from(k);
    let bytes = (n * 14_426_950_408_889_634_u128).div_ceil(10_000_000_000_000_000_u128);
    Ok((
        usize::try_from(bytes.max(1)).map_err(|_| Error::TooLarge)?,
        k,
    ))
}
impl<'id, 'store, 'bytes> Service<'id, 'store, 'bytes> {
    pub(super) fn fail(&mut self, index: usize, reason: Error) {
        if let Some(o) = self.operations[index].state.as_mut() {
            o.phase = Phase::Failed;
            o.failure = Some(reason);
            o.next = NextPeer::None;
            o.build = false;
            o.close = !o.peer_dead;
        }
    }
    /// Advance one actual BF construction with explicit entropy. This is bounded
    /// CPU work only; no queue/write/peer-delivery success is generated here.
    pub fn progress(
        &mut self,
        operation: Operation<'id>,
        entropy: &mut impl Entropy,
    ) -> Result<bool, Error> {
        let r = self.op_ref(operation)?;
        let o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if !o.build {
            return Ok(false);
        }
        if o.pending_peer.is_some() || o.next != NextPeer::None || o.peer_dead {
            return Err(Error::WouldBlock);
        }
        if o.phase != Phase::Bloom {
            return Err(Error::Conflict);
        }
        let (bytes, k) = bloom_parameters(o.count, o.remote)?;
        if bytes > self.limits.bloom_bytes
            || bytes > self.operations[r.index].bloom.len()
            || k > self.limits.hash_rounds
            || o.rounds >= self.limits.exchanges
        {
            self.fail(r.index, Error::Capacity);
            return Err(Error::Capacity);
        }
        let mut salt = None;
        for _ in 0..16 {
            let mut raw = [0; 4];
            if let Err(e) = entropy.fill(&mut raw) {
                raw.fill(0);
                self.fail(r.index, e);
                return Err(e);
            }
            let value = u32::from_ne_bytes(raw);
            if value != u32::MAX {
                salt = Some(value);
                break;
            }
        }
        let Some(salt) = salt else {
            self.fail(r.index, Error::Entropy);
            return Err(Error::Entropy);
        };
        let profile = self.limits.native;
        let slot = &mut self.operations[r.index];
        let mut filter = BloomGroup::new(
            &mut slot.bloom[..bytes],
            BlockType::SETI_TEST,
            k,
            None,
            salt,
            profile,
        )?;
        for (i, e) in self.elements.iter().enumerate() {
            if bit(slot.active, i) {
                let e = e.state.ok_or(Error::StaleGeneration)?;
                filter.test_and_set(&e.hash);
            }
        }
        let o = slot.state.as_mut().ok_or(Error::StaleGeneration)?;
        o.salt = salt;
        o.k = k;
        o.bloom = bytes;
        o.tx = 0;
        o.rx = 0;
        o.rx_total = 0;
        o.rounds += 1;
        o.build = false;
        o.next = NextPeer::Bloom;
        Ok(true)
    }
    fn reduce(&mut self, index: usize) -> Result<(), Error> {
        let o = self.operations[index].state.ok_or(Error::StaleGeneration)?;
        let slot = &mut self.operations[index];
        let filter = BloomGroup::borrow_existing(
            &mut slot.bloom[..o.bloom],
            BlockType::SETI_TEST,
            o.k,
            o.salt,
            self.limits.native,
        )?;
        let mut count = o.count;
        let mut sum = o.xor;
        for (i, e) in self.elements.iter().enumerate() {
            if bit(slot.active, i) {
                let e = e.state.ok_or(Error::StaleGeneration)?;
                if !filter.contains(&e.hash) {
                    set_bit(slot.active, i, false);
                    count = count.checked_sub(1).ok_or(Error::StaleGeneration)?;
                    xor(&mut sum, &e.hash)
                }
            }
        }
        let o = slot.state.as_mut().ok_or(Error::StaleGeneration)?;
        o.count = count;
        o.xor = sum;
        o.rx = 0;
        o.rx_total = 0;
        o.bloom = 0;
        if count == 0 || (count == o.remote && sum == o.remote_xor) {
            o.phase = Phase::SendingDone;
            o.build = false
        } else {
            o.phase = Phase::Bloom;
            o.build = true
        }
        Ok(())
    }
    fn receive_inner(
        &mut self,
        r: Reference,
        message: PeerMessage<'_>,
        now: u64,
    ) -> Result<bool, Error> {
        let old = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if old.deadline != u64::MAX && now >= old.deadline {
            return Err(Error::Deadline);
        }
        match message {
            PeerMessage::OperationRequest {
                element_count,
                app_id: _,
                context,
            } => {
                if old.phase != Phase::AwaitRequest || old.listener.is_none() {
                    return Err(Error::Conflict);
                }
                let len = context.map_or(0, <[u8]>::len);
                if len > self.operations[r.index].context.len() {
                    return Err(Error::Capacity);
                }
                let accept = self.next_accept.checked_add(1).ok_or(Error::Overflow)?;
                if let Some(c) = context {
                    self.operations[r.index].context[..len].copy_from_slice(c)
                }
                self.next_accept = accept;
                let o = self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?;
                o.phase = Phase::AwaitAccept;
                o.accept_id = accept;
                o.context = len;
                o.remote = element_count;
                o.remote_known = true;
                o.deadline = u64::MAX;
                Ok(false)
            }
            PeerMessage::ElementInfo { element_count } => {
                if old.phase != Phase::CountSent
                    || old.pending_peer.is_some()
                    || old.next != NextPeer::None
                    || old.remote_known
                    || old.count > element_count
                {
                    return Err(Error::Conflict);
                }
                let o = self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?;
                o.remote = element_count;
                o.remote_known = true;
                o.phase = Phase::Bloom;
                o.build = true;
                Ok(true)
            }
            PeerMessage::Bloom {
                element_count,
                element_xor,
                mutator,
                total_length,
                bits_per_element,
                data,
            } => {
                if !matches!(old.phase, Phase::CountSent | Phase::Bloom)
                    || old.pending_peer.is_some()
                    || old.next != NextPeer::None
                    || old.build
                {
                    return Err(Error::Conflict);
                }
                let total = usize::try_from(total_length).map_err(|_| Error::TooLarge)?;
                if total == 0
                    || total > self.limits.bloom_bytes
                    || total > self.operations[r.index].bloom.len()
                    || bits_per_element == 0
                    || bits_per_element > self.limits.hash_rounds
                    || data.is_empty()
                {
                    return Err(Error::InvalidInput);
                }
                if old.rx_total == 0 && old.remote_known && element_count > old.remote {
                    return Err(Error::InvalidInput);
                }
                if old.rx_total != 0
                    && (old.rx_total != total
                        || old.k != bits_per_element
                        || old.salt != mutator
                        || old.remote != element_count
                        || old.remote_xor != element_xor)
                {
                    return Err(Error::Conflict);
                }
                let offset = if old.rx_total == 0 { 0 } else { old.rx };
                let end = offset.checked_add(data.len()).ok_or(Error::Overflow)?;
                if end > total {
                    return Err(Error::Malformed);
                }
                self.operations[r.index].bloom[offset..end].copy_from_slice(data);
                let o = self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?;
                o.remote = element_count;
                o.remote_known = true;
                o.remote_xor = element_xor;
                o.salt = mutator;
                o.k = bits_per_element;
                o.bloom = total;
                o.rx_total = total;
                o.rx = end;
                if end == total {
                    self.reduce(r.index)?
                }
                Ok(true)
            }
            PeerMessage::Done {
                element_count,
                element_xor,
            } => {
                let empty_early = old.phase == Phase::CountSent
                    && old.remote_known
                    && old.remote == 0
                    && element_count == 0;
                if old.phase != Phase::Bloom && !empty_early {
                    return Err(Error::Conflict);
                }
                if old.rx_total != 0
                    || old.pending_peer.is_some()
                    || old.next != NextPeer::None
                    || old.build
                {
                    return Err(Error::Conflict);
                }
                if element_count == 0 {
                    if element_xor != [0; 64] {
                        return Err(Error::Conflict);
                    }
                    self.operations[r.index].active.fill(0);
                    if let Some(o) = self.operations[r.index].state.as_mut() {
                        o.count = 0;
                        o.xor = [0; 64]
                    }
                }
                let o = self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?;
                if o.count != element_count || o.xor != element_xor {
                    return Err(Error::Conflict);
                }
                o.phase = Phase::ReceivedDone;
                o.remote = element_count;
                o.remote_xor = element_xor;
                Ok(true)
            }
        }
    }
    /// Consume one exact original CADET plaintext frame. An outstanding Delivery
    /// refuses another input without mutation. Invalid protocol data schedules
    /// failure/actual close and grants no synthetic receive_done.
    pub fn receive_peer(
        &mut self,
        source: PeerSource<'id>,
        bytes: &[u8],
        now: u64,
    ) -> Result<Delivery<'id>, Error> {
        let r = self.source_ref(source)?;
        let old = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if matches!(old.phase, Phase::Failed | Phase::Canceled | Phase::Finished) {
            return Err(Error::Closed);
        }
        if old.input.is_some() {
            return Err(Error::WouldBlock);
        }
        if bytes.len() > gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE {
            self.fail(r.index, Error::TooLarge);
            return Err(Error::TooLarge);
        }
        let message = match PeerMessage::decode(bytes) {
            Ok(m) => m,
            Err(e) => {
                self.fail(r.index, e);
                return Err(e);
            }
        };
        let serial = self.serial()?;
        let ready = match self.receive_inner(r, message, now) {
            Ok(ready) => ready,
            Err(e) => {
                self.fail(r.index, e);
                return Err(e);
            }
        };
        self.operations[r.index]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .input = Some(InputState { serial, ready });
        Ok(Delivery { source, serial })
    }
    fn result_element(&self, index: usize, o: OperationState) -> Option<usize> {
        let full = o.mode == ResultMode::Intersection;
        if full
            && !matches!(
                o.phase,
                Phase::SendingDone | Phase::ReceivedDone | Phase::AwaitClose | Phase::Finished
            )
        {
            return None;
        }
        if matches!(o.phase, Phase::Failed | Phase::Canceled) {
            return None;
        }
        (0..self.elements.len()).find(|i| {
            bit(self.operations[index].members, *i)
                && !bit(self.operations[index].reported, *i)
                && (if full {
                    bit(self.operations[index].active, *i)
                } else {
                    !bit(self.operations[index].active, *i)
                })
        })
    }
    fn results_finished(&self, index: usize, o: OperationState) -> bool {
        self.result_element(index, o).is_none() && o.pending_client.is_none()
    }
    /// Prepare one immutable peer frame. The caller's bounded final allocation
    /// must exist before this commits its original effect; no I/O occurs here.
    pub fn prepare_peer<'a>(
        &mut self,
        operation: Operation<'id>,
        out: &'a mut [u8],
    ) -> Result<Option<Prepared<'a, 'id>>, Error> {
        let r = self.op_ref(operation)?;
        let mut o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if o.peer_dead
            || o.pending_peer.is_some()
            || matches!(
                o.phase,
                Phase::Failed | Phase::Canceled | Phase::Finished | Phase::ReceivedDone
            )
        {
            return Ok(None);
        }
        if o.phase == Phase::SendingDone && self.results_finished(r.index, o) {
            o.next = NextPeer::Done
        }
        let (context, data) = (
            &self.operations[r.index].context[..o.context],
            &self.operations[r.index].bloom[..o.bloom],
        );
        let (message, action) = match o.next {
            NextPeer::None => return Ok(None),
            NextPeer::Request => (
                PeerMessage::OperationRequest {
                    element_count: o.count,
                    app_id: [0; 64],
                    context: (!context.is_empty()).then_some(context),
                },
                Action::Request,
            ),
            NextPeer::Count => (
                PeerMessage::ElementInfo {
                    element_count: o.count,
                },
                Action::Count,
            ),
            NextPeer::Bloom => {
                let left = o.bloom.checked_sub(o.tx).ok_or(Error::StaleGeneration)?;
                let len = left.min(wire::BLOOM_FRAME_MAX - wire::BLOOM_PREFIX);
                if len == 0 {
                    return Err(Error::StaleGeneration);
                }
                (
                    PeerMessage::Bloom {
                        element_count: o.count,
                        element_xor: o.xor,
                        mutator: o.salt,
                        total_length: u32::try_from(o.bloom).map_err(|_| Error::TooLarge)?,
                        bits_per_element: o.k,
                        data: &data[o.tx..o.tx + len],
                    },
                    Action::Bloom {
                        length: len,
                        last: len == left,
                    },
                )
            }
            NextPeer::Done => (
                PeerMessage::Done {
                    element_count: o.count,
                    element_xor: o.xor,
                },
                Action::Done,
            ),
        };
        let len = message.encoded_len()?;
        if out.len() < len {
            return Err(Error::Capacity);
        }
        let serial = self.serial()?;
        message.encode(out)?;
        let source = self.source(r, o)?;
        let effect = Effect {
            operation,
            serial,
            destination: Destination::Peer(source),
        };
        let state = self.operations[r.index]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        state.next = o.next;
        state.pending_peer = Some(EffectMeta {
            operation: r,
            serial,
            action,
            exposed: false,
            queued: false,
        });
        Ok(Some(Prepared {
            effect,
            bytes: &out[..len],
        }))
    }
    fn client_action(&self, index: usize, c: Reference, o: OperationState) -> Option<Action> {
        if o.pending_client.is_some() {
            return None;
        }
        if o.phase == Phase::AwaitAccept
            && !o.suggestion_sent
            && o.listener.and_then(|r| {
                self.listeners
                    .get(r.index)
                    .and_then(|s| s.state)
                    .filter(|s| s.serial == r.serial)
                    .map(|s| s.client)
            }) == Some(c)
        {
            return Some(Action::Suggestion);
        }
        if o.client != Some(c) || o.terminal || o.phase == Phase::Canceled {
            return None;
        }
        if let Some(index) = self.result_element(index, o) {
            return Some(Action::Element { index });
        }
        if o.phase == Phase::Failed {
            return Some(Action::Terminal {
                status: wire::FAILURE,
            });
        }
        if matches!(o.phase, Phase::ReceivedDone | Phase::Finished)
            && self.results_finished(index, o)
        {
            return Some(Action::Terminal { status: wire::DONE });
        }
        None
    }
    /// Prepare one original local result/suggestion. Independent operation cursors
    /// share the MQ's one immutable output budget, without per-result payload Vecs.
    pub fn prepare_client<'a>(
        &mut self,
        client: Client<'id>,
        out: &'a mut [u8],
    ) -> Result<Option<Prepared<'a, 'id>>, Error> {
        let c = self.client_ref(client)?;
        if self.clients[c.index]
            .state
            .is_some_and(|s| s.pending.is_some())
        {
            return Ok(None);
        }
        for n in 0..self.operations.len() {
            let index = (self.client_cursor + n) % self.operations.len();
            let Some(o) = self.operations[index].state else {
                continue;
            };
            let Some(action) = self.client_action(index, c, o) else {
                continue;
            };
            let r = Reference {
                index,
                serial: o.serial,
            };
            let response = match action {
                Action::Suggestion => Response::Request {
                    accept_id: o.accept_id,
                    peer: o.peer,
                    context: (o.context != 0)
                        .then_some(&self.operations[index].context[..o.context]),
                },
                Action::Element { index } => {
                    let e = self.elements[index].state.ok_or(Error::StaleGeneration)?;
                    Response::Result {
                        current_size: u64::from(o.count),
                        request_id: o.request_id,
                        status: if o.mode == ResultMode::Intersection {
                            wire::ADD_LOCAL
                        } else {
                            wire::DEL_LOCAL
                        },
                        element_type: e.element_type,
                        data: &self.elements[index].bytes[..e.len],
                    }
                }
                Action::Terminal { status } => Response::Result {
                    current_size: u64::from(o.count),
                    request_id: o.request_id,
                    status,
                    element_type: 0,
                    data: &[],
                },
                _ => return Err(Error::StaleGeneration),
            };
            let len = response.encoded_len_with_layout(self.limits.result_layout)?;
            if out.len() < len {
                return Err(Error::Capacity);
            }
            let serial = self.serial()?;
            response.encode_with_layout(out, self.limits.result_layout)?;
            let pending = EffectMeta {
                operation: r,
                serial,
                action,
                exposed: false,
                queued: false,
            };
            self.operations[index]
                .state
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .pending_client = Some(pending);
            self.clients[c.index]
                .state
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .pending = Some(pending);
            self.client_cursor = (index + 1) % self.operations.len();
            let effect = Effect {
                operation: self.op(r),
                serial,
                destination: Destination::Client(client),
            };
            return Ok(Some(Prepared {
                effect,
                bytes: &out[..len],
            }));
        }
        Ok(None)
    }
    fn effect_ref(&self, effect: Effect<'id>) -> Result<(Reference, EffectMeta), Error> {
        let r = self.op_ref(effect.operation)?;
        let o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        let pending = match effect.destination {
            Destination::Peer(source) => {
                if self.source_ref(source)? != r {
                    return Err(Error::StaleGeneration);
                }
                o.pending_peer
            }
            Destination::Client(client) => {
                let c = self.client_ref(client)?;
                let pending = self.clients[c.index]
                    .state
                    .and_then(|s| s.pending)
                    .ok_or(Error::StaleGeneration)?;
                if pending.operation != r || pending.serial != effect.serial {
                    return Err(Error::StaleGeneration);
                }
                o.pending_client
            }
        }
        .ok_or(Error::StaleGeneration)?;
        if pending.operation != r || pending.serial != effect.serial {
            return Err(Error::StaleGeneration);
        }
        Ok((r, pending))
    }
    /// Preflight a new physical admission of this original immutable frame.
    /// Logical cancel/failure revokes only never-admitted output, not old writes.
    pub fn can_queue(&self, effect: Effect<'id>) -> Result<(), Error> {
        let (r, pending) = self.effect_ref(effect)?;
        if pending.queued {
            return Err(Error::Conflict);
        }
        let o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if o.phase == Phase::Canceled {
            return Err(Error::Closed);
        }
        if o.phase == Phase::Failed
            && !matches!(
                pending.action,
                Action::Terminal {
                    status: wire::FAILURE
                }
            )
        {
            return Err(Error::Closed);
        }
        Ok(())
    }
    /// Actual original native queue admission. The caller must preflight before
    /// its real enqueue and report this fact before dispatching another event.
    pub fn queued(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        self.can_queue(effect)?;
        let (r, _) = self.effect_ref(effect)?;
        match effect.destination {
            Destination::Peer(_) => {
                self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending_peer
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .queued = true
            }
            Destination::Client(client) => {
                let c = self.client_ref(client)?;
                self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending_client
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .queued = true;
                self.clients[c.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .queued = true
            }
        }
        Ok(())
    }
    /// Retire only an actual never-admitted physical-port refusal. A canceled
    /// waiting future is insufficient; queued/partial original frames must drain.
    pub fn reject_prepared(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        let (r, p) = self.effect_ref(effect)?;
        if p.queued || p.exposed {
            return Err(Error::WouldBlock);
        }
        match effect.destination {
            Destination::Peer(_) => {
                self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending_peer = None
            }
            Destination::Client(client) => {
                let c = self.client_ref(client)?;
                self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending_client = None;
                self.clients[c.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending = None
            }
        }
        Ok(())
    }
    /// Original physical port conclusively settled this frame with zero exposure.
    /// This may retire a truly canceled queued frame; canceling a waiting future
    /// alone cannot call it. No protocol/result progress or ACK is fabricated.
    pub fn unsent(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        let (r, pending) = self.effect_ref(effect)?;
        if pending.exposed {
            return Err(Error::WouldBlock);
        }
        match effect.destination {
            Destination::Peer(_) => {
                self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending_peer = None;
            }
            Destination::Client(client) => {
                let c = self.client_ref(client)?;
                self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending_client = None;
                self.clients[c.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending = None;
            }
        }
        Ok(())
    }
    /// Actual positive write on the original immutable effect, never queue intent.
    pub fn exposed(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        let (r, pending) = self.effect_ref(effect)?;
        if !pending.queued {
            return Err(Error::InvalidInput);
        }
        match effect.destination {
            Destination::Peer(_) => {
                self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending_peer
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .exposed = true
            }
            Destination::Client(client) => {
                let c = self.client_ref(client)?;
                self.operations[r.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending_client
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .exposed = true;
                self.clients[c.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .exposed = true
            }
        }
        Ok(())
    }
    /// Original frame actually completed writing. Local queue admission alone must
    /// never call this method. Canceled old effects settle without reviving state.
    pub fn written(&mut self, effect: Effect<'id>) -> Result<(), Error> {
        let (r, pending) = self.effect_ref(effect)?;
        if !pending.exposed {
            return Err(Error::InvalidInput);
        }
        let mut o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        let canceled = matches!(o.phase, Phase::Canceled | Phase::Failed);
        match effect.destination {
            Destination::Peer(_) => {
                o.pending_peer = None;
                if !canceled {
                    match pending.action {
                        Action::Request | Action::Count => {
                            o.phase = Phase::CountSent;
                            o.next = NextPeer::None
                        }
                        Action::Bloom { length, last } => {
                            o.tx = o.tx.checked_add(length).ok_or(Error::Overflow)?;
                            if last {
                                o.next = NextPeer::None;
                                o.bloom = 0;
                                o.tx = 0;
                                o.phase = Phase::Bloom
                            }
                        }
                        Action::Done => {
                            o.phase = Phase::AwaitClose;
                            o.next = NextPeer::None
                        }
                        _ => return Err(Error::StaleGeneration),
                    }
                }
            }
            Destination::Client(client) => {
                let c = self.client_ref(client)?;
                self.clients[c.index]
                    .state
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .pending = None;
                o.pending_client = None;
                match pending.action {
                    Action::Suggestion => o.suggestion_sent = true,
                    Action::Element { index } => {
                        set_bit(self.operations[r.index].reported, index, true)
                    }
                    Action::Terminal { status } => {
                        o.terminal = true;
                        if !canceled && status == wire::DONE {
                            o.phase = Phase::Finished;
                            o.close = !o.peer_dead
                        }
                    }
                    _ => return Err(Error::StaleGeneration),
                }
            }
        }
        self.operations[r.index].state = Some(o);
        Ok(())
    }
    /// Original actual peer channel stopped, with exact pending/exposure facts.
    /// Expected includes explicit failure/cancel close and protocol close; it
    /// never grants success by itself. Phase/failure determine the actual result.
    pub fn peer_lost(
        &mut self,
        source: PeerSource<'id>,
        reason: Error,
    ) -> Result<PeerLoss<'id>, Error> {
        let r = self.source_ref(source)?;
        let mut o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        let expected = matches!(
            o.phase,
            Phase::AwaitClose
                | Phase::ReceivedDone
                | Phase::Finished
                | Phase::Canceled
                | Phase::Failed
        );
        let loss = PeerLoss {
            reason,
            source,
            pending: o.pending_peer.map(|p| Effect {
                operation: source.operation,
                serial: p.serial,
                destination: Destination::Peer(source),
            }),
            exposed: o.pending_peer.is_some_and(|p| p.exposed),
            queued: o.pending_peer.is_some_and(|p| p.queued),
            delivery: o.input.map(|i| Delivery {
                source,
                serial: i.serial,
            }),
            expected,
        };
        o.peer_dead = true;
        o.close = false;
        o.pending_peer = None;
        o.input = None;
        o.next = NextPeer::None;
        o.build = false;
        if o.phase == Phase::AwaitClose {
            o.phase = Phase::Finished
        } else if !expected {
            o.phase = Phase::Failed;
            o.failure = Some(reason)
        }
        self.operations[r.index].state = Some(o);
        Ok(loss)
    }
    /// Actual local MQ stopped. Cancel its logical set/listener/operation effects
    /// only after preserving original frozen-result facts; peers still need close.
    pub fn detach(&mut self, client: Client<'id>, reason: Error) -> Result<ClientLoss<'id>, Error> {
        let c = self.client_ref(client)?;
        let old = self.clients[c.index].state.ok_or(Error::StaleGeneration)?;
        let mut loss = ClientLoss {
            reason,
            client,
            pending: old.pending.map(|p| Effect {
                operation: self.op(p.operation),
                serial: p.serial,
                destination: Destination::Client(client),
            }),
            exposed: old.pending.is_some_and(|p| p.exposed),
            queued: old.pending.is_some_and(|p| p.queued),
            operations: 0,
            port: None,
        };
        if let Some(l) = old.listener {
            loss.port = self.close_listener(Listener(self.handle(l.index, l.serial)))?
        }
        if let Some(set) = old.set {
            self.release_set(Set(self.handle(set.index, set.serial)))?
        }
        for slot in &mut *self.operations {
            if let Some(o) = slot.state.as_mut() {
                if o.pending_client.is_some_and(|p| Some(p) == old.pending) {
                    o.pending_client = None
                }
                if o.client == Some(c) {
                    o.client = None;
                    o.phase = Phase::Canceled;
                    o.next = NextPeer::None;
                    o.build = false;
                    o.close = !o.peer_dead;
                    loss.operations += 1
                }
            }
        }
        self.clients[c.index].state = None;
        Ok(loss)
    }
}

impl<'id, 'store, 'bytes> Service<'id, 'store, 'bytes> {
    /// Whether an actual local result/suggestion can now be prepared, without
    /// allocating output or committing a new effect. This is not queue credit.
    pub fn client_output_ready(&self, client: Client<'id>) -> Result<bool, Error> {
        let c = self.client_ref(client)?;
        if self.clients[c.index]
            .state
            .is_some_and(|s| s.pending.is_some())
        {
            return Ok(false);
        }
        Ok(self.operations.iter().enumerate().any(|(i, slot)| {
            slot.state
                .is_some_and(|o| self.client_action(i, c, o).is_some())
        }))
    }
    /// Whether an actual peer frame can now be prepared, without allocating a
    /// maximum-size buffer or changing its immutable output/effect ownership.
    pub fn peer_output_ready(&self, operation: Operation<'id>) -> Result<bool, Error> {
        let r = self.op_ref(operation)?;
        let o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if o.peer_dead
            || o.pending_peer.is_some()
            || matches!(
                o.phase,
                Phase::Failed | Phase::Canceled | Phase::Finished | Phase::ReceivedDone
            )
        {
            return Ok(false);
        }
        Ok(o.next != NextPeer::None
            || (o.phase == Phase::SendingDone && self.results_finished(r.index, o)))
    }
}
