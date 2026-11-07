//! Allocation-free SETI sets, snapshots and actual Bloom-reconciliation owner.
//! All clocks, entropy, original MQ/CADET effects and physical-close facts are
//! supplied by explicit caller ports. This crate creates no network or thread.
#![no_std]
#![forbid(unsafe_code)]
mod exchange;
mod types;
use core::ptr;
pub use exchange::bloom_parameters;
use gnunet_crypto::hash512_parts;
use gnunet_types::Error;
pub use gnunet_wire::official::seti::{PeerMessage, Request, Response};
pub use types::*;
/// Exact GNUNET_SETI_element_hash: native uint16 size, native uint16 semantic
/// type, then opaque data. Select the actual C profile; no endian hint is on wire.
pub fn element_hash(element: Element<'_>, native: NativeEndian) -> Result<[u8; 64], Error> {
    let size = u16::try_from(element.data.len()).map_err(|_| Error::TooLarge)?;
    let (size, kind) = match native {
        NativeEndian::Little => (size.to_le_bytes(), element.element_type.to_le_bytes()),
        NativeEndian::Big => (size.to_be_bytes(), element.element_type.to_be_bytes()),
    };
    Ok(hash512_parts(&[&size, &kind, element.data]))
}
/// One bounded node owner. Mutable caller payload pools remain private, so an
/// operation bitmap can retain original bytes while sets add/remove/reuse rows.
pub struct Service<'id, 'store, 'bytes> {
    domain: &'id Instance,
    clients: &'store mut [ClientSlot],
    sets: &'store mut [SetSlot],
    listeners: &'store mut [ListenerSlot],
    elements: &'store mut [ElementSlot<'bytes>],
    operations: &'store mut [OperationSlot<'bytes>],
    limits: Limits,
    next_accept: u32,
    client_cursor: usize,
    operation_cursor: usize,
}
impl<'id, 'store, 'bytes> Service<'id, 'store, 'bytes> {
    /// Borrow all explicitly bounded storage; performs no allocation or I/O.
    pub fn new(
        domain: &'id mut Instance,
        clients: &'store mut [ClientSlot],
        sets: &'store mut [SetSlot],
        listeners: &'store mut [ListenerSlot],
        elements: &'store mut [ElementSlot<'bytes>],
        operations: &'store mut [OperationSlot<'bytes>],
        limits: Limits,
    ) -> Result<Self, Error> {
        let bitmap = elements.len().checked_add(7).ok_or(Error::Overflow)? / 8;
        if clients.is_empty()
            || sets.is_empty()
            || operations.is_empty()
            || elements.len() > u32::MAX as usize
            || limits.element_bytes > 65535 - limits.result_layout.prefix()
            || limits.bloom_bytes == 0
            || limits.bloom_bytes > u32::MAX as usize
            || limits.hash_rounds == 0
            || limits.hash_rounds > i32::MAX as u32
            || limits.exchanges == 0
            || limits.incoming_micros == 0
            || clients.iter().any(|s| s.state.is_some())
            || sets.iter().any(|s| s.state.is_some())
            || listeners.iter().any(|s| s.state.is_some())
            || elements.iter().any(|s| s.state.is_some())
            || operations.iter().any(|s| {
                s.state.is_some()
                    || s.members.len() < bitmap
                    || s.active.len() < bitmap
                    || s.reported.len() < bitmap
                    || s.bloom.is_empty()
            })
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            domain,
            clients,
            sets,
            listeners,
            elements,
            operations,
            limits,
            next_accept: 0,
            client_cursor: 0,
            operation_cursor: 0,
        })
    }
    fn serial(&self) -> Result<u64, Error> {
        let n = self
            .domain
            .next
            .get()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.domain.next.set(n);
        Ok(n)
    }
    fn handle(&self, index: usize, serial: u64) -> Handle<'id> {
        Handle {
            domain: self.domain,
            index,
            serial,
        }
    }
    fn check(&self, h: Handle<'id>) -> Result<Reference, Error> {
        if !ptr::eq(h.domain, self.domain) {
            return Err(Error::StaleGeneration);
        }
        Ok(Reference {
            index: h.index,
            serial: h.serial,
        })
    }
    fn client_ref(&self, c: Client<'id>) -> Result<Reference, Error> {
        let r = self.check(c.0)?;
        if self
            .clients
            .get(r.index)
            .and_then(|s| s.state)
            .is_none_or(|s| s.serial != r.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn set_ref(&self, s: Set<'id>) -> Result<Reference, Error> {
        let r = self.check(s.0)?;
        if self
            .sets
            .get(r.index)
            .and_then(|s| s.state)
            .is_none_or(|s| s.serial != r.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn listener_ref(&self, l: Listener<'id>) -> Result<Reference, Error> {
        let r = self.check(l.0)?;
        if self
            .listeners
            .get(r.index)
            .and_then(|s| s.state)
            .is_none_or(|s| s.serial != r.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn op_ref(&self, op: Operation<'id>) -> Result<Reference, Error> {
        let r = self.check(op.0)?;
        if self
            .operations
            .get(r.index)
            .and_then(|s| s.state)
            .is_none_or(|s| s.serial != r.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    fn op(&self, r: Reference) -> Operation<'id> {
        Operation(self.handle(r.index, r.serial))
    }
    fn source(&self, r: Reference, s: OperationState) -> Result<PeerSource<'id>, Error> {
        Ok(PeerSource {
            operation: self.op(r),
            serial: s.source.ok_or(Error::NotReady)?,
            peer: s.peer,
        })
    }
    fn source_ref(&self, source: PeerSource<'id>) -> Result<Reference, Error> {
        let r = self.op_ref(source.operation)?;
        let s = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if s.source != Some(source.serial) || s.peer_dead || s.peer != source.peer {
            return Err(Error::StaleGeneration);
        }
        Ok(r)
    }
    /// Mint a source only after the caller has accepted its actual IPC MQ.
    pub fn attach(&mut self) -> Result<Client<'id>, Error> {
        let i = self
            .clients
            .iter()
            .position(|s| s.state.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.serial()?;
        self.clients[i].state = Some(ClientState {
            serial,
            set: None,
            listener: None,
            pending: None,
        });
        Ok(Client(self.handle(i, serial)))
    }
    /// Create the one set associated with this original local MQ.
    pub fn create(&mut self, client: Client<'id>) -> Result<Set<'id>, Error> {
        let c = self.client_ref(client)?;
        if self.clients[c.index].state.is_some_and(|s| s.set.is_some()) {
            return Err(Error::Conflict);
        }
        let i = self
            .sets
            .iter()
            .position(|s| s.state.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.serial()?;
        self.sets[i].state = Some(SetState {
            serial,
            client: c,
            generation: 0,
            count: 0,
        });
        if let Some(s) = self.clients[c.index].state.as_mut() {
            s.set = Some(Reference { index: i, serial })
        }
        Ok(Set(self.handle(i, serial)))
    }
    /// Existing original set on this MQ, without reconstructing from an index.
    pub fn set(&self, client: Client<'id>) -> Result<Option<Set<'id>>, Error> {
        let c = self.client_ref(client)?;
        Ok(self.clients[c.index]
            .state
            .and_then(|s| s.set)
            .map(|r| Set(self.handle(r.index, r.serial))))
    }
    /// Current local elements, independent of any in-flight operation snapshot.
    pub fn elements(&self, set: Set<'id>) -> Result<impl Iterator<Item = Element<'_>>, Error> {
        let r = self.set_ref(set)?;
        Ok(self.elements.iter().filter_map(move |e| {
            e.state.filter(|s| s.set == r && s.active).map(|s| Element {
                element_type: s.element_type,
                data: &e.bytes[..s.len],
            })
        }))
    }
    /// Add without cloning payloads per operation. Exact duplicates are ignored;
    /// hash collisions with different bytes are rejected instead of conflated.
    pub fn add(&mut self, set: Set<'id>, element: Element<'_>) -> Result<bool, Error> {
        let r = self.set_ref(set)?;
        if element.data.len() > self.limits.element_bytes {
            return Err(Error::TooLarge);
        }
        let hash = element_hash(element, self.limits.native)?;
        if let Some(i) = self
            .elements
            .iter()
            .position(|e| e.state.is_some_and(|s| s.set == r && s.hash == hash))
        {
            let s = self.elements[i].state.ok_or(Error::StaleGeneration)?;
            if s.element_type != element.element_type
                || &self.elements[i].bytes[..s.len] != element.data
            {
                return Err(Error::Conflict);
            }
            if s.active {
                return Ok(false);
            }
            let generation = self.sets[r.index]
                .state
                .ok_or(Error::StaleGeneration)?
                .generation
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            let count = self.sets[r.index]
                .state
                .ok_or(Error::StaleGeneration)?
                .count
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            if let Some(s) = self.elements[i].state.as_mut() {
                s.active = true;
                s.added = generation
            }
            if let Some(s) = self.sets[r.index].state.as_mut() {
                s.generation = generation;
                s.count = count
            }
            return Ok(true);
        }
        let i = self
            .elements
            .iter()
            .enumerate()
            .filter(|(_, e)| e.state.is_none() && e.bytes.len() >= element.data.len())
            .min_by_key(|(_, e)| e.bytes.len())
            .map(|(i, _)| i)
            .ok_or(Error::Capacity)?;
        let old = self.sets[r.index].state.ok_or(Error::StaleGeneration)?;
        let generation = old.generation.checked_add(1).ok_or(Error::Overflow)?;
        let count = old.count.checked_add(1).ok_or(Error::Overflow)?;
        self.elements[i].bytes[..element.data.len()].copy_from_slice(element.data);
        self.elements[i].state = Some(ElementState {
            set: r,
            active: true,
            references: 0,
            element_type: element.element_type,
            len: element.data.len(),
            hash,
            added: generation,
        });
        if let Some(s) = self.sets[r.index].state.as_mut() {
            s.generation = generation;
            s.count = count
        }
        Ok(true)
    }
    /// Local Rust collection operation only. Official SETI has no REMOVE IPC
    /// assignment; old operation snapshots retain the original selected bytes.
    pub fn remove(&mut self, set: Set<'id>, element: Element<'_>) -> Result<bool, Error> {
        let r = self.set_ref(set)?;
        let hash = element_hash(element, self.limits.native)?;
        let Some(i) = self.elements.iter().position(|e| {
            e.state
                .is_some_and(|s| s.set == r && s.active && s.hash == hash)
        }) else {
            return Ok(false);
        };
        let e = self.elements[i].state.ok_or(Error::StaleGeneration)?;
        if e.element_type != element.element_type
            || &self.elements[i].bytes[..e.len] != element.data
        {
            return Err(Error::Conflict);
        }
        let old = self.sets[r.index].state.ok_or(Error::StaleGeneration)?;
        let generation = old.generation.checked_add(1).ok_or(Error::Overflow)?;
        if e.references == 0 {
            self.elements[i].state = None
        } else if let Some(e) = self.elements[i].state.as_mut() {
            e.active = false
        }
        if let Some(s) = self.sets[r.index].state.as_mut() {
            s.generation = generation;
            s.count -= 1
        }
        Ok(true)
    }
    /// Release the logical set while retained operations continue on snapshots.
    /// An actual MQ detach is different and cancels that source's operations.
    pub fn release_set(&mut self, set: Set<'id>) -> Result<(), Error> {
        let r = self.set_ref(set)?;
        let s = self.sets[r.index].state.ok_or(Error::StaleGeneration)?;
        for e in &mut *self.elements {
            if let Some(m) = e.state.as_mut()
                && m.set == r
            {
                m.active = false;
                if m.references == 0 {
                    e.state = None
                }
            }
        }
        if let Some(c) = self
            .clients
            .get_mut(s.client.index)
            .and_then(|c| c.state.as_mut())
            && c.serial == s.client.serial
            && c.set == Some(r)
        {
            c.set = None
        }
        self.sets[r.index].state = None;
        Ok(())
    }
    /// Register a logical listener. This does not announce a native CADET port.
    pub fn listen(&mut self, client: Client<'id>, app: [u8; 64]) -> Result<Listener<'id>, Error> {
        let c = self.client_ref(client)?;
        if self.clients[c.index]
            .state
            .is_some_and(|s| s.listener.is_some())
            || self
                .listeners
                .iter()
                .any(|s| s.state.is_some_and(|s| s.app == app))
        {
            return Err(Error::Conflict);
        }
        let i = self
            .listeners
            .iter()
            .position(|s| s.state.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.serial()?;
        self.listeners[i].state = Some(ListenerState {
            serial,
            client: c,
            app,
            port: None,
        });
        if let Some(s) = self.clients[c.index].state.as_mut() {
            s.listener = Some(Reference { index: i, serial })
        }
        Ok(Listener(self.handle(i, serial)))
    }
    /// Application port hash required by the explicit native CADET port owner.
    pub fn listener_app(&self, listener: Listener<'id>) -> Result<[u8; 64], Error> {
        let r = self.listener_ref(listener)?;
        Ok(self.listeners[r.index]
            .state
            .ok_or(Error::StaleGeneration)?
            .app)
    }
    /// Trusted actual-port boundary: call only for a real current native binding.
    /// A decoded plaintext app id or queued open alone grants no such evidence.
    pub fn bind_listener(&mut self, listener: Listener<'id>) -> Result<Port<'id>, Error> {
        let r = self.listener_ref(listener)?;
        if self.listeners[r.index]
            .state
            .is_some_and(|s| s.port.is_some())
        {
            return Err(Error::Conflict);
        }
        let serial = self.serial()?;
        if let Some(s) = self.listeners[r.index].state.as_mut() {
            s.port = Some(serial)
        }
        Ok(Port { listener, serial })
    }
    /// Original physical port binding stopped; a later binding has another epoch.
    pub fn unbind_listener(&mut self, port: Port<'id>) -> Result<(), Error> {
        let r = self.listener_ref(port.listener)?;
        let s = self.listeners[r.index]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if s.port != Some(port.serial) {
            return Err(Error::StaleGeneration);
        }
        s.port = None;
        Ok(())
    }
    /// Logical listen cancel rejects unaccepted channels. Return the original
    /// actual port for separate physical close; accepted operations continue.
    pub fn close_listener(&mut self, listener: Listener<'id>) -> Result<Option<Port<'id>>, Error> {
        let r = self.listener_ref(listener)?;
        let s = self.listeners[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        for op in &mut *self.operations {
            if let Some(o) = op.state.as_mut()
                && o.listener == Some(r)
            {
                o.phase = Phase::Canceled;
                o.close = !o.peer_dead;
                o.listener = None
            }
        }
        if let Some(c) = self.clients[s.client.index].state.as_mut()
            && c.serial == s.client.serial
        {
            c.listener = None
        }
        self.listeners[r.index].state = None;
        Ok(s.port.map(|serial| Port { listener, serial }))
    }
    fn allocate_operation(
        &mut self,
        peer: [u8; 32],
        app: [u8; 64],
        deadline: u64,
        context: Option<&[u8]>,
    ) -> Result<Reference, Error> {
        if let Some(c) = context {
            gnunet_wire::official::Frame::decode(c)?;
            if c.len() > gnunet_wire::official::seti::CONTEXT_MAX
                || c.len()
                    .checked_add(72)
                    .is_none_or(|n| n > gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE)
            {
                return Err(Error::TooLarge);
            }
        }
        let len = context.map_or(0, <[u8]>::len);
        let i = self
            .operations
            .iter()
            .position(|s| s.state.is_none() && s.context.len() >= len)
            .ok_or(Error::Capacity)?;
        let serial = self.serial()?;
        let slot = &mut self.operations[i];
        slot.members.fill(0);
        slot.active.fill(0);
        slot.reported.fill(0);
        if let Some(c) = context {
            slot.context[..len].copy_from_slice(c)
        }
        let mut state = OperationState::empty(serial, peer, app, deadline);
        state.context = len;
        slot.state = Some(state);
        Ok(Reference { index: i, serial })
    }
    fn snapshot(
        &mut self,
        op: Reference,
        set: Reference,
        request_id: u32,
        mode: ResultMode,
    ) -> Result<(), Error> {
        let s = self.sets[set.index].state.ok_or(Error::StaleGeneration)?;
        if s.serial != set.serial {
            return Err(Error::StaleGeneration);
        }
        for e in &*self.elements {
            if let Some(e) = e.state
                && e.set == set
                && e.active
            {
                e.references.checked_add(1).ok_or(Error::Overflow)?;
            }
        }
        let slot = &mut self.operations[op.index];
        let mut count = 0;
        let mut sum = [0; 64];
        for (i, e) in self.elements.iter_mut().enumerate() {
            if let Some(e) = e.state.as_mut()
                && e.set == set
                && e.active
            {
                set_bit(slot.members, i, true);
                set_bit(slot.active, i, true);
                e.references += 1;
                count += 1;
                xor(&mut sum, &e.hash)
            }
        }
        let o = slot.state.as_mut().ok_or(Error::StaleGeneration)?;
        o.set = Some(set);
        o.client = Some(s.client);
        o.generation = s.generation;
        o.request_id = request_id;
        o.mode = mode;
        o.count = count;
        o.xor = sum;
        Ok(())
    }
    fn request_available(&self, client: Reference, rid: u32) -> Result<(), Error> {
        if self.operations.iter().any(|s| {
            s.state
                .is_some_and(|o| o.client == Some(client) && o.request_id == rid)
        }) {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    /// Snapshot and request a real outgoing channel. No connection/credit is
    /// fabricated; bind_peer must later observe the actual expected endpoint.
    pub fn evaluate(
        &mut self,
        set: Set<'id>,
        request_id: u32,
        spec: Evaluation<'_>,
    ) -> Result<Operation<'id>, Error> {
        let Evaluation {
            peer,
            app_id: app,
            mode,
            context,
            deadline,
        } = spec;
        let r = self.set_ref(set)?;
        let c = self.sets[r.index]
            .state
            .ok_or(Error::StaleGeneration)?
            .client;
        self.request_available(c, request_id)?;
        let op = self.allocate_operation(peer, app, deadline, context)?;
        if let Err(e) = self.snapshot(op, r, request_id, mode) {
            self.operations[op.index].state = None;
            return Err(e);
        }
        Ok(self.op(op))
    }
    /// Actual outgoing-open metadata for the caller's explicit CADET port.
    pub fn operation_info(&self, operation: Operation<'id>) -> Result<OperationInfo, Error> {
        let r = self.op_ref(operation)?;
        let o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        Ok(OperationInfo {
            phase: o.phase,
            request_id: o.request_id,
            current_size: o.count,
            remote_size: o.remote,
            peer: o.peer,
            deadline: o.deadline,
            failure: o.failure,
        })
    }
    /// Application port required by this original outgoing operation.
    pub fn operation_app(&self, operation: Operation<'id>) -> Result<[u8; 64], Error> {
        let r = self.op_ref(operation)?;
        Ok(self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?
            .app)
    }
    /// Actual connected-channel boundary. The caller must obtain actual_peer
    /// from authenticated end-to-end CADET ownership, never a raw channel id.
    pub fn bind_peer(
        &mut self,
        operation: Operation<'id>,
        actual_peer: [u8; 32],
    ) -> Result<PeerSource<'id>, Error> {
        let r = self.op_ref(operation)?;
        let o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if o.peer != actual_peer {
            return Err(Error::Authentication);
        }
        if o.phase != Phase::Opening || o.source.is_some() {
            return Err(Error::Conflict);
        }
        let serial = self.serial()?;
        let s = self.operations[r.index]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        s.source = Some(serial);
        s.peer_dead = false;
        s.next = NextPeer::Request;
        let state = *s;
        self.source(r, state)
    }
    /// Actual inbound channel on the original live port. The initial request has
    /// a finite caller-clock deadline; no automatic thread/timer is started.
    pub fn incoming(
        &mut self,
        port: Port<'id>,
        actual_peer: [u8; 32],
        now: u64,
    ) -> Result<PeerSource<'id>, Error> {
        let l = self.listener_ref(port.listener)?;
        let listener = self.listeners[l.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if listener.port != Some(port.serial) {
            return Err(Error::StaleGeneration);
        }
        let deadline = now
            .checked_add(self.limits.incoming_micros)
            .ok_or(Error::Overflow)?;
        self.domain
            .next
            .get()
            .checked_add(2)
            .ok_or(Error::Overflow)?;
        let op = self.allocate_operation(actual_peer, listener.app, deadline, None)?;
        let serial = self.serial()?;
        let o = self.operations[op.index]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        o.phase = Phase::AwaitRequest;
        o.listener = Some(l);
        o.source = Some(serial);
        o.peer_dead = false;
        let state = *o;
        self.source(op, state)
    }
    /// Accept a still-current suggested operation using an immutable set snapshot.
    pub fn accept(
        &mut self,
        set: Set<'id>,
        operation: Operation<'id>,
        request_id: u32,
        mode: ResultMode,
        deadline: u64,
    ) -> Result<(), Error> {
        let r = self.set_ref(set)?;
        let c = self.sets[r.index]
            .state
            .ok_or(Error::StaleGeneration)?
            .client;
        self.request_available(c, request_id)?;
        let op = self.op_ref(operation)?;
        let old = self.operations[op.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if old.phase != Phase::AwaitAccept || !old.suggestion_sent {
            return Err(Error::NotReady);
        }
        self.snapshot(op, r, request_id, mode)?;
        let slot = &mut self.operations[op.index];
        let o = slot.state.as_mut().ok_or(Error::StaleGeneration)?;
        o.listener = None;
        o.deadline = deadline;
        o.phase = Phase::CountSent;
        if o.remote == 0 {
            // The original request already proves the intersection is empty.
            // Keep members for FULL/REMOVED result provenance, but reduce only
            // this operation's active view. Send a real empty BF first: the
            // ordinary C initiator rejects ELEMENT_INFO when its own count is0.
            // DONE still requires the actual peer agreement/close phase.
            slot.active.fill(0);
            o.count = 0;
            o.xor = [0; 64];
            o.phase = Phase::Bloom;
            o.build = true
        } else if o.count > o.remote {
            o.next = NextPeer::Count
        } else {
            o.phase = Phase::Bloom;
            o.build = true
        }
        if let Some(i) = o.input.as_mut() {
            i.ready = true
        }
        Ok(())
    }
    /// Correlation-only official incoming id lookup; kernel IPC authorization is
    /// separate. Native ACCEPT legitimately arrives on a different set MQ.
    pub fn suggested(&self, accept_id: u32) -> Option<Operation<'id>> {
        self.operations.iter().enumerate().find_map(|(index, s)| {
            s.state
                .filter(|o| o.phase == Phase::AwaitAccept && o.accept_id == accept_id)
                .map(|o| {
                    self.op(Reference {
                        index,
                        serial: o.serial,
                    })
                })
        })
    }
    /// Explicit incoming refusal; actual channel close remains a caller effect.
    pub fn reject(&mut self, operation: Operation<'id>) -> Result<(), Error> {
        let r = self.op_ref(operation)?;
        let o = self.operations[r.index]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if !matches!(o.phase, Phase::AwaitRequest | Phase::AwaitAccept) {
            return Err(Error::Conflict);
        }
        o.phase = Phase::Canceled;
        o.close = !o.peer_dead;
        Ok(())
    }
    /// Explicit operation cancel. Already frozen output keeps its original effect
    /// until actual write/physical retirement; no result is replayed or invented.
    pub fn cancel(&mut self, operation: Operation<'id>) -> Result<(), Error> {
        let r = self.op_ref(operation)?;
        let o = self.operations[r.index]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        o.phase = Phase::Canceled;
        o.close = !o.peer_dead;
        o.next = NextPeer::None;
        o.build = false;
        Ok(())
    }
    /// Actual open failure, without inventing a connected source or success.
    pub fn open_failed(&mut self, operation: Operation<'id>, reason: Error) -> Result<(), Error> {
        let r = self.op_ref(operation)?;
        let o = self.operations[r.index]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if o.source.is_some() {
            return Err(Error::Conflict);
        }
        o.phase = Phase::Failed;
        o.failure = Some(reason);
        o.peer_dead = true;
        Ok(())
    }
    /// Actual external-port/resource failure, without inventing a peer close.
    /// Original immutable outputs still settle or retire through physical loss.
    pub fn external_failure(
        &mut self,
        operation: Operation<'id>,
        reason: Error,
    ) -> Result<(), Error> {
        let r = self.op_ref(operation)?;
        self.fail(r.index, reason);
        Ok(())
    }
    /// Original operation generation and source decide every semantic credit.
    pub fn receive_ready(&self, operation: Operation<'id>) -> Result<Option<Delivery<'id>>, Error> {
        let r = self.op_ref(operation)?;
        let o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        o.input
            .filter(|i| i.ready)
            .map(|i| {
                self.source(r, o).map(|source| Delivery {
                    source,
                    serial: i.serial,
                })
            })
            .transpose()
    }
    /// Caller consumed the exact original message and may now grant CADET credit.
    /// This is not evidence that a local ACK or peer application data was written.
    pub fn receive_done(&mut self, delivery: Delivery<'id>) -> Result<(), Error> {
        let r = self.source_ref(delivery.source)?;
        let o = self.operations[r.index]
            .state
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if !o
            .input
            .is_some_and(|i| i.serial == delivery.serial && i.ready)
        {
            return Err(Error::StaleGeneration);
        }
        o.input = None;
        Ok(())
    }
    /// Original channels requiring actual close, never a synthetic close receipt.
    pub fn close_required(&self) -> Option<PeerSource<'id>> {
        self.operations.iter().enumerate().find_map(|(index, s)| {
            s.state.filter(|s| s.close && !s.peer_dead).and_then(|s| {
                self.source(
                    Reference {
                        index,
                        serial: s.serial,
                    },
                    s,
                )
                .ok()
            })
        })
    }
    /// Bounded caller-clock expiration. Original deadlines are never extended by
    /// data writes or a late response. Actual sources still require close/drain.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut count = 0;
        for slot in &mut *self.operations {
            if let Some(o) = slot.state.as_mut()
                && o.deadline != u64::MAX
                && now >= o.deadline
                && !matches!(o.phase, Phase::Failed | Phase::Canceled | Phase::Finished)
            {
                o.phase = Phase::Failed;
                o.failure = Some(Error::Deadline);
                o.close = !o.peer_dead;
                o.next = NextPeer::None;
                o.build = false;
                count += 1
            }
        }
        count
    }
    /// Retire only after original peer close and immutable outputs have actually
    /// settled. Releasing snapshots may then recycle inactive element slabs.
    pub fn retire(&mut self, operation: Operation<'id>) -> Result<(), Error> {
        let r = self.op_ref(operation)?;
        let o = self.operations[r.index]
            .state
            .ok_or(Error::StaleGeneration)?;
        if !o.peer_dead
            || o.pending_peer.is_some()
            || o.pending_client.is_some()
            || !matches!(o.phase, Phase::Canceled | Phase::Failed | Phase::Finished)
            || ((o.phase != Phase::Canceled) && o.client.is_some() && !o.terminal)
        {
            return Err(Error::WouldBlock);
        }
        for (i, e) in self.elements.iter_mut().enumerate() {
            if bit(self.operations[r.index].members, i) {
                let s = e.state.as_mut().ok_or(Error::StaleGeneration)?;
                s.references = s.references.checked_sub(1).ok_or(Error::StaleGeneration)?;
                if !s.active && s.references == 0 {
                    e.state = None
                }
            }
        }
        self.operations[r.index].state = None;
        Ok(())
    }
}
/// Actual logical acceptance of one official IPC request; native effects remain
/// explicit (listener binding, channel open, immutable outputs and close/drain).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dispatch<'id> {
    /// No response/ACK exists for this command.
    None,
    /// Logical set created for the original accepted MQ.
    Created(Set<'id>),
    /// Logical registration needs an actual CADET port.
    Listening(Listener<'id>),
    /// Original operation now owns native/open/result work.
    Operation(Operation<'id>),
}
/// Complete outgoing application specification; internal ownership is separate
/// from actual CADET connection establishment and its original callbacks.
#[derive(Clone, Copy, Debug)]
pub struct Evaluation<'a> {
    /// Expected authenticated end-to-end peer.
    pub peer: [u8; 32],
    /// Actual CADET port id.
    pub app_id: [u8; 64],
    /// Local result policy.
    pub mode: ResultMode,
    /// Optional complete original application context.
    pub context: Option<&'a [u8]>,
    /// Original caller-clock deadline, or forever.
    pub deadline: u64,
}
impl<'id, 'store, 'bytes> Service<'id, 'store, 'bytes> {
    /// Execute the registered official IPC command against this actual source.
    /// ADD/CREATE have no fictitious acknowledgement; accept ids correlate across
    /// the separate listen and set MQs as in the official public API.
    pub fn dispatch(
        &mut self,
        client: Client<'id>,
        request: Request<'_>,
        deadline: u64,
    ) -> Result<Dispatch<'id>, Error> {
        let c = self.client_ref(client)?;
        request.encoded_len()?;
        Ok(match request {
            Request::Create => Dispatch::Created(self.create(client)?),
            Request::Add {
                element_type,
                reserved: _,
                data,
            } => {
                let set = self.set(client)?.ok_or(Error::InvalidInput)?;
                self.add(set, Element { element_type, data })?;
                Dispatch::None
            }
            Request::Listen {
                operation: _,
                app_id,
            } => Dispatch::Listening(self.listen(client, app_id)?),
            Request::Evaluate {
                request_id,
                peer,
                app_id,
                return_intersection,
                context,
            } => {
                let set = self.set(client)?.ok_or(Error::InvalidInput)?;
                Dispatch::Operation(self.evaluate(
                    set,
                    request_id,
                    Evaluation {
                        peer,
                        app_id,
                        mode: ResultMode::from_raw(return_intersection),
                        context,
                        deadline,
                    },
                )?)
            }
            Request::Accept {
                accept_id,
                request_id,
                return_intersection,
            } => {
                let set = self.set(client)?.ok_or(Error::InvalidInput)?;
                if let Some(op) = self.suggested(accept_id) {
                    self.accept(
                        set,
                        op,
                        request_id,
                        ResultMode::from_raw(return_intersection),
                        deadline,
                    )?;
                    Dispatch::Operation(op)
                } else {
                    self.request_available(c, request_id)?;
                    let r = self.allocate_operation([0; 32], [0; 64], u64::MAX, None)?;
                    let o = self.operations[r.index]
                        .state
                        .as_mut()
                        .ok_or(Error::StaleGeneration)?;
                    o.client = Some(c);
                    o.request_id = request_id;
                    o.phase = Phase::Failed;
                    o.failure = Some(Error::StaleGeneration);
                    Dispatch::Operation(self.op(r))
                }
            }
            Request::Reject { accept_id } => {
                if let Some(op) = self.suggested(accept_id) {
                    let r = self.op_ref(op)?;
                    let listener = self.operations[r.index]
                        .state
                        .and_then(|o| o.listener)
                        .ok_or(Error::StaleGeneration)?;
                    if self
                        .listeners
                        .get(listener.index)
                        .and_then(|l| l.state)
                        .is_none_or(|l| l.serial != listener.serial || l.client != c)
                    {
                        return Err(Error::Authentication);
                    }
                    self.reject(op)?;
                    Dispatch::Operation(op)
                } else {
                    Dispatch::None
                }
            }
            Request::Cancel { request_id } => {
                let found = self.operations.iter().enumerate().find_map(|(index, s)| {
                    s.state
                        .filter(|o| o.client == Some(c) && o.request_id == request_id)
                        .map(|o| Reference {
                            index,
                            serial: o.serial,
                        })
                });
                if let Some(r) = found {
                    let op = self.op(r);
                    self.cancel(op)?;
                    Dispatch::Operation(op)
                } else {
                    Dispatch::None
                }
            }
        })
    }
    /// Actual retained operation handles, including terminal metadata still
    /// awaiting original port retirement. An index alone never creates a handle.
    pub fn retained_operations(&self) -> impl Iterator<Item = Operation<'id>> + '_ {
        self.operations.iter().enumerate().filter_map(|(index, s)| {
            s.state.map(|o| {
                self.op(Reference {
                    index,
                    serial: o.serial,
                })
            })
        })
    }
    /// Fairly advance one operation needing actual Bloom construction. Entropy
    /// remains explicit and only bounded CPU work occurs; no network is created.
    pub fn progress_next(
        &mut self,
        entropy: &mut impl gnunet_crypto::Entropy,
    ) -> Result<Option<Operation<'id>>, Error> {
        for n in 0..self.operations.len() {
            let index = (self.operation_cursor + n) % self.operations.len();
            let Some(o) = self.operations[index].state else {
                continue;
            };
            if o.build {
                let op = self.op(Reference {
                    index,
                    serial: o.serial,
                });
                self.operation_cursor = (index + 1) % self.operations.len();
                if self.progress(op, entropy)? {
                    return Ok(Some(op));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests;
