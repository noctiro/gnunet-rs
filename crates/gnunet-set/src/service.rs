//! Bounded original-client and actual-peer ownership. No IO is performed here.
use crate::effect::Ordering;
use crate::{
    allocation::Growth,
    content::BodyLedger,
    engine::{Output, Role},
    intersection::Intersection,
    union::Union,
    wire::{Abi, ClientRequest, ClientResponse, Element, PeerMessage},
    *,
};
use alloc::{rc::Rc, vec::Vec};
struct Listener {
    operation: OperationType,
    app: [u8; 64],
    opened: bool,
    close: bool,
    closed: bool,
}
struct Iteration {
    snapshot: Snapshot,
    at: usize,
    awaiting: bool,
    due: bool,
}
struct ClientRow<'id> {
    id: Client<'id>,
    live: bool,
    content: Option<(OperationType, Content)>,
    listener: Option<Listener>,
    iteration: Option<Iteration>,
    iteration_id: u16,
    iteration_effect: Option<EffectId<'id>>,
    failure: Option<Error>,
    close_queued: bool,
}
struct Offer<'id> {
    id: Incoming<'id>,
    listener: Client<'id>,
    accept: u32,
    count: u32,
    expires: u64,
    adopting: Option<Operation<'id>>,
    closing: bool,
    close: bool,
    gone: bool,
}
struct CopyRow<'id> {
    cookie: [u8; 4],
    source: Client<'id>,
}
enum Engine {
    Union(Union),
    Intersection(Intersection),
}
impl Engine {
    fn out(&self) -> &Output {
        match self {
            Self::Union(e) => &e.out,
            Self::Intersection(e) => &e.out,
        }
    }
    fn out_mut(&mut self) -> &mut Output {
        match self {
            Self::Union(e) => &mut e.out,
            Self::Intersection(e) => &mut e.out,
        }
    }
    fn activate(&mut self) {
        match self {
            Self::Union(e) => e.activate(),
            Self::Intersection(e) => e.activate(),
        }
    }
    fn progress(&mut self, p: &mut impl Ports, additional: usize) -> Result<bool, Error> {
        match self {
            Self::Union(e) => e.progress_bounded(p, additional),
            Self::Intersection(e) => e.progress(p),
        }
    }
    fn receive(
        &mut self,
        m: PeerMessage<'_>,
        p: &mut impl Ports,
        additional: usize,
    ) -> Result<(), Error> {
        match self {
            Self::Union(e) => e.receive_bounded(m, p, additional),
            Self::Intersection(e) => e.receive(m, p),
        }
    }
    fn fail(&mut self, e: Error) {
        match self {
            Self::Union(x) => x.fail(e),
            Self::Intersection(x) => x.fail(e),
        }
    }
    fn outcome(&self) -> Option<Result<(), Error>> {
        match self {
            Self::Union(e) => e.outcome(),
            Self::Intersection(e) => e.outcome(),
        }
    }
    fn wants_close(&self) -> bool {
        match self {
            Self::Union(e) => e.wants_close(),
            Self::Intersection(e) => e.wants_close(),
        }
    }
    fn can_finish_locally(&self) -> bool {
        match self {
            Self::Union(e) => e.can_finish_locally(),
            Self::Intersection(_) => false,
        }
    }
    fn retired(&mut self, e: Error) {
        match self {
            Self::Union(x) => x.peer_retired(e),
            Self::Intersection(x) => x.peer_retired(e),
        }
    }
    fn charge(&self) -> Result<usize, Error> {
        match self {
            Self::Union(e) => e.charged_bytes(),
            Self::Intersection(e) => e.charged_bytes(),
        }
    }
    fn size(&self) -> u64 {
        match self {
            Self::Union(e) => e.size(),
            Self::Intersection(e) => e.size(),
        }
    }
}
struct Op<'id> {
    id: Operation<'id>,
    client: Client<'id>,
    rid: u32,
    kind: OperationType,
    engine: Engine,
    reservation: usize,
    expires: u64,
    role: Role,
    context: Vec<u8>,
    app: [u8; 64],
    channel: PeerOwner<'id>,
    original_count: u32,
    opened: bool,
    initial: Option<EffectId<'id>>,
    initial_queued: bool,
    active: bool,
    cancelled: bool,
    closing: bool,
    close_queued: bool,
    gone: bool,
    final_id: Option<EffectId<'id>>,
    final_queued: bool,
    final_done: bool,
}
struct OperationPlan<'a> {
    rid: u32,
    mode: u32,
    options: wire::Options,
    role: Role,
    remote_count: u32,
    origin: u64,
    context: &'a [u8],
    app: [u8; 64],
}
/// One lifetime-branded service. Resource limits are admission bounds; per-operation
/// Intersection future storage is reserved; Union charges actual owners and
/// preclaims each bounded allocating turn against the shared retained budget.
pub struct Service<'id> {
    instance: &'id Instance,
    limits: Limits,
    abi: Abi,
    bodies: Rc<BodyLedger>,
    now: u64,
    serial: u64,
    accept: u32,
    cookie: u32,
    clients: Vec<ClientRow<'id>>,
    offers: Vec<Offer<'id>>,
    ops: Vec<Op<'id>>,
    copies: Vec<CopyRow<'id>>,
    effects: Vec<Effect<'id>>,
    effect_bytes: usize,
    internal_failure: Option<Error>,
    closing: bool,
    op_cursor: usize,
    client_cursor: usize,
}
impl<'id> Service<'id> {
    /// Establish one original service domain; does not launch a worker or open IO.
    pub fn new(
        instance: &'id mut Instance,
        limits: Limits,
        abi: Abi,
        now: u64,
    ) -> Result<Self, Error> {
        limits.validate()?;
        abi.validate()?;
        Ok(Self {
            instance,
            limits,
            abi,
            bodies: BodyLedger::new(),
            now,
            serial: 0,
            accept: 0,
            cookie: 0,
            clients: Vec::new(),
            offers: Vec::new(),
            ops: Vec::new(),
            copies: Vec::new(),
            effects: Vec::new(),
            effect_bytes: 0,
            internal_failure: None,
            closing: false,
            op_cursor: 0,
            client_cursor: 0,
        })
    }
    /// Explicit ABI selected for both peer and local native legacy fields.
    #[must_use]
    pub const fn abi(&self) -> Abi {
        self.abi
    }
    /// First internal accounting failure, independent of original operation
    /// outcomes. The driver observes it through progress and physically closes
    /// its sources; no original native terminal receipt is discarded here.
    #[must_use]
    pub const fn internal_failure(&self) -> Option<Error> {
        self.internal_failure
    }
    fn serial(&mut self) -> Result<u64, Error> {
        let n = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.serial = n;
        Ok(n)
    }
    fn ci(&self, id: Client<'id>) -> Result<usize, Error> {
        if !id.belongs(self.instance) {
            return Err(Error::Stale);
        }
        self.clients
            .iter()
            .position(|r| r.id == id)
            .ok_or(Error::Stale)
    }
    fn oi(&self, id: Operation<'id>) -> Result<usize, Error> {
        if !id.belongs(self.instance) {
            return Err(Error::Stale);
        }
        self.ops.iter().position(|r| r.id == id).ok_or(Error::Stale)
    }
    fn ii(&self, id: Incoming<'id>) -> Result<usize, Error> {
        if !id.belongs(self.instance) {
            return Err(Error::Stale);
        }
        self.offers
            .iter()
            .position(|r| r.id == id)
            .ok_or(Error::Stale)
    }
    fn expiry(&self, origin: u64) -> Result<u64, Error> {
        let expiry = origin
            .checked_add(self.limits.operation_lifetime)
            .ok_or(Error::Overflow)?;
        if expiry <= self.now {
            return Err(Error::Deadline);
        }
        Ok(expiry)
    }
    fn retained(&self) -> Result<usize, Error> {
        let mut n = self
            .effect_bytes
            .checked_add(self.bodies.charged_bytes()?)
            .ok_or(Error::Overflow)?;
        macro_rules! meta {
            ($v:expr,$t:ty) => {
                n = n
                    .checked_add(
                        $v.capacity()
                            .checked_mul(core::mem::size_of::<$t>())
                            .ok_or(Error::Overflow)?,
                    )
                    .ok_or(Error::Overflow)?;
            };
        }
        meta!(self.clients, ClientRow<'id>);
        meta!(self.offers, Offer<'id>);
        meta!(self.ops, Op<'id>);
        meta!(self.copies, CopyRow<'id>);
        meta!(self.effects, Effect<'id>);
        for c in &self.clients {
            if let Some((_, b)) = &c.content {
                n = n.checked_add(b.metadata_bytes()?).ok_or(Error::Overflow)?;
            }
            if let Some(it) = &c.iteration {
                n = n
                    .checked_add(it.snapshot.metadata_bytes()?)
                    .ok_or(Error::Overflow)?;
            }
        }
        for o in &self.ops {
            n = n
                .checked_add(match &o.engine {
                    Engine::Union(_) => o.engine.charge()?,
                    Engine::Intersection(_) => o.reservation,
                })
                .and_then(|n| n.checked_add(o.context.capacity()))
                .ok_or(Error::Overflow)?;
        }
        Ok(n)
    }
    fn extra(&self, bytes: usize) -> Result<(), Error> {
        if self.retained()?.checked_add(bytes).ok_or(Error::Overflow)? > self.limits.retained_bytes
        {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    fn remaining(&self) -> Result<usize, Error> {
        self.limits
            .retained_bytes
            .checked_sub(self.retained()?)
            .ok_or(Error::Capacity)
    }
    fn effect_room(&mut self, count: usize, bytes: usize) -> Result<(), Error> {
        self.effect_room_with_external(count, bytes, bytes)
    }
    // A transferred engine Vec already contributes to the actual Union charge.
    // Only metadata grows while it remains there; queue() accounts its same
    // payload again only after transfer removed it from the engine owner.
    fn effect_room_transfer(&mut self, count: usize, bytes: usize) -> Result<(), Error> {
        self.effect_room_with_external(count, bytes, 0)
    }
    fn effect_room_with_external(
        &mut self,
        count: usize,
        bytes: usize,
        external: usize,
    ) -> Result<(), Error> {
        if self
            .effects
            .len()
            .checked_add(count)
            .ok_or(Error::Overflow)?
            > self.limits.effects
            || self
                .effect_bytes
                .checked_add(bytes)
                .ok_or(Error::Overflow)?
                > self.limits.effect_bytes
        {
            return Err(Error::WouldBlock);
        }
        self.serial
            .checked_add(count as u64)
            .ok_or(Error::Overflow)?;
        let mut growth = Growth::new(self.remaining()?);
        // External immutable bytes are already alive outside Service. Cover
        // them before a replacement effect vector temporarily coexists.
        growth.claim(external)?;
        growth.grow_vec(&mut self.effects, count)?;
        self.extra(external)
    }
    fn queue(&mut self, action: Action<'id>) -> Result<EffectId<'id>, Error> {
        let ordering = self.ordering(&action)?;
        self.effect_room(1, action.bytes())?;
        let id = EffectId::new(self.instance, self.serial()?);
        self.effect_bytes = self
            .effect_bytes
            .checked_add(action.bytes())
            .ok_or(Error::Overflow)?;
        self.effects.push(Effect {
            id,
            action,
            admitted: false,
            ordering,
        });
        Ok(id)
    }
    fn frame(&self, response: ClientResponse<'_>) -> Result<Vec<u8>, Error> {
        let n = response.encoded_len(self.abi)?;
        let mut b = Growth::new(self.remaining()?).vector(n)?;
        b.resize(n, 0);
        response.encode(&mut b, self.abi)?;
        Ok(b)
    }
    fn result(
        &self,
        rid: u32,
        status: Status,
        size: u64,
        body: Option<&crate::content::Body>,
    ) -> Result<Vec<u8>, Error> {
        self.frame(ClientResponse::Result {
            current_size: size,
            request_id: rid,
            status: status as u16,
            element: body.map_or(
                Element {
                    element_type: 0,
                    data: &[],
                },
                |b| b.element(),
            ),
        })
    }
    /// Admit one actual original local client, initially unregistered.
    pub fn attach_client(&mut self) -> Result<Client<'id>, Error> {
        if self.closing {
            return Err(Error::Closed);
        }
        if self.clients.len() >= self.limits.clients {
            return Err(Error::Capacity);
        }
        Growth::new(self.remaining()?).grow_vec(&mut self.clients, 1)?;
        let id = Client::new(self.instance, self.serial()?);
        self.clients.push(ClientRow {
            id,
            live: true,
            content: None,
            listener: None,
            iteration: None,
            iteration_id: 0,
            iteration_effect: None,
            failure: None,
            close_queued: false,
        });
        Ok(id)
    }
    fn content(&self, c: usize) -> Result<(OperationType, &Content), Error> {
        self.clients[c]
            .content
            .as_ref()
            .map(|(t, b)| (*t, b))
            .ok_or(Error::InvalidInput)
    }
    fn reservation(&self, t: OperationType, snapshot: &Snapshot) -> Result<usize, Error> {
        let snap = snapshot.metadata_bytes()?;
        let algorithm = match t {
            OperationType::Union => self
                .limits
                .ibf_buckets
                .checked_mul(core::mem::size_of::<crate::ibf::Cell>())
                .and_then(|n| n.checked_mul(2))
                .and_then(|n| n.checked_add(self.limits.union_bytes))
                .and_then(|n| {
                    self.limits
                        .union_elements
                        .checked_mul(160)
                        .and_then(|m| n.checked_add(m))
                })
                .and_then(|n| n.checked_add(256 * 1024))
                .ok_or(Error::Overflow)?,
            OperationType::Intersection => self
                .limits
                .bloom_bytes
                .checked_mul(2)
                .and_then(|n| snapshot.len().checked_mul(8).and_then(|m| n.checked_add(m)))
                .ok_or(Error::Overflow)?,
            OperationType::Local => return Err(Error::InvalidInput),
        };
        snap.checked_add(algorithm)
            .and_then(|n| n.checked_add(self.limits.output_bytes))
            .and_then(|n| {
                self.limits
                    .output_frames
                    .checked_mul(256)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(65536))
            .ok_or(Error::Overflow)
    }
    fn prepare_op(&mut self, c: usize, plan: OperationPlan<'_>) -> Result<Op<'id>, Error> {
        let OperationPlan {
            rid,
            mode,
            options,
            role,
            remote_count,
            origin,
            context,
            app,
        } = plan;
        if self.ops.len() >= self.limits.operations
            || self
                .ops
                .iter()
                .any(|o| o.client == self.clients[c].id && o.rid == rid)
        {
            return Err(Error::Conflict);
        }
        if context.len() > self.limits.context_bytes {
            return Err(Error::TooLarge);
        }
        let (kind, content) = self.content(c)?;
        let mode = ResultMode::try_from(mode)?;
        mode.validate(kind)?;
        let original_count = u32::try_from(content.len()).map_err(|_| Error::TooLarge)?;
        // Original bodies are already held by this service's ledger. Only the
        // new Rc membership allocation is claimed by this immutable view.
        let snapshot_bound = content.metadata_bytes()?;
        let expires = self.expiry(origin)?;
        let mut growth = Growth::new(self.remaining()?);
        growth.grow_vec(&mut self.ops, 1)?;
        let ctx = growth.copy(context)?;
        growth.claim(snapshot_bound)?;
        let snapshot = self.content(c)?.1.snapshot()?;
        if snapshot.metadata_bytes()? > snapshot_bound {
            return Err(Error::Capacity);
        }
        if !Rc::ptr_eq(&snapshot.ledger, &self.bodies) {
            return Err(Error::Stale);
        }
        let allowance = self
            .remaining()?
            .checked_sub(ctx.capacity())
            .ok_or(Error::Capacity)?;
        let (engine, reservation) = match kind {
            OperationType::Union => {
                let engine = Engine::Union(Union::new_bounded(
                    snapshot,
                    role,
                    mode,
                    options,
                    self.limits,
                    allowance,
                )?);
                let actual = engine.charge()?;
                (engine, actual)
            }
            OperationType::Intersection => {
                // Intersection retains its established whole-future reserve;
                // this change does not weaken its allocation authority.
                let reservation = self.reservation(kind, &snapshot)?;
                self.extra(
                    reservation
                        .checked_add(ctx.capacity())
                        .ok_or(Error::Overflow)?,
                )?;
                let engine = Engine::Intersection(Intersection::new(
                    snapshot,
                    role,
                    remote_count,
                    mode,
                    options,
                    self.limits,
                )?);
                if engine.charge()? > reservation {
                    return Err(Error::Capacity);
                }
                (engine, reservation)
            }
            OperationType::Local => return Err(Error::InvalidInput),
        };
        self.extra(
            reservation
                .checked_add(ctx.capacity())
                .ok_or(Error::Overflow)?,
        )?;
        let id = Operation::new(self.instance, self.serial()?);
        Ok(Op {
            id,
            client: self.clients[c].id,
            rid,
            kind,
            engine,
            reservation,
            expires,
            role,
            context: ctx,
            app,
            channel: PeerOwner::Operation(id),
            original_count,
            opened: false,
            initial: None,
            initial_queued: false,
            active: false,
            cancelled: false,
            closing: false,
            close_queued: false,
            gone: false,
            final_id: None,
            final_queued: false,
            final_done: false,
        })
    }
    /// Process an official local request at its original frame-origin time. A
    /// retained pressure retry never renews the intent deadline.
    pub fn client_request(
        &mut self,
        client: Client<'id>,
        request: ClientRequest<'_>,
        origin: u64,
        _ports: &mut impl Ports,
    ) -> Result<(), Error> {
        self.now = self.now.max(origin);
        let c = self.ci(client)?;
        if !self.clients[c].live || self.closing {
            return Err(Error::Closed);
        }
        match request {
            ClientRequest::Create { operation } => {
                if self.clients[c].content.is_some() || self.clients[c].listener.is_some() {
                    return Err(Error::Conflict);
                }
                let kind = OperationType::try_from(operation)?;
                self.clients[c].content = Some((
                    kind,
                    Content::with_ledger(
                        self.limits.content,
                        self.abi,
                        BodyLedger::share(&self.bodies)?,
                    )?,
                ));
                Ok(())
            }
            ClientRequest::Listen { operation, app_id } => {
                if self.clients[c].content.is_some() || self.clients[c].listener.is_some() {
                    return Err(Error::Conflict);
                }
                let kind = OperationType::try_from(operation)?;
                if kind == OperationType::Local {
                    return Err(Error::InvalidInput);
                }
                if self
                    .clients
                    .iter()
                    .any(|r| r.live && r.listener.as_ref().is_some_and(|l| l.app == app_id))
                {
                    return Err(Error::Conflict);
                }
                self.queue(Action::OpenPort {
                    listener: client,
                    operation: kind,
                    app_id,
                })?;
                self.clients[c].listener = Some(Listener {
                    operation: kind,
                    app: app_id,
                    opened: false,
                    close: false,
                    closed: false,
                });
                Ok(())
            }
            ClientRequest::Add { element } | ClientRequest::Remove { element } => {
                let additional = if matches!(request, ClientRequest::Add { .. }) {
                    self.remaining()?
                } else {
                    0
                };
                let content = &mut self.clients[c].content.as_mut().ok_or(Error::Stale)?.1;
                if matches!(request, ClientRequest::Add { .. }) {
                    content.add_with_allowance(element, additional)?;
                } else {
                    content.remove(element)?;
                }
                Ok(())
            }
            ClientRequest::Evaluate {
                result_mode,
                target,
                app_id,
                request_id,
                options,
                context,
            } => {
                // Encoding preflight enforces the actual CADET application cap,
                // which is narrower than the public local nested-context bound.
                PeerMessage::OperationRequest {
                    operation: self.content(c)?.0 as u32,
                    element_count: 0,
                    app_id,
                    context,
                }
                .encoded_len(self.abi)?;
                self.effect_room(1, 0)?;
                let op = self.prepare_op(
                    c,
                    OperationPlan {
                        rid: request_id,
                        mode: result_mode,
                        options,
                        role: Role::Initiator,
                        remote_count: 0,
                        origin,
                        context,
                        app: app_id,
                    },
                )?;
                let id = op.id;
                self.queue(Action::OpenPeer {
                    operation: id,
                    peer: target,
                    app_id,
                })?;
                self.ops.push(op);
                Ok(())
            }
            ClientRequest::Accept {
                accept_id,
                request_id,
                result_mode,
                options,
            } => {
                let i = self
                    .offers
                    .iter()
                    .position(|i| {
                        i.accept == accept_id && i.adopting.is_none() && !i.closing && !i.gone
                    })
                    .ok_or(Error::Stale)?;
                let listener = self.ci(self.offers[i].listener)?;
                if !self.clients[listener].live || self.offers[i].expires <= self.now {
                    return Err(Error::Deadline);
                }
                let offered_kind = self.clients[listener]
                    .listener
                    .as_ref()
                    .ok_or(Error::Stale)?
                    .operation;
                if self.content(c)?.0 != offered_kind {
                    return Err(Error::InvalidInput);
                }
                let count = self.offers[i].count;
                let incoming = self.offers[i].id;
                let app = self.clients[listener]
                    .listener
                    .as_ref()
                    .ok_or(Error::Stale)?
                    .app;
                self.effect_room(1, 0)?;
                let mut op = self.prepare_op(
                    c,
                    OperationPlan {
                        rid: request_id,
                        mode: result_mode,
                        options,
                        role: Role::Acceptor,
                        remote_count: count,
                        origin,
                        context: &[],
                        app,
                    },
                )?;
                let id = op.id;
                op.expires = op.expires.min(self.offers[i].expires);
                op.channel = PeerOwner::Incoming(incoming);
                self.queue(Action::AdoptPeer {
                    incoming,
                    operation: id,
                })?;
                self.offers[i].adopting = Some(id);
                self.ops.push(op);
                Ok(())
            }
            ClientRequest::Reject { accept_id } => {
                let i = self
                    .offers
                    .iter()
                    .position(|i| {
                        i.accept == accept_id
                            && i.listener == client
                            && i.adopting.is_none()
                            && !i.closing
                    })
                    .ok_or(Error::Stale)?;
                self.offers[i].closing = true;
                Ok(())
            }
            ClientRequest::Cancel { request_id } => {
                let i = self
                    .ops
                    .iter()
                    .position(|o| o.client == client && o.rid == request_id)
                    .ok_or(Error::Stale)?;
                self.cancel_op(i, Error::Cancelled);
                Ok(())
            }
            ClientRequest::Iterate => {
                if self.clients[c].iteration.is_some() {
                    return Err(Error::Conflict);
                }
                self.extra(self.content(c)?.1.metadata_bytes()?)?;
                let snapshot = self.content(c)?.1.snapshot()?;
                self.extra(snapshot.metadata_bytes()?)?;
                self.clients[c].iteration = Some(Iteration {
                    snapshot,
                    at: 0,
                    awaiting: false,
                    due: true,
                });
                Ok(())
            }
            ClientRequest::IterAck { send_more } => {
                let it = self.clients[c]
                    .iteration
                    .as_mut()
                    .ok_or(Error::InvalidInput)?;
                if !it.awaiting {
                    return Err(Error::InvalidInput);
                }
                if send_more == 0 {
                    self.clients[c].iteration = None;
                    self.clients[c].iteration_id = self.clients[c].iteration_id.wrapping_add(1);
                } else {
                    it.awaiting = false;
                    it.due = true;
                }
                Ok(())
            }
            ClientRequest::CopyLazyPrepare => {
                self.content(c)?;
                if self.copies.len() >= self.limits.copies {
                    return Err(Error::Capacity);
                }
                let value = self.cookie.checked_add(1).ok_or(Error::Overflow)?;
                let cookie = value.to_be_bytes();
                let bytes = self.frame(ClientResponse::CopyLazy { cookie })?;
                let mut growth = Growth::new(self.remaining()?);
                growth.claim(bytes.capacity())?;
                growth.grow_vec(&mut self.copies, 1)?;
                self.queue(Action::ClientFrame {
                    client,
                    operation: None,
                    bytes,
                })?;
                self.copies.push(CopyRow {
                    cookie,
                    source: client,
                });
                self.cookie = value;
                Ok(())
            }
            ClientRequest::CopyLazyConnect { cookie } => {
                if self.clients[c].content.is_some() || self.clients[c].listener.is_some() {
                    return Err(Error::Conflict);
                }
                let copy = self
                    .copies
                    .iter()
                    .position(|r| r.cookie == cookie)
                    .ok_or(Error::Stale)?;
                let source = self.ci(self.copies[copy].source)?;
                if !self.clients[source].live {
                    return Err(Error::Closed);
                }
                let (kind, content) = self.content(source)?;
                self.extra(content.metadata_bytes()?)?;
                let fork = content.fork()?;
                self.extra(fork.metadata_bytes()?)?;
                self.clients[c].content = Some((kind, fork));
                self.copies.remove(copy);
                Ok(())
            }
        }
    }
    /// Admit a complete original OperationRequest using the actual native port
    /// and peer as authority. Its payload app_id is not a port capability.
    pub fn incoming(
        &mut self,
        listener: Client<'id>,
        peer: [u8; 32],
        port: [u8; 64],
        request: PeerMessage<'_>,
        origin: u64,
        _: &mut impl Ports,
    ) -> Result<Incoming<'id>, Error> {
        self.now = self.now.max(origin);
        let c = self.ci(listener)?;
        if !self.clients[c].live || self.closing {
            return Err(Error::Closed);
        }
        let l = self.clients[c]
            .listener
            .as_ref()
            .ok_or(Error::InvalidInput)?;
        if !l.opened || l.app != port {
            return Err(Error::InvalidInput);
        }
        let PeerMessage::OperationRequest {
            operation,
            element_count,
            context,
            ..
        } = request
        else {
            return Err(Error::Malformed);
        };
        if operation != l.operation as u32 || context.len() > self.limits.context_bytes {
            return Err(Error::Malformed);
        }
        if self.offers.len() >= self.limits.incoming {
            return Err(Error::Capacity);
        }
        let expires = self.expiry(origin)?;
        let accept = self.accept.checked_add(1).ok_or(Error::Overflow)?;
        let bytes = self.frame(ClientResponse::Request {
            accept_id: accept,
            peer,
            context,
        })?;
        let mut growth = Growth::new(self.remaining()?);
        growth.claim(bytes.capacity())?;
        growth.grow_vec(&mut self.offers, 1)?;
        self.queue(Action::ClientFrame {
            client: listener,
            operation: None,
            bytes,
        })?;
        let id = Incoming::new(self.instance, self.serial()?);
        self.accept = accept;
        self.offers.push(Offer {
            id,
            listener,
            accept,
            count: element_count,
            expires,
            adopting: None,
            closing: false,
            close: false,
            gone: false,
        });
        Ok(id)
    }
    /// Accept one complete official frame only for the same current native owner.
    pub fn receive(
        &mut self,
        owner: PeerOwner<'id>,
        bytes: &[u8],
        origin: u64,
        ports: &mut impl Ports,
    ) -> Result<(), Error> {
        self.now = self.now.max(origin);
        let PeerOwner::Operation(id) = owner else {
            return Err(Error::NotReady);
        };
        let i = self.oi(id)?;
        if !self.peer_owner_live(owner) {
            return Err(Error::Closed);
        }
        if !self.ops[i].active {
            return Err(Error::NotReady);
        }
        if self.ops[i].expires <= self.now {
            self.fail_op(i, Error::Deadline);
            return Err(Error::Deadline);
        }
        let additional = self.remaining()?;
        let outcome = PeerMessage::decode(bytes, self.abi)
            .and_then(|m| self.ops[i].engine.receive(m, ports, additional));
        // NotReady can retain an owned original input. Its real charge belongs
        // to this operation just as on success or a terminal error.
        if matches!(self.ops[i].engine, Engine::Union(_)) {
            self.ops[i].reservation = self.ops[i].engine.charge()?;
        }
        if let Err(e) = outcome
            && !matches!(e, Error::WouldBlock | Error::NotReady)
        {
            self.fail_op(i, e);
        }
        outcome
    }
    fn suppress(&mut self, operation: Operation<'id>) {
        let mut i = 0;
        while i < self.effects.len() {
            let remove = !self.effects[i].admitted
                && match &self.effects[i].action {
                    Action::PeerSend {
                        owner: PeerOwner::Operation(op),
                        ..
                    } => *op == operation,
                    Action::ClientFrame {
                        operation: Some(op),
                        ..
                    } => *op == operation,
                    Action::OpenPeer { operation: op, .. } => *op == operation,
                    _ => false,
                };
            if !remove {
                i += 1;
                continue;
            }
            let effect = self.effects.remove(i);
            self.effect_bytes -= effect.action.bytes();
            if let Ok(o) = self.oi(operation) {
                match effect.action {
                    Action::OpenPeer { .. } => self.ops[o].gone = true,
                    Action::PeerSend { .. } => {
                        if self.ops[o].initial == Some(effect.id) {
                            self.ops[o].initial = None;
                        } else {
                            if let Err(error) = self.ops[o].engine.out_mut().settled() {
                                self.internal_failure.get_or_insert(error);
                            }
                        }
                    }
                    Action::ClientFrame { .. } if self.ops[o].final_id == Some(effect.id) => {
                        self.ops[o].final_id = None;
                        self.ops[o].final_queued = false;
                    }
                    _ => {}
                }
            }
        }
    }
    fn fail_op(&mut self, index: usize, reason: Error) {
        let id = self.ops[index].id;
        self.ops[index].engine.fail(reason);
        if let Ok(charge) = self.ops[index].engine.charge() {
            self.ops[index].reservation = match self.ops[index].engine {
                Engine::Union(_) => charge,
                Engine::Intersection(_) => self.ops[index].reservation.min(charge),
            };
        }
        self.ops[index].closing = true;
        self.suppress(id);
    }
    fn cancel_op(&mut self, index: usize, reason: Error) {
        self.ops[index].cancelled = true;
        self.fail_op(index, reason);
    }
    /// Clock-free retirement of the original local source. Accepted operations
    /// belong to their accepting set, independently of a former listener.
    pub fn detach_client(&mut self, id: Client<'id>) -> Result<(), Error> {
        let c = self.ci(id)?;
        self.clients[c].live = false;
        self.clients[c].content = None;
        self.clients[c].iteration = None;
        self.clients[c].iteration_effect = None;
        self.copies.retain(|r| r.source != id);
        for i in 0..self.ops.len() {
            if self.ops[i].client == id {
                self.cancel_op(i, Error::Closed);
            }
        }
        for offer in &mut self.offers {
            if offer.listener == id && offer.adopting.is_none() {
                offer.closing = true;
            }
        }
        // Unadmitted responses have never entered native output. Admitted ones
        // remain original immutable leases for the actual host to settle.
        let mut i = 0;
        while i < self.effects.len() {
            if !self.effects[i].admitted
                && matches!(&self.effects[i].action,Action::ClientFrame{client,..}if *client==id)
            {
                let e = self.effects.remove(i);
                self.effect_bytes -= e.action.bytes();
            } else {
                i += 1;
            }
        }
        Ok(())
    }
    /// Observe actual physical channel retirement, preserving every separately
    /// admitted close/send lease for its later native terminal receipt.
    pub fn peer_lost(&mut self, owner: PeerOwner<'id>, reason: Error) -> Result<(), Error> {
        match owner {
            PeerOwner::Operation(id) => {
                let o = self.oi(id)?;
                if !self.ops[o].gone {
                    self.ops[o].engine.retired(reason);
                    self.ops[o].gone = true;
                    self.ops[o].closing = !self.ops[o].engine.can_finish_locally();
                    if self.ops[o].engine.outcome().is_some_and(|r| r.is_err()) {
                        self.suppress(id);
                    }
                }
                Ok(())
            }
            PeerOwner::Incoming(id) => {
                let i = self.ii(id)?;
                self.offers[i].gone = true;
                self.offers[i].closing = true;
                if let Some(op) = self.offers[i].adopting {
                    let o = self.oi(op)?;
                    if !self.ops[o].gone {
                        self.ops[o].engine.retired(reason);
                        self.ops[o].gone = true;
                        self.ops[o].closing = !self.ops[o].engine.can_finish_locally();
                        if self.ops[o].engine.outcome().is_some_and(|r| r.is_err()) {
                            self.suppress(op);
                        }
                    }
                }
                Ok(())
            }
        }
    }
    fn ordering(&self, action: &Action<'id>) -> Result<Ordering<'id>, Error> {
        let mut order = Ordering::default();
        let channel = match action {
            Action::OpenPeer { operation, .. } => Some(PeerOwner::Operation(*operation)),
            Action::AdoptPeer { incoming, .. } => Some(PeerOwner::Incoming(*incoming)),
            Action::PeerSend { owner, .. } | Action::ClosePeer { owner } => Some(*owner),
            _ => None,
        };
        if let Some(owner) = channel {
            let normalized = match owner {
                PeerOwner::Operation(id) => self.oi(id).map_or(owner, |o| self.ops[o].channel),
                other => other,
            };
            order.channel = Some(normalized);
            if let PeerOwner::Incoming(id) = owner {
                order.incoming_listener = Some(self.offers[self.ii(id)?].listener);
            }
        }
        match action {
            Action::ClientFrame { client, .. } | Action::CloseClient { client, .. } => {
                order.client = Some(*client)
            }
            Action::OpenPort { app_id, .. } => order.port = Some(*app_id),
            Action::ClosePort { listener, app_id } => {
                order.port = Some(*app_id);
                order.close_listener = Some(*listener);
            }
            _ => {}
        }
        Ok(order)
    }
    /// Constant-time convenience for an unadmitted global front. Native fair
    /// drivers use scan_effect; None here says nothing about independent sinks.
    #[must_use]
    pub fn effect(&self) -> Option<&Effect<'id>> {
        self.effects.first().filter(|e| !e.admitted)
    }
    /// Perform at most min(budget,64) candidate/dependency checks, each using only
    /// bounded binary searches over monotonically increasing original serials and
    /// constant-time frozen ordering metadata. Removals and appends never invalidate
    /// a checked predecessor or relabel an original channel. Ready advances the
    /// scan; Pending requires preserving it; End needs an explicit reset. A round
    /// snapshots its upper serial, so continuous producers cannot prevent its end.
    #[must_use]
    pub fn scan_effect<'a>(
        &'a self,
        scan: &mut EffectScan<'id>,
        budget: usize,
    ) -> EffectScanStep<'a, 'id> {
        if scan.end {
            return EffectScanStep::End;
        }
        if scan.fence.is_none() {
            scan.fence = self.effects.last().map(|e| e.id);
            if scan.fence.is_none() {
                scan.end = true;
                return EffectScanStep::End;
            }
        }
        let Some(fence) = scan.fence else {
            return EffectScanStep::End;
        };
        if !fence.belongs(self.instance) {
            scan.end = true;
            return EffectScanStep::End;
        }
        for _ in 0..budget.min(64) {
            if let Some(id) = scan.candidate {
                let Ok(index) = self
                    .effects
                    .binary_search_by_key(&id.value(), |e| e.id.value())
                else {
                    scan.after = Some(id);
                    scan.candidate = None;
                    scan.checked = None;
                    continue;
                };
                let candidate = &self.effects[index];
                if candidate.admitted {
                    scan.after = Some(id);
                    scan.candidate = None;
                    scan.checked = None;
                    continue;
                }
                let first = scan.checked.map_or(0, |old| {
                    self.effects
                        .partition_point(|e| e.id.value() <= old.value())
                });
                if first < index {
                    let predecessor = &self.effects[first];
                    scan.checked = Some(predecessor.id);
                    if predecessor.ordering.precedes(&candidate.ordering) {
                        scan.after = Some(id);
                        scan.candidate = None;
                        scan.checked = None;
                    }
                } else {
                    scan.after = Some(id);
                    scan.candidate = None;
                    scan.checked = None;
                    return EffectScanStep::Ready(candidate);
                }
            } else {
                let index = scan.after.map_or(0, |old| {
                    self.effects
                        .partition_point(|e| e.id.value() <= old.value())
                });
                let Some(candidate) = self
                    .effects
                    .get(index)
                    .filter(|e| e.id.value() <= fence.value())
                else {
                    scan.end = true;
                    return EffectScanStep::End;
                };
                scan.after = Some(candidate.id);
                if !candidate.admitted {
                    scan.candidate = Some(candidate.id);
                    scan.checked = None;
                }
            }
        }
        EffectScanStep::Pending
    }
    /// Transfer ownership of this exact effect to the native caller once.
    pub fn admit_effect(&mut self, id: EffectId<'id>) -> Result<(), Error> {
        if !id.belongs(self.instance) {
            return Err(Error::Stale);
        }
        let index = self
            .effects
            .binary_search_by_key(&id.value(), |e| e.id.value())
            .map_err(|_| Error::Stale)?;
        let e = &mut self.effects[index];
        if e.admitted {
            return Err(Error::Conflict);
        }
        e.admitted = true;
        Ok(())
    }
    /// Inspect only this retained original final FAILURE response and its
    /// engine's first cause. This allocates nothing and does not admit, settle
    /// or extend the effect or operation. A missing diagnostic cannot refuse
    /// the original work's independent terminal disposition.
    #[must_use]
    pub fn failure_for_effect(&self, id: EffectId<'id>) -> Option<OperationFailure> {
        if !id.belongs(self.instance) {
            return None;
        }
        let at = self
            .effects
            .binary_search_by_key(&id.value(), |effect| effect.id.value())
            .ok()?;
        let Action::ClientFrame {
            client,
            operation: Some(operation),
            bytes,
        } = &self.effects[at].action
        else {
            return None;
        };
        let op = &self.ops[self.oi(*operation).ok()?];
        if op.client != *client || op.final_id != Some(id) {
            return None;
        }
        let ClientResponse::Result {
            request_id, status, ..
        } = ClientResponse::decode(bytes, self.abi).ok()?
        else {
            return None;
        };
        if request_id != op.rid || status != Status::Failure as u16 {
            return None;
        }
        let Err(reason) = op.engine.outcome()? else {
            return None;
        };
        Some(OperationFailure {
            effect_serial: id.value(),
            client_serial: client.value(),
            operation_serial: operation.value(),
            request_id: op.rid,
            kind: op.kind,
            reason,
            expires: op.expires,
        })
    }
    /// Settle original work proven not admitted to its native sink.
    pub fn reject_effect(
        &mut self,
        id: EffectId<'id>,
        reason: Error,
    ) -> Result<Terminal<'id>, Error> {
        self.terminal(id, Completion::Unsent(reason), false)
    }
    /// Settle an admitted original native/local action without allocating or
    /// changing any already settled protocol outcome on a redundant close.
    pub fn complete_effect(
        &mut self,
        id: EffectId<'id>,
        completion: Completion,
    ) -> Result<Terminal<'id>, Error> {
        self.terminal(id, completion, true)
    }
    fn terminal(
        &mut self,
        id: EffectId<'id>,
        completion: Completion,
        admitted: bool,
    ) -> Result<Terminal<'id>, Error> {
        if !id.belongs(self.instance) {
            return Err(Error::Stale);
        }
        let index = self
            .effects
            .binary_search_by_key(&id.value(), |e| e.id.value())
            .map_err(|_| Error::Stale)?;
        if self.effects[index].admitted != admitted {
            return Err(Error::Conflict);
        }
        let effect = self.effects.remove(index);
        self.effect_bytes = self
            .effect_bytes
            .checked_sub(effect.action.bytes())
            .ok_or(Error::Stale)?;
        let failure = match completion {
            Completion::Written => None,
            Completion::Unsent(e) | Completion::Lost(e) => Some(e),
        };
        match &effect.action {
            Action::OpenPort { listener, .. } => {
                let c = self.ci(*listener)?;
                let l = self.clients[c].listener.as_mut().ok_or(Error::Stale)?;
                if failure.is_none() {
                    l.opened = true;
                } else {
                    l.closed = true;
                    self.clients[c].live = false;
                    self.clients[c].failure = failure;
                }
            }
            Action::ClosePort { listener, .. } => {
                let c = self.ci(*listener)?;
                self.clients[c]
                    .listener
                    .as_mut()
                    .ok_or(Error::Stale)?
                    .closed = true;
            }
            Action::OpenPeer { operation, .. } => {
                let o = self.oi(*operation)?;
                if let Some(e) = failure {
                    self.ops[o].gone = true;
                    self.fail_op(o, e);
                } else {
                    self.ops[o].opened = true;
                }
            }
            Action::AdoptPeer {
                incoming,
                operation,
            } => {
                let i = self.ii(*incoming)?;
                let o = self.oi(*operation)?;
                if self.offers[i].adopting != Some(*operation) {
                    return Err(Error::Stale);
                }
                if let Some(e) = failure {
                    self.fail_op(o, e);
                    self.offers[i].adopting = None;
                    self.offers[i].closing = true;
                    self.ops[o].gone = true;
                } else {
                    self.offers[i].gone = true;
                    self.ops[o].opened = true;
                    self.ops[o].active = true;
                    if !self.ops[o].closing {
                        self.ops[o].engine.activate();
                    }
                }
            }
            Action::PeerSend { owner, .. } => {
                if let PeerOwner::Operation(operation) = owner {
                    let o = self.oi(*operation)?;
                    if self.ops[o].initial == Some(id) {
                        self.ops[o].initial = None;
                        if failure.is_none() {
                            self.ops[o].active = true;
                            if !self.ops[o].closing {
                                self.ops[o].engine.activate();
                            }
                        }
                    } else {
                        self.ops[o].engine.out_mut().settled()?;
                    }
                    if let Some(e) = failure {
                        self.fail_op(o, e);
                    }
                }
            }
            Action::ClosePeer { owner } => {
                // peer_lost is the physical fact. A later Unsent(Closed) control
                // receipt neither upgrades nor overturns that existing fact.
                match owner {
                    PeerOwner::Operation(operation) => {
                        let o = self.oi(*operation)?;
                        if !self.ops[o].gone
                            && let Some(e) = failure
                        {
                            self.fail_op(o, e);
                        }
                    }
                    PeerOwner::Incoming(incoming) => {
                        let i = self.ii(*incoming)?;
                        if completion == Completion::Written {
                            self.offers[i].gone = true;
                        }
                    }
                }
            }
            Action::ClientFrame {
                client, operation, ..
            } => {
                let c = self.ci(*client)?;
                if self.clients[c].iteration_effect == Some(id) {
                    self.clients[c].iteration_effect = None;
                    if failure.is_none()
                        && let Some(it) = &mut self.clients[c].iteration
                    {
                        it.awaiting = true;
                    }
                }
                if let Some(operation) = operation {
                    let o = self.oi(*operation)?;
                    if self.ops[o].final_id == Some(id) {
                        self.ops[o].final_done = true;
                        self.ops[o].final_id = None;
                    }
                    if let Some(e) = failure {
                        self.cancel_op(o, e);
                    }
                }
                if failure.is_some() {
                    let c = self.ci(*client)?;
                    self.clients[c].live = false;
                }
            }
            Action::CloseClient { client, .. } => {
                let c = self.ci(*client)?;
                self.clients[c].live = false;
            }
        }
        Ok(Terminal {
            effect: crate::CompletedEffect {
                id: effect.id,
                action: effect.action,
            },
            completion,
        })
    }
    fn op_step(&mut self, o: usize, ports: &mut impl Ports) -> Result<bool, Error> {
        let id = self.ops[o].id;
        if !self.ops[o].closing
            && !self.ops[o].gone
            && self.ops[o].opened
            && self.ops[o].role == Role::Initiator
            && !self.ops[o].initial_queued
        {
            let op = &self.ops[o];
            let count = if op.kind == OperationType::Intersection {
                op.original_count
            } else {
                0
            };
            let message = PeerMessage::OperationRequest {
                operation: op.kind as u32,
                element_count: count,
                app_id: op.app,
                context: &op.context,
            };
            let n = message.encoded_len(self.abi)?;
            let mut bytes = Growth::new(self.remaining()?).vector(n)?;
            bytes.resize(n, 0);
            message.encode(&mut bytes, self.abi)?;
            let effect = self.queue(Action::PeerSend {
                owner: PeerOwner::Operation(id),
                bytes,
            })?;
            self.ops[o].initial = Some(effect);
            self.ops[o].initial_queued = true;
            return Ok(true);
        }
        if self.ops[o].engine.out().frames.front().is_some() {
            let bytes = self.ops[o]
                .engine
                .out()
                .frames
                .front()
                .ok_or(Error::Stale)?
                .capacity();
            match self.ops[o].engine {
                Engine::Union(_) => self.effect_room_transfer(1, bytes)?,
                // This engine retains a whole-future reservation even after
                // transfer; preflight its additional effect bytes as before.
                Engine::Intersection(_) => self.effect_room(1, bytes)?,
            }
            let frame = self.ops[o].engine.out_mut().transfer()?;
            self.queue(Action::PeerSend {
                owner: PeerOwner::Operation(id),
                bytes: frame,
            })?;
            return Ok(true);
        }
        if let Some(row) = self.ops[o].engine.out().results.front() {
            if self.ops[o].cancelled {
                self.ops[o].engine.out_mut().results.pop_front();
                return Ok(true);
            }
            let bytes = self.result(self.ops[o].rid, row.status, row.size, row.body.as_deref())?;
            self.queue(Action::ClientFrame {
                client: self.ops[o].client,
                operation: Some(id),
                bytes,
            })?;
            self.ops[o].engine.out_mut().results.pop_front();
            return Ok(true);
        }
        if !self.ops[o].closing && self.ops[o].active {
            let additional = self.remaining()?;
            let result = self.ops[o].engine.progress(ports, additional);
            if matches!(self.ops[o].engine, Engine::Union(_)) {
                self.ops[o].reservation = self.ops[o].engine.charge()?;
            }
            match result {
                Ok(true) => {
                    if self.ops[o].engine.charge()? > self.ops[o].reservation {
                        self.fail_op(o, Error::Capacity);
                    }
                    return Ok(true);
                }
                Ok(false) => {}
                Err(Error::WouldBlock | Error::NotReady) => {}
                Err(e)
                    if matches!(
                        e,
                        Error::Capacity
                            | Error::TooLarge
                            | Error::Malformed
                            | Error::InvalidInput
                            | Error::Overflow
                    ) =>
                {
                    self.fail_op(o, e);
                    return Ok(true);
                }
                Err(e) => return Err(e),
            }
        }
        if self.ops[o].engine.outcome().is_some() && self.ops[o].engine.out().drained() {
            let charge = self.ops[o].engine.charge()?;
            self.ops[o].reservation = match self.ops[o].engine {
                Engine::Union(_) => charge,
                Engine::Intersection(_) => self.ops[o].reservation.min(charge),
            };
        }
        if self.ops[o].engine.wants_close() {
            self.ops[o].closing = true;
        }
        if self.ops[o].closing && !self.ops[o].gone && !self.ops[o].close_queued {
            self.queue(Action::ClosePeer {
                owner: PeerOwner::Operation(id),
            })?;
            self.ops[o].close_queued = true;
            return Ok(true);
        }
        if self.ops[o].gone
            && self.ops[o].engine.out().drained()
            && self.ops[o].engine.out().results.is_empty()
            && !self.ops[o].final_queued
            && !self.ops[o].cancelled
        {
            let outcome = self.ops[o].engine.outcome().ok_or(Error::Stale)?;
            let bytes = self.result(
                self.ops[o].rid,
                if outcome.is_ok() {
                    Status::Done
                } else {
                    Status::Failure
                },
                self.ops[o].engine.size(),
                None,
            )?;
            let effect = self.queue(Action::ClientFrame {
                client: self.ops[o].client,
                operation: Some(id),
                bytes,
            })?;
            self.ops[o].final_id = Some(effect);
            self.ops[o].final_queued = true;
            return Ok(true);
        }
        Ok(false)
    }
    fn client_step(&mut self, c: usize) -> Result<bool, Error> {
        if !self.clients[c].live {
            if self.clients[c].content.is_some() || self.clients[c].iteration.is_some() {
                let id = self.clients[c].id;
                self.detach_client(id)?;
                return Ok(true);
            }
            if let Some(reason) = self.clients[c].failure
                && !self.clients[c].close_queued
            {
                let client = self.clients[c].id;
                self.queue(Action::CloseClient { client, reason })?;
                self.clients[c].close_queued = true;
                return Ok(true);
            }
            if let Some(l) = &self.clients[c].listener
                && !l.close
                && !l.closed
            {
                let app = l.app;
                let id = self.clients[c].id;
                self.queue(Action::ClosePort {
                    listener: id,
                    app_id: app,
                })?;
                self.clients[c].listener.as_mut().ok_or(Error::Stale)?.close = true;
                return Ok(true);
            }
            return Ok(false);
        }
        let Some(it) = &self.clients[c].iteration else {
            return Ok(false);
        };
        if !it.due || it.awaiting {
            return Ok(false);
        }
        let done = it.at == it.snapshot.len();
        let response = if done {
            ClientResponse::IterDone
        } else {
            ClientResponse::IterElement {
                iteration_id: self.clients[c].iteration_id,
                element: it.snapshot.element(it.at).ok_or(Error::Stale)?,
            }
        };
        let bytes = self.frame(response)?;
        let client = self.clients[c].id;
        let effect = self.queue(Action::ClientFrame {
            client,
            operation: None,
            bytes,
        })?;
        if done {
            self.clients[c].iteration = None;
            self.clients[c].iteration_id = self.clients[c].iteration_id.wrapping_add(1);
        } else {
            let it = self.clients[c].iteration.as_mut().ok_or(Error::Stale)?;
            it.at += 1;
            it.awaiting = false;
            it.due = false;
            self.clients[c].iteration_effect = Some(effect);
        }
        Ok(true)
    }
    fn effect_for_op(&self, id: Operation<'id>) -> bool {
        self.effects.iter().any(|e| match &e.action {
            Action::OpenPeer { operation, .. } | Action::AdoptPeer { operation, .. } => {
                *operation == id
            }
            Action::PeerSend {
                owner: PeerOwner::Operation(op),
                ..
            }
            | Action::ClosePeer {
                owner: PeerOwner::Operation(op),
            } => *op == id,
            Action::ClientFrame {
                operation: Some(op),
                ..
            } => *op == id,
            _ => false,
        })
    }
    fn cleanup_one(&mut self) -> bool {
        if let Some(o) = self.ops.iter().position(|o| {
            o.gone
                && (o.cancelled || o.final_done)
                && o.engine.out().drained()
                && !self.effect_for_op(o.id)
        }) {
            let id = self.ops[o].id;
            if !self
                .offers
                .iter()
                .any(|i| i.adopting == Some(id) && !i.gone)
            {
                self.ops.remove(o);
                return true;
            }
        }
        if let Some(i) = self.offers.iter().position(|i| {
            i.gone
                && !self.effects.iter().any(|e| match &e.action {
                    Action::AdoptPeer { incoming, .. } => *incoming == i.id,
                    Action::ClosePeer {
                        owner: PeerOwner::Incoming(id),
                    }
                    | Action::PeerSend {
                        owner: PeerOwner::Incoming(id),
                        ..
                    } => *id == i.id,
                    _ => false,
                })
        }) {
            self.offers.remove(i);
            return true;
        }
        if let Some(c) = self.clients.iter().position(|c| {
            !c.live
                && c.listener.as_ref().is_none_or(|l| l.closed)
                && !self.ops.iter().any(|o| o.client == c.id)
                && !self.offers.iter().any(|o| o.listener == c.id)
                && !self.effects.iter().any(|e| match &e.action {
                    Action::OpenPort { listener, .. } | Action::ClosePort { listener, .. } => {
                        *listener == c.id
                    }
                    Action::ClientFrame { client, .. } | Action::CloseClient { client, .. } => {
                        *client == c.id
                    }
                    _ => false,
                })
        }) {
            self.clients.remove(c);
            return true;
        }
        false
    }
    /// Perform a finite CPU/queue step. Empty pressure does not mint progress;
    /// caller must fairly drive original IO and retain all original deadlines.
    pub fn progress(&mut self, current: u64, ports: &mut impl Ports) -> Result<bool, Error> {
        if let Some(error) = self.internal_failure {
            return Err(error);
        }
        self.now = self.now.max(current);
        self.tick(current, ports)?;
        if self.cleanup_one() {
            return Ok(true);
        }
        for i in 0..self.offers.len() {
            if self.offers[i].closing
                && !self.offers[i].gone
                && !self.offers[i].close
                && self.offers[i].adopting.is_none()
            {
                let id = self.offers[i].id;
                match self.queue(Action::ClosePeer {
                    owner: PeerOwner::Incoming(id),
                }) {
                    Ok(_) => {
                        self.offers[i].close = true;
                        return Ok(true);
                    }
                    Err(Error::WouldBlock | Error::Capacity) => break,
                    Err(e) => return Err(e),
                }
            }
        }
        let mut changed = false;
        if !self.ops.is_empty() {
            let i = self.op_cursor % self.ops.len();
            self.op_cursor = self.op_cursor.wrapping_add(1);
            match self.op_step(i, ports) {
                Ok(v) => changed |= v,
                Err(Error::WouldBlock | Error::NotReady) => {}
                Err(e) if matches!(e, Error::Capacity | Error::TooLarge) => {
                    self.fail_op(i, e);
                    changed = true;
                }
                Err(e) => return Err(e),
            }
        }
        if !self.clients.is_empty() {
            let i = self.client_cursor % self.clients.len();
            self.client_cursor = self.client_cursor.wrapping_add(1);
            match self.client_step(i) {
                Ok(v) => changed |= v,
                Err(Error::WouldBlock) => {}
                Err(e)
                    if matches!(
                        e,
                        Error::Capacity
                            | Error::TooLarge
                            | Error::Malformed
                            | Error::InvalidInput
                            | Error::Overflow
                    ) =>
                {
                    if self.clients[i].failure.is_none() {
                        self.clients[i].failure = Some(e);
                    }
                    let id = self.clients[i].id;
                    self.detach_client(id)?;
                    changed = true;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(changed)
    }
    /// Expire original intents once; retired targets are removed from the next
    /// deadline projection while their physical effects remain retained.
    pub fn tick(&mut self, current: u64, _: &mut impl Ports) -> Result<(), Error> {
        self.now = self.now.max(current);
        for i in 0..self.ops.len() {
            if !self.ops[i].closing
                && (!self.ops[i].gone || self.ops[i].engine.can_finish_locally())
                && self.ops[i].expires <= self.now
            {
                self.fail_op(i, Error::Deadline);
            }
        }
        for i in &mut self.offers {
            if i.adopting.is_none() && !i.closing && i.expires <= self.now {
                i.closing = true;
            }
        }
        Ok(())
    }
    /// Earliest live original intent expiration, never a renewed retry bound.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.ops
            .iter()
            .filter(|o| !o.closing && (!o.gone || o.engine.can_finish_locally()))
            .map(|o| o.expires)
            .chain(
                self.offers
                    .iter()
                    .filter(|i| i.adopting.is_none() && !i.closing && !i.gone)
                    .map(|i| i.expires),
            )
            .min()
    }
    /// Whether the same local source is still admitted.
    #[must_use]
    pub fn client_live(&self, id: Client<'id>) -> bool {
        self.ci(id).is_ok_and(|i| self.clients[i].live)
    }
    /// Whether original operation metadata remains live for its client results.
    #[must_use]
    pub fn operation_live(&self, id: Operation<'id>) -> bool {
        self.oi(id)
            .is_ok_and(|i| !self.ops[i].cancelled && !self.ops[i].final_done)
    }
    /// Whether the exact pending incoming owner is still permitted native IO.
    #[must_use]
    pub fn incoming_live(&self, id: Incoming<'id>) -> bool {
        self.ii(id)
            .is_ok_and(|i| !self.offers[i].closing && !self.offers[i].gone)
    }
    /// Normal IO authority; retained closing leases are not new IO permission.
    #[must_use]
    pub fn peer_owner_live(&self, owner: PeerOwner<'id>) -> bool {
        match owner {
            PeerOwner::Incoming(id) => self.incoming_live(id),
            PeerOwner::Operation(id) => self
                .oi(id)
                .is_ok_and(|i| !self.ops[i].closing && !self.ops[i].gone),
        }
    }
    /// Number of sequential progress calls covering each current operation and
    /// client slot once when no intervening call changes the owner population.
    /// A false single step is not a whole-service quiescence observation. Native
    /// drivers must restart this finite pass after real input or settlement.
    #[must_use]
    pub fn progress_span(&self) -> usize {
        self.ops.len().max(self.clients.len()).max(1)
    }
    /// Number of original outstanding actions, including admitted retirement debt.
    #[must_use]
    pub fn pending_effects(&self) -> usize {
        self.effects.len()
    }
    /// Begin clock-free shutdown; further progress emits only required original
    /// retirement and all admitted native terminals must still be supplied.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        self.closing = true;
        for i in 0..self.clients.len() {
            let id = self.clients[i].id;
            self.detach_client(id)?;
        }
        Ok(())
    }
    /// True only after all real owner/effect debts have actually been drained.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.clients.is_empty()
            && self.offers.is_empty()
            && self.ops.is_empty()
            && self.effects.is_empty()
            && self.copies.is_empty()
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
