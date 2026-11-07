//! Bounded pure SETU client/set/listener/operation lifecycle. Host callbacks
//! report actual CADET bind/open/send/retirement; this owner creates no socket.
use crate::{
    Codec,
    set::{self, Set, Snapshot},
    union::{self, ResultEntry, Transmission, Union},
    wire::{self, Abi, Options, Peer, Request, Response, Status},
};
use alloc::{rc::Rc, vec::Vec};
use gnunet_types::Error;
#[derive(Debug)]
struct Stamp {
    _nonzero: u8,
}

macro_rules! handle {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Debug)]
        pub struct $name {
            owner: Rc<Stamp>,
            serial: u64,
        }
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                Rc::ptr_eq(&self.owner, &other.owner) && self.serial == other.serial
            }
        }
        impl Eq for $name {}
        impl $name {
            /// Diagnostic generation, never encoded as a private protocol field.
            #[must_use]
            pub const fn diagnostic(&self) -> u64 {
                self.serial
            }
        }
    };
}
handle!(
    Client,
    "One actually attached external application MQ, registered by its host."
);
handle!(
    Operation,
    "One original outgoing or accepted incoming SETU operation."
);
/// Explicit independent service capacities. Union/set budgets remain per owner.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum external application clients/sets/listeners.
    pub clients: usize,
    /// Maximum outgoing+pending incoming operations.
    pub operations: usize,
    /// Per-set actual immutable content resources.
    pub set: set::Limits,
    /// Per-operation algorithm/output/report resources.
    pub union: union::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            operations: 8,
            set: set::Limits::default(),
            union: union::Limits::default(),
        }
    }
}
struct Listener {
    app: [u8; 64],
    issued: bool,
    ready: bool,
}
struct ClientState {
    id: Client,
    set: Option<Set>,
    listener: Option<Listener>,
    close: Option<Error>,
    close_issued: bool,
    retiring: bool,
    unlisten_issued: bool,
}
enum State {
    Connecting {
        snapshot: Option<Snapshot>,
        options: Options,
        context: Option<Vec<u8>>,
        issued: bool,
    },
    Incoming {
        count: u32,
        context: Option<Vec<u8>>,
        incoming: u32,
        reported: bool,
    },
    Running(Union),
    Cancelling(Option<Union>),
    AwaitRetirement(Error),
    RetiredFailure(Option<Error>),
}
struct Entry {
    id: Operation,
    client: Client,
    request: u32,
    peer: Option<[u8; 32]>,
    app: [u8; 64],
    expires: u64,
    state: State,
    close_issued: bool,
}
/// Original host action. Sending/binding/opening is requested, never fabricated.
pub enum Effect<'a> {
    /// Bind actual CADET application port for this original listener MQ.
    Listen {
        /// Original local application owner.
        client: Client,
        /// Exact official CADET port hash.
        app: [u8; 64],
    },
    /// Retire the exact original CADET port/bind attempt after its app MQ closed.
    Unlisten {
        /// Original listener ownership, retained until listener_closed.
        client: Client,
        /// Exact actual application port.
        app: [u8; 64],
    },
    /// Close this exact application MQ after an actual local refusal.
    CloseClient {
        /// Original application MQ.
        client: Client,
        /// Original cause.
        error: Error,
    },
    /// Open actual CADET channel to the expected peer/application.
    Open {
        /// Original operation.
        operation: Operation,
        /// Exact expected actual peer.
        peer: [u8; 32],
        /// Actual application port hash.
        app: [u8; 64],
    },
    /// Write the original immutable complete frame on that operation's actual channel.
    Send {
        /// Original operation/channel scope.
        operation: Operation,
        /// Exact original local write capability.
        transmission: Transmission,
        /// Original immutable peer bytes.
        bytes: &'a [u8],
    },
    /// Physically close the original peer channel before reporting retired.
    Close {
        /// Original operation/channel.
        operation: Operation,
    },
}
/// Original incoming request, held until accept/reject/expiry. It can be copied
/// to the listener's actual MQ with the standard RESPONSE codec, not a new field.
pub struct Incoming {
    /// Original listening application MQ.
    pub client: Client,
    /// Original pending source scope.
    pub operation: Operation,
    /// Official per-service accept/reject correlation id.
    pub incoming: u32,
    /// Actual original requesting peer from the host CADET port.
    pub peer: [u8; 32],
    context: Option<Vec<u8>>,
    abi: Abi,
}
impl Incoming {
    /// Borrow the exact official incoming-request observation.
    #[must_use]
    pub fn response(&self) -> Response<'_> {
        Response::Incoming {
            incoming: self.incoming,
            peer: self.peer,
            context: self.context.as_deref(),
        }
    }
    /// Encode the actual original observation; not a local write receipt.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.response().encode(self.abi, out)
    }
}
/// Original operation result and intended application owner. Host owns immutable
/// queue admission/partial writes after taking this value; no ACK is inferred.
pub struct ServiceResult {
    /// Original application MQ.
    pub client: Client,
    /// Original operation.
    pub operation: Operation,
    /// Official original application request id.
    pub request: u32,
    /// Actual core result/status, including original failure cause.
    pub result: ResultEntry,
    abi: Abi,
}
impl ServiceResult {
    /// Borrow the exact official RESULT data. Terminal statuses carry no element.
    #[must_use]
    pub fn response(&self) -> Response<'_> {
        Response::Result {
            current_size: self.result.current_size,
            request: self.request,
            status: self.result.status,
            element: self
                .result
                .element
                .as_ref()
                .map_or(wire::Element { kind: 0, data: &[] }, |element| {
                    element.borrowed()
                }),
        }
    }
    /// Encode the original complete result, preserving source ABI padding.
    pub fn encode(&self, out: &mut [u8]) -> core::result::Result<usize, Error> {
        self.response().encode(self.abi, out)
    }
}
/// Movable bounded service coordinator. Native peer/application ports are not
/// embedded, borrowed thread handles or private wire capabilities.
pub struct Service {
    stamp: Rc<Stamp>,
    next_client: u64,
    next_operation: u64,
    next_incoming: u64,
    clients: Vec<Option<ClientState>>,
    operations: Vec<Option<Entry>>,
    limits: Limits,
    abi: Abi,
    cursor: usize,
    shutting_down: bool,
}
impl Service {
    /// Reserve fixed small client/operation slots, without any native effects.
    pub fn new(limits: Limits, abi: Abi) -> core::result::Result<Self, Error> {
        abi.validate()?;
        if limits.clients == 0 || limits.operations == 0 {
            return Err(Error::Capacity);
        }
        let mut clients = Vec::new();
        clients
            .try_reserve_exact(limits.clients)
            .map_err(|_| Error::Capacity)?;
        clients.resize_with(limits.clients, || None);
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(limits.operations)
            .map_err(|_| Error::Capacity)?;
        operations.resize_with(limits.operations, || None);
        Ok(Self {
            stamp: Rc::new(Stamp { _nonzero: 0 }),
            next_client: 0,
            next_operation: 0,
            next_incoming: 0,
            clients,
            operations,
            limits,
            abi,
            cursor: 0,
            shutting_down: false,
        })
    }
    fn client_index(&self, client: &Client) -> core::result::Result<usize, Error> {
        if !Rc::ptr_eq(&self.stamp, &client.owner) {
            return Err(Error::Stale);
        }
        self.clients
            .iter()
            .position(|state| state.as_ref().is_some_and(|state| state.id == *client))
            .ok_or(Error::Stale)
    }
    fn op_index(&self, operation: &Operation) -> core::result::Result<usize, Error> {
        if !Rc::ptr_eq(&self.stamp, &operation.owner) {
            return Err(Error::Stale);
        }
        self.operations
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.id == *operation))
            .ok_or(Error::Stale)
    }
    fn vacant(&self) -> core::result::Result<usize, Error> {
        self.operations
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)
    }
    fn deadline(now: u64, expires: u64) -> core::result::Result<(), Error> {
        if expires <= now || expires == u64::MAX {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
    fn copy(bytes: &[u8]) -> core::result::Result<Vec<u8>, Error> {
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Capacity)?;
        copied.extend_from_slice(bytes);
        Ok(copied)
    }
    fn usable(&self, client: &Client) -> core::result::Result<usize, Error> {
        let index = self.client_index(client)?;
        let state = self.clients[index].as_ref().ok_or(Error::Stale)?;
        if self.shutting_down || state.retiring || state.close.is_some() {
            Err(Error::Closed)
        } else {
            Ok(index)
        }
    }
    fn snapshot(&self, client: &Client) -> core::result::Result<Snapshot, Error> {
        self.clients[self.usable(client)?]
            .as_ref()
            .and_then(|state| state.set.as_ref())
            .ok_or(Error::NotReady)?
            .snapshot()
    }
    fn unique_request(&self, client: &Client, request: u32) -> core::result::Result<(), Error> {
        if request == 0
            || self.operations.iter().any(|entry| {
                entry
                    .as_ref()
                    .is_some_and(|entry| entry.client == *client && entry.request == request)
            })
        {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    fn id(&mut self) -> core::result::Result<Operation, Error> {
        self.next_operation = self.next_operation.checked_add(1).ok_or(Error::Overflow)?;
        Ok(Operation {
            owner: self.stamp.clone(),
            serial: self.next_operation,
        })
    }
    /// Register one actual external application MQ supplied by the native host.
    pub fn connect(&mut self) -> core::result::Result<Client, Error> {
        if self.shutting_down {
            return Err(Error::Closed);
        }
        let index = self
            .clients
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let next = self.next_client.checked_add(1).ok_or(Error::Overflow)?;
        let id = Client {
            owner: self.stamp.clone(),
            serial: next,
        };
        self.clients[index] = Some(ClientState {
            id: id.clone(),
            set: None,
            listener: None,
            close: None,
            close_issued: false,
            retiring: false,
            unlisten_issued: false,
        });
        self.next_client = next;
        Ok(id)
    }
    /// Create one actual local union set on the original application owner.
    pub fn create(&mut self, client: &Client) -> core::result::Result<(), Error> {
        let index = self.usable(client)?;
        let state = self.clients[index].as_mut().ok_or(Error::Stale)?;
        if state.set.is_some() || state.listener.is_some() {
            return Err(Error::Conflict);
        }
        state.set = Some(Set::new(self.limits.set, self.abi)?);
        Ok(())
    }
    /// Add an element; duplicate identical bytes/types remain one member.
    pub fn add(
        &mut self,
        client: &Client,
        element: wire::Element<'_>,
    ) -> core::result::Result<bool, Error> {
        let index = self.usable(client)?;
        self.clients[index]
            .as_mut()
            .and_then(|state| state.set.as_mut())
            .ok_or(Error::NotReady)?
            .add(element)
    }
    /// Rust internal remove preserving live snapshots. No REMOVE IPC exists.
    pub fn remove(
        &mut self,
        client: &Client,
        element: wire::Element<'_>,
    ) -> core::result::Result<bool, Error> {
        let index = self.usable(client)?;
        self.clients[index]
            .as_mut()
            .and_then(|state| state.set.as_mut())
            .ok_or(Error::NotReady)?
            .remove(element)
    }
    /// Register an application port intent; actual bind follows through Effect.
    pub fn listen(&mut self, client: &Client, app: [u8; 64]) -> core::result::Result<(), Error> {
        if self.clients.iter().any(|state| {
            state
                .as_ref()
                .and_then(|state| state.listener.as_ref())
                .is_some_and(|listener| listener.app == app)
        }) {
            return Err(Error::Conflict);
        }
        let index = self.usable(client)?;
        let state = self.clients[index].as_mut().ok_or(Error::Stale)?;
        if state.set.is_some() || state.listener.is_some() {
            return Err(Error::Conflict);
        }
        state.listener = Some(Listener {
            app,
            issued: false,
            ready: false,
        });
        Ok(())
    }
    /// Report actual host CADET listen completion; failure requests closing only
    /// its original application source, never an invented readiness ACK. Err
    /// means the host has already retired the failed original bind attempt.
    pub fn listener_ready(
        &mut self,
        client: &Client,
        result: core::result::Result<(), Error>,
    ) -> core::result::Result<(), Error> {
        let index = self.client_index(client)?;
        let state = self.clients[index].as_mut().ok_or(Error::Stale)?;
        if state.retiring {
            return Err(Error::Cancelled);
        }
        let listener = state.listener.as_mut().ok_or(Error::Stale)?;
        if !listener.issued || listener.ready {
            return Err(Error::Stale);
        }
        match result {
            Ok(()) => listener.ready = true,
            Err(error) => {
                listener.issued = false;
                state.close = Some(error)
            }
        }
        Ok(())
    }
    /// Snapshot current membership and open the actual expected peer port later.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original evaluate retains request, peer, application, options, context and absolute source deadline together"
    )]
    pub fn evaluate(
        &mut self,
        client: &Client,
        request: u32,
        peer: [u8; 32],
        app: [u8; 64],
        options: Options,
        context: Option<&[u8]>,
        now: u64,
        expires: u64,
    ) -> core::result::Result<Operation, Error> {
        union::validate_options(options)?;
        Self::deadline(now, expires)?;
        self.unique_request(client, request)?;
        if let Some(context) = context {
            if context.len() > wire::CONTEXT_MAX {
                return Err(Error::TooLarge);
            }
            gnunet_wire::official::Frame::decode(context)?;
        }
        let index = self.vacant()?;
        let snapshot = self.snapshot(client)?;
        let context = context.map(Self::copy).transpose()?;
        let id = self.id()?;
        self.operations[index] = Some(Entry {
            id: id.clone(),
            client: client.clone(),
            request,
            peer: Some(peer),
            app,
            expires,
            state: State::Connecting {
                snapshot: Some(snapshot),
                options,
                context,
                issued: false,
            },
            close_issued: false,
        });
        Ok(id)
    }
    /// Bind actual successful peer-channel creation to its original operation.
    /// Actual host identity must equal the expected original remote peer.
    pub fn connected(
        &mut self,
        operation: &Operation,
        actual_peer: [u8; 32],
    ) -> core::result::Result<(), Error> {
        let index = self.op_index(operation)?;
        let entry = self.operations[index].as_mut().ok_or(Error::Stale)?;
        if !matches!(entry.state, State::Connecting { issued: true, .. }) {
            return Err(Error::Stale);
        }
        if entry.peer != Some(actual_peer) {
            entry.state = State::AwaitRetirement(Error::Authentication);
            return Err(Error::Authentication);
        }
        let State::Connecting {
            snapshot,
            options,
            context,
            issued,
        } = &mut entry.state
        else {
            return Err(Error::Stale);
        };
        if !*issued {
            return Err(Error::NotReady);
        }
        let result = Union::initiate(
            snapshot.take().ok_or(Error::Stale)?,
            *options,
            self.limits.union,
            entry.app,
            context.as_deref(),
        );
        match result {
            Ok(union) => entry.state = State::Running(union),
            Err(error) => {
                entry.state = State::AwaitRetirement(error);
                return Err(error);
            }
        }
        Ok(())
    }
    /// Report an actual failed original open after the host retired that exact
    /// attempt. No unknown native source is declared quiescent by a timeout.
    pub fn connect_failed(
        &mut self,
        operation: &Operation,
        error: Error,
    ) -> core::result::Result<(), Error> {
        let index = self.op_index(operation)?;
        let entry = self.operations[index].as_mut().ok_or(Error::Stale)?;
        if !matches!(entry.state, State::Connecting { issued: true, .. }) {
            return Err(Error::Stale);
        }
        entry.state = State::RetiredFailure(Some(error));
        Ok(())
    }
    /// Receive the actual first request on an actual bound listener channel.
    /// The CADET port is the application authority; the source's unused app_idX
    /// field is retained by the codec and is not substituted for that binding.
    pub fn incoming(
        &mut self,
        listener: &Client,
        actual_peer: [u8; 32],
        bytes: &[u8],
        now: u64,
        expires: u64,
    ) -> core::result::Result<Operation, Error> {
        Self::deadline(now, expires)?;
        let client_index = self.usable(listener)?;
        let app = self.clients[client_index]
            .as_ref()
            .and_then(|state| state.listener.as_ref())
            .filter(|listener| listener.ready)
            .ok_or(Error::NotReady)?
            .app;
        let Peer::Operation { count, context, .. } = Peer::decode(bytes, self.abi)? else {
            return Err(Error::Malformed);
        };
        let context = context.map(Self::copy).transpose()?;
        let index = self.vacant()?;
        let incoming = u32::try_from(self.next_incoming.checked_add(1).ok_or(Error::Overflow)?)
            .map_err(|_| Error::Overflow)?;
        let id = self.id()?;
        self.operations[index] = Some(Entry {
            id: id.clone(),
            client: listener.clone(),
            request: 0,
            peer: Some(actual_peer),
            app,
            expires,
            state: State::Incoming {
                count,
                context,
                incoming,
                reported: false,
            },
            close_issued: false,
        });
        self.next_incoming = u64::from(incoming);
        Ok(id)
    }
    /// Take one original incoming suggestion. Host must retain/copy it until
    /// real output admission or source retirement; no application receive ACK.
    pub fn next_incoming(&mut self) -> core::result::Result<Option<Incoming>, Error> {
        for entry in self.operations.iter_mut().flatten() {
            if let State::Incoming {
                context,
                incoming,
                reported,
                ..
            } = &mut entry.state
            {
                if *reported {
                    continue;
                }
                let copied = context.as_deref().map(Self::copy).transpose()?;
                *reported = true;
                return Ok(Some(Incoming {
                    client: entry.client.clone(),
                    operation: entry.id.clone(),
                    incoming: *incoming,
                    peer: entry.peer.ok_or(Error::NotReady)?,
                    context: copied,
                    abi: self.abi,
                }));
            }
        }
        Ok(None)
    }
    /// Accept an original incoming channel using this set's membership snapshot.
    pub fn accept(
        &mut self,
        client: &Client,
        operation: &Operation,
        request: u32,
        options: Options,
    ) -> core::result::Result<(), Error> {
        union::validate_options(options)?;
        self.unique_request(client, request)?;
        let snapshot = self.snapshot(client)?;
        let index = self.op_index(operation)?;
        let entry = self.operations[index].as_mut().ok_or(Error::Stale)?;
        let State::Incoming { count, .. } = entry.state else {
            return Err(Error::Stale);
        };
        entry.client = client.clone();
        entry.request = request;
        match Union::accept(snapshot, options, self.limits.union, count) {
            Ok(union) => entry.state = State::Running(union),
            Err(error) => {
                entry.state = State::AwaitRetirement(error);
                return Err(error);
            }
        }
        Ok(())
    }
    /// Reject one original incoming suggestion; actual channel close follows.
    pub fn reject(&mut self, operation: &Operation) -> core::result::Result<(), Error> {
        let index = self.op_index(operation)?;
        let entry = self.operations[index].as_mut().ok_or(Error::Stale)?;
        if !matches!(entry.state, State::Incoming { .. }) {
            return Err(Error::Stale);
        }
        entry.state = State::Cancelling(None);
        Ok(())
    }
    /// Cancel only the original scoped operation, retaining native close debt.
    pub fn cancel(&mut self, operation: &Operation) -> core::result::Result<(), Error> {
        let index = self.op_index(operation)?;
        let entry = self.operations[index].as_mut().ok_or(Error::Stale)?;
        if Self::cancel_entry(entry) {
            self.operations[index] = None;
        }
        Ok(())
    }
    // Source validation happens before this transition. Shutdown already owns
    // each entry exclusively, so it need not clone a token and scan all slots.
    fn cancel_entry(entry: &mut Entry) -> bool {
        if matches!(
            entry.state,
            State::Connecting { issued: false, .. } | State::RetiredFailure(_)
        ) || matches!(&entry.state, State::Running(union) if union.is_retired())
        {
            return true;
        }
        let state = core::mem::replace(&mut entry.state, State::Cancelling(None));
        entry.state = match state {
            State::Running(mut union) => {
                union.cancel();
                State::Cancelling(Some(union))
            }
            State::Cancelling(union) => State::Cancelling(union),
            _ => State::Cancelling(None),
        };
        false
    }
    /// Record an actual original peer/open failure while retaining its physical
    /// close debt. This is distinct from cancellation, which suppresses reports.
    pub fn abort(&mut self, operation: &Operation, error: Error) -> Result<(), Error> {
        let index = self.op_index(operation)?;
        let entry = self.operations[index].as_mut().ok_or(Error::Stale)?;
        match &mut entry.state {
            State::Running(union) => union.abort(error),
            State::Connecting { issued: false, .. } => {
                entry.state = State::RetiredFailure(Some(error))
            }
            State::Connecting { issued: true, .. } => entry.state = State::AwaitRetirement(error),
            State::Incoming { .. } => entry.state = State::Cancelling(None),
            State::AwaitRetirement(_) | State::Cancelling(_) | State::RetiredFailure(_) => {}
        }
        Ok(())
    }
    /// Feed original complete peer input to its actual running channel scope.
    pub fn receive(
        &mut self,
        operation: &Operation,
        bytes: &[u8],
        codec: &mut impl Codec,
    ) -> core::result::Result<(), Error> {
        let index = self.op_index(operation)?;
        let entry = self.operations[index].as_mut().ok_or(Error::Stale)?;
        let State::Running(union) = &mut entry.state else {
            return Err(Error::Stale);
        };
        union.receive(bytes, codec)
    }
    /// Advance bounded pure work, sharing one explicit codec across operations.
    pub fn advance(
        &mut self,
        codec: &mut impl Codec,
        budget: usize,
    ) -> core::result::Result<usize, Error> {
        let mut work = 0;
        for _ in 0..budget {
            let mut progressed = false;
            for offset in 0..self.operations.len() {
                let index = (self.cursor + offset) % self.operations.len();
                if let Some(Entry {
                    state: State::Running(union),
                    ..
                }) = &mut self.operations[index]
                {
                    match union.advance(codec, 1) {
                        Ok(0) => {}
                        Ok(n) => {
                            work += n;
                            progressed = true
                        }
                        Err(_) => progressed = true,
                    }
                    if progressed {
                        self.cursor = (index + 1) % self.operations.len();
                        break;
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        Ok(work)
    }
    /// Take one actual host action. Each original operation has at most one
    /// leased immutable peer frame; original tokens cannot cross source scopes.
    pub fn next_effect(&mut self) -> Option<Effect<'_>> {
        for client in self.clients.iter_mut().flatten() {
            if client.retiring {
                if let Some(listener) = &client.listener
                    && listener.issued
                    && !client.unlisten_issued
                {
                    client.unlisten_issued = true;
                    return Some(Effect::Unlisten {
                        client: client.id.clone(),
                        app: listener.app,
                    });
                }
                continue;
            }
            if let Some(error) = client.close
                && !client.close_issued
            {
                client.close_issued = true;
                return Some(Effect::CloseClient {
                    client: client.id.clone(),
                    error,
                });
            }
            if let Some(listener) = &mut client.listener
                && !listener.issued
                && client.close.is_none()
            {
                listener.issued = true;
                return Some(Effect::Listen {
                    client: client.id.clone(),
                    app: listener.app,
                });
            }
        }
        for entry in self.operations.iter_mut().flatten() {
            let operation = entry.id.clone();
            match &mut entry.state {
                State::Connecting { issued, .. } if !*issued => {
                    *issued = true;
                    return Some(Effect::Open {
                        operation,
                        peer: entry.peer?,
                        app: entry.app,
                    });
                }
                State::Running(union) => {
                    if union.close_needed() {
                        if !entry.close_issued {
                            entry.close_issued = true;
                            return Some(Effect::Close { operation });
                        }
                    } else if union.has_unleased_output() {
                        let output = union.outbound()?;
                        return Some(Effect::Send {
                            operation,
                            transmission: output.transmission,
                            bytes: output.bytes,
                        });
                    }
                }
                State::Cancelling(_) | State::AwaitRetirement(_) if !entry.close_issued => {
                    entry.close_issued = true;
                    return Some(Effect::Close { operation });
                }
                _ => {}
            }
        }
        None
    }
    /// Report actual original complete local peer-frame writing.
    pub fn sent(
        &mut self,
        operation: &Operation,
        transmission: &Transmission,
    ) -> core::result::Result<(), Error> {
        let index = self.op_index(operation)?;
        match &mut self.operations[index].as_mut().ok_or(Error::Stale)?.state {
            State::Running(union) | State::Cancelling(Some(union)) => union.sent(transmission),
            _ => Err(Error::Stale),
        }
    }
    /// Actual original channel close callback. Cancellation suppresses results;
    /// successful completion requires the Union's actual end/debt conditions.
    pub fn retired(&mut self, operation: &Operation) -> core::result::Result<(), Error> {
        let index = self.op_index(operation)?;
        let entry = self.operations[index].as_mut().ok_or(Error::Stale)?;
        match &mut entry.state {
            State::Running(union) => union.retired(),
            State::Cancelling(_) | State::Incoming { .. } => self.operations[index] = None,
            State::Connecting { .. } => entry.state = State::RetiredFailure(Some(Error::Io)),
            State::AwaitRetirement(error) => entry.state = State::RetiredFailure(Some(*error)),
            State::RetiredFailure(_) => return Err(Error::Stale),
        }
        Ok(())
    }
    /// Consume one original actual result for the application host port. Moving
    /// it transfers immutable bytes/ownership, not an application write receipt.
    pub fn next_result(&mut self) -> Option<ServiceResult> {
        for index in 0..self.operations.len() {
            let Some(entry) = self.operations[index].as_mut() else {
                continue;
            };
            let result = match &mut entry.state {
                State::Running(union) => union.next_result(),
                State::RetiredFailure(error) => Some(ResultEntry {
                    status: Status::Failure,
                    element: None,
                    current_size: 0,
                    error: error.take(),
                }),
                _ => None,
            };
            if let Some(result) = result {
                let terminal = matches!(result.status, Status::Done | Status::Failure);
                let output = ServiceResult {
                    client: entry.client.clone(),
                    operation: entry.id.clone(),
                    request: entry.request,
                    result,
                    abi: self.abi,
                };
                if terminal {
                    self.operations[index] = None
                }
                return Some(output);
            }
        }
        None
    }
    /// Actual application MQ retirement cancels its own operations/listener. Any
    /// active peer output retains original cancellation/physical-close debt.
    pub fn client_closed(&mut self, client: &Client) -> core::result::Result<(), Error> {
        let index = self.client_index(client)?;
        let state = self.clients[index].as_mut().ok_or(Error::Stale)?;
        if state.retiring {
            return Err(Error::Stale);
        }
        // Drop membership only after actual app retirement. Retain an issued
        // port/bind scope until the host reports its actual unbind completion.
        state.set = None;
        state.retiring = true;
        state.close_issued = true;
        if !state
            .listener
            .as_ref()
            .is_some_and(|listener| listener.issued)
        {
            self.clients[index] = None;
        }
        for index in 0..self.operations.len() {
            if self.operations[index]
                .as_ref()
                .is_some_and(|entry| entry.client == *client)
            {
                let operation = self.operations[index]
                    .as_ref()
                    .ok_or(Error::Stale)?
                    .id
                    .clone();
                self.cancel(&operation)?;
            }
        }
        Ok(())
    }
    /// Report actual retirement of the original listener port or outstanding
    /// bind attempt after Unlisten. A late successful bind must be closed first.
    pub fn listener_closed(&mut self, client: &Client) -> core::result::Result<(), Error> {
        let index = self.client_index(client)?;
        let state = self.clients[index].as_ref().ok_or(Error::Stale)?;
        if !state.retiring || !state.unlisten_issued {
            return Err(Error::Stale);
        }
        self.clients[index] = None;
        Ok(())
    }
    /// Request shutdown through each actual source's original close effect.
    /// Caller must continue draining Close/Unlisten and report real callbacks.
    pub fn shutdown(&mut self) {
        self.shutting_down = true;
        for client in self.clients.iter_mut().flatten() {
            if !client.retiring {
                client.close.get_or_insert(Error::Closed);
            }
        }
        for slot in &mut self.operations {
            if slot.as_mut().is_some_and(Self::cancel_entry) {
                *slot = None;
            }
        }
    }
    /// All original app, port and peer source debt has actually retired.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.clients.iter().all(Option::is_none) && self.operations.iter().all(Option::is_none)
    }
    /// Original earliest operation/open/accept absolute deadline. The host owns
    /// its canonical clock listener and must call expire with actual source time.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.operations
            .iter()
            .flatten()
            .filter(|entry| match &entry.state {
                State::Running(union) => !union.is_retired() && !union.close_needed(),
                State::Connecting { .. } | State::Incoming { .. } => true,
                State::Cancelling(_) | State::AwaitRetirement(_) | State::RetiredFailure(_) => {
                    false
                }
            })
            .map(|entry| entry.expires)
            .min()
    }
    /// Expire original sources without resetting their deadline. Active channels
    /// request physical close; no fabricated source quiescence/DONE is produced.
    pub fn expire(&mut self, now: u64) {
        for entry in self.operations.iter_mut().flatten() {
            if now < entry.expires {
                continue;
            }
            match &mut entry.state {
                State::Running(union) => union.abort(Error::Deadline),
                State::Incoming { .. } => entry.state = State::Cancelling(None),
                State::Connecting { issued: true, .. } => {
                    entry.state = State::AwaitRetirement(Error::Deadline)
                }
                State::Connecting { issued: false, .. } => {
                    entry.state = State::RetiredFailure(Some(Error::Deadline))
                }
                _ => {}
            }
        }
    }
    /// Apply complete actual application bytes using only active official IPC.
    /// The host supplies original finite open/accept deadline and peer port binding.
    pub fn receive_client(
        &mut self,
        client: &Client,
        bytes: &[u8],
        now: u64,
        expires: u64,
    ) -> core::result::Result<Option<Operation>, Error> {
        match Request::decode(bytes, self.abi)? {
            Request::Create => self.create(client)?,
            Request::Add(element) => {
                self.add(client, element)?;
            }
            Request::Listen { app, .. } => self.listen(client, app)?,
            Request::Evaluate {
                request,
                peer,
                app,
                options,
                context,
            } => {
                return self
                    .evaluate(client, request, peer, app, options, context, now, expires)
                    .map(Some);
            }
            Request::Accept {
                incoming,
                request,
                options,
            } => {
                union::validate_options(options)?;
                let operation=self.operations.iter().flatten().find(|entry|matches!(entry.state,State::Incoming{incoming:id,..}if id==incoming)).map(|entry|entry.id.clone());
                if let Some(operation) = operation {
                    self.accept(client, &operation, request, options)?;
                    return Ok(Some(operation));
                }
                // The original incoming source is already absent. Active C
                // returns FAILURE to the accepting set without opening a peer.
                self.unique_request(client, request)?;
                let ci = self.usable(client)?;
                if self.clients[ci]
                    .as_ref()
                    .and_then(|state| state.set.as_ref())
                    .is_none()
                {
                    return Err(Error::NotReady);
                }
                let index = self.vacant()?;
                let operation = self.id()?;
                self.operations[index] = Some(Entry {
                    id: operation.clone(),
                    client: client.clone(),
                    request,
                    peer: None,
                    app: [0; 64],
                    expires,
                    state: State::RetiredFailure(Some(Error::NotFound)),
                    close_issued: false,
                });
                return Ok(Some(operation));
            }
            Request::Reject { incoming } => {
                if let Some(operation)=self.operations.iter().flatten().find(|entry|matches!(entry.state,State::Incoming{incoming:id,..}if id==incoming)).map(|entry|entry.id.clone()) {
                    self.reject(&operation)?;
                }
            }
            Request::Cancel { request } => {
                let operation = self
                    .operations
                    .iter()
                    .flatten()
                    .find(|entry| entry.client == *client && entry.request == request)
                    .map(|entry| entry.id.clone());
                if let Some(operation) = operation {
                    self.cancel(&operation)?;
                }
            }
        }
        Ok(None)
    }
}

#[cfg(all(test, feature = "zlib"))]
#[path = "service_tests.rs"]
mod tests;
