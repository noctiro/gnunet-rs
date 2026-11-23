//! Original allocation domains, source/request/effect capabilities and bounded work.
use crate::MAX_DNS_BYTES;
use core::{cell::Cell, fmt, ptr};
use gnunet_types::Error;
/// Stable caller allocation domain, no hidden global IDs or Atomic64 target need.
#[derive(Debug)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// Empty allocation domain, no effect.
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
    pub(super) fn allocate(&self) -> Result<u64, Error> {
        let n = self.next.get().checked_add(1).ok_or(Error::Overflow)?;
        self.next.set(n);
        Ok(n)
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
impl PartialEq for Instance {
    fn eq(&self, b: &Self) -> bool {
        ptr::eq(self, b)
    }
}
impl Eq for Instance {}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Scope<'a> {
    pub(super) domain: &'a Instance,
    pub(super) serial: u64,
}
impl fmt::Debug for Scope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsInterceptionScope")
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}
/// Original accepted client MQ, not merely UID or a carried identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Client<'id> {
    pub(super) scope: Scope<'id>,
    pub(super) row: usize,
    pub(super) serial: u64,
}
/// Original attached native interception source generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Source<'id> {
    pub(super) scope: Scope<'id>,
    pub(super) serial: u64,
}
/// Original intercepted request, independent from DNS-ID collisions and clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'id> {
    pub(super) scope: Scope<'id>,
    pub(super) row: usize,
    pub(super) serial: u64,
}
/// Exact source-scoped actual resolver operation; no wire field is introduced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolve<'id> {
    pub(super) request: Request<'id>,
    pub(super) serial: u64,
}
impl<'id> Resolve<'id> {
    /// Original service request scope; no answer is implied.
    pub const fn request(self) -> Request<'id> {
        self.request
    }
}
/// Actual output destination, whose physical retirement is separately required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination<'id> {
    /// Original local client MQ.
    Client(Client<'id>),
    /// Original native interception source.
    Source(Source<'id>),
}
/// Immutable original output attempt. Private construction binds exact original
/// request/phase/client/source and serial; it contains no private wire RID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Effect<'id> {
    pub(super) request: Request<'id>,
    pub(super) serial: u64,
    pub(super) destination: Destination<'id>,
}
impl<'id> Effect<'id> {
    /// Exact original request.
    pub const fn request(self) -> Request<'id> {
        self.request
    }
    /// Actual destination owner.
    pub const fn destination(self) -> Destination<'id> {
        self.destination
    }
}
/// Current protocol phase. Only actual client/resolver results advance it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Read-only query observers.
    RequestMonitor,
    /// Answer/query-rewrite providers.
    PreResolution,
    /// Actual original outbound DNSSTUB job outstanding or ready.
    Resolver,
    /// Response rewrite providers.
    PostResolution,
    /// Read-only final observers.
    ResponseMonitor,
    /// Actual native source output awaits local completion.
    Output,
    /// Original request is dropped/expired; external debts still need retirement.
    Dropped,
}
/// Explicit bounded directory and payload limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    ///1..64; eligible phase snapshot is one u64 bitmap.
    pub clients: usize,
    /// Fixed request rows, allocated once.
    pub requests: usize,
    /// Shared current payload capacities; no maximum buffer per client/request.
    pub bytes: usize,
    /// Maximum actual DNS payload,12..MAX_DNS_BYTES.
    pub payload_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 16,
            requests: 128,
            bytes: 4 * 1024 * 1024,
            payload_bytes: MAX_DNS_BYTES,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Read-only original output lifecycle; none means remote DNS/application delivery.
pub enum OutputPhase {
    /// Exact bytes prepared but not admitted to native MQ.
    Prepared,
    /// Immutable bytes admitted to the original native queue.
    Queued,
    /// Actual positive original local-write prefix observed.
    Exposed,
    /// Original complete local-write observed; callback decision may still wait.
    Written,
}
/// One next actual provider/output requirement, borrowed without admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Work<'id> {
    /// Encode and queue one original client callback.
    Client {
        /// Original intercepted request.
        request: Request<'id>,
        /// Exact accepted application MQ allocation.
        client: Client<'id>,
    },
    /// Submit a real resolver operation.
    Resolve(Request<'id>),
    /// Prepare one DNS reply for the original native source.
    Source {
        /// Original intercepted request.
        request: Request<'id>,
        /// Exact original attached native source.
        source: Source<'id>,
    },
    /// Actual original output source must retire before cleanup.
    Close(Destination<'id>),
    /// Cancel only the original actual resolver operation.
    Cancel(Resolve<'id>),
    /// No external debt remains; caller may retire original row.
    Retire(Request<'id>),
}
/// Prepared original source response borrowing its retained DNS allocation.
/// Its immutable borrow ends before the owner admits, rejects or retires the
/// effect, so native encoding needs no intermediate payload allocation/copy.
pub struct PreparedReply<'a, 'id> {
    pub(super) effect: Effect<'id>,
    pub(super) dns: &'a [u8],
}
impl<'a, 'id> PreparedReply<'a, 'id> {
    /// Original prepared output attempt; copying it does not admit a write.
    pub const fn effect(&self) -> Effect<'id> {
        self.effect
    }
    /// Exact retained DNS response bytes, without transport framing.
    pub const fn dns(&self) -> &'a [u8] {
        self.dns
    }
}
impl fmt::Debug for PreparedReply<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedReply")
            .field("effect", &self.effect)
            .field("dns_bytes", &self.dns.len())
            .finish_non_exhaustive()
    }
}
