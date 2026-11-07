//! Bounded communicator session/reversal registry. Metadata never fabricates a
//! socket, NAT request, transport queue, or completed native operation.
use crate::session::{Phase, Scope, Session};
use core::{
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    str::FromStr,
};
use gnunet_crypto::EddsaPublicKey;
use gnunet_types::Error;
/// Maximum retained numeric source address bytes in this explicit resource profile.
pub const ADDRESS_CAPACITY: usize = 128;
/// Source pending NAT-reversal lifetime in logical absolute microseconds.
pub const REVERSAL_US: u64 = 10_000_000;
/// Opaque registry scope/slot/generation. Pointer identity is compared explicitly;
/// equal marker bytes in independent scopes never make identities equal.
#[derive(Clone, Copy)]
pub struct Instance<'a> {
    pub(crate) scope: &'a Scope,
    pub(crate) slot: usize,
    pub(crate) generation: u64,
}
impl PartialEq for Instance<'_> {
    fn eq(&self, o: &Self) -> bool {
        core::ptr::eq(self.scope, o.scope) && self.slot == o.slot && self.generation == o.generation
    }
}
impl Eq for Instance<'_> {}
impl Hash for Instance<'_> {
    fn hash<H: Hasher>(&self, h: &mut H) {
        core::ptr::from_ref(self.scope).hash(h);
        self.slot.hash(h);
        self.generation.hash(h)
    }
}
impl fmt::Debug for Instance<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Instance")
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
/// Unique right to construct one physical session for a reserved native admission.
/// It is neither Copy nor Clone. Failure returns this original right; cancel it
/// through Registry::cancel if construction will not be retried. Dropping it
/// alone leaves the slot reserved, rather than authorizing a replacement session.
/// ```compile_fail,E0382
/// use gnunet_tcp_communicator_core::registry::Admission;
/// fn duplicate(admission: Admission<'_>) {
///   let first=admission;
///   let second=admission;
///   drop((first,second));
/// }
/// ```
#[must_use]
pub struct Admission<'a> {
    pub(crate) instance: Instance<'a>,
    pub(crate) target: Option<EddsaPublicKey>,
}
impl<'a> Admission<'a> {
    /// Original metadata identity; a copy does not grant construction authority.
    #[must_use]
    pub const fn instance(&self) -> Instance<'a> {
        self.instance
    }
}
impl fmt::Debug for Admission<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admission")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}
// Defined-safe sscanf("%u%1s") conversion profile. Bad/over-u16 text returns
// port0 in the source; a value outside unsigned32 is rejected rather than
// reproducing scanf's undefined representability case.
fn source_port(text: &str) -> Result<u16, Error> {
    let mut bytes = text.as_bytes();
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    let negative = bytes.first() == Some(&b'-');
    if negative || bytes.first() == Some(&b'+') {
        bytes = &bytes[1..];
    }
    let mut n = 0u32;
    let mut count = 0;
    while let Some(b) = bytes.first().filter(|b| b.is_ascii_digit()) {
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add((*b - b'0') as u32))
            .ok_or(Error::Overflow)?;
        count += 1;
        bytes = &bytes[1..];
    }
    if count == 0 || bytes.iter().any(|b| !b.is_ascii_whitespace()) {
        return Ok(0);
    }
    if negative {
        n = n.wrapping_neg();
    }
    Ok(u16::try_from(n).unwrap_or(0))
}
/// Parsed official tcp-numeric address. This parser performs no DNS/native IO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address(SocketAddr);
impl Address {
    /// Parse the source's tcp- prefix with numeric IPv4/IPv6 and optional port0.
    /// Undefined C malformed-string paths are rejected without being executed.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let raw = bytes.strip_prefix(b"tcp-").ok_or(Error::InvalidInput)?;
        let text = core::str::from_utf8(raw).map_err(|_| Error::InvalidInput)?;
        let (ip, port) = if let Some(rest) = text.strip_prefix('[') {
            let close = rest.find(']').ok_or(Error::InvalidInput)?;
            let ip = IpAddr::from_str(&rest[..close]).map_err(|_| Error::InvalidInput)?;
            if !ip.is_ipv6() {
                return Err(Error::InvalidInput);
            }
            let tail = &rest[close + 1..];
            let port = if tail.is_empty() {
                0
            } else {
                source_port(tail.strip_prefix(':').ok_or(Error::InvalidInput)?)?
            };
            (ip, port)
        } else {
            let (ip, port) = match text.split_once(':') {
                Some((i, p)) => (i, source_port(p)?),
                None => (text, 0),
            };
            let ip = IpAddr::from_str(ip).map_err(|_| Error::InvalidInput)?;
            if !ip.is_ipv4() {
                return Err(Error::InvalidInput);
            }
            (ip, port)
        };
        Ok(Self(SocketAddr::new(ip, port)))
    }
    /// Exact numeric address; native options/connect remain host obligations.
    #[must_use]
    pub const fn socket(self) -> SocketAddr {
        self.0
    }
    /// Source IPv4 port0 asks NAT for reversal; IPv6 port0 is rejected.
    pub fn reversal(self) -> Result<bool, Error> {
        if self.0.is_ipv6() && self.0.port() == 0 {
            return Err(Error::InvalidInput);
        }
        if let IpAddr::V6(ip) = self.0.ip()
            && ip.is_unicast_link_local()
        {
            return Err(Error::InvalidInput);
        }
        Ok(self.0.port() == 0)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Free,
    Connect,
    ReversalPlanned,
    ReversalWaiting,
    Prepared,
    Proto,
    Session,
}
/// Caller-owned metadata. Generations never wrap within the owning scope.
pub struct Slot {
    generation: u64,
    state: State,
    target: Option<EddsaPublicKey>,
    address: [u8; ADDRESS_CAPACITY],
    length: usize,
    numeric: Option<Address>,
    deadline: u64,
    outbound_key: bool,
    // Exact original pending parent, never an IP-only source association.
    reversal_parent: Option<(usize, u64)>,
}
impl Slot {
    /// Empty storage, only initialized/cleared by an exclusive new registry scope.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: 0,
            state: State::Free,
            target: None,
            address: [0; ADDRESS_CAPACITY],
            length: 0,
            numeric: None,
            deadline: u64::MAX,
            outbound_key: false,
            reversal_parent: None,
        }
    }
}
impl Default for Slot {
    fn default() -> Self {
        Self::new()
    }
}
/// Source native operation still required for an outbound admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pending {
    /// Start an actual nonblocking TCP connect; a planned future is not success.
    Connect,
    /// Admit an actual official NAT reversal request with IPv4 local/remote addresses.
    Reversal,
}
/// Process-wide identity scope and bounded caller metadata. Actual sessions,
/// buffers, original connections and connection futures remain caller-owned.
/// Retained IDs prevent resetting their original scope:
/// ```compile_fail,E0499
/// use gnunet_tcp_communicator_core::{registry::{Registry,Slot},session::Scope};
/// let mut scope=Scope::new();let mut slots=[Slot::new()];
/// let mut registry=Registry::new(&mut scope,&mut slots,false);
/// let id=registry.accepted(b"tcp-127.0.0.1:80").unwrap();drop(registry);
/// let mut next_slots=[Slot::new()];
/// let next=Registry::new(&mut scope,&mut next_slots,false);
/// assert!(next.session(id).is_err());
/// ```
/// A slot is reused only after the original Session reaches Closed, including
/// every old transport completion; all later generations reject the old tickets.
pub struct Registry<'a> {
    scope: &'a Scope,
    slots: &'a mut [Slot],
    disable_v6: bool,
}
impl<'a> Registry<'a> {
    /// Consume a unique scope borrow. Retained IDs prevent safe reset of this same
    /// scope; independent same-valued markers are distinguished by pointer identity.
    #[must_use]
    pub fn new(scope: &'a mut Scope, slots: &'a mut [Slot], disable_v6: bool) -> Self {
        for s in slots.iter_mut() {
            *s = Slot::new();
        }
        Self {
            scope,
            slots,
            disable_v6,
        }
    }
    fn current(&self, id: Instance<'_>) -> bool {
        core::ptr::eq(self.scope, id.scope)
            && self
                .slots
                .get(id.slot)
                .is_some_and(|s| s.generation == id.generation && s.state != State::Free)
    }
    fn slot(&self, id: Instance<'_>) -> Result<&Slot, Error> {
        if !self.current(id) {
            return Err(Error::Stale);
        }
        Ok(&self.slots[id.slot])
    }
    fn slot_mut(&mut self, id: Instance<'_>) -> Result<&mut Slot, Error> {
        if !self.current(id) {
            return Err(Error::Stale);
        }
        Ok(&mut self.slots[id.slot])
    }
    fn reserve(
        &mut self,
        target: Option<EddsaPublicKey>,
        raw: &[u8],
        numeric: Address,
        state: State,
    ) -> Result<Instance<'a>, Error> {
        if raw.len() > ADDRESS_CAPACITY {
            return Err(Error::Capacity);
        }
        let i = self
            .slots
            .iter()
            .position(|s| s.state == State::Free && s.generation < u64::MAX)
            .ok_or(Error::Capacity)?;
        let s = &mut self.slots[i];
        let next = s.generation.checked_add(1).ok_or(Error::Capacity)?;
        s.address.fill(0);
        s.address[..raw.len()].copy_from_slice(raw);
        s.length = raw.len();
        s.target = target;
        s.numeric = Some(numeric);
        s.deadline = u64::MAX;
        s.generation = next;
        s.state = state;
        s.outbound_key = state == State::Connect;
        s.reversal_parent = None;
        Ok(Instance {
            scope: self.scope,
            slot: i,
            generation: next,
        })
    }
    /// Reserve one source outbound request. Duplicate connected/in-construction
    /// exact address+peer pairs return Conflict; no partial reservation is committed.
    /// Equivalent IPv4 reversal addresses compare by IP+peer as the source key does.
    pub fn outbound(
        &mut self,
        target: EddsaPublicKey,
        raw: &[u8],
    ) -> Result<(Instance<'a>, Pending), Error> {
        let numeric = Address::parse(raw)?;
        if self.disable_v6 && numeric.socket().is_ipv6() {
            return Err(Error::Unavailable);
        }
        let reversal = numeric.reversal()?;
        for s in self
            .slots
            .iter()
            .filter(|s| s.state != State::Free && s.target == Some(target))
        {
            if (s.outbound_key && s.address[..s.length] == *raw)
                || (reversal
                    && matches!(s.state, State::ReversalPlanned | State::ReversalWaiting)
                    && s.numeric
                        .is_some_and(|a| a.socket().ip() == numeric.socket().ip()))
            {
                return Err(Error::Conflict);
            }
        }
        let pending = if reversal {
            Pending::Reversal
        } else {
            Pending::Connect
        };
        let id = self.reserve(
            Some(target),
            raw,
            numeric,
            if reversal {
                State::ReversalPlanned
            } else {
                State::Connect
            },
        )?;
        Ok((id, pending))
    }
    /// Reserve metadata only after an actual native listener accepted this original
    /// connection. The verified peer is learned by the session's real KX.
    pub fn accepted(&mut self, raw: &[u8]) -> Result<Instance<'a>, Error> {
        let numeric = Address::parse(raw)?;
        self.reserve(None, raw, numeric, State::Proto)
    }
    /// Commit actual native connect admission (success or EINPROGRESS), never a
    /// merely constructed/unpolled future. Full peer authentication is still pending.
    pub fn connected(&mut self, id: Instance<'_>) -> Result<(), Error> {
        let s = self.slot_mut(id)?;
        if s.state != State::Connect {
            return Err(Error::Stale);
        }
        s.state = State::Prepared;
        Ok(())
    }
    /// Start the ten-second timer only after the actual NAT MQ admitted the request.
    pub fn reversal_admitted(&mut self, id: Instance<'_>, now: u64) -> Result<(), Error> {
        let s = self.slot_mut(id)?;
        if s.state != State::ReversalPlanned {
            return Err(Error::Stale);
        }
        let deadline = now
            .checked_add(REVERSAL_US)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Overflow)?;
        s.state = State::ReversalWaiting;
        s.deadline = deadline;
        Ok(())
    }
    /// Number of reserved parent intents, independent of physical Sessions.
    pub fn pending_reversals(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot.state, State::ReversalPlanned | State::ReversalWaiting))
            .count()
    }
    /// Check the unique unsubmitted original intent. Waiting requests cannot be
    /// submitted a second time on either the original or a replacement NAT MQ.
    pub fn reversal_planned(&self, id: Instance<'_>) -> Result<(), Error> {
        self.reversal_current(id)?;
        if self.slot(id)?.state != State::ReversalPlanned {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Check one original planned/waiting IPv4 reversal without granting native
    /// or authentication success. Foreign or reused generations are rejected.
    pub fn reversal_current(&self, id: Instance<'_>) -> Result<(), Error> {
        let s = self.slot(id)?;
        if !matches!(s.state, State::ReversalPlanned | State::ReversalWaiting)
            || !s
                .numeric
                .is_some_and(|a| a.socket().is_ipv4() && a.socket().port() == 0)
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Reserve a distinct outbound-role proto slot for an actual probe socket.
    /// A claimed identity is only a selector: the original pending parent stays
    /// waiting until the child/another exact connection really verifies its KX.
    pub fn reversal_probe(
        &mut self,
        parent: Instance<'_>,
        raw: &[u8],
        now: u64,
    ) -> Result<Instance<'a>, Error> {
        let p = self.slot(parent)?;
        if p.state != State::ReversalWaiting || now >= p.deadline {
            return Err(Error::Deadline);
        }
        let remote = Address::parse(raw)?;
        if !remote.socket().is_ipv4()
            || p.numeric
                .is_none_or(|a| a.socket().ip() != remote.socket().ip())
        {
            return Err(Error::Authentication);
        }
        let target = p.target.ok_or(Error::Authentication)?;
        let child = self.reserve(Some(target), raw, remote, State::Prepared)?;
        self.slots[child.slot].reversal_parent = Some((parent.slot, parent.generation));
        Ok(child)
    }
    /// Consume only this exact still-live pending IP+PID/generation after the
    /// real session reached Established after its original replay/challenge checks.
    /// An anonymous proto failure or an expired/reused parent cannot cancel another request.
    /// A normal authenticated connection with the same IP+PID can satisfy it too.
    pub fn reversal_authenticated(
        &mut self,
        parent: Instance<'_>,
        session: &Session<'_>,
        now: u64,
    ) -> Result<(), Error> {
        if session.phase() != Phase::Established {
            return Err(Error::NotReady);
        }
        let peer = session.authenticated_target().ok_or(Error::NotReady)?;
        let c = self.slot(session.instance())?;
        if c.state != State::Session {
            return Err(Error::Stale);
        }
        if c.reversal_parent
            .is_some_and(|r| r != (parent.slot, parent.generation))
        {
            return Err(Error::Stale);
        }
        let remote = c.numeric.ok_or(Error::Stale)?.socket().ip();
        let p = self.slot(parent)?;
        if p.state != State::ReversalWaiting || now >= p.deadline {
            return Err(Error::Deadline);
        }
        if p.target != Some(peer) || p.numeric.is_none_or(|a| a.socket().ip() != remote) {
            return Err(Error::Authentication);
        }
        self.slots[parent.slot].state = State::Free;
        Ok(())
    }
    /// Release only an original unbound planned/waiting request. No native NAT
    /// cancellation, socket close or other same-IP peer cancellation is implied.
    pub fn cancel_reversal(&mut self, id: Instance<'_>) -> Result<(), Error> {
        self.reversal_current(id)?;
        self.slots[id.slot].state = State::Free;
        Ok(())
    }
    /// Retire unbound requests when the whole original Pool closes. Actual NAT
    /// source retirement remains the enclosing owner's separate obligation.
    pub fn cancel_reversals(&mut self) -> usize {
        let mut count = 0;
        for slot in &mut *self.slots {
            if matches!(slot.state, State::ReversalPlanned | State::ReversalWaiting) {
                slot.state = State::Free;
                count += 1;
            }
        }
        count
    }
    /// Match the source IP+target-PID key to an actual received reversal connection.
    /// Calling this is not authentication: the subsequent KX must verify that peer.
    pub fn reversed(
        &mut self,
        peer: EddsaPublicKey,
        remote: IpAddr,
    ) -> Result<Instance<'a>, Error> {
        let i = self
            .slots
            .iter()
            .position(|s| {
                s.state == State::ReversalWaiting
                    && s.target == Some(peer)
                    && s.numeric.is_some_and(|a| a.socket().ip() == remote)
            })
            .ok_or(Error::NotFound)?;
        self.slots[i].state = State::Prepared;
        self.slots[i].deadline = u64::MAX;
        Ok(Instance {
            scope: self.scope,
            slot: i,
            generation: self.slots[i].generation,
        })
    }
    /// Expire one real scheduled source reversal timer. No native socket or callback
    /// exists for this pending NAT request, so no fictitious close effect is emitted.
    pub fn expire(&mut self, now: u64) -> Option<Instance<'a>> {
        let i = self.slots.iter().position(|s| {
            s.state == State::ReversalWaiting && s.deadline != u64::MAX && now >= s.deadline
        })?;
        let id = Instance {
            scope: self.scope,
            slot: i,
            generation: self.slots[i].generation,
        };
        self.slots[i].state = State::Free;
        Some(id)
    }
    /// Abort only an unbound native admission after the host physically dropped its
    /// own original failed attempt/socket. Live session cleanup cannot use this port.
    pub fn failed(&mut self, id: Instance<'_>) -> Result<(), Error> {
        let s = self.slot_mut(id)?;
        if s.state == State::Session {
            return Err(Error::Conflict);
        }
        s.state = State::Free;
        Ok(())
    }
    /// Copy only the session's actually signature-verified initial identity into
    /// the current original metadata. This does not certify replay/queue admission.
    pub fn authenticated(&mut self, session: &Session<'_>) -> Result<(), Error> {
        let peer = session.authenticated_target().ok_or(Error::NotReady)?;
        let s = self.slot_mut(session.instance())?;
        if s.state != State::Session {
            return Err(Error::Stale);
        }
        if s.target.is_some() && s.target != Some(peer) {
            return Err(Error::Authentication);
        }
        s.target = Some(peer);
        Ok(())
    }
    /// Release a physical session slot only after actual native/service cleanup and
    /// every original transport completion drained in that exact session.
    pub fn retire(&mut self, session: &Session<'_>) -> Result<(), Error> {
        let s = self.slot_mut(session.instance())?;
        if s.state != State::Session || session.phase() != Phase::Closed {
            return Err(Error::WouldBlock);
        }
        s.state = State::Free;
        Ok(())
    }
    /// Current exact address/peer metadata; borrowing it prevents slot mutation.
    pub fn address(&self, id: Instance<'_>) -> Result<&[u8], Error> {
        let s = self.slot(id)?;
        Ok(&s.address[..s.length])
    }
    /// Original target, updated for inbound only by authenticated(session).
    pub fn target(&self, id: Instance<'_>) -> Result<Option<EddsaPublicKey>, Error> {
        Ok(self.slot(id)?.target)
    }
    /// Reserve the unique constructor right after actual connect/accept admission.
    /// Copying Instance cannot mint a second right. No socket is fabricated here.
    pub fn session(&mut self, id: Instance<'a>) -> Result<Admission<'a>, Error> {
        let s = self.slot_mut(id)?;
        if !matches!(s.state, State::Prepared | State::Proto) {
            return Err(Error::NotReady);
        }
        s.state = State::Session;
        Ok(Admission {
            instance: id,
            target: s.target,
        })
    }
    /// Cancel the original unused/returned constructor right after physically
    /// dropping its original native resource. A live Session owns this right
    /// instead and can only retire after all its cleanup and callbacks finish.
    pub fn cancel(
        &mut self,
        admission: Admission<'a>,
    ) -> Result<(), gnunet_types::Rejected<Admission<'a>>> {
        let s = match self.slot_mut(admission.instance) {
            Ok(s) => s,
            Err(reason) => {
                return Err(gnunet_types::Rejected {
                    reason,
                    value: admission,
                });
            }
        };
        if s.state != State::Session {
            return Err(gnunet_types::Rejected {
                reason: Error::Stale,
                value: admission,
            });
        }
        s.state = State::Free;
        Ok(())
    }
    /// Number of actual reserved/live bounded metadata slots, not authenticated peers.
    #[must_use]
    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|s| s.state != State::Free).count()
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Generation exhaustion regression asserts exact bounded counter behavior"
    )]
    use super::*;
    #[test]
    fn generation_max_retires_only_its_slot_and_never_wraps() -> Result<(), Error> {
        let mut scope = Scope::new();
        let mut slots = [Slot::new(), Slot::new()];
        let mut r = Registry::new(&mut scope, &mut slots, false);
        r.slots[0].generation = u64::MAX;
        r.slots[1].generation = u64::MAX - 1;
        let id = r.accepted(b"tcp-127.0.0.1:5")?;
        assert_eq!(id.slot, 1);
        assert_eq!(id.generation, u64::MAX);
        r.failed(id)?;
        assert_eq!(r.accepted(b"tcp-127.0.0.1:6"), Err(Error::Capacity));
        assert_eq!(r.occupied(), 0);
        assert_eq!(r.slots[0].generation, u64::MAX);
        assert_eq!(r.slots[1].generation, u64::MAX);
        Ok(())
    }
}
