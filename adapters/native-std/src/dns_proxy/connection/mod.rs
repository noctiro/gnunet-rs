//! Bounded Network.framework upstream connections driven by their original owner.
use super::{
    MAX_DATAGRAM_BYTES, TcpFlow,
    callback::{Callback, thread_safe},
    lifetime::{self, Pending},
    provider::ProviderLease,
};
use block2::RcBlock;
use std::{
    fmt, io,
    marker::PhantomData,
    net::SocketAddr,
    rc::Rc,
    task::{Context, Poll},
};
use zeroize::Zeroizing;
#[expect(
    unsafe_code,
    reason = "Typed Network/libdispatch C ABI isolates retained native objects and callback-borrowed data"
)]
pub(super) mod sdk;
mod state;
mod target;
use target::Target;
#[cfg(test)]
mod tests;

#[derive(Clone)]
struct Loans {
    connection: sdk::Object,
    _queue: sdk::Dispatch,
    _provider: Option<ProviderLease>,
}
/// One bounded received fragment or datagram with its original completion facts.
pub struct Received {
    bytes: Zeroizing<Vec<u8>>,
    end: bool,
    error: Option<io::Error>,
}
impl fmt::Debug for Received {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionReceived")
            .field("bytes", &self.bytes.len())
            .field("end", &self.end)
            .field("error", &self.error)
            .finish()
    }
}
impl Received {
    /// Exact original bytes; a native error can accompany a nonempty prefix.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer bytes, TCP final-context EOF and optional original native error.
    /// The caller must wipe the returned Vec and process bytes before the error.
    pub fn into_parts(mut self) -> (Vec<u8>, bool, Option<io::Error>) {
        (std::mem::take(&mut *self.bytes), self.end, self.error)
    }
}
/// Final cancellation and callback-loan disposal of an original connection.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionRetirement {
    cancelled: bool,
    failed_operations: usize,
}
impl ConnectionRetirement {
    /// Whether cancellation was unconfirmed or an operation failed before stop.
    pub const fn has_failure(&self) -> bool {
        !self.cancelled || self.failed_operations != 0
    }
    /// Final Network.framework cancelled state was actually observed.
    pub const fn cancellation_observed(&self) -> bool {
        self.cancelled
    }
}
/// Original upstream connection with one send and one receive in flight.
/// This is neither Send nor Sync; SDK callbacks retain independent native loans.
pub struct Connection {
    loans: Loans,
    watches: state::Watches,
    target: Target,
    sending: Option<Pending<()>>,
    receiving: Option<Pending<Received>>,
    closing: bool,
    write_finished: bool,
    read_finished: bool,
    failures: usize,
    _thread: PhantomData<Rc<()>>,
}
impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkConnection")
            .field("tcp", &self.is_tcp())
            .field("closing", &self.closing)
            .finish_non_exhaustive()
    }
}
impl Connection {
    /// Start plain TCP using the flow's original retained native remote endpoint.
    /// # Errors
    /// Refuses a closed original flow or native endpoint/connection allocation errors.
    pub fn tcp(flow: &TcpFlow) -> io::Result<Self> {
        Self::tcp_owned(flow, None)
    }
    /// Start original-endpoint TCP with a provider retirement keeper reserved first.
    /// # Errors
    /// Refuses a closed original flow or native endpoint/connection allocation errors.
    pub fn tcp_in_provider(flow: &TcpFlow, lease: ProviderLease) -> io::Result<Self> {
        Self::tcp_owned(flow, Some(lease))
    }
    fn tcp_owned(flow: &TcpFlow, lease: Option<ProviderLease>) -> io::Result<Self> {
        let endpoint = flow.upstream_endpoint()?;
        let owners = sdk::create(
            std::ptr::from_ref(endpoint.object()).cast_mut().cast(),
            sdk::Transport::Tcp(flow),
        )?;
        Ok(Self::new(
            owners,
            Target::Tcp {
                flow: flow.id(),
                endpoint: endpoint.clone(),
            },
            lease,
        ))
    }
    /// Start plain UDP to one numeric unicast peer, preserving its native IPv6 zone.
    /// # Errors
    /// Refuses an invalid reply source, zero port, absent required zone or native allocation failure.
    pub fn udp(peer: SocketAddr) -> io::Result<Self> {
        Self::udp_owned(peer, None)
    }
    /// Start numeric UDP with a provider retirement keeper reserved before start.
    /// # Errors
    /// Preserves the numeric endpoint checks and native allocation failures.
    pub fn udp_in_provider(peer: SocketAddr, lease: ProviderLease) -> io::Result<Self> {
        Self::udp_owned(peer, Some(lease))
    }
    fn udp_owned(peer: SocketAddr, lease: Option<ProviderLease>) -> io::Result<Self> {
        let peer = qualify_udp_peer(peer)?;
        let endpoint = sdk::numeric_endpoint(peer)?;
        let owners = sdk::create(endpoint.raw(), sdk::Transport::Udp)?;
        Ok(Self::new(owners, Target::Udp(peer), lease))
    }
    fn new(
        (connection, queue): (sdk::Object, sdk::Dispatch),
        target: Target,
        lease: Option<ProviderLease>,
    ) -> Self {
        let loans = Loans {
            connection,
            _queue: queue,
            _provider: lease,
        };
        let watches = state::register(loans.clone());
        sdk::start(&loans.connection);
        Self {
            loans,
            watches,
            target,
            sending: None,
            receiving: None,
            closing: false,
            write_finished: false,
            read_finished: false,
            failures: 0,
            _thread: PhantomData,
        }
    }
    /// Numeric observation of the original target, never a resolution fallback.
    /// # Errors
    /// A host/service or another opaque native endpoint has no socket address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.target.peer_addr()
    }
    /// Whether TCP was constructed from this exact non-reused native flow.
    /// Equal numeric addresses or another flow cannot establish this binding.
    pub fn matches_tcp_flow(&self, flow: &TcpFlow) -> bool {
        self.target.matches_tcp_flow(flow)
    }
    /// Whether this original connection provides an ordered TCP byte stream.
    pub const fn is_tcp(&self) -> bool {
        self.target.is_tcp()
    }
    /// Observe readiness without resetting native setup or extending any deadline.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closing {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        self.watches.poll_ready(cx)
    }
    fn require_ready(&self) -> io::Result<()> {
        if self.closing || self.watches.state.ended() {
            return Err(self
                .watches
                .state
                .error()
                .unwrap_or_else(|| io::ErrorKind::NotConnected.into()));
        }
        if !self.watches.state.ready() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(())
    }
    /// Synchronously copy one bounded body, then submit one original native send.
    /// # Errors
    /// Refuses state/capacity before submission; the borrowed input remains unchanged.
    pub fn begin_send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.send(bytes, false)
    }
    /// Submit TCP FIN after earlier sends, using the same original send slot.
    /// # Errors
    /// Refuses UDP, duplicate finish and any occupied or unavailable send slot.
    pub fn begin_finish(&mut self) -> io::Result<()> {
        if !self.is_tcp() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.send(&[], true)
    }
    fn send(&mut self, bytes: &[u8], finish: bool) -> io::Result<()> {
        self.require_ready()?;
        if self.sending.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if self.write_finished {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if bytes.len() > MAX_DATAGRAM_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let data = sdk::copy_data(bytes)?;
        let (pending, publisher, disposed) = lifetime::reserve();
        let callback = Callback::new(publisher, self.loans.clone(), disposed, None, data.clone())
            .keep_provider(self.loans._provider.clone());
        let block = RcBlock::new(thread_safe(move |error| {
            callback
                .invoke(|| sdk::failure(error).map_or(Ok(()), |failure| Err(failure.into_error())))
        }));
        self.sending = Some(pending);
        self.write_finished = finish;
        sdk::send(&self.loans.connection, &data, finish, &block);
        Ok(())
    }
    /// Observe one send only after its callback-owned arguments were released.
    pub fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<()>>> {
        poll_slot(&mut self.sending, cx, self.closing, &mut self.failures)
    }
    /// Reserve one bounded stream receive or whole UDP message receive.
    /// # Errors
    /// Refuses invalid bounds, read EOF, unavailable state and an existing read.
    pub fn begin_receive(&mut self, maximum: usize) -> io::Result<()> {
        self.require_ready()?;
        if !(1..=MAX_DATAGRAM_BYTES).contains(&maximum) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self.read_finished {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if self.receiving.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let (pending, publisher, disposed) = lifetime::reserve();
        let callback = Callback::new(publisher, self.loans.clone(), disposed, None, ())
            .keep_provider(self.loans._provider.clone());
        let datagram = !self.is_tcp();
        let block = RcBlock::new(thread_safe(
            move |data, context, complete: sdk::CBool, error| {
                callback.invoke(|| {
                    let bytes = sdk::content(data, maximum)?;
                    if datagram && !complete.get() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "incomplete upstream datagram",
                        ));
                    }
                    Ok(Received {
                        bytes,
                        end: !datagram && complete.get() && sdk::final_context(context),
                        error: sdk::failure(error).map(sdk::Failure::into_error),
                    })
                })
            },
        ));
        self.receiving = Some(pending);
        sdk::receive(&self.loans.connection, maximum as u32, datagram, &block);
        Ok(())
    }
    /// Observe exact received bytes before any accompanying native read error.
    pub fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Received>>> {
        let result = poll_slot(&mut self.receiving, cx, self.closing, &mut self.failures);
        if let Poll::Ready(Some(Ok(received))) = &result {
            self.read_finished |= received.end || received.error.is_some();
            if received.error.is_some() && !self.closing {
                self.failures = self.failures.saturating_add(1);
            }
        }
        result
    }
    /// Stop admission and request native cancellation without releasing any callback loan.
    pub fn request_cancel(&mut self) {
        if !self.closing {
            self.closing = true;
            sdk::cancel(&self.loans.connection);
        }
    }
    /// Drain abandoned results after cancellation, then observe final registration disposal.
    /// No abandoned send is reported as delivered by this method.
    pub fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionRetirement> {
        if !self.closing {
            return Poll::Pending;
        }
        let _send = self.poll_send(cx);
        let _receive = self.poll_receive(cx);
        let cancellation = self.watches.poll_retirement(cx);
        if self.sending.is_none()
            && self.receiving.is_none()
            && let Poll::Ready(cancelled) = cancellation
        {
            self.loans._provider = None;
            return Poll::Ready(ConnectionRetirement {
                cancelled,
                failed_operations: self
                    .failures
                    .saturating_add(usize::from(self.watches.state.failed())),
            });
        }
        Poll::Pending
    }
}

fn qualify_udp_peer(peer: SocketAddr) -> io::Result<SocketAddr> {
    if peer.port() == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // A fixed peer must be a usable source for the replies this connection
    // receives. Multicast requires an independent per-message source owner.
    super::sdk::numeric_scope(peer, super::sdk::EndpointRole::UdpReply)?;
    Ok(peer)
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.request_cancel();
    }
}
fn poll_slot<T>(
    slot: &mut Option<Pending<T>>,
    cx: &mut Context<'_>,
    closing: bool,
    failed: &mut usize,
) -> Poll<Option<io::Result<T>>> {
    let Some(pending) = slot else {
        return Poll::Ready(None);
    };
    match pending.poll(cx) {
        Poll::Ready(result) => {
            if !closing && result.as_ref().is_some_and(Result::is_err) {
                *failed = failed.saturating_add(1);
            }
            *slot = None;
            Poll::Ready(result)
        }
        Poll::Pending => Poll::Pending,
    }
}
