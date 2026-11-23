//! One thread-confined original flow and its three bounded native operations.
use super::{
    callback::{Callback, thread_safe},
    input::{
        Destinations, FlowId, MAX_DATAGRAM_BYTES, Read, ReadLimits, ReplyEndpoint, Reservation,
    },
    lifetime::{self, Pending},
    multicast::{Admission, MulticastEvent, MulticastRequest, Relay},
    sdk::{self, Endpoint, EndpointRole, NativeFlow, WriteObjects},
};
use block2::RcBlock;
use std::{
    ffi::c_void,
    fmt, io,
    marker::PhantomData,
    rc::Rc,
    sync::Mutex,
    task::{Context, Poll},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Unopened,
    Opening,
    Open,
    Closing,
}

/// Final local bookkeeping after both close requests and all callback loans.
/// The SDK close methods return void; this is not a native close ACK or proof
/// that an application consumed any response.
#[derive(Clone, Copy, Debug)]
pub struct Retirement {
    failed_operations: usize,
    multicast_sends_accepted: usize,
}
impl Retirement {
    /// Whether an original open/read/write or callback failed.
    pub const fn has_failure(&self) -> bool {
        self.failed_operations != 0
    }
    /// Original failed-operation count; individual causes are returned by poll.
    pub const fn failed_operations(&self) -> usize {
        self.failed_operations
    }
    /// Original multicast sends confirmed by an SDK callback, including late results.
    pub const fn multicast_sends_accepted(&self) -> usize {
        self.multicast_sends_accepted
    }
    /// Every original callback result was consumed and its loans released.
    pub const fn callbacks_drained(&self) -> bool {
        true
    }
}

/// Pre-submission refusal retaining the complete original datagram and endpoint.
pub struct WriteRejected {
    error: io::Error,
    bytes: Zeroizing<Vec<u8>>,
    endpoint: ReplyEndpoint,
}
impl WriteRejected {
    /// Recover the cause and both owners. The caller must wipe the returned bytes.
    pub fn into_parts(mut self) -> (io::Error, Vec<u8>, ReplyEndpoint) {
        (self.error, std::mem::take(&mut *self.bytes), self.endpoint)
    }

    /// Discard the original owners and return the refusal. The DNS allocation
    /// is wiped before release.
    pub fn into_error(self) -> io::Error {
        self.error
    }
}
impl fmt::Debug for WriteRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteRejected")
            .field("error", &self.error)
            .field("bytes", &self.bytes.len())
            .field("flow", &self.endpoint.flow_id())
            .finish()
    }
}

/// Original Apple UDP flow, polled on its adopting Rust thread.
/// SDK callbacks retain independent references; this owner is neither Send nor
/// Sync and does not spawn threads, install a provider or run an event loop.
pub struct UdpFlow {
    id: FlowId,
    native: NativeFlow,
    local: Option<Endpoint>,
    phase: Phase,
    open: Option<Pending<()>>,
    read: Option<Pending<Read>>,
    write: Option<Pending<()>>,
    multicast: Option<Box<Relay>>,
    read_ended: bool,
    failed_operations: usize,
    multicast_sends_accepted: usize,
    _thread: PhantomData<Rc<()>>,
    provider: Option<super::provider::ProviderLease>,
}
impl fmt::Debug for UdpFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpFlow")
            .field("id", &self.id)
            .field("phase", &self.phase)
            .field("opening", &self.open.is_some())
            .field("reading", &self.read.is_some())
            .field("writing", &self.write.is_some())
            .finish_non_exhaustive()
    }
}
impl UdpFlow {
    /// Retain a flow delivered by the current native DNS provider.
    ///
    /// # Safety
    /// `flow` must be a live borrowed Objective-C NEAppProxyUDPFlow delivered to
    /// the caller's provider. It must be unopened and exclusively adopted once;
    /// no other owner may open, read, write or close it. The provider/event-loop
    /// lifetime must cover all operations and retained callback loans. This does
    /// not grant provider activation or entitlement authority.
    ///
    /// # Errors
    /// Refuses a null/wrong native class, missing modern selectors, unsupported
    /// original endpoint, or exhausted non-reused flow identities.
    #[expect(
        unsafe_code,
        reason = "The native provider supplies the live borrowed SDK flow; all subsequent public methods preserve its checked owners"
    )]
    pub unsafe fn adopt(flow: *mut c_void) -> io::Result<Self> {
        // SAFETY: The caller supplies the SDK object and exclusive native lifetime.
        let native = unsafe { sdk::adopt(flow)? };
        let local = observe_local(&native)?;
        Ok(Self {
            id: FlowId::next()?,
            native,
            local,
            phase: Phase::Unopened,
            open: None,
            read: None,
            write: None,
            multicast: None,
            read_ended: false,
            failed_operations: 0,
            multicast_sends_accepted: 0,
            _thread: PhantomData,
            provider: None,
        })
    }
    /// Original, process-unique flow identity.
    pub const fn id(&self) -> FlowId {
        self.id
    }
    pub(super) fn attach_provider(&mut self, provider: super::provider::ProviderLease) {
        self.provider = Some(provider);
    }

    /// Open the original flow, preserving a provided native local endpoint.
    /// # Errors
    /// Refuses duplicate open or admission after closing.
    pub fn begin_open(&mut self) -> io::Result<()> {
        if self.phase != Phase::Unopened {
            return Err(state_error(
                "native DNS flow cannot be opened in this state",
            ));
        }
        let (pending, publisher, disposed) = lifetime::reserve();
        let callback = Callback::new(publisher, self.native.clone(), disposed, None, ())
            .keep_provider(self.provider.clone());
        let block = RcBlock::new(thread_safe(move |error| {
            callback.invoke(|| sdk::error_result(error))
        }));
        self.open = Some(pending);
        self.phase = Phase::Opening;
        sdk::open(&self.native, self.local.as_ref(), &block);
        Ok(())
    }
    /// Observe opening once after its callback and argument loans retire.
    pub fn poll_open(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<()>>> {
        let result = poll_slot(&mut self.open, cx, &mut self.failed_operations);
        if let Poll::Ready(Some(Ok(()))) = &result
            && self.phase == Phase::Opening
        {
            // A socket without a supplied local address can acquire one during
            // the native open. Retain the resulting endpoint of this same flow
            // before any scoped read is admitted.
            match observe_local(&self.native) {
                Ok(Some(local)) => self.local = Some(local),
                Ok(None) => {}
                Err(error) => {
                    self.failed_operations = self.failed_operations.saturating_add(1);
                    self.request_close();
                    return Poll::Ready(Some(Err(error)));
                }
            }
            self.phase = Phase::Open;
        }
        result
    }
    /// Reserve a bounded result for datagrams with a unicast reply source.
    /// # Errors
    /// Refuses closed/unopened/ended flows, a pending read or invalid bounds.
    pub fn begin_read(&mut self, limits: ReadLimits) -> io::Result<()> {
        self.read_datagrams(limits, Destinations::Unicast)
    }

    /// Reserve a bounded result for unicast datagrams and multicast requests.
    ///
    /// A multicast destination carries authority to start a group exchange.
    /// A unicast reply source can only come from a subsequent native receive.
    ///
    /// # Errors
    /// Refuses closed/unopened/ended flows, a pending read or invalid bounds.
    pub fn begin_read_with_multicast(&mut self, limits: ReadLimits) -> io::Result<()> {
        self.read_datagrams(limits, Destinations::UnicastAndMulticast)
    }

    fn read_datagrams(&mut self, limits: ReadLimits, destinations: Destinations) -> io::Result<()> {
        self.require_open()?;
        if self.read_ended {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "native DNS flow read ended",
            ));
        }
        if self.read.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "native DNS read already pending",
            ));
        }
        let reservation = Mutex::new(Some(Reservation::new(limits, destinations)?));
        let (pending, publisher, disposed) = lifetime::reserve();
        let callback = Callback::new(publisher, self.native.clone(), disposed, None, reservation)
            .keep_provider(self.provider.clone());
        let id = self.id;
        let local = self.local.clone();
        let block = RcBlock::new(thread_safe(move |data, endpoints, error| {
            callback.invoke(|| {
                let reservation = callback
                    .data()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                    .ok_or_else(|| state_error("native DNS read reservation already consumed"))?;
                reservation.complete(id, local.as_ref(), data, endpoints, error)
            })
        }));
        self.read = Some(pending);
        sdk::read(&self.native, &block);
        Ok(())
    }
    /// Observe one original read and explicit per-batch refusals.
    pub fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Read>>> {
        let result = poll_slot(&mut self.read, cx, &mut self.failed_operations);
        if let Poll::Ready(Some(Ok(Read::End))) = &result {
            self.read_ended = true;
        }
        result
    }
    /// Start one original multicast exchange. Polling advances the captured
    /// datagram's send and returns replies with their actual unicast endpoints.
    ///
    /// # Errors
    /// Refuses a foreign request, an occupied group slot, a missing exact local
    /// endpoint or interface, and native setup errors.
    pub fn begin_multicast(&mut self, request: MulticastRequest) -> io::Result<()> {
        self.require_open()?;
        if request.flow_id() != self.id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "foreign native multicast request",
            ));
        }
        if self.multicast.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let local = self
            .local
            .as_ref()
            .ok_or_else(|| sdk::unsupported("multicast flow lacks its original local endpoint"))?;
        self.multicast = Some(Box::new(Relay::new(
            &self.native,
            local,
            request,
            self.provider.clone(),
        )?));
        Ok(())
    }
    /// Advance a multicast exchange through the original group and reply sources.
    /// The caller owns the deadline and decides which replies to write to the flow.
    pub fn poll_multicast(&mut self, cx: &mut Context<'_>) -> Poll<Option<MulticastEvent>> {
        self.poll_multicast_in(cx, Admission::Open)
    }

    /// Observe already submitted multicast work and retirement.
    /// This neither starts the group send nor consumes a live reply.
    pub fn poll_multicast_completions(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<MulticastEvent>> {
        self.poll_multicast_in(cx, Admission::CompletionsOnly)
    }

    /// Borrow the exact original datagram while its multicast exchange is active.
    pub fn multicast_query(&self) -> Option<&[u8]> {
        self.multicast.as_ref().and_then(|relay| relay.query())
    }

    fn poll_multicast_in(
        &mut self,
        cx: &mut Context<'_>,
        admission: Admission,
    ) -> Poll<Option<MulticastEvent>> {
        let Some(relay) = &mut self.multicast else {
            return Poll::Ready(None);
        };
        let event = relay.poll(cx, admission);
        if let Poll::Ready(MulticastEvent::Retired(receipt)) = &event {
            self.multicast = None;
            self.failed_operations = self
                .failed_operations
                .saturating_add(usize::from(receipt.has_failure()));
            self.multicast_sends_accepted = self
                .multicast_sends_accepted
                .saturating_add(usize::from(receipt.send_accepted()));
        }
        event.map(Some)
    }
    /// Cancel this original group while retaining its slot until retirement.
    pub fn cancel_multicast(&mut self) {
        if let Some(relay) = &mut self.multicast {
            relay.cancel();
        }
    }
    /// Submit one datagram through its original native flow and endpoint.
    /// The SDK owns an immutable NSData copy; the original Rust allocation is
    /// wiped before submission. A failed submitted operation never returns new reply
    /// authority. Waiting cancellation does not cancel or replay this write.
    /// # Errors
    /// Every pre-submission refusal returns both original owners unchanged.
    pub fn begin_write(
        &mut self,
        bytes: Vec<u8>,
        endpoint: ReplyEndpoint,
    ) -> Result<(), WriteRejected> {
        let check = self.require_open().and_then(|()| {
            if self.write.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "native DNS write already pending",
                ));
            }
            if endpoint.flow_id() != self.id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "foreign native DNS reply endpoint",
                ));
            }
            if bytes.len() > MAX_DATAGRAM_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "native DNS write exceeds IPC bound",
                ));
            }
            Ok(())
        });
        if let Err(error) = check {
            return Err(WriteRejected {
                error,
                bytes: Zeroizing::new(bytes),
                endpoint,
            });
        }
        let bytes = Zeroizing::new(bytes);
        let objects = WriteObjects::new(&bytes, &endpoint.endpoint);
        drop(bytes);
        let (pending, publisher, disposed) = lifetime::reserve();
        let callback = Callback::new(
            publisher,
            self.native.clone(),
            disposed,
            Some(objects.clone()),
            (),
        )
        .keep_provider(self.provider.clone());
        let block = RcBlock::new(thread_safe(move |error| {
            callback.invoke(|| sdk::error_result(error))
        }));
        self.write = Some(pending);
        // The callback keeps independent native references to these same
        // immutable arrays. Cloning their holders does not copy the DNS body.
        sdk::write(&self.native, &objects, &block);
        Ok(())
    }
    /// Observe one original write only after final callback argument disposal.
    pub fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<()>>> {
        poll_slot(&mut self.write, cx, &mut self.failed_operations)
    }
    /// Whether another original write can be submitted without replacing one.
    pub fn writable(&self) -> bool {
        self.phase == Phase::Open && self.write.is_none()
    }
    /// Close admission and request both flow directions to stop once.
    /// Pending callbacks and copied bytes remain owned until their actual release.
    pub fn request_close(&mut self) {
        if self.phase == Phase::Closing {
            return;
        }
        self.phase = Phase::Closing;
        self.cancel_multicast();
        sdk::close(&self.native);
    }
    /// Observe local retirement after all pending poll results were consumed.
    /// This does not consume or discard open/read/write results on the caller's
    /// behalf and cannot prove a void SDK close was acknowledged.
    pub fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<Retirement> {
        if self.phase != Phase::Closing {
            return Poll::Pending;
        }
        if self.multicast.is_some() {
            let _event = self.poll_multicast_completions(cx);
        }
        if self.multicast.is_none()
            && self.open.is_none()
            && self.read.is_none()
            && self.write.is_none()
        {
            Poll::Ready(Retirement {
                failed_operations: self.failed_operations,
                multicast_sends_accepted: self.multicast_sends_accepted,
            })
        } else {
            Poll::Pending
        }
    }
    fn require_open(&self) -> io::Result<()> {
        if self.phase == Phase::Open {
            Ok(())
        } else {
            Err(state_error("native DNS flow is not open"))
        }
    }
}
impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.request_close();
    }
}
fn observe_local(flow: &NativeFlow) -> io::Result<Option<Endpoint>> {
    let local = sdk::local_endpoint(flow)?;
    if let Some(local) = &local {
        local.scope_for(EndpointRole::Local)?;
    }
    Ok(local)
}
fn state_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, message)
}
fn poll_slot<T>(
    slot: &mut Option<Pending<T>>,
    cx: &mut Context<'_>,
    failed: &mut usize,
) -> Poll<Option<io::Result<T>>> {
    let Some(pending) = slot else {
        return Poll::Ready(None);
    };
    match pending.poll(cx) {
        Poll::Ready(result) => {
            if result.as_ref().is_some_and(Result::is_err) {
                *failed = failed.saturating_add(1);
            }
            *slot = None;
            Poll::Ready(result)
        }
        Poll::Pending => Poll::Pending,
    }
}
