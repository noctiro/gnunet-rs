//! Original TCP application flow, bounded operations and independent half-closes.
use super::{
    callback::{Callback, thread_safe},
    input::FlowId,
    lifetime::{self, Pending},
    sdk::Endpoint,
};
use block2::RcBlock;
use std::{
    ffi::c_void,
    fmt, io,
    marker::PhantomData,
    net::SocketAddr,
    rc::Rc,
    sync::Mutex,
    task::{Context, Poll},
};
mod read;
#[expect(
    unsafe_code,
    reason = "Checked original TCP Objective-C flow and invocation-borrowed native read data"
)]
mod sdk;
pub use read::TcpRead;

/// Maximum copied bytes retained by one native TCP read or write operation.
pub const MAX_TCP_CHUNK_BYTES: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Unopened,
    Opening,
    Open,
    Closing,
}
/// Final callback-loan bookkeeping after both local close requests.
#[derive(Clone, Copy, Debug)]
pub struct TcpRetirement {
    failed_operations: usize,
}
impl TcpRetirement {
    /// Whether an operation or callback failed; no SDK close ACK is implied.
    pub const fn has_failure(&self) -> bool {
        self.failed_operations != 0
    }
    /// Number of failed original operations observed by polling.
    pub const fn failed_operations(&self) -> usize {
        self.failed_operations
    }
}
/// One exclusively adopted original TCP flow; all native callbacks retain their
/// own owners. It stays on its adopting thread and spawns no task or provider.
pub struct TcpFlow {
    id: FlowId,
    native: sdk::Native,
    remote: Endpoint,
    interface: Option<sdk::Interface>,
    phase: Phase,
    open: Option<Pending<()>>,
    read: Option<Pending<TcpRead>>,
    write: Option<Pending<()>>,
    read_closed: bool,
    write_closed: bool,
    read_ended: bool,
    failed_operations: usize,
    _thread: PhantomData<Rc<()>>,
    provider: Option<super::provider::ProviderLease>,
}
impl fmt::Debug for TcpFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpFlow")
            .field("id", &self.id)
            .field("phase", &self.phase)
            .field("reading", &self.read.is_some())
            .field("writing", &self.write.is_some())
            .finish_non_exhaustive()
    }
}
impl TcpFlow {
    /// Retain one unopened TCP flow from the native provider.
    ///
    /// # Safety
    /// `flow` must be a live borrowed NEAppProxyTCPFlow exclusively adopted once.
    /// The provider lifetime covers every operation and retained callback loan.
    /// No other owner may open, read, write or close this same SDK flow.
    ///
    /// # Errors
    /// Refuses unsupported selectors/endpoints, invalid zones or exhausted identity.
    #[expect(
        unsafe_code,
        reason = "Provider supplies the original live SDK object; subsequent operations retain checked typed owners"
    )]
    pub unsafe fn adopt(flow: *mut c_void) -> io::Result<Self> {
        // SAFETY: The caller supplies the exclusive SDK object and native lifetime.
        let native = unsafe { sdk::adopt(flow)? };
        let remote = sdk::remote(&native)?;
        let interface = sdk::bound_interface(&native, &remote)?;
        Ok(Self {
            id: FlowId::next()?,
            provider: None,
            native,
            remote,
            interface,
            phase: Phase::Unopened,
            open: None,
            read: None,
            write: None,
            read_closed: false,
            write_closed: false,
            read_ended: false,
            failed_operations: 0,
            _thread: PhantomData,
        })
    }
    pub(super) fn attach_provider(&mut self, lifetime: super::provider::ProviderLease) {
        self.provider = Some(lifetime);
    }
    /// A closed original flow cannot authorize another upstream connection.
    pub(super) fn upstream_endpoint(&self) -> io::Result<&Endpoint> {
        if self.phase == Phase::Closing {
            return Err(state_error("TCP flow is closed to upstream connections"));
        }
        Ok(&self.remote)
    }
    /// The private constructor lends its original unsubmitted nw_parameters_t.
    #[expect(
        unsafe_code,
        reason = "Only the private Network constructor lends its live parameters for original flow metadata/interface configuration"
    )]
    pub(super) unsafe fn configure_upstream(&self, parameters: *mut c_void) {
        // SAFETY: The private caller retains the original unsubmitted parameters.
        unsafe { sdk::configure_upstream(&self.native, self.interface.as_ref(), parameters) };
    }
    /// Non-reused original flow identity.
    pub const fn id(&self) -> FlowId {
        self.id
    }
    /// Original remote endpoint observations, including the native IPv6 zone.
    /// # Errors
    /// Refuses a native endpoint whose address cannot be represented losslessly.
    pub fn remote_addr(&self) -> io::Result<SocketAddr> {
        self.remote.socket_addr()
    }
    /// Open the flow while preserving any local endpoint the application bound.
    /// # Errors
    /// Refuses duplicate opening or admission after local close.
    pub fn begin_open(&mut self) -> io::Result<()> {
        if self.phase != Phase::Unopened {
            return Err(state_error("TCP flow cannot be opened in this state"));
        }
        let (pending, publisher, disposed) = lifetime::reserve();
        let callback = Callback::new(publisher, self.native.clone(), disposed, None, ())
            .keep_provider(self.provider.clone());
        let block = RcBlock::new(thread_safe(move |error| {
            callback.invoke(|| super::sdk::error_result(error))
        }));
        self.open = Some(pending);
        self.phase = Phase::Opening;
        sdk::open(&self.native, &block);
        Ok(())
    }
    /// Observe opening after result and callback-argument disposal.
    pub fn poll_open(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<()>>> {
        let result = poll_slot(&mut self.open, cx, &mut self.failed_operations);
        if matches!(&result, Poll::Ready(Some(Ok(())))) && self.phase == Phase::Opening {
            self.phase = Phase::Open;
        }
        result
    }
    /// Reserve one bounded chunk before submitting one native read.
    /// # Errors
    /// Refuses ended/closed/unopened reads, an existing read or invalid allocation bounds.
    pub fn begin_read(&mut self, maximum: usize) -> io::Result<()> {
        self.require_open()?;
        if self.read_closed || self.read_ended {
            return Err(state_error("TCP read direction ended"));
        }
        if self.read.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let reservation = Mutex::new(Some(read::Reservation::new(maximum)?));
        let (pending, publisher, disposed) = lifetime::reserve();
        let callback = Callback::new(publisher, self.native.clone(), disposed, None, reservation)
            .keep_provider(self.provider.clone());
        let block = RcBlock::new(thread_safe(move |data, error| {
            callback.invoke(|| {
                let reservation = callback
                    .data()
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                    .ok_or_else(|| state_error("TCP read reservation already consumed"))?;
                reservation.complete(data, error)
            })
        }));
        self.read = Some(pending);
        sdk::read(&self.native, &block);
        Ok(())
    }
    /// Observe one original chunk/EOF only after callback arguments retire.
    pub fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<TcpRead>>> {
        let result = poll_slot(&mut self.read, cx, &mut self.failed_operations);
        if matches!(&result, Poll::Ready(Some(Ok(TcpRead::End)))) {
            self.read_ended = true;
        }
        result
    }
    /// Submit one copied immutable chunk without taking the caller's buffer.
    /// Callback retention survives owner/wait cancellation; the same bytes are
    /// never replayed by this owner.
    /// # Errors
    /// Refuses closed/unopened writes, an outstanding write or oversized data.
    pub fn begin_write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.require_open()?;
        if self.write_closed {
            return Err(state_error("TCP write direction closed"));
        }
        if self.write.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if bytes.len() > MAX_TCP_CHUNK_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let data = sdk::WriteData::new(bytes);
        let (pending, publisher, disposed) = lifetime::reserve();
        let callback = Callback::new(publisher, self.native.clone(), disposed, None, data.clone())
            .keep_provider(self.provider.clone());
        let block = RcBlock::new(thread_safe(move |error| {
            callback.invoke(|| super::sdk::error_result(error))
        }));
        self.write = Some(pending);
        sdk::write(&self.native, &data, &block);
        Ok(())
    }
    /// Observe a complete local application-buffer write, not application consumption.
    pub fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<()>>> {
        poll_slot(&mut self.write, cx, &mut self.failed_operations)
    }
    /// Half-close application reads once, preserving the write direction.
    pub fn close_read(&mut self) {
        if !self.read_closed {
            self.read_closed = true;
            sdk::close_read(&self.native);
        }
        self.update_closing();
    }
    /// Half-close application writes once, preserving the read direction.
    pub fn close_write(&mut self) {
        if !self.write_closed {
            self.write_closed = true;
            sdk::close_write(&self.native);
        }
        self.update_closing();
    }
    /// Close both directions without discarding callback retirement debt.
    pub fn request_close(&mut self) {
        self.close_read();
        self.close_write();
    }
    /// Observe both close requests and all original operation loans retired.
    pub fn poll_retirement(&mut self, _cx: &mut Context<'_>) -> Poll<TcpRetirement> {
        if self.phase == Phase::Closing
            && self.open.is_none()
            && self.read.is_none()
            && self.write.is_none()
        {
            Poll::Ready(TcpRetirement {
                failed_operations: self.failed_operations,
            })
        } else {
            Poll::Pending
        }
    }
    fn update_closing(&mut self) {
        if self.read_closed && self.write_closed {
            self.phase = Phase::Closing;
        }
    }
    fn require_open(&self) -> io::Result<()> {
        if self.phase == Phase::Open {
            Ok(())
        } else {
            Err(state_error("TCP flow is not open"))
        }
    }
}
impl Drop for TcpFlow {
    fn drop(&mut self) {
        self.request_close();
    }
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
