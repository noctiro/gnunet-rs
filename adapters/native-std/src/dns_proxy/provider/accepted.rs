//! Exclusive, original incoming flow loans; no native pointer escapes publicly.
use super::{ProviderLease, native::NativeIncoming};
use crate::dns_proxy::{TcpFlow, UdpFlow};
use std::{fmt, io};

/// Original transport loan accepted by the native DNS provider.
#[derive(Debug)]
pub enum AcceptedFlow {
    /// One unopened UDP flow, retained before the native callback returned YES.
    Udp(UdpFlowLoan),
    /// One unopened TCP flow requiring a bounded byte relay.
    Tcp(TcpFlowLoan),
}
/// Exclusive unopened UDP flow. Dropping it closes both native directions.
pub struct UdpFlowLoan {
    pub(super) native: NativeIncoming,
    pub(super) lease: ProviderLease,
}
impl UdpFlowLoan {
    /// Adopt this original flow on the current Rust owner thread.
    /// # Errors
    /// Preserves native adoption/capability errors; failure closes this flow.
    #[expect(
        unsafe_code,
        reason = "Consumes the unique SDK-delivered UDP loan and transfers its checked reference to the thread-confined flow owner"
    )]
    pub fn adopt(mut self) -> io::Result<UdpFlow> {
        // SAFETY: NativeIncoming retained the unopened SDK-delivered UDP object
        // once, before acceptance. This non-cloneable loan is its sole adopter.
        let mut flow = unsafe { UdpFlow::adopt(self.native.as_ptr())? };
        flow.attach_provider(self.lease.clone());
        self.native.disarm();
        Ok(flow)
    }
}
impl fmt::Debug for UdpFlowLoan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UdpFlowLoan")
    }
}
/// Exclusive unopened TCP flow. Dropping it closes both native directions.
pub struct TcpFlowLoan {
    pub(super) native: NativeIncoming,
    pub(super) lease: ProviderLease,
}
impl TcpFlowLoan {
    /// Adopt this original flow on the current Rust owner thread.
    /// # Errors
    /// Preserves native adoption/capability errors; failure closes this flow.
    #[expect(
        unsafe_code,
        reason = "Consumes the unique SDK-delivered TCP loan and transfers its checked reference to the thread-confined flow owner"
    )]
    pub fn adopt(mut self) -> io::Result<TcpFlow> {
        // SAFETY: The native provider checked and retained this original TCP
        // flow before YES; this unique loan has never opened or adopted it.
        let mut flow = unsafe { TcpFlow::adopt(self.native.as_ptr())? };
        flow.attach_provider(self.lease.clone());
        self.native.disarm();
        Ok(flow)
    }
}
impl fmt::Debug for TcpFlowLoan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TcpFlowLoan")
    }
}
