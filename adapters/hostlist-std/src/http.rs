//! Thin actual HOSTLIST GET owner over the reusable mature HTTP host. All
//! transport sockets/proxies/TLS/DNS/deadlines live in the independent layer.
use crate::{Error, Fault, Fetch};
use gnunet_client_host::resolution::SharedResolution;
pub(crate) use gnunet_http_host::bounded_io::{Counted, Counters, IoLease};
pub use gnunet_http_host::{HttpLimits, Proxy, ProxyKind, SocketDiagnostic, Tls, WireReport};
use std::{
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;
use zeroize::Zeroizing;

/// Keep the official HOSTLIST URL cap while using the same mature URL parser.
pub fn validate_uri(input: &[u8]) -> Result<url::Url, Error> {
    if input.len() > gnunet_hostlist::URL_BYTES {
        return Err(Fault::Capacity.into());
    }
    Ok(gnunet_http_host::validate_uri(input)?)
}
/// Original complete GET body. Actual native bytes remain distinct from verified
/// HELLOs, real PEERSTORE results and downstream processing.
pub struct Download {
    /// Bounded original body, still requiring actual HELLO validation.
    pub body: Zeroizing<Vec<u8>>,
    /// Actual final2xx status.
    pub status: u16,
    /// Actual safe GET redirects under the same original request.
    pub redirects: usize,
    /// Exact original native byte/probe counts.
    pub wire: WireReport,
    /// Actual original nonfatal socket initialization warnings.
    pub diagnostics: Vec<SocketDiagnostic>,
}
impl std::fmt::Debug for Download {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostlistDownload")
            .field("bytes", &self.body.len())
            .field("status", &self.status)
            .field("redirects", &self.redirects)
            .field("wire", &self.wire)
            .finish()
    }
}
/// Original HOSTLIST Job bound to one actual general transport request owner.
/// A new HTTP source cannot be rebound to this immutable Fetch after loss.
pub struct DownloadJob {
    fetch: Fetch,
    client: gnunet_http_host::Client,
}
impl DownloadJob {
    /// Admit actual safe GET; constructor performs no network/TLS IO. Every
    /// transport phase retains the original Fetch until and supplied hard cap.
    pub fn new(
        fetch: Fetch,
        resolution: SharedResolution,
        tls: Tls,
        proxy: Option<Arc<Proxy>>,
        limits: HttpLimits,
        original_hard: Instant,
    ) -> Result<Self, Error> {
        validate_uri(fetch.uri.bytes())?;
        let mut limits = limits;
        limits.uri_bytes = limits.uri_bytes.min(gnunet_hostlist::URL_BYTES);
        let domain = gnunet_http_host::Instance::new();
        let request = gnunet_http_host::Request::get(
            &domain,
            fetch.uri.bytes(),
            fetch.until,
            gnunet_http_host::Redirects::Follow,
        )?;
        let client =
            gnunet_http_host::Client::new(request, resolution, tls, proxy, limits, original_hard)?;
        Ok(Self { fetch, client })
    }
    /// Original immutable business intent and source provenance.
    pub fn fetch(&self) -> &Fetch {
        &self.fetch
    }
    /// Actual original HTTP target, retained for the PEERSTORE handoff.
    pub fn hard_deadline(&self) -> Instant {
        self.client.hard_deadline()
    }
    /// Actual raw socket bytes/probes, without a remote ACK claim.
    pub fn wire(&self) -> WireReport {
        self.client.wire()
    }
    /// Original actual warnings remain obtainable after cancellation/error.
    pub fn take_diagnostics(&mut self) -> Result<Vec<SocketDiagnostic>, Error> {
        Ok(self.client.take_diagnostics()?)
    }
    /// Physical cancellation of exactly the original connection, without clocks.
    pub fn cancel(&mut self) {
        self.client.cancel()
    }
    /// Drive real original cursors; reject non2xx as a failed HOSTLIST round.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Download, Error>> {
        match self.client.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(response)) => {
                if !(200..300).contains(&response.status) {
                    return Poll::Ready(Err(Fault::Unavailable.into()));
                }
                Poll::Ready(Ok(Download {
                    body: response.body,
                    status: response.status,
                    redirects: response.redirects,
                    wire: response.wire,
                    diagnostics: response.diagnostics,
                }))
            }
        }
    }
    /// Borrowed future drop retains the native connection/partial IO cursor.
    pub async fn drive(&mut self) -> Result<Download, Error> {
        poll_fn(|cx| self.poll(cx)).await
    }
}
