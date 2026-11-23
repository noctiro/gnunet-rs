use gnunet_types::Error;
use std::{future::pending, net::SocketAddr};
use tokio::sync::watch;

/// An ordered network snapshot of up to 32 numeric DNS endpoints.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Upstreams(Vec<SocketAddr>);

impl Upstreams {
    /// Maximum distinct endpoints in one snapshot.
    pub const MAX_ENDPOINTS: usize = 32;

    /// Preserve address family, numeric IPv6 scope and priority. Keep only the
    /// first occurrence of an exact endpoint. An empty list revokes DNS.
    pub fn new(endpoints: impl IntoIterator<Item = SocketAddr>) -> Result<Self, Error> {
        let mut ordered = Vec::new();
        for address in endpoints {
            if address.port() == 0 || address.ip().is_unspecified() {
                return Err(Error::InvalidInput);
            }
            if ordered.contains(&address) {
                continue;
            }
            if ordered.len() >= Self::MAX_ENDPOINTS {
                return Err(Error::Capacity);
            }
            ordered.try_reserve(1).map_err(|_| Error::Capacity)?;
            ordered.push(address);
        }
        Ok(Self(ordered))
    }

    /// Configured endpoints in preferred attempt order.
    pub fn as_slice(&self) -> &[SocketAddr] {
        &self.0
    }

    /// Transfer the validated endpoints in their preferred order.
    pub fn into_endpoints(self) -> Vec<SocketAddr> {
        self.0
    }
}

/// Thread-safe producer for the latest original DNS network snapshot.
#[derive(Clone)]
pub struct UpstreamUpdates(watch::Sender<Option<Upstreams>>);

impl UpstreamUpdates {
    /// Publish the latest snapshot, even when it reuses the previous network's
    /// addresses. Success at this boundary is submission only.
    pub fn replace(&self, upstreams: Upstreams) {
        let _previous = self.0.send_replace(Some(upstreams));
    }
}

/// Receiver owned by the embedded Resolver. Default keeps its startup inputs.
#[derive(Default)]
pub struct UpstreamChanges(Option<watch::Receiver<Option<Upstreams>>>);

impl UpstreamChanges {
    pub(super) fn take_pending(&mut self) -> Option<Upstreams> {
        self.0.as_mut()?.borrow_and_update().clone()
    }

    pub(super) async fn next(&mut self) -> Upstreams {
        while let Some(receiver) = &mut self.0 {
            if receiver.changed().await.is_err() {
                self.0 = None;
            } else if let Some(snapshot) = receiver.borrow_and_update().clone() {
                return snapshot;
            }
        }
        pending().await
    }
}

/// Create an initially unfixed, coalescing port for one embedded Resolver.
pub fn upstream_updates() -> (UpstreamUpdates, UpstreamChanges) {
    let (send, receive) = watch::channel(None);
    (UpstreamUpdates(send), UpstreamChanges(Some(receive)))
}
