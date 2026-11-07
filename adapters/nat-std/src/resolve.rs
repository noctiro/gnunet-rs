//! Real shared official Resolver stream. The actual callback copy is completed
//! before returning its callback lease; no private host DNS fallback exists.
use crate::{Error, deadline::Gate};
use gnunet_client_host::resolution::{AddressLookup, SharedResolution};
use gnunet_types::Error as Fault;
use std::{
    net::IpAddr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
/// Retained bounded original hostname lookup; dropping physically cancels this
/// original callback subscription using the actual Resolver owner semantics.
pub struct Lookup {
    lookup: Option<Box<dyn AddressLookup>>,
    addresses: Vec<IpAddr>,
    limit: usize,
    done: bool,
}
impl Lookup {
    /// Start the actual shared Resolver lookup, with the remaining original
    /// absolute lifetime. A missing native handle is explicit NotReady.
    pub fn start(
        resolver: &SharedResolution,
        gate: &Gate,
        hostname: &[u8],
        limit: usize,
    ) -> Result<Self, Error> {
        if !Arc::ptr_eq(&resolver.clock(), gate.clock()) {
            return Err(Fault::InvalidInput.into());
        }
        if hostname.is_empty() || hostname.contains(&0) || hostname.len() > 253 || limit == 0 {
            return Err(Fault::InvalidInput.into());
        }
        let now = gate.check()?;
        let lookup = resolver
            .lookup(hostname, Duration::from_micros(gate.bounds().expires - now))?
            .ok_or(Fault::NotReady)?;
        Ok(Self {
            lookup: Some(lookup),
            addresses: Vec::new(),
            limit,
            done: false,
        })
    }
    /// Poll at most one actual address callback. The supplied Gate must be the
    /// original operation guard and is checked before invoking provider IO.
    pub fn poll(&mut self, cx: &mut Context<'_>, gate: &mut Gate) -> Poll<Result<bool, Error>> {
        match gate.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.lookup = None;
                return Poll::Ready(Err(e));
            }
            Poll::Ready(Ok(_)) => {}
        }
        if self.done {
            return Poll::Ready(Ok(true));
        }
        let lookup = self.lookup.as_mut().ok_or(Fault::Closed)?;
        match lookup.poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.lookup = None;
                Poll::Ready(Err(e.into()))
            }
            Poll::Ready(Ok(None)) => {
                self.lookup = None;
                self.done = true;
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Ok(Some(address))) => {
                if self.addresses.len() >= self.limit {
                    self.lookup = None;
                    return Poll::Ready(Err(Fault::Capacity.into()));
                }
                if !self.addresses.contains(&address) {
                    self.addresses.try_reserve(1).map_err(|_| Fault::Capacity)?;
                    self.addresses.push(address);
                }
                lookup.address_effect_done()?;
                Poll::Ready(Ok(false))
            }
        }
    }
    /// Actual callback addresses already copied; absence of END is not hidden.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
    /// Whether the actual original END callback was received.
    pub const fn is_complete(&self) -> bool {
        self.done
    }
    /// Explicitly cancel only this original lookup and suppress late callbacks.
    pub fn cancel(&mut self) {
        self.lookup = None;
    }
}
