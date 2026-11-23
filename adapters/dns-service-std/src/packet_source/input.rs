//! Original DNS storage and private reply ownership, independent of IP framing.
use super::raw;
use crate::core;
#[cfg(target_os = "linux")]
use gnunet_native::transparent_dns::exclusion::{AdmittedDatagram, IngressObservation};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use std::{fmt, ops::Range};

/// Exact DNS bytes in original source storage, paired with their return owner.
/// Raw adapters retain a checked slice without allocating a second DNS buffer.
pub(crate) struct OriginalInput {
    storage: OwnedFrame,
    dns: Range<usize>,
    reply: ReplyOwner,
}
#[derive(Debug)]
pub(super) enum ReplyOwner {
    Raw(raw::Reply),
    #[cfg(target_os = "linux")]
    Transparent(AdmittedDatagram),
    #[cfg(windows)]
    Wfp(super::wfp::Endpoint),
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    Flow(gnunet_native::dns_proxy::ReplyEndpoint),
}
#[cfg(target_os = "linux")]
impl ReplyOwner {
    fn ingress(&self) -> Option<&IngressObservation> {
        match self {
            Self::Transparent(endpoint) => Some(endpoint.ingress()),
            Self::Raw(_) => None,
        }
    }
}
#[derive(Debug)]
pub(crate) struct InputRefusal {
    pub reason: Fault,
    pub non_dns_udp: bool,
}
impl From<Fault> for InputRefusal {
    fn from(reason: Fault) -> Self {
        Self {
            reason,
            non_dns_udp: false,
        }
    }
}
/// One original host pairing. Endpoint observations alone cannot construct it.
#[derive(Debug)]
pub(crate) struct ReplyPermit<'id> {
    source: core::Source<'id>,
    request: core::Request<'id>,
    pub(super) owner: ReplyOwner,
}
/// Original request/source identity while a native operation owns its endpoint.
#[cfg(any(windows, target_os = "macos", target_os = "ios", test))]
#[derive(Debug)]
pub(super) struct PermitIdentity<'id> {
    source: core::Source<'id>,
    request: core::Request<'id>,
}
#[cfg(any(windows, target_os = "macos", target_os = "ios", test))]
impl<'id> PermitIdentity<'id> {
    pub(super) fn with_owner(self, owner: ReplyOwner) -> ReplyPermit<'id> {
        ReplyPermit {
            source: self.source,
            request: self.request,
            owner,
        }
    }
}
impl<'id> ReplyPermit<'id> {
    #[cfg(target_os = "linux")]
    pub(crate) fn ingress(&self) -> Option<&IngressObservation> {
        self.owner.ingress()
    }
    #[cfg(any(windows, target_os = "macos", target_os = "ios", test))]
    pub(super) fn into_parts(self) -> (PermitIdentity<'id>, ReplyOwner) {
        (
            PermitIdentity {
                source: self.source,
                request: self.request,
            },
            self.owner,
        )
    }
    pub(super) fn check(&self, effect: core::Effect<'id>) -> Result<(), Fault> {
        if effect.request() != self.request
            || effect.destination() != core::Destination::Source(self.source)
        {
            return Err(Fault::StaleGeneration);
        }
        Ok(())
    }
    /// The owning backend prepares its actual output before reserving an effect.
    /// This exclusive engine borrow permits no callback between the two steps.
    pub(super) fn prepare_with(
        &self,
        engine: &mut core::Engine<'id>,
        request: core::Request<'id>,
        encode: impl FnOnce(&[u8]) -> Result<OwnedFrame, Fault>,
    ) -> Result<(core::Effect<'id>, OwnedFrame), Fault> {
        if self.request != request {
            return Err(Fault::StaleGeneration);
        }
        let output = encode(engine.payload(request)?)?;
        let effect = engine.prepare_source(request)?.effect();
        if let Err(error) = self.check(effect) {
            engine.reject_prepared(effect)?;
            return Err(error);
        }
        Ok((effect, output))
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub(crate) fn flow_id(&self) -> Option<gnunet_native::dns_proxy::FlowId> {
        match &self.owner {
            ReplyOwner::Raw(_) => None,
            ReplyOwner::Flow(endpoint) => Some(endpoint.flow_id()),
        }
    }
}
impl OriginalInput {
    /// Only checked source adapters construct storage/return-owner pairs.
    pub(super) fn checked(storage: OwnedFrame, dns: Range<usize>, reply: ReplyOwner) -> Self {
        Self {
            storage,
            dns,
            reply,
        }
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn ingress(&self) -> Option<&IngressObservation> {
        self.reply.ingress()
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub(crate) fn flow_id(&self) -> Option<gnunet_native::dns_proxy::FlowId> {
        match &self.reply {
            ReplyOwner::Raw(_) => None,
            ReplyOwner::Flow(endpoint) => Some(endpoint.flow_id()),
        }
    }
    /// Consume exact DNS bytes together with their original private return path.
    pub fn admit<'id>(
        self,
        engine: &mut core::Engine<'id>,
        source: core::Source<'id>,
        now: u64,
        until: u64,
    ) -> Result<(core::Request<'id>, ReplyPermit<'id>), InputRefusal> {
        let dns = self.storage.bytes().get(self.dns).ok_or(Fault::Malformed)?;
        let request = engine.intercept(source, core::Query::decode(dns)?, now, until)?;
        Ok((
            request,
            ReplyPermit {
                source,
                request,
                owner: self.reply,
            },
        ))
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub(super) fn flow(datagram: gnunet_native::dns_proxy::Datagram) -> Result<Self, InputRefusal> {
        core::Query::decode(datagram.bytes())?;
        let (bytes, endpoint) = datagram.into_parts();
        let len = bytes.len();
        Ok(Self::checked(
            OwnedFrame::new(bytes),
            0..len,
            ReplyOwner::Flow(endpoint),
        ))
    }
}
impl fmt::Debug for OriginalInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsOriginalInput")
            .field("bytes", &self.dns.len())
            .field("reply", &self.reply)
            .finish()
    }
}

#[cfg(test)]
mod tests;
