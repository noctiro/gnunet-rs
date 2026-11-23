//! Typed native system lookup and result admission.
use super::{
    ClientId, DNS_TIMEOUT, LookupId, LookupSource, Resolver, Scratch, StoredEffect, StoredPayload,
    StoredSystemQuestion, SystemPhase,
};
use crate::pool::BytePool;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use gnunet_client::resolver::{Family, Query as ResolverQuery, Request};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::{MessageHeader, message_type};

/// Original native query and its requested address family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemQuestion<'a> {
    /// Resolve the original hostname under the system's name service policy.
    Forward {
        /// Caller-requested address family, including any native family.
        family: Family,
        /// Original UTF-8 hostname, without the IPC terminator.
        hostname: &'a str,
    },
    /// Resolve a name for the original IP address.
    Reverse(IpAddr),
}
/// Native system resolution work scoped to this lookup and its deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemQuery<'a> {
    /// Original lookup generation, also the native association identity.
    pub lookup: LookupId,
    /// Original monotonic timeout, shared with the service owner.
    pub deadline: MonoInstant,
    /// Query to submit without DNSSTUB suffix or cache processing.
    pub question: SystemQuestion<'a>,
}
/// A native result to project into the existing RESOLVER wire response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemAnswer<'a> {
    /// IPv4 address.
    V4(Ipv4Addr),
    /// IPv6 address without an interface scope.
    V6(Ipv6Addr),
    /// Reverse name without a NUL terminator.
    Name(&'a [u8]),
}

fn store_address(
    pool: &mut BytePool<'_>,
    bytes: &[u8],
    maximum: usize,
) -> Result<StoredPayload, Error> {
    if bytes.len() > maximum {
        return Err(Error::Capacity);
    }
    Ok(StoredPayload::Raw(pool.copy(bytes)?))
}

impl<'a> Resolver<'a> {
    /// Stage a request for the system's resolver, which owns search, hosts and
    /// caches. Uses the original C-string prefix without expanding the name.
    pub fn request_system(
        &mut self,
        s: &mut Scratch<'a>,
        client: ClientId,
        request: Request<'_>,
        now: MonoInstant,
    ) -> Result<Option<LookupId>, Error> {
        self.stage(s, |v, scope, _| {
            v.client(scope, client)?;
            let wire = request.id();
            let question = match request.query() {
                ResolverQuery::Forward { family, hostname } => {
                    let end = hostname
                        .iter()
                        .position(|byte| *byte == 0)
                        .unwrap_or(hostname.len());
                    let hostname = &hostname[..end];
                    if hostname.len() >= 255 {
                        v.disconnect(scope, client, Some(Error::TooLarge))?;
                        return Ok(None);
                    }
                    if hostname.is_empty() || core::str::from_utf8(hostname).is_err() {
                        v.output(client, wire, StoredPayload::End)?;
                        return Ok(None);
                    }
                    StoredSystemQuestion::Forward {
                        family,
                        hostname: v.cache.text(hostname)?,
                    }
                }
                ResolverQuery::Reverse(address) => StoredSystemQuestion::Reverse(address),
            };
            let deadline = MonoInstant(now.0.checked_add(DNS_TIMEOUT).ok_or(Error::Overflow)?);
            let source = LookupSource::System {
                question,
                phase: SystemPhase::Queued,
            };
            let lookup = v.allocate_lookup(scope, client, wire, source, deadline)?;
            v.push(StoredEffect::SystemQuery { lookup, client })?;
            Ok(Some(lookup))
        })
    }
    /// Confirm real admission of the leased system query. The host must still
    /// release its start ticket after adopting the operation.
    pub fn system_admitted(&mut self, s: &mut Scratch<'a>, id: LookupId) -> Result<(), Error> {
        self.stage(s, |v, scope, _| {
            let i = v.lookup(scope, id)?;
            let active = v.lookups[i].value.as_mut().ok_or(Error::StaleGeneration)?;
            match &mut active.source {
                LookupSource::System { phase, .. } if *phase == SystemPhase::AwaitAdmission => {
                    *phase = SystemPhase::Active;
                    Ok(())
                }
                _ => Err(Error::InvalidInput),
            }
        })
    }
    /// Retire a system start that could not be submitted and emit one END.
    /// This also consumes the original start lease.
    pub fn system_unavailable(&mut self, s: &mut Scratch<'a>, id: LookupId) -> Result<(), Error> {
        self.stage(s, |v, scope, _| {
            let active = v.active(scope, id)?;
            if !matches!(
                active.source,
                LookupSource::System {
                    phase: SystemPhase::AwaitAdmission,
                    ..
                }
            ) {
                return Err(Error::InvalidInput);
            }
            let active = v.remove_lookup(scope, id)?;
            active.source.release(&mut v.cache.pool)?;
            v.output(active.client, active.wire, StoredPayload::End)
        })
    }
    /// Deliver a completed native operation. The host runs due timeouts before
    /// delivery and retains the response if capacity prevents atomic admission.
    /// Rows and END use normal IPC output ownership and do not populate cache.
    pub fn system_result<'b>(
        &mut self,
        s: &mut Scratch<'a>,
        id: LookupId,
        answers: impl IntoIterator<Item = SystemAnswer<'b>>,
    ) -> Result<(), Error> {
        self.stage(s, |v, scope, limits| {
            let active = v.active(scope, id)?;
            v.client(scope, active.client)?;
            let LookupSource::System {
                phase: SystemPhase::Active,
                question,
            } = active.source
            else {
                return Err(Error::StaleGeneration);
            };
            let active = v.remove_lookup(scope, id)?;
            active.source.release(&mut v.cache.pool)?;
            for answer in answers {
                let payload = match (question, answer) {
                    (
                        StoredSystemQuestion::Forward {
                            family: Family::Any | Family::V4,
                            ..
                        },
                        SystemAnswer::V4(address),
                    ) => store_address(
                        &mut v.cache.pool,
                        &address.octets(),
                        limits.max_record_bytes,
                    )?,
                    (
                        StoredSystemQuestion::Forward {
                            family: Family::Any | Family::V6,
                            ..
                        },
                        SystemAnswer::V6(address),
                    ) => store_address(
                        &mut v.cache.pool,
                        &address.octets(),
                        limits.max_record_bytes,
                    )?,
                    (StoredSystemQuestion::Reverse(_), SystemAnswer::Name(name))
                        if !name.is_empty() && !name.contains(&0) =>
                    {
                        let size = name.len().checked_add(9).ok_or(Error::Overflow)?;
                        MessageHeader::from_total_size(message_type::RESOLVER_RESPONSE, size)?;
                        StoredPayload::Hostname(v.cache.text(name)?)
                    }
                    _ => return Err(Error::InvalidInput),
                };
                v.output(active.client, active.wire, payload)?;
            }
            v.output(active.client, active.wire, StoredPayload::End)
        })
    }
}
