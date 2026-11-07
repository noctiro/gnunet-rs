//! Actual GNS native queries; no GNS service/resolver/recovery backend is created.
use crate::{
    Context, Error, OwnedRequest, Response,
    output::{Json, copy},
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_gns_client_host::{BoundedClient, Instance, LocalOptions, Parameters, Progress};
use gnunet_gnsrecord::{RecordType, ZoneKey};
use gnunet_identity_client_host::{Lookup, LookupOutcome, LookupProgress};
use gnunet_types::Error as Fault;
use std::future::poll_fn;
use tokio::time::Instant;
use zeroize::Zeroizing;
/// Explicit existing GNS query endpoint/configuration, with independent native
/// capacity. Construction opens no socket and owns no hidden Resolver.
pub struct Gns {
    source: EndpointSource,
    configuration: LiveConfiguration,
    limits: gnunet_gns_client_host::Limits,
}
pub(crate) struct Frozen {
    source: EndpointSource,
    configuration: gnunet_config::Configuration,
    limits: gnunet_gns_client_host::Limits,
}
impl Gns {
    /// Retain only caller-supplied native query authority and original mapping cfg.
    pub fn new(
        source: EndpointSource,
        configuration: LiveConfiguration,
        limits: gnunet_gns_client_host::Limits,
    ) -> Self {
        Self {
            source,
            configuration,
            limits,
        }
    }
    pub(crate) fn freeze_with(
        &self,
        sources: &crate::Sources,
    ) -> Result<(crate::Sources, Frozen), Error> {
        let [identity, namestore, reclaim, source] = EndpointSource::snapshot_all([
            &sources.identity,
            &sources.namestore,
            &sources.reclaim,
            &self.source,
        ])?;
        let configuration = match source.configuration_snapshot()? {
            Some(cfg) => cfg,
            None => self.configuration.snapshot()?,
        };
        Ok((
            crate::Sources {
                identity,
                namestore,
                reclaim,
            },
            Frozen {
                source,
                configuration,
                limits: self.limits,
            },
        ))
    }
    /// Exact source clock, for Context attachment domain checks.
    pub fn clock(&self) -> std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.source.clock()
    }
}
impl<I: gnunet_dns::Idna> Context<'_, I> {
    pub(crate) async fn gns(
        &self,
        request: OwnedRequest,
        port: &Frozen,
        until: u64,
        hard: Instant,
    ) -> Result<Response, Error> {
        if request.suffix.is_empty() {
            return Err(Error::GnsNotFound);
        }
        let name = request.suffix.as_slice();
        let kind = request
            .query(b"record_type", self.limits.bytes)?
            .and_then(|t| {
                std::str::from_utf8(&t)
                    .ok()
                    .and_then(gnunet_gnsrecord_text::typename_to_number)
            })
            .unwrap_or(RecordType::ANY);
        let config = &port.configuration;
        let (zone, relative, options) = if let Some(at) = name
            .iter()
            .rposition(|b| *b == b'.')
            .map(|p| p + 1)
            .or(Some(0))
            .filter(|at| {
                ZoneKey::from_ztld(std::str::from_utf8(&name[*at..]).unwrap_or("")).is_ok()
            }) {
            let zone = ZoneKey::from_ztld(
                std::str::from_utf8(&name[at..]).map_err(|_| Fault::Malformed)?,
            )?;
            (zone, eat(name, at)?, LocalOptions::DEFAULT)
        } else if let Some((zone, at)) = configured(config, name)? {
            (zone, eat(name, at)?, LocalOptions::DEFAULT)
        } else {
            // This is the actual official IDENTITY suffix lookup, not a fabricated
            // default zone and not a replay of an old monitor or lost provider source.
            let mut lookup = Lookup::by_suffix(
                self.instances.identity,
                self.sources.identity.duplicate()?,
                name,
                until,
                self.limits.identity,
            )?;
            let identity = loop {
                match poll_fn(|cx| lookup.poll(cx, Some(hard))).await? {
                    LookupProgress::Finished {
                        outcome: LookupOutcome::Found(identity),
                        ..
                    } => break identity,
                    LookupProgress::Finished {
                        outcome: LookupOutcome::ResultCode(200),
                        ..
                    } => return Err(Error::GnsNotFound),
                    LookupProgress::Finished {
                        outcome: LookupOutcome::ResultCode(code),
                        ..
                    } => return Err(Error::Service(code)),
                    LookupProgress::Finished {
                        outcome:
                            LookupOutcome::Local {
                                reason,
                                submission,
                                result_code,
                            },
                        ..
                    } => {
                        return Err(Error::IdentityRetired {
                            reason,
                            submission,
                            result_code,
                        });
                    }
                    LookupProgress::Source(gnunet_identity_client_host::Progress::Lost {
                        cause,
                        ..
                    }) => return Err(Error::IdentitySource(cause)),
                    LookupProgress::Source(gnunet_identity_client_host::Progress::Unavailable(
                        error,
                    )) => return Err(Error::Native(error)),
                    LookupProgress::Source(
                        gnunet_identity_client_host::Progress::ConnectRetry { error, .. },
                    ) => return Err(Error::Io(error)),
                    LookupProgress::Source(gnunet_identity_client_host::Progress::WaitDeadline) => {
                        return Err(Error::Deadline);
                    }
                    LookupProgress::Closed => return Err(Error::SourceLost),
                    _ => {}
                }
            };
            let suffix = identity.name();
            if !name.ends_with(suffix)
                || (name.len() > suffix.len() && name[name.len() - suffix.len() - 1] != b'.')
            {
                return Err(Fault::Malformed.into());
            }
            let at = name.len() - suffix.len();
            let relative = eat(name, at)?;
            let options = if relative.contains(&b'.') {
                LocalOptions::LOCAL_MASTER
            } else {
                LocalOptions::NO_DHT
            };
            (
                ZoneKey::from_wire(&identity.public_key()?)?,
                relative,
                options,
            )
        };
        // The instance and MQ stay inside this one consuming request future. None of
        // their tokens escapes or can be rebound to a later HTTP slot/source.
        let mut instance = Instance::new();
        let mut client =
            BoundedClient::<1, 252>::new(&mut instance, port.source.duplicate()?, port.limits)?;
        let query = client.lookup(
            Parameters {
                zone,
                options,
                recursion_depth: 128,
                record_type: kind,
            },
            &relative,
        )?;
        loop {
            match client.drive(Some(hard)).await? {
                Progress::Answer(answer) if answer.query() == query => {
                    let records = answer.result()?.records();
                    let mut json = Json::new(self.limits.output_bytes)?;
                    if records.is_empty() {
                        json.raw(b"{\"record_name\":")?;
                        json.string(name)?;
                        json.raw(b",\"data\":[]}")?;
                    } else {
                        let count = u16::try_from(records.len()).map_err(|_| Fault::TooLarge)?;
                        let records = gnunet_namestore_client_host::ipc::Records::new(
                            records.record_bytes(),
                            count,
                        )?;
                        if !self.record_json(&mut json, name, records, None)? {
                            return Err(Fault::Malformed.into());
                        }
                    }
                    let _physical_close = client.close();
                    return Ok(Response::json(json.bytes));
                }
                Progress::Lost { cause, .. } => {
                    let _physical_close = client.close();
                    return Err(Error::GnsSource(cause));
                }
                Progress::Refused { reason, .. } => return Err(reason.into()),
                Progress::ConnectRetry { error, .. } => return Err(Error::Io(error)),
                Progress::Unavailable(error) => return Err(Error::Native(error)),
                Progress::Capacity(_) => return Err(Fault::Capacity.into()),
                Progress::WaitDeadline => return Err(Error::Deadline),
                Progress::Closed => return Err(Error::SourceLost),
                _ => {}
            }
        }
    }
}
fn eat(name: &[u8], suffix_at: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    if suffix_at == 0 {
        copy(b"@")
    } else {
        let end = suffix_at.checked_sub(1).ok_or(Fault::Malformed)?;
        if name.get(end) != Some(&b'.') {
            return Err(Fault::Malformed.into());
        }
        copy(&name[..end])
    }
}
fn configured(
    config: &gnunet_config::Configuration,
    name: &[u8],
) -> Result<Option<(ZoneKey, usize)>, Error> {
    for at in std::iter::once(0).chain(
        name.iter()
            .enumerate()
            .filter_map(|(i, b)| (*b == b'.').then_some(i + 1)),
    ) {
        let mut key = Vec::new();
        key.try_reserve_exact(1 + name.len() - at)
            .map_err(|_| Fault::Capacity)?;
        key.push(b'.');
        key.extend_from_slice(&name[at..]);
        if let Some(text) = config.get(b"gns", &key) {
            let zone =
                ZoneKey::from_ztld(std::str::from_utf8(text).map_err(|_| Fault::Malformed)?)?;
            return Ok(Some((zone, at)));
        }
    }
    Ok(None)
}
#[cfg(feature = "oidc")]
impl Frozen {
    /// Actual native direct-zone query for the official redirect record. The
    /// original endpoint was frozen before any IDENTITY/provider admission.
    pub(crate) async fn permits_redirect(
        &self,
        zone: ZoneKey,
        uri: &[u8],
        hard: Instant,
    ) -> Result<bool, Error> {
        let mut instance = Instance::new();
        let mut client =
            BoundedClient::<1, 252>::new(&mut instance, self.source.duplicate()?, self.limits)?;
        let query = client.lookup(
            Parameters {
                zone,
                options: LocalOptions::DEFAULT,
                recursion_depth: 128,
                record_type: RecordType::RECLAIM_OIDC_REDIRECT,
            },
            b"@",
        )?;
        loop {
            match client.drive(Some(hard)).await? {
                Progress::Answer(answer) if answer.query() == query => {
                    let result = answer.result()?;
                    for record in result.records().iter() {
                        let record = record?;
                        if record.record_type == RecordType::RECLAIM_OIDC_REDIRECT {
                            let data = record.data.strip_suffix(&[0]).unwrap_or(record.data);
                            if data == uri {
                                let _close = client.close();
                                return Ok(true);
                            }
                        }
                    }
                    let _close = client.close();
                    return Ok(false);
                }
                Progress::Lost { cause, .. } => {
                    let _close = client.close();
                    return Err(Error::GnsSource(cause));
                }
                Progress::Refused { reason, .. } => return Err(reason.into()),
                Progress::ConnectRetry { error, .. } => return Err(Error::Io(error)),
                Progress::Unavailable(error) => return Err(Error::Native(error)),
                Progress::Capacity(_) => return Err(Fault::Capacity.into()),
                Progress::WaitDeadline => return Err(Error::Deadline),
                Progress::Closed => return Err(Error::SourceLost),
                _ => {}
            }
        }
    }
}
