//! Actual per-call official GNS/IDENTITY clients and shared Resolver retirement.
use crate::{Completion, Error, Family, Limits, Outcome, Report};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_gns_client_host as gns;
use gnunet_gns_host::tld;
use gnunet_identity_client_host as identity;
use gnunet_program_host::shared_clock::SharedClock;
use gnunet_resolver_broker::{BrokerError, Driver, DriverEvent};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    task::Poll,
    time::Instant as NativeInstant,
};
use tokio::time::Instant;

fn gate(hard: NativeInstant) -> Result<(), Error> {
    if NativeInstant::now() >= hard {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}
fn prepare(
    name: &[u8],
    hard: NativeInstant,
) -> Result<(Vec<u8>, gnunet_config::Configuration), Error> {
    gate(hard)?;
    let mut scratch = gnunet_idna::Workspace::new();
    let mut work = [0u8; 1020];
    {
        let idna = gnunet_idna::Backend::new(
            &mut scratch,
            gnunet_idna::Limits::GNUNET,
            gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        gnunet_dns::check_name(name, &idna, &mut work, gnunet_dns::Limits::DNS)?;
    }
    gate(hard)?;
    let size = gnunet_idna::to_unicode(name, &mut work, &mut scratch, gnunet_idna::Limits::GNUNET)
        .map_err(Error::Idna)?;
    gate(hard)?;
    let mut converted = Vec::new();
    converted
        .try_reserve_exact(size)
        .map_err(|_| Fault::Capacity)?;
    converted.extend_from_slice(&work[..size]);
    let project = Arc::new(gnunet_config::ProjectData::default());
    let selected = project
        .default_filename(&gnunet_config::ProcessEnvironment)
        .map_err(Error::Configuration)?;
    gate(hard)?;
    let mut configuration = gnunet_config::Configuration::create(project, Default::default())
        .map_err(Error::Configuration)?;
    configuration
        .load(selected.as_deref())
        .map_err(Error::Configuration)?;
    gate(hard)?;
    Ok((converted, configuration))
}

pub(crate) fn worker(
    name: Vec<u8>,
    family: Family,
    limits: Limits,
    hard: NativeInstant,
) -> Completion {
    let (name, configuration) = match prepare(&name, hard) {
        Ok(v) => v,
        Err(e) => return Completion::failed(e),
    };
    if let Err(e) = gate(hard) {
        return Completion::failed(e);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(v) => v,
        Err(e) => return Completion::failed(Error::Io(e)),
    };
    let mut done = runtime.block_on(run(name, configuration, family, limits, hard));
    done.report.runtime_created = true;
    drop(runtime);
    done.report.runtime_dropped = true;
    done
}

fn retain<T>(slot: &mut Option<T>, value: T, omitted: &mut u64) {
    if slot.is_none() {
        *slot = Some(value);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}
fn native_errors(driver: &mut Driver<8, 64>, report: &mut Report) {
    if let Some(e) = driver.take_io_error() {
        retain(&mut report.resolver_io, e, &mut report.omitted_errors);
    }
    if let Some(e) = driver.take_connect_error() {
        retain(&mut report.resolver_connect, e, &mut report.omitted_errors);
    }
}

async fn run(
    name: Vec<u8>,
    configuration: gnunet_config::Configuration,
    family: Family,
    limits: Limits,
    hard: NativeInstant,
) -> Completion {
    let mut done = Completion {
        outcome: Outcome::Unavailable,
        report: Report::default(),
    };
    let setup = (|| {
        gate(hard)?;
        let shared = SharedClock::native(32).map_err(Error::Clock)?;
        let clock: Arc<dyn RuntimeClock> = Arc::new(shared);
        gate(hard)?;
        let now = clock.sample().map_err(Error::Clock)?.now.as_micros();
        gate(hard)?;
        let remaining = u64::try_from(
            hard.saturating_duration_since(NativeInstant::now())
                .as_micros(),
        )
        .map_err(|_| Fault::Overflow)?;
        let until = now
            .checked_add(remaining)
            .filter(|v| *v != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let live = LiveConfiguration::new(configuration.duplicate().map_err(Error::Configuration)?);
        let (context, driver) = gnunet_resolver_broker::broker::<8, 64>(
            live.clone(),
            Default::default(),
            gnunet_resolver_broker::native_profile()?,
            clock,
        )
        .map_err(Error::Resolver)?;
        Ok::<_, Error>((until, live, context, driver))
    })();
    let (until, live, context, mut driver) = match setup {
        Ok(v) => v,
        Err(e) => return Completion::failed(e),
    };
    let operation = async {
        gate(hard)?;
        let resolution =
            crate::bootstrap::context(&configuration, context.resolution_context(), hard)?;
        let sources = tld::Sources {
            gns: EndpointSource::live(live.clone(), b"gns", resolution.clone()),
            identity: EndpointSource::live(live, b"identity", resolution),
        };
        let mut gns_instance = gns::Instance::new();
        let identity_instance = identity::Instance::new();
        let policy = tld::Limits {
            name_bytes: 1024,
            gns: gns::Limits {
                output: gnunet_service_runtime::framing::Budget {
                    frames: 1,
                    bytes: 512,
                },
                ..Default::default()
            },
            identity: identity::Limits {
                operations: 1,
                egos: 0,
                source_bytes: 2048,
                reconnect: false,
                ..Default::default()
            },
        };
        gate(hard)?;
        let mut owner = tld::Lookup::new(
            &mut gns_instance,
            &identity_instance,
            sources,
            &configuration,
            tld::Request {
                name: &name,
                record_type: match family {
                    Family::V4 => gns::RecordType::A,
                    Family::V6 => gns::RecordType::AAAA,
                },
                options: gns::LocalOptions::DEFAULT,
                recursion_depth: 128,
            },
            tld::Bounds::bounded(until, Instant::from_std(hard)),
            policy,
        )
        .map_err(Error::Lookup)?;
        let result = query(
            &mut owner,
            &mut driver,
            &mut done.report,
            family,
            limits.addresses,
            hard,
        )
        .await;
        if let Some(report) = owner.cancel() {
            done.report.lookup = Some(report.into_diagnostics());
        }
        drop(owner);
        result
    }
    .await;
    match operation {
        Ok(outcome) => done.outcome = outcome,
        Err(e) => done.report.error = Some(e),
    }
    native_errors(&mut driver, &mut done.report);
    match driver.queued_frames() {
        Ok(n) => done.report.queued_before_close = Some(n),
        Err(e) => done.report.queue_error = Some(e),
    }
    match driver.disconnect() {
        Ok(()) => done.report.resolver_disconnected = true,
        Err(e) => done.report.disconnect_error = Some(e),
    }
    native_errors(&mut driver, &mut done.report);
    drop(driver);
    done.report.driver_dropped = true;
    drop(context);
    done
}

#[expect(
    clippy::large_enum_variant,
    reason = "A turn transfers the original inline terminal reports without boxing for lint shape"
)]
enum Turn<'g, 'i> {
    Query(Result<tld::Progress<'g, 'i>, tld::Failure<'g, 'i>>),
    Resolver(Result<gnunet_resolver_broker::Progress, BrokerError>),
    Deadline,
}
async fn query(
    owner: &mut tld::Lookup<'_, '_>,
    driver: &mut Driver<8, 64>,
    report: &mut Report,
    family: Family,
    maximum: usize,
    hard: NativeInstant,
) -> Result<Outcome, Error> {
    let mut timer = std::pin::pin!(tokio::time::sleep_until(Instant::from_std(hard)));
    let mut cursor = 0;
    loop {
        let lost = Cell::new(None);
        let unavailable = Cell::new(false);
        let turn = {
            let mut driving = std::pin::pin!(driver.drive_waiting(
                Some(Instant::from_std(hard)),
                |event| match event {
                    DriverEvent::Lost { cause, .. } => lost.set(Some(cause)),
                    DriverEvent::Unavailable => unavailable.set(true),
                    _ => {}
                }
            ));
            poll_fn(|cx| {
                if let Some(e) = owner.poll_native_guard(cx) {
                    return Poll::Ready(Turn::Query(Err(e)));
                }
                if timer.as_mut().poll(cx).is_ready() || NativeInstant::now() >= hard {
                    return Poll::Ready(Turn::Deadline);
                }
                for _ in 0..2 {
                    let selected = cursor;
                    cursor ^= 1;
                    if selected == 0 {
                        if let Poll::Ready(event) = owner.poll(cx) {
                            return Poll::Ready(Turn::Query(event));
                        }
                    } else if let Poll::Ready(event) = driving.as_mut().poll(cx) {
                        return Poll::Ready(Turn::Resolver(event));
                    }
                }
                Poll::Pending
            })
            .await
        };
        native_errors(driver, report);
        if let Some(cause) = lost.get() {
            report.resolver_loss = Some(cause);
            return Err(Error::Resolver(BrokerError::Core(cause)));
        }
        if unavailable.get() {
            return Err(Error::Resolver(BrokerError::Core(Fault::Unavailable)));
        }
        match turn {
            Turn::Deadline => return Err(Error::Deadline),
            Turn::Resolver(Err(e)) => return Err(Error::Resolver(e)),
            Turn::Resolver(Ok(gnunet_resolver_broker::Progress::WaitDeadline)) => {
                return Err(Error::Deadline);
            }
            Turn::Resolver(Ok(_)) => {}
            Turn::Query(Err(failure)) => {
                let (cause, diagnostics) = failure.into_diagnostics();
                report.lookup = Some(diagnostics);
                return Err(Error::Lookup(cause));
            }
            Turn::Query(Ok(tld::Progress::Finished(tld::Outcome::NotGns { report: facts }))) => {
                report.lookup = Some(facts.into_diagnostics());
                gate(hard)?;
                return Ok(Outcome::NotGns);
            }
            Turn::Query(Ok(tld::Progress::Finished(tld::Outcome::Answer {
                answer,
                report: facts,
            }))) => {
                report.lookup = Some(facts.into_diagnostics());
                let decoded = answer.result()?;
                let mut addresses = Vec::new();
                addresses
                    .try_reserve_exact(maximum)
                    .map_err(|_| Fault::Capacity)?;
                for record in decoded.records().iter() {
                    gate(hard)?;
                    let record = record?;
                    let address = match family {
                        Family::V4 if record.record_type == gns::RecordType::A => {
                            Some(IpAddr::V4(Ipv4Addr::from(
                                <[u8; 4]>::try_from(record.data).map_err(|_| Fault::Malformed)?,
                            )))
                        }
                        Family::V6 if record.record_type == gns::RecordType::AAAA => {
                            Some(IpAddr::V6(Ipv6Addr::from(
                                <[u8; 16]>::try_from(record.data).map_err(|_| Fault::Malformed)?,
                            )))
                        }
                        _ => None,
                    };
                    if let Some(address) = address
                        && addresses.len() < maximum
                    {
                        addresses.push(address);
                    }
                }
                gate(hard)?;
                return Ok(if addresses.is_empty() {
                    Outcome::NoData
                } else {
                    Outcome::Addresses(addresses)
                });
            }
            Turn::Query(Ok(tld::Progress::Gns(gns::Progress::ConnectRetry { error, .. })))
            | Turn::Query(Ok(tld::Progress::Identity(identity::Progress::ConnectRetry {
                error,
                ..
            }))) => retain(&mut report.connect_error, error, &mut report.omitted_errors),
            Turn::Query(Ok(tld::Progress::Closed)) => return Err(Fault::Closed.into()),
            Turn::Query(Ok(_)) => {}
        }
    }
}
