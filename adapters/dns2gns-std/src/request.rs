//! One retained future owns all original native instances and request tokens.
use crate::{
    Limits, Ports, RequestError, RequestReport, Route, StopReason, VpnReport,
    budget::{Budget, check_native},
    packet,
};
use gnunet_dns::AbsoluteTime;
use gnunet_dnsstub_host as stub;
use gnunet_gns_host::tld;
use gnunet_types::Error as Fault;
use gnunet_vpn_client_host as vpn;
use std::{
    cell::Cell,
    future::poll_fn,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc,
    sync::Arc,
};
use tokio::time::Instant;

pub(crate) struct Completion {
    pub(crate) report: RequestReport,
    pub(crate) reply: Option<Vec<u8>>,
    pub(crate) budget: Option<Budget>,
}

pub(crate) async fn run(
    raw: Vec<u8>,
    ports: Arc<Ports>,
    limits: Limits,
    until: u64,
    hard: Instant,
    cancel: Rc<Cell<Option<StopReason>>>,
    mut report: RequestReport,
) -> Completion {
    let mut budget = match Budget::new(ports.clock.clone(), until, hard, cancel) {
        Ok(budget) => budget,
        Err(error) => {
            report.error = Some(error);
            return Completion {
                report,
                reply: None,
                budget: None,
            };
        }
    };
    let result = execute(raw, &ports, limits, &mut budget, &mut report).await;
    match result {
        Ok(reply) => {
            report.reply_bytes = reply.len();
            Completion {
                report,
                reply: Some(reply),
                budget: Some(budget),
            }
        }
        Err(error) => {
            report.error = Some(error);
            Completion {
                report,
                reply: None,
                budget: Some(budget),
            }
        }
    }
}
async fn execute(
    raw: Vec<u8>,
    ports: &Ports,
    limits: Limits,
    budget: &mut Budget,
    report: &mut RequestReport,
) -> Result<Vec<u8>, RequestError> {
    let now = budget.now()?;
    let query = {
        // Backend/Workspace are gone before the first await. Query owns only
        // the bounded normal name and packet bytes, never a borrowed backend.
        let mut workspace = gnunet_idna::Workspace::new();
        let backend = gnunet_idna::Backend::new(
            &mut workspace,
            gnunet_idna::Limits::GNUNET,
            limits.idna_profile,
        );
        packet::Query::parse(
            &raw,
            AbsoluteTime::from_micros(now),
            limits.packet,
            &backend,
        )
        .map_err(RequestError::Packet)?
    };
    // Query now retains the only original packet copy across awaits.
    drop(raw);
    budget.now()?;
    match select(&query, ports, limits, budget, report).await? {
        Selected::Dns => upstream(&query, ports, limits, budget, report).await,
        Selected::Gns(mut response) => {
            // Reserve bounded diagnostic rows before any allocation request.
            while let Some(need) = response.next_vpn() {
                budget.now()?;
                if report.vpn.len() >= limits.packet.maximum_records {
                    return Err(RequestError::Protocol(Fault::Capacity));
                }
                report
                    .vpn
                    .try_reserve(1)
                    .map_err(|_| RequestError::Protocol(Fault::Capacity))?;
                let id = need.id();
                let family = need.family();
                let protocol = match need.protocol() {
                    6 => vpn::Protocol::Tcp,
                    17 => vpn::Protocol::Udp,
                    other => return Err(RequestError::VpnProtocol(other)),
                };
                let target = vpn::Service {
                    peer: need.peer(),
                    descriptor: gnunet_vpn::service_descriptor(need.service()),
                    protocol,
                };
                budget.now()?;
                let now = budget.now()?;
                let lease_micros = crate::budget::duration_micros(limits.vpn_lease)
                    .map_err(RequestError::Protocol)?;
                let lease_until = now
                    .saturating_add(lease_micros)
                    .min(need.expiration().as_micros());
                if lease_until <= now {
                    return Err(RequestError::LogicalDeadline);
                }
                let (address, facts) =
                    allocate(target, family, lease_until, ports, limits, budget).await;
                report.vpn.push(facts);
                let address = address?;
                budget.now()?;
                response
                    .apply_vpn_bounded(&id, address, AbsoluteTime::from_micros(lease_until))
                    .map_err(RequestError::Packet)?;
            }
            let now = budget.now()?;
            let reply = response
                .finish(&query, AbsoluteTime::from_micros(now), limits.packet)
                .map_err(RequestError::Packet)?;
            report.skipped_records = reply.skipped;
            report.packed = Some(reply.report);
            budget.now()?;
            Ok(reply.bytes)
        }
    }
}
enum Selected {
    Gns(packet::Response),
    Dns,
}
async fn select(
    query: &packet::Query,
    ports: &Ports,
    limits: Limits,
    budget: &mut Budget,
    report: &mut RequestReport,
) -> Result<Selected, RequestError> {
    let mut gns_instance = gnunet_gns_client_host::Instance::new();
    let identity_instance = gnunet_identity_client_host::Instance::new();
    budget.now()?;
    let mut lookup = tld::Lookup::new(
        &mut gns_instance,
        &identity_instance,
        tld::Sources {
            gns: ports
                .gns
                .duplicate()
                .map_err(|error| RequestError::Lookup(tld::Cause::Gns(error)))?,
            identity: ports
                .identity
                .duplicate()
                .map_err(|error| RequestError::Lookup(tld::Cause::Identity(error)))?,
        },
        &ports.configuration,
        tld::Request {
            name: query.name(),
            record_type: gnunet_gnsrecord::RecordType::new(u32::from(query.kind().0)),
            options: gnunet_gns_client_host::LocalOptions::DEFAULT,
            recursion_depth: 128,
        },
        tld::Bounds::bounded(budget.until, budget.hard),
        limits.lookup,
    )
    .map_err(RequestError::Lookup)?;
    loop {
        let step = budget.wait(poll_fn(|cx| lookup.poll(cx))).await;
        match step {
            Err(error) => {
                report.lookup = lookup.close().map(tld::Report::into_diagnostics);
                return Err(error);
            }
            Ok(Err(failure)) => {
                let (cause, diagnostics) = failure.into_diagnostics();
                report.lookup = Some(diagnostics);
                return Err(RequestError::Lookup(cause));
            }
            Ok(Ok(tld::Progress::Finished(tld::Outcome::NotGns { report: facts }))) => {
                report.lookup = Some(facts.into_diagnostics());
                report.route = Some(Route::Dns);
                budget.now()?;
                return Ok(Selected::Dns);
            }
            Ok(Ok(tld::Progress::Finished(tld::Outcome::Answer {
                answer,
                report: facts,
            }))) => {
                report.lookup = Some(facts.into_diagnostics());
                report.route = Some(Route::Gns);
                let now = budget.now()?;
                let result = answer.result().map_err(RequestError::Protocol)?;
                report.gns_records = Some(result.records().len());
                let response = packet::Response::from_gns(
                    query,
                    result.records(),
                    AbsoluteTime::from_micros(now),
                    limits.packet,
                )
                .map_err(RequestError::Packet)?;
                drop(answer);
                budget.now()?;
                return Ok(Selected::Gns(response));
            }
            Ok(Ok(tld::Progress::Closed)) => {
                report.lookup = lookup.close().map(tld::Report::into_diagnostics);
                return Err(RequestError::Closed);
            }
            Ok(Ok(progress)) => {
                match progress {
                    tld::Progress::Gns(gnunet_gns_client_host::Progress::ConnectRetry {
                        error,
                        ..
                    }) => {
                        report.gns_connect_failures = report.gns_connect_failures.saturating_add(1);
                        if report.gns_connect_error.is_none() {
                            report.gns_connect_error = Some(error);
                        }
                    }
                    tld::Progress::Identity(
                        gnunet_identity_client_host::Progress::ConnectRetry { error, .. },
                    ) => {
                        report.identity_connect_failures =
                            report.identity_connect_failures.saturating_add(1);
                        if report.identity_connect_error.is_none() {
                            report.identity_connect_error = Some(error);
                        }
                    }
                    _ => {}
                }
                if let Err(error) = budget.yield_turn().await {
                    report.lookup = lookup.close().map(tld::Report::into_diagnostics);
                    return Err(error);
                }
            }
        }
    }
}

async fn upstream(
    query: &packet::Query,
    ports: &Ports,
    limits: Limits,
    budget: &mut Budget,
    report: &mut RequestReport,
) -> Result<Vec<u8>, RequestError> {
    // One original bounded request, one server and no shared-slot eviction.
    let mut owner = stub::DnsStub::<1, 65507, 1>::start(1, limits.packet.maximum_packet_bytes)
        .map_err(RequestError::Protocol)?;
    let result = upstream_owned(&mut owner, query, ports, limits, budget, report).await;
    report.dns_stop = Some(owner.stop());
    report.dns_stopped = true;
    result
}
async fn upstream_owned(
    owner: &mut stub::DnsStub<1, 65507, 1>,
    query: &packet::Query,
    ports: &Ports,
    limits: Limits,
    budget: &mut Budget,
    report: &mut RequestReport,
) -> Result<Vec<u8>, RequestError> {
    budget.now()?;
    owner
        .add_dns_sa(ports.upstream)
        .map_err(RequestError::Protocol)?;
    budget.now()?;
    let admitted = owner.resolve(query.raw()).map_err(RequestError::Dns)?;
    report.dns_admitted = true;
    let request = admitted.request;
    let result = async {
        if admitted.evicted.is_some() {
            return Err(RequestError::Protocol(Fault::Conflict));
        }
        let original = owner.query(request).map_err(RequestError::Protocol)?;
        let expected_id: [u8; 2] = original
            .get(..2)
            .ok_or(RequestError::Protocol(Fault::Truncated))?
            .try_into()
            .map_err(|_| RequestError::Protocol(Fault::Truncated))?;
        loop {
            let mut received = None;
            let cancel = budget.cancel.clone();
            let hard = budget.hard;
            let clock = budget.clock.clone();
            let until = budget.until;
            let driven = budget
                .wait(owner.drive(Some(hard), |event, _context| {
                    // This callback may follow IO in the same native poll. Check
                    // original bounds again before parsing or accepting an answer.
                    if let Err(error) = check_native(&cancel, hard) {
                        received = Some(Err(error));
                        return stub::Flow::Return;
                    }
                    match event {
                        stub::Event::Datagram(datagram) if datagram.request == request => {
                            let now = match clock.sample() {
                                Ok(sample) => sample.now.as_micros(),
                                Err(error) => {
                                    received = Some(Err(RequestError::Protocol(error)));
                                    return stub::Flow::Return;
                                }
                            };
                            if let Err(error) = check_native(&cancel, hard) {
                                received = Some(Err(error));
                                return stub::Flow::Return;
                            }
                            if now >= until {
                                received = Some(Err(RequestError::LogicalDeadline));
                                return stub::Flow::Return;
                            }
                            match packet::validate_upstream(
                                query,
                                datagram.bytes,
                                datagram.source,
                                ports.upstream,
                                expected_id,
                                AbsoluteTime::from_micros(now),
                                limits.packet,
                            ) {
                                Ok(bytes) => received = Some(Ok(bytes)),
                                Err(
                                    error @ packet::Failure::Protocol(
                                        Fault::Capacity | Fault::Overflow,
                                    ),
                                ) => {
                                    received = Some(Err(RequestError::Packet(error)));
                                }
                                Err(_) => {
                                    report.dns_rejected = report.dns_rejected.saturating_add(1);
                                }
                            }
                        }
                        stub::Event::ReceiveFailed { error, .. }
                        | stub::Event::SocketOpened {
                            result: Err(error), ..
                        }
                        | stub::Event::Sent {
                            result: Err(error), ..
                        } => {
                            let _ = report.dns_io.get_or_insert(error);
                        }
                        _ => {}
                    }
                    // Return after each real native observation, so every next
                    // socket poll re-enters the original cancellation/budget gate.
                    stub::Flow::Return
                }))
                .await;
            match driven {
                Err(error) => return Err(error),
                Ok(Err(error)) => return Err(RequestError::Dns(error)),
                Ok(Ok(stub::Progress::Stopped)) => return Err(RequestError::Closed),
                Ok(Ok(_)) => {}
            }
            if let Some(result) = received {
                return result;
            }
            budget.yield_turn().await?;
        }
    }
    .await;
    match owner.resolve_cancel(request) {
        Ok(()) => report.dns_cancelled = true,
        Err(error) => {
            report.dns_cancel_error = Some(error);
            if result.is_ok() {
                return Err(RequestError::DnsCancel(error));
            }
        }
    }
    result
}

async fn allocate(
    target: vpn::Service,
    family: packet::Family,
    lease_until: u64,
    ports: &Ports,
    limits: Limits,
    budget: &mut Budget,
) -> (Result<IpAddr, RequestError>, VpnReport) {
    let mut facts = VpnReport::default();
    let mut instance = vpn::Instance::new();
    let source = match ports.vpn.duplicate() {
        Ok(source) => source,
        Err(error) => return (Err(RequestError::Vpn(error)), facts),
    };
    let mut owner = match vpn::Client::new(&mut instance, source, limits.vpn_profile, limits.vpn) {
        Ok(owner) => owner,
        Err(error) => return (Err(RequestError::Vpn(error)), facts),
    };
    let mut active = None;
    let result = async {
        budget.now()?;
        let desired = match family {
            packet::Family::V4 => vpn::Family::V4,
            packet::Family::V6 => vpn::Family::V6,
        };
        let operation = owner
            .service(target, Some(desired), lease_until, budget.until)
            .map_err(RequestError::Vpn)?;
        active = Some(operation);
        facts.operation = Some(operation.diagnostic());
        loop {
            let hard = budget.hard;
            let step = budget
                .wait(owner.drive(Some(hard)))
                .await?
                .map_err(RequestError::Vpn)?;
            match step {
                vpn::Progress::Connected(epoch) => facts.epoch = Some(epoch.diagnostic()),
                vpn::Progress::Written {
                    epoch,
                    operation: original,
                    ..
                } if original == operation => {
                    facts.epoch = Some(epoch.diagnostic());
                    facts.written = true;
                }
                vpn::Progress::Completed {
                    epoch,
                    operation: original,
                    outcome,
                } if original == operation => {
                    active = None;
                    facts.epoch = epoch.map(vpn::Epoch::diagnostic);
                    facts.outcome = Some(outcome);
                    budget.now()?;
                    return match outcome {
                        vpn::Outcome::Allocation(Some(vpn::Address::V4(bytes)))
                            if desired == vpn::Family::V4 =>
                        {
                            Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
                        }
                        vpn::Outcome::Allocation(Some(vpn::Address::V6(bytes)))
                            if desired == vpn::Family::V6 =>
                        {
                            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
                        }
                        other => Err(RequestError::VpnOutcome(other)),
                    };
                }
                vpn::Progress::Lost { epoch, cause } => {
                    facts.epoch = epoch.map(vpn::Epoch::diagnostic);
                    facts.loss = Some(cause);
                    return Err(RequestError::Closed);
                }
                vpn::Progress::Unavailable(error) => return Err(RequestError::Vpn(error)),
                vpn::Progress::ConnectRetry { error, .. } => {
                    if facts.connect_error.is_none() {
                        facts.connect_error = Some(error);
                    }
                }
                vpn::Progress::Closed => return Err(RequestError::Closed),
                _ => {}
            }
            budget.yield_turn().await?;
        }
    }
    .await;
    if let Some(operation) = active {
        facts.cancel = Some(owner.cancel(operation));
    }
    facts.close_invoked = true;
    match owner.close() {
        Ok(Some(vpn::Progress::Lost { epoch, cause })) => {
            if facts.epoch.is_none() {
                facts.epoch = epoch.map(vpn::Epoch::diagnostic);
            }
            facts.close_loss = Some(cause);
        }
        Ok(_) => {}
        Err(error) => facts.close_error = Some(error),
    }
    (result, facts)
}
