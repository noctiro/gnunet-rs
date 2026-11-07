//! The original DHT client and Resolver remain owned through every exit path.
use crate::{Cause, Mode, budget::Budget, control::Control, options::Settings, output::Output};
use gnunet_dht_client_host::{
    self as dht, Client, Event, Get, Instance, Monitor, Outcome, Progress,
};
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Driver, DriverEvent};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;
use std::{
    cell::Cell,
    fmt,
    future::{Future, poll_fn},
    io::{self, Stdout},
    rc::Rc,
    sync::Arc,
    task::Poll,
};

pub(super) struct Inputs {
    pub settings: Settings,
    pub endpoint: dht::EndpointSource,
    pub resolver: Driver<8, 64>,
    pub clock: Arc<dyn RuntimeClock>,
    pub reporter: Reporter,
    pub stop: Rc<Cell<bool>>,
    pub parent: Option<ParentControl>,
    pub stdout: Stdout,
}
#[derive(Debug, Default)]
pub(super) struct Report {
    pub code: u8,
    results: u64,
    timed_out: bool,
    stopped: bool,
    whole_one_shot_written: bool,
    hello_received: bool,
    connect_retries: u64,
    first_connect_error: Option<io::Error>,
    resolver_io: Option<io::Error>,
    resolver_connect: Option<BrokerError>,
    resolver_disconnected: bool,
    closed: Option<dht::Snapshot>,
}
#[derive(Debug)]
struct Failed {
    original: Option<Cause>,
    disconnect: Option<BrokerError>,
    report: Report,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DHT command original={:?}; Resolver close={:?}; terminal facts={:?}",
            self.original, self.disconnect, self.report
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.disconnect.as_ref().map(|e| e as _))
    }
}
enum Step<'a> {
    Dht(Result<Progress<'a>, dht::Error>),
    Resolver(Result<gnunet_resolver_broker::Progress, BrokerError>),
    Output(io::Result<usize>),
    Stop(io::Result<()>),
    Expired(Fault),
}
pub(super) async fn run(inputs: Inputs) -> Result<Report, Cause> {
    let Inputs {
        mut settings,
        endpoint,
        mut resolver,
        clock,
        reporter,
        stop,
        parent,
        stdout,
    } = inputs;
    let mut instance = Instance::new();
    let mut client = None;
    let mut report = Report::default();
    let original = async {
        let mut control = Control::new(parent, stop, reporter.clone())?;
        if matches!(settings.mode, Mode::Get | Mode::Monitor) && settings.timeout == 0 {
            report.timed_out = true;
            return Ok::<(), Cause>(());
        }
        let mut budget = Budget::new(clock.clone(), settings.timeout)?;
        // Stop and native expiry precede request admission and later polls.
        let gate = poll_fn(|cx| {
            budget.poll(cx)?;
            Poll::Ready(Ok::<_, Fault>(control.poll(cx)))
        })
        .await?;
        if let Poll::Ready(result) = gate {
            result?;
            report.stopped = true;
            return Ok::<(), Cause>(());
        }
        // One command retains one GET or PUT and two physical frames. The
        // original client still owns all correlation and reconnect semantics.
        let mut limits = dht::Limits::default();
        limits.protocol.gets = usize::from(settings.mode == Mode::Get);
        limits.protocol.monitors = usize::from(settings.mode == Mode::Monitor);
        limits.protocol.hellos =
            usize::from(settings.mode == Mode::Hello && settings.payload.is_none());
        limits.protocol.operations = usize::from(
            settings.mode == Mode::Put
                || (settings.mode == Mode::Hello && settings.payload.is_some()),
        );
        limits.protocol.attempts = 2;
        limits.protocol.source_bytes = 128 * 1024;
        limits.output.frames = 2;
        limits.output.bytes = 128 * 1024;
        if settings.mode != Mode::Hello || settings.payload.is_none() {
            limits.hello.maximum_address_bytes = 0;
            limits.hello.maximum_addresses = 0;
        }
        client = Some(Client::new(&mut instance, endpoint, limits)?);
        let owner = client.as_mut().ok_or("DHT owner was not retained")?;
        let get = if settings.mode == Mode::Get {
            Some(
                owner.get(Get {
                    key: settings
                        .key
                        .as_ref()
                        .ok_or("missing original DHT query key")?,
                    block_type: settings.block_type,
                    options: settings.route,
                    replication: settings.replication,
                    extended_query: &[],
                })?,
            )
        } else {
            None
        };
        let monitor = if settings.mode == Mode::Monitor {
            Some(owner.monitor(Monitor {
                block_type: settings.block_type,
                get: 1,
                result: 1,
                put: 1,
                key: settings.key,
            })?)
        } else {
            None
        };
        let hello = if settings.mode == Mode::Hello && settings.payload.is_none() {
            Some(owner.hello()?)
        } else {
            None
        };
        let mut operation = None;
        let mut output = Output::new(stdout);
        let mut cursor = 0;
        let resolver_state = Cell::new(None);
        loop {
            if report.hello_received && output.finished() {
                break;
            }
            if settings.mode == Mode::Put && operation.is_none() && owner.epoch().is_some() {
                // Convert the original relative lifetime exactly once, when the
                // one-shot is admitted. FOREVER saturates as the official time API.
                let now = clock.sample()?.now.as_micros();
                let expiry = now.saturating_add(settings.expiration);
                let payload = settings
                    .payload
                    .take()
                    .ok_or("missing original PUT payload")?;
                operation = Some(
                    owner.put(dht::ipc::Put {
                        key: settings
                            .key
                            .as_ref()
                            .ok_or("missing original DHT query key")?,
                        block_type: settings.block_type,
                        options: settings.route,
                        replication: settings.replication,
                        expiration: AbsoluteTime::from_micros(expiry),
                        payload: &payload,
                    })?,
                );
            }
            if settings.mode == Mode::Hello
                && hello.is_none()
                && operation.is_none()
                && owner.epoch().is_some()
            {
                let url = settings
                    .payload
                    .take()
                    .ok_or("missing original HELLO URL")?;
                let (original, coverage) = owner.offer_hello(&url, clock.sample()?.now)?;
                operation = Some(original);
                if settings.verbose {
                    reporter.debug(
                        "dht.hello.offer",
                        format_args!("Official HELLO signature coverage: {coverage:?}"),
                    );
                }
            }
            let step = {
                let mut driving = std::pin::pin!(owner.drive(budget.hard));
                let mut resolving = std::pin::pin!(resolver.drive_waiting(budget.hard, |event| {
                    if matches!(event, DriverEvent::Lost { .. } | DriverEvent::Unavailable) {
                        resolver_state.set(Some(event));
                    }
                }));
                poll_fn(|cx| {
                    if let Poll::Ready(result) = control.poll(cx) {
                        return Poll::Ready(Step::Stop(result));
                    }
                    if let Err(error) = budget.poll(cx) {
                        return Poll::Ready(Step::Expired(error));
                    }
                    // Rotate the first owner; a hot Resolver cannot starve output
                    // or DHT. Result backpressure retains its original bounded MQ.
                    for offset in 0..3 {
                        if let Err(error) = budget.native_guard(cx) {
                            return Poll::Ready(Step::Expired(error));
                        }
                        match (cursor + offset) % 3 {
                            0 if output.finished() => {
                                if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                    return Poll::Ready(Step::Dht(result));
                                }
                            }
                            1 => {
                                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                                    return Poll::Ready(Step::Resolver(result));
                                }
                            }
                            2 => {
                                if let Poll::Ready(result) = output.poll(cx) {
                                    return Poll::Ready(Step::Output(result));
                                }
                            }
                            _ => {}
                        }
                    }
                    Poll::Pending
                })
                .await
            };
            cursor = (cursor + 1) % 3;
            if let Some(event) = resolver_state.take() {
                if settings.verbose {
                    reporter.debug("dht.resolver.activity", format_args!("{event:?}"));
                }
                if matches!(event, DriverEvent::Lost { .. } | DriverEvent::Unavailable) {
                    return Err(format!("original Resolver source unavailable: {event:?}").into());
                }
            }
            if let Some(error) = resolver.take_io_error() {
                report.resolver_io.get_or_insert(error);
            }
            if let Some(error) = resolver.take_connect_error() {
                report.resolver_connect.get_or_insert(error);
            }
            match step {
                Step::Stop(result) => {
                    result?;
                    report.stopped = true;
                    break;
                }
                Step::Expired(Fault::Deadline)
                    if matches!(settings.mode, Mode::Get | Mode::Monitor) =>
                {
                    if !output.finished() {
                        return Err("DHT timeout interrupted the original result output".into());
                    }
                    report.timed_out = true;
                    break;
                }
                Step::Expired(error) => return Err(error.into()),
                Step::Output(result) => {
                    result?;
                }
                Step::Resolver(result) => {
                    result?;
                }
                Step::Dht(result) => match result? {
                    Progress::Inbound(received) => {
                        if let Event::Result { get: original, .. } = received.event() {
                            if get != Some(*original) {
                                return Err(
                                    "DHT result does not belong to the original query".into()
                                );
                            }
                            output.result(
                                received.result()?,
                                report.results,
                                settings.verbose && settings.route & 2 != 0,
                            )?;
                            report.results = report.results.saturating_add(1);
                        }
                        if let Event::Monitor { kind, monitors } = received.event() {
                            if !monitor.is_some_and(|original| monitors.contains(&original)) {
                                return Err(
                                    "monitor delivery is not for the original subscription".into(),
                                );
                            }
                            output.monitor(*kind, received.bytes(), report.results)?;
                            report.results = report.results.saturating_add(1);
                        }
                        if let Event::Hello { requests } = received.event() {
                            if !hello.is_some_and(|original| requests.contains(&original)) {
                                return Err(
                                    "HELLO delivery is not for the original observation".into()
                                );
                            }
                            output.hello(received.hello_url()?)?;
                            report.hello_received = true;
                        }
                    }
                    Progress::Completed(completion) => {
                        if operation != Some(completion.operation) {
                            return Err(
                                "DHT completion does not belong to original one-shot".into()
                            );
                        }
                        if completion.outcome != Outcome::Written {
                            return Err(format!(
                                "original DHT one-shot terminal outcome: {:?}",
                                completion.outcome
                            )
                            .into());
                        }
                        report.whole_one_shot_written = true;
                        break;
                    }
                    Progress::ConnectRetry { error, .. } => {
                        report.connect_retries = report.connect_retries.saturating_add(1);
                        report.first_connect_error.get_or_insert(error);
                    }
                    Progress::Unavailable(error) => return Err(error.into()),
                    Progress::Lost { cause, .. } => {
                        if settings.verbose {
                            reporter.debug("dht.stream.lost", format_args!("{cause:?}"));
                        }
                        // GET remains in the same logical owner. Issued PUT is
                        // never resubmitted; its original terminal notice follows.
                    }
                    Progress::Capacity(_) => return Err(Fault::Capacity.into()),
                    Progress::Closed => {
                        return Err("original DHT client closed before completion".into());
                    }
                    Progress::WaitDeadline
                    | Progress::Connected(_)
                    | Progress::Written { .. }
                    | Progress::Activity { .. } => {}
                },
            }
        }
        Ok(())
    }
    .await
    .err();
    // Closing the original native client retires its MQ; no fabricated STOP
    // receipt, acknowledgement, worker termination or quiescence claim.
    if let Some(owner) = &mut client {
        let _close = owner.close();
        report.closed = Some(owner.snapshot());
    }
    drop(client);
    if let Some(error) = resolver.take_io_error() {
        report.resolver_io.get_or_insert(error);
    }
    if let Some(error) = resolver.take_connect_error() {
        report.resolver_connect.get_or_insert(error);
    }
    let disconnect = resolver.disconnect().err();
    report.resolver_disconnected = disconnect.is_none();
    drop(resolver);
    if settings.verbose {
        reporter.debug("dht.command.closed", format_args!("{report:?}"));
    }
    if original.is_some() || disconnect.is_some() {
        Err(Box::new(Failed {
            original,
            disconnect,
            report,
        }))
    } else {
        Ok(report)
    }
}
