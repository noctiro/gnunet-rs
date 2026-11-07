//! One original SOCKS/GNS/HTTP session and unconditional old-owner cleanup.
use crate::{
    Error,
    budget::Budget,
    http,
    records::{self, Plan},
    socks, tls,
    types::SessionInput,
    vpn, wire,
};
use gnunet_gns_host::tld;
use gnunet_resolver_broker::{Completion, Family, Reply};
use gnunet_types::Error as Fault;
use std::{cell::RefCell, future::Future, io, net::SocketAddr, pin::Pin, rc::Rc, sync::Arc};
use tokio::{io::AsyncWrite, net::TcpStream, time::Instant};
/// Original source and actual terminal/cleanup facts. Private HTTP/key bytes
/// are never retained in diagnostics. A response write is not remote delivery.
#[derive(Debug, Default)]
pub struct Report {
    /// Actual original session error, if its protocol workflow failed.
    pub error: Option<Error>,
    /// Original GNS/IDENTITY physical-retirement/cancellation facts.
    pub lookup: Option<tld::Diagnostics>,
    /// Actual GNS source loss cause, independent of final close metadata.
    pub gns_loss: Option<gnunet_gns_client_host::LossCause>,
    /// Actual IDENTITY source loss cause, independent of final close metadata.
    pub identity_loss: Option<gnunet_identity_client_host::LossCause>,
    /// First actual original native lookup connection error.
    pub lookup_connect_error: Option<io::Error>,
    /// Actual lookup retry/loss causes omitted after the bounded first slots.
    pub omitted_lookup_errors: u64,
    /// Actual endpoint/clock/Resolver construction failure during lookup.
    pub lookup_ports_error: Option<gnunet_client_host::ConnectError>,
    /// A real GNS Answer was received, including an empty record set.
    pub was_gns: bool,
    /// Actual IDENTITY missing result permitted the ordinary DNS path.
    pub was_not_gns: bool,
    /// Actual source/projection counts, never an allocation proof.
    pub records: Option<records::Summary>,
    /// Actual original Resolver completion callback.
    pub dns_completion: Option<Completion>,
    /// This original DNS callback interest was actually revoked locally.
    pub dns_cancelled: bool,
    /// Independent original DNS cleanup failure.
    pub dns_cancel_error: Option<gnunet_resolver_broker::BrokerError>,
    /// Same process Driver still owns shared wire/tombstone/partial IO scope.
    pub dns_shared_driver: bool,
    /// Actual VPN callbacks and their independent close/submission outcomes.
    pub vpn: Vec<vpn::Report>,
    /// Matching VPN business failures, with their independent report rows above.
    pub vpn_errors: Vec<vpn::Failure>,
    /// Actual native socket facts; TLS plaintext and body counters are separate.
    pub sockets: Vec<crate::SocketReport>,
    /// Independent explicit original-socket cleanup failures.
    pub socket_close_errors: Vec<Error>,
    /// First actual TCP attempt failure, without converting it to DNS absence.
    pub connect_error: Option<io::Error>,
    /// Actual failed TCP attempts, not replayed HTTP operations.
    pub connect_failures: u64,
    /// Actual completed and verified upstream TLS handshakes.
    pub tls_handshakes: u64,
    /// First genuine authentication report, including usable/skipped TLSA facts.
    pub authentication: Option<tls::Authentication>,
    /// Actual browser TLS handshake completed; this does not claim OS trust installed.
    pub browser_tls_completed: bool,
    /// Valid original CONNECT request was completely received.
    pub socks_request_received: bool,
    /// Independent error writing an original standard failure reply.
    pub socks_error_reply: Option<Error>,
    /// Local SOCKS success response was written in full.
    pub socks_granted: bool,
    /// Mature HTTP parser/body/driver/shutdown observations, including cancellation.
    pub http: Option<http::Report>,
    /// Independent error while retiring the original HTTP/TLS IO lease owners.
    pub http_retire_error: Option<Error>,
    /// An HTTP observer remained owned; no completion was invented from metadata.
    pub http_report_retained: bool,
    /// Actual earlier accepted-socket initialization diagnostics.
    pub diagnostics: Option<gnunet_native::network::Diagnostics>,
    /// Actual original clock fault observed inside a synchronous TLS guard.
    pub clock_error: Option<Fault>,
}
impl Report {
    /// Select genuine failures/cleanup/partial facts for a bounded process log;
    /// successful reports must not consume every retained diagnostic slot.
    pub fn has_diagnostics(&self) -> bool {
        self.error.is_some()
            || self.gns_loss.is_some()
            || self.identity_loss.is_some()
            || self.lookup_connect_error.is_some()
            || self.lookup_ports_error.is_some()
            || self.dns_cancel_error.is_some()
            || !self.vpn_errors.is_empty()
            || !self.socket_close_errors.is_empty()
            || self.connect_error.is_some()
            || self.socks_error_reply.is_some()
            || self.http_retire_error.is_some()
            || self.http_report_retained
            || self.clock_error.is_some()
            || self.diagnostics.as_ref().is_some_and(|d| !d.is_empty())
            || self
                .http
                .as_ref()
                .is_some_and(http::Report::has_diagnostics)
            || self
                .sockets
                .iter()
                .any(|s| !s.physically_closed || s.shutdown_attempted && !s.shutdown_completed)
            || self.lookup.as_ref().is_some_and(|r| {
                r.gns_cancel_error.is_some()
                    || r.identity_cancel_error.is_some()
                    || r.gns_source_loss.is_some()
                    || r.identity_source_loss.is_some()
            })
            || self
                .vpn
                .iter()
                .any(|r| r.loss.is_some() || r.connect_error.is_some() || r.close_error.is_some())
    }
}
#[derive(Default)]
struct Network {
    sockets: Vec<wire::Control>,
    first_connect_error: Option<io::Error>,
    connect_failures: u64,
    tls_handshakes: u64,
    authentication: Option<tls::Authentication>,
    first_bound: Option<SocketAddr>,
    last_connect_kind: Option<io::ErrorKind>,
}
struct Connector {
    plan: Rc<Plan>,
    budget: Budget,
    roots: Arc<tls::TrustRoots>,
    network: Rc<RefCell<Network>>,
    prepared: RefCell<Option<wire::Io>>,
}
impl Connector {
    async fn open(&self) -> Result<wire::Io, Error> {
        self.budget.check()?;
        if self.plan.expires != u64::MAX && self.budget.now()? >= self.plan.expires {
            return Err(Fault::Stale.into());
        }
        for address in &self.plan.addresses {
            self.budget.check()?;
            self.network
                .borrow_mut()
                .sockets
                .try_reserve(1)
                .map_err(Error::Allocation)?;
            let socket = match self.budget.wait(TcpStream::connect(address)).await? {
                Ok(socket) => socket,
                Err(error) => {
                    let mut net = self.network.borrow_mut();
                    net.connect_failures = net.connect_failures.saturating_add(1);
                    net.last_connect_kind = Some(error.kind());
                    if net.first_connect_error.is_none() {
                        net.first_connect_error = Some(error)
                    }
                    continue;
                }
            };
            let local = socket.local_addr()?;
            let (control, wire) = wire::Control::new(socket);
            self.network.borrow_mut().sockets.push(control);
            self.network.borrow_mut().first_bound.get_or_insert(local);
            self.budget.check()?;
            if !self.plan.tls {
                return Ok(Box::new(wire));
            }
            let upstream = tls::upstream_config(
                &self.plan.upstream_host,
                self.plan.port,
                self.plan.tlsa.clone(),
                self.roots.clone(),
                self.budget.tls_guard(),
            )?;
            self.budget.check()?;
            let socket = self
                .budget
                .wait(
                    tokio_rustls::TlsConnector::from(upstream.config.clone())
                        .connect(upstream.server_name.clone(), wire),
                )
                .await??;
            let authentication = upstream.authentication(socket.get_ref().1)?;
            self.budget.check()?;
            {
                let mut net = self.network.borrow_mut();
                net.tls_handshakes = net.tls_handshakes.saturating_add(1);
                if net.authentication.is_none() {
                    net.authentication = Some(authentication)
                }
            }
            return Ok(Box::new(socket));
        }
        Err(Fault::Unavailable.into())
    }
}
impl http::Connector for Connector {
    fn connect(&self) -> Pin<Box<dyn Future<Output = Result<wire::Io, Error>> + '_>> {
        Box::pin(async move {
            self.budget.check()?;
            let prepared = self.prepared.borrow_mut().take();
            match prepared {
                Some(io) => Ok(io),
                None => self.open().await,
            }
        })
    }
}
fn lookup_progress<'g, 'id>(
    progress: tld::Progress<'g, 'id>,
    report: &mut Report,
) -> Option<tld::Outcome<'g, 'id>> {
    match progress {
        tld::Progress::Finished(outcome) => return Some(outcome),
        tld::Progress::Gns(gnunet_gns_client_host::Progress::Lost { cause, .. }) => {
            if report.gns_loss.is_none() {
                report.gns_loss = Some(cause)
            } else {
                report.omitted_lookup_errors = report.omitted_lookup_errors.saturating_add(1)
            }
        }
        tld::Progress::Identity(gnunet_identity_client_host::Progress::Lost { cause, .. }) => {
            if report.identity_loss.is_none() {
                report.identity_loss = Some(cause)
            } else {
                report.omitted_lookup_errors = report.omitted_lookup_errors.saturating_add(1)
            }
        }
        tld::Progress::Gns(gnunet_gns_client_host::Progress::ConnectRetry { error, .. })
        | tld::Progress::Identity(gnunet_identity_client_host::Progress::ConnectRetry {
            error,
            ..
        }) => {
            if report.lookup_connect_error.is_none() {
                report.lookup_connect_error = Some(error)
            } else {
                report.omitted_lookup_errors = report.omitted_lookup_errors.saturating_add(1)
            }
        }
        tld::Progress::Gns(gnunet_gns_client_host::Progress::Unavailable(error))
        | tld::Progress::Identity(gnunet_identity_client_host::Progress::Unavailable(error)) => {
            if report.lookup_ports_error.is_none() {
                report.lookup_ports_error = Some(error)
            } else {
                report.omitted_lookup_errors = report.omitted_lookup_errors.saturating_add(1)
            }
        }
        _ => {}
    }
    None
}
async fn dns(plan: &mut Plan, input: &SessionInput, report: &mut Report) -> Result<(), Error> {
    input.budget.check()?;
    let now = input.budget.now()?;
    let family = if input.disable_ipv6 {
        Family::V4
    } else {
        Family::Any
    };
    let mut query = input
        .context
        .ip_get(
            plan.browser_host.as_bytes(),
            family,
            gnunet_types::Duration(
                input
                    .budget
                    .until()
                    .checked_sub(now)
                    .ok_or(Fault::Timeout)?,
            ),
        )
        .map_err(Error::Resolver)?;
    report.dns_shared_driver = true;
    let result: Result<(), Error> = async {
        loop {
            let delivery = input
                .budget
                .wait(query.next())
                .await?
                .map_err(Error::Resolver)?
                .ok_or(Fault::Unavailable)?;
            match delivery.reply()? {
                Reply::Address(address) => {
                    if input.disable_ipv6 && address.is_ipv6() {
                        drop(delivery);
                        continue;
                    }
                    let address = SocketAddr::new(address, plan.port);
                    if !plan.addresses.contains(&address) {
                        if plan.addresses.len() == input.limits.records.addresses {
                            return Err(Fault::Capacity.into());
                        }
                        plan.addresses.try_reserve(1).map_err(Error::Allocation)?;
                        plan.addresses.push(address);
                    }
                }
                Reply::Complete(completion) => {
                    report.dns_completion = Some(completion);
                    drop(delivery);
                    return if completion == Completion::End {
                        Ok(())
                    } else {
                        Err(Fault::Unavailable.into())
                    };
                }
                Reply::Hostname(_) => return Err(Fault::Malformed.into()),
            }
            drop(delivery);
        }
    }
    .await;
    if report.dns_completion.is_none() {
        match query.cancel_clock_free() {
            Ok(()) => report.dns_cancelled = true,
            Err(e) => report.dns_cancel_error = Some(e),
        }
    }
    result
}
async fn resolve(
    name: &str,
    port: u16,
    input: &SessionInput,
    report: &mut Report,
) -> Result<Plan, Error> {
    input.budget.check()?;
    let mut domain = gnunet_gns_client_host::Instance::new();
    let identity = gnunet_identity_client_host::Instance::new();
    let mut lookup = tld::Lookup::new(
        &mut domain,
        &identity,
        tld::Sources {
            gns: input.sources.gns.duplicate().map_err(Error::Connect)?,
            identity: input.sources.identity.duplicate().map_err(Error::Connect)?,
        },
        &input.configuration,
        tld::Request {
            name: name.as_bytes(),
            record_type: gnunet_gns_client_host::RecordType::new(0),
            options: gnunet_gns_client_host::LocalOptions::DEFAULT,
            recursion_depth: 128,
        },
        tld::Bounds::bounded(input.budget.until(), input.budget.hard()),
        input.limits.lookup,
    )
    .map_err(Error::Gns)?;
    loop {
        let progress = match input.budget.wait(lookup.drive()).await {
            Ok(Ok(progress)) => progress,
            Ok(Err(failure)) => {
                let (cause, diagnostics) = failure.into_diagnostics();
                report.lookup = Some(diagnostics);
                return Err(Error::Gns(cause));
            }
            Err(error) => {
                report.lookup = lookup.cancel().map(tld::Report::into_diagnostics);
                return Err(error);
            }
        };
        let Some(outcome) = lookup_progress(progress, report) else {
            continue;
        };
        return match outcome {
            tld::Outcome::Answer {
                answer,
                report: closed,
            } => {
                report.was_gns = true;
                report.lookup = Some(closed.into_diagnostics());
                let records = answer.result()?.records();
                let plan = Plan::gns(
                    name,
                    port,
                    records,
                    input.disable_ipv6,
                    input.limits.records,
                    &input.budget,
                )?;
                drop(answer);
                Ok(plan)
            }
            tld::Outcome::NotGns { report: closed } => {
                report.was_not_gns = true;
                report.lookup = Some(closed.into_diagnostics());
                let mut plan = Plan::dns(name, port)?;
                dns(&mut plan, input, report).await?;
                Ok(plan)
            }
        };
    }
}
fn status(error: &Error) -> socks::Status {
    match error {
        Error::Deadline => socks::Status::Expired,
        Error::Protocol(Fault::NotFound | Fault::Unavailable) => socks::Status::Host,
        Error::Io(e) if e.kind() == io::ErrorKind::ConnectionRefused => socks::Status::Refused,
        Error::Io(e) if e.kind() == io::ErrorKind::NetworkUnreachable => socks::Status::Network,
        Error::Protocol(Fault::Unsupported | Fault::PermissionDenied) => socks::Status::Rules,
        _ => socks::Status::General,
    }
}
async fn retire_io(mut original: wire::Io, hard: Instant) -> Result<(), Error> {
    let mut alarm = Box::pin(tokio::time::sleep_until(hard));
    let outcome = std::future::poll_fn(|cx| {
        if Instant::now() >= hard || alarm.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(Err(Error::Deadline));
        }
        Pin::new(&mut original).poll_shutdown(cx).map_err(Error::Io)
    })
    .await;
    drop(original);
    outcome
}

pub(crate) async fn run(mut input: SessionInput) -> Report {
    let mut report = Report {
        diagnostics: input.diagnostics.take(),
        ..Report::default()
    };
    // Move the unique accepted stream into its retained physical control.
    let Some(socket) = input.socket.take() else {
        report.error = Some(Fault::NotReady.into());
        return report;
    };
    let (browser_control, browser) = wire::Control::new(socket);
    let mut browser = Some(browser);
    let network = Rc::new(RefCell::new(Network::default()));
    network.borrow_mut().sockets.push(browser_control);
    let observer = http::Observer::new();
    let mut browser_tls = None;
    let mut connector = None;
    let outcome: Result<(), Error> = async {
        input.budget.check()?;
        let target =
            socks::handshake(browser.as_mut().ok_or(Fault::Closed)?, &input.budget).await?;
        report.socks_request_received = true;
        let mut plan = match target {
            socks::Target::Numeric(address) => Plan::numeric(address, input.disable_ipv6)?,
            socks::Target::Domain { name, port } => {
                resolve(&name, port, &input, &mut report).await?
            }
        };
        report.records = Some(plan.summary);
        let needs = std::mem::take(&mut plan.vpn);
        report
            .vpn
            .try_reserve_exact(needs.len())
            .map_err(Error::Allocation)?;
        report
            .vpn_errors
            .try_reserve_exact(needs.len())
            .map_err(Error::Allocation)?;
        for need in needs {
            input.budget.check()?;
            let (allocation, closed) = vpn::allocate(
                input.sources.vpn.duplicate().map_err(Error::Connect)?,
                input.budget.clone(),
                need,
                input.limits.vpn_profile,
                input.limits.vpn,
            )
            .await;
            report.vpn.push(closed);
            match allocation {
                Ok(allocation) => plan.allocated(allocation, input.limits.records)?,
                Err(error) => report.vpn_errors.push(error),
            }
        }
        if plan.addresses.is_empty() {
            return Err(Fault::NotFound.into());
        }
        input.budget.check()?;
        if plan.tls {
            browser_tls = Some(input.authority.server_config(
                &plan.browser_host,
                records::system_time(plan.expires)?,
                &input.budget.tls_guard(),
            )?);
        }
        let connection = Rc::new(Connector {
            plan: Rc::new(plan),
            budget: input.budget.clone(),
            roots: input.roots.clone(),
            network: network.clone(),
            prepared: RefCell::new(None),
        });
        connector = Some(connection.clone());
        let original = connection.open().await?;
        *connection.prepared.borrow_mut() = Some(original);
        let bound = network.borrow().first_bound;
        socks::reply(
            browser.as_mut().ok_or(Fault::Closed)?,
            socks::Status::Granted,
            bound,
            &input.budget,
        )
        .await?;
        report.socks_granted = true;
        let io: wire::Io = if let Some(config) = browser_tls.take() {
            input.budget.check()?;
            let stream = input
                .budget
                .wait(
                    tokio_rustls::TlsAcceptor::from(config)
                        .accept(browser.take().ok_or(Fault::Closed)?),
                )
                .await??;
            report.browser_tls_completed = true;
            input.budget.check()?;
            Box::new(stream)
        } else {
            Box::new(browser.take().ok_or(Fault::Closed)?)
        };
        let view = http::View {
            browser_host: connection.plan.browser_host.clone(),
            upstream_host: connection.plan.upstream_host.clone(),
            port: connection.plan.port,
            tls: connection.plan.tls,
        };
        input
            .budget
            .wait(http::serve(
                io,
                connection,
                view,
                input.limits.http,
                input.budget.clone(),
                observer.clone(),
            ))
            .await??;
        Ok(())
    }
    .await;
    report.error = outcome.err();
    if report.socks_request_received
        && !report.socks_granted
        && input.budget.check().is_ok()
        && let (Some(error), Some(browser)) = (&report.error, browser.as_mut())
    {
        let mut reply = status(error);
        match network.borrow().last_connect_kind {
            Some(io::ErrorKind::ConnectionRefused) => reply = socks::Status::Refused,
            Some(io::ErrorKind::NetworkUnreachable) => reply = socks::Status::Network,
            Some(io::ErrorKind::HostUnreachable) => reply = socks::Status::Host,
            _ => {}
        }
        if let Err(error) = socks::reply(browser, reply, None, &input.budget).await {
            report.socks_error_reply = Some(error);
        }
    }
    let now = Instant::now();
    let cleanup = input
        .stop
        .cleanup_hard()
        .or_else(|| now.checked_add(input.limits.cleanup_grace))
        .unwrap_or(now);
    // Prepared upstream TLS may exist before browser handshake starts. Retire
    // that same IO explicitly even when HTTP never takes its first request.
    if let Some(connection) = connector.take() {
        let prepared = connection.prepared.borrow_mut().take();
        if let Some(io) = prepared
            && let Err(e) = retire_io(io, cleanup).await
        {
            report.socket_close_errors.push(e);
        }
        drop(connection);
    }
    if let Some(browser) = browser.take()
        && let Err(e) = retire_io(Box::new(browser), cleanup).await
    {
        report.socket_close_errors.push(e);
    }
    drop(browser_tls);
    if let Err(error) = observer.retire(cleanup).await {
        report.http_retire_error = Some(error)
    }
    match observer.into_report() {
        Ok(closed) => report.http = Some(closed),
        Err(retained) => {
            report.http_report_retained = true;
            drop(retained);
        }
    }
    let mut controls = std::mem::take(&mut network.borrow_mut().sockets);
    if let Err(error) = report.sockets.try_reserve_exact(controls.len()) {
        report.socket_close_errors.push(Error::Allocation(error));
    }
    for control in &mut controls {
        let (error, snapshot) = control.close(cleanup).await;
        if let Some(error) = error {
            report.socket_close_errors.push(error)
        }
        match snapshot {
            Ok(snapshot) => report.sockets.push(snapshot),
            Err(error) => report.socket_close_errors.push(error),
        }
    }
    drop(controls);
    let mut network = network.borrow_mut();
    report.connect_error = network.first_connect_error.take();
    report.connect_failures = network.connect_failures;
    report.tls_handshakes = network.tls_handshakes;
    report.authentication = network.authentication.take();
    report.clock_error = input.budget.first_clock_error();
    report
}
