use crate::{
    Failure,
    options::{Action, Selection, Settings},
};
use gnunet_abd_client_host::{Bounds, EndpointSource};
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tokio::signal::unix::{Signal, SignalKind};
mod identity;
mod namestore;
mod request;

#[derive(Debug, Default)]
pub(super) struct Facts {
    pub identity_found: bool,
    pub undrained: usize,
    pub identity_result: Option<u32>,
    pub identity_local: Option<(
        gnunet_identity_client_host::LocalReason,
        gnunet_identity_client_host::Submission,
        Option<u32>,
    )>,
    pub identity_loss: Option<gnunet_identity_client_host::LossCause>,
    pub identity_retired: Option<(usize, usize, usize)>,
    pub lookup_found: Option<i16>,
    pub lookup_code: Option<u32>,
    pub identity_retry: Option<io::Error>,
    pub namestore_retry: Option<io::Error>,
    pub abd_retry: Option<io::Error>,
    pub store_code: Option<u32>,
    pub store_written: bool,
    pub namestore_local: Option<(
        gnunet_namestore_client_host::Kind,
        gnunet_namestore_client_host::LocalReason,
        gnunet_namestore_client_host::Submission,
    )>,
    pub namestore_loss: Option<gnunet_namestore_client_host::LossCause>,
    pub namestore_retired: Option<(usize, usize)>,
    pub abd_receipt: Option<gnunet_abd_client_host::Receipt>,
    pub abd_loss: Option<gnunet_abd_client_host::Loss>,
    pub found: Option<u32>,
    pub output_bytes: usize,
    pub output_flushed: bool,
}
pub(super) type SharedFacts = Rc<RefCell<Facts>>;
#[derive(Debug)]
struct Failed {
    original: Option<Failure>,
    cleanup: Vec<Failure>,
    facts: SharedFacts,
}
impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ABD original={:?}; independent cleanup={:?}; original facts={:?}",
            self.original,
            self.cleanup,
            self.facts.borrow()
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cleanup.first().map(|e| e.as_ref()))
    }
}
struct Signals {
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    fn new() -> io::Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("ABD signal source ended")));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
struct Resolver {
    driver: gnunet_resolver_broker::Driver<16, 1024>,
    closed: bool,
    retirement: Rc<RefCell<Option<Failure>>>,
}
impl Resolver {
    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            if let Err(e) = self.driver.disconnect() {
                self.retirement.borrow_mut().get_or_insert(Box::new(e));
            }
        }
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        self.close();
    }
}
pub(super) struct Control {
    pub clock: Arc<dyn RuntimeClock>,
    pub settings: Settings,
    pub original: Bounds,
    pub facts: SharedFacts,
    reporter: Reporter,
    signals: Signals,
    resolver: Resolver,
    canonical: Pin<Box<Deadline>>,
    native: Pin<Box<tokio::time::Sleep>>,
}
impl Control {
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if Instant::now() >= self.original.hard || self.native.as_mut().poll(cx).is_ready() {
            return Err(gnunet_types::Error::Deadline.into());
        }
        self.reporter.register(cx);
        if self.reporter.failed() {
            return Err("selected ABD Logger failed".into());
        }
        if let Poll::Ready(result) = self.signals.poll(cx) {
            result?;
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "ABD original command canceled by signal",
            )
            .into());
        }
        self.original.check(self.clock.as_ref())?;
        match self.canonical.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => return Err(gnunet_types::Error::Deadline.into()),
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Pending => {}
        }
        Ok(())
    }
    /// The real Resolver remains independently polled; every native callback is
    /// returned to its original caller before any subsequent fallible wait.
    pub async fn next<T, E: std::error::Error + 'static>(
        &mut self,
        mut source: impl FnMut(&mut Context<'_>) -> Poll<Result<T, E>>,
    ) -> Result<T, Failure> {
        tokio::task::yield_now().await;
        poll_fn(|cx| -> Poll<Result<T, Failure>> {
            self.guard(cx)?;
            let mut activity = false;
            {
                let mut drive = std::pin::pin!(self.resolver.driver.drive_waiting(None, |event| {
                    self.reporter
                        .debug("abd.resolver.activity", format_args!("Resolver: {event:?}"));
                }));
                match drive.as_mut().poll(cx) {
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                    Poll::Pending => {}
                }
            }
            self.guard(cx)?;
            match source(cx) {
                Poll::Ready(Ok(value)) => Poll::Ready(Ok(value)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(Box::new(e))),
                Poll::Pending => {
                    if activity {
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending
                }
            }
        })
        .await
    }
    pub async fn gate(&mut self) -> Result<(), Failure> {
        self.next(|_| Poll::Ready(Ok::<(), gnunet_types::Error>(())))
            .await
    }
    pub fn time(&self) -> Result<gnunet_abd::Time, Failure> {
        let now = self.clock.sample()?.now.as_micros();
        Ok(gnunet_abd::Time {
            monotonic_us: now,
            utc_earliest_us: now.saturating_sub(self.settings.uncertainty),
            utc_latest_us: now
                .checked_add(self.settings.uncertainty)
                .ok_or(gnunet_types::Error::Overflow)?,
        })
    }
}
struct Sources {
    identity: Option<EndpointSource>,
    namestore: Option<EndpointSource>,
    abd: Option<EndpointSource>,
}
impl Sources {
    fn new(
        live: gnunet_client_host::LiveConfiguration,
        resolver: &Resolver,
        action: &Action,
    ) -> Result<Self, Failure> {
        let id = EndpointSource::live(
            live.clone(),
            b"identity",
            resolver.driver.context().resolution_context(),
        );
        let ns = EndpointSource::live(
            live.clone(),
            b"namestore",
            resolver.driver.context().resolution_context(),
        );
        let abd =
            EndpointSource::live(live, b"abd", resolver.driver.context().resolution_context());
        Ok(match action {
            Action::IssuerStore { .. } | Action::SubjectStore { .. } => {
                let [id, ns] = EndpointSource::snapshot_all([&id, &ns])?;
                Self {
                    identity: Some(id.fixed_endpoint()?),
                    namestore: Some(ns.fixed_endpoint()?),
                    abd: None,
                }
            }
            Action::Sign { .. } => {
                let [id] = EndpointSource::snapshot_all([&id])?;
                Self {
                    identity: Some(id.fixed_endpoint()?),
                    namestore: None,
                    abd: None,
                }
            }
            Action::Collect { .. } => {
                let [id, abd] = EndpointSource::snapshot_all([&id, &abd])?;
                Self {
                    identity: Some(id.fixed_endpoint()?),
                    namestore: None,
                    abd: Some(abd.fixed_endpoint()?),
                }
            }
            Action::Verify { .. } => {
                let [abd] = EndpointSource::snapshot_all([&abd])?;
                Self {
                    identity: None,
                    namestore: None,
                    abd: Some(abd.fixed_endpoint()?),
                }
            }
        })
    }
}
/// Single explicit PROGRAM work task, using the standard scheduler/Resolver.
pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    selection: Selection,
    reporter: Reporter,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let canonical: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = gnunet_resolver_broker::LiveConfiguration::new(config);
    let (mut context, driver) = gnunet_resolver_broker::broker::<16, 1024>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        canonical.clone(),
    )?;
    let retirement = Rc::new(RefCell::new(None));
    let facts = Rc::new(RefCell::new(Facts::default()));
    let resolver = Resolver {
        driver,
        closed: false,
        retirement: retirement.clone(),
    };
    let result = Rc::new(RefCell::new(None::<Result<(), Failure>>));
    let receiving = result.clone();
    let history = facts.clone();
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = receiving.clone();
            let stop = scope.clone();
            let aborted = history.clone();
            let task_facts = aborted.clone();
            if let Err(e) = scope.spawn(async move {
                *destination.borrow_mut() = Some(
                    run(
                        resolver, live, canonical, settings, selection, reporter, history,
                    )
                    .await,
                );
                if let Err(e) = stop.shutdown() {
                    let original = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(Err(Box::new(Failed {
                        original,
                        cleanup: vec![Box::new(e)],
                        facts: task_facts,
                    })));
                }
            }) {
                let cleanup: Vec<Failure> = scope
                    .shutdown()
                    .err()
                    .map(|e| Box::new(e) as Failure)
                    .into_iter()
                    .collect();
                *receiving.borrow_mut() = Some(Err(Box::new(Failed {
                    original: Some(Box::new(e)),
                    cleanup,
                    facts: aborted,
                })));
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without the original ABD action result".into()));
    let mut cleanup: Vec<Failure> = Vec::new();
    match program {
        Ok(1) => {}
        Ok(code) => cleanup.push(format!("ABD PROGRAM returned {code}").into()),
        Err(e) => cleanup.push(Box::new(e) as Failure),
    }
    if let Some(e) = retirement.borrow_mut().take() {
        cleanup.push(e);
    }
    match task {
        Ok(()) if cleanup.is_empty() => Ok(()),
        task => Err(Box::new(Failed {
            original: task.err(),
            cleanup,
            facts,
        })),
    }
}
async fn run(
    resolver: Resolver,
    live: gnunet_client_host::LiveConfiguration,
    clock: Arc<dyn RuntimeClock>,
    settings: Settings,
    selection: Selection,
    reporter: Reporter,
    facts: SharedFacts,
) -> Result<(), Failure> {
    let original = Bounds::new(clock.as_ref(), selection.lifetime)?;
    let signals = Signals::new()?;
    let sources = Sources::new(live, &resolver, &selection.action)?;
    let canonical = Box::pin(Deadline::at(
        clock.clone(),
        gnunet_types::AbsoluteTime::from_micros(original.expires),
    )?);
    let native = Box::pin(tokio::time::sleep_until(original.hard.into()));
    let mut control = Control {
        clock,
        settings,
        original,
        facts: facts.clone(),
        reporter,
        signals,
        resolver,
        canonical,
        native,
    };
    let outcome = async {
        control.gate().await?;
        let mut buffers = crate::text::Buffers::new(settings)?;
        match selection.action {
            Action::IssuerStore {
                ego,
                attribute,
                policy,
                expiration,
                private,
            } => {
                let identity = identity::lookup(
                    &mut control,
                    sources
                        .identity
                        .ok_or("missing original IDENTITY selector")?,
                    &ego,
                )
                .await?;
                let record = buffers.parse(gnunet_gnsrecord::RecordType::ATTRIBUTE, &policy)?;
                let expiry = crate::text::expiration(&expiration, false)?;
                namestore::prepend(
                    &mut control,
                    sources
                        .namestore
                        .ok_or("missing original NAMESTORE selector")?,
                    identity.into_secret(),
                    &attribute,
                    &record,
                    gnunet_gnsrecord::RecordType::ATTRIBUTE,
                    expiry,
                    private,
                )
                .await?;
                crate::output::write(&mut control, b"Adding successful.\n").await
            }
            Action::SubjectStore {
                ego,
                record,
                private,
            } => {
                let canonical = buffers.parse(gnunet_gnsrecord::RecordType::DELEGATE, &record)?;
                let credential = gnunet_abd::Credential::verify_record(
                    &canonical,
                    control.time()?,
                    settings.name_bytes,
                    settings.text_bytes,
                )?;
                let identity = identity::lookup(
                    &mut control,
                    sources
                        .identity
                        .ok_or("missing original IDENTITY selector")?,
                    &ego,
                )
                .await?;
                let delegate = credential.view()?.delegate();
                if delegate.subject.bytes() != &identity.public_key()? {
                    return Err(
                        "signed import subject does not match the actual ego public key".into(),
                    );
                }
                let expiry = crate::text::Expiration {
                    value: delegate.expiration_us,
                    relative: false,
                };
                namestore::prepend(
                    &mut control,
                    sources
                        .namestore
                        .ok_or("missing original NAMESTORE selector")?,
                    identity.into_secret(),
                    b"@",
                    credential.bytes(),
                    gnunet_gnsrecord::RecordType::DELEGATE,
                    expiry,
                    private,
                )
                .await?;
                crate::output::write(&mut control, b"Adding successful.\n").await
            }
            Action::Sign {
                ego,
                subject,
                subject_role,
                attribute,
                expiration,
            } => {
                let expiry = crate::text::expiration(&expiration, true)?;
                let identity = identity::lookup(
                    &mut control,
                    sources
                        .identity
                        .ok_or("missing original IDENTITY selector")?,
                    &ego,
                )
                .await?;
                control.gate().await?;
                let secret = identity.into_secret();
                let credential = gnunet_abd::issue(
                    &secret,
                    subject,
                    &attribute,
                    subject_role.as_deref(),
                    expiry.value,
                    control.time()?,
                    settings.name_bytes,
                    settings.text_bytes,
                )?;
                drop(secret);
                let mut formatted =
                    buffers.format(gnunet_gnsrecord::RecordType::DELEGATE, credential.bytes())?;
                formatted.try_reserve_exact(1)?;
                crate::output::record_line(&formatted)?;
                formatted.push(b'\n');
                crate::output::write(&mut control, &formatted).await
            }
            Action::Collect {
                ego,
                issuer,
                attribute,
                direction,
            } => {
                let identity = identity::lookup(
                    &mut control,
                    sources
                        .identity
                        .ok_or("missing original IDENTITY selector")?,
                    &ego,
                )
                .await?;
                request::collect(
                    &mut control,
                    sources.abd.ok_or("missing original ABD selector")?,
                    identity.into_secret(),
                    issuer,
                    &attribute,
                    direction,
                    &mut buffers,
                )
                .await
            }
            Action::Verify {
                subject,
                issuer,
                attribute,
                delegates,
                direction,
            } => {
                request::verify(
                    &mut control,
                    sources.abd.ok_or("missing original ABD selector")?,
                    subject,
                    issuer,
                    &attribute,
                    &delegates,
                    direction,
                    &mut buffers,
                )
                .await
            }
        }
    }
    .await;
    control.resolver.close();
    if facts.borrow().undrained != 0 {
        return Err(Box::new(Failed {
            original: outcome.err(),
            cleanup: vec!["original native retirement has undrained completion debt".into()],
            facts,
        }));
    }
    outcome
}
