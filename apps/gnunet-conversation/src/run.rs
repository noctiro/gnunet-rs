use crate::{
    Failure, media,
    options::{Selection, Settings},
    terminal,
};
use gnunet_conversation_client_host::{Bounds, EndpointSource};
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
mod lookup;
mod sources;
mod state;

#[derive(Debug, Default)]
pub(super) struct Facts {
    identity_found: bool,
    identity_result: Option<u32>,
    identity_local: Option<(
        gnunet_identity_client_host::LocalReason,
        gnunet_identity_client_host::Submission,
        Option<u32>,
    )>,
    identity_initialized: bool,
    identity_retired: Option<(usize, usize, usize)>,
    identity_lookup_retired: Option<(usize, usize, usize)>,
    identity_cause: Option<gnunet_identity_client_host::LossCause>,
    pils_observed: bool,
    pils_retained: usize,
    pils_retired: usize,
    pils_cause: Option<gnunet_pils_host::client::LossCause>,
    sdk_first: Option<gnunet_conversation_client_host::Loss>,
    sdk_last: Option<gnunet_conversation_client_host::Loss>,
    sdk_retirements: u64,
    phone_recovery_losses: u64,
    phone_reregistrations: u64,
    last_write: Option<gnunet_conversation_client_host::Receipt>,
    native_write_events: u64,
    retry_first: Option<(&'static str, io::Error)>,
    retry_last: Option<(&'static str, io::Error)>,
    gns_last: Option<gnunet_gns_host::tld::Diagnostics>,
    gns_attempts: u64,
    media_first: Option<media::Report>,
    media_last: Option<media::Report>,
    media_sessions: u64,
    terminal: Option<terminal::Report>,
    cleanup_failed: bool,
    cleanup_errors: [Option<Failure>; 8],
    cleanup_overflow: bool,
}
pub(super) type Shared = Rc<RefCell<Facts>>;
impl Facts {
    fn cleanup(&mut self, error: Failure) {
        self.cleanup_failed = true;
        if let Some(slot) = self.cleanup_errors.iter_mut().find(|e| e.is_none()) {
            *slot = Some(error);
        } else {
            self.cleanup_overflow = true;
        }
    }

    fn retry(&mut self, owner: &'static str, error: io::Error) {
        if self.retry_first.is_none() {
            self.retry_first = Some((owner, error));
        } else {
            self.retry_last = Some((owner, error));
        }
    }
    fn sdk(&mut self, loss: gnunet_conversation_client_host::Loss) {
        self.sdk_retirements = self.sdk_retirements.saturating_add(1);
        if self.sdk_first.is_none() {
            self.sdk_first = Some(loss);
        } else {
            self.sdk_last = Some(loss);
        }
    }
    pub(super) fn media(&mut self, r: media::Report) {
        self.media_sessions = self.media_sessions.saturating_add(1);
        self.cleanup_failed |=
            r.original.is_some() || !r.cleanup.is_empty() || r.cleanup_overflow || r.undrained != 0;
        if self.media_first.is_none() {
            self.media_first = Some(r);
        } else {
            self.media_last = Some(r);
        }
    }
}
#[derive(Debug)]
struct Failed {
    original: Option<Failure>,
    cleanup: Vec<Failure>,
    facts: Shared,
}
impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Conversation original={:?}; cleanup={:?}; actual bounded observations={:?}",
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
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}
impl Signals {
    fn new() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("Conversation signal source ended")));
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
struct Control {
    clock: Arc<dyn RuntimeClock>,
    original: Bounds,
    reporter: Reporter,
    signals: Signals,
    resolver: Resolver,
    canonical: Pin<Box<Deadline>>,
    native: Pin<Box<tokio::time::Sleep>>,
}
impl Control {
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        self.reporter.register(cx);
        if self.reporter.failed() {
            return Err("selected Conversation Logger failed".into());
        }
        if let Poll::Ready(result) = self.signals.poll(cx) {
            result?;
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Conversation canceled by original signal",
            )
            .into());
        }
        self.original.check(self.clock.as_ref())?;
        if self.native.as_mut().poll(cx).is_ready() {
            return Err(gnunet_types::Error::Deadline.into());
        }
        match self.canonical.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => return Err(gnunet_types::Error::Deadline.into()),
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Pending => {}
        }
        Ok(())
    }
    async fn next<T>(
        &mut self,
        mut source: impl FnMut(&mut Context<'_>) -> Poll<Result<T, Failure>>,
    ) -> Result<T, Failure> {
        tokio::task::yield_now().await;
        poll_fn(|cx| {
            self.guard(cx)?;
            let mut activity = false;
            {
                let mut drive = std::pin::pin!(self.resolver.driver.drive_waiting(None, |event| {
                    self.reporter.debug(
                        "conversation.resolver.activity",
                        format_args!("Resolver: {event:?}"),
                    )
                }));
                match drive.as_mut().poll(cx) {
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e) as Failure)),
                    Poll::Pending => {}
                }
            }
            self.guard(cx)?;
            let value = source(cx);
            if value.is_pending() && activity {
                cx.waker().wake_by_ref();
            }
            value
        })
        .await
    }
    fn bounded(&self, duration: std::time::Duration) -> Result<Bounds, Failure> {
        let cap = Bounds::new(self.clock.as_ref(), duration)?;
        Ok(Bounds {
            expires: cap.expires.min(self.original.expires),
            hard: cap.hard.min(self.original.hard),
        })
    }
}

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
    let resolver = Resolver {
        driver,
        closed: false,
        retirement: retirement.clone(),
    };
    let facts = Rc::new(RefCell::new(Facts::default()));
    let receiving = Rc::new(RefCell::new(None::<Result<(), Failure>>));
    let result = receiving.clone();
    let history = facts.clone();
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |main, scope| {
            let destination = receiving.clone();
            let stop = scope.clone();
            let fallback = history.clone();
            let config = main.config.duplicate();
            if let Err(e) = scope.spawn(async move {
                let outcome = match config {
                    Ok(config) => {
                        run(Inputs {
                            resolver,
                            live,
                            clock: canonical,
                            config,
                            settings,
                            selection,
                            reporter,
                            facts: history,
                        })
                        .await
                    }
                    Err(e) => Err(Box::new(e) as Failure),
                };
                *destination.borrow_mut() = Some(outcome);
                if let Err(e) = stop.shutdown() {
                    let original = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(Err(Box::new(Failed {
                        original,
                        cleanup: vec![Box::new(e)],
                        facts: fallback,
                    })));
                }
            }) {
                *receiving.borrow_mut() = Some(Err(Box::new(e)));
                let _actual = scope.shutdown();
            }
        })
        .await;
    let task = result.borrow_mut().take().unwrap_or_else(|| {
        Err("PROGRAM ended without its original Conversation owner result".into())
    });
    let mut cleanup: Vec<Failure> = Vec::new();
    match program {
        Ok(1) => {}
        Ok(code) => cleanup.push(format!("Conversation PROGRAM returned {code}").into()),
        Err(e) => cleanup.push(Box::new(e)),
    }
    if let Some(e) = retirement.borrow_mut().take() {
        cleanup.push(e);
    }
    if facts.borrow().cleanup_failed {
        cleanup.push(
            "original owner cleanup or terminal restore failed; bounded facts retained".into(),
        );
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
struct Inputs {
    resolver: Resolver,
    live: gnunet_client_host::LiveConfiguration,
    clock: Arc<dyn RuntimeClock>,
    config: gnunet_config::Configuration,
    settings: Settings,
    selection: Selection,
    reporter: Reporter,
    facts: Shared,
}
async fn run(input: Inputs) -> Result<(), Failure> {
    let Inputs {
        resolver,
        live,
        clock,
        config,
        settings,
        selection,
        reporter,
        facts,
    } = input;
    let original = Bounds::new(clock.as_ref(), selection.life)?;
    let canonical = Box::pin(Deadline::at(
        clock.clone(),
        gnunet_types::AbsoluteTime::from_micros(original.expires),
    )?);
    let native = Box::pin(tokio::time::sleep_until(original.hard.into()));
    let signals = Signals::new()?;
    let mut control = Control {
        clock,
        original,
        reporter,
        signals,
        resolver,
        canonical,
        native,
    };
    let startup = control.bounded(settings.startup)?;
    let identity = gnunet_identity_client_host::Instance::new();
    let monitor = gnunet_identity_client_host::Instance::new();
    let mut pils = gnunet_pils::client::Instance::new();
    let selectors = sources::Selectors::new(live, &control.resolver)?;
    let source = sources::Sources::new(
        sources::Domains {
            lookup: &identity,
            monitor: &monitor,
            pils: &mut pils,
        },
        &selectors,
        &selection.ego,
        startup,
        &settings,
        facts.clone(),
    )?;
    let mut state = state::State::new(
        config,
        settings.clone(),
        selection.phone,
        source,
        selectors,
        original,
        facts.clone(),
    )?;
    let mut startup_alarm = Box::pin(tokio::time::sleep_until(startup.hard.into()));
    let outcome = async {
        while !state.ready() && !state.quit_requested() {
            control
                .next(|cx| {
                    if startup_alarm.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(gnunet_types::Error::Deadline.into()));
                    }
                    state.poll_startup(cx, startup)
                })
                .await?;
        }
        if state.quit_requested() {
            return Ok(());
        }
        state.register()?;
        loop {
            let event = control.next(|cx| state.poll(cx)).await?;
            match state.handle(event, &control)? {
                state::Next::Continue => {}
                state::Next::Quit => break,
                state::Next::Call(name) => {
                    let bound = control.bounded(settings.call)?;
                    if lookup::call(&mut state, &mut control, &name, bound).await? {
                        break;
                    }
                }
            }
        }
        Ok::<(), Failure>(())
    }
    .await;
    // Stop every old input and process pipe before independently draining only
    // physical cleanup and the bounded terminal queue. No new call is admitted.
    state.close_sources();
    control.resolver.close();
    state.stop_media();
    let hard = Instant::now()
        .checked_add(settings.shutdown)
        .ok_or(gnunet_types::Error::Overflow)?;
    let mut alarm = Box::pin(tokio::time::sleep_until(hard.into()));
    let cleanup = poll_fn(|cx| {
        if state.cleanup_done() {
            return Poll::Ready(Ok::<(), Failure>(()));
        }
        if alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(
                "Conversation shutdown target expired with original owner debt".into(),
            ));
        }
        match state.poll_cleanup(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    })
    .await;
    state.finish();
    match (outcome, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (original, cleanup) => Err(Box::new(Failed {
            original: original.err(),
            cleanup: cleanup.err().into_iter().collect(),
            facts,
        })),
    }
}
