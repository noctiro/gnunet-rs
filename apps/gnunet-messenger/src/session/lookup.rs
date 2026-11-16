//! Exact original IDENTITY lookup and independent cleanup.
use super::*;
#[derive(Debug)]
struct LookupFailure {
    cause: identity::LossCause,
    operations: usize,
    exposed: usize,
}
impl std::fmt::Display for LookupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original IDENTITY lookup source: cause={:?}; operations={}; exposed={}",
            self.cause, self.operations, self.exposed
        )
    }
}
impl std::error::Error for LookupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            identity::LossCause::Io(e) => Some(e),
            identity::LossCause::Protocol(e) | identity::LossCause::Resource(e) => Some(e),
            identity::LossCause::Ports(e) => Some(e),
            _ => None,
        }
    }
}
pub(super) struct LookupInputs<'run, 'id> {
    pub(super) instance: &'id identity::Instance,
    pub(super) endpoint: EndpointSource,
    pub(super) name: &'run [u8],
    pub(super) source: &'run Arc<dyn RuntimeClock>,
    pub(super) resolver: &'run mut Driver<128, 256>,
    pub(super) signals: &'run mut Signals,
    pub(super) reporter: &'run Reporter,
    pub(super) initial: gnunet_service_runtime::clock::Bounds,
}
pub(super) async fn lookup(
    input: LookupInputs<'_, '_>,
) -> Result<Option<identity::SecretKey>, Failure> {
    let LookupInputs {
        instance,
        endpoint,
        name,
        source,
        resolver,
        signals,
        reporter,
        initial,
    } = input;
    initial.check(source.as_ref())?;
    let hard: Instant = initial.hard();
    let until = AbsoluteTime::from_micros(initial.expires());
    let mut native = Box::pin(tokio::time::sleep_until(hard));
    let mut logical = Box::pin(LogicalDeadline::at(source.clone(), until)?);
    let mut owner = identity::Lookup::exact(
        instance,
        endpoint,
        name,
        until.as_micros(),
        identity::Limits {
            reconnect: false,
            ..Default::default()
        },
    )?;
    let result: Result<Option<identity::SecretKey>, Failure> = async {
        loop {
            let event = {
                let mut observe_resolver = |event| {
                    reporter.debug(
                        "messenger.identity.resolver",
                        format_args!("Resolver: {event:?}"),
                    )
                };
                let mut resolving =
                    std::pin::pin!(resolver.drive_waiting(None, &mut observe_resolver));
                poll_fn(|cx| {
                    if let Poll::Ready(result) = signals.poll(cx) {
                        return Poll::Ready(
                            result.map(|()| None).map_err(|e| Box::new(e) as Failure),
                        );
                    }
                    if native.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(
                            "original ego lookup native deadline expired".into()
                        ));
                    }
                    if let Poll::Ready(result) = logical.as_mut().poll(cx) {
                        return Poll::Ready(Err(match result {
                            Ok(()) => "original ego lookup deadline expired".into(),
                            Err(e) => Box::new(e) as Failure,
                        }));
                    }
                    let event = owner.poll(cx, Some(hard));
                    if event.is_ready() {
                        return event.map(|v| v.map(Some).map_err(|e| Box::new(e) as Failure));
                    }
                    if reporter.failed() {
                        return Poll::Ready(Ok(None));
                    }
                    if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                        if let Err(error) = result {
                            return Poll::Ready(Err(Box::new(error) as Failure));
                        }
                        if event.is_pending() {
                            cx.waker().wake_by_ref();
                        }
                    }
                    event.map(|v| v.map(Some).map_err(|e| Box::new(e) as Failure))
                })
                .await?
            };
            match event {
                None => return Ok(None),
                Some(identity::LookupProgress::Finished {
                    outcome: identity::LookupOutcome::Found(ego),
                    ..
                }) => return Ok(Some(ego.into_secret())),
                Some(identity::LookupProgress::Finished {
                    outcome: identity::LookupOutcome::ResultCode(200),
                    ..
                }) => {
                    reporter.warning(
                        "messenger.ego.missing",
                        format_args!(
                            "requested ego is absent; using the official anonymous identity"
                        ),
                    );
                    return Ok(Some(identity::SecretKey::anonymous()));
                }
                Some(identity::LookupProgress::Finished { outcome, .. }) => {
                    return Err(format!("original ego lookup: {outcome:?}").into());
                }
                Some(identity::LookupProgress::Closed) => {
                    return Err("original ego lookup ended without a result".into());
                }
                Some(identity::LookupProgress::Source(identity::Progress::Lost {
                    cause,
                    report,
                })) => {
                    return Err(Box::new(LookupFailure {
                        cause,
                        operations: report.operations,
                        exposed: report.exposed,
                    }) as Failure);
                }
                Some(identity::LookupProgress::Source(identity::Progress::Unavailable(error))) => {
                    return Err(Box::new(error) as Failure);
                }
                Some(identity::LookupProgress::Source(identity::Progress::ConnectRetry {
                    error,
                    ..
                })) => return Err(Box::new(error) as Failure),
                Some(identity::LookupProgress::Source(event)) => reporter.debug(
                    "messenger.identity.activity",
                    format_args!("IDENTITY: {event:?}"),
                ),
            }
            tokio::task::yield_now().await;
        }
    }
    .await;
    let _original_close = owner.close();
    result
}
