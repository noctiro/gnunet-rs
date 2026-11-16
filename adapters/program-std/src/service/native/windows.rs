//! Native Windows identity, activation, detachment and parent status ownership.
use super::*;
use gnunet_service_runtime::Activation;
use gnunet_service_startup::{CapturedStartup, ParentRole, ReadyStatus, ReadyWriter};
use std::time::Duration;

const READY_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) type Ready<'a> = &'a mut Option<ReadyWriter>;

pub(super) async fn ready(original: Ready<'_>) -> Result<(), Failure> {
    if let Some(writer) = original.as_mut() {
        writer.signal(ReadyStatus::AcceptRegistered).await?;
    }
    drop(original.take());
    Ok(())
}

#[derive(Debug)]
struct NotificationFailure {
    original: Failure,
    notification: Failure,
}
impl fmt::Display for NotificationFailure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{}; independent parent notification: {}",
            self.original, self.notification
        )
    }
}
impl Error for NotificationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}

#[expect(
    unsafe_code,
    reason = "Exclusive process inheritance is transferred once by the native entry"
)]
pub(super) unsafe fn capture() -> Result<CapturedStartup, Failure> {
    // SAFETY: native::main forwards the unique fresh-process startup contract.
    Ok(unsafe { gnunet_service_startup::capture_from_environment() }?)
}

pub(super) fn run<A: Application>(
    captured: CapturedStartup,
    selected: Selected,
    logger: Logger<'static>,
    clock: SharedClock,
) -> Result<(), Failure> {
    let role = captured.parent_control.as_ref().map(|parent| parent.role());
    if selected.daemonize_requested() && role == Some(ParentRole::Supervisor) {
        #[expect(
            unsafe_code,
            reason = "Exclusive startup owns console/stdio before runtime and native stop registration"
        )]
        // SAFETY: output guards ended; no provider, cached stdio owner, runtime
        // or stop subscription competes with this original console transition.
        if let Err(error) = unsafe { gnunet_service_startup::daemon::detach_managed() } {
            return finish::<A>(Err(error.into()), &Reporter::new(logger, clock));
        }
    }
    let reports = Reporter::new(logger, clock.clone());
    let setup = (|| -> Result<_, Failure> {
        let activation = captured
            .activation
            .map(|incoming| Activation::from_imported(incoming.materialize()?))
            .transpose()?
            .unwrap_or_default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok((activation, runtime))
    })();
    let (activation, runtime) = match setup {
        Ok(setup) => setup,
        Err(error) => return finish::<A>(Err(error), &reports),
    };
    if selected.daemonize_requested() && role.is_none() {
        return finish::<A>(
            super::super::detach(&runtime, activation).map_err(|error| error as Failure),
            &reports,
        );
    }
    let connected = {
        let _entered = runtime.enter();
        captured
            .parent_control
            .map(|parent| parent.register())
            .transpose()
    };
    let (parent, mut readiness) = match connected {
        Ok(Some(parent)) => (Some(parent.control), Some(parent.ready)),
        Ok(None) => (None, None),
        Err(error) => return finish::<A>(Err(error.into()), &reports),
    };
    let result = (|| -> Result<(), Failure> {
        if reports.failed() {
            return Err(io::Error::other("service logger failed before initialization").into());
        }
        let config = super::super::load_configuration(
            std::sync::Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = A::settings(&config)?;
        gnunet_service_startup::verify_configured_identity(&config, A::SECTION)?;
        let listeners = if activation.is_empty() {
            runtime.block_on(BoundListeners::bind_configured(
                &config,
                A::SECTION,
                A::access(&settings).into(),
            ))?
        } else {
            let _entered = runtime.enter();
            BoundListeners::from_activation(activation)?
        };
        for error in listeners.failures() {
            reports.warning(
                "service.listener.alternate",
                format_args!("alternate listener: {error}"),
            );
        }
        let signals = {
            let _entered = runtime.enter();
            StopSignals::new(parent)?
        };
        runtime.block_on(A::serve(Context {
            config: &config,
            settings,
            listeners: &listeners,
            signals,
            clock: clock.clone(),
            reports: reports.clone(),
            readiness: Readiness {
                original: &mut readiness,
            },
        }))
    })();
    let result = super::super::retain_diagnostic(result, reports.take_error());
    finish::<A>(notify_failure(&runtime, &mut readiness, result), &reports)
}

fn notify_failure(
    runtime: &tokio::runtime::Runtime,
    readiness: Ready<'_>,
    result: Result<(), Failure>,
) -> Result<(), Failure> {
    let Err(original) = result else {
        return result;
    };
    // Never replace an admitted READY, including after canceled/failed waits.
    let Some(writer) = readiness
        .as_mut()
        .filter(|writer| writer.intent().is_none())
    else {
        return Err(original);
    };
    let notification = runtime.block_on(async {
        tokio::time::timeout(
            READY_TIMEOUT,
            writer.signal(ReadyStatus::InitializationFailed),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "failure notification deadline"))??;
        Ok::<_, Failure>(())
    });
    match notification {
        Ok(()) => Err(original),
        Err(notification) => Err(Box::new(NotificationFailure {
            original,
            notification,
        })),
    }
}
