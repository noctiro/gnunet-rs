//! Fresh native inheritance, parent registration and bounded startup status.
use super::Failure;
use gnunet_service_runtime::Activation;
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::io;

/// Transfer the process's original activation and parent declarations once.
///
/// # Safety
/// Call first in the fresh single-threaded process, before files, runtime,
/// environment mutation or competing descriptor/handle owners.
#[expect(
    unsafe_code,
    reason = "The executable entry supplies exclusive fresh-process inheritance ownership"
)]
pub(super) unsafe fn capture() -> Result<(Activation, Option<ParentControl>), Failure> {
    #[cfg(unix)]
    {
        use gnunet_service_startup::{InheritedMode, InheritedResources};
        // SAFETY: caller transfers the same exclusive fresh-process contract.
        let captured = unsafe {
            gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)?
        };
        if let Some(notice) = captured.control_notice {
            use std::io::Write;
            let _diagnostic = writeln!(io::stderr().lock(), "node parent control: {notice:?}");
        }
        let InheritedResources::Listeners(activation) = captured.inherited else {
            return Err("wrong foreground startup route".into());
        };
        Ok((activation, captured.parent_control))
    }
    #[cfg(windows)]
    {
        // SAFETY: caller transfers the same exclusive fresh-process contract.
        let captured = unsafe { gnunet_service_startup::capture_from_environment()? };
        let activation = captured
            .activation
            .map(|incoming| incoming.materialize().and_then(Activation::from_imported))
            .transpose()?
            .unwrap_or_default();
        Ok((activation, captured.parent_control))
    }
}

pub(super) struct Registered {
    pub control: Option<ControlReceiver>,
    #[cfg(windows)]
    pub ready: Option<gnunet_service_startup::ReadyWriter>,
}

/// Register only after entering the caller's native I/O runtime.
pub(super) fn register(parent: Option<ParentControl>) -> io::Result<Registered> {
    #[cfg(unix)]
    {
        let parent = parent
            .map(|parent| parent.register().map_err(|failure| failure.error))
            .transpose()?;
        Ok(Registered { control: parent })
    }
    #[cfg(windows)]
    {
        let parent = parent.map(|parent| parent.register()).transpose()?;
        let (control, ready) = match parent {
            Some(parent) => (Some(parent.control), Some(parent.ready)),
            None => (None, None),
        };
        Ok(Registered { control, ready })
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct ReadinessFailure {
    original: Failure,
    notification: Failure,
}
#[cfg(windows)]
impl std::fmt::Display for ReadinessFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "node startup: {}; independent failure notification: {}",
            self.original, self.notification
        )
    }
}
#[cfg(windows)]
impl std::error::Error for ReadinessFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}

#[cfg(windows)]
pub(super) async fn finish<T>(
    result: Result<T, Failure>,
    ready: &mut Option<gnunet_service_startup::ReadyWriter>,
) -> Result<T, Failure> {
    use gnunet_service_startup::ReadyStatus;
    let notification = if let Some(writer) =
        ready.as_mut().filter(|writer| writer.intent().is_none())
    {
        let status = if result.is_err() {
            ReadyStatus::InitializationFailed
        } else {
            ReadyStatus::ServerNotStarted
        };
        match tokio::time::timeout(std::time::Duration::from_secs(5), writer.signal(status)).await {
            Ok(result) => result
                .map(|_| ())
                .map_err(|error| Box::new(error) as Failure),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "node startup notification deadline",
            )
            .into()),
        }
    } else if result.is_ok()
        && ready
            .as_ref()
            .is_some_and(|writer| writer.intent().is_some())
    {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "node stopped during original readiness notification",
        )
        .into())
    } else {
        Ok(())
    };
    // A canceled/failed readiness write retains its original intent. Closing
    // this original direction never substitutes another startup status.
    drop(ready.take());
    match (result, notification) {
        (Err(original), Err(notification)) => Err(Box::new(ReadinessFailure {
            original,
            notification,
        })),
        (Err(original), Ok(())) => Err(original),
        (Ok(_), Err(notification)) => Err(notification),
        (Ok(value), Ok(())) => Ok(value),
    }
}
