//! Shared early startup for PROGRAM clients that do not accept service listeners.
use crate::{ParentControl, StopSignals};
use std::{fmt, io};

#[derive(Debug)]
enum Cause {
    Capture(io::Error),
    #[cfg(unix)]
    Listeners(crate::ReleaseReport),
    #[cfg(windows)]
    Listeners,
    #[cfg(unix)]
    Register(gnunet_service_runtime::readiness::RegisterError),
    #[cfg(windows)]
    Register(io::Error),
    Subscription(io::Error),
}
/// Failed client startup or stop registration. A Unix registration failure
/// retains its original descriptor until this error is dropped.
#[derive(Debug)]
pub struct ClientError(Cause);
impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Cause::Capture(error) => write!(f, "client startup capture: {error}"),
            #[cfg(unix)]
            Cause::Listeners(report) => write!(
                f,
                "client refuses inherited service listener/readiness descriptors: {report:?}"
            ),
            #[cfg(windows)]
            Cause::Listeners => f.write_str("client refuses inherited service listeners"),
            #[cfg(unix)]
            Cause::Register(failure) => write!(f, "client parent registration: {}", failure.error),
            #[cfg(windows)]
            Cause::Register(error) => write!(f, "client parent registration: {error}"),
            Cause::Subscription(error) => write!(f, "client stop registration: {error}"),
        }
    }
}
impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            Cause::Capture(error) | Cause::Subscription(error) => Some(error),
            #[cfg(unix)]
            Cause::Register(failure) => Some(&failure.error),
            #[cfg(windows)]
            Cause::Register(error) => Some(error),
            #[cfg(unix)]
            Cause::Listeners(_) => None,
            #[cfg(windows)]
            Cause::Listeners => None,
        }
    }
}
/// Once-captured startup for a client with no listening-service readiness role.
pub struct ClientStartup {
    /// Original parent declaration, consumed later under the caller's runtime.
    pub parent: Option<ParentControl>,
    /// Ignored malformed/closed Unix control declaration, without fake success.
    #[cfg(unix)]
    pub notice: Option<crate::ControlNotice>,
}
impl ClientStartup {
    /// Capture the process's original inheritance and refuse service listeners.
    ///
    /// # Safety
    /// Call exactly once as the fresh process's first initialization, before
    /// logger/files/runtime/threads or competing descriptor/handle owners exist.
    /// Exclude concurrent environment and descriptor-table mutation. A capture
    /// error requires startup exit; the caller must not retry or continue with
    /// potentially consumed declarations.
    #[expect(
        unsafe_code,
        reason = "Caller supplies the unique fresh-process inheritance transfer contract"
    )]
    pub unsafe fn capture() -> Result<Self, ClientError> {
        #[cfg(unix)]
        {
            // SAFETY: the caller transfers the same exclusive startup contract.
            let captured = unsafe {
                crate::capture_from_environment(crate::InheritedMode::CloseAfterConfiguredBind)
            }
            .map_err(|error| ClientError(Cause::Capture(error)))?;
            match captured.inherited {
                crate::InheritedResources::CloseAfterBind(hold) => {
                    let nonempty = !hold.is_empty();
                    let released = hold.abort();
                    if nonempty {
                        return Err(ClientError(Cause::Listeners(released)));
                    }
                }
                crate::InheritedResources::Listeners(_) => {
                    return Err(ClientError(Cause::Capture(io::Error::other(
                        "unexpected client inheritance mode",
                    ))));
                }
            }
            Ok(Self {
                parent: captured.parent_control,
                notice: captured.control_notice,
            })
        }
        #[cfg(windows)]
        {
            // SAFETY: the caller transfers the same exclusive startup contract.
            let captured = unsafe { crate::capture_from_environment() }
                .map_err(|error| ClientError(Cause::Capture(error)))?;
            if captured.activation.is_some() {
                return Err(ClientError(Cause::Listeners));
            }
            Ok(Self {
                parent: captured.parent_control,
            })
        }
    }
}
impl StopSignals {
    /// Register a PROGRAM client's original parent and native stop streams on
    /// the current runtime. Clients do not publish listening-service readiness.
    pub fn for_client(parent: Option<ParentControl>) -> Result<Self, ClientError> {
        #[cfg(unix)]
        let parent = parent
            .map(|parent| parent.register())
            .transpose()
            .map_err(|failure| ClientError(Cause::Register(failure)))?;
        #[cfg(windows)]
        let parent = parent
            .map(|parent| parent.register())
            .transpose()
            .map_err(|error| ClientError(Cause::Register(error)))?
            .map(|connected| connected.control);
        Self::new(parent).map_err(|error| ClientError(Cause::Subscription(error)))
    }
}
