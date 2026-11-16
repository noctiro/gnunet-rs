//! Once-only Windows bootstrap declarations and fresh client registration.
use super::{control::ControlReceiver, ready::ReadyWriter};
use gnunet_native::{pipe::Endpoint, socket_activation::Incoming};
use gnunet_service_runtime::pipe::PipeConnection;
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};
const CONTROL: &str = "GNUNET_OS_CONTROL_PIPE";
pub(super) const ACTIVATION: &str = "GNUNET_RS_ACTIVATION_HANDLE";
pub(super) const DETACH: &str = "GNUNET_RS_DETACH_PIPE";
static CAPTURED: AtomicBool = AtomicBool::new(false);

/// Once-only process bootstrap locations and native activation ownership.
pub struct CapturedStartup {
    /// Private parent byte channel, if this process was launched with one.
    pub parent_control: Option<ParentControl>,
    /// Captured read-only native metadata. Materialize after console detachment,
    /// before listener registration; failure or abandonment requires startup exit.
    pub activation: Option<Incoming>,
}
/// Captured local location. Registration opens a fresh overlapped client handle.
pub struct ParentControl {
    endpoint: Endpoint,
    role: ParentRole,
}
/// Declared purpose of the captured process-local channel. This does not itself
/// prove console state, peer identity, liveness or readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParentRole {
    /// A persistent service supervisor supplies cooperative control.
    Supervisor,
    /// A one-shot launcher awaits startup from its detached re-exec child.
    DetachLauncher,
}
impl ParentControl {
    /// Original validated bootstrap purpose; no native effect occurs.
    pub fn role(&self) -> ParentRole {
        self.role
    }
    /// Consume this declaration under an entered Tokio runtime with I/O enabled.
    /// The parent must have reserved the endpoint before creation. No fallback,
    /// retry or second connection from this captured declaration is hidden.
    pub fn register(self) -> io::Result<ConnectedParent> {
        let (reader, writer) = PipeConnection::connect(&self.endpoint)?.split();
        Ok(ConnectedParent {
            control: ControlReceiver::new(reader),
            ready: ReadyWriter::new(writer),
        })
    }
}
/// Unique logical directions of one original physical parent connection.
/// Dropping a single direction does not half-close the native pipe.
pub struct ConnectedParent {
    /// Exact parent control bytes; EOF does not request termination.
    pub control: ControlReceiver,
    /// Once-only child startup status writer.
    pub ready: ReadyWriter,
}
/// Consume process-local declarations and exclusively inherited activation once.
/// Removes all consumed hints, including malformed ones. Unix FD declarations
/// are refused; Windows sockets use actual native provider duplication.
///
/// # Safety
/// Call at fresh single-threaded startup before native/Rust/CRT owners or runtime
/// registration. Any activation handle is exclusively transferred foreign
/// ownership with the immutable read-only publisher contract of
/// [`Incoming::capture`]. Exit startup on error; do not replay or continue after
/// abandoning incoming provider reservations. Repeated calls return AlreadyExists
/// before inspecting hints; fresh-process preconditions apply to the first attempt.
#[expect(
    unsafe_code,
    reason = "Fresh-process caller transfers exclusive inherited mapping ownership; environment removals are synchronized by Windows"
)]
pub unsafe fn capture_from_environment() -> io::Result<CapturedStartup> {
    CAPTURED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| io::Error::from(io::ErrorKind::AlreadyExists))?;
    let declaration = std::env::var_os(CONTROL);
    let detach = std::env::var_os(DETACH).filter(|value| !value.is_empty());
    let activation = std::env::var_os(ACTIVATION).filter(|value| !value.is_empty());
    // SAFETY: Windows synchronizes environment access. No pointer into the
    // environment is retained: var_os returned owned data.
    unsafe {
        std::env::remove_var(CONTROL);
        std::env::remove_var(DETACH);
        std::env::remove_var(ACTIVATION);
    }
    for key in ["LISTEN_FDS", "LISTEN_FDNAMES"] {
        if std::env::var_os(key).is_some_and(|value| !value.is_empty() && value != "0") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unix raw descriptor activation is unavailable on Windows",
            ));
        }
    }
    let role = match detach {
        None => ParentRole::Supervisor,
        Some(marker) if !marker.is_empty() && declaration.as_ref() == Some(&marker) => {
            ParentRole::DetachLauncher
        }
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "detached-child marker does not match its private parent endpoint",
            ));
        }
    };
    let parent_control = declaration
        .filter(|value| !value.is_empty())
        .map(Endpoint::parse)
        .transpose()?
        .map(|endpoint| ParentControl { endpoint, role });
    let activation = activation
        .map(|value| {
            let text = value.to_str().ok_or(io::ErrorKind::InvalidInput)?;
            if text.is_empty()
                || text.len() > 2 * size_of::<usize>()
                || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let raw = usize::from_str_radix(text, 16).map_err(|_| io::ErrorKind::InvalidInput)?;
            // SAFETY: the fresh-process caller establishes exclusive inherited
            // ownership and immutable read-only publication before this capture.
            unsafe { Incoming::capture(raw) }
        })
        .transpose()?;
    Ok(CapturedStartup {
        parent_control,
        activation,
    })
}
