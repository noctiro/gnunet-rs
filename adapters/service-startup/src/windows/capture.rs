//! Once-only Windows bootstrap declarations and fresh client registration.
use super::{
    control::ControlReceiver,
    grant::{LENGTH, Verifier},
    ready::ReadyWriter,
};
use gnunet_native::{
    pipe::{Endpoint, StartupPipe},
    socket_activation::{ACCOUNT_HANDLE_PREFIX, BOOTSTRAP_KEY_PREFIX, Incoming},
};
use gnunet_service_runtime::pipe::PipeConnection;
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
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
/// Original bootstrap location or the sole client used for an early grant.
pub struct ParentControl {
    pipe: ParentPipe,
    role: ParentRole,
}
enum ParentPipe {
    Location(Endpoint),
    Connected(StartupPipe),
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
        let connection = match self.pipe {
            ParentPipe::Location(endpoint) => PipeConnection::connect(&endpoint),
            ParentPipe::Connected(pipe) => PipeConnection::register_startup_pipe(pipe),
        }?;
        let (reader, writer) = connection.split();
        Ok(ConnectedParent {
            control: ControlReceiver::new(reader),
            ready: ReadyWriter::new(writer),
        })
    }
    #[expect(
        unsafe_code,
        reason = "Verified launch signature and original process target precede fresh-process adoption of the exclusive duplicated section"
    )]
    unsafe fn receive_activation(&mut self, verifier: Verifier) -> io::Result<Incoming> {
        let ParentPipe::Location(endpoint) = &self.pipe else {
            return Err(io::ErrorKind::AlreadyExists.into());
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let pipe = StartupPipe::connect(endpoint)?;
        let mut frame = [0; LENGTH];
        pipe.read_exact(&mut frame, deadline)?;
        let (handle, publisher) = verifier.verify(&frame, std::process::id())?;
        // SAFETY: this fresh process received an exclusive noninheritable handle
        // from the original launcher, authenticated before using its raw value.
        let incoming = unsafe { Incoming::capture_bootstrap(handle, publisher) }?;
        self.pipe = ParentPipe::Connected(pipe);
        Ok(incoming)
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
/// Consume process-local declarations and read-only native activation once.
/// Removes all consumed hints, including malformed ones. Unix FD declarations
/// are refused; Windows sockets use actual native provider duplication.
///
/// # Safety
/// Call at fresh single-threaded startup before native/Rust/CRT owners or runtime
/// registration. Any activation handle is exclusively transferred foreign
/// ownership with the immutable read-only publisher contract of
/// [`Incoming::capture`]. An account section follows
/// [`Incoming::capture_inherited_account`] or [`Incoming::capture_bootstrap`].
/// Exit startup on error; do not replay or continue after
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
    let mut parent_control = declaration
        .filter(|value| !value.is_empty())
        .map(Endpoint::parse)
        .transpose()?
        .map(|endpoint| ParentControl {
            pipe: ParentPipe::Location(endpoint),
            role,
        });
    let activation = activation
        .map(|value| {
            let text = value.to_str().ok_or(io::ErrorKind::InvalidInput)?;
            let account = text.strip_prefix(ACCOUNT_HANDLE_PREFIX);
            let brokered = text.strip_prefix(BOOTSTRAP_KEY_PREFIX);
            if (brokered.is_some() || account.is_some())
                && (parent_control.is_none() || role != ParentRole::Supervisor)
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            if let Some(key) = brokered {
                let parent = parent_control.as_mut().ok_or(io::ErrorKind::InvalidInput)?;
                // SAFETY: original launcher supplies the verification key in
                // the fresh child's environment and owns the suspended transfer.
                return unsafe { parent.receive_activation(Verifier::parse(key)?) };
            }
            if let Some(declaration) = account {
                let (handle, publisher) = declaration
                    .split_once(':')
                    .ok_or(io::ErrorKind::InvalidInput)?;
                let raw = parse_handle(handle)?;
                // SAFETY: the fresh-process caller establishes exclusive inheritance
                // and the original supervisor's immutable publication and SID.
                return unsafe { Incoming::capture_inherited_account(raw, publisher) };
            }
            let raw = parse_handle(text)?;
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

fn parse_handle(text: &str) -> io::Result<usize> {
    if text.is_empty()
        || text.len() > 2 * size_of::<usize>()
        || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    usize::from_str_radix(text, 16).map_err(|_| io::ErrorKind::InvalidInput.into())
}
