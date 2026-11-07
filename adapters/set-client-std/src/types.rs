//! Public source-bound generic SET identities and explicit resource profiles.
use gnunet_types::Error as Fault;
use gnunet_wire::official::set::{Abi, Element};
use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
/// Original failure, without replacing native errors by a string.
#[derive(Debug)]
pub enum Error {
    /// An actual immutable owner/operation bound expired. Provider failures
    /// with the same error value retain their separate Clock/Client variant.
    Deadline(Box<crate::DeadlineContext>),
    /// Pure protocol/resource/identity refusal.
    Protocol(Fault),
    /// Unknown original public result word, preserved without treating it as success.
    UnexpectedStatus(u16),
    /// Actual CLIENT configuration/Resolver/endpoint-selection port failure.
    Client(gnunet_client_host::ConnectError),
    /// Actual shared Clock sample/subscription/notification failure. The error
    /// is retained even when its value is also used for an operation deadline.
    Clock(gnunet_client_host::ConnectError),
    /// Actual native read/write failure.
    Io(io::Error),
}
impl From<Fault> for Error {
    fn from(v: Fault) -> Self {
        Self::Protocol(v)
    }
}
impl From<io::Error> for Error {
    fn from(v: io::Error) -> Self {
        Self::Io(v)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(v: gnunet_client_host::ConnectError) -> Self {
        Self::Client(v)
    }
}
impl Error {
    // One cold allocation at the actual deadline check. Retirement assembly
    // subsequently moves this same box; it does not allocate another record.
    pub(crate) fn deadline(context: crate::DeadlineContext) -> Self {
        Self::Deadline(Box::new(context))
    }
    pub(crate) fn into_cause_parts(self) -> (Cause, Option<Box<crate::DeadlineContext>>) {
        match self {
            Self::Deadline(context) => (Cause::Deadline, Some(context)),
            error => (Cause::Failure(error), None),
        }
    }
    pub(crate) fn clock(error: impl Into<gnunet_client_host::ConnectError>) -> Self {
        Self::Clock(error.into())
    }
    /// Facts from this actual bound refusal, without sampling or granting authority.
    #[must_use]
    pub fn deadline_context(&self) -> Option<crate::DeadlineContext> {
        match self {
            Self::Deadline(context) => Some(**context),
            _ => None,
        }
    }
    /// Preserve the actual failing port boundary. A Clock/Selector error code
    /// alone never identifies an operation deadline or an original socket loss.
    #[must_use]
    pub const fn origin(&self) -> LossOrigin {
        match self {
            Self::Deadline(_) => LossOrigin::Bounds,
            Self::Clock(_) => LossOrigin::Clock,
            Self::Client(_) => LossOrigin::Selector,
            Self::Protocol(_) | Self::UnexpectedStatus(_) | Self::Io(_) => LossOrigin::Source,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deadline(_) => fmt::Display::fmt(&Fault::Deadline, f),
            Self::Protocol(e) => fmt::Display::fmt(e, f),
            Self::UnexpectedStatus(status) => {
                write!(f, "unexpected original SET result status {status}")
            }
            Self::Client(e) | Self::Clock(e) => fmt::Display::fmt(e, f),
            Self::Io(e) => fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Deadline(_) => None,
            Self::Protocol(e) => Some(e),
            Self::UnexpectedStatus(_) => None,
            Self::Client(e) | Self::Clock(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}
/// Set operation selected when the source is created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OperationType {
    /// Local element storage/iteration without reconciliation.
    Local = 0,
    /// Intersection.
    Intersection = 1,
    /// Union.
    Union = 2,
}
/// Actual public result selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ResultMode {
    /// Full result elements.
    Full = 0,
    /// Symmetric difference.
    Symmetric = 1,
    /// Elements removed from the local set.
    Removed = 2,
    /// Elements added to the local set.
    Added = 3,
}
impl ResultMode {
    /// Whether this active protocol operation supports the selected result mode.
    /// Local sets do not start reconciliation. This is checked before commit IO.
    #[must_use]
    pub const fn supports(self, operation: OperationType) -> bool {
        matches!(
            (operation, self),
            (OperationType::Intersection, Self::Full | Self::Removed)
                | (OperationType::Union, Self::Symmetric | Self::Added)
        )
    }
}
/// Actual result status, retaining its public numeric interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    /// One ordinary result element.
    Ok = 0,
    /// Element added locally.
    AddLocal = 1,
    /// Element added remotely.
    AddRemote = 2,
    /// Original operation failed.
    Failure = 3,
    /// Original half completed; still not terminal.
    HalfDone = 4,
    /// Original operation completed.
    Done = 5,
}
impl Status {
    pub(crate) fn from_raw(n: u16) -> Result<Self, Error> {
        Ok(match n {
            0 => Self::Ok,
            1 => Self::AddLocal,
            2 => Self::AddRemote,
            3 => Self::Failure,
            4 => Self::HalfDone,
            5 => Self::Done,
            _ => return Err(Error::UnexpectedStatus(n)),
        })
    }
    /// Only failure and done terminate an operation.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Failure | Self::Done)
    }
}
/// Original physical source identity; diagnostics confer no replacement authority.
#[derive(Clone)]
pub struct Epoch(pub(crate) Arc<AtomicBool>);
impl Epoch {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }
    pub(crate) fn live(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub(crate) fn retire(&self) {
        self.0.store(false, Ordering::Release);
    }
}
impl PartialEq for Epoch {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for Epoch {}
impl fmt::Debug for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Epoch")
            .field("live", &self.live())
            .finish_non_exhaustive()
    }
}
pub(crate) type Owner = Arc<()>;
macro_rules! id {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone)]
        pub struct $name {
            pub(crate) owner: Owner,
            pub(crate) serial: u64,
        }
        impl PartialEq for $name {
            fn eq(&self, r: &Self) -> bool {
                Arc::ptr_eq(&self.owner, &r.owner) && self.serial == r.serial
            }
        }
        impl Eq for $name {}
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.serial)
                    .finish()
            }
        }
    };
}
id!(
    OperationId,
    "One operation on its original Set owner; not a caller-chosen RID."
);
id!(
    MutationId,
    "One original Add/Remove continuation; whole write is not processing."
);
id!(
    IterationId,
    "One original set iteration; never recycled within its Set owner."
);
id!(CopyId, "One original lazy-copy request.");
/// Explicit source and per-owner queue/metadata resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual C result alignment/order, with no automatic fallback.
    pub abi: Abi,
    /// Complete input/output frame limit.
    pub frame_bytes: usize,
    /// Maximum original queued frames.
    pub queued_frames: usize,
    /// Maximum retained queued wire bytes.
    pub queued_bytes: usize,
    /// Maximum live operations on a Set.
    pub operations: usize,
    /// Maximum bytes per actual read/write syscall.
    pub io_slice_bytes: usize,
    /// Fixed initial attachment/initializer-write interval.
    pub initial_timeout: Duration,
    /// Fixed partial response interval.
    pub input_timeout: Duration,
    /// Fixed control/mutation write interval, never refreshed by progress.
    pub write_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            abi: Abi::native(),
            frame_bytes: 65535,
            queued_frames: 128,
            queued_bytes: 1 << 20,
            operations: 128,
            io_slice_bytes: 65535,
            initial_timeout: Duration::from_secs(30),
            input_timeout: Duration::from_secs(15),
            write_timeout: Duration::from_secs(30),
        }
    }
}
impl Limits {
    /// Validate the selected finite native profile before source creation or
    /// SERVICE readiness. This is the same admission used by Set and Listener.
    pub fn validate(self) -> Result<(), Error> {
        self.abi.validate()?;
        if !(112..=65535).contains(&self.frame_bytes)
            || self.queued_frames == 0
            || self.queued_frames > 65536
            || self.queued_bytes < self.frame_bytes
            || self.operations == 0
            || self.operations > 65536
            || self.io_slice_bytes == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        for d in [self.initial_timeout, self.input_timeout, self.write_timeout] {
            if d.is_zero() || std::time::Instant::now().checked_add(d).is_none() {
                return Err(Fault::InvalidInput.into());
            }
        }
        Ok(())
    }
}
/// Caller-owned exact application bytes from one original response.
pub struct ElementOwned {
    /// Application type, without reinterpretation.
    pub element_type: u16,
    /// Exact original element bytes.
    pub data: Vec<u8>,
}
impl ElementOwned {
    pub(crate) fn copy(value: Element<'_>) -> Result<Self, Error> {
        let mut data = Vec::new();
        data.try_reserve_exact(value.data.len())
            .map_err(|_| Fault::Capacity)?;
        data.extend_from_slice(value.data);
        Ok(Self {
            element_type: value.element_type,
            data,
        })
    }
}
/// Actual reason that original physical ownership ended.
#[derive(Debug)]
pub enum Cause {
    /// Actual original error.
    Failure(Error),
    /// Actual EOF, never an operation or iteration completion.
    Eof,
    /// Original native/canonical deadline reached.
    Deadline,
    /// Caller explicitly closed the owner.
    Requested,
    /// Original listener/copy source authority retired before dependent admission.
    OriginalSourceRetired,
}

/// Boundary that actually ended an original owner. Values classify provenance,
/// not the numeric error code or the success/failure of any peer operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LossOrigin {
    /// An actual immutable owner/operation native or canonical target expired.
    Bounds,
    /// This original MQ, remote frame, local owner or original source retired.
    Source,
    /// The shared logical Clock sample, subscription or notification refused.
    Clock,
    /// The original CLIENT configuration, Resolver or selection port refused.
    Selector,
}
impl Cause {
    /// Report the actual boundary, without treating a Clock's Deadline error as
    /// expiry of one operation or a Selector's I/O error as a native socket loss.
    #[must_use]
    pub const fn origin(&self) -> LossOrigin {
        match self {
            Self::Deadline => LossOrigin::Bounds,
            Self::Failure(error) => error.origin(),
            Self::Eof | Self::Requested | Self::OriginalSourceRetired => LossOrigin::Source,
        }
    }
}
impl From<Error> for Cause {
    fn from(error: Error) -> Self {
        error.into_cause_parts().0
    }
}
impl From<Fault> for Cause {
    fn from(error: Fault) -> Self {
        Self::Failure(error.into())
    }
}
