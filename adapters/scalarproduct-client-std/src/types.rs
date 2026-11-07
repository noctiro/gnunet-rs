//! Original computation role, bounded input and actual native receipts.
use gnunet_types::Error as Fault;
use gnunet_wire::official::scalarproduct::{ClientResponse, ResponseStatus};
use std::{fmt, io, sync::Arc, time::Duration};
/// Original local/native failure, without changing provider errors into strings.
#[derive(Debug)]
pub enum Error {
    /// Actual CLIENT clock/configuration/Resolver/native selection failure.
    Native(gnunet_client_host::ConnectError),
    /// Exact protocol/resource/deadline refusal.
    Protocol(Fault),
    /// Actual read/write syscall failure.
    Io(io::Error),
}
impl From<Fault> for Error {
    fn from(v: Fault) -> Self {
        Self::Protocol(v)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(v: gnunet_client_host::ConnectError) -> Self {
        Self::Native(v)
    }
}
impl From<io::Error> for Error {
    fn from(v: io::Error) -> Self {
        Self::Io(v)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(e) => fmt::Display::fmt(e, f),
            Self::Protocol(e) => fmt::Display::fmt(e, f),
            Self::Io(e) => fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Io(e) => Some(e),
        }
    }
}
/// One actual computation; ECC/Paillier selection remains service configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Requester computes with the actual target peer.
    Alice {
        /// Original public session key.
        session: [u8; 64],
        /// Actual target public peer identity.
        peer: [u8; 32],
    },
    /// Responder offers its vector for this public session.
    Bob {
        /// Original public session key.
        session: [u8; 64],
    },
}
impl Role {
    /// Actual standard service configuration section.
    #[must_use]
    pub const fn service(self) -> &'static [u8] {
        match self {
            Self::Alice { .. } => b"scalarproduct-alice",
            Self::Bob { .. } => b"scalarproduct-bob",
        }
    }
}
/// Distinct original physical source identity; numeric diagnostics are not tokens.
#[derive(Clone)]
pub struct Epoch(pub(crate) Arc<()>);
impl PartialEq for Epoch {
    fn eq(&self, r: &Self) -> bool {
        Arc::ptr_eq(&self.0, &r.0)
    }
}
impl Eq for Epoch {}
impl fmt::Debug for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Epoch").finish_non_exhaustive()
    }
}
/// Explicit input/storage and native phase resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete frame, at least one Alice element (184bytes).
    pub frame_bytes: usize,
    /// Maximum original vector elements.
    pub elements: usize,
    /// Actual retained vector plus uniqueness-index capacity budget.
    pub vector_bytes: usize,
    /// Maximum exact MPI response bytes retained.
    pub result_bytes: usize,
    /// Actual bytes offered in one read/write syscall.
    pub io_slice_bytes: usize,
    /// Fixed connection/first-request target.
    pub initial_timeout: Duration,
    /// Fixed target for each original multipart frame, never refreshed by progress.
    pub write_timeout: Duration,
    /// Fixed partial response target.
    pub input_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            elements: 65536,
            vector_bytes: 16 << 20,
            result_bytes: 65519,
            io_slice_bytes: 65535,
            initial_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            input_timeout: Duration::from_secs(15),
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Error> {
        if !(184..=65535).contains(&self.frame_bytes)
            || self.elements == 0
            || u32::try_from(self.elements).is_err()
            || self.vector_bytes == 0
            || self.result_bytes > 65519
            || self.io_slice_bytes == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        for d in [self.initial_timeout, self.write_timeout, self.input_timeout] {
            if d.is_zero() || std::time::Instant::now().checked_add(d).is_none() {
                return Err(Fault::InvalidInput.into());
            }
        }
        Ok(())
    }
}
/// Immutable original input/write facts; whole write is not service processing.
#[derive(Clone, Debug)]
pub struct Receipt {
    /// Original physical source, absent for an unattached attempt.
    pub epoch: Option<Epoch>,
    /// Original total input count.
    pub elements: u32,
    /// Actual whole-written vector entries.
    pub elements_written: u32,
    /// Actual whole-written input frames.
    pub frames_written: u64,
    /// Actual positive input request bytes.
    pub written_bytes: u64,
    /// Original current frame prefix actually written.
    pub partial_frame_bytes: usize,
    /// Whether every original input frame actually wrote wholly.
    pub all_input_written: bool,
    /// Actual current response prefix bytes, including a whole frame at Result.
    pub partial_response_bytes: usize,
}
/// Original physical retirement reason, not a computation result.
#[derive(Debug)]
pub enum Cause {
    /// Actual local/native failure.
    Failure(Error),
    /// Actual source EOF, without a successful result.
    Eof,
    /// Original finite native bound reached.
    Deadline,
    /// Caller explicitly canceled/closed this original source.
    Cancelled,
}
/// Actual source retired before any replacement; inputs/results are not replayed.
#[derive(Debug)]
pub struct Loss {
    /// Original input/source exposure.
    pub receipt: Receipt,
    /// Original cause.
    pub cause: Cause,
}
/// Exact service response, including original signed MPI STD bytes and range.
pub struct Response {
    /// Original raw status word; only SUCCESS2 means computation success.
    pub status: ResponseStatus,
    /// Independent signed word, not inferred from the MPI sign/length.
    pub range: i32,
    /// Exact original GCRYMPI_FMT_STD payload, unparsed by this SDK.
    pub product: Vec<u8>,
}
impl Response {
    /// Borrow the exact response fields without normalizing signed bytes.
    #[must_use]
    pub fn as_wire(&self) -> ClientResponse<'_> {
        ClientResponse {
            status: self.status,
            range: self.range,
            product: &self.product,
        }
    }
}
/// One actual source-driven observation; no local write event is a processing ACK.
pub enum Progress {
    /// A physical source attached; no input is necessarily written.
    Attached(Epoch),
    /// Actual socket attempt failed before attachment/input exposure.
    Retry(io::Error),
    /// Actual original frame prefix/whole write.
    Written {
        /// Original source.
        epoch: Epoch,
        /// Actual bytes in this syscall.
        bytes: usize,
        /// Actual whole original frame write.
        complete: bool,
        /// Current original receipts.
        receipt: Receipt,
    },
    /// Actual response; the physical source is closed before returning it.
    Result {
        /// Exact original service response fields.
        response: Response,
        /// Original input/source receipts.
        receipt: Receipt,
    },
    /// Bounded native input/cursor progress.
    Activity,
    /// Source retired without successful response/replay.
    Lost(Loss),
}

impl fmt::Display for Loss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SCALARPRODUCT original loss={:?}; receipt={:?}",
            self.cause, self.receipt
        )
    }
}
impl std::error::Error for Loss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Cause::Failure(error) = &self.cause {
            Some(error)
        } else {
            None
        }
    }
}
