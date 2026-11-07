use gnunet_client_host::ConnectError;
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as FrameLimits, OwnedFrame};
use gnunet_types::Error as Fault;
use gnunet_wire::official::rps::ClientResponse;
use std::{
    fmt, io,
    sync::Arc,
    time::{Duration, Instant},
};

/// Original native, protocol or actual entropy-provider failure.
#[derive(Debug)]
pub enum Error {
    /// Original configuration, Resolver, canonical-clock or socket failure.
    Native(ConnectError),
    /// Exact bounded protocol/resource/deadline failure.
    Fault(Fault),
    /// Actual first entropy failure; no replacement entropy is supplied.
    Entropy(getrandom::Error),
}
impl From<Fault> for Error {
    fn from(value: Fault) -> Self {
        Self::Fault(value)
    }
}
impl From<ConnectError> for Error {
    fn from(value: ConnectError) -> Self {
        Self::Native(value)
    }
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Native(ConnectError::Io(value))
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(e) => fmt::Display::fmt(e, f),
            Self::Fault(e) => fmt::Display::fmt(e, f),
            Self::Entropy(e) => write!(f, "RPS entropy: {e}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(e) => Some(e),
            Self::Fault(e) => Some(e),
            // getrandom is deliberately built without a std feature. The actual
            // typed error remains available rather than replaced with text.
            Self::Entropy(_) => None,
        }
    }
}
/// One original physical source identity; numeric serial alone is diagnostic.
#[derive(Clone, Debug)]
pub struct Epoch(pub(crate) Arc<()>);
impl Epoch {
    /// Local diagnostic serial; equality also requires the original source domain.
    #[must_use]
    pub const fn value(&self) -> u64 {
        1
    }
}
impl PartialEq for Epoch {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for Epoch {}
/// One normal public operation. Sampling count is local demand, not a wire RPC.
#[derive(Clone, Copy, Debug)]
pub enum Query<'a> {
    /// Request independent sampler results from the actual biased stream.
    Sample {
        /// Bounded result count; zero completes locally without native IO/entropy.
        count: usize,
    },
    /// Observe the service view; finite count means a local frame quota.
    View {
        /// Zero is continuous; a positive count is the exact local frame quota.
        updates: u32,
    },
    /// Observe explicitly biased service stream batches without sampler claims.
    Stream,
    /// Send public seed identities; the wire provides no processing ACK.
    Seed {
        /// Original identities, encoded once before this borrowed query is released.
        peers: &'a [[u8; 32]],
    },
}
/// Explicit bounds on this one original owner, not implicit global reservations.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Whole standard frame including its header, from16 through65535 bytes.
    pub frame_bytes: usize,
    /// Maximum bytes offered to one actual nonblocking syscall.
    pub io_slice_bytes: usize,
    /// Maximum local result slots, at most the pure sampler hard bound65536.
    pub max_sample_peers: usize,
    /// Connect plus whole original request write; not a first-response timeout.
    pub initial_timeout: Duration,
    /// Original first-byte through classification deadline of one input frame.
    pub input_timeout: Duration,
    /// Explicit actual C target ABI for packed reply counts; never guessed.
    pub reply_profile: super::ReplyCountProfile,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            max_sample_peers: 1024,
            initial_timeout: Duration::from_secs(30),
            input_timeout: Duration::from_secs(10),
            reply_profile: super::ReplyCountProfile::native(),
        }
    }
}
impl Limits {
    pub(crate) fn framing(self, request: usize) -> Result<FrameLimits, Error> {
        if !(16..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.max_sample_peers > 65536
            || request > self.frame_bytes
        {
            return Err(Fault::InvalidInput.into());
        }
        for d in [self.initial_timeout, self.input_timeout] {
            if d.is_zero()
                || d.as_micros() >= u128::from(u64::MAX)
                || Instant::now().checked_add(d).is_none()
            {
                return Err(Fault::InvalidInput.into());
            }
        }
        let limits = FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: request.max(4),
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }
}
/// True local cancellation, actual EOF, or the original failure classification.
#[derive(Debug)]
pub enum Cause {
    /// Original local cancel; no remote processing ACK is implied.
    Cancelled,
    /// Actual physical source EOF, never a completion marker.
    Eof,
    /// Original source/protocol/resource/clock/deadline failure.
    Failure(Error),
}
/// Original source facts after its actual connection/attempt was closed.
#[derive(Debug)]
pub struct Loss {
    /// Original admitted physical source, absent before connection attachment.
    pub epoch: Option<Epoch>,
    /// Independent original terminal cause.
    pub cause: Cause,
    /// Positive actual bytes of the original request written locally.
    pub written: usize,
    /// Whether the complete original request wrote locally.
    pub request_written: bool,
    /// Positive actual same-source SubStart bytes written locally.
    pub group_bytes: usize,
    /// Whether that whole original SubStart wrote before the business query.
    pub group_written: bool,
    /// Complete original input batches admitted in this source epoch.
    pub records: u64,
    /// Actual sampler results exposed before termination; not a full result.
    pub samples: usize,
    /// Original current frame bytes retained before physical retirement.
    pub partial_input: usize,
    /// Whether a standard cancel frame was whole-written before physical close.
    pub cancellation_written: bool,
    /// Actual standard cancel bytes written, including a possible partial frame.
    pub cancellation_bytes: usize,
    /// Whole same-MQ SubStop wrote locally; no remote processing ACK exists.
    pub group_stop_written: bool,
    /// Actual same-MQ SubStop bytes written, including a possible partial frame.
    pub group_stop_bytes: usize,
    /// Actual first provider failure, independent of pure failure classification.
    pub entropy_error: Option<getrandom::Error>,
}
impl fmt::Display for Loss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RPS source {:?} retired after {} batches and {} samples: ",
            self.epoch.as_ref().map(Epoch::value),
            self.records,
            self.samples
        )?;
        match &self.cause {
            Cause::Cancelled => f.write_str("cancelled"),
            Cause::Eof => f.write_str("EOF"),
            Cause::Failure(e) => fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for Loss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Cause::Failure(e) => Some(e),
            _ => None,
        }
    }
}
/// One owned original view or explicitly biased stream frame.
pub struct Observation {
    pub(crate) epoch: Epoch,
    pub(crate) ordinal: u64,
    pub(crate) frame: OwnedFrame,
    pub(crate) profile: super::ReplyCountProfile,
}
impl Observation {
    /// Borrow the actual admitted physical source identity.
    #[must_use]
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Original one-based input frame ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
    /// Decode only these original owned bytes with the explicitly selected ABI.
    pub fn response(&self) -> Result<ClientResponse<'_>, Fault> {
        ClientResponse::decode(self.bytes(), self.profile)
    }
    /// Actual complete original frame, including standard header.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.frame.bytes()
    }
}
/// An observation made by this actual native owner; no fabricated peer receipts.
pub enum Progress {
    /// Actual original connection attached; request is not yet written.
    Attached(Epoch),
    /// Bounded cursor, input or sampler progress, without a completed operation.
    Activity,
    /// Original native connection attempt failed before query bytes were sent.
    Retry {
        /// Actual original syscall failure.
        error: io::Error,
    },
    /// Whole original SubStart wrote on this same source before the query.
    GroupWritten {
        /// Original actual source identity.
        epoch: Epoch,
        /// Actual original SubStart byte count, with no processing ACK.
        bytes: usize,
    },
    /// Whole original request wrote locally, without a remote processing ACK.
    Written {
        /// Original actual source identity.
        epoch: Epoch,
        /// Actual original request byte count.
        bytes: usize,
    },
    /// Actual view or explicitly biased raw stream batch.
    Record(Observation),
    /// One actual shared-core client sampler result.
    Sample {
        /// Original actual source identity.
        epoch: Epoch,
        /// One-based local result ordinal.
        ordinal: usize,
        /// Real sampler metadata; probability is not a confidence certificate.
        info: super::SampleInfo,
    },
    /// Local view quota or sampler demand satisfied; there is no wire END.
    Complete {
        /// Actual source, absent for count0 local completion.
        epoch: Option<Epoch>,
        /// Actual complete input batches admitted by this owner.
        records: u64,
    },
    /// Typed cancel whole-written or pre-write cancel, then actual source closed.
    Cancelled(Loss),
    /// Actual source physically retired with original cause and partial facts.
    Lost(Loss),
}
