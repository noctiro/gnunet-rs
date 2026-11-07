use gnunet_service_runtime::framing::{Accounting, Budget, Limits as Framing, OwnedFrame};
use gnunet_types::Error as Fault;
use std::{fmt, io, sync::Arc, time::Duration};

/// Original native/provider/protocol failure, retaining its actual error source.
#[derive(Debug)]
pub enum Error {
    /// Actual shared CLIENT/clock/configuration/Resolver port failure.
    Native(gnunet_client_host::ConnectError),
    /// Classified protocol, resource or deadline refusal.
    Protocol(Fault),
    /// Original socket syscall failure, without string conversion.
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
/// One actual original request kind, not an inferred response message number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Collect the subject's private namestore delegates.
    Collect,
    /// Verify the supplied leaf delegates for an exact subject and trust anchor.
    Verify,
}
/// Actual physical MQ identity. Numeric wire IDs are never source identity.
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

/// Explicit frame/observation and finite native phase resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Complete frame extent, through65535; both collect and verify fit the lower bound.
    pub frame_bytes: usize,
    /// Actual maximum offered syscall bytes, nonzero.
    pub io_slice_bytes: usize,
    /// Maximum intermediate observations before an actual terminal response.
    pub intermediates: u64,
    /// Maximum declared chain entries plus delegates in one actual response.
    pub records: usize,
    /// Unattached connection through first whole request, fixed once.
    pub initial_timeout: Duration,
    /// Original request write target, fixed when its immutable frame is queued.
    pub write_timeout: Duration,
    /// Fixed partial incoming frame target, without renewal by later bytes.
    pub input_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            intermediates: 4096,
            records: 2048,
            initial_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            input_timeout: Duration::from_secs(15),
        }
    }
}
impl Limits {
    /// Check the whole local resource profile before source/native admission.
    pub fn validate(self) -> Result<(), Error> {
        if !(89..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.records == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        for d in [self.initial_timeout, self.write_timeout, self.input_timeout] {
            if d.is_zero() || std::time::Instant::now().checked_add(d).is_none() {
                return Err(Fault::InvalidInput.into());
            }
        }
        self.framing().validate()?;
        Ok(())
    }
    pub(crate) fn framing(self) -> Framing {
        Framing {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
}
/// Actual original request/response exposure, not service processing evidence.
#[derive(Clone, Debug)]
pub struct Receipt {
    /// Actual original physical MQ if attachment occurred.
    pub epoch: Option<Epoch>,
    /// Original request kind.
    pub kind: Kind,
    /// Exact original wire request ID.
    pub request_id: u32,
    /// Original complete immutable request size.
    pub request_bytes: usize,
    /// Actual positive request prefix written on this original MQ.
    pub written_bytes: usize,
    /// Whether the whole original request actually wrote locally.
    pub request_written: bool,
    /// Actual nonterminal intermediate observations delivered.
    pub intermediates: u64,
    /// Actual bytes of the current partial/complete incoming frame.
    pub response_bytes: usize,
}
/// Actual local termination cause, distinct from an ABD terminal claim.
#[derive(Debug)]
pub enum Cause {
    /// Original provider/protocol/syscall failure.
    Failure(Error),
    /// Actual clean EOF before the original terminal response.
    Eof,
    /// Original native/canonical deadline reached.
    Deadline,
    /// Explicit local cancellation/physical close; no cancel message or ACK exists.
    Cancelled,
}
/// Original physical source retired before loss is exposed to the caller.
#[derive(Debug)]
pub struct Loss {
    /// Original write/response facts, including partial exposure.
    pub receipt: Receipt,
    /// Actual original cause, retaining provider/error source.
    pub cause: Cause,
}
/// One exact actual response in zeroizing immutable storage. No signature,
/// authorization or GNS proof is inferred from its raw found/status words.
pub struct Observation {
    pub(crate) frame: OwnedFrame,
}
impl Observation {
    /// Borrow the exact original validated frame.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.frame.bytes()
    }
    /// Borrow original typed fields without allocation or signature verification.
    pub fn view(&self) -> Result<gnunet_wire::official::abd::Response<'_>, Fault> {
        gnunet_wire::official::abd::Response::decode(self.frame.bytes())
    }
}
/// One finite original-MQ event; none of the local write events grants authority.
pub enum Progress {
    /// Actual endpoint attachment, before any request bytes are implied.
    Attached(Epoch),
    /// Actual pre-attachment native attempt failure with original backoff preserved.
    Retry(io::Error),
    /// Actual positive request transfer, including original partial/whole facts.
    Written {
        /// Original physical MQ.
        epoch: Epoch,
        /// Positive syscall bytes.
        bytes: usize,
        /// Original request wholly wrote locally.
        complete: bool,
        /// Exact original receipts.
        receipt: Receipt,
    },
    /// Actual incoming positive bytes, not a completed response.
    Activity {
        /// Original physical MQ.
        epoch: Epoch,
        /// Actual positive incoming syscall bytes.
        bytes: usize,
    },
    /// Actual995 exploration edge. It is nonterminal and grants no authorization.
    Intermediate {
        /// Original unchanged message.
        observation: Observation,
        /// Actual original receipts after this observation.
        receipt: Receipt,
    },
    /// Actual992/994 terminal service claim. Its original physical MQ was closed
    /// before this event. Only a real verified service proof may justify found1.
    Result {
        /// Exact original message, preserving raw found and every record.
        observation: Observation,
        /// Exact original source/write/input facts.
        receipt: Receipt,
    },
    /// Actual loss/cancel/timeout, without an invented negative/positive result.
    Lost(Loss),
}
