use crate::ipc;
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as Framing, OwnedFrame};
use gnunet_types::Error as Fault;
use std::{fmt, io, sync::Arc, time::Duration};
use zeroize::Zeroizing;

/// Actual original provider, protocol or syscall failure.
#[derive(Debug)]
pub enum Error {
    /// Original shared CLIENT/clock/configuration/Resolver failure.
    Native(gnunet_client_host::ConnectError),
    /// Actual bounded local protocol/resource/deadline classification.
    Protocol(Fault),
    /// Original native IO error, without formatting away its errno.
    Io(io::Error),
}
impl From<Fault> for Error {
    fn from(value: Fault) -> Self {
        Self::Protocol(value)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(value: gnunet_client_host::ConnectError) -> Self {
        Self::Native(value)
    }
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
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
/// Exactly one original ordinary operation; no wire RID is invented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Original780 generation request, expecting783.
    Generate,
    /// Original781 decryption request, expecting782.
    Decrypt,
}
/// Physical source authority. Only actual attachment creates this identity.
#[derive(Clone)]
pub struct Epoch(pub(crate) Arc<()>);
impl PartialEq for Epoch {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for Epoch {}
impl fmt::Debug for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Epoch").finish_non_exhaustive()
    }
}
/// Explicit frame/count resources and finite original native phase bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual complete request/reply extent,540 through65535 bytes.
    pub frame_bytes: usize,
    /// Maximum positive bytes offered to one original read/write syscall.
    pub io_slice_bytes: usize,
    /// Accepted request/share participant count; zero permits only empty columns.
    pub peers: usize,
    /// Original selection/connection/first whole request bound.
    pub initial_timeout: Duration,
    /// Original queued immutable request write bound.
    pub write_timeout: Duration,
    /// First partial incoming frame bound, never renewed by additional bytes.
    pub input_timeout: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            peers: 4096,
            initial_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            input_timeout: Duration::from_secs(15),
        }
    }
}
impl Limits {
    /// Validate the whole selected resource profile without any source or crypto.
    pub fn validate(self) -> Result<(), Error> {
        if !(276 + ipc::SHARE_PREFIX..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.peers > usize::from(u16::MAX)
        {
            return Err(Fault::InvalidInput.into());
        }
        for duration in [self.initial_timeout, self.write_timeout, self.input_timeout] {
            if duration.is_zero()
                || duration.as_micros() >= u128::from(u64::MAX)
                || std::time::Instant::now().checked_add(duration).is_none()
            {
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
pub(crate) fn freeze(input: &[u8], cap: usize) -> Result<OwnedFrame, Error> {
    if input.len() > cap {
        return Err(Fault::Capacity.into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(input.len())
        .map_err(|_| Fault::Capacity)?;
    if bytes.capacity() > cap {
        return Err(Fault::Capacity.into());
    }
    bytes.extend_from_slice(input);
    Ok(OwnedFrame::new(std::mem::take(&mut *bytes)))
}
/// Original serialized private share. No Debug or Clone exposes private bytes;
/// complete owned storage is erased when this value drops.
pub struct Share {
    pub(crate) storage: OwnedFrame,
    pub(crate) offset: usize,
}
impl Share {
    /// Freeze an independently supplied exactly shaped share. This authenticates
    /// no threshold/key/membership and preserves empty/nonmember representations.
    pub fn copy_from(bytes: &[u8], limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let value = ipc::Share::decode(bytes)?;
        if value.len() > limits.peers {
            return Err(Fault::Capacity.into());
        }
        Ok(Self {
            storage: freeze(bytes, limits.frame_bytes)?,
            offset: 0,
        })
    }
    /// Original canonical serialized representation, without a response header.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        // Offset is private:0 for a standalone validated share,4 only for an
        // exactly validated783 frame (minimum268 bytes). No mutation is exposed.
        &self.storage.bytes()[self.offset..]
    }
    /// Borrow original threshold/peer/native-index/secret columns; no math check.
    pub fn view(&self) -> Result<ipc::Share<'_>, Fault> {
        ipc::Share::decode(self.bytes())
    }
    /// Actual owned byte-vector capacity, including an original response header.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.storage.retained_bytes()
    }
}
/// Actual782 response in zeroizing original storage; raw status and plaintext
/// remain available without treating the word as mathematical verification.
pub struct Decryption {
    pub(crate) storage: OwnedFrame,
    pub(crate) success: u32,
}
impl Decryption {
    /// Original raw BE32 word, including zero and unknown nonzero values.
    #[must_use]
    pub const fn success(&self) -> u32 {
        self.success
    }
    /// Borrow exact original128-byte plaintext, including failed-response bytes.
    pub fn plaintext(&self) -> Result<&[u8; ipc::FIELD_BYTES], Fault> {
        self.storage
            .bytes()
            .get(8..136)
            .ok_or(Fault::Truncated)?
            .try_into()
            .map_err(|_| Fault::Malformed)
    }
    /// Complete original782 wire representation, not formatted secret text.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.storage.bytes()
    }
    /// Actual retained vector capacity, separate from wire/RSS accounting.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.storage.retained_bytes()
    }
}
/// Actual original transfer receipts. They prove local bytes, not peer/service
/// processing, consensus, threshold, decryption or durable completion.
#[derive(Clone, Debug)]
pub struct Receipt {
    /// Actual original MQ identity, if attachment occurred.
    pub epoch: Option<Epoch>,
    /// Original request kind.
    pub kind: Kind,
    /// Complete immutable original request extent.
    pub request_bytes: usize,
    /// Actual prefix written on that same MQ.
    pub written_bytes: usize,
    /// Exact whole request wrote locally.
    pub request_written: bool,
    /// Actual partial/complete incoming response bytes before this observation.
    pub response_bytes: usize,
}
/// Original local termination without fabricating a response or cancel ACK.
#[derive(Debug)]
pub enum Cause {
    /// Original actual provider/protocol/syscall failure.
    Failure(Error),
    /// Clean source EOF before an actual expected response.
    Eof,
    /// Original finite native/canonical target reached.
    Deadline,
    /// Explicit local physical cancellation; contribution may be irreversible.
    Cancelled,
}
/// The original MQ is physically closed before this local loss is exposed.
#[derive(Debug)]
pub struct Loss {
    /// Original positive-byte/whole-request/partial-response receipts.
    pub receipt: Receipt,
    /// Original cause and nested native error/errno.
    pub cause: Cause,
}
/// One original operation observation. No Debug/Clone because terminal events
/// own private shares/plaintexts. None of the write events grants remote credit.
pub enum Progress {
    /// Actual original endpoint attachment before any request byte is implied.
    Attached(Epoch),
    /// Actual pre-attachment connect failure under original CLIENT backoff.
    Retry(io::Error),
    /// Actual original request transfer, including its final whole-write event.
    Written {
        /// Actual original physical source.
        epoch: Epoch,
        /// Actual positive syscall bytes.
        bytes: usize,
        /// Whether this transfer completed the one original immutable request.
        complete: bool,
        /// Exact original receipts.
        receipt: Receipt,
    },
    /// Actual positive incoming bytes, not yet a typed terminal result.
    Activity {
        /// Actual original source.
        epoch: Epoch,
        /// Actual received syscall bytes.
        bytes: usize,
    },
    /// Actual expected783, physically closed before delivery. An empty/unusable
    /// share is still an actual result, not a fabricated successful DKG.
    Generated {
        /// Owned original private share; no Debug/Clone and erased on Drop.
        share: Share,
        /// Exact original physical/write/read facts.
        receipt: Receipt,
    },
    /// Actual expected782, physically closed before delivery. Preserve raw status
    /// and failed plaintext bytes rather than manufacturing a successful value.
    Decrypted {
        /// Owned raw result, not independently proven mathematical plaintext.
        result: Decryption,
        /// Exact original physical/write/read facts.
        receipt: Receipt,
    },
    /// Actual local error/cancel/timeout; never a protocol response substitute.
    Lost(Loss),
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failure(error) => error.fmt(f),
            Self::Eof => f.write_str("original SECRETSHARING MQ reached EOF before its response"),
            Self::Deadline => f.write_str("original SECRETSHARING operation deadline"),
            Self::Cancelled => f.write_str("original SECRETSHARING MQ cancelled locally"),
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failure(error) => Some(error),
            _ => None,
        }
    }
}
impl fmt::Display for Loss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; actual local receipts={:?}",
            self.cause, self.receipt
        )
    }
}
impl std::error::Error for Loss {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
