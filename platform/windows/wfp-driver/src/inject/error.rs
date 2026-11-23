use super::PacketError;
use crate::sdk;
use core::fmt;

/// Refusal before WFP accepted a native injection or during pool preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// No second initialization or reopening of this original pool is allowed.
    AlreadyInitialized,
    /// Original native pool storage has not been initialized.
    Uninitialized,
    /// A zero outstanding limit was supplied.
    Capacity,
    /// The original pool has stopped accepting packets.
    Stopping,
    /// All bounded original packet slots are occupied.
    Full,
    /// Pool retirement requires stopping admission first.
    AdmissionOpen,
    /// Original packets or preparations still retain pool custody.
    Busy {
        /// Number of original packet/preparation owners still outstanding.
        outstanding: usize,
    },
    /// This original submission has already been attempted once.
    AlreadySubmitted,
    /// Reservation flow and packet path disagree.
    Path,
    /// Reply grammar or ordinary non-jumbo IP/UDP extent was invalid.
    Packet(PacketError),
    /// A native allocation returned no object.
    Allocation {
        /// Exact original allocator that returned null.
        operation: &'static str,
    },
    /// A native operation refused the packet; no completion was accepted.
    Native {
        /// Exact original native operation.
        operation: &'static str,
        /// Untranslated SDK status.
        status: sdk::NTSTATUS,
    },
    /// A successful native allocation omitted its required object.
    MissingOutput,
    /// The current IRQL exceeds the operation's documented contract.
    Irql {
        /// Original current IRQL.
        current: u8,
        /// Maximum permitted IRQL.
        maximum: u32,
    },
}

impl From<PacketError> for Error {
    fn from(error: PacketError) -> Self {
        Self::Packet(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => f.write_str("injection pool was already initialized"),
            Self::Uninitialized => f.write_str("injection pool is not initialized"),
            Self::Capacity => f.write_str("injection pool capacity is zero"),
            Self::Stopping => f.write_str("injection pool admission is stopped"),
            Self::Full => f.write_str("injection pool is full"),
            Self::AdmissionOpen => f.write_str("injection pool admission is still open"),
            Self::Busy { outstanding } => {
                write!(f, "injection pool retains {outstanding} original owners")
            }
            Self::AlreadySubmitted => f.write_str("original injection was already attempted"),
            Self::Path => f.write_str("original flow and injection path disagree"),
            Self::Packet(error) => error.fmt(f),
            Self::Allocation { operation } => write!(f, "{operation} returned no allocation"),
            Self::Native { operation, status } => {
                write!(f, "{operation} returned NTSTATUS {status:#010x}")
            }
            Self::MissingOutput => f.write_str("successful packet allocation omitted its object"),
            Self::Irql { current, maximum } => {
                write!(f, "injection IRQL {current} exceeds {maximum}")
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Packet(error) => Some(error),
            _ => None,
        }
    }
}

pub(super) fn at_most(maximum: u32) -> Result<(), Error> {
    // SAFETY: this real WDK wrapper reads the caller's current IRQL at any level.
    let current = unsafe { sdk::gnunet_wfp_current_irql() };
    if u32::from(current) > maximum {
        Err(Error::Irql { current, maximum })
    } else {
        Ok(())
    }
}
