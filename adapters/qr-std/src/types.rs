use gnunet_types::Error as Fault;
use std::{fmt, io};
/// Real provider/input/decode refusal; no successful decoded data is invented.
#[derive(Debug)]
pub enum Error {
    /// Original actual input IO error.
    Io(io::Error),
    /// Actual bounded shape/allocation/deadline refusal.
    Protocol(Fault),
    /// Actual native provider return value.
    Provider(ProviderFailure),
    /// Original loader diagnostic, bounded and escaped when displayed.
    Loader {
        /// Actual failing operation.
        operation: &'static str,
        /// Original diagnostic bytes rendered safely.
        detail: String,
        /// Original diagnostic exceeded the copied limit.
        truncated: bool,
    },
    /// Original camera preparation failure and independent native retirement.
    Acquisition {
        /// Original typed refusal, not formatted away.
        original: Box<Error>,
        /// Independent actual teardown failures.
        cleanup: Box<Cleanup>,
    },
    /// The actual decoder returned no symbol.
    NoSymbol,
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Provider(e) => e.fmt(f),
            Self::Loader {
                operation,
                detail,
                truncated,
            } => write!(f, "{operation}: {detail:?}; truncated={truncated}"),
            Self::Acquisition { original, cleanup } => {
                write!(f, "{original}; independent camera close={cleanup:?}")
            }
            Self::NoSymbol => f.write_str("actual image contains no decoded barcode/QR symbol"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Provider(e) => Some(e),
            Self::Acquisition { original, .. } => Some(original.as_ref()),
            _ => None,
        }
    }
}
/// Actual native return code and bounded public provider diagnostic.
#[derive(Clone, Debug)]
pub struct ProviderFailure {
    /// Selected standard provider.
    pub provider: &'static str,
    /// Original native operation.
    pub operation: &'static str,
    /// Actual unmodified return/error word.
    pub code: i32,
    /// Bounded library diagnostic; never decoded URI/pixel bytes.
    pub detail: Option<String>,
}
impl fmt::Display for ProviderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} returned {}: {:?}",
            self.provider, self.operation, self.code, self.detail
        )
    }
}
impl std::error::Error for ProviderFailure {}
/// Independent actual camera teardown failures. A destroy call has no status.
#[derive(Debug, Default)]
pub struct Cleanup {
    /// Actual deactivation failure, independent of original scan result.
    pub deactivate: Option<ProviderFailure>,
    /// Actual display-close failure, independent of deactivation.
    pub display: Option<ProviderFailure>,
}
impl Cleanup {
    /// Whether every fallible original teardown call succeeded.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.deactivate.is_none() && self.display.is_none()
    }
}
/// Original decoded data. No Debug/Display of a URI capability or private bytes.
pub struct Symbol {
    pub(crate) data: Vec<u8>,
    pub(crate) kind: i32,
}
impl Symbol {
    /// Borrow the actual native decoder payload without normalization.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
    /// Raw public ZBar symbology type, e.g. QR64, Code128128.
    #[must_use]
    pub const fn kind(&self) -> i32 {
        self.kind
    }
}
/// Explicit owned input/pixel/result limits. Provider internals are not process RSS.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum encoded PNG input bytes.
    pub encoded_bytes: usize,
    /// Maximum decoded width.
    pub width: u32,
    /// Maximum decoded height.
    pub height: u32,
    /// Maximum grayscale pixels; PNG GA staging retains at most twice this byte count.
    pub pixels: usize,
    /// Maximum actual decoded symbol bytes.
    pub symbol_bytes: usize,
    /// Requested finite native camera scan interval, milliseconds.
    pub camera_poll_ms: u32,
    /// Preferred camera width; actual callback dimensions are checked as well.
    pub camera_width: u32,
    /// Preferred camera height.
    pub camera_height: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            encoded_bytes: 16 << 20,
            width: 8192,
            height: 8192,
            pixels: 16 << 20,
            symbol_bytes: 65536,
            camera_poll_ms: 25,
            camera_width: 640,
            camera_height: 480,
        }
    }
}
impl Limits {
    /// Validate limits before loading a provider or opening input.
    pub fn validate(self) -> Result<(), Error> {
        if self.encoded_bytes == 0
            || self.encoded_bytes > 256 << 20
            || self.width == 0
            || self.height == 0
            || self.width > 32768
            || self.height > 32768
            || self.pixels == 0
            || self.pixels > 256 << 20
            || self.symbol_bytes == 0
            || self.symbol_bytes > 1 << 20
            || !(1..=100).contains(&self.camera_poll_ms)
            || self.camera_width == 0
            || self.camera_height == 0
            || self.camera_width > self.width
            || self.camera_height > self.height
        {
            return Err(Fault::InvalidInput.into());
        }
        Ok(())
    }
    pub(crate) fn image(self, width: u32, height: u32) -> Result<usize, Error> {
        let pixels = usize::try_from(width)
            .map_err(|_| Fault::Overflow)?
            .checked_mul(usize::try_from(height).map_err(|_| Fault::Overflow)?)
            .ok_or(Fault::Overflow)?;
        if width == 0
            || height == 0
            || width > self.width
            || height > self.height
            || pixels > self.pixels
        {
            return Err(Fault::TooLarge.into());
        }
        Ok(pixels)
    }
}
