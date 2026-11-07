//! Configured handler arguments and one byte-preserving original URI argument.
use gnunet_config::Configuration;
use std::{
    ffi::OsString,
    io,
    os::unix::ffi::OsStringExt,
    time::{Duration, Instant},
};
/// One parsed configured executable and the complete unchanged URI argument.
/// It grants no source authentication, process success or shell authority.
pub struct Settings {
    /// Parsed executable name/path from the trusted configuration.
    pub handler: OsString,
    /// Complete original argument, without NUL normalization.
    pub uri: OsString,
    /// Original physical child stop grace.
    pub grace: Duration,
    // Both frontdoors use trusted configured arguments; only stdio differs.
    pub(crate) arguments: Vec<OsString>,
    pub(crate) inherit_stdio: bool,
}
fn number(
    config: &Configuration,
    key: &[u8],
    default: usize,
    maximum: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let value = config
        .get(b"uri-rust", key)
        .map(|_| config.get_number(b"uri-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default);
    if value == 0 || value > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "URI resource profile outside supported bound",
        )
        .into());
    }
    Ok(value)
}
fn copy(input: &[u8]) -> io::Result<OsString> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(input.len())
        .map_err(io::Error::other)?;
    bytes.extend_from_slice(input);
    Ok(OsString::from_vec(bytes))
}
impl Settings {
    /// Select exactly one original URI through the ordinary argument slice.
    pub fn read(
        config: &Configuration,
        arguments: &[Vec<u8>],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if arguments.len() != 1 {
            return Err("exactly one gnunet:// URI is required".into());
        }
        Self::from_uri(config, &arguments[0])
    }
    /// Parse only the configured handler's official command argument syntax.
    /// Preserve one complete validated URI argument, without shell/URI parsing.
    /// No automatic `--` is inserted: configured `-u` must consume the URI.
    pub fn from_uri(
        config: &Configuration,
        uri: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let uri_bytes = number(config, b"MAX_URI_BYTES", 65536, 1024 * 1024)?;
        let handler_bytes = number(config, b"MAX_HANDLER_BYTES", 4096, 65536)?;
        if uri.len() > uri_bytes
            || uri.contains(&0)
            || !uri
                .get(..9)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"gnunet://"))
        {
            return Err("invalid or over-budget GNUnet URI".into());
        }
        let tail = &uri[9..];
        let slash = tail
            .iter()
            .position(|b| *b == b'/')
            .ok_or("GNUnet URI must specify a subsystem followed by '/' ")?;
        let subsystem = &tail[..slash];
        if subsystem.is_empty() || subsystem.len() > 256 {
            return Err("GNUnet URI subsystem is empty or too long".into());
        }
        // The Configuration API owns original case matching. No percent/Unicode
        // normalization or reconstruction changes the URI sent to the handler.
        let handler = config
            .get(b"uri", subsystem)
            .ok_or("no configured handler for GNUnet URI subsystem")?;
        if handler.is_empty() || handler.len() > handler_bytes || handler.contains(&0) {
            return Err(
                "configured URI executable is empty, contains NUL or exceeds its budget".into(),
            );
        }
        let micros = config
            .get(b"uri-rust", b"STOP_GRACE")
            .map(|_| config.get_time(b"uri-rust", b"STOP_GRACE"))
            .transpose()?
            .unwrap_or(5_000_000);
        if micros == 0 || micros > 3_600_000_000 {
            return Err("URI stop grace must be finite and at most one hour".into());
        }
        let grace = Duration::from_micros(micros);
        if Instant::now().checked_add(grace).is_none() {
            return Err("URI native stop target overflow".into());
        }
        let maximum = number(config, b"MAX_HANDLER_ARGS", 256, 4096)?;
        let mut arguments = gnunet_service_runtime::process::parse_command(handler, maximum)?;
        if arguments.is_empty() || arguments[0].is_empty() {
            return Err("configured command has no executable".into());
        }
        let handler = arguments.remove(0);
        Ok(Self {
            handler,
            uri: copy(uri)?,
            grace,
            arguments,
            inherit_stdio: false,
        })
    }
    /// Select the same handler/URI arguments with QR's inherited stdio policy.
    /// Neither original URI bytes nor handler identity is reconstructed.
    pub fn from_qr_uri(
        config: &Configuration,
        uri: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut selected = Self::from_uri(config, uri)?;
        selected.inherit_stdio = true;
        Ok(selected)
    }
}
