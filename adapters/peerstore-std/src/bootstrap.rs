//! Bounded included-HELLO URL import shared by native and embedded storage owners.
//!
//! Each accepted URL is signature/time checked under one explicit profile and
//! encoded as the official ordinary HELLO record. This grants no managed local
//! origin or address authentication beyond that profile's actual coverage.
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_hello::{AbsoluteTime, Hello, Limits, SignatureCoverage, SignatureProfile};
use gnunet_native::filesystem::{Directory as NativeDirectory, Entries, EntryInfo};
use gnunet_peerstore::Record;
use gnunet_types::Error;
use std::{
    ffi::OsStr,
    fmt,
    io::{self, Read},
    path::{Path, PathBuf},
};

/// Public ordinary HELLO namespace from the official PEERSTORE header.
pub const SUBSYSTEM: &[u8] = b"peerstore";
/// `GNUNET_PEERSTORE_HELLO_KEY`; values are binary HELLO_URI frames.
pub const KEY: &[u8] = b"peerstore-peer-hello-uri";
const MAX_BYTES: usize = 65535;

/// Explicit absolute startup directory and traversal budget; absence disables import.
/// The caller owns a stable, trusted asset directory for the entire import.
/// Native handles prevent final-link/FIFO substitution; they do not freeze file
/// contents or exclude administrative namespace changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directory {
    path: PathBuf,
    maximum_entries: usize,
}
impl Directory {
    /// Bound every directory entry, including skipped non-files. No directory
    /// traversal, file reads or environment discovery occur in this constructor.
    /// Relative resource paths are refused before any asynchronous startup work.
    pub fn new(path: PathBuf, maximum_entries: usize) -> Result<Self, Error> {
        if !path.is_absolute() || !(1..=65535).contains(&maximum_entries) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            path,
            maximum_entries,
        })
    }

    /// Shared startup policy. The official PEERSTORE switch enables import
    /// from the installation data directory's `hellos` child. Embedded hosts
    /// can set PATHS/GNUNET_DATADIR to their extracted resource directory.
    /// HELLO_DIRECTORY and MAX_INCLUDED_HELLOS are explicit Rust host policies.
    pub fn configured(config: &Configuration) -> Result<Option<Self>, gnunet_config::Error> {
        if !config
            .get(b"peerstore", b"USE_INCLUDED_HELLOS")
            .map(|_| config.get_yesno(b"peerstore", b"USE_INCLUDED_HELLOS"))
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let path = if config.get(b"peerstore-rust", b"HELLO_DIRECTORY").is_some() {
            config.get_filename(b"peerstore-rust", b"HELLO_DIRECTORY", &ProcessEnvironment)?
        } else {
            let key = if config.get(b"PATHS", b"GNUNET_DATADIR").is_some() {
                b"GNUNET_DATADIR".as_slice()
            } else {
                b"DATADIR".as_slice()
            };
            config
                .get_filename(b"PATHS", key, &ProcessEnvironment)?
                .join("hellos")
        };
        let path =
            std::path::absolute(&path).map_err(|error| gnunet_config::Error::Io { path, error })?;
        Self::with_configured_budget(path, config).map(Some)
    }

    /// Select an explicit package or installation data directory. Its `hellos`
    /// child is read with the same entry budget as the configuration path.
    /// The application keeps this data directory stable until import finishes.
    pub fn in_data_directory(
        data_directory: &Path,
        config: &Configuration,
    ) -> Result<Self, gnunet_config::Error> {
        Self::with_configured_budget(data_directory.join("hellos"), config)
    }

    fn with_configured_budget(
        path: PathBuf,
        config: &Configuration,
    ) -> Result<Self, gnunet_config::Error> {
        let maximum = config
            .get(b"peerstore-rust", b"MAX_INCLUDED_HELLOS")
            .map(|_| config.get_number(b"peerstore-rust", b"MAX_INCLUDED_HELLOS"))
            .transpose()?
            .unwrap_or(1024);
        let maximum = usize::try_from(maximum).map_err(|_| gnunet_config::Error::Overflow)?;
        Self::new(path, maximum).map_err(|_| gnunet_config::Error::InvalidValue)
    }

    /// Exact selected resource directory, before any startup I/O.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Total traversal budget, including entries that are not regular files.
    pub const fn maximum_entries(&self) -> usize {
        self.maximum_entries
    }
}

/// One rejected file; other bounded directory entries may still be consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipReason {
    /// File exceeded the complete 65535-byte input cap; no prefix was imported.
    Oversized,
    /// URL, signature, expiration or binary frame could not be accepted.
    Invalid(Error),
}

/// Original import failure. Already stored records remain committed; this is
/// not a whole-directory transaction and an error never implies rollback.
#[derive(Debug)]
pub enum Failure {
    /// Original native error from the selected directory or file.
    Io {
        /// Original selected directory or file path.
        path: PathBuf,
        /// Original operating-system failure.
        error: io::Error,
    },
    /// Traversal/allocation bound or actual storage refusal.
    Protocol(Error),
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, error } => write!(f, "included HELLO {}: {error}", path.display()),
            Self::Protocol(error) => write!(f, "included HELLO import: {error}"),
        }
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { error, .. } => Some(error),
            Self::Protocol(_) => None,
        }
    }
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Protocol(error)
    }
}

/// One immutable verified ordinary record, owned until its store completes.
pub struct Included {
    path: PathBuf,
    peer: [u8; 32],
    expiry: u64,
    value: Vec<u8>,
    coverage: SignatureCoverage,
}
impl Included {
    /// Original file path, for synchronous startup diagnostics only.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Official MULTIPLE store input; no managed local-origin tag is supplied.
    pub fn record(&self) -> Record<'_> {
        Record {
            peer: self.peer,
            expiry: self.expiry,
            subsystem: Some(SUBSYSTEM),
            key: Some(KEY),
            value: &self.value,
        }
    }
    /// Exact signature coverage; metadata-only profiles do not bind addresses.
    pub const fn coverage(&self) -> SignatureCoverage {
        self.coverage
    }
}

/// One file result. Storage owners decide when the original store has completed.
pub enum Event {
    /// Fully checked original URL encoded as an immutable ordinary record.
    Included(Included),
    /// Rejected file with its original path and exact parser/check result.
    Skipped {
        /// Original selected file path.
        path: PathBuf,
        /// Exact bounded codec, signature or time refusal.
        reason: SkipReason,
    },
}

/// Result of one included-record ingestion, separate from official IPC MULTIPLE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOutcome {
    /// A new ordinary public record was durably stored.
    Stored,
    /// An exact ordinary public record was already committed; no write occurred.
    AlreadyPresent,
}

/// Actual completed storage outcomes, never merely parsed-file counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    /// New original store operations completed successfully. Exact previously
    /// committed public records require no write and do not increment this count.
    pub stored: usize,
    /// Files rejected without storage admission.
    pub skipped: usize,
}

/// Caller-driven finite directory cursor. No worker or network work is created.
/// Missing directories and disabled imports are empty. Any native/budget error
/// ends this cursor; callers must not restart it as a transparent store retry.
pub struct Import {
    source: Option<NativeDirectory>,
    entries: Option<Entries>,
    path: PathBuf,
    remaining: usize,
    profile: SignatureProfile,
    now: AbsoluteTime,
    input: Vec<u8>,
    scratch: Vec<u8>,
}
impl Import {
    /// Open one selected directory under one explicit signature/time profile.
    /// Enumeration and child opens retain this original no-follow directory.
    pub fn open(
        directory: Option<&Directory>,
        profile: SignatureProfile,
        now: AbsoluteTime,
    ) -> Result<Self, Failure> {
        let (source, path, remaining) = match directory {
            None => (None, PathBuf::new(), 0),
            Some(directory) => {
                let source = match NativeDirectory::open_source(&directory.path) {
                    Ok(source) => Some(source),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => {
                        return Err(Failure::Io {
                            path: directory.path.clone(),
                            error,
                        });
                    }
                };
                (source, directory.path.clone(), directory.maximum_entries)
            }
        };
        let entries = source
            .as_ref()
            .map(NativeDirectory::entries)
            .transpose()
            .map_err(|error| Failure::Io {
                path: path.clone(),
                error,
            })?;
        let (input, scratch) = if entries.is_some() {
            (buffer(MAX_BYTES + 1)?, buffer(MAX_BYTES)?)
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(Self {
            source,
            entries,
            path,
            remaining,
            profile,
            now,
            input,
            scratch,
        })
    }

    fn read(&mut self, name: &OsStr, path: PathBuf) -> Result<Event, Failure> {
        let mut file = self
            .source
            .as_ref()
            .ok_or(Error::Closed)?
            .open_file(name)
            .map_err(|error| Failure::Io {
                path: path.clone(),
                error,
            })?;
        let mut length = 0;
        while length < self.input.len() {
            let count = file
                .read(&mut self.input[length..])
                .map_err(|error| Failure::Io {
                    path: path.clone(),
                    error,
                })?;
            if count == 0 {
                break;
            }
            length += count;
        }
        if length > MAX_BYTES {
            return Ok(Event::Skipped {
                path,
                reason: SkipReason::Oversized,
            });
        }
        let input = &self.input[..length];
        // Match the original public C string boundary, without treating a
        // truncated oversized file prefix as an independently accepted URL.
        let input = &input[..input
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(input.len())];
        let parsed = checked(input, &mut self.scratch, self.profile, self.now);
        let (hello, coverage, length) = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                return Ok(Event::Skipped {
                    path,
                    reason: SkipReason::Invalid(error),
                });
            }
        };
        // Allocate only the actual immutable output, after all input checks.
        // Allocation failure is terminal, not a malformed-file observation.
        let mut value = buffer(length)?;
        let encoded = hello
            .encode_message(&mut value)
            .and_then(|_| gnunet_hello::message_expiration(&value));
        let expiry = match encoded {
            Ok(expiry) => expiry.as_micros(),
            Err(error) => {
                return Ok(Event::Skipped {
                    path,
                    reason: SkipReason::Invalid(error),
                });
            }
        };
        Ok(Event::Included(Included {
            path,
            peer: *hello.peer().as_bytes(),
            expiry,
            value,
            coverage,
        }))
    }
}
impl Iterator for Import {
    type Item = Result<Event, Failure>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = self.entries.as_mut()?.next()?;
            let result = (|| {
                let name = entry.map_err(|error| Failure::Io {
                    path: self.path.clone(),
                    error,
                })?;
                if self.remaining == 0 {
                    return Err(Failure::Protocol(Error::Capacity));
                }
                self.remaining -= 1;
                let path = self.path.join(&name);
                let kind = self
                    .source
                    .as_ref()
                    .ok_or(Error::Closed)?
                    .entry_info(&name)
                    .map_err(|error| Failure::Io {
                        path: path.clone(),
                        error,
                    })?;
                if !matches!(kind, EntryInfo::File(_)) {
                    return Ok(None);
                }
                self.read(&name, path).map(Some)
            })();
            match result {
                Ok(None) => continue,
                Ok(Some(event)) => return Some(Ok(event)),
                Err(error) => {
                    self.entries = None;
                    return Some(Err(error));
                }
            }
        }
    }
}
fn checked<'a>(
    input: &[u8],
    scratch: &'a mut [u8],
    profile: SignatureProfile,
    now: AbsoluteTime,
) -> Result<(Hello<'a>, SignatureCoverage, usize), Error> {
    let hello = Hello::parse_url(
        input,
        scratch,
        Limits {
            maximum_input_bytes: MAX_BYTES,
            maximum_address_bytes: MAX_BYTES,
            maximum_addresses: MAX_BYTES,
        },
    )?;
    let coverage = hello.verify_at(profile, now)?.coverage();
    let length = hello.message_len()?;
    if length > MAX_BYTES {
        return Err(Error::TooLarge);
    }
    Ok((hello, coverage, length))
}
fn buffer(length: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::Capacity)?;
    bytes.resize(length, 0);
    Ok(bytes)
}
