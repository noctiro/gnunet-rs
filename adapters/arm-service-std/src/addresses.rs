//! Official ARM managed-service endpoint collection, before actual binding.
//! Native BINDTO resolution may consult NSS; callers running tests must select
//! numeric inputs or an explicitly contained and verified hosts-only profile.
use gnunet_config::{Configuration, Environment};
use gnunet_native::addresses::{Hints, resolve};
use socket2::{Domain, Socket, Type};
use std::{
    ffi::OsStr,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

/// Exact requested endpoint. PORT0 disables TCP collection in configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Address {
    /// Filesystem socket; guards may own this newly created pathname only.
    Unix(PathBuf),
    /// Linux abstract sun_path bytes, including its leading and trailing zeros.
    /// The pinned C profile passes the full sockaddr_un, so padding is part of
    /// the Linux abstract socket name; it is not shortened to strlen(name).
    Abstract(Vec<u8>),
    /// TCP endpoint with configured nonzero port and native IPv6 flow/scope.
    Tcp(SocketAddr),
}
/// Source diagnostic which does not itself fail endpoint collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Diagnostic {
    /// Invalid PORT behaves as initialized zero; a value above65535 is fatal.
    InvalidPort,
    /// Non-resource socket probe failure disables this family.
    FamilyUnavailable {
        /// Native family whose probe failed.
        family: i32,
        /// Actual OS error class.
        kind: io::ErrorKind,
    },
}
/// Collection failure: never a successful partial endpoint vector.
#[derive(Debug)]
pub enum Error {
    /// Explicit DISABLEV6 value was malformed.
    Configuration(gnunet_config::Error),
    /// Socket probe or native pathname shaping failure.
    Io(io::Error),
    /// Native getaddrinfo failed with the exact input hints.
    Resolution(gnunet_native::addresses::Error),
    /// PORT exceeds the official 16bit limit.
    Port,
    /// Neither a nonzero PORT nor a supported UNIXPATH was selected.
    NoAddress,
    /// Caller maximum was exceeded; no truncated endpoint success is returned.
    Capacity,
}
/// Collected source-order addresses and nonfatal diagnostics.
#[derive(Debug)]
pub struct Addresses {
    /// Unix first, then native BINDTO result order, or wildcard IPv6 then IPv4.
    pub addresses: Vec<Address>,
    /// Actual source-style diagnostic paths encountered during collection.
    pub diagnostics: Vec<Diagnostic>,
}
fn probe(domain: Domain, diagnostics: &mut Vec<Diagnostic>) -> Result<bool, Error> {
    match Socket::new(domain, Type::STREAM, None) {
        Ok(socket) => {
            drop(socket);
            Ok(true)
        }
        Err(error) => {
            if [libc::ENOBUFS, libc::ENOMEM, libc::ENFILE, libc::EACCES]
                .contains(&error.raw_os_error().unwrap_or(0))
            {
                return Err(Error::Io(error));
            }
            diagnostics.push(Diagnostic::FamilyUnavailable {
                family: i32::from(domain),
                kind: error.kind(),
            });
            Ok(false)
        }
    }
}
impl Addresses {
    /// Collect one service's actual source-shaped endpoints. This performs real
    /// native family probes and native BINDTO resolution, but never bind/listen.
    /// Missing DISABLEV6 is false. Invalid explicit DISABLEV6 rejects collection.
    /// Invalid PORT logs a diagnostic and remains zero; PORT>65535 rejects it.
    /// Filename-getter failure drops UNIXPATH as in the official caller.
    pub fn from_config(
        config: &Configuration,
        section: &[u8],
        environment: &impl Environment,
        maximum: usize,
    ) -> Result<Self, Error> {
        let mut diagnostics = Vec::new();
        let mut disable_v6 = match config.get_yesno(section, b"DISABLEV6") {
            Ok(value) => value,
            Err(gnunet_config::Error::Missing) => false,
            Err(error) => return Err(Error::Configuration(error)),
        };
        if !disable_v6 && !probe(Domain::IPV6, &mut diagnostics)? {
            disable_v6 = true;
        }
        let port = match config.get_number(section, b"PORT") {
            Ok(value) => u16::try_from(value).map_err(|_| Error::Port)?,
            Err(gnunet_config::Error::Missing) => 0,
            Err(_) => {
                diagnostics.push(Diagnostic::InvalidPort);
                0
            }
        };
        let unix = match config.get_filename(section, b"UNIXPATH", environment) {
            Ok(path) if probe(Domain::UNIX, &mut diagnostics)? => {
                let path =
                    gnunet_service_runtime::network::shorten_unixpath(&path).map_err(Error::Io)?;
                #[cfg(target_os = "linux")]
                let abstract_socket = config
                    .get_yesno(b"TESTING", b"USE_ABSTRACT_SOCKETS")
                    .unwrap_or(false);
                #[cfg(not(target_os = "linux"))]
                let abstract_socket = false;
                if abstract_socket {
                    // sockaddr_un.sun_path is108 bytes on the source Linux ABI.
                    // A leading pathname byte is replaced, not prepended. Passing
                    // all108 bytes keeps the official zero-padding in the name.
                    let mut bytes = path.as_os_str().as_bytes().to_vec();
                    bytes.resize(108, 0);
                    bytes[0] = 0;
                    Some(Address::Abstract(bytes))
                } else {
                    Some(Address::Unix(path))
                }
            }
            Ok(_) | Err(_) => None,
        };
        if port == 0 && unix.is_none() {
            return Err(Error::NoAddress);
        }
        let mut addresses = Vec::new();
        if let Some(unix) = unix {
            addresses.push(unix);
        }
        if port != 0 {
            if let Some(hostname) = config.get(section, b"BINDTO") {
                let results = resolve(OsStr::from_bytes(hostname), Hints::arm(disable_v6), maximum)
                    .map_err(Error::Resolution)?;
                for item in results {
                    if (disable_v6 && item.family == libc::AF_INET6)
                        || (item.protocol != 0 && item.protocol != libc::IPPROTO_TCP)
                        || (item.socket_type != 0 && item.socket_type != libc::SOCK_STREAM)
                    {
                        continue;
                    }
                    let mut address = item.address;
                    address.set_port(port);
                    addresses.push(Address::Tcp(address));
                }
            } else {
                if !disable_v6 {
                    addresses.push(Address::Tcp((Ipv6Addr::UNSPECIFIED, port).into()));
                }
                addresses.push(Address::Tcp((Ipv4Addr::UNSPECIFIED, port).into()));
            }
        }
        if addresses.is_empty() {
            return Err(Error::NoAddress);
        }
        if addresses.len() > maximum {
            return Err(Error::Capacity);
        }
        Ok(Self {
            addresses,
            diagnostics,
        })
    }
}
