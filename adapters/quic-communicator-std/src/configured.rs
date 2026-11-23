//! Official communicator configuration plus explicit finite Rust resource policy.
use crate::{Limits, tls::Profile};
use gnunet_config::{Configuration, Environment, ProcessEnvironment};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};
pub(crate) mod credentials;
type Failure = Box<dyn Error>;

/// One configured TLS pair. No file is opened while parsing configuration.
struct Pair {
    key: PathBuf,
    certificate: PathBuf,
}
/// Prepared communicator configuration, without native sockets or TLS I/O.
pub struct Configured {
    /// Original raw QUIC or HTTP/3 wire profile.
    pub profile: Profile,
    pub(crate) bind: Bind,
    pair: Option<Pair>,
    /// Bounds for this single runtime.
    pub limits: Limits,
    /// Total bytes reserved for receive slabs and their loan metadata.
    pub frame_pool_bytes: usize,
    /// Maximum original NAT address advertisements.
    pub nat_addresses: usize,
}
pub(crate) enum Bind {
    Explicit(SocketAddr),
    Wildcard { port: u16, ipv4: bool },
}
impl Bind {
    /// C tests IPv6 family availability for a port-only wildcard. This small
    /// caller-thread native probe is after USER; it never resolves a hostname or
    /// changes the configured port. The family probe creates no binding; the
    /// endpoint's actual bind retains its original caller socket policy.
    pub(crate) fn socket(&self) -> std::io::Result<SocketAddr> {
        match *self {
            Self::Explicit(socket) => Ok(socket),
            Self::Wildcard { port, ipv4: true } => {
                Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            }
            Self::Wildcard { port, ipv4: false } => {
                match socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                ) {
                    Ok(probe) => {
                        drop(probe);
                        Ok(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
                    }
                    Err(error)
                        if gnunet_native::network::socket_family_unavailable(&error)
                            || error.kind() == std::io::ErrorKind::AddrNotAvailable =>
                    {
                        Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }
}
fn rust_section(profile: Profile) -> &'static [u8] {
    match profile {
        Profile::Raw => b"communicator-quic-rust",
        Profile::Http3 => b"communicator-http3-rust",
    }
}
fn number(c: &Configuration, s: &[u8], k: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(s, k)
        .map(|_| c.get_number(s, k))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn time(c: &Configuration, s: &[u8], k: &[u8], default: Duration) -> Result<Duration, Failure> {
    let value = c
        .get(s, k)
        .map(|_| c.get_time(s, k))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    if value == 0 || value == u64::MAX {
        return Err("communicator deadlines must be finite and positive".into());
    }
    Ok(Duration::from_micros(value))
}
impl Configured {
    /// Read the standard communicator settings using the process filename context.
    pub fn read(c: &Configuration, profile: Profile) -> Result<Self, Failure> {
        Self::read_with_environment(c, profile, &ProcessEnvironment)
    }

    /// Read the standard settings and resolve configured filenames through the
    /// caller's explicit context. No key, certificate or listener is opened here.
    pub fn read_with_environment(
        c: &Configuration,
        profile: Profile,
        environment: &impl Environment,
    ) -> Result<Self, Failure> {
        let official = profile.section();
        let rust = rust_section(profile);
        let disable = c
            .get(official, b"DISABLE_V6")
            .map(|_| c.get_yesno(official, b"DISABLE_V6"))
            .transpose()?
            .unwrap_or(false);
        let bytes = c
            .get(official, b"BINDTO")
            .ok_or("missing communicator BINDTO")?;
        if bytes.is_empty() || bytes.len() > 64 || bytes.contains(&0) {
            return Err("invalid communicator BINDTO".into());
        }
        let text = std::str::from_utf8(bytes)?;
        let bind = if bytes.iter().all(u8::is_ascii_digit) {
            Bind::Wildcard {
                port: text.parse()?,
                ipv4: disable,
            }
        } else {
            let socket = match text.parse::<SocketAddr>() {
                Ok(socket) => socket,
                Err(_) => {
                    let plain = text
                        .strip_prefix('[')
                        .and_then(|v| v.strip_suffix(']'))
                        .unwrap_or(text);
                    SocketAddr::new(plain.parse::<IpAddr>()?, 0)
                }
            };
            crate::endpoint::validate_address(socket)?;
            Bind::Explicit(socket)
        };
        // Configuration has no reliable main/default provenance distinction. Any
        // configured pair, including the official installed template, is honored.
        let pair = match (c.get(official, b"KEY_FILE"), c.get(official, b"CERT_FILE")) {
            (None, None) => None,
            (Some(_), Some(_)) => {
                let key = c.get_filename(official, b"KEY_FILE", environment)?;
                let certificate = c.get_filename(official, b"CERT_FILE", environment)?;
                if key == certificate {
                    return Err("KEY_FILE and CERT_FILE must differ".into());
                }
                Some(Pair { key, certificate })
            }
            _ => return Err("KEY_FILE and CERT_FILE must be configured together".into()),
        };
        let mut l = Limits::default();
        l.backend.connections = number(c, rust, b"CONNECTIONS", l.backend.connections)?;
        l.backend.bidi = u32::try_from(number(c, rust, b"BIDI_STREAMS", l.backend.bidi as usize)?)?;
        l.backend.receive_bytes = u32::try_from(number(
            c,
            rust,
            b"CONNECTION_RECEIVE_BYTES",
            l.backend.receive_bytes as usize,
        )?)?;
        l.backend.stream_bytes = u32::try_from(number(
            c,
            rust,
            b"STREAM_RECEIVE_BYTES",
            l.backend.stream_bytes as usize,
        )?)?;
        l.backend.send_bytes = u64::try_from(number(
            c,
            rust,
            b"SEND_BYTES",
            l.backend.send_bytes as usize,
        )?)?;
        l.backend.initial_bytes = u64::try_from(number(
            c,
            rust,
            b"INITIAL_SEND_BYTES",
            l.backend.initial_bytes as usize,
        )?)?;
        l.backend.idle = time(c, rust, b"QUIC_IDLE_TIMEOUT", l.backend.idle)?;
        l.raw_body = number(c, rust, b"RAW_RECEIVE_BYTES", l.raw_body)?;
        l.h3_body = number(c, rust, b"H3_RECEIVE_BYTES", l.h3_body)?;
        l.h3_headers = number(c, rust, b"H3_HEADER_BYTES", l.h3_headers)?;
        l.h3_polls = number(c, rust, b"H3_POLLS", l.h3_polls)?;
        l.h3_requests = u64::try_from(number(
            c,
            rust,
            b"H3_REQUESTS",
            usize::try_from(l.h3_requests)?,
        )?)?;
        l.h3_request_timeout = time(c, rust, b"H3_REQUEST_TIMEOUT", l.h3_request_timeout)?;
        l.output_frames = number(c, rust, b"OUTPUT_FRAMES", l.output_frames)?;
        l.output_bytes = number(c, rust, b"OUTPUT_BYTES", l.output_bytes)?;
        l.io_slice = number(c, rust, b"IO_SLICE_BYTES", l.io_slice)?;
        l.startup = time(c, rust, b"STARTUP_TIMEOUT", l.startup)?;
        l.operation = time(c, rust, b"OPERATION_LIFETIME", l.operation)?;
        l.idle = time(c, rust, b"CONNECTION_IDLE_TIMEOUT", l.idle)?;
        l.lifetime = time(c, rust, b"SOURCE_LIFETIME", l.lifetime)?;
        l.close_grace = time(c, rust, b"CLOSE_GRACE", l.close_grace)?;
        // The application/TLS Profile (Raw versus Http3) is separate from
        // the selected PILS identity and public HELLO signature interpretation.
        l.identity_profile = gnunet_pils::Profile::configured(
            c.get(b"PILS", b"PROFILE"),
            c.get(rust, b"PILS_PROFILE"),
        )?;
        l.validate()?;
        if l.backend.bidi < 2
            || l.backend.receive_bytes < l.backend.stream_bytes
            || l.backend.stream_bytes == 0
            || l.backend.send_bytes == 0
            || l.backend.initial_bytes == 0
            || l.backend.idle.is_zero()
        {
            return Err("invalid QUIC backend windows".into());
        }
        if profile == Profile::Http3 && l.backend.bidi < u32::try_from(l.h3_polls + 2)? {
            return Err("HTTP3 BIDI_STREAMS must cover H3_POLLS+2".into());
        }
        let frame_pool_bytes = number(c, rust, b"FRAME_POOL_BYTES", 16 * 1024 * 1024)?;
        let nat_addresses = number(c, rust, b"NAT_ADDRESSES", 64)?;
        if frame_pool_bytes == 0
            || frame_pool_bytes > 64 * 1024 * 1024
            || nat_addresses == 0
            || nat_addresses > 65535
        {
            return Err("invalid frame/NAT resource bound".into());
        }
        Ok(Self {
            profile,
            bind,
            pair,
            limits: l,
            frame_pool_bytes,
            nat_addresses,
        })
    }

    pub(crate) fn prepare_tls(
        &self,
    ) -> Result<
        (
            crate::credentials::Tls,
            [Option<gnunet_native::DirectorySync>; 2],
        ),
        Failure,
    > {
        let prepared = credentials::prepare(self.profile, self.pair.as_ref())?;
        Ok((prepared.tls, prepared.directory_sync))
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    fn disable_v6_selects_wildcard_family_and_preserves_explicit_bind() -> Result<(), Failure> {
        for profile in [Profile::Raw, Profile::Http3] {
            let mut config = Configuration::default();
            config.set_value(profile.section(), b"DISABLE_V6", Some(b"YES"))?;
            config.set_value(profile.section(), b"BINDTO", Some(b"0"))?;
            if !Configured::read(&config, profile)?.bind.socket()?.is_ipv4() {
                return Err("DISABLE_V6 chose an IPv6 wildcard".into());
            }
            config.set_value(profile.section(), b"BINDTO", Some(b"[::1]:0"))?;
            if !Configured::read(&config, profile)?.bind.socket()?.is_ipv6() {
                return Err("wildcard setting altered an explicit address".into());
            }
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Real shared QUIC/HTTP3 settings must select the node identity profile without changing the TLS/application mode"
    )]
    fn shared_quic_http3_settings_keep_identity_profile_distinct_from_application_alpn()
    -> Result<(), Failure> {
        for application in [Profile::Raw, Profile::Http3] {
            let mut config = Configuration::default();
            config.set_value(application.section(), b"BINDTO", Some(b"127.0.0.1:0"))?;
            assert_eq!(
                Configured::read(&config, application)?
                    .limits
                    .identity_profile,
                gnunet_pils::Profile::Reference029
            );
            config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
            let selected = Configured::read(&config, application)?;
            assert_eq!(selected.profile, application);
            assert_eq!(
                selected.limits.identity_profile,
                gnunet_pils::Profile::ReferenceDeterministic
            );
            config.set_value(
                rust_section(application),
                b"PILS_PROFILE",
                Some(b"reference-0.29.1"),
            )?;
            let failure = Configured::read(&config, application)
                .err()
                .ok_or("incoherent QUIC identity profile admitted")?;
            assert_eq!(
                failure.downcast_ref::<gnunet_types::Error>(),
                Some(&gnunet_types::Error::Conflict)
            );
            config.set_value(
                rust_section(application),
                b"PILS_PROFILE",
                Some(b"deterministic"),
            )?;
            let selected = Configured::read(&config, application)?;
            assert_eq!(selected.profile, application);
            assert_eq!(
                selected.limits.identity_profile,
                gnunet_pils::Profile::ReferenceDeterministic
            );
        }
        Ok(())
    }
}
