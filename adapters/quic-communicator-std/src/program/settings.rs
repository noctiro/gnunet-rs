//! Official communicator configuration plus explicit finite Rust resource policy.
use super::Failure;
use crate::{Limits, tls::Profile};
use gnunet_config::{Configuration, ProcessEnvironment};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};
/// One configured TLS pair. No file is opened while parsing configuration.
pub(super) struct Pair {
    pub key: PathBuf,
    pub certificate: PathBuf,
}
pub(super) struct Settings {
    pub profile: Profile,
    pub bind: Bind,
    pub pair: Option<Pair>,
    pub limits: Limits,
    pub resolver: gnunet_resolver_broker::Limits,
    pub memory: usize,
    pub nat_addresses: usize,
}
pub(super) enum Bind {
    Explicit(SocketAddr),
    Wildcard { port: u16, ipv4: bool },
}
impl Bind {
    /// C tests IPv6 family availability for a port-only wildcard. This small
    /// caller-thread native probe is after USER; it never resolves a hostname or
    /// changes the configured port. Other bind failures retain their real cause.
    pub fn socket(&self) -> std::io::Result<SocketAddr> {
        match *self {
            Self::Explicit(socket) => Ok(socket),
            Self::Wildcard { port, ipv4: true } => {
                Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            }
            Self::Wildcard { port, ipv4: false } => {
                match std::net::UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) {
                    Ok(probe) => {
                        drop(probe);
                        Ok(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
                    }
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::EADDRNOTAVAIL)
                        ) =>
                    {
                        Ok(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }
}
pub(super) const fn section(profile: Profile) -> &'static [u8] {
    match profile {
        Profile::Raw => b"communicator-quic",
        Profile::Http3 => b"communicator-http3",
    }
}
pub(super) const fn binary(profile: Profile) -> &'static [u8] {
    match profile {
        Profile::Raw => b"gnunet-communicator-quic",
        Profile::Http3 => b"gnunet-communicator-http3",
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
impl Settings {
    pub fn read(c: &Configuration, profile: Profile) -> Result<Self, Failure> {
        let official = section(profile);
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
            if disable && socket.is_ipv6() {
                return Err("DISABLE_V6 conflicts with IPv6 BINDTO".into());
            }
            if matches!(socket,SocketAddr::V6(v) if v.flowinfo()!=0||v.scope_id()!=0) {
                return Err(
                    "BINDTO scope/flow metadata is unsupported by official advertisements".into(),
                );
            }
            Bind::Explicit(socket)
        };
        // Configuration has no reliable main/default provenance distinction. Any
        // configured pair, including the official installed template, is honored.
        let pair = match (c.get(official, b"KEY_FILE"), c.get(official, b"CERT_FILE")) {
            (None, None) => None,
            (Some(_), Some(_)) => {
                let key = c.get_filename(official, b"KEY_FILE", &ProcessEnvironment)?;
                let certificate = c.get_filename(official, b"CERT_FILE", &ProcessEnvironment)?;
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
        let memory = number(c, rust, b"FRAME_POOL_BYTES", 16 * 1024 * 1024)?;
        let nat_addresses = number(c, rust, b"NAT_ADDRESSES", 64)?;
        if memory == 0 || memory > 64 * 1024 * 1024 || nat_addresses == 0 || nat_addresses > 65535 {
            return Err("invalid frame/NAT resource bound".into());
        }
        Ok(Self {
            profile,
            bind,
            pair,
            limits: l,
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: l.io_slice,
                max_queued_frames: 8,
            },
            memory,
            nat_addresses,
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Real shared QUIC/HTTP3 settings must select the node identity profile without changing the TLS/application mode"
    )]
    fn shared_quic_http3_settings_keep_identity_profile_distinct_from_application_alpn()
    -> Result<(), Failure> {
        for application in [Profile::Raw, Profile::Http3] {
            let mut config = Configuration::default();
            config.set_value(section(application), b"BINDTO", Some(b"127.0.0.1:0"))?;
            assert_eq!(
                Settings::read(&config, application)?
                    .limits
                    .identity_profile,
                gnunet_pils::Profile::Reference029
            );
            config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
            let selected = Settings::read(&config, application)?;
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
            let failure = Settings::read(&config, application)
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
            let selected = Settings::read(&config, application)?;
            assert_eq!(selected.profile, application);
            assert_eq!(
                selected.limits.identity_profile,
                gnunet_pils::Profile::ReferenceDeterministic
            );
        }
        Ok(())
    }
}
