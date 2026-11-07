//! Official SET service configuration and separate bounded Rust resource policy.
use crate::Cause;
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_set::{ContentLimits, Limits, wire};
use gnunet_set_host::server;
use std::time::Duration;

fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    Ok(c.get(b"set-rust", key)
        .map(|_| c.get_number(b"set-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn size(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Cause> {
    Ok(c.get(b"set-rust", key)
        .map(|_| c.get_size(b"set-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn time(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Cause> {
    let value = c
        .get(b"set-rust", key)
        .map(|_| c.get_time(b"set-rust", key))
        .transpose()?
        .unwrap_or(default);
    if value == 0
        || value == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(value))
            .is_none()
    {
        return Err("SET time bounds must be finite, nonzero and representable".into());
    }
    Ok(value)
}
pub(super) struct Settings {
    pub core: Limits,
    pub abi: wire::Abi,
    pub native: server::Limits,
    pub cadet: gnunet_cadet_host::Limits,
    pub resolver: gnunet_resolver_broker::Limits,
    pub access: UnixAccess,
    pub options: ServiceOptions,
    pub startup_timeout: Duration,
    pub shutdown_grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Cause> {
        let d = Limits::default();
        let core = Limits {
            clients: number(c, b"MAX_CLIENTS", d.clients)?,
            incoming: number(c, b"MAX_INCOMING", d.incoming)?,
            operations: number(c, b"MAX_OPERATIONS", d.operations)?,
            copies: number(c, b"MAX_COPY_COOKIES", d.copies)?,
            effects: number(c, b"MAX_EFFECTS", d.effects)?,
            effect_bytes: size(c, b"EFFECT_BYTES", d.effect_bytes)?,
            retained_bytes: size(c, b"CORE_RETAINED_BYTES", d.retained_bytes)?,
            content: ContentLimits {
                elements: number(c, b"MAX_SET_ELEMENTS", d.content.elements)?,
                body_bytes: size(c, b"SET_BODY_BYTES", d.content.body_bytes)?,
                element_bytes: size(c, b"MAX_ELEMENT_BYTES", d.content.element_bytes)?,
            },
            union_elements: number(c, b"MAX_UNION_ELEMENTS", d.union_elements)?,
            union_bytes: size(c, b"UNION_BODY_BYTES", d.union_bytes)?,
            context_bytes: size(c, b"MAX_CONTEXT_BYTES", d.context_bytes)?,
            operation_lifetime: time(c, b"OPERATION_LIFETIME", d.operation_lifetime)?,
            ibf_buckets: number(c, b"MAX_IBF_BUCKETS", d.ibf_buckets)?,
            bloom_bytes: size(c, b"BLOOM_BYTES", d.bloom_bytes)?,
            bloom_hashes: u32::try_from(number(c, b"BLOOM_HASHES", d.bloom_hashes as usize)?)?,
            rounds: u16::try_from(number(c, b"MAX_ROUNDS", usize::from(d.rounds))?)?,
            output_frames: number(c, b"MAX_ALGORITHM_OUTPUT_FRAMES", d.output_frames)?,
            output_bytes: size(c, b"ALGORITHM_OUTPUT_BYTES", d.output_bytes)?,
            received_records: number(c, b"MAX_RECEIVED_RECORDS", d.received_records)?,
        };
        core.validate()?;
        let native_abi = wire::Abi::native();
        let abi = wire::Abi {
            order: match c.get(b"set-rust", b"NATIVE_BYTE_ORDER") {
                None => native_abi.order,
                Some(b"little" | b"LITTLE") => wire::Order::Little,
                Some(b"big" | b"BIG") => wire::Order::Big,
                Some(_) => return Err("NATIVE_BYTE_ORDER must be little or big".into()),
            },
            align64: u8::try_from(number(
                c,
                b"NATIVE_ALIGN64",
                usize::from(native_abi.align64),
            )?)?,
        };
        abi.validate()?;
        let nd = server::Limits::default();
        let native = server::Limits {
            clients: core.clients,
            ports: number(c, b"MAX_CADET_PORTS", nd.ports)?,
            channels: number(c, b"MAX_CADET_CHANNELS", nd.channels)?,
            frame_bytes: size(c, b"FRAME_BYTES", nd.frame_bytes)?,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", nd.io_slice_bytes)?,
            output_frames: number(c, b"MAX_CLIENT_OUTPUT_FRAMES", nd.output_frames)?,
            output_bytes: size(c, b"CLIENT_OUTPUT_BYTES", nd.output_bytes)?,
            peer_frames: number(c, b"MAX_PEER_OUTPUT_FRAMES", nd.peer_frames)?,
            peer_bytes: size(c, b"PEER_OUTPUT_BYTES", nd.peer_bytes)?,
            first_input: Duration::from_micros(time(c, b"FIRST_INPUT", 30_000_000)?),
            partial_input: Duration::from_micros(time(c, b"PARTIAL_INPUT", 15_000_000)?),
            retirement_grace: Duration::from_micros(time(c, b"RETIREMENT_GRACE", 5_000_000)?),
        };
        native.validate()?;
        let maximum_peers = core
            .operations
            .checked_add(core.incoming)
            .ok_or(gnunet_types::Error::Overflow)?;
        if native.ports < core.clients || native.channels < maximum_peers {
            return Err("SET native ports/channels must cover admitted clients and original operations/offers".into());
        }
        let cd = gnunet_cadet_host::Limits::default();
        let cadet = gnunet_cadet_host::Limits {
            frame_bytes: size(c, b"CADET_FRAME_BYTES", cd.frame_bytes)?,
            io_slice_bytes: size(c, b"CADET_IO_SLICE_BYTES", cd.io_slice_bytes)?,
            max_payload_bytes: size(c, b"CADET_PAYLOAD_BYTES", cd.max_payload_bytes)?,
            max_send_credit: u32::try_from(number(
                c,
                b"CADET_SEND_CREDIT",
                cd.max_send_credit as usize,
            )?)?,
        };
        let rd = gnunet_resolver_broker::Limits::default();
        let resolver = gnunet_resolver_broker::Limits {
            max_frame_bytes: size(c, b"RESOLVER_FRAME_BYTES", rd.max_frame_bytes)?,
            io_chunk_bytes: size(c, b"RESOLVER_IO_SLICE_BYTES", rd.io_chunk_bytes)?,
            max_queued_frames: number(c, b"RESOLVER_OUTPUT_FRAMES", rd.max_queued_frames)?,
        };
        let yes = |key: &[u8]| {
            c.get(b"set", key)
                .map(|_| c.get_yesno(b"set", key))
                .transpose()
                .map(|v| v.unwrap_or(true))
        };
        Ok(Self {
            core,
            abi,
            native,
            cadet,
            resolver,
            access: UnixAccess {
                match_uid: yes(b"UNIX_MATCH_UID")?,
                match_gid: yes(b"UNIX_MATCH_GID")?,
            },
            options: service_options(c, b"set", ShutdownMode::Immediate)?,
            startup_timeout: Duration::from_micros(time(c, b"STARTUP_TIMEOUT", 30_000_000)?),
            shutdown_grace: Duration::from_micros(time(c, b"SHUTDOWN_GRACE", 10_000_000)?),
        })
    }
}
