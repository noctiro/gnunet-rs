//! Official configuration and explicit bounded SETU process resources.
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_setu::{service, set, union, wire};
use std::{error::Error, time::Duration};
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Box<dyn Error>> {
    Ok(c.get(b"setu-rust", key)
        .map(|_| c.get_number(b"setu-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn size(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Box<dyn Error>> {
    Ok(c.get(b"setu-rust", key)
        .map(|_| c.get_size(b"setu-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
pub(super) fn micros(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Box<dyn Error>> {
    let value = c
        .get(b"setu-rust", key)
        .map(|_| c.get_time(b"setu-rust", key))
        .transpose()?
        .unwrap_or(default);
    if value == 0
        || value == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(value))
            .is_none()
    {
        return Err("SETU time bound must be finite, nonzero and representable".into());
    }
    Ok(value)
}
pub(super) struct Settings {
    pub core: service::Limits,
    pub abi: wire::Abi,
    pub access: UnixAccess,
    pub options: ServiceOptions,
    pub shutdown_grace: Duration,
    pub resolver: gnunet_resolver_broker::Limits,
    pub native: gnunet_setu_host::server::Limits,
    pub cadet: gnunet_cadet_host::Limits,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Box<dyn Error>> {
        let d = service::Limits::default();
        let set = set::Limits {
            elements: number(c, b"MAX_SET_ELEMENTS", d.set.elements)?,
            bytes: size(c, b"MAX_SET_BYTES", d.set.bytes)?,
        };
        let union = union::Limits {
            elements: number(c, b"MAX_UNION_ELEMENTS", d.union.elements)?,
            received_bytes: size(c, b"MAX_RECEIVED_BYTES", d.union.received_bytes)?,
            ibf_buckets: number(c, b"MAX_IBF_BUCKETS", d.union.ibf_buckets)?,
            rounds: u16::try_from(number(c, b"MAX_ROUNDS", usize::from(d.union.rounds))?)?,
            output_frames: number(c, b"MAX_UNION_OUTPUT_FRAMES", d.union.output_frames)?,
            output_bytes: size(c, b"MAX_UNION_OUTPUT_BYTES", d.union.output_bytes)?,
            results: number(c, b"MAX_RESULTS", d.union.results)?,
            received_records: number(c, b"MAX_RECEIVED_RECORDS", d.union.received_records)?,
        };
        let core = service::Limits {
            clients: number(c, b"MAX_CLIENTS", d.clients)?,
            operations: number(c, b"MAX_OPERATIONS", d.operations)?,
            set,
            union,
        };
        if !(1..=1024).contains(&core.clients) || !(1..=4096).contains(&core.operations) {
            return Err("invalid SETU client/operation bounds".into());
        }
        let nd = gnunet_setu_host::server::Limits::default();
        let native = gnunet_setu_host::server::Limits {
            clients: core.clients,
            ports: number(c, b"MAX_CADET_PORTS", nd.ports)?,
            channels: number(c, b"MAX_CADET_CHANNELS", nd.channels)?,
            frame_bytes: size(c, b"FRAME_BYTES", nd.frame_bytes)?,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", nd.io_slice_bytes)?,
            output_frames: number(c, b"MAX_CLIENT_OUTPUT_FRAMES", nd.output_frames)?,
            output_bytes: size(c, b"MAX_CLIENT_OUTPUT_BYTES", nd.output_bytes)?,
            operation_lifetime: Duration::from_micros(micros(
                c,
                b"OPERATION_LIFETIME",
                300_000_000,
            )?),
            retirement_grace: Duration::from_micros(micros(c, b"RETIREMENT_GRACE", 5_000_000)?),
        };
        if !(1..=1024).contains(&native.ports)
            || !(1..=4096).contains(&native.channels)
            || native.channels < core.operations
            || native.ports < core.clients
        {
            return Err(
                "CADET port/channel capacities must cover admitted SETU clients/operations".into(),
            );
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
        let native_abi = wire::Abi::native();
        let abi = wire::Abi {
            order: match c.get(b"setu-rust", b"NATIVE_BYTE_ORDER") {
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
        // Validate the chosen core policy before constructing sockets or runtime.
        let _validated = service::Service::new(core, abi)?;
        let yes = |key: &[u8]| {
            c.get(b"setu", key)
                .map(|_| c.get_yesno(b"setu", key))
                .transpose()
                .map(|v| v.unwrap_or(false))
        };
        let rd = gnunet_resolver_broker::Limits::default();
        let resolver = gnunet_resolver_broker::Limits {
            max_frame_bytes: size(c, b"RESOLVER_FRAME_BYTES", rd.max_frame_bytes)?,
            io_chunk_bytes: size(c, b"RESOLVER_IO_SLICE_BYTES", rd.io_chunk_bytes)?,
            max_queued_frames: number(c, b"RESOLVER_OUTPUT_FRAMES", rd.max_queued_frames)?,
        };
        Ok(Self {
            core,
            abi,
            access: UnixAccess {
                match_uid: yes(b"UNIX_MATCH_UID")?,
                match_gid: yes(b"UNIX_MATCH_GID")?,
            },
            options: service_options(c, b"setu", ShutdownMode::Soft)?,
            shutdown_grace: Duration::from_micros(micros(c, b"SHUTDOWN_GRACE", 10_000_000)?),
            resolver,
            native,
            cadet,
        })
    }
}
