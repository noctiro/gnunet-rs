//! Explicit per-source DV resource policy and caller-owned shared buffer pools.
//! Construction allocates bounded empty storage; it creates no key, MQ or worker.
use crate::Failure;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_transport::dv;
use gnunet_transport_dv_runtime_host as actor;
use gnunet_types::{Duration as Micros, Error};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
const SECTION: &[u8] = b"transport-rust";
/// One qualified worker root plus fixed source metadata/shared plaintext policy.
pub struct Policy {
    /// Independently marked Rust-owned public DV ledger, never a C directory.
    pub store: PathBuf,
    /// Actual provider's permanent record quota (LEARN and BOX combined).
    pub records: usize,
    /// Actual one-source Actor RAM/CPU/native budgets.
    pub actor: actor::Limits,
    /// Caller-owned fixed metadata and shared plaintext buffers.
    pub pools: crate::dv_resources::Policy,
    /// Bounded original physical/DV/FC bridge metadata.
    pub bridge: gnunet_transport_dv_bridge_host::Limits,
    /// Actual durable-range/probe/verified-LEARN scheduling policy.
    pub scheduler: crate::dv_schedule::Limits,
    /// Fair actual composition transitions per caller poll.
    pub quantum: usize,
}
fn count(
    c: &Configuration,
    key: &[u8],
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, Failure> {
    let value = c
        .get(SECTION, key)
        .map(|_| c.get_number(SECTION, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default);
    if !(min..=max).contains(&value) {
        return Err(Error::InvalidInput.into());
    }
    Ok(value)
}
impl Policy {
    /// Read finite limits without opening any source/store. Both ledger roots
    /// must be explicit independent absolute final directories.
    pub fn read(c: &Configuration, stamp: &Path, operation: Duration) -> Result<Self, Failure> {
        let raw = c
            .get(SECTION, b"DV_STORE")
            .unwrap_or(b"$GNUNET_DATA_HOME/transport-rust-dv");
        let expanded = c.expand_filename(raw, &ProcessEnvironment)?;
        if !expanded.is_absolute()
            || expanded.file_name().is_none()
            || expanded == stamp
            || expanded.starts_with(stamp)
            || stamp.starts_with(&expanded)
        {
            return Err(Error::InvalidInput.into());
        }
        let neighbours = count(c, b"DV_NEIGHBOURS", 64, 1, 1024)?;
        let inputs = count(c, b"DV_INPUTS", 16, 1, 256)?;
        let outputs = count(c, b"DV_OUTPUTS", 16, 1, 256)?;
        let frame_bytes = count(
            c,
            b"DV_FRAME_BYTES",
            65535,
            dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4,
            65535,
        )?;
        let quantum = count(c, b"DV_QUANTUM", 8, 1, 64)?;
        let probe_slots = count(c, b"DV_PROBES", 8, 1, 64)?;
        let route_slots = count(c, b"DV_ROUTES", 192, 1, 4096)?;
        let materials = count(c, b"DV_MATERIALS", 16, 1, 256)?;
        let plaintext = count(c, b"DV_PLAINTEXT_LOANS", 4, 1, 64)?;
        let replay_peers = count(c, b"DV_REPLAY_PEERS", 128, 1, 4096)?;
        let replay_nonces = count(c, b"DV_REPLAY_NONCES", 4096, 1, 262144)?;
        let source_slots = count(c, b"DV_SOURCE_SLOTS", 64, 1, 4096)?;
        let records = count(c, b"DV_STORE_RECORDS", 8192, 1, 1_000_000)?;
        let bytes = count(c, b"DV_BYTES", 1024 * 1024, frame_bytes, 64 * 1024 * 1024)?;
        plaintext
            .checked_mul(frame_bytes)
            .filter(|n| *n <= 16 * 1024 * 1024)
            .ok_or(Error::Capacity)?;
        let micros = u64::try_from(operation.as_micros()).map_err(|_| Error::Overflow)?;
        let limits = actor::Limits {
            inputs,
            outputs,
            neighbours,
            bytes,
            frame_bytes,
            quantum,
            operation: Micros(micros),
            native_operation: operation,
            ..Default::default()
        };
        let scheduler = crate::dv_schedule::Limits {
            neighbours,
            probes: probe_slots,
            learns: inputs,
            forwards: outputs,
            quantum,
            range_operation: operation,
            probe_lifetime: operation,
            ..Default::default()
        };
        Ok(Self {
            store: expanded,
            records,
            actor: limits,
            pools: crate::dv_resources::Policy {
                routes: route_slots,
                probes: probe_slots,
                sources: source_slots,
                send_materials: materials,
                receive_materials: materials,
                replay_peers,
                replay_nonces,
                plaintext_buffers: plaintext,
                frame_bytes,
                max_total_bytes: 8 * 1024 * 1024,
            },
            bridge: gnunet_transport_dv_bridge_host::Limits {
                neighbours,
                outputs,
                finished: inputs,
                paths: route_slots,
            },
            scheduler,
            quantum,
        })
    }
}
