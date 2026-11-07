use crate::Failure;
use gnunet_config::Configuration;
use std::time::Duration;
pub(super) struct Settings {
    pub monitor: bool,
    pub lifetime: Duration,
    pub snapshot: Duration,
    pub frame: Duration,
    pub rows: u64,
    pub reconnects: u64,
    pub native: gnunet_core_client_host::Limits,
    pub resolver: gnunet_resolver_broker::Limits,
}
const SECTION: &[u8] = b"core-cli-rust";
fn number(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Failure> {
    Ok(c.get(SECTION, key)
        .map(|_| c.get_number(SECTION, key))
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let value = c
        .get(SECTION, key)
        .map(|_| c.get_time(SECTION, key))
        .transpose()?
        .unwrap_or(u64::try_from(default.as_micros())?);
    let value = Duration::from_micros(value);
    if value.is_zero()
        || value.as_micros() >= u128::from(u64::MAX)
        || std::time::Instant::now().checked_add(value).is_none()
    {
        return Err("CORE CLI durations must be nonzero and finite".into());
    }
    Ok(value)
}
impl Settings {
    pub fn read(c: &Configuration, monitor: bool) -> Result<Self, Failure> {
        let snapshot = duration(c, b"SNAPSHOT_TIMEOUT", Duration::from_secs(30))?;
        let lifetime = duration(
            c,
            b"LIFETIME",
            if monitor {
                Duration::from_secs(8 * 3600)
            } else {
                snapshot
            },
        )?;
        let io = usize::try_from(number(c, b"IO_SLICE_BYTES", 65535)?)?;
        let frame_bytes = usize::try_from(number(c, b"FRAME_BYTES", 256)?)?;
        let rows = number(c, b"MAX_ROWS", 1_000_000)?;
        let reconnects = number(c, b"MAX_RECONNECTS", 1024)?;
        if io == 0
            || io > 65535
            || !(56..=65535).contains(&frame_bytes)
            || rows == 0
            || reconnects == 0
        {
            return Err("CORE CLI invalid resource profile".into());
        }
        Ok(Self {
            monitor,
            lifetime,
            snapshot,
            frame: duration(c, b"FRAME_TIMEOUT", Duration::from_secs(10))?,
            rows,
            reconnects,
            native: gnunet_core_client_host::Limits {
                sends: 1,
                source_bytes: 4,
                frame_bytes,
                output: gnunet_service_runtime::framing::Budget {
                    frames: 1,
                    bytes: frame_bytes,
                },
                io_slice_bytes: io,
            },
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: io,
                max_queued_frames: 4,
            },
        })
    }
}
