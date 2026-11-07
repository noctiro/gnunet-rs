use gnunet_config::Configuration;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_seti as core;
use gnunet_seti_host::Limits;
use std::{error::Error, time::Duration};
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Box<dyn Error>> {
    Ok(c.get(b"seti-rust", key)
        .map(|_| c.get_number(b"seti-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: u64) -> Result<Duration, Box<dyn Error>> {
    let n = c
        .get(b"seti-rust", key)
        .map(|_| c.get_time(b"seti-rust", key))
        .transpose()?
        .unwrap_or(default);
    if n == 0
        || n == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(n))
            .is_none()
    {
        return Err("duration must be finite, nonzero and representable".into());
    }
    Ok(Duration::from_micros(n))
}
fn yes(c: &Configuration, key: &[u8]) -> Result<bool, Box<dyn Error>> {
    Ok(c.get(b"seti", key)
        .map(|_| c.get_yesno(b"seti", key))
        .transpose()?
        .unwrap_or(false))
}
pub(super) struct Settings {
    pub native: Limits,
    pub core: core::Limits,
    pub sets: usize,
    pub element_slots: usize,
    pub element_bytes: usize,
    pub large_slots: usize,
    pub large_bytes: usize,
    pub context_bytes: usize,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub startup_timeout: Duration,
    pub shutdown_grace: Duration,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Box<dyn Error>> {
        let d = Limits::default();
        let lifetime = if c.get(b"seti-rust", b"OPERATION_TIMEOUT").is_some() {
            Some(duration(c, b"OPERATION_TIMEOUT", 300_000_000)?)
        } else {
            None
        };
        let native = Limits {
            clients: number(c, b"MAX_CLIENTS", d.clients)?,
            listeners: number(c, b"MAX_LISTENERS", d.listeners)?,
            operations: number(c, b"MAX_OPERATIONS", d.operations)?,
            frame_bytes: 65535,
            io_slice_bytes: number(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            operation_lifetime: lifetime,
            send_timeout: duration(c, b"SEND_TIMEOUT", 30_000_000)?,
        };
        let settings = Self {
            native,
            core: core::Limits {
                bloom_bytes: number(c, b"BLOOM_BYTES", 64 * 1024)?,
                hash_rounds: u32::try_from(number(c, b"HASH_ROUNDS", 256)?)?,
                exchanges: u32::try_from(number(c, b"MAX_EXCHANGES", 1024)?)?,
                ..core::Limits::default()
            },
            sets: number(c, b"MAX_SETS", 8)?,
            element_slots: number(c, b"ELEMENT_SLOTS", 1024)?,
            element_bytes: number(c, b"ELEMENT_BYTES", 1024)?,
            large_slots: number(c, b"LARGE_ELEMENT_SLOTS", 16)?,
            large_bytes: number(
                c,
                b"LARGE_ELEMENT_BYTES",
                core::Limits::default().element_bytes,
            )?,
            context_bytes: number(c, b"CONTEXT_BYTES", 1024)?,
            options: service_options(c, b"seti", ShutdownMode::Soft)?,
            unix: UnixAccess {
                match_uid: yes(c, b"UNIX_MATCH_UID")?,
                match_gid: yes(c, b"UNIX_MATCH_GID")?,
            },
            startup_timeout: duration(c, b"CADET_STARTUP_TIMEOUT", 15_000_000)?,
            shutdown_grace: duration(c, b"SHUTDOWN_GRACE", 10_000_000)?,
        };
        if !(1..=256).contains(&native.clients)
            || native.listeners > 256
            || !(1..=256).contains(&native.operations)
            || native.io_slice_bytes == 0
            || !(1..=256).contains(&settings.sets)
            || settings.element_slots > 65536
            || settings.large_slots > 4096
            || settings.element_slots + settings.large_slots == 0
            || settings.element_bytes == 0
            || settings.element_bytes > settings.core.element_bytes
            || settings.large_bytes == 0
            || settings.large_bytes > settings.core.element_bytes
            || !(8..=16 * 1024 * 1024).contains(&settings.core.bloom_bytes)
            || settings.context_bytes > 64276
            || settings.core.hash_rounds == 0
            || settings.core.hash_rounds > 4096
            || settings.core.exchanges == 0
        {
            return Err("invalid explicit SETI resources".into());
        }
        let elements = settings
            .element_slots
            .checked_add(settings.large_slots)
            .ok_or("element slots overflow")?;
        let bitmap = elements.checked_add(7).ok_or("bitmap overflow")? / 8;
        let pools = settings
            .element_slots
            .checked_mul(settings.element_bytes)
            .and_then(|n| {
                settings
                    .large_slots
                    .checked_mul(settings.large_bytes)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                bitmap
                    .checked_mul(3)
                    .and_then(|b| b.checked_add(settings.core.bloom_bytes))
                    .and_then(|b| b.checked_add(settings.context_bytes))
                    .and_then(|b| b.checked_mul(native.operations))
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or("SETI backing pool overflow")?;
        if pools > 128 * 1024 * 1024 {
            return Err("SETI shared backing exceeds explicit 128MiB foreground ceiling".into());
        }
        Ok(settings)
    }
}
pub(super) fn filled<T>(n: usize, mut make: impl FnMut() -> T) -> Result<Vec<T>, Box<dyn Error>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)?;
    for _ in 0..n {
        v.push(make());
    }
    Ok(v)
}
pub(super) fn bytes(n: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    filled(n, || 0)
}
