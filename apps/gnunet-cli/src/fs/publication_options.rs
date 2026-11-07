//! One publication policy selection, frozen into existing BlockOptions/tasks.
use gnunet::{fs_host::network::BlockOptions, types::AbsoluteTime};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{error::Error, ffi::OsStr, os::unix::ffi::OsStrExt};

const DEFAULT_LIFETIME_US: u64 = 63_072_000_000_000;
#[derive(Clone, Copy)]
enum Expiration {
    Absolute(AbsoluteTime),
    Relative(u64),
}
#[derive(Clone, Copy, Default)]
pub(crate) struct Selection {
    priority: Option<u32>,
    anonymity: Option<u32>,
    replication: Option<u32>,
    expiration: Option<Expiration>,
}
impl Selection {
    /// The enclosing grammar handles literal `--` and consumes metadata/named
    /// values atomically. A recognized policy option owns its complete value.
    pub(super) fn consume<T: AsRef<OsStr>>(
        &mut self,
        args: &[T],
        at: &mut usize,
    ) -> Result<bool, Box<dyn Error>> {
        let name = args
            .get(*at)
            .ok_or("missing publication option")?
            .as_ref()
            .as_bytes();
        if !matches!(
            name,
            b"-p"
                | b"--priority"
                | b"-a"
                | b"--anonymity"
                | b"-r"
                | b"--replication"
                | b"--expiration-us"
                | b"--expiration"
        ) {
            return Ok(false);
        }
        let value = args
            .get(*at + 1)
            .ok_or("publication option requires a value")?
            .as_ref();
        match name {
            b"--expiration-us" | b"--expiration" => {
                if self.expiration.is_some() {
                    return Err("publication expiration may be selected only once".into());
                }
                self.expiration = Some(if name == b"--expiration-us" {
                    let micros = value
                        .to_str()
                        .ok_or("absolute expiration requires UTF-8 digits")?
                        .parse::<u64>()?;
                    Expiration::Absolute(AbsoluteTime::from_micros(micros))
                } else {
                    Expiration::Relative(gnunet_config::parse_relative_time_checked(
                        value.as_bytes(),
                    )?)
                });
            }
            _ => {
                let selected = match name {
                    b"-p" | b"--priority" => &mut self.priority,
                    b"-a" | b"--anonymity" => &mut self.anonymity,
                    _ => &mut self.replication,
                };
                if selected.is_some() {
                    return Err("publication policy field may be selected only once".into());
                }
                *selected = Some(
                    value
                        .to_str()
                        .ok_or("publication policy requires UTF-8 digits")?
                        .parse::<u32>()?,
                );
            }
        }
        *at += 2;
        Ok(true)
    }
    /// Read the original actual source exactly once. Operation deadlines are
    /// selected independently; task resume never invokes this selection again.
    pub(super) fn select(self, clock: &dyn RuntimeClock) -> Result<BlockOptions, Box<dyn Error>> {
        let now = clock.sample()?.now;
        self.resolve(now)
    }
    fn resolve(self, now: AbsoluteTime) -> Result<BlockOptions, Box<dyn Error>> {
        let finite = |interval| {
            now.as_micros()
                .checked_add(interval)
                .filter(|value| *value != u64::MAX)
                .map(AbsoluteTime::from_micros)
                .ok_or("finite publication expiration overflows absolute time")
        };
        let expiration = match self.expiration {
            None => finite(DEFAULT_LIFETIME_US)?,
            Some(Expiration::Absolute(value)) => value,
            Some(Expiration::Relative(u64::MAX)) => AbsoluteTime::NEVER,
            Some(Expiration::Relative(interval)) => finite(interval)?,
        };
        Ok(BlockOptions {
            expiration,
            priority: self.priority.unwrap_or(365),
            anonymity: self.anonymity.unwrap_or(1),
            replication: self.replication.unwrap_or(1),
        })
    }
}

#[cfg(test)]
mod tests;
