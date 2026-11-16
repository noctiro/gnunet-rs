//! Calendar backends retain native conversions; date assembly is shared.
#[cfg(unix)]
mod posix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub(crate) use posix::{Calendar, wall_time};
#[cfg(windows)]
pub(crate) use windows::{Calendar, wall_time};

/// Wall-clock sampling does not need a local/UTC calendar or locale conversion.
pub(crate) struct WallTime {
    pub(crate) seconds: i64,
    pub(crate) micros: i64,
}
impl Calendar {
    pub(crate) fn date(&self) -> Vec<u8> {
        let Ok(pattern) = self.format(b"%Y-%m-%dT%H:%M:%S.@%z", 64) else {
            return b"localtime error".to_vec();
        };
        let Some(split) = pattern.iter().position(|&b| b == b'@') else {
            return b"localtime error".to_vec();
        };
        let mut date = pattern[..split].to_vec();
        date.extend_from_slice(format!("{:06}", self.micros as u32).as_bytes());
        date.extend_from_slice(&pattern[split + 1..]);
        date
    }
}
