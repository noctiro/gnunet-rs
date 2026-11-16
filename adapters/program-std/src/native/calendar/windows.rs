//! Wide native calendar output with shared local byte encoding and date assembly.
use super::WallTime;
use gnunet_native::{
    calendar::{Calendar as NativeCalendar, Zone},
    os_bytes,
};
use std::{
    fmt, io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) struct Calendar {
    pub(crate) micros: i64,
    local: Result<NativeCalendar, Arc<io::Error>>,
}
#[derive(Debug)]
struct RetainedError(Arc<io::Error>);
impl fmt::Display for RetainedError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(output)
    }
}
impl std::error::Error for RetainedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
pub(crate) fn wall_time() -> io::Result<WallTime> {
    let (seconds, micros) = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => (
            i64::try_from(value.as_secs()).map_err(io::Error::other)?,
            i64::from(value.subsec_micros()),
        ),
        Err(error) => {
            let value = error.duration();
            let seconds = i64::try_from(value.as_secs()).map_err(io::Error::other)?;
            if value.subsec_nanos() == 0 {
                (-seconds, 0)
            } else {
                (
                    seconds
                        .checked_neg()
                        .and_then(|s| s.checked_sub(1))
                        .ok_or(io::ErrorKind::InvalidData)?,
                    i64::from((1_000_000_000 - value.subsec_nanos()) / 1000),
                )
            }
        }
    };
    Ok(WallTime { seconds, micros })
}
impl Calendar {
    pub(crate) fn new(seconds: i64, micros: i64, utc: bool) -> io::Result<Self> {
        Ok(Self {
            micros,
            local: NativeCalendar::from_epoch(seconds, if utc { Zone::Utc } else { Zone::Local })
                .map_err(Arc::new),
        })
    }
    pub(crate) fn format(&self, pattern: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
        let local = self
            .local
            .as_ref()
            .map_err(|error| io::Error::new(error.kind(), RetainedError(Arc::clone(error))))?;
        let pattern = os_bytes::decode(
            &pattern[..pattern
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(pattern.len())],
        )?;
        let result = local.format(&pattern, capacity.min(32768))?;
        let bytes = os_bytes::encode(&result).into_owned();
        if bytes.len() >= capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "calendar output exceeds byte capacity",
            ));
        }
        Ok(bytes)
    }
}
