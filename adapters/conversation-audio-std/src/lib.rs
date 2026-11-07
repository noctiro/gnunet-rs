//! Explicit independent Conversation media helpers, standard730/Ogg/Opus only.
//! Blocking native audio belongs in the real helper process, never an SDK loop.
#![deny(unsafe_code)]
mod error;
pub mod framing;
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Confined standard POSIX loader and libopus/PulseAudio ABI provider; no GNUnet FFI or opaque protocol implementation"
)]
mod native;
pub mod ogg;
#[cfg(unix)]
mod playback;
#[cfg(unix)]
mod record;
pub use error::Error;
#[cfg(unix)]
pub use playback::playback;
#[cfg(unix)]
pub use record::record;
/// Selected standard codec sample rate; Ogg Opus granules always use48kHz.
pub const RATE: u32 = 48000;
/// Actual selected40ms mono recording packet extent.
pub const RECORD_SAMPLES: usize = 1920;
/// Maximum legal Opus packet duration at48kHz,120ms per channel.
pub const DECODE_SAMPLES: usize = 5760;
/// Finite owner capacities. No value changes official730 or Ogg syntax.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Complete standard helper frame, including its4-byte header.
    pub frame_bytes: usize,
    /// Complete Ogg page; all version0 pages fit65307 bytes.
    pub page_bytes: usize,
    /// Assembled packet/comment capacity across continuation pages.
    pub packet_bytes: usize,
    /// Consecutive capture resynchronization bytes before a real refusal.
    pub resync_bytes: usize,
    /// Maximum retained Rust-owned buffer capacities (not total native RSS).
    pub retained_bytes: usize,
    /// Maximum queried opaque libopus state allocation.
    pub codec_state_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            page_bytes: 65307,
            packet_bytes: 262144,
            resync_bytes: 65536,
            retained_bytes: 4 << 20,
            codec_state_bytes: 1 << 20,
        }
    }
}
impl Limits {
    /// Validate representable finite policies before opening a provider/device.
    pub fn validate(self) -> Result<Self, Error> {
        if !(1100..=65535).contains(&self.frame_bytes)
            || !(1100..=65307).contains(&self.page_bytes)
            || !(1024..=(1 << 20)).contains(&self.packet_bytes)
            || self.resync_bytes == 0
            || self.resync_bytes > 16 << 20
            || self.codec_state_bytes == 0
            || self.codec_state_bytes > 16 << 20
        {
            return Err(gnunet_types::Error::InvalidInput.into());
        }
        let required = self
            .frame_bytes
            .checked_add(self.page_bytes)
            .and_then(|n| n.checked_add(self.packet_bytes))
            .and_then(|n| n.checked_add(DECODE_SAMPLES * 2 * 8 + RECORD_SAMPLES * 8 + 2048 + 16384))
            .and_then(|n| n.checked_add(self.codec_state_bytes))
            .ok_or(gnunet_types::Error::Overflow)?;
        if required > self.retained_bytes {
            return Err(gnunet_types::Error::Capacity.into());
        }
        Ok(self)
    }
}
/// Actual helper observations, never human hearing or remote delivery receipts.
#[derive(Default, Debug)]
pub struct Report {
    /// Actual complete730 frames read/written on the original helper pipe.
    pub frames: u64,
    /// Actual decoded Opus samples per channel before cropping.
    pub decoded_samples: u64,
    /// Actual PCM samples per channel submitted to the standard audio provider.
    pub submitted_samples: u64,
    /// Actual source samples consumed by the recording encoder.
    pub recorded_samples: u64,
    /// Actual valid Ogg pages, not packet count.
    pub pages: u64,
    /// Actual capture-prefix bytes discarded before a verified page.
    pub resynchronized_bytes: u64,
    /// Actual positive page-sequence gap count; no missing PCM was invented.
    pub lost_pages: u64,
    /// Actual packet terminations whose missing prefix could not be decoded.
    pub unrecoverable_packets: u64,
    /// Actual new BOS without previous EOS, retained as a discontinuity.
    pub unterminated_streams: u64,
    /// Actual logical streams with their real EOS observed.
    pub eos_streams: u64,
    /// Actual Pulse drain returned successfully; no hearing proof is implied.
    pub drained: bool,
}
#[cfg(unix)]
pub(crate) fn buffer<T: Default + Clone>(n: usize) -> Result<zeroize::Zeroizing<Vec<T>>, Error>
where
    Vec<T>: zeroize::Zeroize,
{
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| gnunet_types::Error::Capacity)?;
    if v.capacity() > n {
        return Err(gnunet_types::Error::Capacity.into());
    }
    v.resize(n, T::default());
    Ok(zeroize::Zeroizing::new(v))
}
#[cfg(unix)]
pub(crate) fn increment(n: &mut u64, by: u64) -> Result<(), Error> {
    *n = n.checked_add(by).ok_or(gnunet_types::Error::Overflow)?;
    Ok(())
}

#[cfg(test)]
mod tests;
