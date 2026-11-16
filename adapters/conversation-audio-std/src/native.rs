//! Codec ABI and platform audio endpoints; protocol framing stays in Rust.
mod codec;
mod library;
#[cfg(unix)]
mod pulse;
#[cfg(windows)]
mod wasapi;
pub(crate) use codec::{Decoder, Encoder};
#[cfg(unix)]
pub(crate) use pulse::Device;
#[cfg(windows)]
pub(crate) use wasapi::Device;
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Direction {
    Capture,
    Playback,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Finish {
    Drain,
    Flush,
}
