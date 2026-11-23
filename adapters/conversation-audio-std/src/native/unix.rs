//! Unix PCM provider selection at the helper's native device boundary.
use super::{Direction, Finish, pulse};
use crate::Error;
use gnunet_types::Error as Fault;

pub(crate) enum Device {
    Pulse(pulse::Device),
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    Gstreamer(super::gstreamer::Device),
}

impl Device {
    pub(crate) fn new(direction: Direction, channels: u8) -> Result<Self, Error> {
        match std::env::var_os("GNUNET_CONVERSATION_AUDIO_PROVIDER")
            .as_deref()
            .map(std::ffi::OsStr::as_encoded_bytes)
        {
            None | Some(b"pulseaudio") => pulse::Device::new(direction, channels).map(Self::Pulse),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            Some(b"gstreamer") => {
                super::gstreamer::Device::new(direction, channels).map(Self::Gstreamer)
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
            Some(b"gstreamer") => Err(Fault::Unsupported.into()),
            Some(_) => Err(Fault::InvalidInput.into()),
        }
    }

    pub(crate) fn take_discontinuities(&mut self) -> u64 {
        match self {
            Self::Pulse(device) => device.take_discontinuities(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            Self::Gstreamer(device) => device.take_discontinuities(),
        }
    }

    pub(crate) fn read(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        match self {
            Self::Pulse(device) => device.read(bytes),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            Self::Gstreamer(device) => device.read(bytes),
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::Pulse(device) => device.write(bytes),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            Self::Gstreamer(device) => device.write(bytes),
        }
    }

    pub(crate) fn finish(&mut self, action: Finish) -> Result<(), Error> {
        match self {
            Self::Pulse(device) => device.finish(action),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            Self::Gstreamer(device) => device.finish(action),
        }
    }
}
