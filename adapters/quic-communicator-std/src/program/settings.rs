//! PROGRAM-specific settings layered over the shared communicator setup.
use super::Failure;
use crate::{configured::Configured, tls::Profile};
use gnunet_config::Configuration;

pub(super) struct Settings {
    pub configured: Configured,
    pub resolver: gnunet_resolver_broker::Limits,
}

impl Settings {
    pub fn read(config: &Configuration, profile: Profile) -> Result<Self, Failure> {
        let configured = Configured::read(config, profile)?;
        let resolver = gnunet_resolver_broker::Limits {
            max_frame_bytes: 65535,
            io_chunk_bytes: configured.limits.io_slice,
            max_queued_frames: 8,
        };
        Ok(Self {
            configured,
            resolver,
        })
    }
}

pub(super) const fn binary(profile: Profile) -> &'static [u8] {
    match profile {
        Profile::Raw => b"gnunet-communicator-quic",
        Profile::Http3 => b"gnunet-communicator-http3",
    }
}
