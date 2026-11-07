//! Bounded TOPOLOGY policy, with actual verified HELLO provenance. No socket,
//! store, entropy, implicit clock, hashing cache or transport authority exists.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
use gnunet_hello::{AbsoluteTime, Hello, SignatureProfile, VerifiedHello};
use gnunet_types::Error;
/// Public peer identity, never an address-validation or connection capability.
pub type Peer = [u8; 32];
/// Exact original HELLO frame paired with actual shared signature verification.
/// Parsing alone cannot create this value. Default official profile authenticates
/// metadata only; no method upgrades that into address or transport authority.
pub struct VerifiedFrame<'a> {
    bytes: &'a [u8],
    verified: VerifiedHello<'a>,
}
impl<'a> VerifiedFrame<'a> {
    /// Verify one original full HELLO_URI with caller scratch and explicit UTC.
    /// This performs real signature work; no caller-provided score/boolean is used.
    pub fn verify(
        bytes: &'a [u8],
        scratch: &'a mut [u8],
        limits: gnunet_hello::Limits,
        profile: SignatureProfile,
        now: u64,
    ) -> Result<Self, Error> {
        if bytes.get(2..4) != Some(&16u16.to_be_bytes()[..]) {
            return Err(Error::Unsupported);
        }
        let hello = Hello::parse_message(bytes, None, scratch, limits)?;
        let verified = hello.verify_at(profile, AbsoluteTime::from_micros(now))?;
        Ok(Self { bytes, verified })
    }
    /// Actual original complete frame, including its original reserved/count bytes.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// Actual shared verification receipt and its precise signature coverage.
    pub const fn verified(&self) -> VerifiedHello<'a> {
        self.verified
    }
}
/// Finite caller-selected business resources and UTC scheduling intervals.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bounded known/connected peer rows.
    pub peers: usize,
    /// Aggregate retained full HELLO bytes.
    pub hello_bytes: usize,
    /// Per-HELLO frame bound.
    pub frame_bytes: usize,
    /// Desired connection count; current peers below this target produce hints.
    pub target: usize,
    /// Minimum successful advertisement spacing per recipient, official5min.
    pub advertisement_interval: u64,
    /// HELLO revision suppression window, official4h.
    pub repeat_interval: u64,
    /// Periodic reconnection policy interval, official1min.
    pub reconsider_interval: u64,
    /// Retry failed local submission after this finite delay.
    pub retry_interval: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            peers: 64,
            hello_bytes: 1024 * 1024,
            frame_bytes: 65535,
            target: 16,
            advertisement_interval: 300_000_000,
            repeat_interval: 14_400_000_000,
            reconsider_interval: 60_000_000,
            retry_interval: 1_000_000,
        }
    }
}
impl Limits {
    /// Validate every finite capacity and arithmetic domain before allocation.
    pub fn validate(self) -> Result<(), Error> {
        if self.peers == 0
            || self.peers > 1024
            || self.frame_bytes < 112
            || self.frame_bytes > 65535
            || self.hello_bytes < self.frame_bytes
            || self.target > self.peers
        {
            return Err(Error::Capacity);
        }
        self.peers
            .checked_mul(self.peers.div_ceil(64))
            .ok_or(Error::Overflow)?;
        if [
            self.advertisement_interval,
            self.repeat_interval,
            self.reconsider_interval,
            self.retry_interval,
        ]
        .iter()
        .any(|n| *n == 0 || *n == u64::MAX)
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}
#[cfg(feature = "alloc")]
mod engine;
#[cfg(feature = "alloc")]
pub use engine::*;

#[cfg(all(test, feature = "alloc"))]
mod tests;
