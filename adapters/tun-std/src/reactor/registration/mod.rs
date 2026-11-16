//! Original native readiness/packet owner beneath the shared packet state machine.
use crate::OwnedTun;
use std::io;
pub(super) enum Input {
    Data(usize),
    #[cfg(windows)]
    Oversize,
}
/// Original packet owner and the actual registration/preparation error.
pub struct Refusal {
    pub(super) tun: OwnedTun,
    pub(super) cause: io::Error,
}
impl Refusal {
    /// Return the original owner; no native close or source replacement occurs.
    pub fn into_parts(self) -> (OwnedTun, io::Error) {
        (self.tun, self.cause)
    }
}
impl std::fmt::Debug for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationFailure")
            .field("tun", &self.tun)
            .field("cause", &self.cause)
            .finish()
    }
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TUN reactor registration: {}", self.cause)
    }
}
impl std::error::Error for Refusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(super) use unix::Registered;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(super) use windows::Registered;
