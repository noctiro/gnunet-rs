//! Explicit original-process console transition before runtime registration.
pub use gnunet_native::stdio::ConsoleDetachFailure;
pub use gnunet_native::stdio::DetachedStderr;
/// Detach an already supervised original process without creating a successor.
/// Its supervisor/control connection continues to name the same process object.
///
/// # Safety
/// Establish native stream/console exclusion: fresh startup, flushed/quiescent
/// streams, no externally cached standard handles or competing launch/attachment.
/// Invoke before console handler registration. Partial native failure requires
/// explicit recovery or startup exit.
#[expect(
    unsafe_code,
    reason = "The fresh-process caller establishes native stream/console exclusion; this wrapper preserves that contract and performs no extra effect"
)]
pub unsafe fn detach_managed() -> Result<DetachedStderr, ConsoleDetachFailure> {
    // SAFETY: the caller establishes the original native global-state contract.
    unsafe { gnunet_native::stdio::detach_console() }
}
