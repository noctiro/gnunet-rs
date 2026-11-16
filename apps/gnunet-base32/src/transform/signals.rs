//! Native cancellation without a platform stub in the conversion loop.
#[cfg(unix)]
#[path = "signals_unix.rs"]
mod native;
#[cfg(unix)]
pub(super) use native::Signals;

#[cfg(windows)]
pub(super) struct Signals(gnunet_service_runtime::signals::Termination);
#[cfg(windows)]
impl Signals {
    pub(super) fn new() -> std::io::Result<Self> {
        gnunet_service_runtime::signals::Termination::new().map(Self)
    }
    pub(super) fn check(
        &mut self,
        cx: &mut std::task::Context<'_>,
        facts: &mut super::Facts,
    ) -> Result<(), super::Problem> {
        if let std::task::Poll::Ready(result) = self.0.poll_stop(cx) {
            result.map_err(|error| super::Problem::new(1, error))?;
            facts.cancelled = Some(2);
            return Err(super::Problem::message(
                130,
                "original conversion cancelled by native termination",
            ));
        }
        Ok(())
    }
}
