//! Test-only successful provider turns for pure Engine FLOW scenarios.
//!
//! This supplies an exact Engine demand with a finite numeric span. It models
//! only the provider boundary; it proves no filesystem commit, fsync or restart
//! durability. The original test clock is never advanced to make FLOW succeed.
use gnunet_crypto::Entropy;
use gnunet_transport::{Engine, Times, monotime::Span};
use gnunet_types::Error;

pub fn tick_with_monotime_provider(
    engine: &mut Engine,
    now: u64,
    entropy: &mut impl Entropy,
) -> Result<(), Error> {
    engine.tick(now, entropy)?;
    if let Some(demand) = engine.monotime_demand().cloned() {
        let first = engine
            .monotime_state()
            .greatest_upper
            .checked_add(1)
            .ok_or(Error::Overflow)?
            .max(now);
        let last = first.checked_add(1023).ok_or(Error::Overflow)?;
        engine.supply_monotime(
            demand.id(),
            Span::checked(first, last)?,
            Times::shared_coordinate(now),
        )?;
        // Resume work at the same original coordinate after this provider result.
        engine.tick(now, entropy)?;
    }
    Ok(())
}
