//! Authenticated original channel input and immediate local output revocation.
use super::{Book, Channel, ChannelMessage, Effect, Pending, ProtocolError, peer};
use gnunet_types::MonoInstant;

impl<'node> Channel<'_, 'node, '_, '_> {
    pub(super) fn receive<'book, const P: usize>(
        &mut self,
        index: usize,
        pending: &[Option<Pending<'node, 'book>>],
        book: &mut Book<'book, '_, '_, P>,
        message: ChannelMessage<'_>,
        connection: [u8; 32],
        now: MonoInstant,
    ) -> Result<peer::Event<'node>, ProtocolError> {
        let owner = self.owner.as_mut().ok_or(ProtocolError::StaleGeneration)?;
        let expected = (owner.ack().0, owner.phase());
        let before = owner.available_send();
        let result = owner.receive(owner.scope(), message, connection, now);
        if let Some(observations) = &mut self.observations {
            observations.input(
                message,
                expected,
                (before, owner.available_send()),
                owner.phase(),
                &result,
                now,
            );
        }
        if matches!(result, Ok(peer::Event::Destroyed { .. })) {
            self.closing = true;
            self.lost = true;
            // The next Node turn may run CORE before channel maintenance.
            // Remove queued originals now; already-started physical attempts
            // retain their exact native debt and settle through the observer.
            for pending in pending.iter().flatten() {
                if matches!(pending.effect, Effect::Channel { slot, .. } if slot == index) {
                    match book.cancel_frame(pending.effect.frame()) {
                        Ok(()) | Err(ProtocolError::WouldBlock) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests;
