//! Physical request retirement and separately staged Core/room failure cleanup.
use super::*;

impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    pub(in crate::server) fn retire_signing_requests(
        &mut self,
        epoch: pc::Epoch<'p>,
    ) -> Result<(), Error> {
        for sign in self.signs.iter_mut().flatten() {
            let SignState::Crypto(signing) = &sign.state else {
                continue;
            };
            let original = match signing.phase {
                SignPhase::Pending(original) | SignPhase::Cancelling(original) => original,
                _ => continue,
            };
            if original.identity.epoch() != epoch {
                return Err(Fault::StaleGeneration.into());
            }
            if !self.pils.operation_quiescent(original.operation)? {
                self.pils.cancel(original.operation)?;
            }
            if !self.pils.operation_quiescent(original.operation)? {
                return Err(Fault::NotReady.into());
            }
            sign.state = SignState::Retiring {
                original: Some(original),
                reason: Fault::Closed,
                stage: SignRetirement::Core,
            };
        }
        // An untracked request must never be carried onto the next socket.
        if !self.pils.is_idle() {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(())
    }
    pub(super) fn apply_retired_signature(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let sign = self.signs[index].as_ref().ok_or(Fault::Stale)?;
        let binding = sign.binding;
        let SignState::Retiring {
            original,
            reason,
            stage,
        } = sign.state
        else {
            return Err(Fault::Conflict.into());
        };
        let next = match stage {
            SignRetirement::Core => {
                match self.core.provider_failed(binding, reason.into()) {
                    Ok(()) => {}
                    Err(error) => {
                        let error = Error::Core(error);
                        if busy(&error) {
                            return Ok(false);
                        }
                        return Err(error);
                    }
                }
                SignRetirement::Room
            }
            SignRetirement::Room => {
                self.room_control_finished(binding.operation(), false)?;
                SignRetirement::Operation
            }
            SignRetirement::Operation => {
                if let Err(error) = self.core.retire_operation(binding.operation()) {
                    let error = Error::Core(error);
                    if busy(&error) {
                        return Ok(false);
                    }
                    return Err(error);
                }
                self.signs[index] = None;
                match original {
                    Some(original) => observe(Event::SignRetired {
                        operation: original.operation.value(),
                        reason,
                    }),
                    None => observe(Event::SignDraftRetired {
                        operation: binding.operation().observation(),
                        reason,
                    }),
                }
                return Ok(true);
            }
        };
        self.signs[index].as_mut().ok_or(Fault::Stale)?.state = SignState::Retiring {
            original,
            reason,
            stage: next,
        };
        Ok(true)
    }
}
