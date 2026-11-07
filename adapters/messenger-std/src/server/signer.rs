//! One original shared PILS MQ. Only its exact consumed Signature receipt can
//! finish the retained purpose12 draft; no seed or C private key is obtained.
use super::*;
#[cfg(test)]
mod profile_tests;
#[cfg(test)]
mod rotation_tests;
impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    pub(super) fn signing_work(&mut self) -> Result<bool, Error> {
        let Some(index) = self.signs.iter().position(Option::is_none) else {
            return Ok(false);
        };
        if !self.identity_ready() {
            return Ok(false);
        }
        for n in 0..self.rooms.len() {
            let i = (self.room_cursor + n) % self.rooms.len();
            let Some(r) = self.rooms[i].as_ref() else {
                continue;
            };
            let room = r.room;
            let Some(work) = self.core.take_service_signing_work(room)? else {
                continue;
            };
            let core::ServiceSignWork {
                binding,
                kind,
                body,
                public,
                sender,
                previous,
                timestamp,
            } = work;
            let peer = self.current_peer().ok_or(Fault::NotReady)?;
            if public[..4] != wire::KeyType::Eddsa.value().to_be_bytes()
                || public[4..] != peer
                || sender != peer
            {
                return Err(Fault::PermissionDenied.into());
            }
            let mut signature = [0; 68];
            signature[..4].copy_from_slice(&wire::KeyType::Eddsa.value().to_be_bytes());
            let mut bytes = Zeroizing::new(vector(
                176usize
                    .checked_add(body.expose().len())
                    .ok_or(Fault::Overflow)?,
            )?);
            wire::envelope::encode(
                wire::envelope::Header {
                    signature: wire::envelope::Signature::new(&signature)?,
                    timestamp: gnunet_wire::official::AbsoluteTime::from_micros(timestamp),
                    sender_id: &sender,
                    previous: &previous,
                    kind,
                },
                wire::SensitiveBytes::new(body.expose()),
                &mut bytes,
            )?;
            let parsed = wire::message::Message::decode(
                &bytes,
                self.limits.profile,
                padding::Decode::Absent,
            )?;
            if core::crypto::signature::message_hash(parsed) != *binding.message() {
                return Err(Fault::Authentication.into());
            }
            let budget = self
                .control_budgets
                .iter()
                .position(|b| {
                    b.as_ref()
                        .is_some_and(|b| b.operation == binding.operation())
                })
                .ok_or(Fault::StaleGeneration)?;
            let until = self.control_budgets[budget]
                .take()
                .ok_or(Fault::Stale)?
                .until;
            let hard = until
                .checked_add(self.limits.retirement_grace)
                .ok_or(Fault::Overflow)?;
            self.signs[index] = Some(Sign {
                room,
                binding,
                peer,
                frame: OwnedBytes::new(bytes),
                phase: SignPhase::Draft,
                until,
                hard,
            });
            self.room_cursor = (i + 1) % self.rooms.len();
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn apply_signature(
        &mut self,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        for i in 0..self.signs.len() {
            let Some(s) = self.signs[i].as_ref() else {
                continue;
            };
            let (binding, room, phase) = (s.binding, s.room, s.phase);
            match phase {
                SignPhase::Pending(_) | SignPhase::Cancelling(_) => continue,
                SignPhase::Draft => {
                    let Some(identity) = self.active_identity() else {
                        continue;
                    };
                    if identity.peer().as_bytes() != &s.peer
                        || self.pils.identity().is_none_or(|actual| {
                            actual.epoch() != identity.epoch() || actual.peer() != identity.peer()
                        })
                    {
                        return Err(Fault::StaleGeneration.into());
                    }
                    let payload = core::crypto::signature::signing_payload(binding.message())
                        .map_err(core::Error::from)?;
                    let operation = self.pils.sign(&payload, pc::KeyTarget::Exact(identity))?;
                    self.signs[i].as_mut().ok_or(Fault::Stale)?.phase =
                        SignPhase::Pending(OriginalSign {
                            operation,
                            identity,
                        });
                    observe(Event::SignAdmitted {
                        operation: operation.value(),
                    });
                }
                SignPhase::Verified(original) => {
                    let input = match OwnedBytes::copy_from(s.frame.expose()) {
                        Ok(input) => input,
                        Err(error) => {
                            let error = Error::from(error);
                            if busy(&error) {
                                return Ok(false);
                            }
                            return Err(error);
                        }
                    };
                    match self.core.complete_signature(
                        binding,
                        input,
                        padding::Decode::Absent,
                        self.last_now,
                    ) {
                        Ok(()) => {
                            self.signs[i].as_mut().ok_or(Fault::Stale)?.phase =
                                SignPhase::PreparedCore(original)
                        }
                        Err(rejected) => {
                            let error = Error::Core(rejected.error);
                            if busy(&error) {
                                return Ok(false);
                            }
                            return Err(error);
                        }
                    }
                }
                SignPhase::PreparedCore(original) => {
                    if self.messages.iter().all(Option::is_some) {
                        return Ok(false);
                    }
                    let hash = match self.core.service_commit_signature(binding, self.last_now) {
                        Ok(hash) => hash,
                        Err(error) => {
                            let error = Error::Core(error);
                            if busy(&error) {
                                return Ok(false);
                            }
                            return Err(error);
                        }
                    };
                    // Commit is a real fact before any later hook, graph
                    // advancement or delivery admission can fail or block.
                    self.signs[i].as_mut().ok_or(Fault::Stale)?.phase =
                        SignPhase::Committed { original, hash };
                    self.room_control_finished(binding.operation(), true)?;
                }
                SignPhase::Committed { original, hash } => {
                    if let Err(error) = self.core.advance(room, self.last_now) {
                        let error = Error::Core(error);
                        if busy(&error) {
                            return Ok(false);
                        }
                        return Err(error);
                    }
                    if let Err(error) = self.track(room, hash, None, true) {
                        let error = Error::Protocol(error);
                        if busy(&error) {
                            return Ok(false);
                        }
                        return Err(error);
                    }
                    self.core.retire_operation(binding.operation())?;
                    observe(Event::SignApplied {
                        operation: original.operation.value(),
                    });
                    self.signs[i] = None;
                }
            }
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn signing_expiry(&mut self) -> Result<bool, Error> {
        let now = Instant::now();
        for i in 0..self.signs.len() {
            let Some(s) = self.signs[i].as_ref() else {
                continue;
            };
            if now >= s.hard {
                return Err(Fault::Deadline.into());
            }
            let locally_finished = if now >= s.until {
                match s.phase {
                    SignPhase::PreparedCore(_) | SignPhase::Committed { .. } => {
                        return Err(Fault::Deadline.into());
                    }
                    SignPhase::Pending(original) => {
                        self.pils.cancel(original.operation)?;
                        self.signs[i].as_mut().ok_or(Fault::Stale)?.phase =
                            SignPhase::Cancelling(original);
                        return Ok(true);
                    }
                    SignPhase::Draft | SignPhase::Verified(_) => true,
                    SignPhase::Cancelling(original) => {
                        self.pils.operation_quiescent(original.operation)?
                    }
                }
            } else {
                false
            };
            if locally_finished {
                let sign = self.signs[i].take().ok_or(Fault::Stale)?;
                self.core
                    .provider_failed(sign.binding, Fault::Deadline.into())?;
                self.room_control_finished(sign.binding.operation(), false)?;
                self.core.retire_operation(sign.binding.operation())?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub(super) fn signer_poll(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.signing_expiry()?
            || self.identity_step(observe)?
            || (!self.history_frozen() && self.apply_signature(observe)?)
            || self.signing_work()?
        {
            return Poll::Ready(Ok(Progress::Activity));
        }
        // PILS's caller-driven drive preserves all original cursors when this single
        // wait future is dropped. No background or per-room PILS client is spawned.
        let p = {
            let mut f = std::pin::pin!(self.pils.drive(None));
            f.as_mut().poll(cx)
        };
        let p = match p {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(p)) => p,
            Poll::Ready(Err(error)) => {
                self.retire_pils();
                return Poll::Ready(Err(error.into()));
            }
        };
        self.signer_progress(p, observe)?;
        Poll::Ready(Ok(Progress::Activity))
    }
    /// Consume one actual native-client observation. This does not poll or
    /// replace the source and never manufactures a provider completion.
    pub(super) fn signer_progress(
        &mut self,
        progress: pils::Progress<'p, O>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        match progress {
            pils::Progress::Inbound(pc::Inbound::Identity { identity, .. }) => {
                self.observe_identity(identity)?;
                observe(Event::Identity);
            }
            pils::Progress::Inbound(pc::Inbound::Complete(completion)) => {
                let operation = completion.operation();
                let Some(i) = self.signs.iter().position(|s| {
                    s.as_ref().is_some_and(|s| {
                        s.phase
                            .original()
                            .is_some_and(|original| original.operation == operation)
                    })
                }) else {
                    return Ok(());
                };
                let sign = self.signs[i].as_mut().ok_or(Fault::Stale)?;
                if matches!(sign.phase, SignPhase::Cancelling(_)) {
                    return Ok(());
                }
                let SignPhase::Pending(original) = sign.phase else {
                    return Err(Fault::Replay.into());
                };
                match completion {
                    pc::Completion::Signature {
                        peer,
                        signature,
                        announced,
                        ..
                    } => {
                        // The SDK verified this exact original operation's
                        // region and expected key. After a healthy update it
                        // may no longer expose that old announcement as current.
                        if Some(original.identity.epoch()) != self.pils.epoch()
                            || peer != original.identity.peer()
                            || peer.as_bytes() != &sign.peer
                            || announced.is_some_and(|id| {
                                id.epoch() != original.identity.epoch()
                                    || id.peer() != original.identity.peer()
                            })
                        {
                            return Err(Fault::Authentication.into());
                        }
                        let mut bytes = Zeroizing::new(vector(sign.frame.expose().len())?);
                        bytes.copy_from_slice(sign.frame.expose());
                        bytes[4..68].copy_from_slice(signature.as_bytes());
                        sign.frame = OwnedBytes::new(bytes);
                        sign.phase = SignPhase::Verified(original);
                    }
                    pc::Completion::Failed { reason, .. } => {
                        observe(Event::SignRejected {
                            operation: operation.value(),
                            reason,
                        });
                        let sign = self.signs[i].take().ok_or(Fault::Stale)?;
                        self.core
                            .provider_failed(sign.binding, Fault::Authentication.into())?;
                        self.room_control_finished(sign.binding.operation(), false)?;
                        self.core.retire_operation(sign.binding.operation())?;
                    }
                    _ => return Err(Fault::Conflict.into()),
                }
            }
            pils::Progress::Written(w) => observe(Event::SignWritten {
                operation: w.operation.value(),
            }),
            pils::Progress::Lost { cause, .. } => {
                self.retire_pils();
                observe(Event::DependencyLost { pils: true });
                return Err(Error::PilsLost(cause));
            }
            pils::Progress::Unavailable(e) => {
                self.retire_pils();
                return Err(e.into());
            }
            pils::Progress::Closed => {
                self.retire_pils();
                return Err(Fault::Closed.into());
            }
            pils::Progress::Connected(epoch) => {
                if let Err(error) = self.check_pils_epoch(epoch) {
                    self.retire_pils();
                    return Err(error);
                }
            }
            _ => {}
        }
        Ok(())
    }
}
