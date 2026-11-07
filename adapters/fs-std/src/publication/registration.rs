//! Independent original FS INDEX_START history; PUT STATUS never establishes it.
use super::{
    codec,
    model::{AcceptedRef, Attempt, ModelError, NoEffect, Phase},
};
use gnunet_datastore_host::Interruption;
use gnunet_wire::official::fs::Response;

/// Original declaration or unresolved exposure of an INDEX_START request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Intent was synced; its actual effect is not yet known.
    Intent,
    /// An actual original FS IndexFailed reply remains retained.
    Refused {
        /// Exact Refused record, holding the original frame once.
        record_index: usize,
        /// Original independent caller interruption, if any.
        interruption: Option<Interruption>,
    },
    /// An exposed original registration has no affirmative or negative reply.
    Unknown {
        /// Original uncertainty record with an optional actual diagnostic frame.
        record_index: usize,
        /// Original independent caller interruption, if any.
        interruption: Option<Interruption>,
    },
}
/// Original index intent; its row coordinate is separate from PUT coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Original request hash and local intent generation.
    pub attempt: Attempt,
    /// Actual retained effect knowledge, never a retry authorization by itself.
    pub disposition: Disposition,
}
/// Original registration facts. Only the native receipt owner constructs these
/// for admission; structural decoding does not manufacture native authority.
#[derive(Debug)]
pub enum Event<'a> {
    /// Must be synced before one exact original INDEX_START is submitted.
    Intent {
        /// Ordered source coordinate from the immutable plan.
        index: usize,
        /// Exact full official request digest, including its canonical raw path.
        request_hash: [u8; 64],
    },
    /// An actual request-bound original FS IndexStarted was received.
    Accepted {
        /// Original task source/request/intent generation.
        attempt: Attempt,
        /// Original complete four-byte FS IndexStarted reply.
        response: &'a [u8],
        /// Original independent caller interruption, if any.
        interruption: Option<Interruption>,
    },
    /// Original local/native owner proved the registration was never exposed.
    NotApplied {
        /// Original request and its local generation.
        attempt: Attempt,
        /// Actual zero-exposure proof class; a negative peer reply is not one.
        reason: NoEffect,
        /// Original independent caller interruption, if any.
        interruption: Option<Interruption>,
    },
    /// Actual IndexFailed retains refusal and requires explicit retry.
    Refused {
        /// Exact original request generation.
        attempt: Attempt,
        /// Complete original FS IndexFailed including its terminated diagnostic.
        response: &'a [u8],
        /// Original independent caller interruption, if any.
        interruption: Option<Interruption>,
    },
    /// Preserve uncertainty rather than replaying an original exposed mutation.
    Unknown {
        /// Exact original request generation.
        attempt: Attempt,
        /// Actual optional original diagnostic; absence never establishes no-send.
        response: Option<&'a [u8]>,
        /// Original independent caller interruption, if any.
        interruption: Option<Interruption>,
    },
    /// Explicit caller authorization after a recorded actual IndexFailed only.
    RetryRefused {
        /// Original recorded refused request generation.
        attempt: Attempt,
    },
}
impl Event<'_> {
    pub(super) fn interruption(&self) -> Option<Interruption> {
        match self {
            Self::Accepted { interruption, .. }
            | Self::NotApplied { interruption, .. }
            | Self::Refused { interruption, .. }
            | Self::Unknown { interruption, .. } => *interruption,
            Self::Intent { .. } | Self::RetryRefused { .. } => None,
        }
    }
}
/// A small independent registration prefix. Reply bodies remain in the Store.
#[derive(Default)]
pub struct State {
    /// One reference for each actual original accepted source registration.
    pub accepted: Vec<AcceptedRef>,
    /// At most one original unresolved registration.
    pub pending: Option<Pending>,
}
impl State {
    /// Whether a receipt-less intent or Unknown forbids automatic repetition.
    #[must_use]
    pub fn uncertain(&self) -> bool {
        self.pending
            .is_some_and(|p| !matches!(p.disposition, Disposition::Refused { .. }))
    }
    /// Whether a recorded negative peer reply requires an explicit retry choice.
    #[must_use]
    pub fn requires_explicit_retry(&self) -> bool {
        self.pending
            .is_some_and(|p| matches!(p.disposition, Disposition::Refused { .. }))
    }
    pub(super) fn complete(&self, total: usize) -> bool {
        self.pending.is_none() && self.accepted.len() == total
    }
    pub(super) fn check(
        &self,
        event: &Event<'_>,
        total: usize,
        phase: Phase,
    ) -> Result<(), ModelError> {
        match event {
            Event::Intent { index, .. } => {
                if phase != Phase::Running || self.pending.is_some() {
                    return Err(ModelError::Transition);
                }
                if *index != self.accepted.len() || *index >= total {
                    return Err(ModelError::Order);
                }
            }
            Event::RetryRefused { attempt } => {
                self.original(*attempt, total)?;
                if matches!(
                    phase,
                    Phase::CancelRequested | Phase::Cancelled | Phase::Complete
                ) || !matches!(
                    self.pending.map(|p| p.disposition),
                    Some(Disposition::Refused { .. })
                ) {
                    return Err(ModelError::Transition);
                }
            }
            Event::Accepted {
                attempt, response, ..
            }
            | Event::Refused {
                attempt, response, ..
            } => {
                self.original_intent(*attempt, total, phase)?;
                match (event, Response::decode(response)?) {
                    (Event::Accepted { .. }, Response::IndexStarted)
                    | (Event::Refused { .. }, Response::IndexFailed { .. }) => {}
                    _ => return Err(ModelError::Format),
                }
            }
            Event::NotApplied { attempt, .. } | Event::Unknown { attempt, .. } => {
                if matches!(event, Event::NotApplied {reason,..} if *reason != NoEffect::UnexposedRegistration)
                {
                    return Err(ModelError::Format);
                }
                self.original_intent(*attempt, total, phase)?;
                if let Event::Unknown {
                    response: Some(bytes),
                    ..
                } = event
                    && bytes.len() > codec::MAX_RESPONSE_BYTES
                {
                    return Err(ModelError::Limit);
                }
            }
        }
        Ok(())
    }
    pub(super) fn prepare(&mut self, event: &Event<'_>) -> Result<(), ModelError> {
        if matches!(event, Event::Accepted { .. }) {
            self.accepted
                .try_reserve(1)
                .map_err(|_| ModelError::Limit)?;
        }
        Ok(())
    }
    pub(super) fn apply(&mut self, index: usize, event: Event<'_>) -> Result<(), ModelError> {
        match event {
            Event::Intent {
                index: row,
                request_hash,
            } => {
                self.pending = Some(Pending {
                    attempt: Attempt {
                        index: row,
                        request_hash,
                        intent_record: index,
                    },
                    disposition: Disposition::Intent,
                })
            }
            Event::Accepted {
                attempt,
                interruption,
                ..
            } => {
                self.accepted.push(AcceptedRef {
                    attempt,
                    record_index: index,
                    interruption,
                });
                self.pending = None;
            }
            Event::NotApplied { .. } | Event::RetryRefused { .. } => self.pending = None,
            Event::Refused { interruption, .. } => {
                self.pending
                    .as_mut()
                    .ok_or(ModelError::Binding)?
                    .disposition = Disposition::Refused {
                    record_index: index,
                    interruption,
                }
            }
            Event::Unknown { interruption, .. } => {
                self.pending
                    .as_mut()
                    .ok_or(ModelError::Binding)?
                    .disposition = Disposition::Unknown {
                    record_index: index,
                    interruption,
                }
            }
        }
        Ok(())
    }
    fn original(&self, attempt: Attempt, total: usize) -> Result<(), ModelError> {
        if self.pending.is_none_or(|p| p.attempt != attempt)
            || attempt.index != self.accepted.len()
            || attempt.index >= total
        {
            return Err(ModelError::Binding);
        }
        Ok(())
    }
    fn original_intent(
        &self,
        attempt: Attempt,
        total: usize,
        phase: Phase,
    ) -> Result<(), ModelError> {
        self.original(attempt, total)?;
        if !matches!(
            phase,
            Phase::Running
                | Phase::PauseRequested
                | Phase::CancelRequested
                | Phase::Failed
                | Phase::Uncertain
                | Phase::Cancelled
        ) || !matches!(
            self.pending.map(|p| p.disposition),
            Some(Disposition::Intent)
        ) {
            return Err(ModelError::Transition);
        }
        Ok(())
    }
}

const INTENT: u16 = 0x100;
const ACCEPTED: u16 = 0x101;
const NOT_APPLIED: u16 = 0x102;
const REFUSED: u16 = 0x103;
const UNKNOWN: u16 = 0x104;
const RETRY_REFUSED: u16 = 0x105;
pub(super) fn is_kind(kind: u16) -> bool {
    (INTENT..=RETRY_REFUSED).contains(&kind)
}
pub(super) fn encode_event(event: &Event<'_>) -> Result<(u16, Vec<u8>), ModelError> {
    let mut w = codec::Writer(Vec::new());
    w.u16(codec::VERSION)?;
    let kind = match event {
        Event::Intent {
            index,
            request_hash,
        } => {
            w.usize(*index)?;
            w.raw(request_hash)?;
            INTENT
        }
        Event::Accepted {
            attempt,
            response,
            interruption,
        }
        | Event::Refused {
            attempt,
            response,
            interruption,
        } => {
            codec::put_attempt(&mut w, *attempt)?;
            codec::put_interruption(&mut w, *interruption)?;
            w.blob(response, codec::MAX_RESPONSE_BYTES)?;
            if matches!(event, Event::Accepted { .. }) {
                ACCEPTED
            } else {
                REFUSED
            }
        }
        Event::NotApplied {
            attempt,
            reason,
            interruption,
        } => {
            codec::put_attempt(&mut w, *attempt)?;
            w.u8(codec::no_effect_tag(*reason))?;
            codec::put_interruption(&mut w, *interruption)?;
            NOT_APPLIED
        }
        Event::Unknown {
            attempt,
            response,
            interruption,
        } => {
            codec::put_attempt(&mut w, *attempt)?;
            codec::put_interruption(&mut w, *interruption)?;
            w.optional_blob(*response, codec::MAX_RESPONSE_BYTES)?;
            UNKNOWN
        }
        Event::RetryRefused { attempt } => {
            codec::put_attempt(&mut w, *attempt)?;
            RETRY_REFUSED
        }
    };
    Ok((kind, w.0))
}
pub(super) fn decode_event(kind: u16, bytes: &[u8]) -> Result<Event<'_>, ModelError> {
    if bytes.len() > codec::MAX_EVENT_BYTES {
        return Err(ModelError::Limit);
    }
    let mut r = codec::Reader(bytes);
    if r.u16()? != codec::VERSION {
        return Err(ModelError::Version);
    }
    let event = match kind {
        INTENT => Event::Intent {
            index: r.usize()?,
            request_hash: r.array()?,
        },
        ACCEPTED | REFUSED => {
            let attempt = codec::get_attempt(&mut r)?;
            let interruption = codec::get_interruption(&mut r)?;
            let response = r.blob(codec::MAX_RESPONSE_BYTES)?;
            if kind == ACCEPTED {
                Event::Accepted {
                    attempt,
                    response,
                    interruption,
                }
            } else {
                Event::Refused {
                    attempt,
                    response,
                    interruption,
                }
            }
        }
        NOT_APPLIED => Event::NotApplied {
            attempt: codec::get_attempt(&mut r)?,
            reason: codec::get_no_effect(r.u8()?)?,
            interruption: codec::get_interruption(&mut r)?,
        },
        UNKNOWN => Event::Unknown {
            attempt: codec::get_attempt(&mut r)?,
            interruption: codec::get_interruption(&mut r)?,
            response: r.optional_blob(codec::MAX_RESPONSE_BYTES)?,
        },
        RETRY_REFUSED => Event::RetryRefused {
            attempt: codec::get_attempt(&mut r)?,
        },
        _ => return Err(ModelError::Version),
    };
    if !r.0.is_empty() {
        return Err(ModelError::Format);
    }
    Ok(event)
}
/// Borrow the original affirmative FS reply from its actual journal row.
pub(super) fn accepted_view(
    kind: u16,
    bytes: &[u8],
) -> Result<(Attempt, &[u8], Option<Interruption>), ModelError> {
    match decode_event(kind, bytes)? {
        Event::Accepted {
            attempt,
            response,
            interruption,
        } => Ok((attempt, response, interruption)),
        _ => Err(ModelError::Format),
    }
}

#[cfg(test)]
mod tests;
