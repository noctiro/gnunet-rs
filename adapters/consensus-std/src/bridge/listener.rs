//! Original SET listener offers, rejection writes and source retirement.
use super::{Bridge, Offer, OfferState, cause, classify, pressure};
use crate::{
    Error, Progress,
    core::{self, Action, Completion, EffectId, OfferId},
};
use gnunet_set_client_host as set;
use gnunet_types::Error as Fault;
use gnunet_wire::official::consensus::RoundContext;
use std::task::{Context, Poll};
#[cfg(test)]
mod tests;

fn settle_rejection<'id>(
    core: &mut core::Session<'id>,
    offers: &mut Vec<Offer<'id>>,
    terminal: &mut Option<core::Terminal<'id>>,
    event: &set::ListenProgress,
) -> Result<(), Error> {
    let set::ListenProgress::Written {
        epoch,
        rejected: Some(rejected),
        complete: true,
        ..
    } = event
    else {
        return Ok(());
    };
    let Some(effect) = core.effect() else {
        return Ok(());
    };
    let Action::RejectOffer { offer } = effect.action else {
        return Ok(());
    };
    let Some(at) = offers.iter().position(|row| row.id == offer) else {
        return Ok(());
    };
    if !matches!(&offers[at].state, OfferState::Rejecting(id) if id.matches(epoch, *rejected)) {
        return Ok(());
    }
    if terminal.is_some() {
        return Err(Fault::WouldBlock.into());
    }
    // The exact whole Reject write retires this original native offer. Keep
    // its separate Written event; cleanup settlement is not a semantic ACK.
    let completed = core.complete_effect(effect.id, Completion::Retired)?;
    offers.swap_remove(at);
    *terminal = Some(completed);
    Ok(())
}

impl<'id> Bridge<'id, '_> {
    pub(super) fn listener_close(&mut self) {
        if let Some(mut listener) = self.listener.take() {
            self.listener_event = Some(set::ListenProgress::Lost(listener.close()));
        }
        self.offers.clear();
    }
    pub(super) fn reject_offer(
        &mut self,
        effect: EffectId<'id>,
        offer: OfferId<'id>,
    ) -> Result<Option<Progress<'id>>, Error> {
        let Some(listener) = &mut self.listener else {
            // Only retirement of the original listener can discharge an
            // unwritten rejection without a corresponding whole-write fact.
            if let Some(at) = self.offers.iter().position(|row| row.id == offer) {
                self.offers.swap_remove(at);
            }
            self.settle(effect, Completion::Retired)?;
            return Ok(Some(Progress::Activity));
        };
        let at = self
            .offers
            .iter()
            .position(|row| row.id == offer)
            .ok_or(Fault::StaleGeneration)?;
        if matches!(self.offers[at].state, OfferState::Rejecting(_)) {
            return Ok(None);
        }
        let OfferState::Prepared(prepared) =
            std::mem::replace(&mut self.offers[at].state, OfferState::Committing)
        else {
            return Err(Fault::NotReady.into());
        };
        match listener.reject_prepared(prepared) {
            Ok(rejection) => {
                self.offers[at].state = OfferState::Rejecting(rejection);
                Ok(Some(Progress::Activity))
            }
            Err(failure) => {
                self.offers[at].state = OfferState::Prepared(failure.prepared);
                if pressure(&failure.error) {
                    return Ok(None);
                }
                let why = classify(&failure.error);
                self.listener_close();
                self.cancel(why)?;
                self.fault = Some(failure.error.into());
                Ok(Some(Progress::Activity))
            }
        }
    }
    pub(super) fn listen(&mut self, cx: &mut Context<'_>) -> Result<Option<Progress<'id>>, Error> {
        if self.listener.is_none() {
            return Ok(None);
        }
        if !self.core.listener_live()
            && self
                .core
                .effect()
                .is_none_or(|e| !matches!(e.action, Action::Listen { .. }))
        {
            self.listener_close();
            return Ok(Some(Progress::Activity));
        }
        let free = self.free()?;
        let max = self.limits.core.offers;
        let core = &mut self.core;
        let offers = &mut self.offers;
        let mut accepted = None;
        let mut rejected = None;
        let step = self
            .listener
            .as_mut()
            .ok_or(Fault::NotReady)?
            .poll_progress(cx, &mut |incoming| {
                let decide = (|| -> Result<(OfferId<'id>, RoundContext), Fault> {
                    let context = RoundContext::decode(incoming.context)?;
                    Self::reserve(offers, max, free).map_err(|e| match e {
                        Error::Protocol(e) => e,
                        Error::Set(_) | Error::Native(_) | Error::Io(_) => Fault::Capacity,
                    })?;
                    let id = core.offer(incoming.peer, context, self.last_now)?;
                    Ok((id, context))
                })();
                match decide {
                    Ok((id, context)) => {
                        accepted = Some((id, incoming.epoch.clone(), incoming.peer, context));
                        set::Decision::Accept {
                            mode: set::ResultMode::Symmetric,
                            options: Action::RECONCILIATION_OPTIONS,
                        }
                    }
                    Err(error) => {
                        rejected = Some((incoming.peer, error));
                        set::Decision::Reject
                    }
                }
            });
        if let Some(rejected) = rejected {
            self.rejection = Some(rejected);
        }
        let event = match step {
            Poll::Pending => return Ok(None),
            Poll::Ready(Ok(event)) => event,
            Poll::Ready(Err(e)) => {
                self.listener_close();
                self.cancel(classify(&e))?;
                return Ok(Some(Progress::Fault(e.into())));
            }
        };
        match event {
            set::ListenProgress::Accepted(prepared) => {
                let (id, epoch, peer, context) = accepted.ok_or(Fault::StaleGeneration)?;
                self.offers.push(Offer {
                    id,
                    state: OfferState::Prepared(prepared),
                });
                Ok(Some(Progress::Offer {
                    offer: id,
                    epoch,
                    peer,
                    context,
                }))
            }
            event @ set::ListenProgress::Written {
                rejected: Some(_), ..
            } => {
                settle_rejection(&mut self.core, &mut self.offers, &mut self.terminal, &event)?;
                Ok(Some(Progress::Listener(event)))
            }
            event @ set::ListenProgress::Written {
                complete: true,
                rejected: None,
                ..
            } => {
                if let Some(effect) = self.core.effect()
                    && matches!(effect.action, Action::Listen { .. })
                {
                    self.settle(effect.id, Completion::Written)?;
                }
                Ok(Some(Progress::Listener(event)))
            }
            set::ListenProgress::Lost(loss) => {
                if let Some(effect) = self.core.effect()
                    && matches!(effect.action, Action::Listen { .. })
                {
                    let completion = if loss.transport.initializer_written {
                        Completion::Written
                    } else if loss.transport.initializer_bytes == 0 {
                        Completion::Unsent(cause(&loss.cause))
                    } else {
                        Completion::Lost(cause(&loss.cause))
                    };
                    self.settle(effect.id, completion)?;
                }
                let why = cause(&loss.cause);
                self.listener_close();
                self.cancel(why)?;
                Ok(Some(Progress::Listener(set::ListenProgress::Lost(loss))))
            }
            other => Ok(Some(Progress::Listener(other))),
        }
    }
}
