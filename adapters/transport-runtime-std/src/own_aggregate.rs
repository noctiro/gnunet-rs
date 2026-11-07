//! Original purpose7 HELLO signing and cancellation ownership on native PILS.
//!
//! This helper queues official PILS work but does not poll a socket, publish a
//! record, renew a candidate or claim Node readiness. Keep the original owner
//! until its completion is handled and actual native cursor quiescence is known.
use crate::own::ObservedAuthority;
use gnunet_pils::client as pc;
use gnunet_pils_host::client::{Client as NativeClient, Error as NativeError};
use gnunet_transport::own_hello::{HelloCandidate, HelloOfferId};
use gnunet_types::Error;

/// A compact original offer and physical epoch, prepared before admission.
/// Same-key metadata revisions on that same epoch do not replace this offer.
pub struct HelloSignaturePlan<'a> {
    offer: HelloOfferId,
    epoch: pc::Epoch<'a>,
}
impl<'a> HelloSignaturePlan<'a> {
    /// Prepare only a nonempty, still-offered original on this observed authority.
    /// Empty managed withdrawal is already Verified and needs no signature.
    pub fn prepare(
        candidate: &HelloCandidate,
        authority: &ObservedAuthority<'a>,
        identity: pc::Identity<'a>,
    ) -> Result<Self, Error> {
        if !candidate.needs_signature() {
            return Err(Error::NotReady);
        }
        if candidate.authority() != authority.pure() || !authority.compatible(identity) {
            return Err(Error::Stale);
        }
        if candidate.peer() != identity.peer() {
            return Err(Error::Authentication);
        }
        Ok(Self {
            offer: candidate.id().clone(),
            epoch: identity.epoch(),
        })
    }
    /// Original aggregate offer; neither a wire RID nor a later same-set refresh.
    pub fn offer(&self) -> &HelloOfferId {
        &self.offer
    }
    /// Recheck the actual native client's current identity, then admit and claim
    /// synchronously before any driver poll can run. Builder errors and actual
    /// NativeError values remain distinct until returned in the refused owner.
    /// No Box or other allocation occurs here after native admission succeeds.
    pub fn admit<const O: usize>(
        self,
        candidate: &mut HelloCandidate,
        client: &mut NativeClient<'a, O>,
        scratch: &mut [u8],
    ) -> HelloSignatureAdmission<'a> {
        if candidate.id() != &self.offer
            || candidate.authority() != self.offer.authority()
            || !candidate.needs_signature()
        {
            return HelloSignatureAdmission::RefusedPlan {
                original: self,
                cause: Error::Stale.into(),
            };
        }
        let Some(identity) = client.identity().filter(|identity| {
            identity.epoch() == self.epoch && identity.peer() == self.offer.authority().peer()
        }) else {
            return HelloSignatureAdmission::RefusedPlan {
                original: self,
                cause: Error::Stale.into(),
            };
        };
        let expiry = candidate.expiry();
        // The outer Result belongs to the pure builder. Its closure returns the
        // native Result as its value, preserving any actual OS/configuration
        // error rather than reducing it to a gnunet_types::Error.
        let operation = match candidate.with_builder(scratch, |builder| {
            Ok(client.sign_hello(builder, expiry, pc::KeyTarget::Exact(identity)))
        }) {
            Ok(Ok(operation)) => operation,
            Ok(Err(cause)) => {
                return HelloSignatureAdmission::RefusedPlan {
                    original: self,
                    cause,
                };
            }
            Err(cause) => {
                return HelloSignatureAdmission::RefusedPlan {
                    original: self,
                    cause: cause.into(),
                };
            }
        };
        let mut original = OriginalHelloSignature {
            plan: self,
            operation,
            pure_admitted: false,
            retiring: false,
            applied: false,
            failure: None,
        };
        match candidate.signing_admitted(&original.plan.offer) {
            Ok(()) => {
                original.pure_admitted = true;
                HelloSignatureAdmission::Queued(original)
            }
            Err(cause) => {
                original.retiring = true;
                HelloSignatureAdmission::RetireAdmitted { original, cause }
            }
        }
    }
}

/// No-op refusal and admitted-operation retirement have different original owners.
#[must_use = "Retain the refused plan or admitted operation until explicit disposition."]
pub enum HelloSignatureAdmission<'a> {
    /// Both actual native operation and original pure Issued state were admitted.
    Queued(OriginalHelloSignature<'a>),
    /// No native operation exists; the unchanged plan can be retained or retired.
    RefusedPlan {
        /// Original offer and physical target, not reconstructed from a wire RID.
        original: HelloSignaturePlan<'a>,
        /// Original builder/native refusal, including actual OS errors.
        cause: NativeError,
    },
    /// Native admission succeeded; cancel/drain this operation even though the
    /// subsequent pure claim unexpectedly refused. No admitted owner is erased.
    RetireAdmitted {
        /// Actual original native operation requiring retirement.
        original: OriginalHelloSignature<'a>,
        /// Original post-admission pure claim refusal.
        cause: Error,
    },
}

/// One exact admitted operation and pure offer, not a reused numeric request id.
#[must_use = "Keep this original until its result and native cursor disposition are known."]
pub struct OriginalHelloSignature<'a> {
    plan: HelloSignaturePlan<'a>,
    operation: pc::OperationId<'a>,
    pure_admitted: bool,
    retiring: bool,
    applied: bool,
    failure: Option<pc::Failure>,
}
/// Result handling does not consume the caller's original completion event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "A pending original retirement still requires the native owner to be driven."]
pub enum HelloSignatureResult {
    /// Original purpose7 signature was verified and the common HELLO is staged.
    /// This alone does not assert physical native-output quiescence or storage.
    Verified,
    /// Original intent is retired and its actual native operation is quiescent.
    Retired,
    /// Actual original service failure, after native cursor retirement.
    Failed {
        /// Original actual failure; retry pacing belongs to the publisher owner.
        reason: pc::Failure,
    },
    /// Original intent is retired, but copied/native work still needs to drain.
    RetirementPending {
        /// Original service failure if one was observed before physical retirement.
        reason: Option<pc::Failure>,
    },
}
impl<'a> OriginalHelloSignature<'a> {
    /// Actual original operation, never an interchangeable u32 wire RID.
    pub fn operation(&self) -> pc::OperationId<'a> {
        self.operation
    }
    /// Exact pure aggregate offer retained across cancellation or context loss.
    pub fn offer(&self) -> &HelloOfferId {
        &self.plan.offer
    }
    /// Original service failure retained while a native cursor still drains.
    /// Native I/O/configuration errors remain owned by the returned NativeError.
    pub fn service_failure(&self) -> Option<pc::Failure> {
        self.failure
    }
    /// Current key metadata may differ only on the same original physical epoch.
    pub fn context_is_current(&self, current: Option<pc::Identity<'a>>) -> bool {
        current.is_some_and(|identity| {
            identity.epoch() == self.plan.epoch
                && identity.peer() == self.plan.offer.authority().peer()
        })
    }
    fn check_candidate(&self, candidate: &HelloCandidate) -> Result<(), Error> {
        if candidate.id() != &self.plan.offer
            || candidate.authority() != self.plan.offer.authority()
            || candidate.peer() != self.plan.offer.authority().peer()
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Exact original quiescence includes core logical work, copied lease and
    /// native output. This can still be needed after a Verified result.
    pub fn operation_quiescent<const O: usize>(
        &self,
        client: &NativeClient<'a, O>,
    ) -> Result<bool, NativeError> {
        client.operation_quiescent(self.operation)
    }
    /// Retire original intent and make one logical cancellation attempt. Keep this
    /// owner even when cancellation returns an actual error. A repeated explicit
    /// request can return Stale; no such error is silently treated as quiescence.
    pub fn request_cancel<const O: usize>(
        &mut self,
        candidate: &mut HelloCandidate,
        client: &mut NativeClient<'a, O>,
    ) -> Result<(), NativeError> {
        self.check_candidate(candidate)?;
        if self.applied {
            return Err(Error::Stale.into());
        }
        candidate.retire();
        self.retiring = true;
        client.cancel(self.operation)
    }
    /// Request retirement and finish it only after the actual native owner
    /// reports no logical, copied or native-output work. An already closed
    /// physical client can therefore settle without an invalid cancel call. Cancel Ok
    /// alone never permits the pure signing_retired transition.
    pub fn finish_retirement<const O: usize>(
        &mut self,
        candidate: &mut HelloCandidate,
        client: &NativeClient<'a, O>,
    ) -> Result<bool, NativeError> {
        self.check_candidate(candidate)?;
        if self.applied {
            return Err(Error::Stale.into());
        }
        candidate.retire();
        self.retiring = true;
        if !client.operation_quiescent(self.operation)? {
            return Ok(false);
        }
        if self.pure_admitted {
            candidate.signing_retired(&self.plan.offer)?;
            self.pure_admitted = false;
        }
        self.applied = true;
        Ok(true)
    }
    fn retirement_result<const O: usize>(
        &mut self,
        candidate: &mut HelloCandidate,
        client: &NativeClient<'a, O>,
    ) -> Result<HelloSignatureResult, NativeError> {
        if self.finish_retirement(candidate, client)? {
            Ok(match self.failure {
                Some(reason) => HelloSignatureResult::Failed { reason },
                None => HelloSignatureResult::Retired,
            })
        } else {
            Ok(HelloSignatureResult::RetirementPending {
                reason: self.failure,
            })
        }
    }
    /// Borrow only this exact actual completion. A foreign operation is refused
    /// before candidate state changes. Context loss first retires original intent;
    /// no later same-peer/new-MQ identity may adopt that old signature.
    /// Insufficient common scratch leaves the original completion retryable.
    pub fn apply<const O: usize>(
        &mut self,
        candidate: &mut HelloCandidate,
        completion: &pc::Completion<'a>,
        client: &NativeClient<'a, O>,
        scratch: &mut [u8],
    ) -> Result<HelloSignatureResult, NativeError> {
        self.check_candidate(candidate)?;
        if self.applied || !self.pure_admitted || completion.operation() != self.operation {
            return Err(Error::Stale.into());
        }
        if !self.context_is_current(client.identity()) {
            candidate.retire();
            self.retiring = true;
        }
        match completion {
            pc::Completion::Signature {
                peer, signature, ..
            } => {
                if *peer != self.plan.offer.authority().peer() {
                    return Err(Error::Authentication.into());
                }
                if self.retiring {
                    peer.verify(7, candidate.signed_region(), signature)?;
                    return self.retirement_result(candidate, client);
                }
                if candidate.signed(&self.plan.offer, *peer, *signature, scratch)? {
                    self.pure_admitted = false;
                    self.applied = true;
                    Ok(HelloSignatureResult::Verified)
                } else {
                    // A caller may have retired this same original intent before
                    // its already-verified completion arrived. signed() finished
                    // that pure state; still wait for the actual native cursor.
                    self.pure_admitted = false;
                    self.retiring = true;
                    self.retirement_result(candidate, client)
                }
            }
            pc::Completion::Failed {
                kind: pc::OperationKind::Sign,
                reason,
                ..
            } => {
                self.failure.get_or_insert(*reason);
                candidate.retire();
                self.retiring = true;
                self.retirement_result(candidate, client)
            }
            _ => Err(Error::Malformed.into()),
        }
    }
}
