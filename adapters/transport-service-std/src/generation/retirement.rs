//! Original reservation retirement after an identity or service admission fence.
//! A committed old interval is consumed history.
use super::{self as generation, Reservations};
use crate::SharedFailure;
use gnunet_pils::client::Identity;
use gnunet_transport::{addresses::AddressLease, monotime::Demand};
use gnunet_types::Error;
use std::task::{Context, Poll};
/// Exact original own-address stamp, retained only as retired provenance.
pub struct RetiredStamp<'id> {
    identity: Identity<'id>,
    lease: AddressLease,
    request: generation::Request,
}
impl<'id> RetiredStamp<'id> {
    pub(crate) fn from_original(
        identity: Identity<'id>,
        lease: AddressLease,
        request: generation::Request,
    ) -> Self {
        Self {
            identity,
            lease,
            request,
        }
    }
    /// Original actual source, never replacement authority.
    pub fn identity(&self) -> Identity<'id> {
        self.identity
    }
    /// Original address ownership of this request.
    pub fn lease(&self) -> &AddressLease {
        &self.lease
    }
    /// Original actual worker job and fixed targets.
    pub fn request(&self) -> &generation::Request {
        &self.request
    }
}
/// Original range consumer provenance. No value here proves durable completion.
pub enum RangeOrigin<'id> {
    /// Exact original Engine demand, including its allocation brand.
    Flow(Demand),
    /// Caller-owned DV scheduler retains its additional original actor binding.
    Dv(crate::sender::DvScope<'id>),
}
/// Original FLOW/DV job after retirement of its authority.
pub struct RetiredRange<'id> {
    identity: Identity<'id>,
    origin: RangeOrigin<'id>,
    request: generation::Request,
}
impl<'id> RetiredRange<'id> {
    pub(crate) fn flow(
        identity: Identity<'id>,
        demand: Demand,
        request: generation::Request,
    ) -> Self {
        Self {
            identity,
            origin: RangeOrigin::Flow(demand),
            request,
        }
    }
    pub(crate) fn dv(original: crate::sender::DvReservation<'id>) -> Self {
        Self {
            identity: original.identity(),
            request: original.request().clone(),
            origin: RangeOrigin::Dv(original.scope().clone()),
        }
    }
    /// Original actual public source, usable here only as historical metadata.
    pub fn identity(&self) -> Identity<'id> {
        self.identity
    }
    /// Exact original range purpose and consumer provenance.
    pub fn origin(&self) -> &RangeOrigin<'id> {
        &self.origin
    }
    /// Actual original worker job; unchanged while retirement waits for IO.
    pub fn request(&self) -> &generation::Request {
        &self.request
    }
}
/// Exactly one pending actual operation can own the shared single worker.
pub enum RetiredReservation<'id> {
    /// One own-address stamp.
    Stamp(RetiredStamp<'id>),
    /// One independent exclusive FLOW or DV range.
    Range(RetiredRange<'id>),
}
impl RetiredReservation<'_> {
    /// Original actual worker identity, purpose and targets.
    pub fn request(&self) -> &generation::Request {
        match self {
            Self::Stamp(r) => r.request(),
            Self::Range(r) => r.request(),
        }
    }
}
/// Actual result of retiring one original operation. Deadline expiry cannot
/// cancel fsync/rename or recover consumed values, including unused range tail.
pub enum ReservationOutcome<'id> {
    /// No actually admitted reservation remained.
    None,
    /// Genuine original single stamp completion, preserved as old history.
    StampCommitted {
        /// Original retired address, identity and worker request.
        original: RetiredStamp<'id>,
        /// Matching actual durable stamp, retained only as old history.
        actual: generation::CommittedReservation,
    },
    /// Genuine original range completion, whose entire interval is burnt.
    RangeBurned {
        /// Original retired Engine/source range request and purpose.
        original: RetiredRange<'id>,
        /// Genuine consumed interval; it cannot authorize a replacement.
        actual: generation::CommittedRange,
    },
    /// Actual original worker/storage failure, retaining exposure/cleanup facts.
    Failed {
        /// Original stamp or range whose actual worker failed.
        original: RetiredReservation<'id>,
        /// Shared original storage failure, not a synthetic cancellation.
        error: SharedFailure,
    },
    /// Genuine unrelated receipt; never rebound to either old or new owner.
    Mismatched {
        /// Original retained operation expected by this drain.
        original: RetiredReservation<'id>,
        /// Genuine unrelated result, preserved without rebinding.
        actual: generation::Completion,
    },
}
/// At most one original actual disk drain. No IO admission/clock/key operation
/// occurs here; Pending retains exactly the same original request.
pub struct Drain<'id> {
    original: Option<RetiredReservation<'id>>,
    finished: bool,
}
impl<'id> Drain<'id> {
    pub(crate) fn new(original: Option<RetiredReservation<'id>>) -> Self {
        Self {
            original,
            finished: false,
        }
    }
    /// True only after delivering this drain's actual terminal outcome once.
    pub fn finished(&self) -> bool {
        self.finished
    }
    /// Original retained historical provenance, never a replacement capability.
    pub fn original(&self) -> Option<&RetiredReservation<'id>> {
        self.original.as_ref()
    }
    /// Settle the original worker's operation before replacement admission.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        reservations: &mut Reservations,
    ) -> Poll<Result<ReservationOutcome<'id>, Error>> {
        if self.finished {
            return Poll::Ready(Err(Error::Stale));
        }
        if self.original.is_none() {
            self.finished = true;
            return Poll::Ready(Ok(ReservationOutcome::None));
        }
        match reservations.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(Some(actual))) => {
                self.finished = true;
                let original = self.original.take().ok_or(Error::Stale)?;
                if actual.request() != original.request() {
                    return Poll::Ready(Ok(ReservationOutcome::Mismatched { original, actual }));
                }
                Poll::Ready(Ok(match (original, actual) {
                    (
                        RetiredReservation::Stamp(original),
                        generation::Completion::Stamp(actual),
                    ) => ReservationOutcome::StampCommitted { original, actual },
                    (
                        RetiredReservation::Range(original),
                        generation::Completion::Range(actual),
                    ) => ReservationOutcome::RangeBurned { original, actual },
                    (original, actual) => ReservationOutcome::Mismatched { original, actual },
                }))
            }
            Poll::Ready(Err(error)) => {
                self.finished = true;
                let original = self.original.take().ok_or(Error::Stale)?;
                Poll::Ready(Ok(ReservationOutcome::Failed {
                    original,
                    error: SharedFailure::new(Box::new(error)),
                }))
            }
            Poll::Ready(Ok(None)) => {
                self.finished = true;
                Poll::Ready(Err(Error::OutcomeUnknown))
            }
        }
    }
}
