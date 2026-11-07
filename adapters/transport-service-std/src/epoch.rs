//! Original public reservation retirement during real service epoch rebuild.
//! Physical IPC retirement precedes this mandatory disk drain. A committed old
//! interval is burnt history only; it is never installed into a new Engine.
use crate::generation::{self, Reservations};
use gnunet_pils::client::Identity;
use gnunet_transport::{addresses::AddressLease, monotime::Demand};
use gnunet_types::Error;
use std::task::{Context, Poll};
/// One real error shared by the original observer and terminal failure.
#[derive(Clone, Debug)]
pub struct SharedFailure(std::rc::Rc<dyn std::error::Error>);
impl SharedFailure {
    pub(crate) fn new(error: crate::Failure) -> Self {
        Self(std::rc::Rc::from(error))
    }
    /// Share the same original cause without manufacturing another result.
    pub fn boxed(&self) -> crate::Failure {
        Box::new(self.clone())
    }
}
impl std::fmt::Display for SharedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), f)
    }
}
impl std::error::Error for SharedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
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
    /// Original closed Engine/address allocation.
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
/// Original FLOW/DV job after its source/Engine physically retired.
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
    pub(crate) fn after_physical_retirement(original: Option<RetiredReservation<'id>>) -> Self {
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
    /// Settle the same original worker before a replacement Owner is allocated.
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
/// Finite reconstitution barrier. Old URI bytes are comparison metadata only;
/// they never create a new ADD lease, signer authority or a wire FEED payload.
pub(crate) struct Recovery {
    expected: Vec<u8>,
    revision: Option<gnunet_transport::addresses::PublicationId>,
    quiet_at: Option<tokio::time::Instant>,
    until: tokio::time::Instant,
    quiet: std::time::Duration,
    window: std::time::Duration,
    observed_actual: bool,
}
impl Recovery {
    pub(crate) fn capture(
        server: &gnunet_transport_host::Server,
        maximum: usize,
        window: std::time::Duration,
        quiet: std::time::Duration,
    ) -> Result<Self, Error> {
        let mut expected = Vec::new();
        expected
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        for uri in server.address_snapshot()?.uris() {
            if expected
                .len()
                .checked_add(uri.len())
                .and_then(|n| n.checked_add(1))
                .is_none_or(|n| n > maximum)
            {
                return Err(Error::Capacity);
            }
            expected.extend_from_slice(uri);
            expected.push(0);
        }
        let until = tokio::time::Instant::now()
            .checked_add(window)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            expected,
            revision: None,
            quiet_at: None,
            until,
            quiet,
            window,
            observed_actual: false,
        })
    }
    /// A distinct new Engine allocation starts one finite reconstruction
    /// window; it does not renew any old source/job/native/record target.
    pub(crate) fn start(&mut self) -> Result<(), Error> {
        self.until = tokio::time::Instant::now()
            .checked_add(self.window)
            .ok_or(Error::Overflow)?;
        self.quiet_at = None;
        self.revision = None;
        self.observed_actual = false;
        Ok(())
    }
    pub(crate) fn ready(&mut self, server: &gnunet_transport_host::Server) -> Result<bool, Error> {
        let view = server.address_snapshot()?;
        if self.revision.as_ref() != Some(view.id()) {
            self.revision = Some(view.id().clone());
            self.quiet_at = Some(
                tokio::time::Instant::now()
                    .checked_add(self.quiet)
                    .ok_or(Error::Overflow)?
                    .min(self.until),
            );
        }
        let actual_count = view.uris().count();
        self.observed_actual |= actual_count != 0;
        let expected_count = self
            .expected
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .count();
        let exact = actual_count == expected_count
            && self
                .expected
                .split(|b| *b == 0)
                .filter(|b| !b.is_empty())
                .all(|uri| view.uris().any(|a| a == uri));
        // Until an actual ADD/DEL revision exists, do not send an empty reset
        // just because the new book starts empty. Later real changes still
        // publish their actual set under the finite stabilization policy.
        let now = tokio::time::Instant::now();
        let ready = exact
            || (self.observed_actual
                && (now >= self.until || self.quiet_at.is_some_and(|at| at <= now)));
        if !ready && now >= self.until {
            // No communicator reconstructed any original address. Retire this
            // finite recovery attempt instead of waiting forever or granting
            // the empty allocation authority to replace the old public HELLO.
            return Err(Error::Deadline);
        }
        Ok(ready)
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use gnunet_crypto::Entropy;
    use gnunet_transport::{Engine, Limits, PeerId, Signer};
    use gnunet_transport_host::Server;
    use gnunet_wire::official::communicator::{Characteristics, Request};
    use std::time::Duration;

    struct UnusedCrypto;
    impl Signer for UnusedCrypto {
        fn identity(&self) -> PeerId {
            PeerId([1; 32])
        }
        fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Error> {
            Err(Error::PermissionDenied)
        }
    }
    impl Entropy for UnusedCrypto {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
            Err(Error::Entropy)
        }
    }

    fn server(address: Option<&[u8]>) -> Result<Server, Error> {
        let mut engine = Engine::new(PeerId([1; 32]), Limits::default())?;
        if let Some(address) = address {
            let client = engine.accept()?;
            for request in [
                Request::Register {
                    characteristics: Characteristics::Reliable,
                    can_burst: false,
                    prefix: b"unix",
                },
                Request::AddAddress {
                    id: 1,
                    validity: 60_000_000,
                    network: 1,
                    address,
                },
            ] {
                let mut frame = vec![0; request.encoded_len()?];
                request.encode(&mut frame)?;
                engine.receive(&client, &frame, 1, &mut UnusedCrypto, &mut UnusedCrypto)?;
            }
        }
        Server::new(engine, 2, 65535)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Real address-book and fixed recovery-bound assertions with fallible setup"
    )]
    fn absent_communicator_expires_original_recovery_without_empty_publication()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let old = server(Some(b"unix-/private/recovery-original"))?;
                let current = server(None)?;
                let mut recovery = Recovery::capture(
                    &old,
                    4096,
                    Duration::from_millis(5),
                    Duration::from_millis(1),
                )?;
                recovery.start()?;
                let original = recovery.until;
                assert!(!recovery.ready(&current)?);
                assert!(!recovery.ready(&current)?);
                assert_eq!(recovery.until, original);
                tokio::time::sleep_until(original).await;
                assert_eq!(recovery.ready(&current), Err(Error::Deadline));
                assert_eq!(recovery.until, original);
                assert!(current.address_publication()?.is_none());
                assert_eq!(current.address_snapshot()?.uris().count(), 0);

                // An actually empty previous set needs no reconstruction and
                // does not acquire a fake ADD or dirty publication either.
                let mut empty = Recovery::capture(
                    &current,
                    4096,
                    Duration::from_secs(1),
                    Duration::from_millis(1),
                )?;
                empty.start()?;
                assert!(empty.ready(&current)?);
                assert!(current.address_publication()?.is_none());
                Ok(())
            })
    }
}
