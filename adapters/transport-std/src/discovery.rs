//! Caller-driven address lookup. Stores supply candidates, never peer authority.
use gnunet_transport::{
    PeerId, Times,
    application::{AddressAdmission, Discovery},
};
use gnunet_types::Error;
use std::num::NonZeroUsize;

/// Whether this candidate was consumed or awaits actual output capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisitControl {
    /// Move past this candidate, including an unsupported communicator prefix.
    Continue,
    /// Retain this candidate's source position for a later original lookup.
    Pause,
}
/// Continuation after a bounded source enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Visit {
    /// Position after all candidates actually consumed.
    pub cursor: usize,
    /// This source's current enumeration ended. Future retries begin a new scan.
    pub finished: bool,
}
/// Read-only candidate source. Its results are untrusted; communicator/peer
/// authentication is still required. An error may follow successful visits.
/// The caller retains the same discovery lease and supervises the original cause.
pub trait AddressSource {
    /// Visit only this peer, with explicit UTC expiry, continuation and work cap.
    /// Pause does not consume the candidate. Avoid blocking native IO here;
    /// asynchronous sources should expose their already-observed candidate state.
    fn visit(
        &mut self,
        peer: PeerId,
        utc: u64,
        start: usize,
        quantum: NonZeroUsize,
        visitor: &mut dyn FnMut(&[u8]) -> Result<VisitControl, Error>,
    ) -> Result<Visit, Error>;
}
/// One bounded address-discovery step, independent of native delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryStep {
    /// No currently due application demand.
    Idle,
    /// Original application canceled or its physical MQ retired.
    Retired,
    /// A source pass completed; no address here is implicitly authenticated.
    Progress {
        /// New communicator create requests admitted.
        issued: usize,
        /// Source scan reached its current end.
        finished: bool,
    },
}
/// Retains the exact original lease across source errors and canceled host calls.
#[derive(Default)]
pub(crate) struct Pending(pub(crate) Option<Discovery>);
impl Pending {
    pub(crate) fn drive_at(
        &mut self,
        engine: &mut gnunet_transport::Engine,
        times: Times,
        source: &mut impl AddressSource,
        quantum: NonZeroUsize,
    ) -> Result<DiscoveryStep, Error> {
        engine.validate_times(times)?;
        if self.0.is_none() {
            self.0 = engine.discovery_at(times)?;
        }
        let Some(original) = &self.0 else {
            return Ok(DiscoveryStep::Idle);
        };
        if !engine.discovery_live(original) {
            self.0 = None;
            return Ok(DiscoveryStep::Retired);
        }
        let mut issued = 0;
        let visit = source.visit(
            original.peer(),
            times.absolute().as_micros(),
            original.cursor(),
            quantum,
            &mut |address| match engine.discovered_address_at(original, address, times) {
                Ok(AddressAdmission::Issued) => {
                    issued += 1;
                    Ok(VisitControl::Continue)
                }
                Ok(
                    AddressAdmission::Existing
                    | AddressAdmission::Unsupported
                    | AddressAdmission::Declined(_),
                ) => Ok(VisitControl::Continue),
                Ok(AddressAdmission::Deferred) => Ok(VisitControl::Pause),
                Err(Error::Malformed | Error::TooLarge) => Ok(VisitControl::Continue),
                Err(error) => Err(error),
            },
        )?;
        engine.discovery_complete_at(original, times, visit.cursor, visit.finished)?;
        self.0 = None;
        Ok(DiscoveryStep::Progress {
            issued,
            finished: visit.finished,
        })
    }
}
