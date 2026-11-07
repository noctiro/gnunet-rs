//! Actual original FLOW range admission and receipt ownership. No stored value
//! is a key or wire receipt. This module never polls the shared worker itself.
use crate::{
    generation::{self, Purpose, Reservations},
    time::{Bounds, Clock},
};
use gnunet_pils::client::Identity;
use gnunet_transport::{Times, monotime::Demand};
use gnunet_transport_host::Server;
use gnunet_types::Error;
use std::{future::Future, pin::Pin, task::Context, time::Duration};
use tokio::time::{Instant, Sleep};
/// Opaque allocation identity of one actual Engine under its original PILS
/// source. Returning to the same peer on the same MQ never reuses this brand.
#[derive(Clone)]
pub struct DvScope<'id> {
    engine: std::sync::Arc<()>,
    identity: Identity<'id>,
    generation: u64,
}
impl<'id> DvScope<'id> {
    pub(crate) fn allocated(identity: Identity<'id>, generation: u64) -> Self {
        Self {
            engine: std::sync::Arc::new(()),
            identity,
            generation,
        }
    }
    /// Original actual source observation, retained as provenance only.
    pub fn identity(&self) -> Identity<'id> {
        self.identity
    }
    /// Checked allocation sequence; equality also checks the private brand.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}
impl PartialEq for DvScope<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.engine, &other.engine)
    }
}
impl Eq for DvScope<'_> {}
impl std::fmt::Debug for DvScope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TransportDvScope")
            .field(&self.generation)
            .finish()
    }
}
/// Actual original DV reservation admission under one observed PILS/Engine.
/// The constructor is private; a receipt matches its real original Request.
pub struct DvReservation<'id> {
    scope: DvScope<'id>,
    request: generation::Request,
}
impl<'id> DvReservation<'id> {
    pub(crate) fn admitted(scope: DvScope<'id>, request: generation::Request) -> Self {
        Self { scope, request }
    }
    /// Original actual source observation; never a replacement source token.
    pub fn identity(&self) -> Identity<'id> {
        self.scope.identity()
    }
    /// Original Engine brand; peer bytes or a local integer cannot replace it.
    pub fn scope(&self) -> &DvScope<'id> {
        &self.scope
    }
    /// Original actual single-worker request with unchanged deadlines.
    pub fn request(&self) -> &generation::Request {
        &self.request
    }
}
/// Actual FLOW range result, preserving even unusable genuine receipts.
pub enum Outcome<'id> {
    /// Original matching durable result was installed in its original Engine.
    Installed {
        /// Original observed PILS identity for this Engine.
        identity: Identity<'id>,
        /// Original Engine-branded demand and unchanged targets.
        demand: Demand,
        /// Actual matching durable interval installed in that Engine.
        actual: generation::CommittedRange,
    },
    /// Actual interval was consumed durably but could not authorize output.
    Burned {
        /// Original observed identity; no replacement source is authorized.
        identity: Identity<'id>,
        /// Original demand that could no longer consume its result.
        demand: Demand,
        /// Actual durably consumed interval, retained as history only.
        actual: generation::CommittedRange,
    },
    /// Original fixed targets expired before any worker admission.
    NotAdmitted {
        /// Original observed identity at demand creation.
        identity: Identity<'id>,
        /// Expired original demand for which no disk job was admitted.
        demand: Demand,
    },
}
struct Intent<'id> {
    identity: Identity<'id>,
    demand: Demand,
    bounds: Bounds,
    request: Option<generation::Request>,
    retiring: bool,
}
pub(crate) struct Sender<'id> {
    intent: Option<Intent<'id>>,
    horizon: Duration,
    alarm: Option<Pin<Box<Sleep>>>,
}
impl<'id> Sender<'id> {
    pub(crate) fn new(horizon: Duration) -> Self {
        Self {
            intent: None,
            horizon,
            alarm: None,
        }
    }
    /// Register/check the original native bound before canonical clock wait.
    /// Expiry never cancels/requeues an already admitted actual disk job.
    pub(crate) fn native_guard(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(intent) = &mut self.intent else {
            return false;
        };
        if intent.retiring {
            return false;
        }
        if Instant::now() >= intent.bounds.hard {
            intent.retiring = true;
            self.alarm = None;
            return true;
        }
        if self.alarm.is_none() {
            self.alarm = Some(Box::pin(tokio::time::sleep_until(intent.bounds.hard)));
        }
        if let Some(alarm) = &mut self.alarm {
            let _ready = alarm.as_mut().poll(cx);
        }
        false
    }
    pub(crate) fn advance(
        &mut self,
        server: &mut Server,
        identity: Identity<'id>,
        clock: &mut Clock,
        reservations: &mut Reservations,
        times: Times,
    ) -> Result<(bool, Option<Outcome<'id>>), crate::Failure> {
        let mut changed = false;
        if let Some(intent) = &mut self.intent {
            let matches = server
                .monotime_demand()
                .is_some_and(|d| d.id() == intent.demand.id());
            if !matches
                || identity.epoch() != intent.identity.epoch()
                || identity.peer() != intent.identity.peer()
                || !intent.bounds.live(times.absolute().as_micros())
                || !intent.demand.live(times)
            {
                intent.retiring = true;
            }
            if intent.retiring && intent.request.is_none() {
                let old = self.intent.take().ok_or(Error::Stale)?;
                self.alarm = None;
                if server
                    .monotime_demand()
                    .is_some_and(|d| d.id() == old.demand.id())
                {
                    server.retire_monotime(old.demand.id())?;
                }
                return Ok((
                    true,
                    Some(Outcome::NotAdmitted {
                        identity: old.identity,
                        demand: old.demand,
                    }),
                ));
            }
        }
        if self.intent.is_none() {
            let Some(demand) = server.monotime_demand().cloned() else {
                return Ok((changed, None));
            };
            let bounds = Bounds {
                expires: demand.expires().as_micros(),
                hard: clock.native_bound(demand.until())?,
            };
            self.intent = Some(Intent {
                identity,
                demand,
                bounds,
                request: None,
                retiring: false,
            });
            changed = true;
        }
        let intent = self.intent.as_mut().ok_or(Error::Stale)?;
        if !intent.retiring && intent.request.is_none() && reservations.is_idle() {
            // Other native ports may have run after the early guard. Check
            // the original hard bound again before invoking a logical port.
            if Instant::now() >= intent.bounds.hard {
                intent.retiring = true;
                self.alarm = None;
                return Ok((true, None));
            }
            // Use a fresh actual observation at this admission boundary. Any
            // correction while other native ports ran changes first/expiry
            // checks, never this original demand's already captured targets.
            let admission = clock.sample()?;
            if identity.expiration() <= admission.absolute() {
                return Err(Error::Deadline.into());
            }
            if !intent.bounds.live(admission.absolute().as_micros())
                || !intent.demand.live(admission)
            {
                intent.retiring = true;
            } else {
                intent.request = Some(reservations.request_range(
                    Purpose::Flow,
                    admission.absolute().as_micros(),
                    self.horizon,
                    intent.bounds.expires,
                    intent.bounds.hard,
                )?);
                changed = true;
            }
        }
        Ok((changed, None))
    }
    pub(crate) fn complete(
        &mut self,
        actual: generation::CommittedRange,
        server: &mut Server,
        identity: Identity<'id>,
        times: Times,
    ) -> Result<Outcome<'id>, crate::Failure> {
        let intent = self.intent.take().ok_or(Error::Stale)?;
        self.alarm = None;
        if actual.purpose() != Purpose::Flow || intent.request.as_ref() != Some(actual.request()) {
            return Err(Error::Stale.into());
        }
        let matches = server
            .monotime_demand()
            .is_some_and(|d| d.id() == intent.demand.id());
        let live = !intent.retiring
            && matches
            && intent.identity.epoch() == identity.epoch()
            && intent.identity.peer() == identity.peer()
            && identity.expiration() > times.absolute()
            && intent.bounds.live(times.absolute().as_micros())
            && intent.demand.live(times);
        if live {
            match server.supply_monotime(intent.demand.id(), actual.span(), times) {
                Ok(()) => {
                    return Ok(Outcome::Installed {
                        identity: intent.identity,
                        demand: intent.demand,
                        actual,
                    });
                }
                Err(Error::Deadline | Error::Stale | Error::Replay) => {}
                Err(e) => return Err(e.into()),
            }
        }
        server.burn_monotime(intent.demand.id(), actual.span())?;
        Ok(Outcome::Burned {
            identity: intent.identity,
            demand: intent.demand,
            actual,
        })
    }
    /// Physical Engine/source retirement discards unadmitted metadata only;
    /// actual jobs move to the mandatory original worker drain.
    pub(crate) fn retire(&mut self) -> Option<crate::epoch::RetiredRange<'id>> {
        self.alarm = None;
        let old = self.intent.take()?;
        old.request
            .map(|request| crate::epoch::RetiredRange::flow(old.identity, old.demand, request))
    }
}
