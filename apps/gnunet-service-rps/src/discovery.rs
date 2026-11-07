//! Actual original CORE/PEERSTORE/NSE sources; public peers remain only hints.
use crate::{Cause, settings::Settings};
use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_core_client_host as core;
use gnunet_nse_client_host as nse;
use gnunet_peerstore_client_host as peerstore;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    pin::pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

// Match the ordinary service's explicit upper channel/discovery profile. CORE's
// existing pure client uses fixed bounded metadata, not an application payload
// subscription or an unbounded discovered-peer collection.
const CORE_PEERS: usize = 4096;
const CORE_SENDS: usize = 32;

pub(super) struct Instances {
    core: core::Instance,
    peerstore: peerstore::Instance,
    nse: nse::Instance,
}
impl Instances {
    pub(super) const fn new() -> Self {
        Self {
            core: core::Instance::new(),
            peerstore: peerstore::Instance::new(),
            nse: nse::Instance::new(),
        }
    }
}
pub(super) struct Endpoints {
    pub core: EndpointSource,
    pub peerstore: EndpointSource,
    pub nse: EndpointSource,
}
/// Original source tokens are retained without granting RPS online authority.
pub(super) enum Hint<'id> {
    Core {
        epoch: core::ConnectionEpoch<'id>,
        peer: core::Peer<'id>,
    },
    Peerstore {
        epoch: peerstore::Epoch<'id>,
        operation: peerstore::Operation<'id>,
        phase: peerstore::RecordPhase,
    },
}
pub(super) enum Event<'id> {
    Identity {
        epoch: core::ConnectionEpoch<'id>,
        peer: [u8; 32],
        previous: Option<[u8; 32]>,
    },
    PeerHint {
        peer: [u8; 32],
        source: Hint<'id>,
    },
    Estimate(nse::Observation<'id>),
    Core(core::Progress<'id>),
    Peerstore {
        event: peerstore::Progress<'id>,
        retired_credit: bool,
    },
    Nse(nse::Progress<'id>),
    /// A refused original grant remains owed until it is admitted or the actual
    /// operation/MQ retires. This event is not a fresh monitor or grant receipt.
    CreditRefused {
        epoch: peerstore::Epoch<'id>,
        operation: peerstore::Operation<'id>,
        error: peerstore::Error,
    },
    /// Local original intent admission, not MONITOR_START Written or SYNC.
    MonitorStarted {
        operation: peerstore::Operation<'id>,
        expires: u64,
    },
}
/// Independent actual close attempts; one failure never suppresses the others.
pub(super) struct Close<'id> {
    pub core: Result<Option<core::Progress<'id>>, core::Error>,
    pub peerstore: Result<Option<peerstore::Progress<'id>>, peerstore::Error>,
    /// One monitor can queue Completed plus its original Lost during grant
    /// deadline/clock refusal. close()'s own returned loss stays independent.
    pub peerstore_events: [Option<peerstore::Progress<'id>>; 2],
    /// Logical/debt rows only; this count alone does not prove events drained.
    pub peerstore_pending: usize,
    /// Actual native post-drain predicate, including original queued events.
    pub peerstore_idle: bool,
    /// Defensive actual remaining debt flag; never infer it from pending()==0.
    pub peerstore_undrained: bool,
    pub nse: nse::Loss<'id>,
    pub retired_credit: bool,
}
#[derive(Clone, Copy)]
struct Credit<'id> {
    epoch: peerstore::Epoch<'id>,
    operation: peerstore::Operation<'id>,
    reported: bool,
}

pub(super) struct Sources<'id> {
    core: core::Client<'id, CORE_PEERS, CORE_SENDS>,
    peerstore: peerstore::Client<'id>,
    nse: nse::Subscription<'id>,
    clock: Arc<dyn RuntimeClock>,
    lifetime: u64,
    monitor: Option<peerstore::Operation<'id>>,
    credit: Option<Credit<'id>>,
    retired_credit: bool,
    identity: Option<[u8; 32]>,
    cursor: usize,
    closed: bool,
}
impl<'id> Sources<'id> {
    pub(super) fn new(
        instances: &'id mut Instances,
        endpoints: Endpoints,
        settings: &Settings,
    ) -> Result<Self, Cause> {
        if settings.discovery_lifetime == 0 || settings.discovery_lifetime == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        if settings.core_client.sends > CORE_SENDS {
            return Err(Fault::Capacity.into());
        }
        let clock = endpoints.peerstore.clock();
        let class = if cfg!(target_endian = "little") {
            core::ClassOrder::Little
        } else {
            core::ClassOrder::Big
        };
        let core = core::Client::new(
            &mut instances.core,
            endpoints.core,
            class,
            gnunet_wire::official::core::STATUS_CHANGE,
            &[],
            settings.core_client,
        )?;
        let peerstore = peerstore::Client::new_monitor(
            &mut instances.peerstore,
            endpoints.peerstore,
            settings.peerstore,
        )?;
        let mut nse_limits = settings.nse;
        nse_limits.source_lifetime = Duration::from_micros(settings.discovery_lifetime);
        let nse = nse::Subscription::new(&mut instances.nse, endpoints.nse, None, nse_limits)?;
        Ok(Self {
            core,
            peerstore,
            nse,
            clock,
            lifetime: settings.discovery_lifetime,
            monitor: None,
            credit: None,
            retired_credit: false,
            identity: None,
            cursor: 0,
            closed: false,
        })
    }
    fn core_event(&mut self, event: core::Progress<'id>) -> Event<'id> {
        match event {
            core::Progress::Inbound {
                epoch,
                event:
                    core::Inbound::Ready {
                        local,
                        previous_identity,
                    },
            } => {
                let peer = local.identity().0;
                let previous = self.identity.or(previous_identity.map(|p| p.0));
                // The service is built with its first actual CORE identity.
                // A later different identity is exposed, never installed into
                // the existing RPS owner by this actor.
                if self.identity.is_none() {
                    self.identity = Some(peer);
                }
                Event::Identity {
                    epoch,
                    peer,
                    previous,
                }
            }
            core::Progress::Inbound {
                epoch,
                event: core::Inbound::Connected(peer),
            } => Event::PeerHint {
                peer: peer.identity().0,
                source: Hint::Core { epoch, peer },
            },
            other => Event::Core(other),
        }
    }
    /// Bootstrap polls CORE only. No PEERSTORE lease or NSE source is admitted
    /// or driven before the caller has received the actual local identity.
    pub(super) fn poll_identity(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Event<'id>, Cause>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        match self.core.poll(cx, None) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(event)) => Poll::Ready(Ok(self.core_event(event))),
        }
    }
    fn start_monitor(&mut self) -> Result<Option<Event<'id>>, Cause> {
        if self.monitor.is_some() || !self.peerstore.is_idle() {
            return Ok(None);
        }
        let now = self.clock.sample()?.now.as_micros();
        let expires = now
            .checked_add(self.lifetime)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let operation = self.peerstore.monitor(
            peerstore::Filter {
                peer: None,
                subsystem: Some(peerstore::hello::SUBSYSTEM),
                key: Some(peerstore::hello::KEY),
            },
            true,
            expires,
        )?;
        self.monitor = Some(operation);
        Ok(Some(Event::MonitorStarted { operation, expires }))
    }
    fn credit_retired(&mut self) {
        if self.credit.take().is_some() {
            self.retired_credit = true;
        }
    }
    fn grant(&mut self) -> Result<Option<Event<'id>>, Cause> {
        let Some(mut credit) = self.credit else {
            return Ok(None);
        };
        if self.peerstore.epoch() != Some(credit.epoch) || !self.peerstore.live(credit.operation) {
            self.credit_retired();
            return Ok(None);
        }
        match self.peerstore.next(credit.operation, 1) {
            Ok(()) => {
                self.credit = None;
                Ok(None)
            }
            Err(error) => {
                let deferred = matches!(
                    &error,
                    ConnectError::Protocol(
                        Fault::Capacity
                            | Fault::NotReady
                            | Fault::WouldBlock
                            | Fault::Deadline
                            | Fault::Stale
                    )
                );
                if !deferred {
                    return Err(error.into());
                }
                if !credit.reported {
                    credit.reported = true;
                    self.credit = Some(credit);
                    Ok(Some(Event::CreditRefused {
                        epoch: credit.epoch,
                        operation: credit.operation,
                        error,
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }
    fn peerstore_event(&mut self, event: peerstore::Progress<'id>) -> Result<Event<'id>, Cause> {
        match event {
            peerstore::Progress::Record(observation) => {
                let operation = observation.operation();
                if self.monitor != Some(operation) {
                    return Ok(Event::Peerstore {
                        event: peerstore::Progress::Record(observation),
                        retired_credit: std::mem::take(&mut self.retired_credit),
                    });
                }
                if self.credit.is_some() {
                    return Err(Fault::Conflict.into());
                }
                let epoch = observation.epoch();
                self.credit = Some(Credit {
                    epoch,
                    operation,
                    reported: false,
                });
                let record = observation.record()?.record;
                if record.subsystem == Some(peerstore::hello::SUBSYSTEM)
                    && record.key == Some(peerstore::hello::KEY)
                {
                    // The opaque cache record, including an old public identity,
                    // is only a discovery hint. No HELLO crypto/address parser or
                    // online qualification is hidden in this source actor.
                    Ok(Event::PeerHint {
                        peer: record.peer,
                        source: Hint::Peerstore {
                            epoch,
                            operation,
                            phase: observation.phase(),
                        },
                    })
                } else {
                    Ok(Event::Peerstore {
                        event: peerstore::Progress::Record(observation),
                        retired_credit: std::mem::take(&mut self.retired_credit),
                    })
                }
            }
            peerstore::Progress::Completed {
                operation,
                epoch,
                kind,
                outcome,
            } => {
                if self.monitor == Some(operation) {
                    self.monitor = None;
                    self.credit_retired();
                }
                Ok(Event::Peerstore {
                    event: peerstore::Progress::Completed {
                        operation,
                        epoch,
                        kind,
                        outcome,
                    },
                    retired_credit: std::mem::take(&mut self.retired_credit),
                })
            }
            peerstore::Progress::Lost {
                epoch,
                cause,
                monitor_retained,
            } => {
                self.credit_retired();
                if !monitor_retained && self.monitor.is_some_and(|op| !self.peerstore.live(op)) {
                    self.monitor = None;
                }
                Ok(Event::Peerstore {
                    event: peerstore::Progress::Lost {
                        epoch,
                        cause,
                        monitor_retained,
                    },
                    retired_credit: std::mem::take(&mut self.retired_credit),
                })
            }
            peerstore::Progress::Connected(epoch) => {
                if self.credit.is_some_and(|credit| credit.epoch != epoch) {
                    self.credit_retired();
                }
                Ok(Event::Peerstore {
                    event: peerstore::Progress::Connected(epoch),
                    retired_credit: std::mem::take(&mut self.retired_credit),
                })
            }
            other => Ok(Event::Peerstore {
                event: other,
                retired_credit: std::mem::take(&mut self.retired_credit),
            }),
        }
    }
    fn poll_peerstore(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'id>, Cause>> {
        if let Some(event) = self.grant()? {
            return Poll::Ready(Ok(event));
        }
        if let Some(event) = self.start_monitor()? {
            return Poll::Ready(Ok(event));
        }
        // This wait future is only polled, never spawned. Its documented drop
        // contract retains actual native cursors, debts and original deadlines.
        let progress = {
            let future = self.peerstore.drive(None);
            let mut future = pin!(future);
            future.as_mut().poll(cx)
        };
        match progress {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(event)) => Poll::Ready(self.peerstore_event(event)),
        }
    }
    /// Fairly poll one actual event. Identity bootstrap remains CORE-only even
    /// if the caller uses this entry before constructing its RPS service.
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'id>, Cause>> {
        if self.closed {
            return Poll::Ready(Err(Fault::Closed.into()));
        }
        if self.identity.is_none() {
            return self.poll_identity(cx);
        }
        for _ in 0..3 {
            let slot = self.cursor;
            self.cursor = (self.cursor + 1) % 3;
            let progress = match slot {
                0 => match self.core.poll(cx, None) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(event)) => Poll::Ready(Ok(self.core_event(event))),
                },
                1 => self.poll_peerstore(cx),
                _ => match self.nse.poll(cx, None) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(nse::Progress::Estimate(observation))) => {
                        Poll::Ready(Ok(Event::Estimate(observation)))
                    }
                    Poll::Ready(Ok(event)) => Poll::Ready(Ok(Event::Nse(event))),
                },
            };
            if progress.is_ready() {
                return progress;
            }
        }
        Poll::Pending
    }
    pub(super) fn close(&mut self) -> Close<'id> {
        self.closed = true;
        let had_credit = self.credit.take().is_some();
        let retired_credit = std::mem::take(&mut self.retired_credit) || had_credit;
        // Deliberately independent; one actual close error cannot short circuit.
        let core = self.core.close();
        let peerstore = self.peerstore.close();
        // Exclusive one-monitor ownership plus is_idle before every new intent
        // prevents an old terminal queue coexisting with a later monitor. The
        // native deadline/clock path can queue exactly Completed then Lost;
        // native close returns its own Lost separately rather than queueing it.
        let peerstore_events = [self.peerstore.next_event(), self.peerstore.next_event()];
        let peerstore_pending = self.peerstore.pending();
        let peerstore_idle = self.peerstore.is_idle();
        let peerstore_undrained = !peerstore_idle;
        let nse = self.nse.close();
        Close {
            core,
            peerstore,
            peerstore_events,
            peerstore_pending,
            peerstore_idle,
            peerstore_undrained,
            nse,
            retired_credit,
        }
    }
}
impl Drop for Sources<'_> {
    fn drop(&mut self) {
        let _actual = self.close();
    }
}
