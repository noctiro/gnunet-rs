//! Explicit shared SERVICE/Resolver/statistics/signal ports for the real DV
//! session. Native IO remains inside Owner's single actual maintenance machine.
use crate::{
    Failure, Failures,
    foreground::{Reports, Signals},
    generation::Reservations,
    owner::{self, Owner, TransportContext},
    settings::Settings,
    statistics::Publisher,
};
use gnunet_crypto::Entropy;
use gnunet_service_runtime::{
    accepted::AcceptState,
    service::{Listener, PeerAddress, ShutdownMode},
};
use gnunet_types::Error;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
/// Caller-visible SERVICE control result, never a fabricated IO completion.
pub(crate) enum Turn {
    Activity,
    Stop,
}
/// Only the move-only shared-worker receipts need deferred Scheduler routing.
/// Other original facts go to the existing non-reentrant diagnostic observer.
pub(crate) struct Receipts<'id> {
    pub(crate) reports: Reports,
    queue: VecDeque<owner::Event<'id>>,
    overflow: Option<owner::Event<'id>>,
    fenced: bool,
}
impl<'id> Receipts<'id> {
    pub(crate) fn new(reports: Reports) -> Result<Self, Error> {
        let mut queue = VecDeque::new();
        queue.try_reserve_exact(4).map_err(|_| Error::Capacity)?;
        Ok(Self {
            reports,
            queue,
            overflow: None,
            fenced: false,
        })
    }
    pub(crate) fn observe(&mut self, event: owner::Event<'id>) {
        if matches!(
            &event,
            owner::Event::DvRange { .. } | owner::Event::ReservationRetired(_)
        ) {
            if self.queue.len() < 4 {
                self.queue.push_back(event);
            } else {
                self.fenced = true;
                // Preserve the original receipt even on an internal capacity
                // violation; no later Scheduler work is allowed this turn.
                if let Some(previous) = self.overflow.replace(event) {
                    self.reports.observe(previous);
                }
            }
        } else {
            self.reports.observe(event);
        }
    }
    pub(crate) fn pop(&mut self) -> Option<owner::Event<'id>> {
        self.queue.pop_front().or_else(|| self.overflow.take())
    }
    pub(crate) fn fenced(&self) -> bool {
        self.fenced
    }
}
/// Same actual process ports across every DV bootstrap/live/retirement phase.
pub(crate) struct Service<'a, 'listen, 'stats> {
    pub(crate) reports: Reports,
    pub(crate) settings: &'a Settings,
    pub(crate) listeners: &'a [Listener<'listen>],
    pub(crate) resolver: &'a mut gnunet_resolver_broker::Driver<64, 1024>,
    pub(crate) signals: &'a mut Signals,
    pub(crate) statistics: &'a mut Publisher<'stats>,
    pub(crate) foreign_base: u64,
    pub(crate) ever_ready: bool,
    accepting: AcceptState,
    cursor: usize,
    previous_clients: usize,
    draining: Option<Instant>,
    alarm: Option<Pin<Box<Sleep>>>,
    resolver_broken: bool,
    stop_requested: bool,
}
impl<'a, 'listen, 'stats> Service<'a, 'listen, 'stats> {
    pub(crate) fn new(
        settings: &'a Settings,
        listeners: &'a [Listener<'listen>],
        resolver: &'a mut gnunet_resolver_broker::Driver<64, 1024>,
        signals: &'a mut Signals,
        statistics: &'a mut Publisher<'stats>,
        foreign_base: u64,
    ) -> Self {
        Self {
            reports: signals.reports(),
            settings,
            listeners,
            resolver,
            signals,
            statistics,
            foreign_base,
            ever_ready: false,
            accepting: AcceptState::default(),
            cursor: 0,
            previous_clients: 0,
            draining: None,
            alarm: None,
            resolver_broken: false,
            stop_requested: false,
        }
    }
    /// Every call drives original Owner/native guards before unrelated work.
    /// The callback receives only disjoint actual fields and must perform IO
    /// through the real Bridge observer when a DV Actor source is attached.
    pub(crate) fn poll<'id, E: Entropy>(
        &mut self,
        cx: &mut Context<'_>,
        owner: &mut Owner<'id, E>,
        reservations: &mut Reservations,
        receipts: &mut Receipts<'id>,
        transport: &mut impl FnMut(
            &mut Context<'_>,
            TransportContext<'_, 'id, E>,
        ) -> Poll<Result<gnunet_transport_host::Step, Failure>>,
    ) -> Poll<Result<Turn, Failure>> {
        let owning = owner.poll_with_transport(
            cx,
            reservations,
            &mut |event| receipts.observe(event),
            transport,
        );
        self.statistics.refresh(owner::Statistics {
            foreign_address_failures: self
                .foreign_base
                .saturating_add(owner.statistics().foreign_address_failures),
        });
        let stats = self.statistics.poll(cx);
        let resolution = if self.resolver_broken {
            Poll::Pending
        } else {
            let resolving = self.resolver.drive_waiting(None, |error| {
                self.reports
                    .diagnostic(format_args!("TRANSPORT Resolver: {error:?}"))
            });
            let mut resolving = std::pin::pin!(resolving);
            resolving.as_mut().poll(cx)
        };
        if let Poll::Ready(Err(original)) = owning {
            let mut cleanup = Vec::new();
            if let Poll::Ready(Err(error)) = resolution {
                self.resolver_broken = true;
                cleanup.push(Box::new(error) as Failure);
            }
            if receipts.fenced() {
                cleanup.push(Box::new(Error::Capacity));
            }
            return Poll::Ready(Err(if cleanup.is_empty() {
                original
            } else {
                Box::new(Failures {
                    original: Some(original),
                    cleanup,
                })
            }));
        }
        if let Poll::Ready(Err(error)) = resolution {
            self.resolver_broken = true;
            return Poll::Ready(Err(Box::new(error)));
        }
        if receipts.fenced() {
            let cleanup = owner.stop(&mut |event| receipts.observe(event));
            return Poll::Ready(Err(Box::new(Failures {
                original: Some(Box::new(Error::Capacity)),
                cleanup,
            })));
        }
        if owner.ready()
            && let Some(identity) = owner.dv_identity()
        {
            self.reports
                .ready(gnunet_transport::PeerId(*identity.peer().as_bytes()));
        }
        self.ever_ready |= owner.ready();
        let clients = owner.snapshot().map_or(0, |snapshot| snapshot.clients);
        if clients < self.previous_clients {
            self.accepting.client_closed();
        }
        self.previous_clients = clients;
        if self.draining.is_none()
            && let Poll::Ready(signal) = self.signals.poll(cx)
        {
            signal?;
            self.stop_requested = true;
            if self.settings.options.shutdown == ShutdownMode::Immediate {
                return Poll::Ready(Ok(Turn::Stop));
            }
            let until = Instant::now()
                .checked_add(self.settings.grace)
                .ok_or(Error::Overflow)?;
            self.draining = Some(until);
            self.alarm = Some(Box::pin(tokio::time::sleep_until(until)));
        }
        if self.draining.is_some() {
            if owner.draining_complete() {
                return Poll::Ready(Ok(Turn::Stop));
            }
            if let Some(alarm) = &mut self.alarm
                && alarm.as_mut().poll(cx).is_ready()
            {
                return Poll::Ready(Ok(Turn::Stop));
            }
        } else if owner.ready() && self.accepting.ready() && clients < self.settings.clients {
            for _ in 0..self.listeners.len() {
                let index = self.cursor % self.listeners.len();
                self.cursor = (self.cursor + 1) % self.listeners.len();
                match self.listeners[index].poll_canonical_connection(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(error)) => {
                        let actual = self.accepting.failed(error);
                        self.reports
                            .diagnostic(format_args!("TRANSPORT accept: {actual:?}"));
                        return Poll::Ready(Ok(Turn::Activity));
                    }
                    Poll::Ready(Ok(accepted)) => {
                        if !accepted.diagnostics().is_empty() {
                            self.reports.diagnostic(format_args!(
                                "TRANSPORT accepted socket: {:?}",
                                accepted.diagnostics()
                            ));
                        }
                        let allowed = match accepted.peer() {
                            PeerAddress::Tcp(address) => {
                                self.settings.options.access.allows(address.ip())
                            }
                            PeerAddress::Unix => {
                                self.settings.unix.allows(accepted.connection())?
                            }
                        };
                        if allowed {
                            let (connection, _, _) = accepted.into_parts();
                            match owner.admit(connection) {
                                Ok(_) | Err(Error::Capacity | Error::WouldBlock) => {}
                                Err(error) => return Poll::Ready(Err(Box::new(error))),
                            }
                        }
                        return Poll::Ready(Ok(Turn::Activity));
                    }
                }
            }
        }
        if owning.is_ready() || resolution.is_ready() || stats.is_ready() {
            Poll::Ready(Ok(Turn::Activity))
        } else {
            Poll::Pending
        }
    }
    pub(crate) fn stop_requested(&self) -> bool {
        self.stop_requested
    }
    fn cleanup_signal(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        if let Poll::Ready(signal) = self.signals.poll(cx) {
            signal?;
            self.stop_requested = true;
            if self.draining.is_none() {
                let hard = Instant::now()
                    .checked_add(self.settings.grace)
                    .ok_or(Error::Overflow)?;
                self.draining = Some(hard);
                self.alarm = Some(Box::pin(tokio::time::sleep_until(hard)));
            }
            return Ok(true);
        }
        Ok(false)
    }
    /// Fair independent process ports during a real Provider shutdown future.
    /// Broken Resolver is reported once; it never cancels an admitted fsync.
    pub(crate) fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        let signal = self.cleanup_signal(cx)?;
        let stats = self.statistics.poll(cx);
        if self.resolver_broken {
            return if stats.is_ready() || signal {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }
        let resolving = self.resolver.drive_waiting(None, |error| {
            self.reports
                .diagnostic(format_args!("TRANSPORT DV drain Resolver: {error:?}"))
        });
        let mut resolving = std::pin::pin!(resolving);
        match resolving.as_mut().poll(cx) {
            Poll::Ready(Err(error)) => {
                self.resolver_broken = true;
                Poll::Ready(Err(Box::new(error)))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Pending => {
                if stats.is_ready() || signal {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}
