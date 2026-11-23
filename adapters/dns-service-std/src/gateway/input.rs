//! Checked source admission and original resolver result intake.
use super::{Captured, Gateway, GatewayProgress, Span};
use crate::upstream::{Event as StubEvent, Flow};
use crate::{Error, Event, packet_source::SourceEvent};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    task::{Context, Poll},
};
use tokio::time::Instant;

impl<'id> Gateway<'id> {
    pub(super) fn source_event(
        &mut self,
        event: SourceEvent<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<GatewayProgress<'id>, Error> {
        match event {
            SourceEvent::Input(Err(refused)) => {
                if refused.non_dns_udp {
                    self.report.non_dns_udp = self.report.non_dns_udp.saturating_add(1);
                }
                Ok(GatewayProgress::PacketDropped(refused.reason))
            }
            SourceEvent::Input(Ok(frame)) => {
                if self.held_input.is_some() {
                    return Err(Fault::Conflict.into());
                }
                let hard = Instant::now()
                    .checked_add(self.limits.request_hard_lifetime)
                    .ok_or(Fault::Overflow)?;
                self.held_input = Some((frame, hard));
                Ok(GatewayProgress::Activity)
            }
            SourceEvent::Written {
                effect,
                observation,
            } => {
                if observation.exposed() {
                    self.server.engine_mut().exposed(effect)?;
                }
                if observation.complete() {
                    self.server.engine_mut().written(effect)?;
                    self.report.outputs_written = self.report.outputs_written.saturating_add(1);
                }
                Ok(GatewayProgress::Activity)
            }
            SourceEvent::OutputStopped {
                effect,
                exposure,
                total,
                reason,
            } => {
                self.server.engine_mut().source_stopped(effect)?;
                observe(Event::PacketOutputLost {
                    effect,
                    exposure,
                    total,
                });
                self.report.packet_refusals = self.report.packet_refusals.saturating_add(1);
                Ok(GatewayProgress::PacketRefused {
                    request: Some(effect.request()),
                    reason,
                })
            }
            #[cfg(any(windows, target_os = "macos", target_os = "ios", target_os = "linux"))]
            SourceEvent::Refused(reason) => {
                self.report.packet_refusals = self.report.packet_refusals.saturating_add(1);
                Ok(GatewayProgress::PacketRefused {
                    request: None,
                    reason,
                })
            }
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            SourceEvent::FlowStopped { flow, reason } => {
                for span in self
                    .spans
                    .iter()
                    .flatten()
                    .filter(|span| span.flow == Some(flow))
                {
                    self.server.engine_mut().abort(span.request)?;
                }
                if self
                    .held_input
                    .as_ref()
                    .is_some_and(|(packet, _)| packet.flow_id() == Some(flow))
                {
                    self.held_input = None;
                }
                Ok(GatewayProgress::FlowStopped { flow, reason })
            }
            #[cfg(target_os = "linux")]
            SourceEvent::IngressRetired => {
                for span in self.spans.iter_mut().flatten() {
                    if span
                        .ingress
                        .as_ref()
                        .is_some_and(|ingress| !ingress.active())
                    {
                        self.server.engine_mut().abort(span.request)?;
                        // The engine still owns original resolver/output debts
                        // until their normal cancellation receipts settle.
                        span.ingress = None;
                    }
                }
                if self.held_input.as_ref().is_some_and(|(packet, _)| {
                    packet.ingress().is_some_and(|ingress| !ingress.active())
                }) {
                    self.held_input = None;
                    return Ok(GatewayProgress::PacketDropped(Fault::StaleGeneration));
                }
                Ok(GatewayProgress::Activity)
            }
            #[cfg(windows)]
            SourceEvent::RouteObservationFailed(reason) => {
                self.report.route_observation_failures =
                    self.report.route_observation_failures.saturating_add(1);
                Ok(GatewayProgress::RouteObservationFailed { reason })
            }
            SourceEvent::Activity => Ok(GatewayProgress::Activity),
            #[cfg(any(windows, target_os = "linux"))]
            SourceEvent::Suspended(reason) => {
                self.report.source_outages = self.report.source_outages.saturating_add(1);
                self.suspend_source_work()?;
                Ok(GatewayProgress::PacketRefused {
                    request: None,
                    reason: reason.into(),
                })
            }
            #[cfg(any(windows, target_os = "linux"))]
            SourceEvent::Detached {
                retirement,
                pending,
            } => {
                self.suspend_source_work()?;
                if let Some(pending) = pending {
                    observe(Event::PacketOutputLost {
                        effect: pending.effect,
                        exposure: pending.exposure,
                        total: pending.total,
                    });
                }
                if self.source_attached {
                    self.server.engine_mut().source_lost(self.source)?;
                    self.source_attached = false;
                }
                if self.report.first_source_loss.is_none() {
                    self.report.first_source_loss = Some(retirement);
                }
                Ok(GatewayProgress::Activity)
            }
            #[cfg(any(windows, target_os = "linux"))]
            SourceEvent::Attached => {
                if self.source_attached || !self.source_suspended {
                    return Err(Fault::Conflict.into());
                }
                self.source = self.server.engine_mut().attach_source()?;
                self.source_attached = true;
                self.source_suspended = false;
                self.report.source_recoveries = self.report.source_recoveries.saturating_add(1);
                Ok(GatewayProgress::Activity)
            }
            SourceEvent::Failed(e) => Err(e.into()),
            SourceEvent::Retired(exit) => {
                self.source_done = true;
                self.report.source_retirement = Some(exit);
                self.close(Some(Fault::Closed.into()), observe);
                Ok(GatewayProgress::SourceRetired)
            }
        }
    }
    pub(super) fn admit_input(&mut self, now: u64) -> Result<Option<GatewayProgress<'id>>, Error> {
        let Some((frame, hard)) = self.held_input.take() else {
            return Ok(None);
        };
        if Instant::now() >= hard {
            return Ok(Some(GatewayProgress::PacketDropped(Fault::Deadline)));
        }
        let duration =
            u64::try_from(self.limits.request_lifetime.as_micros()).map_err(|_| Fault::Overflow)?;
        let until = now
            .checked_add(duration)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let Some(slot) = self.spans.iter().position(Option::is_none) else {
            return Ok(Some(GatewayProgress::PacketDropped(Fault::Capacity)));
        };
        match frame.admit(self.server.engine_mut(), self.source, now, until) {
            Ok((request, permit)) => {
                self.spans[slot] = Some(Span {
                    request,
                    hard,
                    #[cfg(any(target_os = "macos", target_os = "ios"))]
                    flow: permit.flow_id(),
                    #[cfg(target_os = "linux")]
                    ingress: permit.ingress().cloned(),
                    permit: Some(permit),
                });
                self.report.packets = self.report.packets.saturating_add(1);
                Ok(Some(GatewayProgress::Activity))
            }
            Err(refused) => {
                if refused.non_dns_udp {
                    self.report.non_dns_udp = self.report.non_dns_udp.saturating_add(1);
                }
                Ok(Some(GatewayProgress::PacketDropped(refused.reason)))
            }
        }
    }
    pub(super) fn poll_stub(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<GatewayProgress<'id>, Error>> {
        let mut captured = None;
        let progress = {
            let future = self.stub.drive(None, |event| {
                captured = Some(match event {
                    StubEvent::Datagram(packet) => match OwnedFrame::copy_from(packet.bytes) {
                        Ok(frame) => Captured::Datagram {
                            request: packet.request,
                            frame,
                        },
                        Err(reason) => Captured::Refused {
                            request: packet.request,
                            reason,
                        },
                    },
                    StubEvent::SocketOpened { result: Err(_), .. } => Captured::SocketFailure,
                    _ => Captured::Activity,
                });
                Flow::Return
            });
            let mut future = std::pin::pin!(future);
            future.as_mut().poll(cx)
        };
        match progress {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Io(std::io::Error::other(e)))),
            Poll::Ready(Ok(_)) => match captured.ok_or(Fault::Conflict)? {
                Captured::Activity => Poll::Ready(Ok(GatewayProgress::Activity)),
                Captured::SocketFailure => {
                    self.report.resolver_socket_failures =
                        self.report.resolver_socket_failures.saturating_add(1);
                    Poll::Ready(Ok(GatewayProgress::Activity))
                }
                Captured::Refused { request, reason } => {
                    Poll::Ready(Ok(GatewayProgress::ResolverDiscarded {
                        native: request,
                        reason,
                    }))
                }
                Captured::Datagram { request, frame } => {
                    let Some(index) = self
                        .maps
                        .iter()
                        .position(|m| m.as_ref().is_some_and(|m| m.native == request))
                    else {
                        self.report.resolver_discarded =
                            self.report.resolver_discarded.saturating_add(1);
                        return Poll::Ready(Ok(GatewayProgress::ResolverDiscarded {
                            native: request,
                            reason: Fault::StaleGeneration,
                        }));
                    };
                    let job = self.maps[index].as_ref().ok_or(Fault::StaleGeneration)?.job;
                    match self.server.engine_mut().resolved(job, frame.bytes()) {
                        Ok(()) => {
                            self.stub.resolve_cancel(request)?;
                            self.maps[index] = None;
                            self.report.resolver_answers =
                                self.report.resolver_answers.saturating_add(1);
                            Poll::Ready(Ok(GatewayProgress::Activity))
                        }
                        Err(reason) => {
                            self.report.resolver_discarded =
                                self.report.resolver_discarded.saturating_add(1);
                            Poll::Ready(Ok(GatewayProgress::ResolverDiscarded {
                                native: request,
                                reason,
                            }))
                        }
                    }
                }
            },
        }
    }

    /// Retire existing native I/O and enforce its original monotonic bounds even
    /// while the canonical clock is incoherent. Responses stay in their native
    /// receive slots until the normal, clock-checked resolver turn.
    pub(super) fn poll_stub_guard(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<GatewayProgress<'id>, Error>> {
        let mut failed_socket = false;
        let mut unexpected_datagram = false;
        let result = self.stub.poll_native_guard(cx, |event| {
            match event {
                StubEvent::SocketOpened { result: Err(_), .. } => failed_socket = true,
                StubEvent::Datagram(_) => unexpected_datagram = true,
                _ => {}
            }
            Flow::Return
        });
        if unexpected_datagram {
            return Poll::Ready(Err(Fault::Conflict.into()));
        }
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(Error::Io(std::io::Error::other(error)))),
            Poll::Ready(Ok(_)) => {
                if failed_socket {
                    self.report.resolver_socket_failures =
                        self.report.resolver_socket_failures.saturating_add(1);
                }
                Poll::Ready(Ok(GatewayProgress::Activity))
            }
        }
    }
}
