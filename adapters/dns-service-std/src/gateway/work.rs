//! Fair dispatch of original client, resolver and source effects.
use super::{Gateway, GatewayProgress, ResolveMap};
use crate::{
    Error, Event,
    core::{Destination, Work},
    packet_source::{self, OutputStop},
};
use gnunet_types::Error as Fault;

impl<'id> Gateway<'id> {
    pub(super) fn core_work(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
        admit: bool,
    ) -> Result<Option<GatewayProgress<'id>>, Error> {
        let cap = self.server.engine().request_capacity();
        for n in 0..cap {
            let i = (self.cursor + n) % cap;
            let Some(request) = self.server.engine().request_at(i) else {
                continue;
            };
            let work = match self.server.engine_mut().next_work(request) {
                Ok(w) => w,
                Err(Fault::WouldBlock) => continue,
                Err(e) => return Err(e.into()),
            };
            match work {
                Work::Resolve(request) => {
                    if !admit {
                        continue;
                    }
                    let Some(slot) = self.maps.iter().position(Option::is_none) else {
                        continue;
                    };
                    // DNSSTUB admission does no IO and all fallible preflights
                    // precede its mutation. A refusal affects only this query.
                    let admission = match self.stub.resolve(self.server.engine().payload(request)?)
                    {
                        Ok(admission) => admission,
                        Err(reason) => {
                            self.server.engine_mut().abort(request)?;
                            self.report.resolver_refusals =
                                self.report.resolver_refusals.saturating_add(1);
                            self.cursor = (i + 1) % cap;
                            return Ok(Some(GatewayProgress::ResolverRefused { request, reason }));
                        }
                    };
                    if let Some(evicted) = admission.evicted {
                        let old = self
                            .maps
                            .iter_mut()
                            .find(|m| m.as_ref().is_some_and(|m| m.native == evicted))
                            .and_then(Option::take)
                            .ok_or(Fault::StaleGeneration)?;
                        self.server.engine_mut().resolve_stopped(old.job)?;
                        self.report.resolver_evictions =
                            self.report.resolver_evictions.saturating_add(1);
                    }
                    let job = match self.server.engine_mut().resolving(request) {
                        Ok(job) => job,
                        Err(e) => {
                            let _cancel = self.stub.resolve_cancel(admission.request);
                            return Err(e.into());
                        }
                    };
                    self.maps[slot] = Some(ResolveMap {
                        job,
                        native: admission.request,
                    });
                    self.cursor = (i + 1) % cap;
                    self.report.resolver_queries = self.report.resolver_queries.saturating_add(1);
                    return Ok(Some(GatewayProgress::ResolverQueued {
                        request,
                        native: admission.request,
                    }));
                }
                Work::Cancel(job) => {
                    let index = self
                        .maps
                        .iter()
                        .position(|m| m.as_ref().is_some_and(|m| m.job == job))
                        .ok_or(Fault::StaleGeneration)?;
                    let map = self.maps[index].as_ref().ok_or(Fault::StaleGeneration)?;
                    self.stub.resolve_cancel(map.native)?;
                    self.server.engine_mut().resolve_stopped(job)?;
                    self.maps[index] = None;
                    self.cursor = (i + 1) % cap;
                    return Ok(Some(GatewayProgress::Activity));
                }
                Work::Source { request, source } => {
                    if !admit {
                        continue;
                    }
                    if source != self.source {
                        return Err(Fault::StaleGeneration.into());
                    }
                    if !self.packets.writable() {
                        continue;
                    }
                    let slot = self
                        .spans
                        .iter()
                        .position(|s| s.as_ref().is_some_and(|s| s.request == request))
                        .ok_or(Fault::StaleGeneration)?;
                    let span = self.spans[slot].as_ref().ok_or(Fault::StaleGeneration)?;
                    let permit = span.permit.as_ref().ok_or(Fault::Conflict)?;
                    #[cfg(any(target_os = "macos", target_os = "ios"))]
                    let native_flow = span.flow.is_some();
                    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
                    let native_flow = false;
                    let (effect, frame) =
                        match self
                            .packets
                            .prepare(self.server.engine_mut(), request, permit)
                        {
                            Ok(prepared) => prepared,
                            Err(Fault::WouldBlock) => continue,
                            Err(reason)
                                if matches!(reason, Fault::TooLarge | Fault::Capacity)
                                    || (native_flow
                                        && matches!(
                                            reason,
                                            Fault::Closed | Fault::StaleGeneration
                                        )) =>
                            {
                                self.server.engine_mut().abort(request)?;
                                self.report.packet_refusals =
                                    self.report.packet_refusals.saturating_add(1);
                                self.cursor = (i + 1) % cap;
                                return Ok(Some(GatewayProgress::PacketRefused {
                                    request: Some(request),
                                    reason: reason.into(),
                                }));
                            }
                            Err(reason) => return Err(reason.into()),
                        };
                    let hard = span.hard;
                    let permit = self.spans[slot]
                        .as_mut()
                        .and_then(|span| span.permit.take())
                        .ok_or(Fault::Conflict)?;
                    match self.packets.queue(effect, frame, hard, permit) {
                        Ok(()) => {
                            self.server.engine_mut().queued(effect)?;
                            self.report.outputs_queued =
                                self.report.outputs_queued.saturating_add(1);
                        }
                        Err((e, _, permit)) => {
                            self.server.engine_mut().reject_prepared(effect)?;
                            self.spans[slot]
                                .as_mut()
                                .ok_or(Fault::StaleGeneration)?
                                .permit = Some(permit);
                            if matches!(&e, Error::Protocol(Fault::WouldBlock))
                                || matches!(&e, Error::Io(error) if error.kind() == std::io::ErrorKind::WouldBlock)
                            {
                                continue;
                            }
                            if native_flow
                                || packet_source::route_refusal(&e)
                                || matches!(
                                    &e,
                                    Error::Protocol(
                                        Fault::TooLarge | Fault::Capacity | Fault::Deadline
                                    )
                                )
                            {
                                self.server.engine_mut().abort(request)?;
                                self.report.packet_refusals =
                                    self.report.packet_refusals.saturating_add(1);
                                self.cursor = (i + 1) % cap;
                                return Ok(Some(GatewayProgress::PacketRefused {
                                    request: Some(request),
                                    reason: e,
                                }));
                            }
                            return Err(e);
                        }
                    }
                    self.cursor = (i + 1) % cap;
                    return Ok(Some(GatewayProgress::Activity));
                }
                Work::Close(Destination::Source(source)) => {
                    if source != self.source {
                        return Err(Fault::StaleGeneration.into());
                    }
                    match self.packets.cancel_output(request)? {
                        OutputStop::Requested => continue,
                        OutputStop::SourceRequired => return Err(Fault::Deadline.into()),
                    }
                }
                Work::Close(Destination::Client(client)) => {
                    self.server
                        .close_client(client, Fault::Deadline.into(), observe)?;
                    return Ok(Some(GatewayProgress::Activity));
                }
                Work::Retire(request) => {
                    self.server.engine_mut().retire(request)?;
                    for slot in &mut self.spans {
                        if slot.as_ref().is_some_and(|s| s.request == request) {
                            *slot = None;
                            break;
                        }
                    }
                    self.cursor = (i + 1) % cap;
                    return Ok(Some(GatewayProgress::Activity));
                }
                _ => {}
            }
        }
        Ok(None)
    }
}
