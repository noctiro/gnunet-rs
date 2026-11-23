//! Original CADET output cancellation, bounded drain and physical retirement.
use super::*;
#[cfg(test)]
mod tests;

impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    pub(super) fn track_cadet_admission(
        &mut self,
        target: CadetAdmissionTarget<'c>,
        hard: Instant,
        requested: Instant,
        automatic: Option<Instant>,
    ) -> Result<(), Error> {
        let transmit = self.cadet.pending_transmit().ok_or(Fault::Conflict)?;
        self.cadet_pending = Some((transmit, hard.min(requested)));
        self.cadet_admission = Some(CadetAdmission {
            transmit,
            target,
            hard,
            automatic,
        });
        Ok(())
    }

    pub(super) fn refresh_cadet_pending(&mut self, now: Instant) {
        let pending = self.cadet.pending_transmit();
        if let Some(admission) = self.cadet_admission {
            if pending == Some(admission.transmit) {
                let automatic = admission.automatic.filter(|until| {
                    *until > now
                        && self
                            .apps
                            .iter()
                            .flatten()
                            .flat_map(|app| &app.rooms)
                            .any(|lease| {
                                let CadetAdmissionTarget::Channel { room, .. } = admission.target
                                else {
                                    return false;
                                };
                                lease.room == room && !lease.phase.is_closing()
                            })
                });
                let until = self
                    .cadet_admission_demand(admission.target, now)
                    .into_iter()
                    .chain(automatic)
                    .max()
                    .map_or(now, |until| until.min(admission.hard));
                self.cadet_pending = Some((admission.transmit, until));
                return;
            }
            self.cadet_admission = None;
        }
        if self.cadet_pending.map(|(transmit, _)| transmit) != pending {
            self.cadet_pending =
                pending.map(|transmit| (transmit, now + self.limits.operation_lifetime));
        }
    }

    fn discard_cadet_admission(&mut self) -> Result<bool, Error> {
        let Some(admission) = self.cadet_admission else {
            return Ok(false);
        };
        if self.cadet.pending_transmit() != Some(admission.transmit)
            || !self.cadet.discard_unexposed(admission.transmit)?
        {
            return Ok(false);
        }
        self.cadet_admission = None;
        self.cadet_pending = None;
        match admission.target {
            CadetAdmissionTarget::Channel { channel, .. } => {
                self.retire_tunnel_with_missing(channel, false)?;
            }
            CadetAdmissionTarget::Port { room, port } => {
                self.forget_unannounced_port(room, port)?;
            }
        }
        Ok(true)
    }

    fn forget_unannounced_port(
        &mut self,
        room: Room<'c>,
        port: cadet::Port<'c>,
    ) -> Result<(), Error> {
        let index = self.room_index(room)?;
        let entry = self.rooms[index].as_mut().ok_or(Fault::Stale)?;
        if entry.port != Some(port) {
            return Err(Fault::StaleGeneration.into());
        }
        entry.port = None;
        entry.hosting = false;
        Ok(())
    }

    /// Remove only an actual unwritten SDK frame; an exposed prefix keeps its
    /// exact source, bytes, credit reservation and original deadline.
    fn discard_peer_output(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Error> {
        let Some(out) = &self.peer_output else {
            return Ok(false);
        };
        if !matches!(out.target, PeerTarget::Channel(_))
            || !self.cadet.discard_unexposed(out.transmit)?
        {
            return Ok(false);
        }
        let out = self.peer_output.take().ok_or(Fault::Stale)?;
        if self
            .cadet_pending
            .is_some_and(|(transmit, _)| transmit == out.transmit)
        {
            self.cadet_pending = None;
        }
        if let Some(task) = out.task {
            self.finish_task(task);
        }
        observe(Event::OutputLost {
            sequence: out.sequence,
            exposed: Some(false),
        });
        Ok(true)
    }

    pub(super) fn reconcile_peer_output(
        &mut self,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Error> {
        let Some(PeerOutput {
            target: PeerTarget::Channel(channel),
            ..
        }) = &self.peer_output
        else {
            return Ok(false);
        };
        let tunnel = self
            .tunnels
            .iter()
            .flatten()
            .find(|tunnel| tunnel.channel == *channel)
            .ok_or(Fault::StaleGeneration)?;
        if !tunnel.closing && !tunnel.remote_closed {
            return Ok(false);
        }
        self.discard_peer_output(observe)
    }

    /// An unwritten payload can fail independently. A partial or internal
    /// frame must retire the original shared MQ before its sources are stopped.
    pub(super) fn expire_cadet_output(
        &mut self,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        if self.discard_cadet_admission()? {
            return Ok(());
        }
        if let Some(PeerOutput {
            target: PeerTarget::Channel(channel),
            ..
        }) = &self.peer_output
        {
            let channel = *channel;
            if self.discard_peer_output(observe)? {
                let tunnel = self
                    .tunnels
                    .iter_mut()
                    .flatten()
                    .find(|tunnel| tunnel.channel == channel)
                    .ok_or(Fault::StaleGeneration)?;
                tunnel.closing = true;
                self.discard_tunnel_input(channel);
                return Ok(());
            }
        }
        let cadet::Step::Lost { report, cause, .. } = self.cadet.reconnect()? else {
            return Err(Fault::Conflict.into());
        };
        self.cadet_lost(Some(report), Some(cause), observe)
    }
    pub(super) fn retire_remote_tunnel(&mut self) -> Result<bool, Error> {
        for index in 0..self.tunnels.len() {
            let Some(tunnel) = &self.tunnels[index] else {
                continue;
            };
            if !tunnel.remote_closed {
                continue;
            }
            let channel = tunnel.channel;
            // Keep this exact Source alive until its native frame settles.
            // The same room/peer on a replacement channel cannot inherit it.
            if self
                .peer_output
                .as_ref()
                .is_some_and(|out| out.target.channel() == Some(channel))
            {
                continue;
            }
            // Local cancellation wins independently of history. Otherwise retain
            // the same Source/room until held raw input and its actual durable
            // cut finish; receive_packet releases a processed packet only after
            // history_ready. Unrelated room cuts cannot prolong an empty source.
            if !tunnel.closing
                && self
                    .received
                    .iter()
                    .flatten()
                    .any(|r| r.input.channel() == channel)
            {
                continue;
            }
            self.retire_tunnel(channel)?;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn retire_tunnel(&mut self, channel: cadet::Channel<'c>) -> Result<(), Error> {
        self.retire_tunnel_with_missing(channel, true)
    }

    fn retire_tunnel_with_missing(
        &mut self,
        channel: cadet::Channel<'c>,
        report_missing: bool,
    ) -> Result<(), Error> {
        if let Some(i) = self
            .tunnels
            .iter()
            .position(|t| t.as_ref().is_some_and(|t| t.channel == channel))
        {
            let t = self.tunnels[i].as_ref().ok_or(Fault::Stale)?;
            let (source, room, peer) = (t.source, t.room, t.peer);
            // Reserve the reconnect relation before revoking the original Core
            // source. Capacity refusal leaves this exact tunnel owned for cleanup.
            let reconnect = report_missing
                && self.shutdown.is_none()
                && self
                    .apps
                    .iter()
                    .flatten()
                    .any(|a| a.rooms.iter().any(|l| l.room == room))
                && self
                    .core
                    .peers(room)?
                    .any(|(p, announced, _, _)| *p == peer && announced)
                && !self
                    .tunnels
                    .iter()
                    .flatten()
                    .any(|p| p.channel != channel && p.room == room && p.peer == peer)
                && !self
                    .misses
                    .iter()
                    .flatten()
                    .any(|m| m.room == room && m.peer == peer);
            let missing = if reconnect {
                Some(
                    self.misses
                        .iter()
                        .position(Option::is_none)
                        .ok_or(Fault::Capacity)?,
                )
            } else {
                None
            };
            // One MQ can lose more sources than the Core event queue can hold.
            // Consume each preceding source's real events before the next stop.
            self.drain_events();
            self.core.source_stopped(source)?;
            self.tunnels[i] = None;
            if let Some(slot) = missing {
                self.misses[slot] = Some(MissingPeer { room, peer });
            }

            for task in &mut self.tasks {
                if task
                    .as_ref()
                    .is_some_and(|t| t.destination == Destination::Peer(channel))
                {
                    *task = None
                }
            }
        }
        for r in &mut self.received {
            if r.as_ref().is_some_and(|r| r.input.channel() == channel) {
                *r = None
            }
        }
        Ok(())
    }
    pub(super) fn cadet_lost(
        &mut self,
        report: Option<cadet::Loss<'c>>,
        cause: Option<cadet::LossCause>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Error> {
        for r in &mut self.received {
            *r = None
        }
        self.cadet_pending = None;
        if let Some(admission) = self.cadet_admission.take()
            && let CadetAdmissionTarget::Port { room, port } = admission.target
            && report
                .and_then(|loss| loss.pending)
                .is_some_and(|out| out.transmit == admission.transmit)
        {
            // Losing the pending first write fails that original OPEN. Already
            // announced logical ports have no admission marker and still restore.
            if self.cadet.close_port(port)?.is_some() {
                return Err(Fault::Conflict.into());
            }
            self.forget_unannounced_port(room, port)?;
        }
        if let Some(out) = self.peer_output.take() {
            let exposed = report
                .and_then(|l| l.pending)
                .filter(|p| p.transmit == out.transmit)
                .map(|p| p.exposed);
            if exposed != Some(false) {
                self.report.unknown = self.report.unknown.saturating_add(1)
            }
            observe(Event::OutputLost {
                sequence: out.sequence,
                exposed,
            });
            if let Some(task) = out.task {
                self.finish_task(task)
            }
        }
        // No temporary channel vector is allocated after native loss.
        for i in 0..self.tunnels.len() {
            if let Some(t) = self.tunnels[i].as_ref() {
                let channel = t.channel;
                self.retire_tunnel(channel)?
            }
        }
        if let (Some(report), Some(cause)) = (report, cause) {
            observe(Event::CadetLost {
                epoch: report.epoch.value(),
                channels: report.channels,
                pending: report.pending.map(|p| (p.transmit.value(), p.exposed)),
                cause,
            })
        }
        observe(Event::DependencyLost { pils: false });
        Ok(())
    }
}
