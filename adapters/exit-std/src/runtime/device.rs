//! Actual verified TUN whole-packet ownership, never partial-suffix replay.
use super::*;
impl<'cfg, 'id, 'slots, E: Entropy> Driver<'cfg, 'id, 'slots, E> {
    pub(super) fn cancel_flow_tun(
        &mut self,
        flow: &Flow,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        if self.tun_held.as_ref().is_some_and(|p| p.flow == *flow) {
            let p = self.tun_held.take().ok_or(Fault::Stale)?;
            if let Some(tun) = &self.core_tun {
                self.engine.tun_unsent(tun, &p.write, Fault::Cancelled)?;
            }
        }
        if self.tun_pending.as_ref().is_some_and(|p| p.flow == *flow) {
            let native = self
                .tun_pending
                .as_ref()
                .ok_or(Fault::Stale)?
                .native
                .clone();
            let event = self.tun.as_mut().ok_or(Fault::Stale)?.cancel(&native)?;
            self.tun_write(event, observe)?;
        }
        Ok(())
    }
    fn queue_tun(&mut self, now: MonoInstant) -> Result<bool, Error> {
        if self.tun_pending.is_some() || self.tun.is_none() {
            return Ok(false);
        }
        if self.tun_held.is_none()
            && let Some(out) = self.engine.tun_output()
        {
            let flow = out.flow;
            let write = out.write;
            let expires = out.expires;
            match self.until(now, expires, Some(self.limits.io_grace)) {
                Ok(until) => self.tun_held = Some(Held { flow, write, until }),
                Err(e) => {
                    if let Some(tun) = &self.core_tun {
                        self.engine.tun_unsent(tun, &write, e)?;
                    }
                    return Ok(true);
                }
            }
        }
        let Some(held) = &self.tun_held else {
            return Ok(false);
        };
        let write = held.write.clone();
        let flow = held.flow.clone();
        let until = held.until;
        let out = self.engine.tun_output().ok_or(Fault::Stale)?;
        if out.write != write || out.flow != flow {
            return Err(Fault::Stale.into());
        }
        match self
            .tun
            .as_mut()
            .ok_or(Fault::Stale)?
            .queue(out.bytes, until)
        {
            Ok(native) => {
                self.tun_held = None;
                self.tun_pending = Some(TunPending {
                    native,
                    write,
                    flow,
                });
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => {
                let cause = if e.kind() == io::ErrorKind::TimedOut {
                    Fault::Deadline
                } else {
                    Fault::Io
                };
                self.tun_held = None;
                if let Some(tun) = &self.core_tun {
                    self.engine.tun_unsent(tun, &write, cause)?;
                }
                Err(e.into())
            }
        }
    }
    pub(super) fn tun_loss(
        &mut self,
        loss: tun::Loss,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let mut failure = None;
        if self.tun_epoch.as_ref() != Some(&loss.epoch) {
            failure = Some(Fault::Stale.into());
        }
        let pending = self.tun_pending.take();
        if loss
            .pending
            .as_ref()
            .is_some_and(|id| pending.as_ref().is_none_or(|p| &p.native != id))
            && failure.is_none()
        {
            failure = Some(Fault::Stale.into());
        }
        let uncertain = matches!(&loss.cause, tun::LossCause::ShortWrite { .. })
            || loss
                .pending
                .as_ref()
                .is_some_and(|id| id.helper_accepted_prefix() > 0);
        if let Some(tun) = self.core_tun.take() {
            let unknown = if uncertain {
                pending.as_ref().map(|p| &p.write)
            } else {
                None
            };
            if let Err(e) = self.engine.tun_lost(&tun, unknown)
                && failure.is_none()
            {
                failure = Some(e.into())
            }
        }
        if let Some(owner) = self.tun.take()
            && owner.is_helper()
        {
            self.retiring_tun = Some(owner);
        }
        self.tun_epoch = None;
        self.tun_held = None;
        self.tun_input = None;
        for p in &mut self.ports {
            if p.binding.target != Target::Dns {
                p.disabled = true;
            }
        }
        if let Some(e) = &loss.close_error
            && failure.is_none()
        {
            failure = Some(io::Error::new(e.kind(), e.to_string()).into())
        }
        observe(Event::TunLost(loss));
        match failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    pub(super) fn tun_write(
        &mut self,
        event: tun::WriteEvent,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        match event {
            tun::WriteEvent::Written { write, .. } => {
                let p = self.tun_pending.take().ok_or(Fault::Stale)?;
                if p.native != write {
                    return Err(Fault::Stale.into());
                }
                let tun = self.core_tun.as_ref().ok_or(Fault::Stale)?;
                self.engine.tun_written(tun, &p.write)?;
                if self.tun.as_ref().is_some_and(PacketSource::is_helper) {
                    self.report.helper_submitted = self.report.helper_submitted.saturating_add(1);
                } else {
                    self.report.tun_written = self.report.tun_written.saturating_add(1);
                }
                Ok(true)
            }
            tun::WriteEvent::Unsent { write, reason } => {
                let p = self.tun_pending.take().ok_or(Fault::Stale)?;
                if p.native != write {
                    return Err(Fault::Stale.into());
                }
                if let Some(tun) = &self.core_tun {
                    self.engine.tun_unsent(
                        tun,
                        &p.write,
                        match reason {
                            tun::Unsent::Cancelled => Fault::Cancelled,
                            tun::Unsent::Deadline => Fault::Deadline,
                        },
                    )?;
                }
                Ok(true)
            }
            tun::WriteEvent::Lost(loss) => {
                self.tun_loss(loss, observe)?;
                Ok(true)
            }
            tun::WriteEvent::Idle | tun::WriteEvent::Closed | tun::WriteEvent::WaitDeadline => {
                Ok(false)
            }
        }
    }
    pub(super) fn poll_tun(
        &mut self,
        cx: &mut Context<'_>,
        now: MonoInstant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.tun.is_none() {
            return Poll::Pending;
        }
        if self.queue_tun(now)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.tun_pending.is_some()
            && let Poll::Ready(event) = self.tun.as_mut().ok_or(Fault::Stale)?.poll_write(cx)
            && self.tun_write(event, observe)?
        {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if let Some(input) = &self.tun_input {
            if self.tun_epoch.as_ref() != Some(input.packet.epoch()) {
                return Poll::Ready(Err(Fault::Stale.into()));
            }
            let token = self.core_tun.as_ref().ok_or(Fault::Stale)?;
            let result = self.engine.from_tun(token, input.packet.bytes(), now);
            match result {
                Ok(_) => {
                    self.tun_input = None;
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Err(Fault::WouldBlock) => return Poll::Pending,
                Err(e) => {
                    self.tun_input = None;
                    observe(Event::TunDropped(e));
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        match self.tun.as_mut().ok_or(Fault::Stale)?.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(tun::ReadEvent::Packet(packet)) => {
                if self.tun_epoch.as_ref() != Some(packet.epoch()) {
                    return Poll::Ready(Err(Fault::Stale.into()));
                }
                if self.tun.as_ref().is_some_and(PacketSource::is_helper) {
                    self.report.helper_received = self.report.helper_received.saturating_add(1);
                } else {
                    self.report.tun_read = self.report.tun_read.saturating_add(1);
                }
                self.tun_input = Some(TunInput {
                    packet,
                    until: Instant::now()
                        .checked_add(self.limits.tun_input)
                        .ok_or(Fault::Overflow)?,
                });
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(tun::ReadEvent::Lost(loss)) => {
                self.tun_loss(loss, observe)?;
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(tun::ReadEvent::WriteExpired(write)) => {
                self.tun_write(
                    tun::WriteEvent::Unsent {
                        write,
                        reason: tun::Unsent::Deadline,
                    },
                    observe,
                )?;
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(tun::ReadEvent::Rejected(_)) => {
                observe(Event::TunDropped(Fault::Malformed));
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(tun::ReadEvent::Closed | tun::ReadEvent::WaitDeadline) => Poll::Pending,
        }
    }
}
