use super::*;
mod application;
impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    fn drop_input(
        &mut self,
        flow: Option<core::Flow<'id>>,
        reason: Fault,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) {
        self.report.dropped = self.report.dropped.saturating_add(1);
        observe(Event::Dropped { flow, reason });
    }
    pub(super) fn tun_lost(
        &mut self,
        loss: tun::Loss,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        if self.device.epoch().as_ref() != Some(&loss.epoch) {
            return Err(Fault::StaleGeneration.into());
        }
        #[cfg(any(windows, target_os = "freebsd"))]
        let recovering = self.arm_recovery(&loss)?;
        #[cfg(target_os = "freebsd")]
        let loss = {
            let mut loss = loss;
            if let Some(owner) = loss.freebsd_recovery.take() {
                if self.recovery.packet.is_some() {
                    return Err(Fault::Conflict.into());
                }
                self.recovery.packet = Some(recovery::PacketRecovery::Retained(owner));
            }
            loss
        };
        // An unexpected source loss is not this coordinator's explicit
        // same-epoch device-removal receipt, even if its close returned no errno.
        self.control.uncertain = true;
        if let Some(error) = loss.close_error.as_ref() {
            self.control.prior_tun_close_error = Some(match error.raw_os_error() {
                Some(errno) => io::Error::from_raw_os_error(errno),
                None => io::Error::new(error.kind(), error.to_string()),
            });
        }
        if (matches!(loss.cause,tun::LossCause::ShortWrite{bytes,..} if bytes>0)
            || loss
                .pending
                .as_ref()
                .is_some_and(|id| id.helper_accepted_prefix() > 0))
            && let Some(p) = self.output.as_ref()
            && loss.pending.as_ref() == p.write.native()
        {
            self.server.engine_mut().exposed(p.effect)?;
        }
        self.output = None;
        self.input = None;
        if !self.control.dead {
            if let Some(source) = self.source {
                self.server
                    .engine_mut()
                    .route_lost(source, Fault::OutcomeUnknown)?;
                let fact = self.server.engine_mut().tun_lost(source, Fault::Closed)?;
                observe(Event::TunCoreLost(fact));
            }
            self.control.dead = true;
            self.report.tun_losses = self.report.tun_losses.saturating_add(1);
        }
        #[cfg(windows)]
        if recovering {
            let result = self.retire_control_for_recovery(observe);
            observe(Event::TunLost(loss));
            return result;
        }
        #[cfg(target_os = "freebsd")]
        if recovering {
            let result = self.retire_control_for_recovery(observe);
            if result.is_ok() && self.stopping.is_none() {
                observe(Event::TunRecovering(loss));
            } else {
                observe(Event::TunLost(loss));
            }
            return result;
        }
        observe(Event::TunLost(loss));
        self.request_shutdown();
        Ok(())
    }
    pub(super) fn poll_tun_output(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        if self.control.dead {
            return Ok(false);
        }
        let mut activity = false;
        if self.device.provenance == Provenance::Provider {
            activity |= self.poll_provider_output(cx, observe)?;
        } else {
            match self.device.io.poll_write(cx) {
                Poll::Ready(tun::WriteEvent::Written { write, raw_bytes }) => {
                    let p = self.output.take().ok_or(Fault::StaleGeneration)?;
                    if p.write.native() != Some(&write) {
                        self.output = Some(p);
                        return Err(Fault::StaleGeneration.into());
                    }
                    self.server.engine_mut().exposed(p.effect)?;
                    self.server.engine_mut().written(p.effect)?;
                    let event = if self.device.io.is_helper() {
                        self.report.helper_submitted =
                            self.report.helper_submitted.saturating_add(1);
                        Event::HelperSubmitted {
                            write,
                            effect: p.effect,
                            bytes: raw_bytes,
                        }
                    } else {
                        self.report.tun_written = self.report.tun_written.saturating_add(1);
                        Event::TunWritten {
                            write,
                            effect: p.effect,
                            bytes: raw_bytes,
                        }
                    };
                    observe(event);
                    activity = true;
                }
                Poll::Ready(tun::WriteEvent::Unsent { write, reason }) => {
                    let p = self.output.take().ok_or(Fault::StaleGeneration)?;
                    if p.write.native() != Some(&write) {
                        self.output = Some(p);
                        return Err(Fault::StaleGeneration.into());
                    }
                    self.server.engine_mut().unsent(
                        p.effect,
                        match reason {
                            tun::Unsent::Cancelled => Fault::Cancelled,
                            tun::Unsent::Deadline => Fault::Deadline,
                        },
                    )?;
                    activity = true;
                }
                Poll::Ready(tun::WriteEvent::Lost(loss)) => {
                    self.tun_lost(loss, observe)?;
                    return Ok(true);
                }
                Poll::Ready(tun::WriteEvent::Closed) => {
                    if !self.control.dead {
                        return Err(Fault::Closed.into());
                    }
                }
                Poll::Pending
                | Poll::Ready(tun::WriteEvent::Idle | tun::WriteEvent::WaitDeadline) => {}
            }
        }
        if self.output.is_none()
            && self.stopping.is_none()
            && let Some(source) = self.source
            && self.server.engine().tun_ready(source)?
        {
            match self.server.engine_mut().prepare_tun(source) {
                Ok(Some(prepared)) => {
                    let effect = prepared.effect;
                    let (i, input_until) = self
                        .links
                        .iter()
                        .enumerate()
                        .find_map(|(i, l)| {
                            l.as_ref()?.input.as_ref().and_then(|input| {
                                input
                                    .processing
                                    .filter(|(delivery, _)| {
                                        Some(delivery.buffer()) == effect.buffer()
                                    })
                                    .map(|_| (i, input.until))
                            })
                        })
                        .ok_or(Fault::StaleGeneration)?;
                    let until = Self::deadline(self.limits.tun_send_timeout)?.min(input_until);
                    if Instant::now() >= until {
                        self.server.engine_mut().reject_prepared(effect)?;
                        self.fail_flow(i, Fault::Deadline)?;
                        let flow = self.links[i].as_ref().ok_or(Fault::StaleGeneration)?.flow;
                        self.drop_input(Some(flow), Fault::Deadline, observe);
                        return Ok(true);
                    }
                    let io = &mut self.device.io;
                    let queue = if let Some(owner) = io.provider_mut() {
                        owner.issue().and_then(|id| {
                            let request = provider::PacketRequest {
                                id,
                                deadline: until,
                            };
                            owner.driver.begin_write(request, prepared.bytes)?;
                            Ok(PacketWrite::Provider {
                                request,
                                bytes: prepared.bytes.len(),
                            })
                        })
                    } else {
                        io.queue(prepared.bytes, until).map(PacketWrite::Native)
                    };
                    match queue {
                        Ok(write) => {
                            self.server.engine_mut().queued(effect)?;
                            self.output = Some(TunOutput { write, effect });
                            activity = true;
                        }
                        Err(e) => {
                            self.server.engine_mut().reject_prepared(effect)?;
                            if self.device.provenance == Provenance::Provider {
                                if e.kind() == io::ErrorKind::WouldBlock {
                                    return Ok(activity);
                                }
                                self.control.provider_error.get_or_insert(Error::Native(e));
                                self.request_shutdown();
                                return Ok(true);
                            }
                            return Err(e.into());
                        }
                    }
                }
                Ok(None) | Err(Fault::Closed | Fault::NotReady | Fault::Unavailable) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(activity)
    }
    pub(super) fn poll_tun_input(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        if self.control.dead {
            return Ok(false);
        }
        let Some(source) = self.source else {
            return Ok(false);
        };
        if !self.server.engine().tun_ready(source)? {
            return Ok(false);
        }
        let mut activity = false;
        if self.input.is_none() {
            if let Some(owner) = self.device.io.provider_mut() {
                match owner.driver.poll_read(cx, self.limits.mtu as usize) {
                    Poll::Ready(Ok(Some(packet))) => {
                        if packet.len() > self.limits.mtu as usize || tun::version(&packet).is_err()
                        {
                            self.drop_input(None, Fault::Malformed, observe);
                            return Ok(true);
                        }
                        self.report.tun_read = self.report.tun_read.saturating_add(1);
                        self.input = Some(TunInput {
                            packet: IncomingPacket::Provider(packet),
                            until: Self::deadline(self.limits.input_timeout)?,
                        });
                        activity = true;
                    }
                    Poll::Ready(Ok(None)) => {
                        self.control
                            .provider_error
                            .get_or_insert(Fault::Closed.into());
                        self.request_shutdown();
                        return Ok(true);
                    }
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData => {
                        self.drop_input(None, Fault::Malformed, observe);
                        return Ok(true);
                    }
                    Poll::Ready(Err(error)) => {
                        self.control
                            .provider_error
                            .get_or_insert(Error::Native(error));
                        self.request_shutdown();
                        return Ok(true);
                    }
                    Poll::Pending => {}
                }
            } else {
                match self.device.io.poll_read(cx) {
                    Poll::Pending | Poll::Ready(tun::ReadEvent::WaitDeadline) => {}
                    Poll::Ready(tun::ReadEvent::Packet(packet)) => {
                        if self.device.epoch().as_ref() != Some(packet.epoch()) {
                            return Err(Fault::StaleGeneration.into());
                        }
                        self.report.tun_read = self.report.tun_read.saturating_add(1);
                        self.input = Some(TunInput {
                            packet: IncomingPacket::Native(packet),
                            until: Self::deadline(self.limits.input_timeout)?,
                        });
                        activity = true;
                    }
                    Poll::Ready(tun::ReadEvent::Rejected(_)) => {
                        self.drop_input(None, Fault::Malformed, observe);
                        return Ok(true);
                    }
                    Poll::Ready(tun::ReadEvent::WriteExpired(write)) => {
                        let p = self.output.take().ok_or(Fault::StaleGeneration)?;
                        if p.write.native() != Some(&write) {
                            self.output = Some(p);
                            return Err(Fault::StaleGeneration.into());
                        }
                        self.server.engine_mut().unsent(p.effect, Fault::Deadline)?;
                        return Ok(true);
                    }
                    Poll::Ready(tun::ReadEvent::Lost(loss)) => {
                        self.tun_lost(loss, observe)?;
                        return Ok(true);
                    }
                    Poll::Ready(tun::ReadEvent::Closed) => return Err(Fault::Closed.into()),
                }
            }
        }
        if let Some(input) = self.input.take() {
            if Instant::now() >= input.until {
                self.drop_input(None, Fault::Deadline, observe);
                return Ok(true);
            }
            let (absolute, native_activity) = self.server.sample()?;
            match self.server.engine_mut().forward_tun(
                source,
                input.packet.bytes(),
                absolute,
                native_activity,
            ) {
                Ok(ingress) => {
                    if let Err(e) = self.insert(ingress.flow) {
                        self.server
                            .engine_mut()
                            .close_flow(ingress.flow, Fault::Capacity)?;
                        if ingress.new_flow {
                            // This rejected metadata row has no provider/channel
                            // work yet. Retire the canceled original packet and
                            // flow instead of leaving an untracked pool owner.
                            self.server.engine_mut().release_buffer(ingress.buffer)?;
                            self.server.engine_mut().retire_flow(ingress.flow)?;
                        }
                        self.drop_input(Some(ingress.flow), Fault::Capacity, observe);
                        if ingress.new_flow && matches!(e, Error::Protocol(Fault::Capacity)) {
                            return Ok(true);
                        }
                        return Err(e);
                    }
                    activity = true;
                }
                Err(Fault::Capacity | Fault::WouldBlock) => self.input = Some(input),
                Err(e) => {
                    self.drop_input(None, e, observe);
                    activity = true;
                }
            }
        }
        Ok(activity)
    }
    pub(super) fn advance_input(
        &mut self,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        for _ in 0..self.links.len() {
            let i = self.receive_cursor;
            self.receive_cursor = (self.receive_cursor + 1) % self.links.len();
            if self.links[i].as_ref().is_some_and(|l| l.input.is_some())
                && self.advance_one(i, observe)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn advance_one(
        &mut self,
        i: usize,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        // Process one complete inner frame at a time. A blocked channel cannot
        // prevent another channel from releasing its completed delivery buffer.
        let mut input = self.links[i]
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .input
            .take()
            .ok_or(Fault::StaleGeneration)?;
        let flow = self.links[i].as_ref().ok_or(Fault::StaleGeneration)?.flow;
        if self.stopping.is_some()
            || self.control.dead
            || self.server.engine().flow_info(flow)?.phase == core::Phase::Closing
        {
            // Local cancellation/failure wins even if Destroyed arrived later.
            // Physical channel loss retires the original processing permission.
            return Ok(true);
        }
        if Instant::now() >= input.until {
            self.fail_flow(i, Fault::Deadline)?;
            self.drop_input(Some(flow), Fault::Deadline, observe);
            // Native processing remains outstanding until actual channel close.
            return Ok(true);
        }
        let peer = self.links[i].as_ref().and_then(Link::peer);
        let Some(peer) = peer else {
            self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = Some(input);
            return Ok(false);
        };
        if let Some((delivery, length)) = input.processing {
            if self.server.engine().delivery_ready(delivery)? {
                self.server.engine_mut().receive_done(delivery)?;
                self.server.engine_mut().release_buffer(delivery.buffer())?;
                input.offset = input.offset.checked_add(length).ok_or(Fault::Overflow)?;
                input.processing = None;
                self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = Some(input);
                return Ok(true);
            }
            self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = Some(input);
            return Ok(false);
        }
        if input.offset == input.frame.messages().len() {
            if self.links[i]
                .as_ref()
                .ok_or(Fault::StaleGeneration)?
                .remote_closed()
            {
                // Its actual TUN writes have settled. Drop the old outer receipt
                // locally; an ended channel cannot receive processing credit.
                return Ok(true);
            }
            if self.native.is_some() {
                self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = Some(input);
                return Ok(false);
            }
            match self.cadet.receive_done(input.frame.delivery()) {
                Ok(tx) => {
                    self.pending(tx, Action::Ack(i))?;
                    return Ok(true);
                }
                Err(cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady)) => {
                    self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = Some(input);
                    return Ok(false);
                }
                Err(e) => {
                    self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = Some(input);
                    return Err(e.into());
                }
            }
        }
        let body = &input.frame.messages()[input.offset..];
        let size = if body.len() >= 4 {
            usize::from(u16::from_be_bytes([body[0], body[1]]))
        } else {
            0
        };
        if size < 4 || size > body.len() {
            self.fail_flow(i, Fault::Malformed)?;
            self.drop_input(Some(flow), Fault::Malformed, observe);
            return Ok(true);
        }
        let (_, activity) = self.server.sample()?;
        match self
            .server
            .engine_mut()
            .receive_peer(peer, &body[..size], activity)
        {
            Ok(delivery) => {
                input.processing = Some((delivery, size));
                self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = Some(input);
                Ok(true)
            }
            Err(Fault::Capacity | Fault::WouldBlock) => {
                self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = Some(input);
                Ok(false)
            }
            Err(e) => {
                self.fail_flow(i, e)?;
                self.drop_input(Some(flow), e, observe);
                Ok(true)
            }
        }
    }
}
