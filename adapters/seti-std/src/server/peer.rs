//! Real CADET port/channel operations and exact original completion mapping.
use super::*;
use gnunet_seti::Phase;
use gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE;
fn transient(e: &cadet::Error) -> bool {
    matches!(
        e,
        cadet::Error::Protocol(ProtocolError::WouldBlock | ProtocolError::NotReady)
    )
}
impl<'id, 'store, 'bytes, 'cadet, 'cstore> Server<'id, 'store, 'bytes, 'cadet, 'cstore> {
    fn track(
        &mut self,
        transmit: cadet::Transmit<'cadet>,
        action: Action<'id>,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(ProtocolError::Conflict.into());
        }
        self.pending = Some(Pending {
            transmit,
            action,
            expires: Instant::now()
                .checked_add(self.limits.send_timeout)
                .ok_or(ProtocolError::Overflow)?,
        });
        Ok(())
    }
    fn track_pending(&mut self, action: Action<'id>) -> Result<(), Error> {
        let transmit = self
            .cadet
            .pending_transmit()
            .ok_or(ProtocolError::NotReady)?;
        self.track(transmit, action)
    }
    fn native_free(&self) -> bool {
        self.pending.is_none()
            && self.cadet.pending_transmit().is_none()
            && self.cadet.epoch().is_some()
    }
    fn bind_port(&mut self, index: usize) -> Result<bool, Error> {
        let listen = self.listeners[index]
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?;
        if listen.closing || listen.bound.is_some() {
            return Ok(false);
        }
        if let Some(port) = listen.port
            && self.cadet.port_announced(port)?
        {
            let app = self.core.listener_app(listen.listener)?;
            if self.cadet.port_hash(port)? != app {
                return Err(ProtocolError::Authentication.into());
            }
            listen.bound = Some(self.core.bind_listener(listen.listener)?);
            return Ok(true);
        }
        Ok(false)
    }
    fn listener_work(&mut self, index: usize) -> Result<bool, Error> {
        let Some(listen) = &self.listeners[index] else {
            return Ok(false);
        };
        let app = self.core.listener_app(listen.listener);
        let closing = listen.closing || app.is_err() || self.shutdown.is_some();
        if closing {
            let listen = self.listeners[index]
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?;
            if !listen.closing {
                if app.is_ok() {
                    self.core.close_listener(listen.listener)?;
                }
                listen.closing = true;
                listen.bound = None;
            }
            let Some(port) = listen.port else {
                self.listeners[index] = None;
                return Ok(true);
            };
            if !self.native_free() {
                return Ok(false);
            }
            match self.cadet.close_port(port) {
                Ok(Some(transmit)) => {
                    self.track(transmit, Action::PortClose(index))?;
                    return Ok(true);
                }
                Ok(None) | Err(cadet::Error::Protocol(ProtocolError::StaleGeneration)) => {
                    self.listeners[index] = None;
                    return Ok(true);
                }
                Err(e) if transient(&e) => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
        if self.bind_port(index)? {
            return Ok(true);
        }
        if self.listeners[index]
            .as_ref()
            .is_some_and(|l| l.port.is_none())
            && self.native_free()
        {
            match self.cadet.listen(app?) {
                Ok(port) => {
                    self.listeners[index]
                        .as_mut()
                        .ok_or(ProtocolError::StaleGeneration)?
                        .port = Some(port);
                    self.track_pending(Action::PortOpen(index))?;
                    return Ok(true);
                }
                Err(e) if transient(&e) => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(false)
    }
    pub(super) fn finish_channel(
        &mut self,
        index: usize,
        reason: ProtocolError,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        let Some(link) = self.links[index].as_mut() else {
            return Ok(());
        };
        if let Some(pending) = &mut self.pending
            && let Action::Data(effect) = pending.action
            && link.operation == Some(effect.operation())
        {
            pending.action = Action::RetiredData(effect);
        }
        if self
            .held
            .as_ref()
            .is_some_and(|h| link.operation == Some(h.effect.operation()))
        {
            self.held = None;
        }
        link.channel = None;
        link.input = None;
        if let Some(source) = link.source.take() {
            let loss = self.core.peer_lost(source, reason)?;
            observe(Event::PeerLost(loss));
        } else if let Some(operation) = link.operation
            && self.core.operation_info(operation)?.phase == Phase::Opening
        {
            self.core.open_failed(operation, reason)?;
        }
        if link.operation.is_none()
            && !self.pending.as_ref().is_some_and(|p| match p.action {
                Action::Open(i) | Action::Ack(i) | Action::Destroy(i) => i == index,
                _ => false,
            })
        {
            self.links[index] = None;
        }
        Ok(())
    }
    pub(super) fn backend_lost(
        &mut self,
        report: cadet::Loss<'cadet>,
        cause: cadet::LossCause,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        // Recover the exact exposure even if the native owner returned loss in
        // the same observation as a later socket failure, before another event.
        if let (Some(pending), Some(retired)) = (&self.pending, report.pending)
            && retired.transmit == pending.transmit
            && retired.exposed
        {
            match pending.action {
                Action::Data(effect) => self.core.exposed(effect)?,
                Action::RetiredData(effect) => self.retired_exposed(effect)?,
                _ => {}
            }
        }
        if let Some(pending) = self.pending.take()
            && let Action::PortClose(index) = pending.action
        {
            self.listeners[index] = None;
        }
        self.held = None;
        let reason = match &cause {
            cadet::LossCause::Protocol(e) => *e,
            cadet::LossCause::Io(_) => ProtocolError::Io,
            cadet::LossCause::Eof | cadet::LossCause::Requested => ProtocolError::Closed,
        };
        let mut first = None;
        for index in 0..self.links.len() {
            if self.links[index]
                .as_ref()
                .is_some_and(|l| l.channel.is_some_and(|c| c.epoch() == report.epoch))
                && let Err(e) = self.finish_channel(index, reason, observe)
                && first.is_none()
            {
                first = Some(e);
            }
        }
        for listen in self.listeners.iter_mut().flatten() {
            if let Some(port) = listen.bound.take() {
                match self.core.unbind_listener(port) {
                    Ok(()) | Err(ProtocolError::StaleGeneration) => {}
                    Err(e) if first.is_none() => first = Some(e.into()),
                    Err(_) => {}
                }
            }
        }
        self.report.backend_losses = self.report.backend_losses.saturating_add(1);
        observe(Event::BackendLost { report, cause });
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
    fn retired_exposed(&mut self, effect: core::Effect<'id>) -> Result<(), Error> {
        if self
            .links
            .iter()
            .flatten()
            .any(|link| link.operation == Some(effect.operation()) && link.source.is_some())
        {
            self.core.exposed(effect)?;
        }
        Ok(())
    }
    fn written(
        &mut self,
        transmit: cadet::Transmit<'cadet>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        let pending = if self
            .pending
            .as_ref()
            .is_some_and(|p| p.transmit == transmit)
        {
            self.pending.take()
        } else {
            None
        };
        if let Some(pending) = pending {
            match pending.action {
                Action::Data(effect) => {
                    self.core.exposed(effect)?;
                    self.core.written(effect)?;
                    self.report.peer_frames = self.report.peer_frames.saturating_add(1);
                }
                Action::RetiredData(effect) => {
                    self.retired_exposed(effect)?;
                    observe(Event::RetiredWrite {
                        transmit,
                        effect,
                        complete: true,
                    });
                }
                Action::Destroy(index) => {
                    self.finish_channel(index, ProtocolError::Closed, observe)?
                }
                Action::PortClose(index) => self.listeners[index] = None,
                Action::PortOpen(index) => {
                    self.bind_port(index)?;
                }
                Action::Open(index) | Action::Ack(index) => {
                    // Index is original metadata only. Full local writing grants
                    // no new SETI result, remote acceptance or application credit.
                    let _original = self.links.get(index);
                }
                Action::Auxiliary => {}
            }
        }
        observe(Event::PeerWritten(transmit));
        Ok(())
    }
    fn reconnect(
        &mut self,
        reason: ProtocolError,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        observe(Event::PeerRefused {
            channel: None,
            reason,
        });
        match self.cadet.reconnect()? {
            cadet::Step::Lost { report, cause, .. } => self.backend_lost(report, cause, observe),
            _ => Err(ProtocolError::Conflict.into()),
        }
    }
    fn incoming(
        &mut self,
        channel: cadet::Channel<'cadet>,
        port: cadet::Port<'cadet>,
        now: u64,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        let Some(index) = self.links.iter().position(Option::is_none) else {
            return self.reconnect(ProtocolError::Capacity, observe);
        };
        self.links[index] = Some(Link {
            operation: None,
            channel: Some(channel),
            source: None,
            input: None,
            close: true,
            remote_closed: false,
        });
        let result = (|| {
            let listen_index = self
                .listeners
                .iter()
                .position(|l| {
                    l.as_ref()
                        .is_some_and(|l| l.port == Some(port) && !l.closing)
                })
                .ok_or(ProtocolError::NotFound)?;
            self.bind_port(listen_index)?;
            let actual = self.cadet.channel_info(channel)?;
            let binding = self.listeners[listen_index]
                .as_ref()
                .and_then(|l| l.bound)
                .ok_or(ProtocolError::NotReady)?;
            let source = self.core.incoming(binding, actual.peer, now)?;
            Ok::<_, Error>(source)
        })();
        match result {
            Ok(source) => {
                let link = self.links[index]
                    .as_mut()
                    .ok_or(ProtocolError::StaleGeneration)?;
                link.operation = Some(source.operation());
                link.source = Some(source);
                link.close = false;
                self.report.channels = self.report.channels.saturating_add(1);
            }
            Err(error) => {
                let reason = match error {
                    Error::Protocol(e) | Error::Cadet(cadet::Error::Protocol(e)) => e,
                    _ => ProtocolError::Io,
                };
                observe(Event::PeerRefused {
                    channel: Some(channel),
                    reason,
                });
            }
        }
        Ok(())
    }
    fn data(
        &mut self,
        received: cadet::Received<'cadet>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        let channel = received.channel();
        let Some(index) = self
            .links
            .iter()
            .position(|l| l.as_ref().is_some_and(|l| l.channel == Some(channel)))
        else {
            drop(received);
            return self.reconnect(ProtocolError::StaleGeneration, observe);
        };
        if self.links[index]
            .as_ref()
            .is_some_and(|l| l.input.is_some())
        {
            drop(received);
            return self.reconnect(ProtocolError::Conflict, observe);
        }
        self.links[index]
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?
            .input = Some(Input {
            received,
            offset: 0,
            end: 0,
            processing: None,
        });
        Ok(())
    }
    pub(super) fn poll_cadet(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Poll<Result<Progress, Error>> {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.expires)
        {
            self.report.stalled = self.report.stalled.saturating_add(1);
            self.reconnect(ProtocolError::Deadline, observe)?;
            return Poll::Ready(Ok(Progress::Activity));
        }
        let step = match self.cadet.poll(cx, None) {
            Poll::Pending => {
                if self.pending.is_none() && self.cadet.pending_transmit().is_some() {
                    self.track_pending(Action::Auxiliary)?;
                    return Poll::Ready(Ok(Progress::Activity));
                }
                return Poll::Pending;
            }
            Poll::Ready(result) => result?,
        };
        match step {
            cadet::Step::Connected(epoch) => observe(Event::BackendConnected(epoch)),
            cadet::Step::Written(w) => self.written(w.transmit, observe)?,
            cadet::Step::Activity { written_bytes, .. } => {
                if written_bytes != 0 {
                    if self.pending.is_none() && self.cadet.pending_transmit().is_some() {
                        self.track_pending(Action::Auxiliary)?;
                    }
                    if let Some(pending) = &self.pending
                        && let Action::Data(effect) = pending.action
                    {
                        self.core.exposed(effect)?;
                    }
                    if let Some((transmit, effect)) =
                        self.pending
                            .as_ref()
                            .and_then(|pending| match pending.action {
                                Action::RetiredData(effect) => Some((pending.transmit, effect)),
                                _ => None,
                            })
                    {
                        self.retired_exposed(effect)?;
                        observe(Event::RetiredWrite {
                            transmit,
                            effect,
                            complete: false,
                        });
                    }
                }
            }
            cadet::Step::Incoming { channel, port } => {
                let now = self.clock.sample()?.now.as_micros();
                self.incoming(channel, port, now, observe)?;
            }
            cadet::Step::Destroyed(channel) => {
                if let Some(index) = self
                    .links
                    .iter()
                    .position(|l| l.as_ref().is_some_and(|l| l.channel == Some(channel)))
                {
                    let link = self.links[index]
                        .as_mut()
                        .ok_or(ProtocolError::StaleGeneration)?;
                    link.remote_closed = true;
                    // A later terminal event cannot erase earlier complete DATA.
                    // Retain the pure source only to consume those owned bytes;
                    // it grants no new native send or receive credit.
                    if link.close {
                        link.input = None;
                    }
                    if let Some(pending) = &mut self.pending
                        && let Action::Data(effect) = pending.action
                        && link.operation == Some(effect.operation())
                    {
                        pending.action = Action::RetiredData(effect);
                    }
                }
            }
            cadet::Step::Data(received) => self.data(received, observe)?,
            cadet::Step::Credit { .. }
            | cadet::Step::RejectedIncoming { .. }
            | cadet::Step::Ignored { .. } => {}
            cadet::Step::Blocked { reason, .. } => self.reconnect(reason, observe)?,
            cadet::Step::Lost { report, cause, .. } => self.backend_lost(report, cause, observe)?,
            cadet::Step::ConnectRetry { error, retry_after } => {
                observe(Event::BackendRetry { error, retry_after })
            }
            cadet::Step::Unavailable(e) => return Poll::Ready(Err(e.into())),
            cadet::Step::Closed => return Poll::Ready(Err(ProtocolError::Closed.into())),
            cadet::Step::WaitDeadline => {}
        }
        Poll::Ready(Ok(Progress::Activity))
    }
    fn input_work(
        &mut self,
        index: usize,
        now: u64,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        let native_free = self.native_free();
        let link = self.links[index]
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?;
        let Some(input) = &mut link.input else {
            return Ok(false);
        };
        let operation = link.operation.ok_or(ProtocolError::NotReady)?;
        let source = link.source.ok_or(ProtocolError::NotReady)?;
        if let Some(delivery) = input.processing {
            if self.core.receive_ready(operation)? == Some(delivery) {
                self.core.receive_done(delivery)?;
                input.offset = input.end;
                input.processing = None;
                return Ok(true);
            }
            return Ok(false);
        }
        let bytes = input.received.messages();
        if input.offset == bytes.len() {
            if link.remote_closed {
                // Semantic Delivery was really consumed above. The native
                // channel is gone, so release locally without an old ACK.
                link.input = None;
                return Ok(true);
            }
            if !native_free {
                return Ok(false);
            }
            let delivery = self.links[index]
                .as_ref()
                .and_then(|l| l.input.as_ref())
                .ok_or(ProtocolError::NotReady)?
                .received
                .delivery();
            match self.cadet.receive_done(delivery) {
                Ok(transmit) => {
                    self.links[index]
                        .as_mut()
                        .ok_or(ProtocolError::StaleGeneration)?
                        .input = None;
                    self.track(transmit, Action::Ack(index))?;
                    return Ok(true);
                }
                Err(e) if transient(&e) => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
        let tail = &bytes[input.offset..];
        let size = if tail.len() >= 4 {
            usize::from(u16::from_be_bytes([tail[0], tail[1]]))
        } else {
            0
        };
        if size < 4 || size > tail.len() || size > MAX_APPLICATION_MESSAGE_SIZE {
            self.core
                .external_failure(operation, ProtocolError::Malformed)?;
            link.close = true;
            observe(Event::PeerRefused {
                channel: link.channel,
                reason: ProtocolError::Malformed,
            });
            return Ok(true);
        }
        match self.core.receive_peer(source, &tail[..size], now) {
            Ok(delivery) => {
                input.processing = Some(delivery);
                input.end = input.offset + size;
            }
            Err(e) => {
                link.close = true;
                observe(Event::PeerRefused {
                    channel: link.channel,
                    reason: e,
                });
            }
        }
        Ok(true)
    }
    fn link_work(
        &mut self,
        index: usize,
        now: u64,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        let Some(link) = &self.links[index] else {
            return Ok(false);
        };
        let info = link
            .operation
            .map(|op| self.core.operation_info(op))
            .transpose()?;
        let local_stop =
            link.close || info.is_some_and(|o| matches!(o.phase, Phase::Canceled | Phase::Failed));
        if link.remote_closed {
            if link.channel.is_none() {
                // The pure source has already retired; local results retain
                // their own actual write/deadline obligations.
                return Ok(false);
            }
            let abandon = local_stop
                || info.is_none_or(|o| {
                    matches!(
                        o.phase,
                        Phase::Opening | Phase::AwaitRequest | Phase::AwaitAccept
                    )
                });
            if abandon {
                self.links[index]
                    .as_mut()
                    .ok_or(ProtocolError::StaleGeneration)?
                    .input = None;
            } else if self.input_work(index, now, observe)? {
                return Ok(true);
            }
            if self.links[index]
                .as_ref()
                .is_some_and(|l| l.input.is_some())
            {
                return Ok(false);
            }
            let operation = self.links[index].as_ref().and_then(|l| l.operation);
            if self
                .pending
                .as_ref()
                .is_some_and(|pending| match pending.action {
                    Action::Data(effect) | Action::RetiredData(effect) => {
                        operation == Some(effect.operation())
                    }
                    Action::Open(i) | Action::Ack(i) | Action::Destroy(i) => i == index,
                    _ => false,
                })
            {
                return Ok(false);
            }
            self.finish_channel(index, ProtocolError::Closed, observe)?;
            return Ok(true);
        }
        let close = local_stop || info.is_some_and(|o| o.phase == Phase::Finished);
        if close {
            let channel = link.channel;
            let unassigned = link.operation.is_none();
            let link = self.links[index]
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?;
            // Local cancel/failure/completion revokes unprocessed input now;
            // a later Destroyed cannot revive it as remote-first input.
            link.close = true;
            link.input = None;
            if let Some(channel) = channel {
                if !self.native_free() {
                    return Ok(false);
                }
                match self.cadet.destroy(channel) {
                    Ok(transmit) => {
                        self.track(transmit, Action::Destroy(index))?;
                        return Ok(true);
                    }
                    Err(e) if transient(&e) => return Ok(false),
                    Err(cadet::Error::Protocol(ProtocolError::StaleGeneration)) => {
                        return Err(ProtocolError::StaleGeneration.into());
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if unassigned {
                self.links[index] = None;
                return Ok(true);
            }
            return Ok(false);
        }
        let Some(operation) = link.operation else {
            return Ok(false);
        };
        let info = info.ok_or(ProtocolError::NotReady)?;
        if info.phase == Phase::Opening && link.source.is_none() {
            if link.input.is_some() {
                self.core
                    .external_failure(operation, ProtocolError::Conflict)?;
                let link = self.links[index]
                    .as_mut()
                    .ok_or(ProtocolError::StaleGeneration)?;
                link.close = true;
                observe(Event::PeerRefused {
                    channel: link.channel,
                    reason: ProtocolError::Conflict,
                });
                return Ok(true);
            }
            if let Some(channel) = link.channel {
                let actual = self.cadet.channel_info(channel)?;
                if actual.send_credit != 0 && !actual.closing {
                    let source = self.core.bind_peer(operation, actual.peer)?;
                    self.links[index]
                        .as_mut()
                        .ok_or(ProtocolError::StaleGeneration)?
                        .source = Some(source);
                    return Ok(true);
                }
                return Ok(false);
            }
            if !self.native_free() {
                return Ok(false);
            }
            let port = self.core.operation_app(operation)?;
            match self.cadet.open(info.peer, port) {
                Ok(channel) => {
                    self.links[index]
                        .as_mut()
                        .ok_or(ProtocolError::StaleGeneration)?
                        .channel = Some(channel);
                    self.track_pending(Action::Open(index))?;
                    self.report.channels = self.report.channels.saturating_add(1);
                    return Ok(true);
                }
                Err(e) if transient(&e) => return Ok(false),
                Err(cadet::Error::Protocol(e)) => {
                    self.core.open_failed(operation, e)?;
                    return Ok(true);
                }
                Err(e) => return Err(e.into()),
            }
        }
        if self.input_work(index, now, observe)? {
            return Ok(true);
        }
        let channel = self.links[index]
            .as_ref()
            .and_then(|l| l.channel)
            .ok_or(ProtocolError::NotReady)?;
        if !self.native_free()
            || self.held.is_some()
            || self.cadet.channel_info(channel)?.send_credit == 0
        {
            return Ok(false);
        }
        if !self.core.peer_output_ready(operation)? {
            return Ok(false);
        }
        let mut bytes = buffer(MAX_APPLICATION_MESSAGE_SIZE)?;
        let Some(prepared) = self.core.prepare_peer(operation, &mut bytes)? else {
            return Ok(false);
        };
        let effect = prepared.effect;
        let len = prepared.bytes.len();
        bytes.truncate(len);
        self.held = Some(Held {
            effect,
            bytes: OwnedFrame::new(bytes),
        });
        Ok(true)
    }
    fn send_held(&mut self, observe: &mut impl FnMut(Event<'id, 'cadet>)) -> Result<bool, Error> {
        if !self.native_free() {
            return Ok(false);
        }
        let Some(held) = &self.held else {
            return Ok(false);
        };
        let effect = held.effect;
        if let Err(e) = self.core.can_queue(effect) {
            self.core.reject_prepared(effect)?;
            self.held = None;
            if e != ProtocolError::Closed {
                return Err(e.into());
            }
            return Ok(true);
        }
        let index = self
            .links
            .iter()
            .position(|l| {
                l.as_ref()
                    .is_some_and(|l| l.operation == Some(effect.operation()))
            })
            .ok_or(ProtocolError::StaleGeneration)?;
        if self.links[index]
            .as_ref()
            .is_some_and(|link| link.remote_closed)
        {
            // This prepared frame never entered native IO. Preserve admitted
            // suffixes separately; do not send new output on a gone channel.
            self.core.reject_prepared(effect)?;
            self.held = None;
            return Ok(true);
        }
        let channel = self.links[index]
            .as_ref()
            .and_then(|l| l.channel)
            .ok_or(ProtocolError::NotReady)?;
        match self.cadet.send(channel, 0, held.bytes.bytes()) {
            Ok(transmit) => {
                self.core.queued(effect)?;
                self.held = None;
                self.track(transmit, Action::Data(effect))?;
                observe(Event::PeerQueued { effect, transmit });
                Ok(true)
            }
            Err(e) if transient(&e) => Ok(false),
            Err(e) => {
                self.core.reject_prepared(effect)?;
                self.held = None;
                let reason = match e {
                    cadet::Error::Protocol(e) => e,
                    _ => ProtocolError::Io,
                };
                self.core.external_failure(effect.operation(), reason)?;
                observe(Event::PeerRefused {
                    channel: Some(channel),
                    reason,
                });
                Ok(true)
            }
        }
    }
    pub(super) fn peer_work(
        &mut self,
        now: u64,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        if self.send_held(observe)? {
            return Ok(true);
        }
        for n in 0..self.listeners.len() {
            let i = (self.listener_cursor + n) % self.listeners.len();
            if self.listeners[i].is_some() && self.listener_work(i)? {
                self.listener_cursor = (i + 1) % self.listeners.len();
                return Ok(true);
            }
        }
        for n in 0..self.links.len() {
            let i = (self.link_cursor + n) % self.links.len();
            if self.links[i].is_some() && self.link_work(i, now, observe)? {
                self.link_cursor = (i + 1) % self.links.len();
                return Ok(true);
            }
        }
        Ok(false)
    }
}
